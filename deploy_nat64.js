const { Client } = require('ssh2');
const fs = require('fs');

const host = process.env.NAT64_SSH_HOST;
const port = Number(process.env.NAT64_SSH_PORT || 22);
const username = process.env.NAT64_SSH_USER;
const password = process.env.NAT64_SSH_PASSWORD;
const sudoPassword = process.env.NAT64_SUDO_PASSWORD || password;

if (!host || !username || !password || !sudoPassword) {
  throw new Error('Set NAT64_SSH_HOST, NAT64_SSH_USER, NAT64_SSH_PASSWORD, and optionally NAT64_SUDO_PASSWORD before running this script.');
}

const sudo = (cmd) => ({ command: `sudo -S ${cmd}`, sudo: true });

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.sftp((err, sftp) => {
    if (err) throw err;
    
    const localFile = 'nat64-src.tar.gz';
    const remoteFile = '/home/cernet/nat64-src.tar.gz';
    console.log(`Uploading ${localFile} to ${remoteFile}...`);
    
    const content = fs.readFileSync(localFile);
    const stream = sftp.createWriteStream(remoteFile);
    
    stream.on('close', () => {
      console.log('Upload successful! Beginning remote installation...');
      
      const commands = [
        // 1. Set IPv6 address on enp2s0f0
        sudo('ip addr add 1111::2/126 dev enp2s0f0 2>/dev/null || true'),
        sudo('ip link set dev enp2s0f0 up'),
        
        // 2. Clear old directories and create new workspace
        'rm -rf /home/cernet/nat64-alg',
        'mkdir -p /home/cernet/nat64-alg',
        
        // 3. Unpack source code
        'tar -xzf /home/cernet/nat64-src.tar.gz -C /home/cernet/nat64-alg',
        
        // 4. Configure Go Proxy
        'go env -w GOPROXY=https://goproxy.cn,direct',
        
        // 5. Compile XDP kernel program (incorporate host asm header path)
        'cd /home/cernet/nat64-alg && clang -O2 -target bpf -g -I/usr/include/x86_64-linux-gnu -c xdp/nat64.c -o nat64.o',
        
        // 6. Go mod tidy to resolve all checksums/dependencies
        'cd /home/cernet/nat64-alg && go mod tidy',
        
        // 7. Compile Go user-space program
        'cd /home/cernet/nat64-alg && go build -o nat64-alg main.go',
        
        // 8. Create config.json
        `cat << 'EOF' > /home/cernet/nat64-alg/config.json
{
  "mode": "dual",
  "pool_ipv4s": ["121.194.15.71"],
  "nat64_prefix": "240C:C0A9:100F:1::/96",
  "iface_ipv6": "enp2s0f0",
  "iface_ipv4": "enp2s0f1",
  "gw_ipv6": "1111::2",
  "ipv6_gateway": "1111::1",
  "ipv4_gateway_mac": "48:8e:ef:9f:26:3d",
  "rtp_port_start": 20000,
  "rtp_port_end": 30000,
  "static_mappings": {
    "2001:da8:20d:7000:598a:b9cd:664a:429b": "121.194.15.71"
  }
}
EOF`,

        // 9. Write systemd service file locally in home dir
        `cat << 'EOF' > /home/cernet/nat64-alg.service
[Unit]
Description=High Performance NAT64 ALG Gateway (AF_XDP)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/cernet/nat64-alg
ExecStartPre=/usr/sbin/ethtool -K enp2s0f0 rx off tx off tso off gso off gro off lro off
ExecStartPre=-/usr/sbin/ethtool -K enp2s0f1 rx off tx off tso off gso off gro off lro off
ExecStartPre=-/usr/sbin/ethtool -L enp2s0f0 combined 1
ExecStartPre=-/usr/sbin/ethtool -L enp2s0f1 combined 1
ExecStartPre=/usr/sbin/ip link set dev enp2s0f0 promisc on
ExecStartPre=/usr/sbin/ip link set dev enp2s0f1 promisc on
ExecStartPre=-/usr/sbin/ip -6 neigh replace 1111::1 lladdr 98:35:ed:35:f6:c2 dev enp2s0f0 nud permanent
ExecStart=/home/cernet/nat64-alg/nat64-alg -config /home/cernet/nat64-alg/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF`,

        // 10. Move service file using sudo (without here-doc, safe from stdin conflict)
        sudo('mv /home/cernet/nat64-alg.service /etc/systemd/system/nat64-alg.service'),

        // 11. Reload systemd daemon and restart the service
        sudo('systemctl daemon-reload'),
        sudo('systemctl enable nat64-alg'),
        sudo('systemctl restart nat64-alg'),
        
        // 12. Wait a little and show status & logs
        'sleep 3',
        sudo('systemctl status nat64-alg || true'),
        sudo('journalctl -u nat64-alg -n 30 || true')
      ];
      
      function runNext(index) {
        if (index >= commands.length) {
          console.log('All deployment steps completed!');
          conn.end();
          return;
        }
        const step = typeof commands[index] === 'string' ? { command: commands[index] } : commands[index];
        console.log(`\n--- Running [${index}]: ${step.command.substring(0, 100)}... ---`);
        conn.exec(step.command, (err, stream) => {
          if (err) {
            console.error(`Exec error: ${err}`);
            conn.end();
            return;
          }
          if (step.sudo) {
            stream.write(`${sudoPassword}\n`);
          }
          stream.on('close', (code) => {
            console.log(`Command [${index}] finished with code ${code}`);
            if (code !== 0 && index !== 0) { // allow ip addr add to fail if already added
              console.error(`Command [${index}] failed with code ${code}. Aborting.`);
              conn.end();
              return;
            }
            runNext(index + 1);
          }).on('data', (data) => {
            process.stdout.write(data);
          }).stderr.on('data', (data) => {
            process.stderr.write(data);
          });
        });
      }
      
      runNext(0);
    });
    
    stream.end(content);
  });
}).on('error', (err) => {
  console.log('ERROR: ' + err);
}).connect({
  host,
  port,
  username,
  password,
  algorithms: {
    kex: [
      'curve25519-sha256',
      'curve25519-sha256@libssh.org',
      'ecdh-sha2-nistp256',
      'diffie-hellman-group14-sha256'
    ]
  }
});
