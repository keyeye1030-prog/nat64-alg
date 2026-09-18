const { Client } = require('ssh2');
const fs = require('fs');

const ssh = {
  host: process.env.NAT64_SSH_HOST,
  port: Number(process.env.NAT64_SSH_PORT || 22),
  username: process.env.NAT64_SSH_USER,
  password: process.env.NAT64_SSH_PASSWORD,
  sudoPassword: process.env.NAT64_SUDO_PASSWORD || process.env.NAT64_SSH_PASSWORD
};

if (!ssh.host || !ssh.username || !ssh.password || !ssh.sudoPassword) {
  throw new Error('Set NAT64_SSH_HOST, NAT64_SSH_USER, NAT64_SSH_PASSWORD, and optionally NAT64_SUDO_PASSWORD before running this script.');
}

const deployConfigPath = process.env.NAT64_DEPLOY_CONFIG || 'deploy_config.json';
if (!fs.existsSync(deployConfigPath)) {
  throw new Error(`Missing ${deployConfigPath}. Copy deploy_config.json.example and adjust it for the target host.`);
}

const deploy = JSON.parse(fs.readFileSync(deployConfigPath, 'utf8'));
const remote = {
  workdir: deploy.remote_workdir || `/home/${ssh.username}/nat64-alg`,
  archive: deploy.remote_archive || `/home/${ssh.username}/nat64-src.tar.gz`,
  serviceTmp: deploy.remote_service_tmp || `/home/${ssh.username}/nat64-alg.service`,
  serviceName: deploy.service_name || 'nat64-alg'
};

const sourceArchive = deploy.source_archive || 'nat64-src.tar.gz';
const goProxy = deploy.go_proxy || 'https://goproxy.cn,direct';
const bpfInclude = deploy.bpf_include || '/usr/include/x86_64-linux-gnu';
const config = deploy.config || {};
const ipv6Interface = config.iface_ipv6;
const ipv4Interface = config.iface_ipv4;

if (!ipv6Interface || !ipv4Interface) {
  throw new Error('deploy config must include config.iface_ipv6 and config.iface_ipv4.');
}

const sudo = (cmd) => ({ command: `sudo -S ${cmd}`, sudo: true });
const sh = (value) => `'${String(value).replace(/'/g, `'\\''`)}'`;

function serviceFile() {
  const pre = [];
  pre.push(`ExecStartPre=-/usr/sbin/ethtool -K ${ipv6Interface} rx off tx off tso off gso off gro off lro off`);
  pre.push(`ExecStartPre=-/usr/sbin/ethtool -K ${ipv4Interface} rx off tx off tso off gso off gro off lro off`);
  pre.push(`ExecStartPre=-/usr/sbin/ethtool -L ${ipv6Interface} combined ${config.preflight_queues || 1}`);
  pre.push(`ExecStartPre=-/usr/sbin/ethtool -L ${ipv4Interface} combined ${config.preflight_queues || 1}`);
  pre.push(`ExecStartPre=/usr/sbin/ip link set dev ${ipv6Interface} promisc on`);
  pre.push(`ExecStartPre=/usr/sbin/ip link set dev ${ipv4Interface} promisc on`);
  if (deploy.ipv6_gateway_mac && config.ipv6_gateway) {
    pre.push(`ExecStartPre=-/usr/sbin/ip -6 neigh replace ${config.ipv6_gateway} lladdr ${deploy.ipv6_gateway_mac} dev ${ipv6Interface} nud permanent`);
  }

  return `[Unit]
Description=High Performance NAT64 ALG Gateway (AF_XDP)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${remote.workdir}
${pre.join('\n')}
ExecStart=${remote.workdir}/nat64-alg -config ${remote.workdir}/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`;
}

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.sftp((err, sftp) => {
    if (err) throw err;

    console.log(`Uploading ${sourceArchive} to ${remote.archive}...`);
    const content = fs.readFileSync(sourceArchive);
    const stream = sftp.createWriteStream(remote.archive);

    stream.on('close', () => {
      console.log('Upload successful. Beginning remote installation...');

      const configJson = JSON.stringify(config, null, 2);
      const serviceText = serviceFile();
      const commands = [
        sudo(`ip link set dev ${ipv6Interface} up`),
        sudo(`ip link set dev ${ipv4Interface} up`),
        `rm -rf ${sh(remote.workdir)}`,
        `mkdir -p ${sh(remote.workdir)}`,
        `tar -xzf ${sh(remote.archive)} -C ${sh(remote.workdir)}`,
        `go env -w GOPROXY=${sh(goProxy)}`,
        `cd ${sh(remote.workdir)} && clang -O2 -target bpf -g -I${sh(bpfInclude)} -c xdp/nat64.c -o nat64.o`,
        `cd ${sh(remote.workdir)} && go mod tidy`,
        `cd ${sh(remote.workdir)} && go build -o nat64-alg main.go`,
        `cat > ${sh(`${remote.workdir}/config.json`)} << 'EOF'\n${configJson}\nEOF`,
        `cat > ${sh(remote.serviceTmp)} << 'EOF'\n${serviceText}EOF`,
        sudo(`mv ${sh(remote.serviceTmp)} /etc/systemd/system/${remote.serviceName}.service`),
        sudo('systemctl daemon-reload'),
        sudo(`systemctl enable ${remote.serviceName}`),
        sudo(`systemctl restart ${remote.serviceName}`),
        'sleep 3',
        sudo(`systemctl status ${remote.serviceName} || true`),
        sudo(`journalctl -u ${remote.serviceName} -n 30 || true`)
      ];

      runNext(commands, 0);
    });

    stream.end(content);
  });
}).on('error', (err) => {
  console.log('ERROR: ' + err);
}).connect({
  host: ssh.host,
  port: ssh.port,
  username: ssh.username,
  password: ssh.password,
  algorithms: {
    kex: [
      'curve25519-sha256',
      'curve25519-sha256@libssh.org',
      'ecdh-sha2-nistp256',
      'diffie-hellman-group14-sha256'
    ]
  }
});

function runNext(commands, index) {
  if (index >= commands.length) {
    console.log('All deployment steps completed.');
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
      stream.write(`${ssh.sudoPassword}\n`);
    }
    stream.on('close', (code) => {
      console.log(`Command [${index}] finished with code ${code}`);
      if (code !== 0) {
        console.error(`Command [${index}] failed with code ${code}. Aborting.`);
        conn.end();
        return;
      }
      runNext(commands, index + 1);
    }).on('data', (data) => {
      process.stdout.write(data);
    }).stderr.on('data', (data) => {
      process.stderr.write(data);
    });
  });
}
