const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  // 在 enp2s0f0 上抓包 5 秒，看有没有 NAT64 前缀的 IPv6 包到达
  const cmd = 'echo "cernet@226!" | sudo -S timeout 8 tcpdump -i enp2s0f0 -n -c 20 "ip6" 2>&1 || true';
  console.log('Running tcpdump on enp2s0f0 for 8 seconds... Keep pinging!');
  conn.exec(cmd, (err, stream) => {
    if (err) throw err;
    stream.on('close', (code) => {
      console.log(`\ntcpdump finished (code ${code})`);
      conn.end();
    }).on('data', (data) => {
      process.stdout.write(data);
    }).stderr.on('data', (data) => {
      process.stderr.write(data);
    });
  });
}).on('error', (err) => {
  console.log('ERROR: ' + err);
}).connect({
  host: '121.194.10.55',
  port: 7122,
  username: 'cernet',
  password: 'cernet@226!',
  algorithms: {
    kex: ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'diffie-hellman-group14-sha256']
  }
});
