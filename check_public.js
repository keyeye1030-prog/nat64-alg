const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  console.log('请立即从公网 ping 240C:C0A9:100F:1::121.194.10.1 ！');
  console.log('正在 enp2s0f0 上抓包 15 秒...\n');
  
  conn.exec('echo "cernet@226!" | sudo -S timeout 15 tcpdump -i enp2s0f0 -n -v "ip6" -c 20 2>&1', (err, stream) => {
    if (err) throw err;
    stream.on('close', (code) => {
      console.log(`\ntcpdump finished (code ${code})`);
      // 查看 Go 引擎日志
      conn.exec('echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "30 sec ago" --no-pager 2>/dev/null', (err2, stream2) => {
        if (err2) { conn.end(); return; }
        console.log('\n=== Go 引擎日志 ===');
        stream2.on('close', () => conn.end())
          .on('data', (d) => process.stdout.write(d))
          .stderr.on('data', (d) => process.stderr.write(d));
      });
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
