const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  // 等 10 秒让路由器 NDP 刷新，然后抓包
  console.log('等待 10 秒让路由器 NDP 缓存通过 XDP NDP 代理刷新...\n');
  const commands = [
    'sleep 10',
    'echo "=== 抓包 15 秒 (请从公网 ping) ==="',
    'echo "cernet@226!" | sudo -S timeout 15 tcpdump -i enp2s0f0 -n "ip6" -c 10 2>&1',
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "30 sec ago" --no-pager 2>/dev/null',
  ];
  function runNext(i) {
    if (i >= commands.length) { conn.end(); return; }
    console.log(`\n--- [${i}] ---`);
    conn.exec(commands[i], (err, stream) => {
      if (err) { conn.end(); return; }
      stream.on('close', () => runNext(i + 1))
        .on('data', (d) => process.stdout.write(d))
        .stderr.on('data', (d) => process.stderr.write(d));
    });
  }
  runNext(0);
}).connect({
  host: '121.194.10.55', port: 7122,
  username: 'cernet', password: 'cernet@226!',
  algorithms: { kex: ['curve25519-sha256','curve25519-sha256@libssh.org','ecdh-sha2-nistp256','diffie-hellman-group14-sha256'] }
});
