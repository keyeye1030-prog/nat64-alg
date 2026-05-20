const { Client } = require('ssh2');
const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 最近 30 秒日志 - 看 DNS/UDP 翻译
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "30 sec ago" --no-pager 2>/dev/null | grep -v "NeighborTable" | tail -30',
    // 2. 抓 IPv4 侧 UDP 53 出站
    'echo "cernet@226!" | sudo -S timeout 10 tcpdump -i enp2s0f1 -n "udp port 53" -c 5 2>&1',
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
