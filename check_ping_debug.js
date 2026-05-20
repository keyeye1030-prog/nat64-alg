const { Client } = require('ssh2');
const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 服务是否正常运行(没有 crash)
    'echo "cernet@226!" | sudo -S systemctl is-active nat64-alg 2>/dev/null',
    // 2. 最新引擎日志 (过滤掉邻居学习噪音, 看翻译和错误)
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "2 min ago" --no-pager 2>/dev/null | grep -v "NeighborTable" | tail -30',
    // 3. 同时抓 IPv4 侧看翻译后的包是否出去了
    'echo "cernet@226!" | sudo -S timeout 8 tcpdump -i enp2s0f1 -n "icmp" -c 10 2>&1',
    // 4. 引擎统计 (翻译计数)
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "2 min ago" --no-pager 2>/dev/null | grep -iE "6to4|4to6|translate|error|TX|发送" | tail -20',
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
