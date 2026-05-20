const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 清除失败的 NDP 条目
    'echo "cernet@226!" | sudo -S ip -6 neigh del 1111::1 dev enp2s0f0 2>&1 || true',
    // 2. 先 ping 1111::1 恢复 NDP
    'ping6 -c 2 -W 2 1111::1 2>&1',
    // 3. 确认 NDP 恢复
    'ip -6 neigh show 1111::1 2>&1',
    // 4. 添加 NAT64 路由
    'echo "cernet@226!" | sudo -S ip -6 route replace 240c:c0a9:100f:1::/96 via 1111::1 dev enp2s0f0 metric 10 2>&1',
    // 5. TX 计数器 (前)
    'echo "TX before:"; cat /sys/class/net/enp2s0f0/statistics/tx_packets',
    // 6. ping NAT64 地址
    'ping6 -c 3 -W 2 -I 1111::2 240c:c0a9:100f:1::79c2:0a01 2>&1 || true',
    // 7. TX 计数器 (后)
    'echo "TX after:"; cat /sys/class/net/enp2s0f0/statistics/tx_packets',
    // 8. Go 引擎日志
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "30 sec ago" --no-pager 2>/dev/null',
    // 9. 保留路由（不删除）用于公网测试
  ];
  
  function runNext(index) {
    if (index >= commands.length) { conn.end(); return; }
    console.log(`\n--- [${index}] ---`);
    conn.exec(commands[index], (err, stream) => {
      if (err) { console.error(err); conn.end(); return; }
      stream.on('close', () => runNext(index + 1))
        .on('data', (d) => process.stdout.write(d))
        .stderr.on('data', (d) => process.stderr.write(d));
    });
  }
  runNext(0);
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
