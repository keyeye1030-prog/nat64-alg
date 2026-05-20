const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 添加路由
    'echo "cernet@226!" | sudo -S ip -6 route replace 240c:c0a9:100f:1::/96 via 1111::1 dev enp2s0f0 metric 10 2>&1',
    // 2. TX 包计数 (前)
    'echo "TX before:"; cat /sys/class/net/enp2s0f0/statistics/tx_packets',
    // 3. 发 ping (不等结果)
    'ping6 -c 2 -W 1 -I 1111::2 240c:c0a9:100f:1::79c2:0a01 2>&1 || true',
    // 4. TX 包计数 (后)
    'echo "TX after:"; cat /sys/class/net/enp2s0f0/statistics/tx_packets',
    // 5. 检查 ip6tables
    'echo "cernet@226!" | sudo -S ip6tables -L -n -v 2>&1 | head -30',
    // 6. 检查 NDP 缓存
    'ip -6 neighbor show 1111::1 2>&1',
    // 7. 检查 IPv6 是否被禁用
    'cat /proc/sys/net/ipv6/conf/enp2s0f0/disable_ipv6',
    // 8. 清理
    'echo "cernet@226!" | sudo -S ip -6 route del 240c:c0a9:100f:1::/96 via 1111::1 dev enp2s0f0 2>&1 || true',
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
