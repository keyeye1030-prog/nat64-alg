const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 设置永久 NDP 条目 (我们侧)
    'echo "cernet@226!" | sudo -S ip -6 neigh replace 1111::1 lladdr 98:35:ed:35:f6:c2 dev enp2s0f0 nud permanent 2>&1',
    // 2. ping 网关触发路由器端 NDP 刷新 (路由器会重新解析 1111::2)
    'ping6 -c 3 -W 2 1111::1 2>&1 || true',
    // 3. 确认 NDP 状态
    'ip -6 neigh show dev enp2s0f0',
    // 4. 等路由器 NDP 稳定
    'sleep 3',
    // 5. 现在抓包 20 秒 (请从公网 ping!)
    'echo "\n=== 请从公网 ping 240C:C0A9:100F:1::121.194.10.1 ==="',
    'echo "cernet@226!" | sudo -S timeout 20 tcpdump -i enp2s0f0 -n "ip6" -c 10 2>&1',
    // 6. 引擎日志
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
