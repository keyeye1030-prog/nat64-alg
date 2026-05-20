const { Client } = require('ssh2');
const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 检查当前队列
    'ethtool -l enp2s0f0 2>&1',
    // 2. 强制设置单队列
    'echo "cernet@226!" | sudo -S ethtool -L enp2s0f0 combined 1 2>&1 || true',
    'echo "cernet@226!" | sudo -S ethtool -L enp2s0f1 combined 1 2>&1 || true',
    // 3. 验证
    'ethtool -l enp2s0f0 2>&1',
    // 4. 重启服务
    'echo "cernet@226!" | sudo -S systemctl restart nat64-alg 2>&1',
    'sleep 3',
    // 5. ping 网关触发 NDP
    'ping6 -c 2 -W 2 1111::1 2>&1 || true',
    // 6. 等用户 ping
    'echo "=== 请从公网 ping 240C:C0A9:100F:1::121.194.10.1 ==="; sleep 15',
    // 7. 引擎日志
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "20 sec ago" --no-pager 2>/dev/null | grep -v "NeighborTable"',
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
