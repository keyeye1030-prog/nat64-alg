const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 设置永久 NDP 条目 (不会过期，不需要 NDP 探测)
    'echo "cernet@226!" | sudo -S ip -6 neigh replace 1111::1 lladdr 98:35:ed:35:f6:c2 dev enp2s0f0 nud permanent 2>&1',
    // 2. 确认
    'ip -6 neigh show dev enp2s0f0',
    // 3. 重启 NAT64 服务
    'echo "cernet@226!" | sudo -S systemctl restart nat64-alg 2>&1',
    // 4. 等一下
    'sleep 3',
    // 5. 重新设置永久 NDP (服务重启可能清除)
    'echo "cernet@226!" | sudo -S ip -6 neigh replace 1111::1 lladdr 98:35:ed:35:f6:c2 dev enp2s0f0 nud permanent 2>&1',
    // 6. 确认服务状态
    'echo "cernet@226!" | sudo -S systemctl status nat64-alg 2>&1 | head -15',
    // 7. 确认 NDP 永久条目还在
    'ip -6 neigh show dev enp2s0f0',
    // 8. 确认 XDP 附着
    'ip link show enp2s0f0 | head -3',
    // 9. 等待并抓包验证 (20 秒)
    'echo "\n=== 请从公网 ping 240C:C0A9:100F:1::121.194.10.1 ==="',
    'echo "cernet@226!" | sudo -S timeout 20 tcpdump -i enp2s0f0 -n "ip6" -c 10 2>&1',
    // 10. 查看 Go 引擎日志
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "30 sec ago" --no-pager 2>/dev/null',
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
