const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 检查服务状态
    'echo "cernet@226!" | sudo -S systemctl is-active nat64-alg 2>/dev/null',
    // 2. 检查 NDP 状态
    'ip -6 neigh show dev enp2s0f0',
    // 3. 检查 XDP
    'ip link show enp2s0f0 | head -3',
    // 4. 查看最新引擎日志
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "5 min ago" --no-pager 2>/dev/null | tail -30',
    // 5. 抓包 15 秒 (请用户从公网 ping)
    'echo "\n=== 请立即从公网 ping 240C:C0A9:100F:1::121.194.10.1 ===\n抓包 15 秒..."',
    'echo "cernet@226!" | sudo -S timeout 15 tcpdump -i enp2s0f0 -n "ip6" -c 10 2>&1',
    // 6. 检查引擎日志
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "20 sec ago" --no-pager 2>/dev/null',
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
