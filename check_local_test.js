const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 添加临时路由: 让 NAT64 前缀走 enp2s0f0 → 1111::1
    'echo "cernet@226!" | sudo -S ip -6 route add 240c:c0a9:100f:1::/96 via 1111::1 dev enp2s0f0 2>&1 || true',
    // 2. 确认路由
    'ip -6 route get 240c:c0a9:100f:1::79c2:0a01 2>&1',
    // 3. 后台 tcpdump + ping 测试
    'echo "cernet@226!" | sudo -S bash -c "timeout 8 tcpdump -i enp2s0f0 -n -c 30 2>&1 & sleep 1; ping6 -c 3 -W 2 240c:c0a9:100f:1::79c2:0a01 2>&1; wait"',
    // 4. 看 Go 引擎日志
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg -n 20 --no-pager 2>/dev/null',
    // 5. 清理临时路由
    'echo "cernet@226!" | sudo -S ip -6 route del 240c:c0a9:100f:1::/96 via 1111::1 dev enp2s0f0 2>&1 || true',
  ];
  
  function runNext(index) {
    if (index >= commands.length) { conn.end(); return; }
    console.log(`\n=== [${index}] ===`);
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
