const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 最新30条服务日志
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg -n 50 --no-pager 2>/dev/null',
    // 2. 检查 XDP 程序是否附着
    'echo "cernet@226!" | sudo -S ip link show enp2s0f0 2>/dev/null',
    // 3. 检查 IPv6 邻居表
    'echo "cernet@226!" | sudo -S ip -6 neighbor show dev enp2s0f0 2>/dev/null',
    // 4. 检查 IPv6 路由
    'echo "cernet@226!" | sudo -S ip -6 route show dev enp2s0f0 2>/dev/null',
    // 5. 检查 enp2s0f0 有没有收到包 (接口统计)
    'cat /sys/class/net/enp2s0f0/statistics/rx_packets',
    'cat /sys/class/net/enp2s0f0/statistics/tx_packets',
  ];
  
  function runNext(index) {
    if (index >= commands.length) {
      conn.end();
      return;
    }
    console.log(`\n--- [${index}]: ${commands[index].substring(0, 80)}... ---`);
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
