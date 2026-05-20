const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 停止 NAT64 服务 (会自动卸载 XDP)
    'echo "cernet@226!" | sudo -S systemctl stop nat64-alg 2>&1',
    // 2. 确认 XDP 已卸载
    'ip link show enp2s0f0 | head -3',
    // 3. 确保 IPv6 地址存在
    'echo "cernet@226!" | sudo -S ip addr add 1111::2/126 dev enp2s0f0 2>/dev/null || true',
    'echo "cernet@226!" | sudo -S ip link set dev enp2s0f0 up',
    'ip -6 addr show dev enp2s0f0',
    // 4. 确认 NDP 正常
    'ping6 -c 1 -W 2 1111::1 2>&1 || true',
    'ip -6 neigh show dev enp2s0f0',
    // 5. 开始抓包 (30秒, 抓所有 IPv6 包)
    'echo "\n==============================\n请立即从公网 ping 240C:C0A9:100F:1::121.194.10.1\n抓包 30 秒...\n=============================="',
    'echo "cernet@226!" | sudo -S timeout 30 tcpdump -i enp2s0f0 -n -v "ip6" -c 30 2>&1',
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
