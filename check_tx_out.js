const { Client } = require('ssh2');
const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 在 IPv6 侧 (enp2s0f0) 抓出站 IPv6 包 - 看翻译后的回包是否发出
    'echo "cernet@226!" | sudo -S timeout 8 tcpdump -i enp2s0f0 -n -e "ip6 and not ip6 proto 58" -c 5 2>&1 || true',
    // 2. 也抓 ICMPv6 看回包
    'echo "cernet@226!" | sudo -S timeout 8 tcpdump -i enp2s0f0 -n -e "icmp6" -c 5 2>&1 || true',
    // 3. 检查 TX 计数器
    'echo "TX:"; cat /sys/class/net/enp2s0f0/statistics/tx_packets; echo "TX errors:"; cat /sys/class/net/enp2s0f0/statistics/tx_errors; echo "TX dropped:"; cat /sys/class/net/enp2s0f0/statistics/tx_dropped',
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
