const { Client } = require('ssh2');
const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 抓 IPv4 侧 DNS 请求和回复 (看 114.114.114.114 是否回复)
    'echo "cernet@226!" | sudo -S timeout 10 tcpdump -i enp2s0f1 -n "host 114.114.114.114" -c 10 2>&1',
    // 2. 抓 IPv6 侧看翻译后的回复是否发出
    'echo "cernet@226!" | sudo -S timeout 5 tcpdump -i enp2s0f0 -n -e "ip6 and udp" -c 5 2>&1 || true',
    // 3. 引擎日志 (看 DNS 翻译)
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "15 sec ago" --no-pager 2>/dev/null | grep -E "84 字节|171 字节|翻译错误|114" | tail -20',
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
