const { Client } = require('ssh2');
const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 确认队列数
    'ethtool -l enp2s0f0 2>&1 | head -10',
    // 2. 等待 15 秒 (请从公网 ping!)
    'echo "=== 请从公网 ping 240C:C0A9:100F:1::121.194.10.1 ==="; sleep 15',
    // 3. 引擎日志
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "20 sec ago" --no-pager 2>/dev/null',
    // 4. BPF stats
    'echo "cernet@226!" | sudo -S bpftool map dump name stats 2>&1 | head -60',
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
