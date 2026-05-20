const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 检查 XDP BPF 统计数据
    'echo "cernet@226!" | sudo -S bpftool map dump name stats 2>&1 | head -40',
    // 2. 检查最近引擎日志 (全部)
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "3 min ago" --no-pager 2>/dev/null',
    // 3. 检查 NDP 状态
    'ip -6 neigh show dev enp2s0f0',
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
