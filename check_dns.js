const { Client } = require('ssh2');
const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 服务状态
    'echo "cernet@226!" | sudo -S systemctl is-active nat64-alg 2>/dev/null',
    // 2. 最近日志 (过滤翻译和错误)
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "1 min ago" --no-pager 2>/dev/null | grep -E "翻译|错误|UDP|DNS|Error" | tail -30',
    // 3. 全部最新日志
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since "30 sec ago" --no-pager 2>/dev/null | tail -20',
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
