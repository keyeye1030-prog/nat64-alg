const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 添加明细路由并确认
    'echo "cernet@226!" | sudo -S ip -6 route replace 240c:c0a9:100f:1::/96 via 1111::1 dev enp2s0f0 metric 10 2>&1',
    'ip -6 route get 240c:c0a9:100f:1::79c2:0a01 from 1111::2 2>&1',
    // 2. 启动 tcpdump 同时抓两个网卡, 然后 ping
    'echo "cernet@226!" | sudo -S bash -c "' +
      'timeout 10 tcpdump -i enp2s0f0 -n -c 30 2>&1 > /tmp/tcpdump_v6.log & ' +
      'timeout 10 tcpdump -i enp2s0f1 -n -c 30 2>&1 > /tmp/tcpdump_v4.log & ' +
      'sleep 1; ' +
      'ping6 -c 3 -W 2 -I 1111::2 240c:c0a9:100f:1::79c2:0a01 2>&1; ' +
      'sleep 2; ' +
      'echo === enp2s0f0 tcpdump ===; cat /tmp/tcpdump_v6.log; ' +
      'echo === enp2s0f1 tcpdump ===; cat /tmp/tcpdump_v4.log; ' +
      'wait"',
    // 3. 查看 Go 引擎最新日志 (翻译+邻居学习)
    'echo "cernet@226!" | sudo -S journalctl -u nat64-alg --since \"1 min ago\" --no-pager 2>/dev/null',
    // 4. 清理
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
