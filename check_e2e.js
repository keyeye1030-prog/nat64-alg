const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 在后台启动 tcpdump 抓 enp2s0f0 上所有流量 5 秒
    'echo "cernet@226!" | sudo -S bash -c "timeout 6 tcpdump -i enp2s0f0 -n -v -c 30 2>&1 &  sleep 1; ping6 -c 3 -W 2 -I enp10s0 240c:c0a9:100f:1::79c2:0a01 2>&1; wait"',
    // 2. 从服务器直接 ping NAT64 合成地址 (看内核选择哪条路由)
    'ip -6 route get 240c:c0a9:100f:1::79c2:0a01 from 2001:da8:20d:40d9::430:1111 2>&1',
    // 3. 抓 enp2s0f0 上 ANY 流量 (包括 NDP, ARP 等)
    'echo "cernet@226!" | sudo -S timeout 5 tcpdump -i enp2s0f0 -n -c 20 2>&1 || true',
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
