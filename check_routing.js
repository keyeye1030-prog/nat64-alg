const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    // 1. 从 NAT64 网关服务器 ping IPv6 上游网关
    'ping6 -c 2 -W 2 1111::1 2>&1 || true',
    // 2. 查看完整 IPv6 路由表
    'ip -6 route show 2>&1',
    // 3. 确认 enp2s0f0 网卡地址
    'ip -6 addr show dev enp2s0f0 2>&1',
    // 4. 确认 enp2s0f0 上是否有 NAT64 前缀的路由
    'ip -6 route get 240c:c0a9:100f:1::1 2>&1 || true',
    // 5. 检查 IPv6 转发是否开启
    'cat /proc/sys/net/ipv6/conf/all/forwarding',
    'cat /proc/sys/net/ipv6/conf/enp2s0f0/forwarding',
  ];
  
  function runNext(index) {
    if (index >= commands.length) { conn.end(); return; }
    console.log(`\n--- [${index}]: ${commands[index]} ---`);
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
