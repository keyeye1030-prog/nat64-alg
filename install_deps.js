const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  
  const commands = [
    'echo "cernet@226!" | sudo -S apt-get update',
    'echo "cernet@226!" | sudo -S apt-get install -y golang clang llvm libbpf-dev make gcc ethtool'
  ];
  
  function runNext(index) {
    if (index >= commands.length) {
      console.log('All installations finished');
      conn.end();
      return;
    }
    console.log(`Running: ${commands[index]}`);
    conn.exec(commands[index], (err, stream) => {
      if (err) throw err;
      stream.on('close', (code) => {
        console.log(`Command ${index} finished with code ${code}`);
        runNext(index + 1);
      }).on('data', (data) => process.stdout.write(data))
        .stderr.on('data', (data) => process.stderr.write(data));
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
    kex: [
      'curve25519-sha256',
      'curve25519-sha256@libssh.org',
      'ecdh-sha2-nistp256',
      'diffie-hellman-group14-sha256'
    ]
  }
});
