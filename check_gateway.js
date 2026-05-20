const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.exec('ping -c 3 121.194.15.65 && ip neighbor show dev enp2s0f1', (err, stream) => {
    if (err) throw err;
    stream.on('close', (code) => {
      console.log(`Diagnostic finished with exit code ${code}`);
      conn.end();
    }).on('data', (data) => {
      process.stdout.write(data);
    }).stderr.on('data', (data) => {
      process.stderr.write(data);
    });
  });
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
