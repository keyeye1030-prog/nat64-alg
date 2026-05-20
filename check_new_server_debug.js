const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.exec('uname -a', (err, stream) => {
    if (err) throw err;
    stream.on('close', () => conn.end()).on('data', (data) => console.log('STDOUT: ' + data));
  });
}).on('error', (err) => {
  console.log('ERROR: ' + err);
}).on('debug', (msg) => {
  console.log('DEBUG: ' + msg);
}).connect({
  host: '42.247.0.183',
  port: 22,
  username: 'root',
  password: 'Cernet@gemini123!',
  algorithms: {
    kex: ['curve25519-sha256@libssh.org', 'curve25519-sha256', 'ecdh-sha2-nistp256']
  }
});
