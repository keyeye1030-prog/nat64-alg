const { Client } = require('ssh2');
const fs = require('fs');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.sftp((err, sftp) => {
    if (err) throw err;
    const content = fs.readFileSync('xdp/nat64.c');
    const remotePath = '/home/work/nat64.c';
    const stream = sftp.createWriteStream(remotePath);
    stream.on('close', () => {
      console.log('Upload finished');
      conn.end();
    });
    stream.end(content);
  });
}).on('error', (err) => {
  console.log('ERROR: ' + err);
}).connect({
  host: '42.247.0.183',
  port: 22,
  username: 'work',
  password: 'Cernet@gemini123!',
  algorithms: {
    kex: ['curve25519-sha256@libssh.org', 'curve25519-sha256', 'ecdh-sha2-nistp256']
  }
});
