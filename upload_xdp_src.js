const { Client } = require('ssh2');
const fs = require('fs');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.sftp((err, sftp) => {
    if (err) throw err;
    const localDir = 'xdp/';
    const remoteDir = '/home/work/xdp/';
    
    conn.exec(`mkdir -p ${remoteDir}`, (err, stream) => {
      if (err) throw err;
      stream.on('close', () => {
        const file = 'nat64.c';
        console.log(`Uploading ${localDir}${file} to ${remoteDir}${file}...`);
        sftp.fastPut(`${localDir}${file}`, `${remoteDir}${file}`, (err) => {
          if (err) throw err;
          console.log('Upload successful');
          conn.end();
        });
      });
    });
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
