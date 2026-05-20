const { Client } = require('ssh2');
const fs = require('fs');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.sftp((err, sftp) => {
    if (err) throw err;
    const localFile = 'bin/nat64-alg-linux-amd64';
    const remoteFile = '/tmp/nat64-alg';
    console.log(`Uploading ${localFile} to ${remoteFile}...`);
    sftp.fastPut(localFile, remoteFile, (err) => {
      if (err) throw err;
      console.log('Upload successful');
      conn.exec('echo "Cernet@gemini123!" | sudo -S mv /tmp/nat64-alg /usr/local/bin/nat64-alg && echo "Cernet@gemini123!" | sudo -S chmod +x /usr/local/bin/nat64-alg', (err, stream) => {
        if (err) throw err;
        stream.on('close', (code) => {
          console.log(`Move/Chmod finished with code ${code}`);
          conn.end();
        }).on('data', (data) => console.log('STDOUT: ' + data))
          .stderr.on('data', (data) => console.log('STDERR: ' + data));
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
