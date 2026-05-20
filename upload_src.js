const { Client } = require('ssh2');
const fs = require('fs');
const path = require('path');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.sftp((err, sftp) => {
    if (err) throw err;
    
    const filesToUpload = [
      'go.mod', 'go.sum', 'main.go',
      'engine/xdp.go', 'engine/dual_nic.go',
      'nat64/translator.go', 'nat64/session.go', 'nat64/prefix.go', 'nat64/pipeline.go', 'nat64/mac.go',
      'nat64/ipv4.go', 'nat64/ipv6.go', 'nat64/icmp.go', 'nat64/checksum.go', 'nat64/pool.go'
    ];

    function uploadFile(index) {
      if (index >= filesToUpload.length) {
        console.log('All source files uploaded');
        conn.end();
        return;
      }
      const file = filesToUpload[index];
      const localPath = path.join(__dirname, file);
      const remotePath = path.join('/home/work/nat64-alg-src', file).replace(/\\/g, '/');
      const remoteDir = path.dirname(remotePath);
      
      conn.exec(`mkdir -p ${remoteDir}`, (err, stream) => {
        if (err) throw err;
        stream.on('close', () => {
          console.log(`Uploading ${file}...`);
          sftp.fastPut(localPath, remotePath, (err) => {
            if (err) {
              console.error(`Failed to upload ${file}: ${err}`);
              uploadFile(index + 1);
            } else {
              uploadFile(index + 1);
            }
          });
        });
      });
    }

    uploadFile(0);
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
