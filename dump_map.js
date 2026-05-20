const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  conn.exec('echo "Cernet@gemini123!" | sudo -S bpftool map dump name pool_ips', (err, stream) => {
    if (err) throw err;
    stream.on('close', () => conn.end())
      .on('data', (data) => process.stdout.write(data))
      .stderr.on('data', (data) => process.stderr.write(data));
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
