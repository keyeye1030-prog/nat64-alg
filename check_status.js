const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.exec('ps aux | grep nat64-alg; ls -l /home/work/nat64.log; tail -n 20 /home/work/nat64.log', (err, stream) => {
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
