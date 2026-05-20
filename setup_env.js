const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  const commands = [
    'echo "Cernet@gemini123!" | sudo -S apt-get update',
    'echo "Cernet@gemini123!" | sudo -S apt-get install -y libelf-dev zlib1g-dev ethtool iproute2',
    'echo \'{"mode": "single", "interface": "ens18", "pool_ipv4s": ["101.7.8.9"]}\' > /home/work/config.json'
  ];
  
  function runNext(index) {
    if (index >= commands.length) {
      console.log('All commands finished');
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
  host: '42.247.0.183',
  port: 22,
  username: 'work',
  password: 'Cernet@gemini123!',
  algorithms: {
    kex: ['curve25519-sha256@libssh.org', 'curve25519-sha256', 'ecdh-sha2-nistp256']
  }
});
