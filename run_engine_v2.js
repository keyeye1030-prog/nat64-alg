const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  // Use Generic mode (already compiled into the code)
  const commands = [
    'echo "Cernet@gemini123!" | sudo -S pkill nat64-alg', // Kill any old ones
    'echo "Cernet@gemini123!" | sudo -S ip link set dev ens18 xdp off', // Reset XDP
    'cd /home/work/nat64-alg-src && echo "Cernet@gemini123!" | sudo -S nohup ./nat64-alg -config /home/work/config.json > /home/work/nat64-v2.log 2>&1 &'
  ];
  
  function runNext(index) {
    if (index >= commands.length) {
      console.log('Start command sent');
      setTimeout(() => {
        conn.exec('tail -n 20 /home/work/nat64-v2.log', (err, stream) => {
          if (err) throw err;
          stream.on('close', () => conn.end())
            .on('data', (data) => process.stdout.write(data))
            .stderr.on('data', (data) => process.stderr.write(data));
        });
      }, 5000); // Wait 5s for start
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
