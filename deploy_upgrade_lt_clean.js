const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  // Try kernel-lt with problematic repos disabled
  conn.exec('yum --disablerepo=epel,rpmfusion-free-updates --enablerepo=elrepo-kernel install kernel-lt -y', (err, stream) => {
    if (err) throw err;
    stream.on('close', (code, signal) => {
      console.log('Finished with code: ' + code);
      conn.end();
    }).on('data', (data) => {
      process.stdout.write(data);
    }).stderr.on('data', (data) => {
      process.stderr.write(data);
    });
  });
}).connect({
  host: '192.168.50.18',
  port: 22,
  username: 'root',
  password: 'Cernet@gemini123!'
});
