const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  // Disable problematic repos and try to list kernel-ml
  conn.exec('pkill yum; rm -f /var/run/yum.pid; yum --disablerepo=epel,rpmfusion-free-updates --enablerepo=elrepo-kernel list available kernel-ml', (err, stream) => {
    if (err) throw err;
    stream.on('close', (code, signal) => {
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
