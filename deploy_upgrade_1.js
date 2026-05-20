const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.exec('df -h /boot; rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org && rpm -Uvh https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm', (err, stream) => {
    if (err) throw err;
    stream.on('close', (code, signal) => {
      conn.end();
    }).on('data', (data) => {
      console.log('STDOUT: ' + data);
    }).stderr.on('data', (data) => {
      console.log('STDERR: ' + data);
    });
  });
}).connect({
  host: '192.168.50.18',
  port: 22,
  username: 'root',
  password: 'Cernet@gemini123!'
});
