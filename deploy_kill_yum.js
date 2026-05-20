const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.exec('pkill yum; rm -f /var/run/yum.pid', (err, stream) => {
    if (err) throw err;
    stream.on('close', (code, signal) => {
      console.log('Killed yum with code: ' + code);
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
