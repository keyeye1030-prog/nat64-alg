const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.exec('curl -s https://mirrors.aliyun.com/elrepo/archive/kernel/el7/x86_64/RPMS/ | grep kernel-ml', (err, stream) => {
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
