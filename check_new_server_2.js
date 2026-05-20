const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.exec('uname -r; cat /etc/os-release | grep PRETTY', (err, stream) => {
    if (err) throw err;
    stream.on('close', (code, signal) => {
      conn.end();
    }).on('data', (data) => {
      console.log('STDOUT: ' + data);
    }).stderr.on('data', (data) => {
      console.log('STDERR: ' + data);
    });
  });
}).on('error', (err) => {
  console.log('ERROR: ' + err);
}).on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
  console.log('Keyboard-interactive');
  finish(['Cernet@gemini123!']);
}).connect({
  host: '42.247.0.183',
  port: 22,
  username: 'root',
  password: 'Cernet@gemini123!',
  tryKeyboard: true
});
