const { Client } = require('ssh2');

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  // Enable elrepo-kernel and use a direct baseurl (Rackspace is usually reliable)
  const cmd = `
    sed -i '/\\[elrepo-kernel\\]/,/\\[/ s/enabled=0/enabled=1/' /etc/yum.repos.d/elrepo.repo
    sed -i '/\\[elrepo-kernel\\]/,/\\[/ s/mirrorlist=/#mirrorlist=/' /etc/yum.repos.d/elrepo.repo
    yum clean all && yum makecache
  `;
  conn.exec(cmd, (err, stream) => {
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
