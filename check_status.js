const { Client } = require('ssh2');
const conn = new Client();

const host = process.env.NAT64_SSH_HOST;
const port = Number(process.env.NAT64_SSH_PORT || 22);
const username = process.env.NAT64_SSH_USER;
const password = process.env.NAT64_SSH_PASSWORD;

if (!host || !username || !password) {
  throw new Error('Set NAT64_SSH_HOST, NAT64_SSH_USER, and NAT64_SSH_PASSWORD before running this script.');
}

conn.on('ready', () => {
  conn.exec('systemctl status nat64-alg --no-pager && journalctl -u nat64-alg --since "10 sec ago" --no-pager', (err, stream) => {
    if (err) throw err;
    stream.on('close', () => conn.end()).on('data', d => process.stdout.write(d)).stderr.on('data', d => process.stderr.write(d));
  });
}).connect({host, port, username, password, algorithms: { kex: ['curve25519-sha256','curve25519-sha256@libssh.org','ecdh-sha2-nistp256'] }});
