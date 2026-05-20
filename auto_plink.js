const { spawn } = require('child_process');

const plink = spawn('plink.exe', ['-v', 'root@42.247.0.183', 'uname -a']);

plink.stdout.on('data', (data) => {
  console.log(`STDOUT: ${data}`);
});

plink.stderr.on('data', (data) => {
  const output = data.toString();
  console.log(`STDERR: ${output}`);
  if (output.includes('password:') || output.includes('Password:')) {
    console.log('Sending password...');
    plink.stdin.write('Cernet@gemini123!\n');
  }
  if (output.includes('(y/n)')) {
    console.log('Sending y...');
    plink.stdin.write('y\n');
  }
});

plink.on('close', (code) => {
  console.log(`Process exited with code ${code}`);
});
