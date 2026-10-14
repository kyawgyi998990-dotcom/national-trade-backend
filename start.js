'use strict';

try {
  process.loadEnvFile(
    require('node:path').join(__dirname, '.env')
  );
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}

require('./server').start().catch(error => {
  console.error('Server startup failed:', error);
  process.exitCode = 1;
});
