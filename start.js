
'use strict';

// Load environment variables before database initialization
try {
  process.loadEnvFile(
    require('node:path').join(__dirname, '.env')
  );
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}

const db = require('./database');

const demoMode =
  process.env.PUBLIC_VIRTUAL_MODE === 'true' &&
  process.env.DEMO_ONLY_PLATFORM === 'true';

if (demoMode) {
  const count = db.prepare(
    'SELECT COUNT(*) AS total FROM admin_users'
  ).get().total;

  if (count === 0) {
    require('node:child_process').execFileSync(
      process.execPath,
      ['create-admin.js'],
      { cwd: __dirname, stdio: 'inherit' }
    );
  }
}

require('./server');
