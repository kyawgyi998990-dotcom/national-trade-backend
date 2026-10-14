'use strict';

try {
  process.loadEnvFile(
    require('node:path').join(__dirname, '.env')
  );
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}

const db = require('./turso-db');
const { validateDatabase } = require('./database');
const bcrypt = require('bcryptjs');
const username = String(process.env.ADMIN_SETUP_USERNAME || '').trim();
const password = String(process.env.ADMIN_SETUP_PASSWORD || '');

(async function main() {
  try {
    if (!process.argv.includes('--bootstrap') ||
        process.env.NT_ALLOW_ADMIN_BOOTSTRAP !== 'true') {
      throw new Error(
        'Admin bootstrap requires --bootstrap and NT_ALLOW_ADMIN_BOOTSTRAP=true'
      );
    }
    if ((process.env.TURSO_DATABASE_URL || '').toLowerCase().includes('nationaltrade-safe-snapshot')) {
      throw new Error('Admin bootstrap is disabled for the protected production snapshot');
    }
    if (!/^[A-Za-z0-9._@-]{3,80}$/.test(username)) {
      throw new Error('ADMIN_SETUP_USERNAME must be 3-80 permitted characters');
    }
    if (password.length < 16 || Buffer.byteLength(password, 'utf8') > 72) {
      throw new Error('ADMIN_SETUP_PASSWORD must be at least 16 characters and at most 72 bytes');
    }

    await validateDatabase(db);
    const hash = await bcrypt.hash(password, 12);
    const result = await db.transaction(async tx => {
      const exists = await tx.get(
        'SELECT id FROM admin_users WHERE username = ?',
        username
      );
      if (exists) {
        throw new Error('Admin username already exists; existing password was not changed');
      }
      return tx.run(
        'INSERT INTO admin_users(username,password_hash) VALUES(?, ?)',
        username,
        hash
      );
    });
    console.log(`Created new virtual-platform admin with id ${result.lastInsertRowid}. Keep credentials private.`);
  } catch (error) {
    console.error('Admin creation not completed:', error.message);
    process.exitCode = 1;
  }
})();
