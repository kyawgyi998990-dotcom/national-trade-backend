'use strict';
// Optional, one-time admin creation for a NEW, isolated virtual-credit database.
// Supply credentials as environment variables at execution time; never commit them.
const db = require('./database');
const bcrypt = require('bcryptjs');
const username = String(process.env.ADMIN_SETUP_USERNAME || '').trim();
const password = String(process.env.ADMIN_SETUP_PASSWORD || '');
(async function main() {
  try {
    if (!/^[A-Za-z0-9._@-]{3,80}$/.test(username)) {
      throw new Error('ADMIN_SETUP_USERNAME must be 3-80 permitted characters');
    }
    if (password.length < 16 || Buffer.byteLength(password, 'utf8') > 72) {
      throw new Error('ADMIN_SETUP_PASSWORD must be at least 16 characters and at most 72 bytes');
    }
    const exists = db.prepare('SELECT id FROM admin_users WHERE username = ?').get(username);
    if (exists) throw new Error('Admin username already exists; existing password was not changed');
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO admin_users(username,password_hash) VALUES(?, ?)').run(username, hash);
    console.log(`Created new virtual-platform admin with id ${result.lastInsertRowid}. Keep credentials private.`);
  } catch (error) {
    console.error('Admin creation not completed:', error.message);
    process.exitCode = 1;
  } finally { db.close(); }
})();
