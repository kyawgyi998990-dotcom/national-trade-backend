'use strict';

try {
  process.loadEnvFile(
    require('node:path').join(__dirname, '.env')
  );
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}

const db = require('./turso-db');
const { migrateDatabase, validateDatabase } = require('./database');

async function main() {
  if (!process.argv.includes('--apply') ||
      process.env.NT_ALLOW_SCHEMA_MIGRATIONS !== 'true') {
    throw new Error(
      'Schema migration requires --apply and NT_ALLOW_SCHEMA_MIGRATIONS=true'
    );
  }
  if ((process.env.TURSO_DATABASE_URL || '').toLowerCase().includes('nationaltrade-safe-snapshot')) {
    throw new Error('Schema migration is disabled for the protected production snapshot');
  }

  await migrateDatabase(db);
  await validateDatabase(db);
  console.log('Turso schema validation passed.');
}

main().catch(error => {
  console.error('Schema migration not completed:', error.message);
  process.exitCode = 1;
}).finally(async () => {
  await db.close();
});
