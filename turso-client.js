'use strict';

const { createClient } = require('@libsql/client');
const { assertDatabaseTarget } = require('./startup-safety');

assertDatabaseTarget(process.env.TURSO_DATABASE_URL);
if (!process.env.TURSO_AUTH_TOKEN) throw new Error('TURSO_AUTH_TOKEN is missing');

const turso = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN
});

module.exports = turso;