'use strict';

const path = require('node:path');

function assertDatabaseTarget(databaseUrl, { production = process.env.NODE_ENV === 'production' } = {}) {
  const url = String(databaseUrl || '').trim();
  if (!url) throw new Error('TURSO_DATABASE_URL is missing');

  if (url.toLowerCase().includes('nationaltrade-safe-snapshot') &&
    process.env.NT_ALLOW_SNAPSHOT_APP !== 'true') {
  throw new Error(
    'The protected production snapshot cannot be used by this application without explicit approval'
  );
}

  if (production && !/^(?:libsql|https):\/\//i.test(url)) {
    throw new Error('Production requires a remote libSQL database URL');
  }
}

function assertStartupSafety(env = process.env) {
  const production = env.NODE_ENV === 'production';
  assertDatabaseTarget(env.TURSO_DATABASE_URL, { production });

  if (!env.TURSO_AUTH_TOKEN) {
    throw new Error('TURSO_AUTH_TOKEN is missing');
  }
  if (!production) return;

  if (env.PUBLIC_VIRTUAL_MODE !== 'true' || env.DEMO_ONLY_PLATFORM !== 'true' ||
      env.TRADING_DEMO_MODE !== 'true') {
    throw new Error('Production requires the nonredeemable virtual demo platform modes');
  }

  let publicOrigin;
  try {
    publicOrigin = new URL(env.PUBLIC_ORIGIN);
  } catch {
    throw new Error('PUBLIC_ORIGIN must be a valid HTTPS origin');
  }
  if (publicOrigin.protocol !== 'https:' || publicOrigin.origin === 'null' ||
      publicOrigin.pathname !== '/' || publicOrigin.search || publicOrigin.hash ||
      publicOrigin.username || publicOrigin.password) {
    throw new Error('PUBLIC_ORIGIN must be an HTTPS origin without a path or credentials');
  }

  if (String(env.SESSION_SECRET || '').length < 32) {
    throw new Error('Production SESSION_SECRET must be >= 32 chars');
  }
  if (!/^[0-9a-f]{64}$/i.test(env.KYC_DATA_KEY || '')) {
    throw new Error('Production KYC_DATA_KEY must be a 64-hex encryption key');
  }
  const cloudStorageEnabled =
    env.NT_USE_SUPABASE_STORAGE === 'true';

if (cloudStorageEnabled) {
    const url = String(env.SUPABASE_URL || '').trim();
    const secret = String(env.SUPABASE_SECRET_KEY || '').trim();
    const bucket = String(env.SUPABASE_BUCKET || '').trim();

    if (
        !/^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/.test(url) ||
        !secret ||
        bucket !== 'national-trade-private'
    ) {
        throw new Error(
            'Supabase private storage configuration is missing or invalid'
        );
    }
 } else {
  const privateStorageDir = String(env.PRIVATE_STORAGE_DIR || '').trim();
  if (!privateStorageDir) {
    throw new Error(
      'PRIVATE_STORAGE_DIR must point to a mounted persistent private disk in production'
    );
  }
  if (!path.isAbsolute(privateStorageDir)) {
    throw new Error('Production PRIVATE_STORAGE_DIR must be an absolute mount path');
  }

  const publicRoot = path.resolve(__dirname, 'public');
  const storageRoot = path.resolve(privateStorageDir);
  const relativeToPublic = path.relative(publicRoot, storageRoot);
  if (relativeToPublic === '' ||
      (!relativeToPublic.startsWith(`..${path.sep}`) && relativeToPublic !== '..') ||
      path.isAbsolute(relativeToPublic)) {
    throw new Error('PRIVATE_STORAGE_DIR must be outside the public web directory');
  }
}
}

module.exports = { assertDatabaseTarget, assertStartupSafety };
