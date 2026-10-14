'use strict';

process.env.TURSO_DATABASE_URL = 'file::memory:';
process.env.TURSO_AUTH_TOKEN = 'isolated-test-token';
process.env.SESSION_SECRET = 'isolated-test-session-secret-only';
process.env.NODE_ENV = 'test';
process.env.PUBLIC_VIRTUAL_MODE = 'true';
process.env.DEMO_ONLY_PLATFORM = 'true';
process.env.TRADING_DEMO_MODE = 'true';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');
const bcrypt = require('bcryptjs');
const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'national-trade-turso-test-'));
process.env.PRIVATE_STORAGE_DIR = path.join(testRoot, 'private');
process.env.PRIVATE_STORAGE_LEGACY_DIR = path.join(testRoot, 'legacy');
const db = require('../turso-db');
const { migrateDatabase, validateDatabase } = require('../database');
const server = require('../server');

/* TEST ONLY: Capture registration OTP without sending real emails */
const ntOriginalTestFetch = globalThis.fetch;
let ntTestRegistrationOtp = null;

Object.assign(process.env, {
    EMAILJS_PUBLIC_KEY: 'test-public-key',
    EMAILJS_PRIVATE_KEY: 'test-private-key',
    EMAILJS_SERVICE_ID: 'test-service',
    EMAILJS_TEMPLATE_ID: 'test-template'
});

globalThis.fetch = async (url, options) => {
    if (String(url) === 'https://api.emailjs.com/api/v1.0/email/send') {
        assert.equal(process.env.NODE_ENV, 'test');       
        assert.equal(process.env.TURSO_DATABASE_URL, 'file::memory:');

        const payload = JSON.parse(options.body);
        const email = payload.template_params.to_email;
        const code = String(payload.template_params.otp_code);

        assert.match(code, /^[0-9]{6}$/);

        ntTestRegistrationOtp = { email, code };

        return new Response('OK', { status: 200 });
    }

    return ntOriginalTestFetch(url, options);
};

const { createPrivateStorage } = require('../private-storage');
const { assertDatabaseTarget, assertStartupSafety } = require('../startup-safety');

let httpServer;
let baseUrl;
let uploadedProofPath;
const proofDirectory = path.join(testRoot, 'private', 'deposit-uploads');

before(async () => {
  await migrateDatabase(db);
  await server.initialize();
  await db.run(
    'INSERT INTO admin_users(username,password_hash) VALUES(?,?)',
    'isolated-admin',
    await bcrypt.hash('isolated-test-admin-password', 4)
  );
  await new Promise(resolve => {
    httpServer = server.app.listen(0, resolve);
  });
  baseUrl = `http://127.0.0.1:${httpServer.address().port}`;
});

after(async () => {
  if (httpServer) {
    await new Promise((resolve, reject) => {
      httpServer.close(error => error ? reject(error) : resolve());
    });
  }
  if (uploadedProofPath && fs.existsSync(uploadedProofPath)) {
    await fs.promises.unlink(uploadedProofPath);
  }
  await db.close();
  await fs.promises.rm(testRoot, { recursive: true, force: true });
});

test('production startup guards reject unsafe database and storage configuration', () => {
  assert.throws(
    () => assertDatabaseTarget('libsql://nationaltrade-safe-snapshot.turso.io'),
    /protected production snapshot/
  );
  assert.throws(
    () => assertDatabaseTarget('file:production.db', { production: true }),
    /remote libSQL/
  );
  assert.throws(
    () => assertStartupSafety({
      NODE_ENV: 'production',
      TURSO_DATABASE_URL: 'libsql://example.turso.io',
      TURSO_AUTH_TOKEN: 'test-only-token',
      PUBLIC_VIRTUAL_MODE: 'true',
      DEMO_ONLY_PLATFORM: 'true',
      TRADING_DEMO_MODE: 'true',
      PUBLIC_ORIGIN: 'https://example.test/path',
      SESSION_SECRET: 'isolated-test-session-secret-only',
      KYC_DATA_KEY: 'a'.repeat(64),
      PRIVATE_STORAGE_DIR: path.join(__dirname, '..', 'public', 'uploads')
    }),
    /PUBLIC_ORIGIN/
  );
  assert.throws(
    () => assertStartupSafety({
      NODE_ENV: 'production',
      TURSO_DATABASE_URL: 'libsql://example.turso.io',
      TURSO_AUTH_TOKEN: 'test-only-token',
      PUBLIC_VIRTUAL_MODE: 'true',
      DEMO_ONLY_PLATFORM: 'true',
      TRADING_DEMO_MODE: 'true',
      PUBLIC_ORIGIN: 'https://example.test',
      SESSION_SECRET: 'isolated-test-session-secret-only',
      KYC_DATA_KEY: 'a'.repeat(64),
      PRIVATE_STORAGE_DIR: path.join(__dirname, '..', 'public', 'uploads')
    }),
    /outside the public/
  );
  assert.throws(
    () => assertStartupSafety({
      NODE_ENV: 'production',
      TURSO_DATABASE_URL: 'libsql://example.turso.io',
      TURSO_AUTH_TOKEN: 'test-only-token',
      PUBLIC_VIRTUAL_MODE: 'true',
      DEMO_ONLY_PLATFORM: 'true',
      TRADING_DEMO_MODE: 'true',
      PUBLIC_ORIGIN: 'https://example.test',
      SESSION_SECRET: 'isolated-test-session-secret-only',
      KYC_DATA_KEY: 'a'.repeat(64),
      PRIVATE_STORAGE_DIR: 'relative/private-storage'
    }),
    /absolute mount path/
  );
});

test('private storage imports legacy documents without overwriting or deleting source files', async () => {
  const legacyRoot = path.join(testRoot, 'legacy-fixture');
  const storageRoot = path.join(testRoot, 'persistent-fixture');
  const name = '123e4567-e89b-12d3-a456-426614174000.jpg';
  const kycName = '123e4567-e89b-12d3-a456-426614174000-jpg.enc';
  const loanName = '123e4567-e89b-12d3-a456-426614174000-jpg.enc';
  const sourceDirectory = path.join(legacyRoot, 'deposit-uploads');
  const legacyFiles = [
    ['deposit-uploads', name, 'legacy receipt'],
    ['kyc-uploads', kycName, 'legacy KYC document'],
    ['loan-uploads', loanName, 'legacy loan document']
  ];
  for (const [directory, filename, contents] of legacyFiles) {
    const source = path.join(legacyRoot, directory);
    await fs.promises.mkdir(source, { recursive: true });
    await fs.promises.writeFile(path.join(source, filename), contents);
  }

  const storage = createPrivateStorage({
    root: storageRoot,
    legacyRoot,
    production: false
  });
  await storage.initialize();

  for (const [directory, filename, contents] of legacyFiles) {
    const destination = path.join(storage.directories[
      directory === 'deposit-uploads' ? 'deposits' :
        directory === 'kyc-uploads' ? 'kyc' : 'loans'
    ], filename);
    assert.equal(await fs.promises.readFile(destination, 'utf8'), contents);
    assert.equal(
      await fs.promises.readFile(path.join(legacyRoot, directory, filename), 'utf8'),
      contents
    );
  }

  await fs.promises.writeFile(path.join(sourceDirectory, name), 'changed source');
  await storage.initialize();
  assert.equal(
    await fs.promises.readFile(path.join(storage.directories.deposits, name), 'utf8'),
    'legacy receipt'
  );
});

async function post(path, body, cookie) {
  return fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(cookie ? { cookie } : {})
    },
    body: JSON.stringify(body)
  });
}

async function assertStatus(response, expected) {
  if (response.status !== expected) {
    throw new Error(`Expected HTTP ${expected}, got ${response.status}: ${await response.text()}`);
  }
}

async function login(path, credentials) {
  const response = await post(path, credentials);
  await assertStatus(response, 200);
  return response.headers.get('set-cookie').split(';')[0];
}

test('Turso-backed auth, sessions, and financial demo transactions', async () => {
  const tables = await db.all("SELECT name FROM sqlite_master WHERE type='table'");
  for (const table of [
    'users',
    'nt_web_sessions',
    'withdrawal_requests',
    'savings_positions',
    'loan_applications',
    'demo_main_trades'
  ]) {
    assert(tables.some(row => row.name === table), `missing initialized table: ${table}`);
  }
  
/* Request OTP in the isolated test environment */
let response = await post('/api/register/request-otp', {
    email: 'isolated-user@example.test'
});

await assertStatus(response, 200);

const otpCookie = response.headers
    .get('set-cookie')?.split(';')[0];

assert.ok(otpCookie, 'OTP session cookie missing');

assert.equal(
    ntTestRegistrationOtp?.email,
    'isolated-user@example.test'
);

/* Register using the verified test OTP */
response = await post('/api/register', {
    email: 'isolated-user@example.test',
    password: 'isolated-test-password',
    otp: ntTestRegistrationOtp.code
}, otpCookie);

await assertStatus(response, 201);


/* Request a fresh OTP for duplicate registration test */
response = await post('/api/register/request-otp', {
    email: 'isolated-user@example.test'
});

await assertStatus(response, 200);

const duplicateOtpCookie = response.headers
    .get('set-cookie')?.split(';')[0];

assert.ok(
    duplicateOtpCookie,
    'Duplicate OTP cookie missing'
);

/* Duplicate account must still be rejected */
response = await post('/api/register', {
    email: 'isolated-user@example.test',
    password: 'isolated-test-password',
    otp: ntTestRegistrationOtp.code
}, duplicateOtpCookie);

await assertStatus(response, 409);


  const userCookie = await login('/api/login', {
    email: 'isolated-user@example.test',
    password: 'isolated-test-password'
  });
  const adminCookie = await login('/api/admin/login', {
    username: 'isolated-admin',
    password: 'isolated-test-admin-password'
  });

  response = await fetch(`${baseUrl}/api/me`, {
    headers: { cookie: userCookie }
  });
  await assertStatus(response, 200);
  response = await fetch(`${baseUrl}/api/admin/me`, {
    headers: { cookie: adminCookie }
  });
  await assertStatus(response, 200);

  response = await post('/api/kyc/requests', {}, userCookie);
  await assertStatus(response, 201);
  response = await fetch(`${baseUrl}/api/admin/kyc/requests/1/approve`, {
    method: 'PATCH',
    headers: {
      'content-type': 'application/json',
      cookie: adminCookie
    },
    body: JSON.stringify({ accountReviewConfirmed: true })
  });
  await assertStatus(response, 200);

  await db.run(
    'UPDATE wallet_balances SET balance_cents=1000 WHERE user_id=1'
  );

  const withdrawalBody = {
    method: 'Bitcoin (BTC)',
    address: 'isolated-test-address-123',
    amount_cents: 800
  };
  const withdrawals = await Promise.all([
    post('/api/withdrawals', withdrawalBody, userCookie),
    post('/api/withdrawals', withdrawalBody, userCookie)
  ]);
  const withdrawalResponses = await Promise.all(
    withdrawals.map(async result => ({ status: result.status, body: await result.json() }))
  );
  assert.deepEqual(
    withdrawalResponses.map(result => result.status).sort(),
    [201, 409]
  );
  assert.equal(
    (await db.get('SELECT balance_cents FROM wallet_balances WHERE user_id=1')).balance_cents,
    200
  );

  const withdrawal = await db.get(
    "SELECT id FROM withdrawal_requests WHERE user_id=1 AND status='PENDING'"
  );
  response = await fetch(`${baseUrl}/api/admin/withdrawals/${withdrawal.id}/review`, {
    method: 'PATCH',
    headers: {
      'content-type': 'application/json',
      cookie: adminCookie
    },
    body: JSON.stringify({ action: 'REJECTED' })
  });
  await assertStatus(response, 200);
  assert.equal(
    (await db.get('SELECT balance_cents FROM wallet_balances WHERE user_id=1')).balance_cents,
    1000
  );

  const depositForm = new FormData();
  depositForm.append('asset', 'Bitcoin (BTC)');
  depositForm.append('amount_cents', '500');
  depositForm.append(
    'proof',
    new Blob([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])], {
      type: 'image/png'
    }),
    'isolated-proof.png'
  );
  response = await fetch(`${baseUrl}/api/deposits`, {
    method: 'POST',
    headers: { cookie: userCookie },
    body: depositForm
  });
  await assertStatus(response, 201);
  const deposit = await response.json();
  const storedDeposit = await db.get(
    'SELECT proof_path FROM deposit_requests WHERE id=?',
    deposit.deposit.id
  );
  uploadedProofPath = path.join(proofDirectory, storedDeposit.proof_path);
  const approveDeposit = () => fetch(
    `${baseUrl}/api/admin/deposits/${deposit.deposit.id}/review`,
    {
      method: 'PATCH',
      headers: {
        'content-type': 'application/json',
        cookie: adminCookie
      },
      body: JSON.stringify({
        action: 'APPROVED',
        reviewedProof: true,
        testCreditAcknowledged: true
      })
    }
  );
  response = await approveDeposit();
  await assertStatus(response, 200);
  response = await approveDeposit();
  await assertStatus(response, 409);
  assert.equal(
    (await db.get('SELECT balance_cents FROM wallet_balances WHERE user_id=1')).balance_cents,
    1500
  );

  const savingsBody = {
    amount_cents: 500,
    days: 7,
    request_token: 'isolated-savings-token-0001'
  };
  response = await post('/api/savings', savingsBody, userCookie);
  await assertStatus(response, 201);
  const savings = await response.json();
  const replayedSavings = await post('/api/savings', savingsBody, userCookie);
  await assertStatus(replayedSavings, 200);
  assert.equal((await replayedSavings.json()).replayed, true);
  assert.equal(
    (await db.get('SELECT balance_cents FROM wallet_balances WHERE user_id=1')).balance_cents,
    1000
  );
  await db.run(
    'UPDATE savings_positions SET unlock_at_ms=? WHERE id=?',
    Date.now() - 1,
    savings.saving.id
  );
  response = await fetch(`${baseUrl}/api/savings/${savings.saving.id}/claim`, {
    method: 'POST',
    headers: { cookie: userCookie }
  });
  await assertStatus(response, 200);
  response = await fetch(`${baseUrl}/api/savings/${savings.saving.id}/claim`, {
    method: 'POST',
    headers: { cookie: userCookie }
  });
  await assertStatus(response, 409);
  assert.equal(
    (await db.get('SELECT balance_cents FROM wallet_balances WHERE user_id=1')).balance_cents,
    1625
  );

  response = await post('/api/demo-main/trades', {
    asset: 'BTCUSDT',
    direction: 'UP',
    amount_cents: 200,
    entry_price: 100,
    request_token: '00000000-0000-4000-8000-000000000001'
  }, userCookie);
  await assertStatus(response, 201);
  const placed = await response.json();
  const replay = await post('/api/demo-main/trades', {
    asset: 'BTCUSDT',
    direction: 'UP',
    amount_cents: 200,
    entry_price: 100,
    request_token: '00000000-0000-4000-8000-000000000001'
  }, userCookie);
  await assertStatus(replay, 200);
  assert.equal((await replay.json()).duplicate, true);

  await db.run(
    'UPDATE demo_main_trades SET expires_at_ms=? WHERE id=?',
    Date.now() - 1,
    placed.trade_id
  );
  response = await fetch(`${baseUrl}/api/admin/demo-main/trades/${placed.trade_id}/result`, {
    method: 'PATCH',
    headers: {
      'content-type': 'application/json',
      cookie: adminCookie
    },
    body: JSON.stringify({ result: 'WIN' })
  });
  await assertStatus(response, 200);
  assert.equal(
    (await db.get('SELECT balance_cents FROM wallet_balances WHERE user_id=1')).balance_cents,
    1685
  );
  response = await fetch(`${baseUrl}/api/admin/demo-main/trades/${placed.trade_id}/result`, {
    method: 'PATCH',
    headers: {
      'content-type': 'application/json',
      cookie: adminCookie
    },
    body: JSON.stringify({ result: 'WIN' })
  });
  await assertStatus(response, 409);
  response = await post('/api/admin/users/1/adjust-balance', {
    action: 'add',
    amount_cents: 100,
    reason: 'isolated admin adjustment'
  }, adminCookie);
  await assertStatus(response, 200);
  assert.equal(
    (await db.get('SELECT balance_cents FROM wallet_balances WHERE user_id=1')).balance_cents,
    1785
  );
});
