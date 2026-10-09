
const Database = require("better-sqlite3");

// Create or open SQLite Database
const db = new Database(require('node:path').join(__dirname, 'nationaltrade.db'));

// Database settings
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// Create Users Table
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
`);

 // Create Wallet Balances Table
db.exec(`
    CREATE TABLE IF NOT EXISTS wallet_balances (
        user_id INTEGER PRIMARY KEY,
        balance_cents INTEGER NOT NULL DEFAULT 0
            CHECK (balance_cents >= 0),
        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    )
`);

 // Automatically create wallet for new users
db.exec(`
    CREATE TRIGGER IF NOT EXISTS create_user_wallet
    AFTER INSERT ON users
    BEGIN
        INSERT INTO wallet_balances (
            user_id,
            balance_cents
        )
        VALUES (NEW.id, 0);
    END;
`);

 // Create Admin Accounts Table
db.exec(`
    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
`);

 // Add Block / Unblock status to Users Database
const userColumns = db.prepare("PRAGMA table_info(users)").all();

const hasBlockColumn = userColumns.some(
    column => column.name === "is_blocked"
);

if (!hasBlockColumn) {
    db.exec(`
        ALTER TABLE users
        ADD COLUMN is_blocked INTEGER NOT NULL DEFAULT 0
        CHECK (is_blocked IN (0, 1))
    `);
}

 // Record admin wallet balance adjustments
db.exec(`
    CREATE TABLE IF NOT EXISTS wallet_adjustments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        admin_id INTEGER NOT NULL,
        delta_cents INTEGER NOT NULL
            CHECK (delta_cents != 0),
        balance_before_cents INTEGER NOT NULL,
        balance_after_cents INTEGER NOT NULL
            CHECK (balance_after_cents >= 0),
        reason TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (admin_id) REFERENCES admin_users(id)
    )
`);

 // Track user login session version
const hasAuthVersion = db.prepare("PRAGMA table_info(users)")
    .all()
    .some(column => column.name === "auth_version");

if (!hasAuthVersion) {
    db.exec(`
        ALTER TABLE users
        ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0
    `);
}

 // Deposit Requests Database
db.exec(`
    CREATE TABLE IF NOT EXISTS deposit_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        asset TEXT NOT NULL,
        amount_cents INTEGER NOT NULL
            CHECK (amount_cents > 0),
        proof_path TEXT,
        status TEXT NOT NULL DEFAULT 'PENDING'
            CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        reviewed_by INTEGER,
        reviewed_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (reviewed_by) REFERENCES admin_users(id)
    )
`);

 // Deposit review audit fields (non-destructive migration for older databases).
const depositCols = db.prepare("PRAGMA table_info(deposit_requests)").all();
if (!depositCols.some(c => c.name === "review_txid")) {
    db.exec("ALTER TABLE deposit_requests ADD COLUMN review_txid TEXT");
}
if (!depositCols.some(c => c.name === "review_note")) {
    db.exec("ALTER TABLE deposit_requests ADD COLUMN review_note TEXT");
}
// Never credit the same blockchain transaction twice, across users and assets.
db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_deposit_approved_txid
    ON deposit_requests(lower(review_txid))
    WHERE status = 'APPROVED' AND review_txid IS NOT NULL
`);

// User KYC Verification Status
const kycColumns = db.prepare("PRAGMA table_info(users)").all();

if (!kycColumns.some(column => column.name === "kyc_status")) {
    db.exec(`
        ALTER TABLE users
        ADD COLUMN kyc_status TEXT NOT NULL
        DEFAULT 'UNVERIFIED'
        CHECK (
            kyc_status IN (
                'UNVERIFIED',
                'PENDING',
                'VERIFIED',
                'REJECTED'
            )
        )
    `);
}

 // KYC Verification Requests
db.exec(`
    CREATE TABLE IF NOT EXISTS kyc_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING'
            CHECK (status IN (
                'PENDING',
                'VERIFIED',
                'REJECTED'
            )),
        submitted_at TEXT DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TEXT,
        reviewed_by INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (reviewed_by) REFERENCES admin_users(id)
    );

    CREATE UNIQUE INDEX IF NOT EXISTS
        idx_kyc_one_pending_per_user
    ON kyc_requests(user_id)
    WHERE status = 'PENDING';
`);

 // KYC Document Storage Columns
const kycRequestColumns = db.prepare(
    "PRAGMA table_info(kyc_requests)"
).all();

if (!kycRequestColumns.some(c => c.name === "front_image_path")) {
    db.exec(`
        ALTER TABLE kyc_requests
        ADD COLUMN front_image_path TEXT
    `);
}

if (!kycRequestColumns.some(c => c.name === "back_image_path")) {
    db.exec(`
        ALTER TABLE kyc_requests
        ADD COLUMN back_image_path TEXT
    `);
}

// A separate marker for deliberately fictional sample-review documents.
// Never treat older real-KYC files as mock files or return them from virtual APIs.
const ntMockKycColumns = db.prepare("PRAGMA table_info(kyc_requests)").all();
if (!ntMockKycColumns.some(column => column.name === "is_mock_submission")) {
    db.exec(`ALTER TABLE kyc_requests ADD COLUMN is_mock_submission INTEGER NOT NULL
        DEFAULT 0 CHECK (is_mock_submission IN (0, 1))`);
}

// KYC identity information is encrypted before it is stored (new submissions only).
const kycIdentityColumns = db.prepare("PRAGMA table_info(kyc_requests)").all();
for (const column of ["full_name_enc", "document_number_enc"]) {
    if (!kycIdentityColumns.some(c => c.name === column)) {
        db.exec(`ALTER TABLE kyc_requests ADD COLUMN ${column} TEXT`);
    }
}

// Withdrawal requests are server-authoritative. The available wallet balance is
// reserved (deducted) within the same SQLite transaction as a new request.
db.exec(`
    CREATE TABLE IF NOT EXISTS withdrawal_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        method TEXT NOT NULL,
        address TEXT NOT NULL,
        amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
        status TEXT NOT NULL DEFAULT 'PENDING'
            CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TEXT,
        reviewed_by INTEGER,
        review_note TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (reviewed_by) REFERENCES admin_users(id)
    );
    CREATE INDEX IF NOT EXISTS idx_withdrawals_user
      ON withdrawal_requests(user_id, id DESC);
    CREATE INDEX IF NOT EXISTS idx_withdrawals_pending
      ON withdrawal_requests(status, id DESC);
`);


// Savings positions (localhost test returns only; no live investment yield engine).
// Amounts are stored in integer cents and balances are changed in SQLite transactions.
db.exec(`
    CREATE TABLE IF NOT EXISTS savings_positions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
        duration_days INTEGER NOT NULL CHECK (duration_days IN (7, 15, 20, 30)),
        profit_rate_bps INTEGER NOT NULL CHECK (
           (duration_days = 7 AND profit_rate_bps = 2500) OR
           (duration_days = 15 AND profit_rate_bps = 4000) OR
           (duration_days = 20 AND profit_rate_bps = 5000) OR
           (duration_days = 30 AND profit_rate_bps = 6500)
        ),
        status TEXT NOT NULL DEFAULT 'LOCKED'
            CHECK (status IN ('LOCKED', 'COMPLETED')),
        started_at_ms INTEGER NOT NULL,
        unlock_at_ms INTEGER NOT NULL,
        released_at_ms INTEGER,
        released_by INTEGER,
        release_kind TEXT CHECK (release_kind IN ('USER_CLAIM', 'ADMIN_TEST_RELEASE')),
        payout_cents INTEGER,
        request_token TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (released_by) REFERENCES admin_users(id)
    );
    CREATE INDEX IF NOT EXISTS idx_savings_user ON savings_positions(user_id, id DESC);
    CREATE INDEX IF NOT EXISTS idx_savings_active ON savings_positions(status, unlock_at_ms);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_savings_request_token ON savings_positions(user_id, request_token)
        WHERE request_token IS NOT NULL;
    CREATE TABLE IF NOT EXISTS savings_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        savings_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        admin_id INTEGER,
        action TEXT NOT NULL CHECK (action IN ('LOCK', 'USER_CLAIM', 'ADMIN_TEST_RELEASE')),
        wallet_delta_cents INTEGER NOT NULL,
        created_at_ms INTEGER NOT NULL,
        FOREIGN KEY (savings_id) REFERENCES savings_positions(id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (admin_id) REFERENCES admin_users(id)
    );
`);

// Personal Loan application records. Only the existing loan feature uses these tables.
// IDs and personal names are encrypted; only non-sensitive summaries reach the UI.
db.exec(`
    CREATE TABLE IF NOT EXISTS loan_applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        region TEXT NOT NULL CHECK (region IN ('US','OTHER')),
        tier TEXT,
        amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
        credit_score INTEGER,
        full_name_enc TEXT NOT NULL,
        identity_number_enc TEXT NOT NULL,
        identity_last4 TEXT NOT NULL,
        front_file TEXT NOT NULL,
        back_file TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING'
            CHECK (status IN ('PENDING','APPROVED','REJECTED')),
        request_token TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        reviewed_at_ms INTEGER,
        reviewed_by INTEGER,
        credited_cents INTEGER NOT NULL DEFAULT 0 CHECK (credited_cents >= 0),
        wallet_before_cents INTEGER,
        wallet_after_cents INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (reviewed_by) REFERENCES admin_users(id),
        UNIQUE(user_id, request_token)
    );
    CREATE INDEX IF NOT EXISTS idx_loan_applications_user ON loan_applications(user_id,id DESC);
    CREATE INDEX IF NOT EXISTS idx_loan_applications_status ON loan_applications(status,id DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_loan_one_pending ON loan_applications(user_id)
       WHERE status='PENDING';
    CREATE TABLE IF NOT EXISTS loan_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        loan_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        admin_id INTEGER,
        action TEXT NOT NULL CHECK(action IN ('SUBMITTED','APPROVED_TEST_CREDIT','REJECTED')),
        wallet_delta_cents INTEGER NOT NULL DEFAULT 0,
        created_at_ms INTEGER NOT NULL,
        FOREIGN KEY (loan_id) REFERENCES loan_applications(id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (admin_id) REFERENCES admin_users(id)
    );
`);

// Live Support Chat: shared SQLite message history, not browser localStorage.
// Images are stored as validated JPEG/PNG BLOBs and served only to participants/admins.
db.exec(`
    CREATE TABLE IF NOT EXISTS support_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        sender TEXT NOT NULL CHECK (sender IN ('user', 'admin')),
        admin_id INTEGER,
        message_text TEXT NOT NULL DEFAULT '',
        image_mime TEXT CHECK (image_mime IN ('image/jpeg','image/png') OR image_mime IS NULL),
        image_blob BLOB,
        created_at_ms INTEGER NOT NULL,
        edited_at_ms INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (admin_id) REFERENCES admin_users(id),
        CHECK (length(message_text) > 0 OR image_blob IS NOT NULL)
    );
    CREATE INDEX IF NOT EXISTS idx_support_messages_user ON support_messages(user_id,id DESC);
    CREATE INDEX IF NOT EXISTS idx_support_messages_created ON support_messages(created_at_ms DESC);
`);


// DEMO-ONLY Trading — the existing wallet_balances is the shared DEMO Main Balance.
// These are SIMULATED entries, NOT executed cryptocurrency or cash transactions.
db.exec(`
 CREATE TABLE IF NOT EXISTS demo_main_trades (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
   asset TEXT NOT NULL CHECK(asset IN ('BTCUSDT','XAUUSD')),
   direction TEXT NOT NULL CHECK(direction IN ('UP','DOWN')),
   amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
   entry_price REAL NOT NULL CHECK(entry_price > 0),
   closing_price REAL,
   result_source TEXT CHECK(result_source IN ('ADMIN_DEMO','BROWSER_INDICATIVE') OR result_source IS NULL),
   chosen_result TEXT CHECK(chosen_result IN ('WIN','LOSS') OR chosen_result IS NULL),
   status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','WIN','LOSS')),
   profit_cents INTEGER NOT NULL DEFAULT 0 CHECK(profit_cents >= 0),
   created_at_ms INTEGER NOT NULL,
   expires_at_ms INTEGER NOT NULL,
   settled_at_ms INTEGER,
   settled_by INTEGER REFERENCES admin_users(id),
   request_token TEXT NOT NULL,
   UNIQUE(user_id, request_token)
 );
 CREATE INDEX IF NOT EXISTS idx_demo_main_trades_user ON demo_main_trades(user_id,id DESC);
 CREATE INDEX IF NOT EXISTS idx_demo_main_trades_open ON demo_main_trades(status,expires_at_ms);
 CREATE TABLE IF NOT EXISTS demo_main_trade_audit (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   trade_id INTEGER NOT NULL REFERENCES demo_main_trades(id),
   user_id INTEGER NOT NULL REFERENCES users(id),
   admin_id INTEGER REFERENCES admin_users(id),
   action TEXT NOT NULL CHECK(action IN ('STAKE','ADMIN_CHOOSE_WIN','ADMIN_CHOOSE_LOSS','WIN','LOSS')),
   wallet_delta_cents INTEGER NOT NULL,
   created_at_ms INTEGER NOT NULL
 );
`);

console.log("National Trade Database Ready!");

module.exports = db;
