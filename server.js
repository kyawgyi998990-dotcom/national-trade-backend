
const express = require("express");

const app = express();

app.use(express.json());

// Read local .env when present; hosting providers may inject environment variables.
try { process.loadEnvFile(require("node:path").join(__dirname, ".env")); }
catch (e) { if (e.code !== 'ENOENT') throw e; }
const { assertStartupSafety } = require("./startup-safety");
assertStartupSafety();
const db = require("./turso-db");
const { validateDatabase } = require("./database");
const privateStorage = require("./private-storage");
const useSupabaseStorage =
    process.env.NT_USE_SUPABASE_STORAGE === "true";

const supabaseStorage = useSupabaseStorage
    ? require("./supabase-storage")
    : null;
const ntPublicVirtual = process.env.PUBLIC_VIRTUAL_MODE === 'true' &&
    process.env.DEMO_ONLY_PLATFORM === 'true';
if (process.env.PUBLIC_VIRTUAL_MODE === 'true' && !ntPublicVirtual) {
    throw new Error('PUBLIC_VIRTUAL_MODE requires DEMO_ONLY_PLATFORM=true');
}
if (ntPublicVirtual && process.env.TRADING_DEMO_MODE !== 'true') {
    throw new Error('Public virtual mode requires TRADING_DEMO_MODE=true');
}
app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 1 : false);

const session = require("express-session");
const TursoSessionStore = require("./turso-session-store");

const sessionStore = new TursoSessionStore({
    client: require("./turso-client")
});

if (!process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET is missing");
}

// Login Session Configuration
app.use(session({
    name: "nt.sid",

    store: sessionStore,

    secret: process.env.SESSION_SECRET,

    resave: false,
    saveUninitialized: false,

    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 2 * 60 * 60 * 1000
    }
}));

// Production mutation requests must originate from this site's own HTTPS origin.
app.use('/api', async (req, res, next) => {
    if (process.env.NODE_ENV !== 'production' || !['POST','PUT','PATCH','DELETE'].includes(req.method)) return next();
    const origin = req.get('origin');
    const siteOrigin = process.env.PUBLIC_ORIGIN;
    if (!siteOrigin || origin !== siteOrigin) {
        return res.status(403).json({ message: 'Same-origin request required' });
    }
    return next();
});
app.get('/api/public-mode', async (_req, res) => {
    res.set('Cache-Control','no-store').json({virtualCredits: ntPublicVirtual, cashValue: false, realTransfers: false});
});
app.use(express.static(require("node:path").join(__dirname, "public")));
  
app.get("/", async (req, res) => {
    res.send("National Trade Backend Server is Running!");
});

app.get("/api/health", async (req, res) => {
    try {
        await db.get("SELECT 1");

        res.json({
            server: "running",
            database: "connected"
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            server: "running",
            database: "error"
        });
    }
});

const bcrypt = require("bcryptjs");
// National Trade - Secure Registration OTP Helpers
const ntOtpCrypto = require("node:crypto");

const NT_OTP_EXPIRY_MS = 10 * 60 * 1000;
const NT_OTP_MAX_ATTEMPTS = 5;

function ntHashRegistrationOtp(email, code) {
    return ntOtpCrypto
        .createHmac("sha256", process.env.SESSION_SECRET)
        .update(`register:${email}:${code}`)
        .digest("hex");
}

function ntCheckRegistrationOtp(email, code, storedHash) {
    if (
        typeof code !== "string" ||
        !/^[0-9]{6}$/.test(code) ||
        typeof storedHash !== "string" ||
        !/^[0-9a-f]{64}$/.test(storedHash)
    ) {
        return false;
    }

    const receivedHash = Buffer.from(
        ntHashRegistrationOtp(email, code),
        "hex"
    );

    const expectedHash = Buffer.from(storedHash, "hex");

    return ntOtpCrypto.timingSafeEqual(
        receivedHash,
        expectedHash
    );
}
// National Trade - Server-side OTP Email Sender
async function ntSendRegistrationOtpEmail(email, otpCode) {
    const publicKey = process.env.EMAILJS_PUBLIC_KEY;
    const privateKey = process.env.EMAILJS_PRIVATE_KEY;
    const serviceId = process.env.EMAILJS_SERVICE_ID;
    const templateId = process.env.EMAILJS_TEMPLATE_ID;

    if (!publicKey || !privateKey || !serviceId || !templateId) {
        throw new Error("EmailJS server configuration is missing");
    }

    const response = await fetch(
        "https://api.emailjs.com/api/v1.0/email/send",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                service_id: serviceId,
                template_id: templateId,
                user_id: publicKey,
                accessToken: privateKey,
                template_params: {
                    to_email: email,
                    otp_code: otpCode
                }
            }),
            signal: AbortSignal.timeout(15000)
        }
    );

    if (!response.ok) {
        throw new Error(
            `OTP email delivery failed (${response.status})`
        );
    }
}
function ntIsUniqueConstraintError(error) {
    return error?.extendedCode === "SQLITE_CONSTRAINT_UNIQUE" ||
        error?.code === "SQLITE_CONSTRAINT_UNIQUE" ||
        error?.cause?.code === "SQLITE_CONSTRAINT_UNIQUE";
}

// Basic per-process authentication throttling (also configure a reverse-proxy/WAF limiter).
const ntLoginAttempts = new Map();
function ntAuthThrottle(req,res,next) {
    const now=Date.now(), key=(req.ip||req.socket?.remoteAddress||'unknown')+'|'+req.path;
    const prior=ntLoginAttempts.get(key) || {start:now,count:0};
    if (now-prior.start>15*60*1000) {prior.start=now;prior.count=0;}
    if (++prior.count>15) return res.status(429).json({message:'Too many requests. Please try later.'});
    ntLoginAttempts.set(key,prior);next();
}
app.use(['/api/login','/api/register','/api/admin/login'],ntAuthThrottle);
// National Trade - Request Registration OTP
app.post("/api/register/request-otp", async (req, res) => {
    const email =
        typeof req.body?.email === "string"
            ? req.body.email.trim().toLowerCase()
            : "";

    if (
        email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
        return res.status(400).json({
            message: "Please enter a valid email address."
        });
    }

    const now = Date.now();
    const previous = req.session.ntRegistrationOtp;

    // Allow another OTP only after 60 seconds.
    if (
        previous?.lastSentAt &&
        now - previous.lastSentAt < 60_000
    ) {
        return res.status(429).json({
            message: "Please wait 60 seconds before requesting another code."
        });
    }

    // Maximum 5 successful OTP requests per session per hour.
    const sameWindow =
        previous?.windowStart &&
        now - previous.windowStart < 60 * 60 * 1000;

    const windowStart = sameWindow
        ? previous.windowStart
        : now;

    const sentCount = sameWindow
        ? previous.sentCount || 0
        : 0;

    if (sentCount >= 5) {
        return res.status(429).json({
            message: "Too many OTP requests. Please try again later."
        });
    }

    const otpCode = ntOtpCrypto
        .randomInt(100000, 1000000)
        .toString();

    try {
        // Send the code using EmailJS from the backend.
        await ntSendRegistrationOtpEmail(email, otpCode);

        const sentAt = Date.now();

        // Store only the OTP hash, not the plain code.
        req.session.ntRegistrationOtp = {
            email: email,
            hash: ntHashRegistrationOtp(email, otpCode),
            expiresAt: sentAt + NT_OTP_EXPIRY_MS,
            attempts: 0,
            lastSentAt: sentAt,
            windowStart: windowStart,
            sentCount: sentCount + 1
        };

        await new Promise((resolve, reject) => {
            req.session.save(error => {
                if (error) reject(error);
                else resolve();
            });
        });

        return res.status(200).json({
            message: "Verification code sent to your email."
        });

    } catch (error) {
        console.error("Registration OTP error:", error.message);

        return res.status(502).json({
            message: "Unable to send verification code. Please try again."
        });
    }
});

// User Registration API
app.post("/api/register", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (
            typeof email !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                message: "Email and password are required"
            });
        }

        const userEmail = email.trim().toLowerCase();

        if (
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(userEmail) ||
            userEmail.length > 254
        ) {
            return res.status(400).json({
                message: "Invalid email address"
            });
        }

        if (
            password.length < 12 ||
            Buffer.byteLength(password, "utf8") > 72
        ) {
            return res.status(400).json({
                message: "Password must be at least 12 characters and at most 72 bytes"
            });
        }
        // National Trade - Verify OTP before registration
const otp = req.body?.otp;
const pendingOtp = req.session?.ntRegistrationOtp;

if (
    !pendingOtp ||
    pendingOtp.email !== userEmail ||
    !Number.isSafeInteger(pendingOtp.expiresAt) ||
    Date.now() >= pendingOtp.expiresAt ||
    pendingOtp.attempts >= NT_OTP_MAX_ATTEMPTS ||
    !pendingOtp.hash
) {
    return res.status(400).json({
        message: "Verification code is missing, expired or invalid. Please request a new code."
    });
}

const otpValid = ntCheckRegistrationOtp(
    userEmail,
    otp,
    pendingOtp.hash
);

if (!otpValid) {
    pendingOtp.attempts =
        Number(pendingOtp.attempts || 0) + 1;

    if (pendingOtp.attempts >= NT_OTP_MAX_ATTEMPTS) {
        pendingOtp.hash = null;
    }

    await new Promise((resolve, reject) => {
        req.session.save(error => {
            if (error) reject(error);
            else resolve();
        });
    });

    return res.status(400).json({
        message: "Incorrect verification code. Please check your email."
    });
}

// OTP verified. Consume it so it cannot be reused.
// Keep send counters for rate limiting.
pendingOtp.hash = null;
pendingOtp.email = null;
pendingOtp.expiresAt = 0;

await new Promise((resolve, reject) => {
    req.session.save(error => {
        if (error) reject(error);
        else resolve();
    });
});
        const hashedPassword = await bcrypt.hash(password, 12);

        const result = await db.run(`
            INSERT INTO users (email, password_hash)
            VALUES (?, ?)
        `, userEmail, hashedPassword);

        res.status(201).json({
            message: "Account created successfully",
            user: {
                id: Number(result.lastInsertRowid),
                email: userEmail
            }
        });

    } catch (error) {
        if (ntIsUniqueConstraintError(error)) {
            return res.status(409).json({
                message: "Account already exists"
            });
        }

        console.error(error);

        res.status(500).json({
            message: "Registration failed"
        });
    }
});

 // User Login API
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (
            typeof email !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                message: "Email and password are required"
            });
        }

        const userEmail = email.trim().toLowerCase();

        // Find user in database
        const user = await db.get(`
            SELECT id, email, password_hash
            FROM users
            WHERE email = ?
        `, userEmail);

        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        // Check password
        const passwordMatch = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        // Login credentials verified
       
            
 // Check if user account is blocked
const accountStatus = await db.get("SELECT is_blocked FROM users WHERE id = ?", user.id);

if (accountStatus?.is_blocked === 1) {
    return res.status(403).json({
        message: "Your account has been blocked. Please contact support."
    });
}

        // Create a fresh login session
        await new Promise((resolve, reject) => {
            req.session.regenerate((err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        // Store the logged-in user's ID
        req.session.userId = user.id;
        
const versionRow = await db.get("SELECT auth_version FROM users WHERE id = ?", user.id);
req.session.authVersion = versionRow.auth_version;

        // Save the login session to Turso.
        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        res.status(200).json({
            message: "Login successful",
            user: {
                id: user.id,
                email: user.email
            }
        });


    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Login failed"
        });
    }
});

 // Check Logged-in User
 
 // Check blocked users on existing sessions
app.use(["/api/me", "/api/wallet"], async (req, res, next) => {
    const userId = req.session?.userId;

    if (!userId) {
        return next();
    }

    try {
        const user = await db.get("SELECT is_blocked, auth_version FROM users WHERE id = ?", userId);

        if (
    !user ||
    user.is_blocked === 1 ||
    req.session.authVersion !== user.auth_version
) {
            return req.session.destroy((error) => {
                if (error) {
                    return res.status(500).json({
                        message: "Session expired or account blocked. Please log in again."
                    });
                }

                res.clearCookie("nt.sid");

                return res.status(403).json({
                    message: "Your account has been blocked. Please contact support."
                });
            });
        }

        next();

    } catch (error) {
        console.error("Block Check Error:", error);

        res.status(500).json({
            message: "Server error"
        });
    }
});

app.get("/api/me", async (req, res) => {

    // Check login session
    if (!req.session.userId) {
        return res.status(401).json({
            message: "Please login first"
        });
    }

    // Get user from database
    const user = await db.get(`
        SELECT id, email
        FROM users
        WHERE id = ?
    `, req.session.userId);

    if (!user) {
        return res.status(401).json({
            message: "User not found"
        });
    }

    res.json({
        message: "User authenticated",
        user: user
    });
});

 // User Logout API
app.post("/api/logout", async (req, res) => {

    // Delete login session
    req.session.destroy((error) => {

        if (error) {
            console.error(error);

            return res.status(500).json({
                message: "Logout failed"
            });
        }

        // Remove session cookie
        res.clearCookie("nt.sid", {
            path: "/",
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax"
        });

        res.status(200).json({
            message: "Logout successful"
        });

    });
});

 // Get Logged-in User Wallet Balance
app.get("/api/wallet", async (req, res) => {

    // Check login session
    if (!req.session?.userId) {
        return res.status(401).json({
            message: "Please login first"
        });
    }

    try {
        // Get the wallet balance from Turso.
        const wallet = await db.get(`
            SELECT balance_cents
            FROM wallet_balances
            WHERE user_id = ?
        `, req.session.userId);

        if (!wallet) {
            return res.status(404).json({
                message: "Wallet not found"
            });
        }

        res.set("Cache-Control", "no-store");

        res.json({
            message: "Wallet loaded successfully",
            balance_cents: wallet.balance_cents,
            balance_usd: (wallet.balance_cents / 100).toFixed(2)
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Failed to load wallet"
        });
    }
});

 // Admin Login API
app.post("/api/admin/login", async (req, res) => {
    const { username, password } = req.body || {};

    if (
        typeof username !== "string" ||
        typeof password !== "string" ||
        !username.trim() ||
        !password
    ) {
        return res.status(400).json({
            message: "Username and password are required"
        });
    }

    try {
        const admin = await db.get(`
            SELECT id, username, password_hash
            FROM admin_users
            WHERE username = ?
        `, username.trim());

        const bcrypt = require("bcryptjs");

        if (
            !admin ||
            !(await bcrypt.compare(password, admin.password_hash))
        ) {
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }

        req.session.regenerate((error) => {
            if (error) {
                return res.status(500).json({
                    message: "Admin login failed"
                });
            }

            req.session.adminId = admin.id;

            req.session.save((error) => {
                if (error) {
                    return res.status(500).json({
                        message: "Session save failed"
                    });
                }

                res.json({
                    message: "Admin login successful",
                    admin: {
                        username: admin.username
                    }
                });
            });
        });

    } catch (error) {
        console.error("Admin login error:", error);

        res.status(500).json({
            message: "Server error"
        });
    }
});

 // Check Admin Login Session
app.get("/api/admin/me", async (req, res) => {

    if (!req.session?.adminId) {
        return res.status(401).json({
            message: "Admin login required"
        });
    }

    try {
        const admin = await db.get(`
            SELECT id, username
            FROM admin_users
            WHERE id = ?
        `, req.session.adminId);

        if (!admin) {
            return res.status(401).json({
                message: "Admin session invalid"
            });
        }

        res.set("Cache-Control", "no-store");

        res.json({
            message: "Admin session active",
            admin: {
                id: admin.id,
                username: admin.username
            }
        });

    } catch (error) {
        console.error("Admin session error:", error);

        res.status(500).json({
            message: "Server error"
        });
    }
});

 // Separate admin entry route: login form is public; dashboard actions remain session-protected.
app.get('/admin-login.html', async (_req, res) => {
    res.set('Cache-Control','no-store');
    res.sendFile(require('node:path').join(__dirname,'private','admin.html'));
});

// Protected Admin Dashboard
app.get("/admin", async (req, res) => {

    if (!req.session?.adminId) {
        return res.status(401).send("Admin login required");
    }

    const admin = await db.get("SELECT id FROM admin_users WHERE id = ?", req.session.adminId);

    if (!admin) {
        return res.status(401).send("Admin session invalid");
    }

    res.set("Cache-Control", "no-store");

    res.sendFile(
        require("node:path").join(__dirname, "private", "admin.html")
    );
});

 // Admin - Get All Registered Users
app.get("/api/admin/users", async (req, res) => {

    if (!req.session?.adminId) {
        return res.status(401).json({
            message: "Admin login required"
        });
    }

    try {
        const admin = await db.get("SELECT id FROM admin_users WHERE id = ?", req.session.adminId);

        if (!admin) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        const users = await db.all(`
            SELECT
    u.id,
    u.email,
    u.created_at,
    u.is_blocked,
    u.kyc_status,
    COALESCE(w.balance_cents, 0) AS balance_cents
            FROM users u
            LEFT JOIN wallet_balances w
                ON w.user_id = u.id
            ORDER BY u.id DESC
        `);

        res.set("Cache-Control", "no-store");

        res.json({
            message: "Users loaded successfully",
            users: users
        });

    } catch (error) {
        console.error("Admin users error:", error);

        res.status(500).json({
            message: "Failed to load users"
        });
    }
});

 // Admin Block / Unblock User API
app.patch("/api/admin/users/:id/block", async (req, res) => {
    if (!req.session?.adminId) {
        return res.status(401).json({
            message: "Admin login required"
        });
    }

    try {
        const admin = await db.get("SELECT id FROM admin_users WHERE id = ?", req.session.adminId);

        if (!admin) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        const userId = Number(req.params.id);
        const { blocked } = req.body || {};

        if (
            !Number.isSafeInteger(userId) ||
            userId <= 0 ||
            typeof blocked !== "boolean"
        ) {
            return res.status(400).json({
                message: "Invalid request"
            });
        }

        const result = await db.run(`
            UPDATE users
            SET is_blocked = ?
            WHERE id = ?
        `, blocked ? 1 : 0, userId);

        if (result.changes === 0) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        res.json({
            message: blocked ? "User blocked" : "User unblocked",
            user_id: userId,
            is_blocked: blocked
        });

    } catch (error) {
        console.error("Block User Error:", error);
        res.status(500).json({
            message: "Server error"
        });
    }
});

 // Admin Add / Deduct Wallet Balance
app.post("/api/admin/users/:id/adjust-balance", async (req, res) => {

    if (!req.session?.adminId) {
        return res.status(401).json({
            message: "Admin login required"
        });
    }

    try {
        const admin = await db.get("SELECT id FROM admin_users WHERE id = ?", req.session.adminId);

        if (!admin) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        const userId = Number(req.params.id);
        const { action, amount_cents, reason } = req.body || {};

        if (
            !Number.isSafeInteger(userId) ||
            userId <= 0 ||
            !["add", "deduct"].includes(action) ||
            !Number.isSafeInteger(amount_cents) ||
            amount_cents <= 0 ||
            typeof reason !== "string" ||
            !reason.trim() ||
            reason.length > 200
        ) {
            return res.status(400).json({
                message: "Invalid balance adjustment"
            });
        }

        const adjustBalance = await db.transaction(async tx => {

            const wallet = await tx.get(`
                SELECT balance_cents
                FROM wallet_balances
                WHERE user_id = ?
            `, userId);

            if (!wallet) {
                return {
                    error: "User wallet not found",
                    status: 404
                };
            }

            const before = wallet.balance_cents;

            const delta = action === "add"
                ? amount_cents
                : -amount_cents;

            const after = before + delta;

            if (!Number.isSafeInteger(after) || after < 0) {
                return {
                    error: "Insufficient balance or invalid amount",
                    status: 400
                };
            }

            await tx.run(`
                UPDATE wallet_balances
                SET balance_cents = ?
                WHERE user_id = ?
            `, after, userId);

            await tx.run(`
                INSERT INTO wallet_adjustments (
                    user_id,
                    admin_id,
                    delta_cents,
                    balance_before_cents,
                    balance_after_cents,
                    reason
                )
                VALUES (?, ?, ?, ?, ?, ?)
            `, userId,
                admin.id,
                delta,
                before,
                after,
                reason.trim());

            return {
                balance_cents: after
            };
        });

        const result = adjustBalance;

        if (result.error) {
            return res.status(result.status).json({
                message: result.error
            });
        }

        res.set("Cache-Control", "no-store");

        res.json({
            message: "Balance updated successfully",
            balance_cents: result.balance_cents,
            balance_usd: (result.balance_cents / 100).toFixed(2)
        });

    } catch (error) {
        console.error("Balance Adjustment Error:", error);

        res.status(500).json({
            message: "Failed to update balance"
        });
    }
});

 // Admin Edit User Account
app.patch("/api/admin/users/:id/edit", async (req, res) => {
    if (!req.session?.adminId) {
        return res.status(401).json({
            message: "Admin login required"
        });
    }

    try {
        const admin = await db.get("SELECT id FROM admin_users WHERE id = ?", req.session.adminId);

        if (!admin) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        const userId = Number(req.params.id);
        const { email, newPassword } = req.body || {};

        if (!Number.isSafeInteger(userId) || userId <= 0 ||
            typeof email !== "string") {
            return res.status(400).json({
                message: "Invalid user"
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        if (
            cleanEmail.length > 254 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
        ) {
            return res.status(400).json({
                message: "Invalid email"
            });
        }

        const user = await db.get("SELECT id, password_hash FROM users WHERE id = ?", userId);

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        let passwordHash = user.password_hash;

        if (newPassword !== undefined && newPassword !== "") {
            if (typeof newPassword !== "string" ||
                newPassword.length < 12 ||
                newPassword.length > 128) {
                return res.status(400).json({
                    message: "New password must be 12-128 characters"
                });
            }

            passwordHash = await require("bcryptjs").hash(
                newPassword, 12
            );
        }

        
await db.run(`
    UPDATE users
    SET email = ?,
        password_hash = ?,
        auth_version = auth_version + ?
    WHERE id = ?
`, cleanEmail,
    passwordHash,
    newPassword ? 1 : 0,
    userId);


        res.json({
            message: "User updated successfully"
        });

    } catch (error) {
        if (ntIsUniqueConstraintError(error)) {
            return res.status(409).json({
                message: "Email already exists"
            });
        }

        console.error("Edit User Error:", error);
        res.status(500).json({
            message: "Failed to update user"
        });
    }
});

 // Deposit request / private proof / status workflow
// NOTE: A screenshot is not proof of settled cryptocurrency. Only independently
// confirmed transfers may be credited, and test credits are local-only.
const depositMulter = require("multer");
const depositFs = require("node:fs");
const depositPath = require("node:path");
const depositCrypto = require("node:crypto");
const depositProofDir = privateStorage.directories.deposits;
const depositUpload = depositMulter({
    storage: depositMulter.memoryStorage(),
    limits: { fileSize: 3 * 1024 * 1024, files: 1, fields: 2 },
    fileFilter(_req, file, callback) {
        if (!["image/jpeg", "image/png"].includes(file.mimetype)) {
            return callback(new Error("Only JPG or PNG receipt images are accepted"));
        }
        callback(null, true);
    }
}).single("proof");

async function validateDepositUser(req, res) {
    if (!req.session?.userId) {
        res.status(401).json({ message: "Please log in first" }); return null;
    }
    const user = await db.get(`
        SELECT id, is_blocked, auth_version, kyc_status
        FROM users WHERE id = ?
    `, req.session.userId);
    if (!user || user.is_blocked === 1 ||
        req.session.authVersion !== user.auth_version) {
        res.status(403).json({ message: "Account blocked or session expired" }); return null;
    }
    return user;
}
async function validateDepositAdmin(req, res) {
    if (!req.session?.adminId) {
        res.status(401).json({ message: "Admin login required" }); return null;
    }
    const admin = await db.get("SELECT id FROM admin_users WHERE id = ?", req.session.adminId);
    if (!admin) {
        res.status(403).json({ message: "Access denied" }); return null;
    }
    return admin;
}
function receiptExtension(file) {
    const b = file?.buffer;
    if (!b) return null;
    if (file.mimetype === "image/jpeg" && b.length >= 3 &&
        b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return ".jpg";
    if (file.mimetype === "image/png" && b.length >= 8 &&
        b.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return ".png";
    return null;
}

// Submit a PENDING request; do not change the wallet balance here.
app.post("/api/deposits", async (req, res) => {
    const user = await validateDepositUser(req, res);
    if (!user) return;
    if (user.kyc_status !== "VERIFIED") {
        return res.status(403).json({ message: "KYC verification required before depositing" });
    }
    // Public virtual requests never represent a blockchain transfer or real deposit.
    if (process.env.NODE_ENV === 'production' && !ntPublicVirtual) {
        return res.status(503).json({message:'Real-money deposits are not supported by this website'});
    }
    depositUpload(req, res, async (uploadError) => {
        if (uploadError) {
            return res.status(400).json({ message: uploadError.message });
        }
        const { asset, amount_cents } = req.body || {};
        // Multipart sends strings; require the exact unsigned-integer format.
        const amountCents = typeof amount_cents === "string" &&
            /^\d{1,10}$/.test(amount_cents) ? Number(amount_cents) : NaN;
        if (!["USDT (TRC20)", "Bitcoin (BTC)", "Ethereum (ETH)"].includes(asset) ||
            !Number.isSafeInteger(amountCents) || amountCents <= 0 ||
            amountCents > 1000000000) {
            return res.status(400).json({ message: "Invalid deposit details" });
        }
        // Public virtual credit requests have no real-world receipt or wallet transfer.
        // In virtual mode, an optional illustrative image can be reviewed by admin.
        // It does NOT verify a transfer or determine a real-money balance.
        const ext = req.file ? receiptExtension(req.file) : null;
        if (req.file && !ext) {
            return res.status(400).json({ message: "Invalid JPG or PNG example image" });
        }
        if (!ext) {
    return res.status(400).json({
        message: "A JPG or PNG receipt image is required for deposit requests"
    });
}
        let proofFilename = null;
        let proofSaved = false;
        try {
            if (ext) {
    proofFilename = depositCrypto.randomUUID() + ext;

    if (useSupabaseStorage) {
        await supabaseStorage.save(
            "deposits",
            proofFilename,
            req.file.buffer
        );
    } else {
        depositFs.mkdirSync(depositProofDir, {
            recursive: true,
            mode: 0o700
        });

        depositFs.writeFileSync(
            depositPath.join(depositProofDir, proofFilename),
            req.file.buffer,
            { flag: "wx", mode: 0o600 }
        );
    }
    proofSaved = true;
}
            const result = await db.run(`
                INSERT INTO deposit_requests (user_id, asset, amount_cents, proof_path, status)
                VALUES (?, ?, ?, ?, 'PENDING')
            `, user.id, asset, amountCents, proofFilename);
            res.set("Cache-Control", "no-store");
            return res.status(201).json({
                message: ntPublicVirtual ? 'Virtual-credit request submitted for admin review. No payment was made.' :
                    'Deposit proof submitted for review. Payment not yet verified.', 
                deposit: { id: String(result.lastInsertRowid), asset,
                    amount_cents: amountCents, status: "PENDING" }
            });
        } catch (error) {
            if (proofSaved) {
    try {
        if (useSupabaseStorage) {
            await supabaseStorage.remove("deposits", proofFilename);
        } else {
            depositFs.unlinkSync(
                depositPath.join(depositProofDir, proofFilename)
            );
        }
    } catch (cleanupError) {
        console.error("Deposit proof cleanup failed:", cleanupError.message);
    }
}
            console.error("Deposit Request Error:", error);
            return res.status(500).json({ message: "Failed to submit deposit proof" });
        }
    });
});

// Turso history: the browser's old localStorage history is not authoritative.
app.get("/api/deposits", async (req, res) => {
    const user = await validateDepositUser(req, res);
    if (!user) return;
    try {
        const deposits = await db.all(`
            SELECT id, asset, amount_cents, status, created_at, reviewed_at
            FROM deposit_requests WHERE user_id = ? ORDER BY id DESC LIMIT 100
        `, user.id);
        res.set("Cache-Control", "no-store");
        res.json({ deposits: deposits.map(d => ({
            id: d.id, asset: d.asset, amount: d.amount_cents / 100,
            status: d.status, timestamp: d.created_at, reviewedAt: d.reviewed_at
        })) });
    } catch (error) {
        console.error("Deposit History Error:", error);
        res.status(500).json({ message: "Unable to load deposit history" });
    }
});

// Admin dashboard's deposit table is populated from the database.
app.get("/api/admin/deposits", async (req, res) => {
    const admin = await validateDepositAdmin(req, res);
    if (!admin) return;
    try {
        const deposits = await db.all(`
            SELECT d.id, d.user_id, u.email AS userEmail, d.asset,
                   d.amount_cents, d.status, d.created_at, d.proof_path,
                   d.reviewed_at, d.review_txid, d.review_note
            FROM deposit_requests d JOIN users u ON u.id = d.user_id
            ORDER BY d.id DESC LIMIT 200
        `);
        res.set("Cache-Control", "no-store");
        res.json({
            testApprovalEnabled: ntPublicVirtual || (process.env.NODE_ENV !== "production" &&
                process.env.DEPOSIT_TEST_MODE === "true" &&
                ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket?.remoteAddress) &&
                ['localhost', '127.0.0.1'].includes(req.hostname)),
            virtualCredits: ntPublicVirtual,
            deposits: deposits.map(d => ({
            id: d.id, userId: d.user_id, userEmail: d.userEmail,
            asset: d.asset, amount: d.amount_cents / 100,
            status: d.status, timestamp: d.created_at,
            hasProof: Boolean(d.proof_path), reviewedAt: d.reviewed_at,
            reviewTxid: d.review_txid, reviewNote: d.review_note
        })) });
    } catch (error) {
        console.error("Admin Deposits Error:", error);
        res.status(500).json({ message: "Failed to load deposit requests" });
    }
});

// Receipts never live under /public; a valid admin session is required.
// Admin-only deposit proof download.
app.get("/api/admin/deposits/:id/proof", async (req, res) => {
    try {
        if (!await validateDepositAdmin(req, res)) return;

        const id = Number(req.params.id);
        if (!Number.isSafeInteger(id) || id <= 0) {
            return res.status(400).json({
                message: "Invalid deposit ID"
            });
        }

        const row = await db.get(
            "SELECT proof_path FROM deposit_requests WHERE id = ?",
            id
        );

        if (!row) {
            return res.status(404).json({
                message: "Deposit request not found"
            });
        }

        if (!row.proof_path) {
            return res.status(404).json({
                message: "No receipt attached"
            });
        }

        if (!/^[a-f0-9-]{36}\.(jpg|png)$/.test(row.proof_path)) {
            return res.status(400).json({
                message: "Invalid stored receipt name"
            });
        }

        res.set({
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox"
        });

        res.type(
            row.proof_path.endsWith(".png") ? "png" : "jpeg"
        );

        if (useSupabaseStorage) {
            const image = await supabaseStorage.read(
                "deposits",
                row.proof_path
            );
            return res.send(image);
        }

        return res.sendFile(
            row.proof_path,
            { root: depositProofDir },
            err => {
                if (err && !res.headersSent) {
                    res.status(err.statusCode || 500).json({
                        message: "Receipt unavailable"
                    });
                }
            }
        );

    } catch (error) {
        console.error("Deposit proof error:", error);

        if (!res.headersSent) {
            return res.status(500).json({
                message: "Receipt unavailable"
            });
        }
    }
});

// Review is available only for local test credits until verified on-chain
// reconciliation, independent accounting and live-wallet integrations exist.
app.patch("/api/admin/deposits/:id/review", async (req, res) => {
    const admin = await validateDepositAdmin(req, res);
    if (!admin) return;
    const id = Number(req.params.id);
    const { action, reviewedProof, testCreditAcknowledged, note } = req.body || {};
    if (!Number.isSafeInteger(id) || id <= 0 || !["APPROVED", "REJECTED"].includes(action)) {
        return res.status(400).json({ message: "Invalid review request" });
    }
    const cleanNote = typeof note === "string" ? note.trim() : "";
    if (cleanNote.length > 500) return res.status(400).json({ message: "Review note too long" });
    if (action === "APPROVED") {
        if (!ntPublicVirtual && (process.env.NODE_ENV === "production" ||
            process.env.DEPOSIT_TEST_MODE !== "true")) {
            return res.status(403).json({ message: "Test deposit credit disabled. Live settlement integration required." });
        }
        // Explicit test-only acknowledgement: a receipt is not proof of payment.
        // This path NEVER claims on-chain verification.
        if (reviewedProof !== true || testCreditAcknowledged !== true) {
            return res.status(400).json({
                message: "Review the receipt and confirm LOCAL TEST credit before proceeding"
            });
        }
        // Limit this test-credit API to local requests even when the env flag is set.
        const remote = req.socket?.remoteAddress || "";
        if (!ntPublicVirtual && (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(remote) ||
            !['localhost', '127.0.0.1'].includes(req.hostname))) {
            return res.status(403).json({ message: "Local test credit available only via localhost" });
        }
    }
    try {
        const review = await db.transaction(async tx => {
            const d = await tx.get(`
                SELECT id, user_id, amount_cents, asset, status, proof_path
                FROM deposit_requests WHERE id = ?
            `, id);
            if (!d) return { code: 404, message: "Deposit not found" };
            if (d.status !== "PENDING") return { code: 409, message: "Deposit already reviewed" };
            if (action === "APPROVED" && !ntPublicVirtual && !d.proof_path) {
                return { code: 400, message: "Receipt required for approval" };
            }
            // No fake blockchain hash is generated. These are local test credits,
            // identified uniquely by the deposit request id and wallet audit row.
            // Existing real transaction hash uniqueness constraints are retained.
            const normalizedTx = null;
            const wallet = action === "APPROVED" ? await tx.get(`
                SELECT balance_cents FROM wallet_balances WHERE user_id = ?
            `, d.user_id) : null;
            if (action === "APPROVED" && !wallet) {
                return { code: 404, message: "User wallet unavailable" };
            }
            const after = wallet ? wallet.balance_cents + d.amount_cents : null;
            if (after !== null && !Number.isSafeInteger(after)) {
                return { code: 400, message: "Balance exceeds safe integer limit" };
            }
            const result = await tx.run(`
                UPDATE deposit_requests SET status = ?, reviewed_by = ?,
                    reviewed_at = CURRENT_TIMESTAMP, review_txid = ?, review_note = ?
                WHERE id = ? AND status = 'PENDING'
            `, action, admin.id, normalizedTx, cleanNote || null, id);
            if (result.changes !== 1) return { code: 409, message: "Deposit already reviewed" };
            if (action === "APPROVED") {
                await tx.run(`UPDATE wallet_balances SET balance_cents = ? WHERE user_id = ?`, after, d.user_id);
                await tx.run(`
                    INSERT INTO wallet_adjustments
                    (user_id, admin_id, delta_cents, balance_before_cents,
                     balance_after_cents, reason)
                    VALUES (?, ?, ?, ?, ?, ?)
                `, d.user_id, admin.id, d.amount_cents, wallet.balance_cents,
                    after, (ntPublicVirtual ? 'VIRTUAL CREDIT request #' : 'LOCAL TEST deposit #') + id + ' (NO PAYMENT)');
            }
            return { status: action, testCreditCents: action === "APPROVED" ? d.amount_cents : 0 };
        });
        const result = review;
        if (result.code) return res.status(result.code).json({ message: result.message });
        res.set("Cache-Control", "no-store");
        res.json({ message: action === "APPROVED" ?
            (ntPublicVirtual ? 'Virtual credits approved and added' : 'LOCAL TEST deposit approved; test wallet credited') : "Deposit rejected",
            deposit: { id, status: result.status, testCreditCents: result.testCreditCents } });
    } catch (error) {
        if (error.code?.startsWith("SQLITE_CONSTRAINT") ||
            error.extendedCode?.startsWith("SQLITE_CONSTRAINT")) {
            return res.status(409).json({ message: "Duplicate test deposit transaction" });
        }
        console.error("Deposit Review Error:", error);
        res.status(500).json({ message: "Failed to review deposit" });
    }
});

 // Get Current User KYC Status
app.get("/api/kyc/status", async (req, res) => {
    const userId = req.session?.userId;

    if (!userId) {
        return res.status(401).json({
            message: "Please log in first"
        });
    }

    try {
        const user = await db.get(`
            SELECT kyc_status, is_blocked, auth_version
            FROM users
            WHERE id = ?
        `, userId);

        if (
            !user ||
            user.is_blocked === 1 ||
            req.session.authVersion !== user.auth_version
        ) {
            return res.status(401).json({
                message: "Session expired or account blocked"
            });
        }

        res.set("Cache-Control", "no-store");

        // Sample fields are disclosed only to the authenticated owner of the request.
        // Older practice access-only requests never contained this information.
        const latest = await db.get(`
            SELECT id, status, is_mock_submission, full_name_enc, document_number_enc
            FROM kyc_requests WHERE user_id = ? ORDER BY id DESC LIMIT 1
        `, userId);
        const isMock = ntPublicVirtual && latest?.is_mock_submission === 1;
        let sampleProfile = null;
        if (isMock && latest.full_name_enc && latest.document_number_enc) {
            sampleProfile = {
                name: kycDecryptText(latest.full_name_enc),
                reference: kycDecryptText(latest.document_number_enc)
            };
        }
        res.json({
            status: user.kyc_status,
            review_type: isMock ? 'SAMPLE_APPLICATION' : 'ACCOUNT_ACCESS_ONLY',
            needs_sample_documents: Boolean(ntPublicVirtual && latest?.status === 'PENDING' &&
                latest.is_mock_submission !== 1),
            sample_profile: sampleProfile
        });

    } catch (error) {
        console.error("KYC Status Error:", error);

        res.status(500).json({
            message: "Failed to load KYC status"
        });
    }
});

// Encrypt newly submitted KYC identity fields and images at rest.
// KYC_DATA_KEY must be a separately backed-up 32-byte (64 hex) secret.
const kycCrypto = require("node:crypto");
const kycFs = require("node:fs");
const kycPath = require("node:path");
const kycDir = privateStorage.directories.kyc;
function kycKey() {
    const hex = process.env.KYC_DATA_KEY;
    if (!hex || !/^[0-9a-f]{64}$/i.test(hex)) {
        throw new Error("KYC_DATA_KEY must be 64 hex characters in .env");
    }
    return Buffer.from(hex, "hex");
}
function kycEncrypt(buffer) {
    const iv = kycCrypto.randomBytes(12);
    const cipher = kycCrypto.createCipheriv("aes-256-gcm", kycKey(), iv);
    const value = Buffer.concat([cipher.update(buffer), cipher.final()]);
    return Buffer.concat([Buffer.from("NTK1"), iv, cipher.getAuthTag(), value]);
}
function kycDecrypt(blob) {
    if (blob.length < 32 || blob.subarray(0, 4).toString() !== "NTK1") {
        throw new Error("Invalid encrypted KYC document");
    }
    const dec = kycCrypto.createDecipheriv("aes-256-gcm", kycKey(), blob.subarray(4, 16));
    dec.setAuthTag(blob.subarray(16, 32));
    return Buffer.concat([dec.update(blob.subarray(32)), dec.final()]);
}
function kycEncryptText(value) {
    return "v1:" + kycEncrypt(Buffer.from(value, "utf8")).toString("base64");
}
function kycDecryptText(value) {
    if (!value) return null;
    if (!value.startsWith("v1:")) throw new Error("Invalid encrypted KYC field");
    return kycDecrypt(Buffer.from(value.slice(3), "base64")).toString("utf8");
}
function kycImageExt(file) {
    const b = file?.buffer;
    if (!b) return null;
    if (file.mimetype === "image/jpeg" && b.length > 3 &&
        b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpg";
    if (file.mimetype === "image/png" && b.length > 8 &&
        b.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return "png";
    return null;
}
 // User KYC Request API
app.post("/api/kyc/requests", async (req, res) => {
    const userId = req.session?.userId;

    if (!userId) {
        return res.status(401).json({
            message: "Please log in first"
        });
    }

    try {
        const user = await db.get(`
            SELECT id, is_blocked, auth_version, kyc_status
            FROM users
            WHERE id = ?
        `, userId);

        if (
            !user ||
            user.is_blocked === 1 ||
            req.session.authVersion !== user.auth_version
        ) {
            return res.status(401).json({
                message: "Session expired or account blocked"
            });
        }

        if (user.kyc_status === "VERIFIED") {
            return res.status(409).json({
                message: "Account already verified"
            });
        }

        if (user.kyc_status === "PENDING") {
            return res.status(409).json({
                message: "KYC request already pending"
            });
        }

        const createRequest = await db.transaction(async tx => {
            const result = await tx.run(`
                INSERT INTO kyc_requests (user_id, status)
                VALUES (?, 'PENDING')
            `, userId);

            await tx.run(`
                UPDATE users
                SET kyc_status = 'PENDING'
                WHERE id = ?
            `, userId);

            return result.lastInsertRowid.toString();
        });

        const requestId = createRequest;

        res.status(201).json({
            message: "KYC request created",
            request: {
                id: requestId,
                status: "PENDING"
            }
        });

    } catch (error) {
        if (ntIsUniqueConstraintError(error)) {
            return res.status(409).json({
                message: "KYC request already pending"
            });
        }

        console.error("KYC Request Error:", error);

        res.status(500).json({
            message: "Failed to create KYC request"
        });
    }
});

 // Admin - View KYC Requests
app.get("/api/admin/kyc/requests", async (req, res) => {
    if (!req.session?.adminId) {
        return res.status(401).json({
            message: "Admin login required"
        });
    }

    try {
        const admin = await db.get(`
            SELECT id FROM admin_users WHERE id = ?
        `, req.session.adminId);

        if (!admin) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        const requests = await db.all(`
            SELECT
                k.id,
                k.user_id,
                u.email,
                k.status,
                k.submitted_at,
                k.reviewed_at,
                k.full_name_enc,
                k.document_number_enc,
                k.is_mock_submission,
                k.front_image_path,
                k.back_image_path
            FROM kyc_requests k
            JOIN users u ON u.id = k.user_id
            ORDER BY k.id DESC
            LIMIT 100
        `);

        res.set("Cache-Control", "no-store");

        res.json({
            virtualAccountReview: ntPublicVirtual,
            requests: requests.map(({ full_name_enc, document_number_enc,
                    front_image_path, back_image_path, ...r }) => {
                const mayShowSample = !ntPublicVirtual || r.is_mock_submission === 1;
                return {
                    ...r,
                    full_name: mayShowSample ? kycDecryptText(full_name_enc) : null,
                    document_number: mayShowSample ? kycDecryptText(document_number_enc) : null,
                    has_mock_documents: Boolean(r.is_mock_submission === 1 &&
                        front_image_path && back_image_path),
                    review_type: r.is_mock_submission === 1 ? 'SAMPLE_APPLICATION' : 'ACCOUNT_ACCESS_ONLY'
                };
            })
        });

    } catch (error) {
        console.error("Admin KYC Error:", error);

        res.status(500).json({
            message: "Failed to load KYC requests"
        });
    }
});

 // Admin KYC Reject API
app.patch("/api/admin/kyc/requests/:id/reject", async (req, res) => {
    const adminId = req.session?.adminId;

    if (!adminId) {
        return res.status(401).json({
            message: "Admin login required"
        });
    }

    const requestId = Number(req.params.id);

    if (!Number.isSafeInteger(requestId) || requestId <= 0) {
        return res.status(400).json({
            message: "Invalid KYC request ID"
        });
    }

    try {
        const admin = await db.get("SELECT id FROM admin_users WHERE id = ?", adminId);

        if (!admin) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        const rejectKyc = await db.transaction(async tx => {
            const request = await tx.get(`
                SELECT k.user_id
                FROM kyc_requests k
                JOIN users u ON u.id = k.user_id
                WHERE k.id = ?
                  AND k.status = 'PENDING'
                  AND u.kyc_status = 'PENDING'
            `, requestId);

            if (!request) return false;

            await tx.run(`
                UPDATE kyc_requests
                SET status = 'REJECTED',
                    reviewed_at = CURRENT_TIMESTAMP,
                    reviewed_by = ?
                WHERE id = ?
            `, adminId, requestId);

            await tx.run(`
                UPDATE users
                SET kyc_status = 'REJECTED'
                WHERE id = ?
            `, request.user_id);

            return true;
        });

        if (!rejectKyc) {
            return res.status(409).json({
                message: "KYC request is no longer pending"
            });
        }

        res.json({
            message: "KYC request rejected successfully",
            status: "REJECTED"
        });

    } catch (error) {
        console.error("KYC Reject Error:", error);

        res.status(500).json({
            message: "Failed to reject KYC request"
        });
    }
});

 // KYC Test Image Upload Configuration
const kycMulter = require("multer");

const kycUpload = kycMulter({
    storage: kycMulter.memoryStorage(),

    limits: {
        fileSize: 2 * 1024 * 1024,
        files: 2,
        fields: 2,
        fieldSize: 512
    },

    fileFilter(req, file, callback) {
        const allowedTypes = [
            "image/jpeg",
            "image/png"
        ];

        if (!allowedTypes.includes(file.mimetype)) {
            return callback(
                new Error("Only JPG and PNG document images are allowed")
            );
        }

        callback(null, true);
    }
}).fields([
    { name: "front", maxCount: 1 },
    { name: "back", maxCount: 1 }
]);

 // User KYC Document Upload API — original form, server-backed storage.
app.post("/api/kyc/documents", async (req, res) => {
    const userId = req.session?.userId;
    if (!userId) return res.status(401).json({ message: "Please log in first" });
    const user = await db.get(`
        SELECT id, is_blocked, auth_version, kyc_status FROM users WHERE id = ?
    `, userId);
    if (!user || user.is_blocked === 1 ||
        req.session.authVersion !== user.auth_version) {
        return res.status(403).json({ message: "Session invalid or account blocked" });
    }
    if (user.kyc_status !== "PENDING") {
        return res.status(409).json({ message: "Create a pending KYC request first" });
    }

    // The virtual site accepts only clearly fictional sample-reference submissions.
    // Real SSNs, national-ID numbers and legacy government-ID data are not permitted.
    kycUpload(req, res, async (uploadError) => {
        if (uploadError) return res.status(400).json({ message: uploadError.message });
        const fullName = typeof req.body?.full_name === "string" ? req.body.full_name.trim() : "";
        const idNumber = typeof req.body?.document_number === "string" ? req.body.document_number.trim() : "";
        const front = req.files?.front?.[0];
        const back = req.files?.back?.[0];
        if (!fullName || !idNumber || fullName.length > 150 || idNumber.length > 100) {
            return res.status(400).json({ message: "Enter a name and an ID reference number" });
        }
        if (ntPublicVirtual && (!/^SAMPLE-[A-Za-z0-9-]{4,40}$/i.test(idNumber) ||
            /\b(?:ssn|social.security|passport.number)\b/i.test(fullName))) {
            return res.status(400).json({message:
                'Use fictional applicant details and a SAMPLE- reference. Real identity numbers are not accepted.'});
        }
        const frontType = kycImageExt(front);
        const backType = kycImageExt(back);
        if (!frontType || !backType) {
            return res.status(400).json({ message: "Two JPG or PNG document photos required" });
        }

        const saved = [];
        try {
            const request = await db.get(`
                SELECT id FROM kyc_requests WHERE user_id = ? AND status = 'PENDING'
                AND front_image_path IS NULL AND back_image_path IS NULL LIMIT 1
            `, userId);
            if (!request) return res.status(409).json({
                message: "A KYC application has already been submitted. Please wait for review."
            });
            // Verify encryption configuration before touching the filesystem.
            const nameEncrypted = kycEncryptText(fullName);
            const numberEncrypted = kycEncryptText(idNumber);
            if (!useSupabaseStorage) {
    kycFs.mkdirSync(kycDir, {
        recursive: true,
        mode: 0o700
    });
}

const frontName = kycCrypto.randomUUID() + "-" + frontType + ".enc";
const backName = kycCrypto.randomUUID() + "-" + backType + ".enc";

for (const [fileName, file] of [[frontName, front], [backName, back]]) {
    const encrypted = kycEncrypt(file.buffer);

    if (useSupabaseStorage) {
        await supabaseStorage.save("kyc", fileName, encrypted);
        saved.push({ cloud: true, name: fileName });
    } else {
        const filePath = kycPath.join(kycDir, fileName);
        kycFs.writeFileSync(filePath, encrypted, {
            flag: "wx",
            mode: 0o600
        });
        saved.push({ cloud: false, path: filePath });
    }
}
            const saveRequest = await db.transaction(async tx => {
                const result = await tx.run(`
                    UPDATE kyc_requests SET front_image_path=?, back_image_path=?,
                    full_name_enc=?, document_number_enc=?, is_mock_submission=?
                    WHERE id=? AND user_id=? AND status='PENDING'
                    AND front_image_path IS NULL AND back_image_path IS NULL
                `, frontName, backName, nameEncrypted, numberEncrypted,
                    ntPublicVirtual ? 1 : 0, request.id, userId);
                if (result.changes !== 1) throw new Error("KYC request changed during upload");
            });
            return res.status(201).json({
                message: ntPublicVirtual ? "Sample account-review application submitted" :
                    "KYC documents submitted for admin review",
                requestId: request.id,
                status: "PENDING"
            });
        } catch (error) {
            for (const item of saved) {
    try {
        if (item.cloud) {
            await supabaseStorage.remove("kyc", item.name);
        } else {
            kycFs.unlinkSync(item.path);
        }
    } catch (cleanupError) {
        console.error("KYC cleanup failed:", cleanupError.message);
    }
}
            console.error("KYC Upload Error:", error.message);
            return res.status(500).json({ message: "Unable to securely save KYC application. Check KYC_DATA_KEY on server." });
        }
    });
});

 // Admin - View KYC Documents
app.get("/api/admin/kyc/requests/:id/documents/:side", async (req, res) => {
    const adminId = req.session?.adminId;

    if (!adminId) {
        return res.status(401).json({
            message: "Admin login required"
        });
    }

    const requestId = Number(req.params.id);
    const side = req.params.side;

    if (
        !Number.isSafeInteger(requestId) ||
        requestId <= 0 ||
        !["front", "back"].includes(side)
    ) {
        return res.status(400).json({
            message: "Invalid document request"
        });
    }

    try {
        const admin = await db.get("SELECT id FROM admin_users WHERE id = ?", adminId);

        if (!admin) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        const request = await db.get(`
            SELECT front_image_path, back_image_path, is_mock_submission
            FROM kyc_requests
            WHERE id = ?
        `, requestId);

        if (!request || (ntPublicVirtual && request.is_mock_submission !== 1)) {
            return res.status(404).json({
                message: "Sample review images not found"
            });
        }

        const fileName = side === "front"
            ? request.front_image_path
            : request.back_image_path;

        if (!fileName) {
            return res.status(404).json({
                message: "Document photo not uploaded"
            });
        }

        // Allow only server-generated UUID file names
        const validName =
            /^[0-9a-f-]{36}(?:-(?:jpg|png)\.enc|\.(?:jpg|png))$/i;

        if (!validName.test(fileName)) {
            return res.status(400).json({
                message: "Invalid stored file name"
            });
        }

        const uploadDir = privateStorage.directories.kyc;

        res.set({
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff"
        });

        if (useSupabaseStorage &&
    !kycFs.existsSync(kycPath.join(uploadDir, fileName))) {

    const stored = await supabaseStorage.read("kyc", fileName);

    const image = fileName.endsWith(".enc")
        ? kycDecrypt(stored)
        : stored;

    res.type(
        fileName.endsWith(".png") ||
        fileName.endsWith("-png.enc")
            ? "png"
            : "jpeg"
    );

    return res.send(image);
}
        if (fileName.endsWith(".enc")) {
            const image = kycDecrypt(kycFs.readFileSync(kycPath.join(uploadDir, fileName)));
            res.type(fileName.endsWith("-png.enc") ? "png" : "jpeg");
            return res.send(image);
        }
        // Older test requests may contain unencrypted JPG/PNG images.
        res.type(fileName.endsWith(".png") ? "png" : "jpeg");
        res.sendFile(fileName, { root: uploadDir }, (error) => {
            if (error && !res.headersSent) res.status(error.statusCode || 500).json({
                message: "Unable to load document image"
            });
        });

    } catch (error) {
        console.error("Admin KYC Document Error:", error);

        if (!res.headersSent) {
            res.status(500).json({
                message: "Failed to load KYC document"
            });
        }
    }
});

 // Admin KYC Approval (admin-reviewed documents only)
app.patch("/api/admin/kyc/requests/:id/approve", async (req, res) => {
    const adminId = req.session?.adminId;
    const requestId = Number(req.params.id);

    if (!adminId) {
        return res.status(401).json({
            message: "Admin login required"
        });
    }

    if (!Number.isSafeInteger(requestId) || requestId <= 0) {
        return res.status(400).json({
            message: "Invalid KYC request ID"
        });
    }
    
 // Require admin's manual review confirmation
if ((ntPublicVirtual && req.body?.accountReviewConfirmed !== true) ||
    (!ntPublicVirtual && req.body?.reviewedDocuments !== true)) {
    return res.status(400).json({message:ntPublicVirtual ?
        'Confirm that this is a virtual account-access approval' :
        'Please confirm that both documents were reviewed'});
}

    try {
        const admin = await db.get("SELECT id FROM admin_users WHERE id = ?", adminId);

        if (!admin) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        const fs = require("node:fs");
        const path = require("node:path");

        const request = await db.get(`
            SELECT
                k.id,
                k.user_id,
                k.front_image_path,
                k.back_image_path,
                k.full_name_enc,
                k.document_number_enc,
                k.is_mock_submission
            FROM kyc_requests k
            JOIN users u ON u.id = k.user_id
            WHERE k.id = ?
              AND k.status = 'PENDING'
              AND u.kyc_status = 'PENDING'
        `, requestId);

        if (!request) {
            return res.status(409).json({
                message: "No pending KYC request found"
            });
        }

        const validName =
            /^[0-9a-f-]{36}-(jpg|png)\.enc$/i;

        const names = [
            request.front_image_path,
            request.back_image_path
        ];

        const uploadDir = privateStorage.directories.kyc;

        const documentsAvailable = (
    await Promise.all(names.map(async (name) => {
        if (typeof name !== "string" || !validName.test(name)) {
            return false;
        }

        const localFile = path.join(uploadDir, name);

        if (fs.existsSync(localFile)) {
            return true;
        }

        if (!useSupabaseStorage) {
            return false;
        }

        try {
            const encrypted = await supabaseStorage.read("kyc", name);
            return Buffer.isBuffer(encrypted) && encrypted.length > 0;
        } catch (error) {
            console.error("KYC cloud document check failed:", error.message);
            return false;
        }
    }))
).every(Boolean);

        if ((request.is_mock_submission === 1 || !ntPublicVirtual) &&
            (!documentsAvailable || !request.full_name_enc || !request.document_number_enc)) {
            return res.status(400).json({
                message: "Full name, document number and both images are required for approval"
            });
        }

        if (ntPublicVirtual && request.is_mock_submission === 1 &&
            req.body?.reviewedDocuments !== true) {
            return res.status(400).json({message:'Confirm that you inspected both example images'});
        }

        const approveKyc = await db.transaction(async tx => {
            const result = await tx.run(`
                UPDATE kyc_requests
                SET status = 'VERIFIED',
                    reviewed_by = ?,
                    reviewed_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND status = 'PENDING'
            `, adminId, requestId);

            if (result.changes !== 1) {
                throw new Error("Request already processed");
            }

            const updated = await tx.run(`
                UPDATE users
                SET kyc_status = 'VERIFIED'
                WHERE id = ?
                  AND kyc_status = 'PENDING'
            `, request.user_id);

            if (updated.changes !== 1) {
                throw new Error("User status changed");
            }
        });

        res.json({
            message: ntPublicVirtual ? 'Virtual account access approved (not identity verification)' : 'KYC approved by admin', 
            status: "VERIFIED"
        });

    } catch (error) {
        console.error("KYC Approval Error:", error);

        res.status(500).json({
            message: "KYC approval failed"
        });
    }
});

// WITHDRAWAL DATABASE API — server-authoritative, no blockchain transfer.
const NT_WITHDRAW_METHODS = ["USDT (TRC20)", "Bitcoin (BTC)", "Ethereum (ETH)"];
async function ntActiveWithdrawalUser(req, res) {
    const id = req.session?.userId;
    if (!id) { res.status(401).json({message:"Please log in first"}); return null; }
    const user = await db.get(`SELECT id, is_blocked, auth_version, kyc_status
      FROM users WHERE id = ?`, id);
    if (!user || user.is_blocked === 1 || user.auth_version !== req.session.authVersion) {
        res.status(403).json({message:"Account blocked or session expired"}); return null;
    }
    return user;
}
async function ntWithdrawalAdmin(req, res) {
    const id = req.session?.adminId;
    const admin = id ? await db.get("SELECT id FROM admin_users WHERE id = ?", id) : null;
    if (!admin) res.status(401).json({message:"Admin login required"});
    return admin;
}
function ntWithdrawalRow(w) {
    return {
        id:w.id, userEmail:w.userEmail, method:w.method, address:w.address,
        amount:w.amount_cents / 100, status:w.status,
        timestamp:w.created_at, reviewedAt:w.reviewed_at, reviewNote:w.review_note
    };
}

// Reserve the funds at submission, rather than waiting for approval.
app.post("/api/withdrawals", async (req, res) => {
    const user = await ntActiveWithdrawalUser(req, res);
    if (!user) return;
    if (user.kyc_status !== "VERIFIED") return res.status(403).json({message:"KYC verification required"});
    if (process.env.NODE_ENV === "production" && !ntPublicVirtual) {
        return res.status(503).json({message:"Real-money withdrawals are not supported"});
    }
    const {method, amount_cents} = req.body || {};
    const address = req.body?.address;
    if (!NT_WITHDRAW_METHODS.includes(method) || typeof address !== "string" ||
        address.trim().length < 10 || address.trim().length > 180 ||
        /[<>\s]/.test(address.trim()) ||
        !Number.isSafeInteger(amount_cents) || amount_cents < 1 || amount_cents > 1000000000) {
        return res.status(400).json({message:"Invalid withdrawal details"});
    }
    try {
        const result = await db.transaction(async tx => {
            // The write transaction serializes balance reservation.
            const changed = await tx.run(`UPDATE wallet_balances
              SET balance_cents = balance_cents - ?
              WHERE user_id = ? AND balance_cents >= ?`, amount_cents, user.id, amount_cents);
            if (changed.changes !== 1) return {code:409, message:"Insufficient available balance"};
            const added = await tx.run(`INSERT INTO withdrawal_requests
              (user_id, method, address, amount_cents)
              VALUES (?, ?, ?, ?)`, user.id, method, address.trim(), amount_cents);
            return {id:Number(added.lastInsertRowid)};
        });
        if (result.code) return res.status(result.code).json({message:result.message});
        res.set("Cache-Control","no-store");
        res.status(201).json({message:"Withdrawal request pending admin review (funds reserved)",
          withdrawal:{id:result.id, status:"PENDING"}});
    } catch(error) {
        console.error("Withdrawal Submission Error:",error);
        res.status(500).json({message:"Unable to save withdrawal request"});
    }
});

app.get("/api/withdrawals", async (req, res) => {
    const user = await ntActiveWithdrawalUser(req, res);
    if (!user) return;
    try {
        const rows = await db.all(`SELECT method, address, amount_cents, status,
          created_at, reviewed_at, review_note FROM withdrawal_requests
          WHERE user_id = ? ORDER BY id DESC LIMIT 100`, user.id);
        res.set("Cache-Control","no-store");
        res.json({withdrawals:rows.map(ntWithdrawalRow)});
    } catch(error) {
        console.error("Withdrawal History Error:",error);
        res.status(500).json({message:"Unable to load withdrawal history"});
    }
});

app.get("/api/admin/withdrawals", async (req, res) => {
    const admin = await ntWithdrawalAdmin(req,res);
    if (!admin) return;
    try {
        const rows = await db.all(`SELECT w.id, u.email AS userEmail, w.method, w.address,
          w.amount_cents, w.status, w.created_at, w.reviewed_at, w.review_note
          FROM withdrawal_requests w JOIN users u ON u.id = w.user_id
          ORDER BY w.id DESC LIMIT 200`);
        const remote = req.socket?.remoteAddress || "";
        const testApprovalEnabled = ntPublicVirtual || (process.env.NODE_ENV !== "production" &&
          process.env.WITHDRAW_TEST_MODE === "true" &&
          ['127.0.0.1','::1','::ffff:127.0.0.1'].includes(remote) &&
          ['localhost','127.0.0.1'].includes(req.hostname));
        res.set('Cache-Control','no-store');
        res.json({withdrawals:rows.map(ntWithdrawalRow), testApprovalEnabled, virtualCredits:ntPublicVirtual});
    } catch(error) {
        console.error("Admin Withdrawal History Error:",error);
        res.status(500).json({message:"Unable to load withdrawals"});
    }
});

// APPROVED means local-test review completed; it does NOT transfer crypto.
// Production approval is disabled until a verified payout/settlement system exists.
app.patch("/api/admin/withdrawals/:id/review", async (req, res) => {
    const admin = await ntWithdrawalAdmin(req,res);
    if (!admin) return;
    const id = Number(req.params.id);
    const {action, note, testAcknowledged} = req.body || {};
    const cleanNote = typeof note === 'string' ? note.trim() : '';
    if (!Number.isSafeInteger(id) || id <= 0 ||
        !['APPROVED','REJECTED'].includes(action) || cleanNote.length > 500) {
        return res.status(400).json({message:"Invalid review"});
    }
    if (action === 'APPROVED') {
        const remote = req.socket?.remoteAddress || '';
        if ((!ntPublicVirtual && (process.env.NODE_ENV === 'production' ||
            process.env.WITHDRAW_TEST_MODE !== 'true' ||
            !['127.0.0.1','::1','::ffff:127.0.0.1'].includes(remote) ||
            !['localhost','127.0.0.1'].includes(req.hostname))) ||
            testAcknowledged !== true) {
            return res.status(403).json({message:"LOCAL TEST approval only; live payout integration required"});
        }
    }
    try {
        const outcome = await db.transaction(async tx => {
            const row = await tx.get(`SELECT id, user_id, amount_cents, status
              FROM withdrawal_requests WHERE id = ?`, id);
            if (!row) return {code:404, message:"Withdrawal not found"};
            if (row.status !== 'PENDING') return {code:409, message:"Withdrawal already reviewed"};
            const updated = await tx.run(`UPDATE withdrawal_requests
              SET status = ?, reviewed_at = CURRENT_TIMESTAMP,
                  reviewed_by = ?, review_note = ?
              WHERE id = ? AND status = 'PENDING'`, action, admin.id, cleanNote || null, id);
            if (updated.changes !== 1) return {code:409, message:"Withdrawal already reviewed"};
            if (action === 'REJECTED') {
                const wallet = await tx.get(`SELECT balance_cents FROM wallet_balances
                  WHERE user_id = ?`, row.user_id);
                if (!wallet) throw new Error("Wallet not found for refund");
                const after = wallet.balance_cents + row.amount_cents;
                if (!Number.isSafeInteger(after)) throw new Error("Wallet balance overflow");
                await tx.run(`UPDATE wallet_balances SET balance_cents = ? WHERE user_id = ?`, after,row.user_id);
                await tx.run(`INSERT INTO wallet_adjustments
                  (user_id, admin_id, delta_cents, balance_before_cents, balance_after_cents, reason)
                  VALUES (?, ?, ?, ?, ?, ?)`, row.user_id, admin.id,
                    row.amount_cents, wallet.balance_cents, after,
                    "Withdrawal rejected; reserved balance returned (request " + id + ")");
            }
            return {status:action};
        });
        if (outcome.code) return res.status(outcome.code).json({message:outcome.message});
        res.set("Cache-Control","no-store");
        res.json({message:action === 'APPROVED' ?
          (ntPublicVirtual ? 'Virtual withdrawal request approved — no funds transferred' : 'LOCAL TEST withdrawal approved — NO cryptocurrency sent') :
          "Withdrawal rejected; reserved balance returned", withdrawal:{id,status:outcome.status}});
    } catch(error) {
        console.error("Withdrawal Review Error:",error);
        res.status(500).json({message:"Unable to review withdrawal"});
    }
});


// SAVINGS LOCAL TEST API — backed by the same wallet_balances as /api/wallet.
// High illustrative yields and early admin release are intentionally unavailable in production.
const NT_SAVINGS_RATES = Object.freeze({7:2500, 15:4000, 20:5000, 30:6500});
function ntSavingsLocalMode(req) {
    if (ntPublicVirtual) return true;
    const ip = req.socket?.remoteAddress || '';
    return process.env.NODE_ENV !== 'production' &&
      process.env.SAVINGS_LOCAL_TEST_MODE === 'true' &&
      ['127.0.0.1','::1','::ffff:127.0.0.1'].includes(ip) &&
      ['localhost','127.0.0.1'].includes(req.hostname);
}
function ntSavingsPosition(row) {
    return {
        id: row.id,
        userEmail: row.userEmail || undefined,
        amount: row.amount_cents / 100,
        amount_cents: row.amount_cents,
        days: row.duration_days,
        profitRate: row.profit_rate_bps / 10000,
        status: row.status,
        unlockTime: row.unlock_at_ms,
        startTimeStr: new Date(row.started_at_ms).toISOString(),
        endTimeStr: new Date(row.unlock_at_ms).toISOString(),
        reviewedAt: row.released_at_ms ? new Date(row.released_at_ms).toISOString() : null,
        payout_cents: row.payout_cents,
        releaseKind: row.release_kind || null
    };
}
async function ntSavingsRequireUser(req,res) {
    const user = await ntActiveWithdrawalUser(req,res);
    if (!user) return null;
    if (user.kyc_status !== 'VERIFIED') {
        res.status(403).json({message:'KYC verification required'});
        return null;
    }
    return user;
}
function ntSavingsRequireLocalTest(req,res) {
    if (!ntSavingsLocalMode(req)) {
        res.status(403).json({message:'Savings payout simulation only available on localhost with SAVINGS_LOCAL_TEST_MODE=true; never use with real customer funds'});
        return false;
    }
    return true;
}
async function ntSavingsGetBalance(id, connection = db) {
    const row = await connection.get('SELECT balance_cents FROM wallet_balances WHERE user_id=?', id);
    if (!row) throw new Error('User wallet not found');
    return row.balance_cents;
}
async function ntSavingsRelease(savingId, userId, kind, adminId, checkMaturity) {
    return await db.transaction(async tx => {
        const saving=await tx.get('SELECT * FROM savings_positions WHERE id=? AND user_id=?', savingId,userId);
        if (!saving) return {code:404,message:'Savings record not found'};
        if (saving.status !== 'LOCKED') return {code:409,message:'Savings already released'};
        const now=Date.now();
        if (checkMaturity && now < saving.unlock_at_ms) return {code:409,message:'Savings is still locked'};
        const profit=Math.round(saving.amount_cents * saving.profit_rate_bps / 10000);
        const payout=saving.amount_cents+profit;
        const walletBefore=await ntSavingsGetBalance(userId,tx);
        if (![profit,payout,walletBefore+payout].every(Number.isSafeInteger)) throw new Error('Wallet balance overflow');
        const marked=await tx.run(`UPDATE savings_positions SET status='COMPLETED',
          released_at_ms=?, released_by=?, release_kind=?, payout_cents=?
          WHERE id=? AND status='LOCKED'`, now,adminId,kind,payout,savingId);
        if (marked.changes!==1) return {code:409,message:'Savings already released'};
        await tx.run('UPDATE wallet_balances SET balance_cents=? WHERE user_id=?', walletBefore+payout,userId);
        await tx.run(`INSERT INTO savings_audit
           (savings_id,user_id,admin_id,action,wallet_delta_cents,created_at_ms)
           VALUES (?,?,?,?,?,?)`, savingId,userId,adminId,kind,payout,now);
        return {id:savingId,status:'COMPLETED',payout_cents:payout,balance_cents:walletBefore+payout};
    });
}
app.get('/api/savings',async (req, res) =>{
    const user=await ntSavingsRequireUser(req,res);
    if (!user) return;
    try {
        const rows=await db.all(`SELECT * FROM savings_positions WHERE user_id=? ORDER BY id DESC LIMIT 200`, user.id);
        res.set('Cache-Control','no-store');
        res.json({savings:rows.map(ntSavingsPosition),balance_cents:await ntSavingsGetBalance(user.id),testModeEnabled:ntSavingsLocalMode(req)});
    } catch(error) {console.error('Savings GET:',error);res.status(500).json({message:'Unable to load savings'});}
});
app.post('/api/savings',async (req, res) =>{
    const user=await ntSavingsRequireUser(req,res);
    if (!user || !ntSavingsRequireLocalTest(req,res)) return;
    const {amount_cents,days,request_token}=req.body||{};
    if (!Number.isSafeInteger(amount_cents) || amount_cents<100 || amount_cents>1000000000 ||
        !Number.isSafeInteger(days) || !Object.hasOwn(NT_SAVINGS_RATES,days) ||
        typeof request_token!=='string' || !/^[a-zA-Z0-9_-]{16,80}$/.test(request_token)) {
        return res.status(400).json({message:'Invalid amount, savings plan, or request token'});
    }
    try {
        const outcome=await db.transaction(async tx =>{
            // Retried browser requests with the same token must not debit twice.
            const existing=await tx.get('SELECT * FROM savings_positions WHERE user_id=? AND request_token=?', user.id,request_token);
            if (existing) return {saving:existing,balance_cents:await ntSavingsGetBalance(user.id,tx),replayed:true};
            const changed=await tx.run(`UPDATE wallet_balances SET balance_cents=balance_cents-?
                WHERE user_id=? AND balance_cents>=?`, amount_cents,user.id,amount_cents);
            if (changed.changes!==1) return {code:409,message:'Insufficient main account balance'};
            const now=Date.now();
            const end=now+days*86400000;
            const inserted=await tx.run(`INSERT INTO savings_positions
               (user_id,amount_cents,duration_days,profit_rate_bps,status,started_at_ms,unlock_at_ms,request_token)
               VALUES (?,?,?,?,'LOCKED',?,?,?)`, user.id,amount_cents,days,NT_SAVINGS_RATES[days],now,end,request_token);
            const id=Number(inserted.lastInsertRowid);
            await tx.run(`INSERT INTO savings_audit
               (savings_id,user_id,admin_id,action,wallet_delta_cents,created_at_ms)
               VALUES (?,?,NULL,'LOCK',?,?)`, id,user.id,-amount_cents,now);
            return {saving:await tx.get('SELECT * FROM savings_positions WHERE id=?', id),balance_cents:await ntSavingsGetBalance(user.id,tx)};
        });
        if (outcome.code) return res.status(outcome.code).json({message:outcome.message});
        res.set('Cache-Control','no-store');
        res.status(outcome.replayed?200:201).json({message:outcome.replayed?'Savings request already processed':'LOCAL TEST: funds moved from main balance into locked savings',
           saving:ntSavingsPosition(outcome.saving),balance_cents:outcome.balance_cents,replayed:!!outcome.replayed});
    } catch(error) {console.error('Savings POST:',error);res.status(500).json({message:'Unable to create savings record'});}
});
app.post('/api/savings/:id/claim',async (req, res) =>{
    const user=await ntSavingsRequireUser(req,res);
    if (!user || !ntSavingsRequireLocalTest(req,res)) return;
    const id=Number(req.params.id);
    if (!Number.isSafeInteger(id)||id<=0) return res.status(400).json({message:'Invalid savings ID'});
    try {
        const result=await ntSavingsRelease(id,user.id,'USER_CLAIM',null,true);
        if(result.code) return res.status(result.code).json({message:result.message});
        res.set('Cache-Control','no-store');res.json({message:'LOCAL TEST: savings principal and simulated yield credited',...result});
    } catch(error) {console.error('Savings Claim:',error);res.status(500).json({message:'Unable to claim savings'});}
});
app.get('/api/admin/savings',async (req, res) =>{
    const admin=await ntWithdrawalAdmin(req,res);
    if(!admin)return;
    try {
        const rows=await db.all(`SELECT s.*,u.email AS userEmail FROM savings_positions s
            JOIN users u ON u.id=s.user_id ORDER BY s.id DESC LIMIT 500`);
        res.set('Cache-Control','no-store');res.json({savings:rows.map(ntSavingsPosition),testModeEnabled:ntSavingsLocalMode(req)});
    } catch(error) {console.error('Admin Savings GET:',error);res.status(500).json({message:'Unable to load savings'});}
});
// Read-only Savings cash-flow audit for authenticated admins. Never changes wallet balances.
app.get('/api/admin/savings/audit',async (req, res) =>{
    const admin=await ntWithdrawalAdmin(req,res);
    if (!admin) return;
    try {
        const rows=await db.all(`SELECT a.id,a.savings_id,a.action,a.wallet_delta_cents,
              a.created_at_ms,u.email AS user_email,au.username AS admin_username
            FROM savings_audit a
            JOIN users u ON u.id=a.user_id
            LEFT JOIN admin_users au ON au.id=a.admin_id
            ORDER BY a.id DESC LIMIT 200`);
        res.set('Cache-Control','no-store');
        res.json({events:rows.map(a=>({
            id:a.id, savingsId:a.savings_id, action:a.action,
            delta_cents:a.wallet_delta_cents, timestamp_ms:a.created_at_ms,
            userEmail:a.user_email, operator:a.admin_username || (a.action==='LOCK'?'User':'User claim')
        }))});
    } catch(error) {
        console.error('Savings Audit GET:',error);
        res.status(500).json({message:'Unable to load Savings audit'});
    }
});

app.patch('/api/admin/savings/:id/release',async (req, res) =>{
    const admin=await ntWithdrawalAdmin(req,res);
    if(!admin || !ntSavingsRequireLocalTest(req,res))return;
    if(req.body?.testAcknowledged!==true) return res.status(400).json({message:'Explicit local simulation acknowledgement required'});
    const id=Number(req.params.id);
    if(!Number.isSafeInteger(id)||id<=0) return res.status(400).json({message:'Invalid savings ID'});
    try {
        const owner=await db.get('SELECT user_id FROM savings_positions WHERE id=?', id);
        if(!owner)return res.status(404).json({message:'Savings record not found'});
        const result=await ntSavingsRelease(id,owner.user_id,'ADMIN_TEST_RELEASE',admin.id,false);
        if(result.code)return res.status(result.code).json({message:result.message});
        res.set('Cache-Control','no-store');res.json({message:'LOCAL TEST: savings released with simulated payout',...result});
    } catch(error) {console.error('Admin Savings Release:',error);res.status(500).json({message:'Unable to release savings'});}
});

// PERSONAL LOANS — existing US tier / Other Country 2x UI, server-owned Turso records.
// This phase tests application review and virtual-wallet loan credits on localhost ONLY.
// It does not issue an enforceable real-world loan or implement repayment/interest terms.
const NT_LOAN_US_TIERS = Object.freeze({
  '800-850':[800,850,10000000], '740-799':[740,799,7000000],
  '670-739':[670,739,5000000], '580-669':[580,669,3000000],
  'under-580':[300,579,1000000]
});
const ntLoanFileDir = privateStorage.directories.loans;
function ntLoanLocal(req) {
  if (ntPublicVirtual) return true;
  const remote=req.socket?.remoteAddress||'';
  return process.env.NODE_ENV!=='production' && process.env.LOAN_LOCAL_TEST_MODE==='true' &&
    ['127.0.0.1','::1','::ffff:127.0.0.1'].includes(remote) &&
    ['localhost','127.0.0.1'].includes(req.hostname);
}
function ntLoanRequireLocal(req,res) {
  if(ntLoanLocal(req))return true;
  res.status(403).json({message:'Loan application and test credit require localhost with LOAN_LOCAL_TEST_MODE=true; not available for real customer funds'});
  return false;
}
function ntLoanSafeRow(r,includeName=false){
  const summary=r.region==='US' ? 'Tier: '+r.tier+' | Amount: $'+(r.amount_cents/100).toFixed(2)
    : '$'+(r.amount_cents/100).toFixed(2)+' Loan';
  return {id:r.id,userEmail:r.userEmail||undefined,region:r.region==='US'?'US Region':'Other Country',
    tierOrAmount:summary, amount_cents:r.amount_cents,amount:r.amount_cents/100,
    details:(includeName ? 'Name: '+kycDecryptText(r.full_name_enc)+' | ' : '')+
      (r.region==='US'?'Credit Score: '+r.credit_score+' | ':'')+(ntPublicVirtual?'Sample ID ending ':(r.region==='US'?'SSN ending ':'ID ending '))+r.identity_last4,
    status:r.status,timestamp:new Date(r.created_at_ms).toISOString(),
    reviewedAt:r.reviewed_at_ms?new Date(r.reviewed_at_ms).toISOString():null,
    credited_cents:r.credited_cents,hasDocs:/^[0-9a-f-]{36}-(jpg|png)\.enc$/i.test(r.front_file||'') && /^[0-9a-f-]{36}-(jpg|png)\.enc$/i.test(r.back_file||'')};
}
const ntLoanUpload=kycMulter({storage:kycMulter.memoryStorage(),
  limits:{fileSize:2*1024*1024,files:2,fields:8,fieldSize:512},
  fileFilter(req,file,cb){
    return cb(['image/jpeg','image/png'].includes(file.mimetype)?null:new Error('Only JPG/PNG images are accepted'),true);
  }
}).fields([{name:'front',maxCount:1},{name:'back',maxCount:1}]);
async function ntLoanUser(req,res,requireVerified=false){
  const user=await ntActiveWithdrawalUser(req,res);
  if(!user)return null;
  if(requireVerified && user.kyc_status!=='VERIFIED'){
    res.status(403).json({message:'Identity verification (KYC) required before applying'});return null;
  }
  return user;
}
app.get('/api/loans',async (req, res) =>{
  const user=await ntLoanUser(req,res);if(!user)return;
  try{
    const rows=await db.all('SELECT * FROM loan_applications WHERE user_id=? ORDER BY id DESC LIMIT 100', user.id);
    res.set('Cache-Control','no-store');res.json({loans:rows.map(r=>ntLoanSafeRow(r)),testModeEnabled:ntLoanLocal(req)});
  }catch(error){console.error('Loan history error:',error.message);res.status(500).json({message:'Unable to load loan history'});}
});
app.post('/api/loans',async (req, res) =>{
  const user=await ntLoanUser(req,res,true);if(!user || !ntLoanRequireLocal(req,res))return;
  ntLoanUpload(req,res,async (uploadErr)=>{
    if(uploadErr)return res.status(400).json({message:uploadErr.message});
    const region=req.body?.region;
    const tier=typeof req.body?.tier==='string'?req.body.tier:'';
    const amount=Number(req.body?.amount_cents);
    const name=typeof req.body?.full_name==='string'?req.body.full_name.trim():'';
    const identity=typeof req.body?.identity_number==='string'?req.body.identity_number.trim():'';
    const score=Number(req.body?.credit_score);
    const token=typeof req.body?.request_token==='string'?req.body.request_token:'';
    const front=req.files?.front?.[0],back=req.files?.back?.[0];
    if (ntPublicVirtual && !/^SAMPLE-[A-Za-z0-9-]{4,40}$/.test(identity))
      return res.status(400).json({message:'A fictional SAMPLE- reference is required; do not submit real identity numbers'});
    const ft=kycImageExt(front),bt=kycImageExt(back);
    if(!['US','OTHER'].includes(region)||!Number.isSafeInteger(amount)||amount<=0||
      (name.length<2||name.length>150||identity.length<4||identity.length>100||!ft||!bt)||
      !/^[a-zA-Z0-9_-]{16,100}$/.test(token))
      return res.status(400).json({message:'Valid loan details and two JPG/PNG ID photos are required'});
    if(region==='US'){
      const rule=NT_LOAN_US_TIERS[tier];
      if(!rule || !Number.isSafeInteger(score)||score<rule[0]||score>rule[1]||
         amount<500000||amount>rule[2])
        return res.status(400).json({message:'Credit score, tier and loan amount do not match selected US tier'});
    }else if(![50000,100000,200000,500000,1000000].includes(amount)){
      return res.status(400).json({message:'Select a valid Other Country loan amount'});
    }
    const saved=[];
    const cleanupLoanFiles = async () => {
    for (const item of saved) {
        try {
            if (item.cloud) {
                await supabaseStorage.remove("loans", item.name);
            } else {
                kycFs.unlinkSync(item.path);
            }
        } catch (error) {
            console.error("Loan file cleanup failed:", error.message);
        }
    }
};
    try{
      const previous=await db.get('SELECT * FROM loan_applications WHERE user_id=? AND request_token=?', user.id,token);
      if(previous)return res.status(200).json({message:'Loan request already received',loan:ntLoanSafeRow(previous),replayed:true});
      // Validate encryption key before persisting PII or photos.
      // Public virtual mode accepts only fictional SAMPLE-* references and example images.
      const safeName=name;
      const safeIdentity=identity;
      const nameEnc=kycEncryptText(safeName),idEnc=kycEncryptText(safeIdentity);
      const fName=kycCrypto.randomUUID()+'-'+ft+'.enc';
      const bName=kycCrypto.randomUUID()+'-'+bt+'.enc';
      {
    if (!useSupabaseStorage) {
        kycFs.mkdirSync(ntLoanFileDir, {
            recursive: true,
            mode: 0o700
        });
    }

    for (const [f, data] of [[fName, front], [bName, back]]) {
        const encrypted = kycEncrypt(data.buffer);

        if (useSupabaseStorage) {
            await supabaseStorage.save("loans", f, encrypted);
            saved.push({ cloud: true, name: f });
        } else {
            const target = kycPath.join(ntLoanFileDir, f);

            kycFs.writeFileSync(target, encrypted, {
                flag: "wx",
                mode: 0o600
            });

            saved.push({ cloud: false, path: target });
        }
    }
}
      const result=await db.transaction(async tx =>{
        const pending=await tx.get("SELECT id FROM loan_applications WHERE user_id=? AND status='PENDING'", user.id);
        if(pending)return {code:409,message:'An application is already pending review'};
        if(region==='OTHER'){
          const wallet=await tx.get('SELECT balance_cents FROM wallet_balances WHERE user_id=?', user.id);
          if(!wallet||!Number.isSafeInteger(wallet.balance_cents)||amount>wallet.balance_cents*2)
            return {code:409,message:'Insufficient main balance for the selected 2x loan amount'};
        }
        const now=Date.now();
        const insert=await tx.run(`INSERT INTO loan_applications
          (user_id,region,tier,amount_cents,credit_score,full_name_enc,identity_number_enc,identity_last4,
           front_file,back_file,status,request_token,created_at_ms)
          VALUES (?,?,?,?,?,?,?,?,?,?,'PENDING',?,?)`, user.id,region,region==='US'?tier:null,amount,
          region==='US'?score:null,nameEnc,idEnc,safeIdentity.slice(-4),fName,bName,token,now);
        const id=Number(insert.lastInsertRowid);
        await tx.run('INSERT INTO loan_audit(loan_id,user_id,action,created_at_ms) VALUES(?,?,?,?)', id,user.id,'SUBMITTED',now);
        return {loan:await tx.get('SELECT * FROM loan_applications WHERE id=?', id)};
      });
      if (result.code) {
    await cleanupLoanFiles();
    return res.status(result.code).json({
        message: result.message
    });
}
      res.set('Cache-Control','no-store');return res.status(201).json({message:'Loan application submitted for admin review',loan:ntLoanSafeRow(result.loan)});
    }catch(error){
      await cleanupLoanFiles();
      console.error('Loan submission:',error.message);
      if(ntIsUniqueConstraintError(error) || error.code==='SQLITE_CONSTRAINT')return res.status(409).json({message:'Loan application already exists'});
      return res.status(500).json({message:'Unable to securely save loan application; check KYC_DATA_KEY'});
    }
  });
});
app.get('/api/admin/loans',async (req, res) =>{
  const admin=await ntWithdrawalAdmin(req,res);if(!admin)return;
  try{
    const rows=await db.all(`SELECT l.*,u.email AS userEmail FROM loan_applications l
      JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 500`);
    res.set('Cache-Control','no-store');res.json({loans:rows.map(r=>ntLoanSafeRow(r,true)),testModeEnabled:ntLoanLocal(req)});
  }catch(error){console.error('Admin loans:',error.message);res.status(500).json({message:'Unable to load loans'});}
});
app.get('/api/admin/loans/:id/documents/:side',async (req, res) =>{
  const admin=await ntWithdrawalAdmin(req,res);if(!admin)return;
  const id=Number(req.params.id),side=req.params.side;
  if(!Number.isSafeInteger(id)||id<=0||!['front','back'].includes(side))
    return res.status(400).json({message:'Invalid loan document request'});
  try{
    const row=await db.get('SELECT front_file,back_file FROM loan_applications WHERE id=?', id);
    if(!row)return res.status(404).json({message:'Loan application not found'});
    const fileName=side==='front'?row.front_file:row.back_file;
    const m=/^[0-9a-f-]{36}-(jpg|png)\.enc$/i.exec(fileName||'');
    if(!m)return res.status(404).json({message:'Document unavailable'});
    const localPath = kycPath.join(ntLoanFileDir, fileName);

const encrypted = useSupabaseStorage && !kycFs.existsSync(localPath)
    ? await supabaseStorage.read("loans", fileName)
    : kycFs.readFileSync(localPath);

const image = kycDecrypt(encrypted);
    res.set('Cache-Control','private, no-store');res.set('X-Content-Type-Options','nosniff');res.set('Content-Security-Policy',"default-src 'none'; sandbox");
    res.type(m[1]==='jpg'?'image/jpeg':'image/png').send(image);
  }catch(error){console.error('Loan docs:',error.message);res.status(500).json({message:'Unable to view protected document'});}
});
app.patch('/api/admin/loans/:id/review',async (req, res) =>{
  const admin=await ntWithdrawalAdmin(req,res);if(!admin || !ntLoanRequireLocal(req,res))return;
  const id=Number(req.params.id),action=req.body?.action;
  if(!Number.isSafeInteger(id)||id<=0||!['APPROVED','REJECTED'].includes(action))
    return res.status(400).json({message:'Invalid review request'});
  if(action==='APPROVED'&&req.body?.testAcknowledged!==true)
    return res.status(400).json({message:'Local test credit acknowledgement required'});
  try{
    const result=await db.transaction(async tx =>{
      const row=await tx.get('SELECT * FROM loan_applications WHERE id=?', id);
      if(!row)return {code:404,message:'Loan application not found'};
      if(row.status!=='PENDING')return {code:409,message:'Application already reviewed'};
      let before=null,after=null,delta=0;
      if(action==='APPROVED'){
        const wallet=await tx.get('SELECT balance_cents FROM wallet_balances WHERE user_id=?', row.user_id);
        if(!wallet)return {code:404,message:'Applicant wallet not found'};
        if(row.region==='OTHER'&&row.amount_cents>wallet.balance_cents*2)
          return {code:409,message:'Current balance no longer meets 2x loan eligibility'};
        before=wallet.balance_cents;after=before+row.amount_cents;
        if(!Number.isSafeInteger(after))return {code:400,message:'Balance overflow'};
        delta=row.amount_cents;
      }
      const now=Date.now();
      const changed=await tx.run(`UPDATE loan_applications SET status=?,reviewed_at_ms=?,reviewed_by=?,
        credited_cents=?,wallet_before_cents=?,wallet_after_cents=? WHERE id=? AND status='PENDING'`, action,now,admin.id,delta,before,after,id);
      if(changed.changes!==1)return {code:409,message:'Application already reviewed'};
      if(action==='APPROVED'){
        await tx.run('UPDATE wallet_balances SET balance_cents=? WHERE user_id=?', after,row.user_id);
        await tx.run(`INSERT INTO wallet_adjustments
          (user_id,admin_id,delta_cents,balance_before_cents,balance_after_cents,reason)
          VALUES (?,?,?,?,?,?)`, row.user_id,admin.id,delta,before,after,
          'LOCAL TEST loan principal credited, application #'+id);
      }
      await tx.run('INSERT INTO loan_audit(loan_id,user_id,admin_id,action,wallet_delta_cents,created_at_ms) VALUES (?,?,?,?,?,?)', id,row.user_id,admin.id,action==='APPROVED'?'APPROVED_TEST_CREDIT':'REJECTED',delta,now);
      return {status:action,credited_cents:delta,balance_cents:after};
    });
    if(result.code)return res.status(result.code).json({message:result.message});
    res.set('Cache-Control','no-store');res.json({message:action==='APPROVED'?'Test loan credit added to main balance':'Loan application rejected',...result});
  }catch(error){console.error('Loan review:',error.message);res.status(500).json({message:'Unable to review loan'});}
});

// LIVE SUPPORT CHAT -- Turso is authoritative; no localStorage sync.
// Retains existing UI and image-attachment functionality, with session-bound image URLs.
const ntSupportUpload = require('multer')({
    storage: require('multer').memoryStorage(),
    limits: { fileSize: 2 * 1024 * 1024, files: 1, fields: 2, fieldSize: 16 * 1024 },
    fileFilter(_req, file, cb) {
        if (!['image/jpeg', 'image/png'].includes(file.mimetype))
            return cb(new Error('Only JPG or PNG images are supported'));
        cb(null, true);
    }
}).single('image');

function ntSupportUploadRequest(req, res, next) {
    ntSupportUpload(req, res, error => {
        if (error) return res.status(400).json({message: 'Image must be JPG/PNG and no larger than 2 MB'});
        if (req.file && !['image/jpeg', 'image/png'].includes(req.file.mimetype))
            return res.status(400).json({message:'Only JPG or PNG images are supported'});
        Promise.resolve().then(next).catch(error => {
            console.error('Support upload handler:', error);
            if (!res.headersSent) {
                res.status(500).json({message:'Unable to save support message'});
            }
        });
    });
}
function ntSupportMime(file) {
    const b = file?.buffer;
    if (!b) return null;
    if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff)
        return file.mimetype === 'image/jpeg' ? 'image/jpeg' : null;
    if (b.length >= 8 && b.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])))
        return file.mimetype === 'image/png' ? 'image/png' : null;
    return null;
}
function ntSupportMessageRow(row) {
    return {
        id: row.id, sender: row.sender, text: row.message_text,
        image_url: row.image_mime ? '/api/support/images/' + row.id : null,
        created_at_ms: row.created_at_ms, edited_at_ms: row.edited_at_ms
    };
}
async function ntSupportSend(req, res, userId, sender, adminId=null) {
    const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
    if (text.length > 2000 || (!text && !req.file))
        return res.status(400).json({message:'Message must contain text or an image (max 2,000 characters)'});
    const mime = req.file ? ntSupportMime(req.file) : null;
    if (req.file && !mime)
        return res.status(400).json({message:'Invalid JPG/PNG image contents'});
    try {
        const now = Date.now();
        const recent = await db.get(`SELECT count(*) AS total FROM support_messages
            WHERE user_id=? AND sender=? AND created_at_ms>?`, userId, sender, now-10000);
        if (recent.total >= 10)
            return res.status(429).json({message:'Too many messages; please wait a few seconds'});
        const result = await db.run(`INSERT INTO support_messages
            (user_id, sender, admin_id, message_text, image_mime, image_blob, created_at_ms)
            VALUES (?,?,?,?,?,?,?)`, userId, sender, adminId, text, mime, mime ? req.file.buffer : null, now);
        const id = Number(result.lastInsertRowid);
        const msg = await db.get(`SELECT id,sender,message_text,image_mime,created_at_ms,edited_at_ms
            FROM support_messages WHERE id=?`, id);
        res.set('Cache-Control','no-store');
        res.status(201).json({message:'Message sent',chat:ntSupportMessageRow(msg)});
    } catch (error) {
        console.error('Support send:',error.message);
        res.status(500).json({message:'Unable to save support message'});
    }
}
// Users can see/send messages for their own authenticated account only.
app.get('/api/support/messages', async (req, res) =>{
    const user=await ntActiveWithdrawalUser(req,res); if(!user)return;
    try {
        const rows=await db.all(`SELECT id,sender,message_text,image_mime,created_at_ms,edited_at_ms
           FROM (SELECT id,sender,message_text,image_mime,created_at_ms,edited_at_ms
           FROM support_messages WHERE user_id=? ORDER BY id DESC LIMIT 200)
           ORDER BY id ASC`, user.id);
        res.set('Cache-Control','no-store');res.json({messages:rows.map(ntSupportMessageRow)});
    } catch(error){console.error('Support history:',error.message);res.status(500).json({message:'Could not load support chat'});}
});
app.post('/api/support/messages',async (req, res) =>{
    const user=await ntActiveWithdrawalUser(req,res); if(!user)return;
    ntSupportUploadRequest(req,res,async ()=>ntSupportSend(req,res,user.id,'user'));
});
// Admin conversation list, ordered by latest activity.
app.get('/api/admin/support/conversations',async (req, res) =>{
    const admin=await ntWithdrawalAdmin(req,res); if(!admin)return;
    try {
        const rows=await db.all(`SELECT u.id AS user_id,u.email,COUNT(m.id) AS message_count,
          MAX(m.created_at_ms) AS last_at_ms
          FROM support_messages m JOIN users u ON u.id=m.user_id
          GROUP BY m.user_id ORDER BY last_at_ms DESC LIMIT 500`);
        res.set('Cache-Control','no-store');res.json({conversations:rows});
    }catch(error){console.error('Support conversations:',error.message);res.status(500).json({message:'Unable to load conversations'});}
});
app.get('/api/admin/support/conversations/:userId/messages',async (req, res) =>{
    const admin=await ntWithdrawalAdmin(req,res); if(!admin)return;
    const userId=Number(req.params.userId);
    if(!Number.isSafeInteger(userId)||userId<=0)return res.status(400).json({message:'Invalid user ID'});
    try {
        const user=await db.get('SELECT id,email FROM users WHERE id=?', userId);
        if(!user)return res.status(404).json({message:'Conversation user not found'});
        const rows=await db.all(`SELECT id,sender,message_text,image_mime,created_at_ms,edited_at_ms
          FROM (SELECT id,sender,message_text,image_mime,created_at_ms,edited_at_ms
          FROM support_messages WHERE user_id=? ORDER BY id DESC LIMIT 200)
          ORDER BY id ASC`, userId);
        res.set('Cache-Control','no-store');res.json({user,messages:rows.map(ntSupportMessageRow)});
    }catch(error){console.error('Admin support history:',error.message);res.status(500).json({message:'Unable to load messages'});}
});
app.post('/api/admin/support/conversations/:userId/messages',async (req, res) =>{
    const admin=await ntWithdrawalAdmin(req,res); if(!admin)return;
    const userId=Number(req.params.userId);
    if(!Number.isSafeInteger(userId)||userId<=0)return res.status(400).json({message:'Invalid user ID'});
    if(!await db.get('SELECT id FROM users WHERE id=?', userId))
        return res.status(404).json({message:'Conversation user not found'});
    ntSupportUploadRequest(req,res,async ()=>ntSupportSend(req,res,userId,'admin',admin.id));
});
app.patch('/api/admin/support/messages/:messageId',async (req, res) =>{
    const admin=await ntWithdrawalAdmin(req,res); if(!admin)return;
    const id=Number(req.params.messageId);
    const value=req.body?.text;
    if(!Number.isSafeInteger(id)||id<=0 || typeof value!=='string'||value.trim().length>2000)
        return res.status(400).json({message:'Invalid message edit'});
    try {
        const original=await db.get('SELECT image_mime FROM support_messages WHERE id=? AND sender=\'admin\'', id);
        if(!original)return res.status(404).json({message:'Admin message not found'});
        if(!value.trim()&&!original.image_mime)
            return res.status(400).json({message:'Cannot leave a text-only message empty'});
        await db.run('UPDATE support_messages SET message_text=?,edited_at_ms=? WHERE id=? AND sender=\'admin\'', value.trim(),Date.now(),id);
        res.set('Cache-Control','no-store');res.json({message:'Message updated'});
    }catch(error){console.error('Edit support message:',error.message);res.status(500).json({message:'Unable to edit message'});}
});
// Return images only to the owning user or an authenticated admin.
app.get('/api/support/images/:messageId',async (req, res) =>{
    const id=Number(req.params.messageId);
    if(!Number.isSafeInteger(id)||id<=0)return res.status(400).send('Invalid image ID');
    try {
        const adminId=req.session?.adminId;
        const isAdmin=!!(adminId&&await db.get('SELECT id FROM admin_users WHERE id=?', adminId));
        const userId=req.session?.userId;
        const owner=!isAdmin&&userId?await db.get('SELECT id,is_blocked,auth_version FROM users WHERE id=?', userId):null;
        const userAllowed=!!(owner&&owner.is_blocked===0&&owner.auth_version===req.session.authVersion);
        if(!isAdmin&&!userAllowed)return res.status(401).send('Authentication required');
        const row=await db.get('SELECT user_id,image_mime,image_blob FROM support_messages WHERE id=?', id);
        if(!row || !row.image_blob || (!isAdmin&&row.user_id!==userId))
            return res.status(404).send('Image not found');
        res.set('Cache-Control','private, no-store');res.set('X-Content-Type-Options','nosniff');
        res.set('Content-Security-Policy',"default-src 'none'; sandbox");
        
const blob = row.image_blob;

const imageBuffer = Buffer.isBuffer(blob)
    ? blob
    : blob instanceof ArrayBuffer
        ? Buffer.from(blob)
        : ArrayBuffer.isView(blob)
            ? Buffer.from(
                blob.buffer,
                blob.byteOffset,
                blob.byteLength
            )
            : null;

if (!imageBuffer || imageBuffer.length === 0) {
    return res.status(500).send("Invalid image data");
}

return res.type(row.image_mime).send(imageBuffer);

    }catch(error){console.error('Support image:',error.message);res.status(500).send('Unable to load image');}
});


// ===== DEMO TRADING: shared Turso Main Balance (SIMULATED, NON-CASHABLE) =====
// Safety rule: this feature is enabled ONLY for an explicitly DEMO-ONLY platform.
// No exchange trade is executed; client-reported indicative prices are not verified market prices.
const ntTradingDemoOnly = () => process.env.TRADING_DEMO_MODE === 'true' && process.env.DEMO_ONLY_PLATFORM === 'true';
function ntTradeDemoGate(req,res) {
    if (ntTradingDemoOnly()) return true;
    res.status(403).json({message:'Demo Trading is disabled. This feature requires DEMO_ONLY_PLATFORM=true and TRADING_DEMO_MODE=true; never connect it to redeemable customer funds.'});
    return false;
}
async function ntTradeUser(req,res) {
    const id=req.session?.userId;
    const user=id?await db.get('SELECT id,kyc_status,is_blocked,auth_version FROM users WHERE id=?', id):null;
    if (!user || user.is_blocked!==0 || user.auth_version!==req.session.authVersion) {
        res.status(401).json({message:'Valid user login required'});return null;
    }
    if (user.kyc_status!=='VERIFIED') {
        res.status(403).json({message:'Identity verification required'});return null;
    }
    return user;
}
async function ntTradeAdmin(req,res) {
    const id=req.session?.adminId;
    const a=id?await db.get('SELECT id FROM admin_users WHERE id=?', id):null;
    if(!a)res.status(401).json({message:'Admin login required'});
    return a;
}


/* National Trade - Admin Demo Result Settings (Read Only) */
app.get('/api/admin/demo-result-modes', async (req, res) => {
    if (!ntTradeDemoGate(req, res)) return;

    const admin = await ntTradeAdmin(req, res);
    if (!admin) return;

    try {
        const users = await db.all(`
            SELECT
                u.id AS user_id,
                u.email,
                COALESCE(
                    m.result_mode,
                    'MANUAL'
                ) AS result_mode,
                m.updated_at_ms
            FROM users AS u
            LEFT JOIN demo_user_result_modes AS m
                ON m.user_id = u.id
            ORDER BY u.id DESC
        `);

        res.set('Cache-Control', 'private, no-store');

        return res.status(200).json({
            mode: 'DEMO ONLY',
            users
        });

    } catch (error) {
        console.error(
            'Demo result settings error:',
            error.message
        );

        return res.status(500).json({
            message: 'Unable to load demo result settings'
        });
    }
});

/* Save per-user DEMO simulation setting */
app.post('/api/admin/demo-result-modes/:userId', async (req, res) => {
    if (!ntTradeDemoGate(req, res)) return;

    const admin = await ntTradeAdmin(req, res);
    if (!admin) return;

    const userId = Number(req.params.userId);
    const resultMode = req.body?.result_mode;

    const allowedModes = [
        'MANUAL',
        'ALWAYS_WIN',
        'ALWAYS_LOSS'
    ];

    if (!Number.isSafeInteger(userId) || userId <= 0) {
        return res.status(400).json({
            message: 'Invalid user ID'
        });
    }

    if (!allowedModes.includes(resultMode)) {
        return res.status(400).json({
            message: 'Invalid demo simulation mode'
        });
    }

    try {
        const user = await db.get(
            'SELECT id FROM users WHERE id = ?',
            userId
        );

        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            });
        }

        const updatedAt = Date.now();

        await db.run(`
            INSERT INTO demo_user_result_modes
                (user_id, result_mode, updated_by, updated_at_ms)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                result_mode = excluded.result_mode,
                updated_by = excluded.updated_by,
                updated_at_ms = excluded.updated_at_ms
        `, userId, resultMode, admin.id, updatedAt);

        res.set('Cache-Control', 'private, no-store');

        return res.status(200).json({
            message: 'Demo simulation setting saved',
            user_id: userId,
            result_mode: resultMode
        });

    } catch (error) {
        console.error(
            'Demo mode save error:',
            error.message
        );

        return res.status(500).json({
            message: 'Unable to save demo simulation setting'
        });
    }
});

function ntTradeRow(t) {
    return {id:t.id,user_email:t.user_email||null,asset:t.asset,direction:t.direction,
       amount_cents:t.amount_cents,entry_price:t.entry_price,closing_price:t.closing_price,
       chosen_result:t.chosen_result,status:t.status,result_source:t.result_source,
       profit_cents:t.profit_cents,created_at_ms:t.created_at_ms,expires_at_ms:t.expires_at_ms,
       settled_at_ms:t.settled_at_ms};
}
async function ntTradeBalance(id, connection = db){
    const row=await connection.get('SELECT balance_cents FROM wallet_balances WHERE user_id=?', id);
    if(!row)throw new Error('Demo Main Balance missing');return row.balance_cents;
}
// Called within one Turso write transaction; only one status transition can pay out.
async function ntTradeSettle(tx, id, closingPrice, adminId) {
    const t=await tx.get('SELECT * FROM demo_main_trades WHERE id=?', id);
    if(!t)return {code:404,message:'Demo trade not found'};
    if(t.status!=='PENDING')return {already:true,trade:t};
    const now=Date.now();
    if(now<t.expires_at_ms)return {code:409,message:'60-second demo timer has not finished'};
    const forced=!!t.chosen_result;
    // Public practice settlement never trusts a price supplied by a user's browser.
    if(ntPublicVirtual && !forced) return {code:409,message:'Awaiting administrator-selected virtual outcome'};
    if(!forced && !(Number.isFinite(closingPrice)&&closingPrice>0&&closingPrice<1e12)){
        return {code:409,message:'Indicative closing price required for demo settlement'};
    }
    const result=forced?t.chosen_result:((t.direction==='UP'?closingPrice>t.entry_price:closingPrice<t.entry_price)?'WIN':'LOSS');
    const profit=result==='WIN'?Math.round(t.amount_cents*30/100):0;
    const payout=result==='WIN'?t.amount_cents+profit:0;
    const before=await ntTradeBalance(t.user_id,tx);
    if(!Number.isSafeInteger(profit)||!Number.isSafeInteger(payout)||!Number.isSafeInteger(before+payout)){
        throw new Error('Invalid demo wallet arithmetic');
    }
    const updated=await tx.run(`UPDATE demo_main_trades SET status=?,result_source=?,closing_price=?,
       profit_cents=?,settled_at_ms=?,settled_by=COALESCE(?,settled_by) WHERE id=? AND status='PENDING'`, result,forced?'ADMIN_DEMO':'BROWSER_INDICATIVE',forced?null:closingPrice,profit,now,adminId||null,id);
    if(updated.changes!==1)return {code:409,message:'Trade was settled by another request'};
    if(payout)await tx.run('UPDATE wallet_balances SET balance_cents=balance_cents+? WHERE user_id=?', payout,t.user_id);
    await tx.run(`INSERT INTO demo_main_trade_audit(trade_id,user_id,admin_id,action,wallet_delta_cents,created_at_ms)
       VALUES (?,?,?,?,?,?)`, id,t.user_id,adminId||null,result,payout,now);
    return {result,balance_cents:before+payout};
}
const ntTradeSettleTxn=async (id,closingPrice,adminId) =>
    await db.transaction(tx => ntTradeSettle(tx,id,closingPrice,adminId));
app.get('/api/demo-main/trades',async (req, res) =>{
    if(!ntTradeDemoGate(req,res))return;
    const user=await ntTradeUser(req,res);if(!user)return;
    try {
        const rows=await db.all('SELECT * FROM demo_main_trades WHERE user_id=? ORDER BY id DESC LIMIT 200', user.id);
        res.set('Cache-Control','no-store');
        res.json({mode:'DEMO_ONLY',wallet_balance_cents:await ntTradeBalance(user.id),trades:rows.map(ntTradeRow)});
    }catch(e){console.error('Demo Main trade list:',e);res.status(500).json({message:'Unable to load demo trading history'});}
});
app.post('/api/demo-main/trades',async (req, res) =>{
    if(!ntTradeDemoGate(req,res))return;
    const user=await ntTradeUser(req,res);if(!user)return;
    const {asset,direction,amount_cents,entry_price,request_token}=req.body||{};
    if(!['BTCUSDT','XAUUSD'].includes(asset)||!['UP','DOWN'].includes(direction)||
       !Number.isSafeInteger(amount_cents)||amount_cents<1||amount_cents>1000000000||
       !Number.isFinite(entry_price)||entry_price<=0||entry_price>=1e12||
       typeof request_token!=='string'||!/^[0-9a-f-]{36}$/i.test(request_token)){
        return res.status(400).json({message:'Invalid demo order details'});
    }
    try {
        const record=await db.transaction(async tx =>{
            const prior=await tx.get('SELECT id FROM demo_main_trades WHERE user_id=? AND request_token=?', user.id,request_token);
            if(prior)return {id:prior.id,duplicate:true};
            
/* Read the user's disclosed DEMO result setting */
const modeRow = await tx.get(
    'SELECT result_mode FROM demo_user_result_modes WHERE user_id = ?',
    user.id
);

const presetResult =
    modeRow?.result_mode === 'ALWAYS_WIN'
        ? 'WIN'
        : modeRow?.result_mode === 'ALWAYS_LOSS'
            ? 'LOSS'
            : null;

            const debit=await tx.run(`UPDATE wallet_balances SET balance_cents=balance_cents-?
               WHERE user_id=? AND balance_cents>=?`, amount_cents,user.id,amount_cents);
            if(debit.changes!==1)return {code:409,message:'Insufficient Demo Main Balance'};
            const now=Date.now();
            
const result = await tx.run(
    `INSERT INTO demo_main_trades (
        user_id,
        asset,
        direction,
        amount_cents,
        entry_price,
        chosen_result,
        created_at_ms,
        expires_at_ms,
        request_token
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    user.id,
    asset,
    direction,
    amount_cents,
    entry_price,
    presetResult,
    now,
    now + 60000,
    request_token
);

const id = Number(result.lastInsertRowid);
            await tx.run(`INSERT INTO demo_main_trade_audit(trade_id,user_id,action,wallet_delta_cents,created_at_ms)
                VALUES (?,?, 'STAKE', ?, ?)`, id,user.id,-amount_cents,now);
            return {id};
        });
        if(record.code)return res.status(record.code).json({message:record.message});
        res.set('Cache-Control','no-store');
        res.status(record.duplicate?200:201).json({trade_id:record.id,duplicate:!!record.duplicate,
          wallet_balance_cents:await ntTradeBalance(user.id),message:'Demo trade recorded (virtual credits only)'});
    }catch(e){console.error('Demo Main place:',e);res.status(500).json({message:'Unable to place demo trade'});}
});
app.post('/api/demo-main/trades/:id/settle',async (req, res) =>{
    if(!ntTradeDemoGate(req,res))return;
    const user=await ntTradeUser(req,res);if(!user)return;
    const id=Number(req.params.id),close=req.body?.closing_price;
    if(!Number.isSafeInteger(id)||id<1||!(close===null||(typeof close==='number'&&Number.isFinite(close)&&close>0&&close<1e12))){
        return res.status(400).json({message:'Invalid demo settlement'});
    }
    try {
        const owner=await db.get('SELECT user_id FROM demo_main_trades WHERE id=?', id);
        if(!owner||owner.user_id!==user.id)return res.status(404).json({message:'Demo trade not found'});
        const settled=await ntTradeSettleTxn(id,close,null);
        if(settled.code)return res.status(settled.code).json({message:settled.message});
        res.set('Cache-Control','no-store');
        res.json({message:'Demo trade settled',status:settled.result||settled.trade.status,
          wallet_balance_cents:await ntTradeBalance(user.id)});
    }catch(e){console.error('Demo Main settlement:',e);res.status(500).json({message:'Unable to settle demo trade'});}
});
app.get('/api/admin/demo-main/trades',async (req, res) =>{
    if(!ntTradeDemoGate(req,res))return;
    const admin=await ntTradeAdmin(req,res);if(!admin)return;
    try{
        // Admin-selected trades can settle without any user browser remaining open.
        await db.transaction(async tx =>{
          const now=Date.now();
          const due=await tx.all(`SELECT id FROM demo_main_trades WHERE status='PENDING'
             AND chosen_result IS NOT NULL AND expires_at_ms<=? LIMIT 200`, now);
          for(const t of due)await ntTradeSettle(tx,t.id,null,null);
        });
        const rows=await db.all(`SELECT t.*,u.email AS user_email FROM demo_main_trades t
            JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 300`);
        res.set('Cache-Control','no-store');res.json({mode:'DEMO_ONLY',trades:rows.map(ntTradeRow)});
    }catch(e){console.error('Admin Demo Main list:',e);res.status(500).json({message:'Unable to load demo admin trades'});}
});
app.patch('/api/admin/demo-main/trades/:id/result',async (req, res) =>{
    if(!ntTradeDemoGate(req,res))return;
    const admin=await ntTradeAdmin(req,res);if(!admin)return;
    const id=Number(req.params.id),result=req.body?.result;
    if(!Number.isSafeInteger(id)||id<1||!['WIN','LOSS'].includes(result))return res.status(400).json({message:'Invalid demo outcome'});
    try{
      const outcome=await db.transaction(async tx =>{
          const row=await tx.get('SELECT status,chosen_result,expires_at_ms FROM demo_main_trades WHERE id=?', id);
          if(!row)return {code:404,message:'Demo trade not found'};
          if(row.status!=='PENDING'||row.chosen_result)return {code:409,message:'Demo result already chosen or settled'};
          const now=Date.now();
          await tx.run('UPDATE demo_main_trades SET chosen_result=?,settled_by=? WHERE id=? AND status=\'PENDING\'', result,admin.id,id);
          await tx.run(`INSERT INTO demo_main_trade_audit(trade_id,user_id,admin_id,action,wallet_delta_cents,created_at_ms)
             SELECT id,user_id,?,?,0,? FROM demo_main_trades WHERE id=?`, admin.id,'ADMIN_CHOOSE_'+result,now,id);
          if(now>=row.expires_at_ms)await ntTradeSettle(tx,id,null,admin.id);
          return {status:'OK'};
      });
      if(outcome.code)return res.status(outcome.code).json({message:outcome.message});
      res.set('Cache-Control','no-store');res.json({message:'Simulated '+result+' chosen; settles at 60 seconds'});
    }catch(e){console.error('Demo Main admin choose:',e);res.status(500).json({message:'Unable to record demo outcome'});}
});
// ===== END DEMO TRADING =====

const PORT = Number(process.env.PORT || 3000);
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error('Invalid PORT');
let settlementSweep;
async function initialize(database = db) {
   if (!useSupabaseStorage) {
    await privateStorage.initialize();
}
   await sessionStore.ready;
   await validateDatabase(database);
}

function startSettlementSweep() {
    if (!ntPublicVirtual || settlementSweep) return;
    settlementSweep = setInterval(async () => {
        try {
            await db.transaction(async tx => {
                const due = await tx.all(`SELECT id FROM demo_main_trades
                    WHERE status='PENDING' AND chosen_result IS NOT NULL AND expires_at_ms<=?
                    ORDER BY id LIMIT 200`, Date.now());
                for (const row of due) {
                    await ntTradeSettle(tx, row.id, null, null);
                }
            });
        } catch (error) {
            console.error('Virtual trade settlement sweep:', error);
        }
    }, 5000);
    settlementSweep.unref();
}

async function start() {
    await initialize();
    startSettlementSweep();
    return app.listen(PORT, () => {
        console.log(`National Trade virtual-credit server listening on ${PORT}`);
    });
}

module.exports = { app, initialize, start };

if (require.main === module) {
    start().catch(error => {
        console.error('Server startup failed:', error);
        process.exitCode = 1;
    });
}
