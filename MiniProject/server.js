// server.js — ZeroBank (Atlas-only) — full file
// npm i dotenv express mongoose cors bcrypt crypto nodemailer
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
app.use(cors()); // no credentials; frontend uses fetch without credentials
app.use(express.json());

const PORT = process.env.PORT || 5000;

// ---------- rate-limit / lock config ----------
const MAX_ATTEMPTS = 3;
const BLOCK_TIME = 3 * 60 * 1000; // 3 minutes

// ---------- MONGO CONNECTOR (Atlas-only) ----------
function buildAtlasUriFromEnv() {
  if (process.env.MONGO_URI && process.env.MONGO_URI.trim()) {
    return process.env.MONGO_URI.trim();
  }
  const user = process.env.MONGO_USER;
  const passRaw = process.env.MONGO_PASS || '';
  const host = process.env.MONGO_HOST;
  const db = process.env.MONGO_DB || 'ZeroBankDB';

  if (!user || !host) {
    console.error('\nERROR: Atlas credentials missing. Set MONGO_URI or MONGO_USER + MONGO_HOST in .env\n');
    process.exit(1);
  }

  const pass = encodeURIComponent(passRaw);
  return `mongodb+srv://${user}:${pass}@${host}/${db}?retryWrites=true&w=majority`;
}

async function connectMongo() {
  try {
    const uri = buildAtlasUriFromEnv();
    await mongoose.connect(uri, { maxPoolSize: 10 });
    console.log('MongoDB Connected to Atlas');
  } catch (err) {
    console.error('MongoDB ERROR:', err);
    throw err;
  }
}

// ---------- MODELS ----------
const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true, sparse: true },
  password: String,
  totpSecret: String,
  securityQuestion: { question: String, answer: String },
  failedAttempts: { type: Number, default: 0 },
  isLocked: { type: Boolean, default: false },
  lockUntil: Date,
  lastIP: String,
  lastUA: String,
  knownDevices: [String],
  mfaToken: String,
  mfaExpiry: Date,
  resetToken: String,
  resetTokenExpiry: Date
});
const User = mongoose.model('User', userSchema);

const eventSchema = new mongoose.Schema({
  type: { type: String, required: true },
  email: String,
  ip: String,
  ua: String,
  time: { type: Date, default: Date.now },
  details: mongoose.Schema.Types.Mixed
});
const Event = mongoose.model('Event', eventSchema);

// ---------- HELPERS ----------
async function logEvent(type, { email = null, ip = null, ua = null, details = {} } = {}) {
  try {
    const ev = new Event({ type, email, ip, ua, details });
    await ev.save();
    console.log(`[EVENT] ${type} ${email || ''} ${ip || ''}`, details);
  } catch (err) {
    console.error('logEvent error:', err);
  }
}

async function sendAlertEmail(toEmail, subject, htmlBody) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.warn('SMTP not configured — skipping sendAlertEmail for', toEmail);
    return;
  }
  try {
    const transporter = nodemailer.createTransport({
      service: process.env.SMTP_SERVICE || 'gmail',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
    await transporter.sendMail({
      from: `${process.env.FROM_NAME || 'Zero Bank'} <${process.env.SMTP_USER}>`,
      to: toEmail,
      subject,
      html: htmlBody
    });
    console.log('Alert email sent to', toEmail);
  } catch (err) {
    console.error('sendAlertEmail error:', err);
  }
}

function deviceFingerprint(ua, extra = '') {
  return crypto.createHash('sha256').update((ua || '') + '|' + (extra || '')).digest('hex');
}

// BASE32 helpers for TOTP
function base32ToBytes(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '', bytes = [];
  base32 = (base32 || '').replace(/=+$/, '').toUpperCase();
  for (let c of base32) {
    const val = alphabet.indexOf(c);
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}
function verifyTOTP(token, secret) {
  if (!token || !secret) return false;
  const key = base32ToBytes(secret);
  const timeStep = 30;
  const now = Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / timeStep);
  for (let offset = -1; offset <= 1; offset++) {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(counter + offset));
    const hmac = crypto.createHmac('sha1', key).update(buf).digest();
    const pos = hmac[hmac.length - 1] & 0xf;
    const code =
      ((hmac[pos] & 0x7f) << 24) |
      ((hmac[pos + 1] & 0xff) << 16) |
      ((hmac[pos + 2] & 0xff) << 8) |
      (hmac[pos + 3] & 0xff);
    const otp = (code % 1000000).toString().padStart(6, '0');
    if (otp === token) return true;
  }
  return false;
}

// generate base32 secret
function generateBase32Secret(length = 16) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}
function buildOtpauthUrl(accountName, issuer, secret) {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const query = `secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  return `otpauth://totp/${label}?${query}`;
}

// ---------- RISK ENGINE ----------
function computeRisk(req, user) {
  const ua = (req.headers['user-agent'] || '').slice(0, 255);
  const ip = (req.ip || req.connection?.remoteAddress || '').replace(/^::ffff:/, '');
  const nowHour = new Date().getHours();

  let score = 0;
  const reasons = [];

  const failed = user ? (user.failedAttempts || 0) : 0;
  score += Math.min(failed * 15, 45);
  if (failed > 0) reasons.push(`failedAttempts:${failed}`);

  if (user && user.lastIP && user.lastIP !== ip) {
    score += 20;
    reasons.push('ip_change');
  }
  if (user && user.lastUA && user.lastUA !== ua) {
    score += 15;
    reasons.push('ua_change');
  }
  if (nowHour < 6 || nowHour > 22) {
    score += 10;
    reasons.push('odd_time');
  }
  if (user && (!user.knownDevices || user.knownDevices.length === 0)) {
    score += 5;
    reasons.push('no_known_devices');
  }
  if (user && user.totpSecret) reasons.push('has_totp');

  if (score > 100) score = 100;
  return { score, reasons, ua, ip };
}

// ---------- ROUTES ----------

// SIGNUP
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email and password required' });
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ success: false, error: 'Email already exists' });
    if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ success: false, error: 'Weak password' });
    const hashed = await bcrypt.hash(password, 10);
    await User.create({ username, email, password: hashed });
    res.json({ success: true });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// LOGIN (risk engine, mfa)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email and password required' });

    const ua = (req.headers['user-agent'] || '').slice(0, 255);
    const ip = (req.ip || req.connection?.remoteAddress || '').replace(/^::ffff:/, '');

    const user = await User.findOne({ email });

    if (!user) {
      await logEvent('failed_login', { email, ip, ua, details: { reason: 'no_user' } });
      return res.status(400).json({ success: false, error: 'Invalid credentials' });
    }

    const risk = computeRisk(req, user);
    await logEvent('login_attempt', { email, ip, ua, details: { score: risk.score, reasons: risk.reasons } });

    if (user.lockUntil && user.lockUntil.getTime() <= Date.now()) {
      user.isLocked = false;
      user.failedAttempts = 0;
      user.lockUntil = null;
      await user.save();
    }

    if (user.isLocked && user.lockUntil && user.lockUntil.getTime() > Date.now()) {
      const remainingMs = user.lockUntil.getTime() - Date.now();
      const remainingSec = Math.ceil(remainingMs / 1000);
      await logEvent('login_blocked_locked', { email, ip, ua, details: { remainingSec } });
      return res.status(429).json({ success: false, error: `Too many failed attempts. Try again in ${remainingSec} seconds.` });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      user.failedAttempts = (user.failedAttempts || 0) + 1;
      if (user.failedAttempts >= MAX_ATTEMPTS) {
        user.isLocked = true;
        user.lockUntil = new Date(Date.now() + BLOCK_TIME);
        user.failedAttempts = 0;
        await user.save();

        await logEvent('account_locked', { email, ip, ua, details: { blockForMs: BLOCK_TIME } });
        await sendAlertEmail(user.email, 'ZeroBank — Account locked', `<p>Your account was locked after too many failed login attempts. It will unlock automatically in ${Math.ceil(BLOCK_TIME/60000)} minute(s).</p>`);

        return res.status(429).json({ success: false, error: `Too many failed attempts. Account locked for ${Math.ceil(BLOCK_TIME / 60000)} minute(s).` });
      }
      await user.save();
      await logEvent('failed_login', { email, ip, ua, details: { failedAttempts: user.failedAttempts } });
      return res.status(400).json({ success: false, error: 'Invalid credentials' });
    }

    // success path
    user.failedAttempts = 0;
    user.isLocked = false;
    user.lockUntil = null;

    user.lastIP = ip;
    user.lastUA = ua;
    user.knownDevices = user.knownDevices || [];
    const fp = deviceFingerprint(ua, ip);
    if (!user.knownDevices.includes(fp)) {
      user.knownDevices.push(fp);
      if (user.knownDevices.length > 10) user.knownDevices.shift();
    }

    if (risk.score >= 60) {
      const mfaToken = crypto.randomBytes(16).toString('hex');
      user.mfaToken = mfaToken;
      user.mfaExpiry = Date.now() + 5 * 60 * 1000;
      await user.save();

      await logEvent('suspicious_login', { email, ip, ua, details: { score: risk.score, reasons: risk.reasons } });
      await sendAlertEmail(user.email, 'ZeroBank — Suspicious login attempt', `<p>A suspicious login to your account was detected (score ${risk.score}). If this was not you, please reset your password immediately.</p>`);

      return res.json({ success: true, requireMfa: true, message: 'MFA required for this login (suspicious activity).' });
    }

    if (risk.score >= 30) {
      const mfaToken = crypto.randomBytes(16).toString('hex');
      user.mfaToken = mfaToken;
      user.mfaExpiry = Date.now() + 5 * 60 * 1000;
      await user.save();

      await logEvent('require_mfa', { email, ip, ua, details: { score: risk.score, reasons: risk.reasons } });
      return res.json({ success: true, requireMfa: true, message: 'MFA required for this login.' });
    }

    await user.save();
    await logEvent('login_success', { email, ip, ua, details: { score: risk.score } });

    return res.json({ success: true, username: user.username, email: user.email });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// VERIFY SECURITY ANSWER
app.post('/verify-security-answer', async (req, res) => {
  const { email, answer, question } = req.body;
  try {
    if (!email) {
      console.log('[verify-security-answer] missing email', req.body);
      return res.status(400).json({ valid: false, error: 'missing email' });
    }
    const user = await User.findOne({ email }).lean();
    if (!user) {
      console.log('[verify-security-answer] user not found for', email);
      return res.json({ valid: false, error: 'user not found' });
    }
    const storedQ = (user.securityQuestion && user.securityQuestion.question) || '';
    const storedA = (user.securityQuestion && user.securityQuestion.answer) || '';

    console.log('[verify-security-answer] incoming:', { email, question, answer });
    console.log('[verify-security-answer] stored   :', { storedQ, storedA });

    const normIncomingAnswer = (answer || '').toString().trim().toLowerCase();
    const normStoredAnswer = (storedA || '').toString().trim().toLowerCase();

    const questionMatches =
      !storedQ ||
      !question ||
      storedQ.trim().toLowerCase() === (question || '').trim().toLowerCase() ||
      storedQ.trim().toLowerCase().includes((question || '').trim().toLowerCase());

    const answerMatches = normStoredAnswer !== '' && normStoredAnswer === normIncomingAnswer;

    if (questionMatches && answerMatches) {
      console.log('[verify-security-answer] OK ->', email);
      return res.json({ valid: true });
    } else {
      console.log('[verify-security-answer] FAIL -> questionMatches:', questionMatches, 'answerMatches:', answerMatches);
      return res.json({ valid: false, error: 'Incorrect question or answer.' });
    }
  } catch (err) {
    console.error('verify-security-answer error:', err);
    return res.status(500).json({ valid: false, error: 'server error' });
  }
});

// VERIFY TOTP
app.post('/verify-totp', async (req, res) => {
  const { email, code } = req.body;
  try {
    if (!email || !code) return res.json({ valid: false });
    const user = await User.findOne({ email });
    if (!user) return res.json({ valid: false });

    const ok = verifyTOTP(String(code).trim(), user.totpSecret || '');
    if (ok) await logEvent('totp_ok', { email, ip: req.ip, ua: req.headers['user-agent'] });
    else await logEvent('totp_failed', { email, ip: req.ip, ua: req.headers['user-agent'] });

    return res.json({ valid: ok });
  } catch (err) {
    console.error('TOTP Error:', err);
    res.status(500).json({ valid: false });
  }
});

// ---------- SECURITY SETUP endpoints ----------
// GET new TOTP secret + otpauth (frontend requests before showing QR)
app.get('/security/setup/new', async (req, res) => {
  try {
    const email = (req.query.email || '').trim();
    if (!email) return res.status(400).json({ success: false, error: 'Email required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, error: 'User not found' });

    const secret = generateBase32Secret(16);
    const issuer = process.env.FROM_NAME || 'ZeroBank';
    const otpauth = buildOtpauthUrl(email, issuer, secret);

    return res.json({ success: true, secret, otpauth });
  } catch (err) {
    console.error('GET /security/setup/new error:', err);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
});

// POST save security setup (answer + totpSecret + verify code)
app.post('/security/setup', async (req, res) => {
  try {
    const { email, question, answer, totpSecret, totpCode } = req.body || {};
    if (!email) return res.status(400).json({ success: false, error: 'Email required' });
    if (!question || !answer) return res.status(400).json({ success: false, error: 'Question and answer required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, error: 'User not found' });

    if (totpSecret && totpCode) {
      const ok = verifyTOTP(String(totpCode).trim(), String(totpSecret).trim());
      if (!ok) {
        await logEvent('security_setup_totp_failed', { email, ip: req.ip, ua: req.headers['user-agent'], details: {} });
        return res.status(400).json({ success: false, error: 'TOTP verification failed. Check the code and try again.' });
      }
    }

    user.securityQuestion = { question: String(question).trim(), answer: String(answer).trim() };
    if (totpSecret) user.totpSecret = String(totpSecret).trim().toUpperCase();
    await user.save();

    await logEvent('security_setup_complete', { email, ip: req.ip, ua: req.headers['user-agent'], details: {} });

    return res.json({ success: true, message: 'Security setup saved.' });
  } catch (err) {
    console.error('POST /security/setup error:', err);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ADMIN events endpoint
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
app.get('/admin/events', async (req, res) => {
  try {
    if (ADMIN_SECRET && req.query.secret !== ADMIN_SECRET) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const limit = Math.min(100, parseInt(req.query.limit || '50', 10));
    const events = await Event.find({}).sort({ time: -1 }).limit(limit).lean().exec();
    res.json({ success: true, events });
  } catch (err) {
    console.error('admin/events error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Serve frontend static files
app.use(express.static(path.join(__dirname, 'frontend')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'signin.html')));

// ---------- START ----------
async function start() {
  try {
    await connectMongo();
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (err) {
    console.error('Startup failed:', err);
    process.exit(1);
  }
}
start();

// graceful shutdown
process.on('SIGINT', async () => {
  try { await mongoose.disconnect(); } catch (e) {}
  process.exit(0);
});
