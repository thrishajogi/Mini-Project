// server-sqlite-admin.js — ZeroBank with SQLite + Admin dashboard
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');

const { Sequelize, DataTypes, Op } = require('sequelize');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'demo-admin-key'; // protect admin endpoints

// ---------- SQLITE SETUP ----------
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.join(__dirname, 'database.sqlite'),
  logging: false
});

// ---------- USER MODEL ----------
const User = sequelize.define('User', {
  username: { type: DataTypes.STRING },
  email: { type: DataTypes.STRING, unique: true },
  password: { type: DataTypes.STRING },
  totpSecret: { type: DataTypes.STRING },
  securityQuestionQuestion: { type: DataTypes.STRING },
  securityQuestionAnswer: { type: DataTypes.STRING },
  failedAttempts: { type: DataTypes.INTEGER, defaultValue: 0 },
  isLocked: { type: DataTypes.BOOLEAN, defaultValue: false },
  resetToken: { type: DataTypes.STRING },
  resetTokenExpiry: { type: DataTypes.DATE }
}, {
  tableName: 'users',
  timestamps: true
});

// ---------- HELPERS ----------
function isStrongPassword(password) {
  return (
    typeof password === 'string' &&
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

// ---------- APP ROUTES (signup/login as before) ----------

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email and password required' });

    const exists = await User.findOne({ where: { email } });
    if (exists) return res.status(400).json({ success: false, error: 'Email already exists' });

    if (!isStrongPassword(password))
      return res.status(400).json({ success: false, error: 'Password must include uppercase, lowercase, number, symbol and be 8+ characters.' });

    const hashed = await bcrypt.hash(password, 10);
    await User.create({ username, email, password: hashed });
    res.json({ success: true });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email and password required' });

    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(400).json({ success: false, error: 'Invalid credentials' });
    if (user.isLocked) return res.status(403).json({ success: false, error: 'Account locked' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      await user.increment('failedAttempts');
      if ((user.failedAttempts || 0) + 1 >= 5) await user.update({ isLocked: true });
      return res.status(400).json({ success: false, error: 'Invalid credentials' });
    }

    await user.update({ failedAttempts: 0 });
    res.json({ success: true, username: user.username, email: user.email });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// NOTE: other routes (forgot-password, reset, security, totp) can remain same as earlier code,
// for demo we only need signup/login and admin view; you can paste earlier implementations if needed.

// ---------- ADMIN PROTECTION MIDDLEWARE ----------
function requireAdmin(req, res, next) {
  const key = req.header('x-admin-key') || req.query.adminKey || req.body.adminKey;
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized (admin key required)' });
  }
  next();
}

// ---------- ADMIN: list users (paginated) ----------
app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const perPage = Math.min(100, Math.max(5, parseInt(req.query.perPage || '10')));

    const { count, rows } = await User.findAndCountAll({
      offset: (page - 1) * perPage,
      limit: perPage,
      order: [['createdAt', 'DESC']]
    });

    // map to safe view: DO NOT send raw hashed password or totp secret — show masked info
    const users = rows.map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      createdAt: u.createdAt,
      updatedAt: u.updatedAt,
      hasTotp: !!u.totpSecret,
      isLocked: !!u.isLocked
    }));

    res.json({ total: count, page, perPage, users });
  } catch (err) {
    console.error('Admin list users error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- ADMIN: export all users as CSV ----------
app.get('/admin/export-users.csv', requireAdmin, async (req, res) => {
  try {
    const users = await User.findAll({ order: [['createdAt', 'DESC']] });
    const header = ['id', 'username', 'email', 'createdAt', 'hasTotp', 'isLocked'];
    const lines = [header.join(',')];

    for (const u of users) {
      const row = [
        u.id,
        `"${(u.username || '').replace(/"/g, '""')}"`,
        `"${(u.email || '').replace(/"/g, '""')}"`,
        u.createdAt ? u.createdAt.toISOString() : '',
        !!u.totpSecret,
        !!u.isLocked
      ];
      lines.push(row.join(','));
    }

    const csv = lines.join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="users.csv"');
    res.send(csv);
  } catch (err) {
    console.error('Export CSV error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- ADMIN: simple search ----------
app.get('/admin/search', requireAdmin, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (!q) return res.json({ results: [] });

    const results = await User.findAll({
      where: {
        [Op.or]: [
          { email: { [Op.like]: `%${q}%` } },
          { username: { [Op.like]: `%${q}%` } }
        ]
      },
      limit: 100
    });

    const out = results.map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      createdAt: u.createdAt,
      hasTotp: !!u.totpSecret,
      isLocked: !!u.isLocked
    }));

    res.json({ results: out });
  } catch (err) {
    console.error('Admin search error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Serve frontend (including admin.html) ----------
app.use(express.static(path.join(__dirname, 'frontend')));

// fallback for index
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'signin.html')));

// ---------- START ----------
(async () => {
  try {
    await sequelize.sync();
    console.log('SQLite DB ready at', path.join(__dirname, 'database.sqlite'));
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (err) {
    console.error('Startup error:', err);
    process.exit(1);
  }
})();
