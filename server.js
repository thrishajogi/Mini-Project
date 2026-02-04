const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');

// MODELS
const User = require('./models/User');
const UserSecurity = require('./models/UserSecurity');

// UTILS
const bcrypt = require('bcrypt');
const { verifyCodeLocally } = require('./utils/totp');

const app = express();

// Connect MongoDB
connectDB();

app.use(cors());
app.use(express.json());

/* ===============================================================
   SIGN UP  (Save user to MongoDB)
================================================================ */
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await User.create({
      username,
      email,
      password: hashed
    });

    res.json({ success: true });

  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


/* ===============================================================
   LOGIN (Check email + bcrypt password)
================================================================ */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check email
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    // Compare password
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Incorrect password" });

    res.json({ success: true });

  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


/* ===============================================================
   BEHAVIOUR MONITORING
================================================================ */
app.post('/behaviour-log', async (req, res) => {
  const { email, behaviour } = req.body;

  console.log("Behaviour Data:", email, behaviour);

  let risk = "normal";

  if (behaviour.typingSpeed > 12) 
      risk = "suspicious (too fast)";
  if (behaviour.mouseMoves < 5) 
      risk = "suspicious (no mouse movement)";
  if (behaviour.timeSpent < 2) 
      risk = "suspicious (too fast login)";

  console.log(`Login Behaviour for ${email}: ${risk}`);

  res.json({ status: "logged", risk });
});


/* ===============================================================
   SAVE SECURITY QUESTION
================================================================ */
app.post('/security/setup', async (req, res) => {
  const { email, question, answer, totpSecret } = req.body;

  try {
    await UserSecurity.findOneAndUpdate(
      { email },
      {
        securityQuestion: { question, answer },
        totpSecret,
        isBlocked: false,
        'attempts.count': 0
      },
      { upsert: true }
    );

    res.json({ success: true });

  } catch (err) {
    console.error("Security Setup Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


/* ===============================================================
   VERIFY SECURITY ANSWER (Case-insensitive)
================================================================ */
app.post('/verify-security-answer', async (req, res) => {
  const { email, answer } = req.body;

  try {
    const user = await UserSecurity.findOne({ email });
    if (!user) return res.json({ valid: false });

    const correct = user.securityQuestion.answer;

    const isMatch =
      answer.trim().toLowerCase() === correct.trim().toLowerCase();

    res.json({ valid: isMatch });

  } catch (err) {
    console.error("Security Answer Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


/* ===============================================================
   VERIFY TOTP (3 attempts → 24hr block)
================================================================ */
app.post('/verify-totp', async (req, res) => {
  const { email, secret, code } = req.body;

  try {
    let userSec = await UserSecurity.findOne({ email });

    if (!userSec) {
      userSec = new UserSecurity({ email, totpSecret: secret });
    }

    // Check blocked
    if (userSec.isBlocked) {
      if (userSec.blockExpiry > new Date()) {
        return res.status(429).json({
          blocked: true,
          error: "Account is blocked for 24 hours"
        });
      } else {
        userSec.isBlocked = false;
        userSec.attempts.count = 0;
      }
    }

    // TOTP check
    const valid = await verifyCodeLocally(secret, code);

    if (!valid) {
      userSec.attempts.count++;
      userSec.attempts.lastAttempt = new Date();

      if (userSec.attempts.count >= 3) {
        userSec.isBlocked = true;
        userSec.blockExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
      }

      await userSec.save();

      return res.status(401).json({
        error: "Invalid code",
        attemptsRemaining: 3 - userSec.attempts.count
      });
    }

    // Success
    userSec.attempts.count = 0;
    await userSec.save();

    res.json({ valid: true });

  } catch (err) {
    console.error("TOTP Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


/* ===============================================================
   START SERVER
================================================================ */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
