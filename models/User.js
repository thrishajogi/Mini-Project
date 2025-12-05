const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Helper function to encrypt TOTP
function encrypt(text) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.createHash('sha256').update(process.env.JWT_SECRET).digest(); // 32 bytes key
    const iv = crypto.randomBytes(16); // 16 bytes IV
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; // store IV along with encrypted text
}

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    totp: { type: String, required: true },
    qotp: { type: String, required: true }
});

// Hash password & qotp, encrypt totp before saving
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }

    if (this.isModified('qotp')) {
        const salt = await bcrypt.genSalt(10);
        this.qotp = await bcrypt.hash(this.qotp, salt);
    }

    if (this.isModified('totp')) {
        this.totp = encrypt(this.totp);
    }

    next();
});

module.exports = mongoose.model('User', userSchema);
