const crypto = require("crypto");

// ----------------------------------------
// Base32 Encoding
// ----------------------------------------
function base32Encode(buffer) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0, value = 0, output = "";

    for (let byte of buffer) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            output += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }

    if (bits > 0) {
        output += alphabet[(value << (5 - bits)) & 31];
    }

    return output;
}

// ----------------------------------------
// Base32 Decoding
// ----------------------------------------
function base32ToBuffer(str) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0, value = 0, bytes = [];

    str = str.replace(/=+$/, "").toUpperCase();

    for (let char of str) {
        value = (value << 5) | alphabet.indexOf(char);
        bits += 5;

        if (bits >= 8) {
            bytes.push((value >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }

    return Buffer.from(bytes);
}

// ----------------------------------------
// Generate Secret
// ----------------------------------------
function generateSecret() {
    return base32Encode(crypto.randomBytes(20));
}

// ----------------------------------------
// Generate TOTP Code
// ----------------------------------------
function generateTOTP(secret, window = 0) {
    const counter = Math.floor(Date.now() / 30000) + window;
    const key = base32ToBuffer(secret);

    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64BE(BigInt(counter));

    const hmac = crypto.createHmac("sha1", key).update(buffer).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;

    const code =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);

    return (code % 1000000).toString().padStart(6, "0");
}

// ----------------------------------------
// Verify TOTP with 1-step time window
// ----------------------------------------
function verifyTOTP(secret, token) {
    return (
        generateTOTP(secret, -1) === token ||
        generateTOTP(secret, 0) === token ||
        generateTOTP(secret, 1) === token
    );
}

// EXPORT FINAL
module.exports = {
    generateSecret,
    generateTOTP,
    verifyTOTP
};
