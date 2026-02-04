// utils/encrypt.js
import crypto from "crypto";

// Key for encryption (in real apps, store this safely)
const SECRET_KEY = "zerobank-secret-key-2025"; 
const ALGORITHM = "aes-256-cbc";

// Generate a random IV (Initialization Vector)
function generateIV() {
  return crypto.randomBytes(16);
}

// Encrypt function
export function encryptText(text) {
  const iv = generateIV();
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(SECRET_KEY.padEnd(32, "0")), iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted; // combine IV + encrypted text
}

// Decrypt function
export function decryptText(encryptedText) {
  const [ivHex, encrypted] = encryptedText.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(SECRET_KEY.padEnd(32, "0")), iv);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}