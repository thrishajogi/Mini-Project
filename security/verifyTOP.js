const { generateSecret, generateTOTP } = require("./totp.js");
console.log("running");

function verifyTOTP(secret, userOTP) {
  const current = generateTOTP(secret);
  return current === userOTP;
}

// --- Test the verification ---
const secret = generateSecret();
const otp = generateTOTP(secret);

console.log("Secret:", secret);
console.log("Generated OTP:", otp);
console.log("Verify OTP (correct):", verifyTOTP(secret, otp));
console.log("Verify OTP (wrong):", verifyTOTP(secret, "123456"));