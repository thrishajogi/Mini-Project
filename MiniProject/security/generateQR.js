// security/generateQR.js  – QR for otpauth URI
const QRCode = require('qrcode');

async function generateQR(secret, label = 'user@zerobank.com') {
  const encLabel = encodeURIComponent(label);
  // use SHA1 (most authenticators expect SHA1) and digits=6, period=30
  const uri = `otpauth://totp/ZeroBank:${encLabel}?secret=${secret}&issuer=ZeroBank&algorithm=SHA1&digits=6&period=30`;
  const dataUrl = await QRCode.toDataURL(uri); // base64 image
  return dataUrl; // ready for <img src="...">
}

module.exports = { generateQR };