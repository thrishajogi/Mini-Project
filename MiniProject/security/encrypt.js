// security/encrypt.js  – AES-256-GCM helpers
const crypto = require('crypto');

function encrypt(text, base64Key) {
  const key = Buffer.from(base64Key, 'base64');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return { ct: ct.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}

function decrypt(encObj, base64Key) {
  const key = Buffer.from(base64Key, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encObj.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(encObj.tag, 'base64'));
  return decipher.update(Buffer.from(encObj.ct, 'base64'), undefined, 'utf8') + decipher.final('utf8');
}

module.exports = { encrypt, decrypt };