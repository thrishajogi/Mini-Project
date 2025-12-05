   const crypto = require('crypto');
   const { encrypt, decrypt } = require('./encrypt.js');

   const key = crypto.randomBytes(32).toString('base64');
   const cipher = encrypt('ZeroBank', key);
   console.log('Cipher:', cipher);

   const plain = decrypt(cipher, key);
   console.log('Plain :', plain);