   const { generateSecret, verifyTOTP } = require('./security/totp.js');

   const secret = generateSecret();
   console.log('Secret:', secret);

   const otp = verifyTOTP('000000', secret);
   console.log('000000 valid?', otp);          // should be false

   const good = verifyTOTP('123456', secret);  // dummy – will fail
   console.log('123456 valid?', good);