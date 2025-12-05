// test-mongo.js
require('dotenv').config();
const mongoose = require('mongoose');

const user = process.env.MONGO_USER || '<MONGO_USER>';
const passRaw = process.env.MONGO_PASS || '<MONGO_PASS>';
const host = process.env.MONGO_HOST || '<MONGO_HOST>';
const db = process.env.MONGO_DB || 'ZeroBankDB';

const pass = encodeURIComponent(passRaw);
const uri = `mongodb+srv://${user}:${pass}@${host}/${db}?retryWrites=true&w=majority`;

// Masked URI for printing (password masked)
const maskedURI = `mongodb+srv://${user}:***@${host}/${db}?retryWrites=true&w=majority`;
console.log('Using (masked) URI:', maskedURI);

mongoose.connect(uri, {
  // new driver ignores useNewUrlParser/useUnifiedTopology flags; keeping clean
})
  .then(() => {
    console.log('Connected OK');
    mongoose.disconnect();
  })
  .catch(err => {
    console.error('Connect ERROR:', err.message || err);
    // print full error object (redact if posting publicly)
    console.error(err);
    process.exit(1);
  });
