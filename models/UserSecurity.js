const mongoose = require('mongoose');

const userSecuritySchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },

  securityQuestion: {
    question: String,
    answer: String
  },

  totpSecret: {
    type: String,
    required: false   // FIXED (not required during first login)
  },

  attempts: {
    count: {
      type: Number,
      default: 0
    },
    lastAttempt: Date
  },

  isBlocked: {
    type: Boolean,
    default: false
  },

  blockExpiry: Date

}, { timestamps: true });

module.exports = mongoose.model('UserSecurity', userSecuritySchema);
