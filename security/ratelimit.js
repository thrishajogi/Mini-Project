// security/rate-limit.js  – in-memory fail counter (Redis can replace later)
const fails = {};   // fails[ip:email] = count
const blockedUsers = new Set(); // Store blocked users

function failKey(ip, user) {
  return `${ip}:${user}`;
}

// Express middleware: 3 fails max then permanent block until manual reset
function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const user = (req.body.email || req.body.username || 'unknown').toLowerCase();
  const key = failKey(ip, user);

  // Check if user is already blocked
  if (blockedUsers.has(key)) {
    return res.status(403).json({ 
      error: 'Account blocked due to too many failed attempts. Please contact support for manual unblock.',
      blocked: true
    });
  }

  fails[key] = (fails[key] || 0) + 1;
  
  if (fails[key] > 3) {
    // Block user after 3 failed attempts
    blockedUsers.add(key);
    delete fails[key]; // Clear fail counter since user is now blocked
    
    return res.status(403).json({
      error: 'Account blocked due to too many failed attempts. Please contact support for manual unblock.',
      blocked: true
    });
  }

  // Inform user of remaining attempts
  const remainingAttempts = 3 - fails[key];
  res.locals.remainingAttempts = remainingAttempts;
  
  next();
}

// Manual unblock function - to be used by admin/support team only
function manualUnblock(ip, user) {
  const key = failKey(ip, user);
  blockedUsers.delete(key);
  delete fails[key];
  return true;
}

// reset counter on successful login
function resetLimit(ip, user) {
  const key = failKey(ip, user);
  delete fails[key];
}

module.exports = { rateLimit, resetLimit, manualUnblock };