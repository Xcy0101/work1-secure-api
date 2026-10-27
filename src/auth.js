'use strict';

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';
const TOKEN_TTL = '15m';
const ISSUER = 'work1-api';

// Passwords are never stored or compared in plaintext: bcrypt with cost 10.
function hashPassword(password) {
  return bcrypt.hashSync(password, 10);
}

function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

function signToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    SECRET,
    { algorithm: 'HS256', expiresIn: TOKEN_TTL, issuer: ISSUER }
  );
}

// Verifies the JWT on every protected endpoint. Passing an explicit
// `algorithms` list prevents the "alg: none" / algorithm-confusion bypass.
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const match = /^Bearer ([A-Za-z0-9._-]+)$/.exec(header);
  if (!match) {
    return res.status(401).json({ error: 'missing_token' });
  }
  try {
    req.user = jwt.verify(match[1], SECRET, {
      algorithms: ['HS256'],
      issuer: ISSUER
    });
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

module.exports = { hashPassword, verifyPassword, signToken, requireAuth };