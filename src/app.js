'use strict';

// Fixed revision of src/app.js.
// The only functional change is the guard in POST /api/cache-policy.

const express = require('express');
const CachePolicy = require('http-cache-semantics');

const { verifyPassword, signToken, requireAuth } = require('./auth');
const { escapeHtml, escapeLike, checkCacheControl } = require('./security');

function createApp(db) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '10kb' }));

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.post('/auth/login', (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'bad_request' });
    }
    const user = db
      .prepare('SELECT id, username, role, password_hash FROM users WHERE username = ?')
      .get(username);
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    return res.json({ token: signToken(user), tokenType: 'Bearer', expiresIn: 900 });
  });

  app.get('/api/data', requireAuth, (req, res) => {
    const q = typeof req.query.q === 'string' ? req.query.q : '';
    const rows = q
      ? db
          .prepare(
            "SELECT p.id, p.title, p.body, u.username AS author " +
              'FROM posts p JOIN users u ON u.id = p.author_id ' +
              "WHERE p.title LIKE ? ESCAPE '\\' OR p.body LIKE ? ESCAPE '\\' " +
              'ORDER BY p.id LIMIT 50'
          )
          .all('%' + escapeLike(q) + '%', '%' + escapeLike(q) + '%')
      : db
          .prepare(
            'SELECT p.id, p.title, p.body, u.username AS author ' +
              'FROM posts p JOIN users u ON u.id = p.author_id ORDER BY p.id LIMIT 50'
          )
          .all();

    return res.json({
      requestedBy: req.user.username,
      items: rows.map((row) => ({
        id: row.id,
        title: escapeHtml(row.title),
        body: escapeHtml(row.body),
        author: escapeHtml(row.author)
      }))
    });
  });

  // FIX: reject oversized or malformed Cache-Control values before parsing.
  app.post('/api/cache-policy', requireAuth, (req, res) => {
    const check = checkCacheControl(req.headers['cache-control']);
    if (!check.ok) {
      return res.status(431).json({ error: 'cache_control_rejected', reason: check.reason });
    }

    const policy = new CachePolicy(
      {
        method: 'GET',
        url: '/api/cache-policy',
        headers: { host: req.headers.host || 'localhost', 'cache-control': check.value }
      },
      { status: 200, headers: { 'cache-control': 'max-age=60' } }
    );

    return res.json({
      storable: policy.storable(),
      ttlMs: Math.round(policy.timeToLive()),
      requestDirectives: Object.keys(policy.toObject().reqcc)
    });
  });

  app.get('/health', (req, res) => res.json({ status: 'ok', pid: process.pid }));

  app.use((req, res) => res.status(404).json({ error: 'not_found' }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    res.status(500).json({ error: 'internal_error' });
  });

  return app;
}

module.exports = { createApp };