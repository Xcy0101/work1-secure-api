'use strict';

const Database = require('better-sqlite3');
const { hashPassword } = require('./auth');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS posts (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL REFERENCES users(id),
  title     TEXT NOT NULL,
  body      TEXT NOT NULL
);
`;

const SEED_USERS = [
  { username: 'alice', password: 'S3curePass!', role: 'admin' },
  { username: 'bob', password: 'An0therPass!', role: 'user' }
];

const SEED_POSTS = [
  { author: 'alice', title: 'Welcome to Work 1', body: 'This API is used as the test bench for CVE-2022-25881.' },
  { author: 'alice', title: 'Cache-Control handling', body: 'The /api/cache-policy endpoint parses the request Cache-Control header.' },
  { author: 'bob', title: 'Notes', body: 'Passwords are hashed with bcrypt, tokens are signed with HS256.' }
];

function createDb(file = ':memory:') {
  const db = new Database(file);
  if (file !== ':memory:') db.pragma('journal_mode = WAL');
  db.exec(SCHEMA);

  const insertUser = db.prepare(
    'INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)'
  );
  for (const u of SEED_USERS) {
    insertUser.run(u.username, hashPassword(u.password), u.role);
  }

  const userId = db.prepare('SELECT id FROM users WHERE username = ?');
  const insertPost = db.prepare(
    'INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)'
  );
  const count = db.prepare('SELECT COUNT(*) AS n FROM posts').get().n;
  if (count === 0) {
    for (const p of SEED_POSTS) {
      insertPost.run(userId.get(p.author).id, p.title, p.body);
    }
  }
  return db;
}

module.exports = { createDb };