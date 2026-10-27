'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const { createDb } = require('../src/db');
const { createApp } = require('../src/app');

const app = createApp(createDb(':memory:'));

async function login(username = 'alice', password = 'S3curePass!') {
  const res = await request(app).post('/auth/login').send({ username, password });
  return res;
}

test('login returns a token for valid credentials', async () => {
  const res = await login();
  assert.equal(res.status, 200);
  assert.equal(res.body.tokenType, 'Bearer');
  assert.match(res.body.token, /^[A-Za-z0-9._-]+$/);
});

test('login fails with a wrong password and does not leak whether the user exists', async () => {
  const wrongPassword = await login('alice', 'nope');
  const unknownUser = await login('mallory', 'nope');
  assert.equal(wrongPassword.status, 401);
  assert.equal(unknownUser.status, 401);
  assert.deepEqual(wrongPassword.body, unknownUser.body);
});

test('/api/data is denied without a token', async () => {
  const res = await request(app).get('/api/data');
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'missing_token');
});

test('/api/data is denied with a forged token', async () => {
  const res = await request(app).get('/api/data').set('Authorization', 'Bearer abc.def.ghi');
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'invalid_token');
});

test('/api/data returns rows for an authenticated user', async () => {
  const { body } = await login();
  const res = await request(app).get('/api/data').set('Authorization', 'Bearer ' + body.token);
  assert.equal(res.status, 200);
  assert.equal(res.body.requestedBy, 'alice');
  assert.ok(res.body.items.length >= 3);
});

test('SQL injection in the search term is treated as data', async () => {
  const { body } = await login();
  const evil = "x' OR 1=1 --";
  const res = await request(app)
    .get('/api/data')
    .query({ q: evil })
    .set('Authorization', 'Bearer ' + body.token);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.items, []);
});

test('XSS payloads are returned encoded', async () => {
  const { body } = await login();
  const res = await request(app)
    .get('/api/data')
    .query({ q: '<script>' })
    .set('Authorization', 'Bearer ' + body.token);
  assert.equal(res.status, 200);
  const serialized = JSON.stringify(res.body);
  assert.equal(serialized.includes('<script>'), false);
});

test('/api/cache-policy parses a normal Cache-Control header', async () => {
  const { body } = await login();
  const res = await request(app)
    .post('/api/cache-policy')
    .set('Authorization', 'Bearer ' + body.token)
    .set('Cache-Control', 'no-cache, max-age=0');
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.requestDirectives.sort(), ['max-age', 'no-cache']);
});