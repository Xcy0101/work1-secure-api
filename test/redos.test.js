'use strict';

// Security regression tests for CVE-2022-25881.
//
// On http-cache-semantics@4.1.0 the parser needs hundreds of milliseconds for a
// whitespace-heavy header and the first assertion below fails. With 4.1.1 the
// parser is linear and both assertions pass.

const test = require('node:test');
const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const request = require('supertest');

const CachePolicy = require('http-cache-semantics');
const { createDb } = require('../src/db');
const { createApp } = require('../src/app');

const PAYLOAD = 'no-cache' + ' '.repeat(15000) + 'x';
const FAST_MS = 50;

test('the parser stays linear on a 15 KB whitespace payload', () => {
  const started = performance.now();
  const policy = new CachePolicy(
    { method: 'GET', url: '/', headers: { host: 'test', 'cache-control': PAYLOAD } },
    { status: 200, headers: { 'cache-control': 'max-age=60' } }
  );
  const elapsed = performance.now() - started;
  policy.toObject();
  assert.ok(
    elapsed < FAST_MS,
    'parsing took ' + elapsed.toFixed(1) + ' ms; http-cache-semantics < 4.1.1 is vulnerable'
  );
});

test('the API rejects an oversized Cache-Control header before parsing it', async () => {
  const app = createApp(createDb(':memory:'));
  const login = await request(app)
    .post('/auth/login')
    .send({ username: 'alice', password: 'S3curePass!' });
  const res = await request(app)
    .post('/api/cache-policy')
    .set('Authorization', 'Bearer ' + login.body.token)
    .set('Cache-Control', PAYLOAD);
  assert.equal(res.status, 431);
  assert.equal(res.body.reason, 'too_long');
});