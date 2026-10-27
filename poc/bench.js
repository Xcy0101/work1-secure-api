'use strict';

// Compares the Regexp cost of the installed http-cache-semantics with a local
// copy of the 4.1.1 parser. No server needed:  npm run bench

const { performance } = require('node:perf_hooks');
const CachePolicy = require('http-cache-semantics');

function parseFixed(header) {
  const cc = {};
  if (!header) return cc;
  const parts = header.trim().split(/,/);
  for (const part of parts) {
    const [k, v] = part.split(/=/, 2);
    cc[k.trim()] = v === undefined ? true : v.trim().replace(/^"|"$/g, '');
  }
  return cc;
}

function readInstalled(header) {
  const policy = new CachePolicy(
    { method: 'GET', url: '/', headers: { host: 'bench', 'cache-control': header } },
    { status: 200, headers: { 'cache-control': 'max-age=60' } }
  );
  return policy.toObject().reqcc;
}

const version = require('http-cache-semantics/package.json').version;
console.log('installed http-cache-semantics:', version);
console.log('spaces\tinstalled ms\tfixed ms\n');

let previous = 0;
for (const n of [1000, 2000, 4000, 8000, 15000]) {
  const header = 'no-cache' + ' '.repeat(n) + 'x';
  readInstalled('no-cache');

  let started = performance.now();
  readInstalled(header);
  const installed = performance.now() - started;

  started = performance.now();
  parseFixed(header);
  const fixed = performance.now() - started;

  const growth = previous ? ' (' + (installed / previous).toFixed(1) + 'x vs previous row)' : '';
  previous = installed;
  console.log('%s\t%s\t\t%s%s', n, installed.toFixed(2), fixed.toFixed(3), growth);
}