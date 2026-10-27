'use strict';

/**
 * SCA gate.
 *
 * Runs `npm audit` on the runtime dependency tree and fails the build when a
 * high or critical advisory is reported that is not listed in the risk
 * acceptance file (.github/audit-allowlist.json).
 *
 * Why not simply `npm audit --audit-level=high`? Because the tree contains
 * advisories that have no upstream fix at all (body-parser, path-to-regexp and
 * one in http-cache-semantics). A gate that fires on those can never turn
 * green and would be tuned down until it catches nothing. Accepted advisories
 * are therefore explicit, reviewed and printed on every run, while anything
 * new — in particular CVE-2022-25881 in http-cache-semantics < 4.1.1 — still
 * breaks the build.
 *
 * Usage: node scripts/audit-gate.js
 * Exit codes: 0 = nothing unaccepted, 1 = unaccepted high/critical advisory.
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ALLOWLIST_PATH = path.join(__dirname, '..', '.github', 'audit-allowlist.json');

function runAudit() {
  const args = ['audit', '--omit=dev', '--json'];
  // On Windows npm is a .cmd shim, which cannot be spawned without a shell
  // (Node >= 20.12 refuses it with EINVAL). The arguments are constants, so
  // using a shell here does not introduce an injection surface.
  const options = {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    shell: process.platform === 'win32'
  };
  try {
    return execFileSync(npmCommand(), args, options);
  } catch (err) {
    // npm exits with 1 when it reports vulnerabilities; the JSON is still on stdout.
    if (err.stdout) return err.stdout;
    throw err;
  }
}

function npmCommand() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

function loadAllowlist() {
  if (!fs.existsSync(ALLOWLIST_PATH)) return { accepted: [] };
  return JSON.parse(fs.readFileSync(ALLOWLIST_PATH, 'utf8'));
}

function collectAdvisories(report) {
  const found = new Map();
  for (const [name, entry] of Object.entries(report.vulnerabilities || {})) {
    for (const via of entry.via || []) {
      if (typeof via !== 'object') continue;
      const severity = String(via.severity || entry.severity || '').toLowerCase();
      if (severity !== 'high' && severity !== 'critical') continue;
      // npm reports the advisory identifier inside the URL, not as its own field.
      const match = String(via.url || '').match(/GHSA-[0-9a-z-]+/i);
      const id = match ? match[0] : String(via.url || via.title || name);
      if (found.has(id)) continue;
      found.set(id, {
        ghsa: id,
        package: name,
        title: via.title || '',
        cve: Array.isArray(via.cve) ? via.cve.join(', ') : via.cve || '',
        url: via.url || ''
      });
    }
  }
  return [...found.values()];
}

function main() {
  const report = JSON.parse(runAudit());
  const advisories = collectAdvisories(report);
  const { accepted } = loadAllowlist();
  const acceptedIds = new Set(accepted.map((a) => a.ghsa.toLowerCase()));

  const failing = advisories.filter((a) => !acceptedIds.has(a.ghsa.toLowerCase()));
  const tolerated = advisories.filter((a) => acceptedIds.has(a.ghsa.toLowerCase()));

  console.log(`runtime advisories of high or critical severity: ${advisories.length}`);
  for (const a of tolerated) {
    const reason = accepted.find((x) => x.ghsa === a.ghsa).reason || 'accepted';
    console.log(`  ACCEPTED  ${a.ghsa}  ${a.package}  ${a.cve || '-'}  (${reason})`);
  }
  for (const a of failing) {
    console.log(`  FAIL      ${a.ghsa}  ${a.package}  ${a.cve || '-'}  ${a.title}`);
  }

  if (failing.length > 0) {
    console.error(`\n${failing.length} unaccepted advisory/advisories: fix them or document them in .github/audit-allowlist.json.`);
    return 1;
  }
  console.log('\nno unaccepted high or critical advisory in the runtime dependency tree');
  return 0;
}

process.exit(main());