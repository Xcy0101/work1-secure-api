# Work 1 — Secure REST API with CI, and reproduction/fix of CVE-2022-25881

A small Node.js/Express REST API that is secured against the OWASP Top 10 issues
requested by the assignment (SQL injection, XSS, broken authentication), scanned
automatically by GitHub Actions (SAST + SCA), and used as the test bench for a
real vulnerability: **CVE-2022-25881 — Regular Expression Denial of Service in
the npm package `http-cache-semantics`**.

* Public repository: `https://github.com/<your-account>/work1-secure-api`
* Last successful pipeline run: `https://github.com/<your-account>/work1-secure-api/actions/runs/<run-id>`

---

## 1. Project and API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/auth/login` | – | Authenticates a user, returns a JWT (HS256, 15 min) |
| `GET` | `/api/data` | Bearer JWT | Returns the post list; `?q=` performs a parameterized LIKE search |
| `POST` | `/api/cache-policy` | Bearer JWT | Parses the request `Cache-Control` header with `http-cache-semantics` and returns the resulting policy |
| `GET` | `/health` | – | Liveness probe used to measure whether the event loop is responsive |

### Run it locally

Requires **Node.js 20 – 24**. `better-sqlite3@12.2.0` ships prebuilt binaries for
these ABIs, so no C++ compiler is needed.

```bash
npm install                 # installs dependencies and writes package-lock.json
npm start                   # http://127.0.0.1:3000
```

### Call it

```bash
# 1. log in and keep the token
TOKEN=$(curl -s -X POST http://127.0.0.1:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"S3curePass!"}' | jq -r .token)

# 2. read protected data
curl -s http://127.0.0.1:3000/api/data -H "Authorization: Bearer $TOKEN"

# 3. search (parameterized)
curl -s 'http://127.0.0.1:3000/api/data?q=cache' -H "Authorization: Bearer $TOKEN"

# 4. own endpoint: inspect the cache policy of the request
curl -s -X POST http://127.0.0.1:3000/api/cache-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Cache-Control: no-cache, max-age=0'

# 5. no token -> 401
curl -i http://127.0.0.1:3000/api/data
```

Seeded accounts: `alice / S3curePass!` (admin) and `bob / An0therPass!`.

---

## 2. Implemented security measures

### 2.1 SQL injection — `src/db.js`, `src/app.js`

Every statement is a prepared statement with bound parameters; user input never
reaches the SQL text:

```js
db.prepare('SELECT id, username, role, password_hash FROM users WHERE username = ?')
  .get(username);
```

The search endpoint also escapes the `LIKE` wildcards (`%`, `_`, `\`) and uses an
explicit `ESCAPE '\'` clause, so `%` typed by a user is a literal percent sign
rather than a wildcard. `ORDER BY` and `LIMIT` are constants, never parameters.

### 2.2 XSS — `src/security.js`

All user-controlled strings are HTML-encoded on output (`& < > " ' \``) before the
JSON response is built, and the service sends `X-Content-Type-Options: nosniff`
plus a restrictive `Content-Security-Policy`. Example result:

```
GET /api/data?q=<script>   ->   {"items": []}    (no raw "<script>" in the body)
```

### 2.3 Authentication — `src/auth.js`

* Passwords are stored as **bcrypt** hashes (cost 10); plaintext is never stored
  or logged.
* A successful login returns a **JWT** signed with HS256, 15-minute expiry,
  issuer `work1-api`.
* `requireAuth` middleware protects `/api/data` and `/api/cache-policy`; a
  missing or invalid token yields `401 {"error":"missing_token"|"invalid_token"}`.
* `jwt.verify` is called with an explicit `algorithms: ['HS256']` list, which
  blocks `alg: none` and algorithm-confusion attempts.
* The login error is identical for an unknown user and a wrong password, so the
  endpoint cannot be used to enumerate accounts.

---

## 3. CI/CD pipeline (`.github/workflows/ci.yml`)

Three jobs run on every push and pull request:

| Job | Tool | What it does | Fails the build when |
|---|---|---|---|
| `sast` | ESLint + `eslint-plugin-security` | static analysis of `src/`, `test/`, `poc/` | a security rule is violated |
| `sca` | `scripts/audit-gate.js` (wraps `npm audit --omit=dev`) | checks the runtime dependency tree against the advisory database | a high/critical advisory is present that is not accepted in `.github/audit-allowlist.json` |
| `test` | `node --test` + `supertest` | API tests and the ReDoS regression test | a test fails |

Both scanners also write JSON reports that are uploaded as workflow artifacts
(`sast-report`, `sca-report`), so the results can be attached to the report.

> **Note:** the workflow uses `npm ci`, so `package-lock.json` must be committed.
> Run `npm install` once before the first push.

> **Reproducing the vulnerable state:** `main` always holds the fixed revision.
> The pre-fix state (guard removed, `http-cache-semantics@4.1.0`) is kept on the
> `vulnerable` branch, and the workflow runs there as well — that is where the red
> pipeline and the `GHSA-rc47-6667-2j5j` entry in the SCA log come from.

### Screenshots

![SAST job](docs/screenshots/01-sast-job.png)
![SCA job detecting CVE-2022-25881](docs/screenshots/02-sca-npm-audit.png)
![Failed pipeline on the vulnerable revision](docs/screenshots/03-pipeline-failed.png)
![Successful pipeline after the fix](docs/screenshots/04-pipeline-success.png)

---

## 4. Selected vulnerability: CVE-2022-25881

| Field | Value |
|---|---|
| CVE | **CVE-2022-25881** |
| Advisory | GHSA-rc47-6667-2j5j |
| Weakness | CWE-1333 — Inefficient Regular Expression Complexity (parent CWE-400) |
| Severity | NVD CVSS 3.1: **7.5 HIGH** (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`); Snyk: 5.3 MEDIUM |
| Package | `http-cache-semantics` (npm and Maven `org.webjars.npm`) |
| Affected | every version `< 4.1.1`, including `4.1.0` |
| Fixed | `4.1.1` |
| Impact | availability only — the Node.js event loop stops serving requests |

**Brief description.** `http-cache-semantics` parses `Cache-Control` header
values. In versions before 4.1.1 the parser splits the header on the regular
expressions `/\s*,\s*/` and `/\s*=\s*/`. For a header value that contains a long
run of spaces and no comma, the regex engine tries `\s*`, then has to give back
one character at a time to look for a `,`. That backtracking happens at every
starting offset, so the parsing cost grows quadratically with the header length.
A single request with a ~15 KB header keeps the single-threaded Node.js event
loop busy for hundreds of milliseconds; a few concurrent connections keep the
process at 100 % CPU and the service stops answering.

---

## 5. Reproducing the vulnerability

### 5.1 Vulnerable environment

`package.json` pins `http-cache-semantics` to `4.1.0`. With Docker:

```bash
docker compose -f docker/docker-compose.yml up --build -d
curl -s http://127.0.0.1:3000/health
```

![Vulnerable container running](docs/screenshots/05-vulnerable-env.png)

### 5.2 Micro-benchmark of the parser

```bash
npm run bench          # installed version vs. the 4.1.1 parser
```

Measured on the test machine (Node.js 24, desktop CPU):

| spaces in header | `4.1.0` | `4.1.1` |
|---:|---:|---:|
| 1 000 | 0.54 ms | 0.002 ms |
| 2 000 | 2.27 ms | 0.002 ms |
| 4 000 | 10.69 ms | 0.010 ms |
| 8 000 | 39.09 ms | 0.031 ms |
| 15 000 | 141.67 ms | 0.019 ms |

Every doubling of the payload roughly quadruples the time — the signature of
quadratic complexity. The fixed parser stays flat.

### 5.3 Attack against the running service

```bash
npm run poc            # logs in, probes /health, then sends the payload
```

```bash
# equivalent raw request
curl -s -o /dev/null -w '%{time_total}\n' -X POST http://127.0.0.1:3000/api/cache-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Cache-Control: no-cache$(printf ' %.0s' $(seq 1 15000))x"
```

Observed on the vulnerable revision: the request needs ~140 ms of CPU, three
`/health` probes issued during the attack all return only after the parse
finishes, and `top` shows the node process at 100 % CPU while the payload keeps
arriving.

![Attack result: event loop blocked](docs/screenshots/06-redos-result.png)

---

## 6. Root cause analysis

1. **Untrusted input reaches a parser.** `new CachePolicy(req, res)` calls
   `parseCacheControl(req.headers['cache-control'])` — the header value is fully
   attacker-controlled.
2. **The parser uses a super-linear regular expression.** In 4.1.0:

   ```js
   const parts = header.trim().split(/\s*,\s*/);       // <-- O(n^2)
   for (const part of parts) {
       const [k, v] = part.split(/\s*=\s*/, 2);        // <-- O(n^2)
       cc[k] = v === undefined ? true : v.replace(/^"|"$/g, '');
   }
   ```

   `\s*` is greedy and matched against a run of spaces. When the following `,`
   is missing, the engine backtracks one space at a time. `String.prototype.split`
   retries at every offset, so the work is `Θ(n²)` instead of `Θ(n)`.
3. **Nothing bounds `n`.** Node.js accepts headers up to
   `--max-http-header-size` (16 KiB by default, sometimes raised to 64 KiB for
   large cookies), and the library imposes no length limit of its own.
4. **The runtime is single-threaded.** The regex runs to completion inside one
   tick of the event loop; no other request, timer or socket callback can run
   while it executes. This turns a CPU-cost bug into a denial of service.

In other words the defect is not a logic error in the business code — it is an
*algorithmic complexity* flaw inside a third-party component that the
application passes user input to. This is exactly the class of risk that SCA
exists to catch and that SAST on your own sources cannot see.

---

## 7. Applied fix

Two layers (files in [`fix/`](fix/)):

### 7.1 Primary fix — upgrade the dependency

```bash
npm install http-cache-semantics@4.1.1
npm ls http-cache-semantics      # http-cache-semantics@4.1.1
```

4.1.1 removes the ambiguous `\s*` from both split patterns and trims the pieces
instead:

```js
const parts = header.trim().split(/,/);
for (const part of parts) {
    const [k, v] = part.split(/=/, 2);
    cc[k.trim()] = v === undefined ? true : v.trim().replace(/^"|"$/g, '');
}
```

The parser becomes linear, so the payload has no measurable effect. The upgrade
also removes the advisory from `npm audit`, which turns the `sca` job green.

### 7.2 Defence in depth — bound the input before parsing

`checkCacheControl()` in `fix/security.js` (wired into `fix/app.js`) rejects,
before the library is ever called:

* values longer than **1024 bytes** → `431 too_long`,
* characters outside printable ASCII/tab → `431 illegal_characters`,
* more than 32 directives → `431 too_many_directives`.

The guard pattern `/^[\t\x20-\x7E]*$/` is a single character class and therefore
linear itself. Even if a future version of the library reintroduced a
super-linear expression, the attacker could no longer supply a long enough
input to exploit it.

### 7.3 Why this is effective

* The quadratic term disappears at the source (dependency upgrade), which fixes
  the root cause rather than hiding it.
* The length cap removes the attacker's control over `n`, which is the variable
  the complexity depends on — a defence that survives the next parser bug.
* No functional behaviour changes: valid `Cache-Control` values such as
  `no-cache, max-age=0` still parse into the expected directives (covered by
  tests).

---

## 8. Proof that the vulnerability is eliminated

```bash
npm test        # includes test/redos.test.js
npm run poc
npm run audit   # scripts/audit-gate.js
```

* `test/redos.test.js` fails on 4.1.0 (“parsing took ~140 ms”) and passes on
  4.1.1 (well under the 50 ms budget).
* `npm run poc` against the fixed build returns
  `431 {"error":"cache_control_rejected","reason":"too_long"}` and the `/health`
  probes stay in the single-digit millisecond range.
* `npm run audit` reports **no unaccepted high or critical advisory**, and the
  pipeline is green.

> `npm audit` on its own still reports three advisories in transitive packages
> (`body-parser`, `path-to-regexp`, and a second one in
> `http-cache-semantics`) for which **no patched release exists**. They are
> listed with a reason and a review date in `.github/audit-allowlist.json`;
> anything not listed there fails `scripts/audit-gate.js`. Advisories would
> otherwise keep the pipeline permanently red, which in practice means the gate
> gets switched off.

| Measurement | Vulnerable (4.1.0) | Fixed (4.1.1 + guard) |
|---|---|---|
| 15 KB payload, parse time | 141.67 ms | 0.02 ms |
| `/health` during attack | 138–145 ms | 2–4 ms |
| HTTP status of the attack | `200` | `431` |
| SCA gate (unaccepted advisories) | 1 — `GHSA-rc47-6667-2j5j` | 0 |

![Fix verified](docs/screenshots/07-fix-verified.png)
![npm audit clean](docs/screenshots/08-npm-audit-clean.png)

---

## 9. Repository layout

```
.
├── .github/workflows/ci.yml     # SAST + SCA + tests
├── .github/audit-allowlist.json # accepted advisories, with reason and review date
├── scripts/
│   └── audit-gate.js            # SCA gate: fails on an unaccepted high/critical advisory
├── src/
│   ├── app.js                   # Express routes
│   ├── auth.js                  # bcrypt + JWT
│   ├── db.js                    # SQLite schema, seed data, prepared statements
│   ├── security.js              # escaping helpers
│   └── server.js                # entry point
├── test/
│   ├── api.test.js              # functional and injection tests
│   └── redos.test.js            # CVE-2022-25881 regression tests
├── poc/
│   ├── bench.js                 # parser micro-benchmark
│   └── redos-poc.js             # end-to-end attack script
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── fix/                         # patched files submitted with the report
│   ├── app.js
│   ├── security.js
│   ├── package.json
│   └── FIX_NOTES.md
└── docs/screenshots/
```

## 10. References

1. NVD — CVE-2022-25881: https://nvd.nist.gov/vuln/detail/CVE-2022-25881
2. GitHub Advisory GHSA-rc47-6667-2j5j: https://github.com/advisories/GHSA-rc47-6667-2j5j
3. OSV — CVE-2022-25881: https://osv.dev/vulnerability/CVE-2022-25881
4. `http-cache-semantics` source: https://github.com/kornelski/http-cache-semantics
5. CWE-1333: https://cwe.mitre.org/data/definitions/1333.html
6. OWASP Top 10 2021: https://owasp.org/www-project-top-ten/