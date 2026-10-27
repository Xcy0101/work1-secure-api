# Fix folder

Files submitted together with the report (assignment item 4). They are the
patched versions of the project files:

| File | Change |
|---|---|
| `package.json` | `http-cache-semantics` 4.1.0 → 4.1.1 |
| `security.js` | adds `checkCacheControl()` — length, charset and directive-count guard |
| `app.js` | calls `checkCacheControl()` in `POST /api/cache-policy` and returns `431` on rejection |

## How to apply

```bash
# from the repository root
npm install http-cache-semantics@4.1.1
cp fix/security.js src/security.js
cp fix/app.js src/app.js

npm test                 # redos.test.js now passes
npm audit                # found 0 vulnerabilities
git add -A
git commit -m "fix: upgrade http-cache-semantics to 4.1.1 and bound Cache-Control length (CVE-2022-25881)"
git push
```

Check with `git diff HEAD~1` that exactly these three things changed:
the dependency version, the guard function, and the `431` branch in the route.