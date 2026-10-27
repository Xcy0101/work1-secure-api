# Screenshots used by the README and the report

Save the PNG files here with these names so that the Markdown links resolve:

| File | What it must show |
|---|---|
| `01-sast-job.png` | Actions run — `SAST - ESLint security rules` job, green |
| `02-sca-npm-audit.png` | Actions run — `SCA - npm audit` job failing with the CVE-2022-25881 advisory (vulnerable revision) |
| `03-pipeline-failed.png` | Overview of the red run on the vulnerable revision |
| `04-pipeline-success.png` | Overview of the green run after the fix, with the run URL visible |
| `05-vulnerable-env.png` | `docker compose up` + `GET /health` response |
| `06-redos-result.png` | Attack in progress: 100 % CPU / blocked `/health` / PoC console output |
| `07-fix-verified.png` | Same payload answered with `431` and fast `/health` |
| `08-npm-audit-clean.png` | `npm audit` → `found 0 vulnerabilities` |

Tip: take the Actions screenshots from the run page in the browser so that the
repository name and the run number are visible — the grader uses them to confirm
that the pipeline really ran.