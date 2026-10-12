# GUI guide

Start the GUI with `white serve` and open <http://127.0.0.1:8000>.

## Modes

| Mode | When | Behaviour |
| --- | --- | --- |
| Local single-user | `SUPABASE_URL` / `SUPABASE_PUBLISHABLE_KEY` not set | No sign-in. History is stored in `~/.white/white.db`. Domain verification is off by default. Keep the server bound to 127.0.0.1. |
| Accounts | Supabase configured | Sign-up, sign-in, password reset, per-user history stored in Supabase with Row Level Security. Domain verification is required by default. |

## Pages

| Page | Path | Purpose |
| --- | --- | --- |
| Welcome | `/` | What WHITE checks and does not do. |
| Sign up / Sign in | `/signup`, `/login` | Supabase email + password accounts. |
| Forgot / reset password | `/forgot-password`, `/reset-password` | Email link, then choose a new password. |
| Dashboard | `/dashboard` | Executive overview of the most recent completed scan of a chosen website. |
| New scan | `/scans/new` | URL, authorization confirmation, optional active checks, list of checks. |
| Scan progress | `/scans/{id}` while running | Real status, current stage, completed/total checks, elapsed time, cancel. |
| Report | `/scans/{id}` when finished | Summary, severity cards, charts, next steps, findings grouped by severity, check coverage, limitations, downloads (PDF/JSON/HTML), delete. |
| Finding details | `/scans/{id}/findings/{finding}` | What was detected, why it matters, what to do, severity and confidence, evidence, technical details. |
| Scan history | `/history` | All your scans with dates, statuses and finding counts. |
| Domains | `/domains` | Add a domain and verify it by DNS TXT record or verification file (shown when verification is required). |
| Settings | `/settings` | Account details, change password, sign out everywhere. |

## Dashboard charts

All charts use the stored reports of the signed-in user only. Each chart has a text alternative and a
"Show data as a table" view.

| Chart | Data |
| --- | --- |
| Overview cards | Most recent completed scan, findings recorded (with change vs the previous comparable scan), high-priority issues (critical + high), checks completed (excludes skipped and failed checks). |
| Severity doughnut | Count of findings per severity in the most recent completed scan. |
| Findings by category | Connection protection, browser security, cookies, information exposure, website configuration, input handling. |
| Progress over time | Per completed scan of the same address: newly detected, still present, no longer detected and not re-verified. Requires at least two completed scans; otherwise an explanation is shown. |
| Scan coverage | Number of checks per outcome: passed, issue found, possible issue, inconclusive, not applicable, skipped, error. |
| What to do next | Up to six actions ordered by severity, then confirmed before possible, then confidence. |

WHITE never shows a "secure" score. The overall label is one of: urgent action recommended, important
issues found, improvements recommended, minor improvements suggested, no issues detected by these
checks, or assessment incomplete.

## Interpreting results

- **Severity** is the potential impact; **confidence** is how sure WHITE is about the observation.
- **Possible issue** (POTENTIAL) means an indicator that a qualified person should confirm.
- **Passed** means only that the specific issue was not detected in this scan.
