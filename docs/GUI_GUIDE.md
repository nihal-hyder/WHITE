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
| Home | `/` | Full product homepage for business leaders: intro animation, hero with interactive 3D globe, leadership questions, facts, how it works, product, report anatomy, coverage (generated from the real check list), audiences, responsible-use limits, FAQ and call to action. |
| Security, Privacy, Acceptable use | `/security`, `/privacy`, `/acceptable-use` | Plain-language policy pages linked from the footer. |
| Sign up / Sign in | `/signup`, `/login` | Supabase email + password accounts. |
| Forgot / reset password | `/forgot-password`, `/reset-password` | Email link, then choose a new password. |
| Dashboard | `/dashboard` | Executive overview of the most recent completed scan of a chosen website. |
| New scan | `/scans/new` | URL, authorization confirmation, optional active checks, list of checks. |
| Scan progress | `/scans/{id}` while running | Animated live view: a progress ring with a radar sweep, a checklist of all checks that tick off as they complete (the current one spinning), the current stage, a ticking elapsed timer, and cancel. All values are the real job status; the page reloads into the report when the scan finishes. |
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

## Design and motion

- Solid colours only (warm ivory, deep ink, emerald accent, copper highlight); Instrument Serif headings and
  Inter body text, both bundled locally under `web/static/fonts/` (SIL Open Font License).
- The homepage shows a short intro animation on every load (it waits for fonts and the page to load, with a
  minimum of about 1.7 seconds and a 4-second failsafe), then reveals the hero.
- Custom cursor (dot + trailing ring that grows over interactive elements), magnetic buttons, 3D tilt cards,
  scroll reveals and a 3D headline that tilts with the pointer; individual words lift on hover.
- The globe is drawn on a plain canvas (no 3D library) and pauses when off-screen or when the tab is hidden.
- With the operating system's "reduce motion" setting enabled, animations are minimised. On touch
  devices the custom cursor and pointer effects are disabled. Without JavaScript all content remains visible.
- Homepage examples (floating cards, sample finding) are labelled "Example" / "Illustrative example". The
  homepage contains no invented customers, testimonials or usage numbers.

## Operator admin console (`/admin`)

A separate console for the person running WHITE (not the end users). Open **`/admin`** and sign in
with the operator username and password — default **`nihal` / `nihal`** (change them for anything
beyond local use). It is gated by its own login and session, independent of user accounts.

It shows:

- **Registered users** — count, emails, sign-up and last-sign-in dates, confirmation status, and how
  many scans each has run. *This requires Supabase accounts plus a service key (see below).*
- **All scans** across every user — target, status, findings and high-priority counts, and when.
- Headline metrics: users, total scans, scans in the last 7 days, findings and high-priority totals.

The console is **read-only**. Configure it with these environment variables (all optional):

| Variable | Purpose |
| --- | --- |
| `WHITE_ADMIN_USER` / `WHITE_ADMIN_PASSWORD` | Operator credentials (default `nihal`/`nihal`). |
| `WHITE_ADMIN_PASSWORD_HASH` | A strong PBKDF2 hash instead of a plaintext password (recommended). Generate with `python -c "from white.auth.passwords import hash_password; print(hash_password('…'))"`. |
| `WHITE_ADMIN_ENABLED` | Force the console on/off. |
| `WHITE_SUPABASE_SERVICE_KEY` | Supabase **service-role** key, needed to list registered users and their emails. Used only server-side by `/admin`, never sent to the browser. Without it, the console shows only locally stored scans. |

Safety: the login is rate-limited and the password is stored only as a PBKDF2 hash. On a public
(serverless) deployment the console is disabled unless you set a real `WHITE_ADMIN_PASSWORD_HASH`,
so the default credentials can never be exposed to the internet.
