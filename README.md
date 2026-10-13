# WHITE - Website Security Assessment Tool

WHITE checks a website you own for common, externally visible security weaknesses and explains the
results in plain English for business owners, with technical evidence for IT staff.

It has two interfaces that share one Python scanning engine and one versioned finding schema:

- **CLI** (`white`) - terminal scanning and JSON/HTML/PDF reports. Needs no server and no account.
- **GUI** (`white serve`) - a browser-based executive dashboard with charts, scan history, report
  downloads and (optionally) Supabase accounts.

> **Authorized use only.** Only scan websites you own or have explicit permission to assess.
> WHITE performs a limited, non-intrusive assessment. It cannot detect every vulnerability and never
> claims that a website is secure.

## What WHITE does

21 independent checks (`white checks` lists them):

| Area | Checks |
| --- | --- |
| Connection protection | HTTPS availability and certificate trust, HTTP->HTTPS redirect, TLS certificate expiry and protocol, HSTS, mixed content |
| Browser security | Content-Security-Policy, clickjacking protection, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Cookies | Secure, HttpOnly and SameSite attributes (values are never recorded) |
| Information exposure | Server/version headers, stack traces and debug pages, directory listing, `/.git/HEAD`, `/.env`, `/.DS_Store`, `/server-status`, `/phpinfo.php`, robots.txt, sitemap.xml |
| Website configuration | Insecure redirects (HTTPS->HTTP downgrade, unexpected domains), insecure form actions |
| Input handling (opt-in) | Reflected-input (XSS) indicator, SQL error indicator - harmless GET probes, reported only as "possible issues" |

Each check returns PASS, FINDING, POTENTIAL, INCONCLUSIVE, NOT_APPLICABLE, NOT_TESTED or ERROR.
Findings carry severity (Critical/High/Medium/Low/Informational) and, separately, confidence
(High/Medium/Low), plus a plain-English explanation, business impact, next step, evidence and
technical remediation. Rules are documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What WHITE does not do

No login, form submission, POST requests, password guessing, brute force, exploitation,
denial-of-service testing, stealth or evasion. It refuses private, local and cloud-metadata network
addresses, limits every scan (40 requests, 120 s, 2 MB per response) and never executes downloaded
content. It does not estimate financial loss or produce a "security score".

## Project structure

```
WHITE/
  README.md  LICENSE  CLAUDE.md (Claude.md)  pyproject.toml  requirements.txt  requirements-dev.txt
  .env.example  .gitignore
  src/white/
    config.py            settings from environment / .env
    scanner/             engine, checks/, SSRF-safe HTTP client, models (finding schema)
    reporting/           analytics (charts, history), JSON, HTML, PDF
    cli/                 Typer CLI
    api/                 FastAPI app, routes, jobs, CSRF/security middleware
    auth/                Supabase Auth client, server-side sessions, domain verification
    database/            SQLite and Supabase repositories
    web/                 Jinja2 templates, CSS, JS, vendored Chart.js
  supabase/migrations/   SQL schema with Row Level Security
  tests/                 unit/, integration/, security/
  docs/                  ARCHITECTURE, SECURITY, CLI_GUIDE, GUI_GUIDE, SUPABASE_SETUP,
                         TROUBLESHOOTING, TESTING, IMPLEMENTATION_PLAN
```

## Prerequisites

- Python **3.11 or newer** (verified with 3.13.7)
- Git (to clone)
- Optional: a Supabase project for accounts and cloud history

## Installation

### Windows (PowerShell)

```powershell
git clone <your-repository-url> WHITE
cd WHITE
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e . --no-deps
white --version
```

If activation is blocked, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or call
`.\.venv\Scripts\white.exe` directly.

### Linux / macOS

```bash
git clone <your-repository-url> WHITE
cd WHITE
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e . --no-deps
white --version
```

`pip install -e ".[dev]"` also works if you prefer unpinned (range-constrained) dependencies.

## Configuration

Everything is optional for the CLI. For the GUI, copy the template and set a secret:

```bash
cp .env.example .env          # Windows: Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste as WHITE_SECRET_KEY
```

| Variable | Purpose | Default |
| --- | --- | --- |
| `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` | Enable accounts + cloud history (publishable/anon key only) | unset = local mode |
| `WHITE_SECRET_KEY` | Signs CSRF tokens, encrypts stored sessions | temporary key (sessions reset on restart) |
| `WHITE_SITE_URL` | Public GUI address used in email links | `http://127.0.0.1:8000` |
| `WHITE_DATA_DIR` | Local SQLite data | `~/.white` |
| `WHITE_REQUIRE_DOMAIN_VERIFICATION` | Require DNS/file ownership proof before scanning | `true` with Supabase, else `false` |
| `WHITE_REQUEST_TIMEOUT`, `WHITE_MAX_SCAN_SECONDS`, `WHITE_MAX_RESPONSE_BYTES` | Scanner limits | 10, 120, 2000000 |
| `WHITE_MAX_CONCURRENT_SCANS`, `WHITE_SCANS_PER_USER_PER_HOUR` | Abuse limits | 3, 20 |
| `WHITE_ALLOW_PRIVATE_TARGETS` | Development only: allow private IPs in the GUI | `false` |

Check with `white config` and `white doctor`.

## Running the GUI

```bash
white serve
```

Open **<http://127.0.0.1:8000>**. Stop with Ctrl+C. Use `white serve --port 8001` to change the port.

- **Without Supabase** the GUI runs in local single-user mode (no sign-in; history on this computer).
- **With Supabase** you get sign-up, sign-in, email confirmation, password reset, account settings,
  per-user history and domain verification. See below.

### Creating an account and signing in (accounts mode)

1. Apply the database migration and configure Auth URLs ([docs/SUPABASE_SETUP.md](docs/SUPABASE_SETUP.md)).
2. Open `http://127.0.0.1:8000/signup`, enter email and a password (8+ characters).
3. Open the confirmation email and click the link (it returns to `/auth/callback` and signs you in).
4. Later visits: `http://127.0.0.1:8000/login`. Forgot your password? Use "Forgot your password?".
5. Before scanning, add your domain on **Domains** and verify it with the shown DNS TXT record
   (`_white-verify.<domain>`) or file (`https://<domain>/.well-known/white-verify.txt`).

## CLI examples

```bash
white --help
white --version
white doctor
white config
white checks
white scan https://example.com --authorized
white scan https://example.com --authorized --format json --output report.json
white scan https://example.com --authorized --format pdf --output report.pdf
white report report.json
white report report.json --format pdf --output report.pdf
```

Full options and exit codes: [docs/CLI_GUIDE.md](docs/CLI_GUIDE.md).

## Reports

| Format | Contents |
| --- | --- |
| JSON | Complete machine-readable report (schema 1.0): every check, finding, evidence, summary, limitations. |
| PDF | WHITE branding, scan metadata, executive summary, overall assessment, severity and category charts, prioritised action plan, every finding in plain English with technical evidence and remediation, coverage table, comparison with the previous scan (GUI), limitations, page numbers. |
| HTML | Standalone, script-free version of the report. |

GUI downloads: on any report page (PDF / JSON / HTML buttons).

## Dashboard and severity

The dashboard shows overview cards, a severity doughnut, findings by category, progress over time
(needs two or more completed scans of the same address), scan coverage and prioritised actions. All
values come from your stored scans. See [docs/GUI_GUIDE.md](docs/GUI_GUIDE.md).

- **Critical/High**: address first (exposed secrets, unencrypted data, exposed repositories).
- **Medium**: meaningful weaknesses (missing CSP, clickjacking, debug pages).
- **Low/Informational**: hardening and awareness items.
- **Possible issue**: an indicator to confirm manually. **Passed**: that issue was not detected.

## Tests

```bash
pytest
ruff check src tests
```

161 automated tests (scanner, SSRF protections, reports, CLI, GUI, authentication, session handling,
cross-user isolation). Details and limits of coverage: [docs/TESTING.md](docs/TESTING.md).

## Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Security and limitations

See [docs/SECURITY.md](docs/SECURITY.md). Key limitations: URL-only, unauthenticated, point-in-time
assessment; in-process job queue and rate limits suited to a single local server; the GUI is not
production-hosted by default. Before hosting any scanning service, check the provider's terms and
acceptable-use policy.

## Uploading to GitHub safely

```bash
git status                       # .env, .venv and *.db must NOT appear
git add .
git status                       # review the staged files once more
git commit -m "Initial WHITE implementation"
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

Before pushing: confirm `.env` is not staged (`git check-ignore .env` prints `.env`), never commit the
Supabase service-role key or database password, and prefer a private repository until you have
reviewed everything.

## License

MIT - see [LICENSE](LICENSE). Chart.js (MIT) is vendored in `src/white/web/static/vendor/`.
