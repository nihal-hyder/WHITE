# Architecture

```
            +-------------------+          +---------------------------+
 terminal ->|  CLI (Typer)      |          |  Browser                  |
            |  white.cli        |          |  Jinja2 pages + Chart.js  |
            +---------+---------+          +-------------+-------------+
                      |                                  | HTTP (cookie session + CSRF)
                      |                    +-------------v-------------+
                      |                    | FastAPI app  white.api     |
                      |                    |  routes_web / routes_api   |
                      |                    |  routes_auth / jobs        |
                      |                    +------+-------------+-------+
                      |                           |             |
            +---------v---------------------------v--+   +------v-----------------+
            | Scanner engine  white.scanner          |   | Persistence            |
            |  registry -> 21 checks                 |   |  SQLite (local mode,   |
            |  SafeHttpClient -> SafeTransport       |   |   sessions, domains)   |
            |  models (versioned finding schema)     |   |  Supabase PostgREST    |
            +---------+------------------------------+   |   (accounts mode, RLS) |
                      |                                  +------------------------+
            +---------v---------------+
            | Reporting white.reporting|  JSON / HTML / PDF, analytics (charts, history)
            +-------------------------+
```

## Packages

| Package | Responsibility |
| --- | --- |
| `white.scanner.models` | Versioned schema (`SCHEMA_VERSION = "1.0"`): `Finding`, `CheckResult`, `ScanReport`, enums. Shared by everything. |
| `white.scanner.netsafety` | URL validation, IP classification, DNS validation, `SafeNetworkBackend`/`SafeTransport`. |
| `white.scanner.http` | `SafeHttpClient`: manual redirects with revalidation, size/time/request budgets, rate limiting, cancellation, caching. |
| `white.scanner.checks.*` | Independent checks. Each has a stable `id`, `version`, category and OWASP Top 10:2025 mapping. |
| `white.scanner.registry` | Ordered list of checks. |
| `white.scanner.engine` | `Scanner.run()` - runs checks, isolates failures, computes final state and summary. |
| `white.reporting` | `analytics` (summary text, chart data, history comparison, action ranking), `json_report`, `html_report`, `pdf_report`. |
| `white.cli` | Typer CLI. No dependency on the web app or Supabase. |
| `white.api` | FastAPI app factory, middleware (CSP, CSRF, Trusted Host), routes, `JobManager`. |
| `white.auth` | Supabase Auth REST client, server-side session store, domain verification. |
| `white.database` | Repository protocol; SQLite and Supabase implementations. |
| `white.web` | Templates, CSS, JS, vendored Chart.js 4.4.7 (MIT). |

## Scan lifecycle (GUI)

1. `POST /scans` (form) or `POST /api/scans` (JSON) with CSRF token and the authorization checkbox.
2. `start_scan` validates the URL, checks domain verification (if required), applies abuse limits
   (`JobManager.reserve`: one active scan per user, duplicate window 30 s, hourly quota, global queue),
   creates a `queued` record and submits the job to a thread pool.
3. The job runs `Scanner.run()`; progress callbacks update the in-memory job (stage, completed/total).
4. The browser polls `GET /api/scans/{id}/status`. Values are exactly the job's real counters.
5. On completion the report is saved (SQLite or Supabase), then the job state becomes final, so a
   "finished" status always means the report is retrievable.
6. If the server restarts mid-scan, local records are marked `interrupted`; Supabase records that are
   still `queued`/`running` but unknown to the process are displayed as `interrupted`.

The job manager is in-process and suitable for local use only. A durable worker could call the same
`Scanner.run()` without changes.

## Finding schema

Every `Finding` contains: stable `id` (fingerprint of check + issue key + host, used for history),
`check_id`, `check_version`, `title`, `category`, `status` (FINDING/POTENTIAL), `severity`,
`confidence`, `summary` (plain English), `business_impact`, `recommendation`, `technical_details`,
`technical_remediation`, `evidence[]`, `affected_url` (redacted), `references[]`, `owasp`, `timestamp`.
Every `CheckResult` has `status`, `message` and `errors`. See `src/white/scanner/models.py`.

## Severity and confidence rules

Severity = potential impact if the issue is real; confidence = how sure WHITE is of the observation.

| Severity | Rule used |
| --- | --- |
| CRITICAL | Direct exposure of secrets (e.g. a `.env` file containing key/password/token variable names). |
| HIGH | Exposure of data in transit or of sensitive internals: no HTTPS, untrusted certificate, password/form data over HTTP, exposed `.git`, SQL error indicator. |
| MEDIUM | Weakness that meaningfully helps common attacks: missing CSP, clickjacking, HTTP not redirected, debug pages, directory listing, active mixed content, session cookies without Secure/HttpOnly, reflected input. |
| LOW | Missing hardening with limited direct impact: HSTS, nosniff, SameSite, version banners, passive mixed content. |
| INFO | Awareness items: Referrer-Policy/Permissions-Policy not set, robots/sitemap entries, cross-domain redirect. |

| Confidence | Rule used |
| --- | --- |
| HIGH | Directly observed in a response (header absent/present, content signature verified). |
| MEDIUM | Strong indicator with plausible benign explanations (cookie purpose guessed from its name, reflected marker, DB error after a quote). |
| LOW | Heuristic keyword match needing human review (credential words in comments, sensitive-looking sitemap paths). |

## History comparison

Scans are comparable when scheme, host, port and path match and the scan state is `completed` or
`completed_with_errors`. Compared by finding fingerprint: **new**, **still present**, **no longer
detected** (only if the same check ran to PASS/FINDING/POTENTIAL in a completed scan) and **not
re-verified** (check errored, skipped, inconclusive or not applicable).
