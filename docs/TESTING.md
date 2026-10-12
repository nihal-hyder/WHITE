# Testing

```bash
pip install -e ".[dev]"
pytest                    # all tests
pytest tests/unit         # scanner checks, HTTP client, engine, analytics, reports, CLI
pytest tests/security     # SSRF protections, sessions, CSRF, ownership, escaping
pytest tests/integration  # web GUI/API in local mode and in Supabase mode (simulated)
ruff check src tests      # lint
ruff format --check src tests
```

Last verified run (Windows 11, Python 3.13.7): **158 passed**, ruff clean.

## What is covered

| Area | Tests |
| --- | --- |
| URL validation, schemes, credentials, ports, IDN | `tests/security/test_netsafety.py` |
| Private/loopback/link-local/metadata/IPv6/mapped addresses | same |
| DNS validation, mixed answers fail closed, rebinding (connects to validated IP only) | same |
| Redirect revalidation (private IP, `file://`, credentials, bad port) | same |
| Timeouts, connection/TLS errors, size limits, redirect limit, request budget, cancellation | `tests/unit/test_http_client.py` |
| Every check against controlled responses, including soft-404 false-positive protection | `tests/unit/test_checks.py` |
| Engine states (completed, failed, errors, cancelled, budget), progress counts | `tests/unit/test_engine_and_analytics.py` |
| Severity counts, fingerprints, history comparison (new/still present/fixed/unverified), trend and chart data | same |
| JSON round-trip and validation, HTML escaping, PDF validity and multi-page layout with long URLs, redaction | `tests/unit/test_reports.py` |
| CLI commands, exit codes, overwrite protection, secret masking | `tests/unit/test_cli.py` |
| GUI pages, security headers, Host header, CSRF, scan flow, downloads, chart data consistency, domain verification | `tests/integration/test_web_local.py` |
| Sign-up (with/without confirmation), duplicates, login errors, rate limiting, open redirect, session cookie, logout invalidation, token refresh, revoked sessions, bearer API, password reset, callback flow, change password, sign out everywhere | `tests/integration/test_web_supabase.py` |
| Cross-user isolation (pages, API, downloads, delete, cancel) | same |
| Local repository ownership, encrypted sessions, filename sanitisation, JSON-in-script escaping | `tests/security/test_app_security.py` |

## Test infrastructure

- No test contacts external websites: `tests/conftest.py` provides `MockSite` (an `httpx.MockTransport`).
- `FakeSupabase` emulates Supabase Auth and PostgREST. It enforces ownership from the bearer token
  and deliberately ignores the client's `user_id` filter, so isolation tests prove the database-side
  rule and the application filters together.

## Not covered automatically

- Real Supabase RLS policies are not executed by the automated suite (no local PostgreSQL). They were
  verified once on the live project with a two-user test inside a rolled-back transaction: user B saw
  0 of user A's rows, could not update them, could not insert rows or findings for user A, and `anon`
  could not select. Re-check with `docs/SUPABASE_SETUP.md` section 5 after schema changes.
- Real email delivery (confirmation and reset emails).
- Browser JavaScript is exercised manually (headless Edge screenshots were reviewed), not by an
  automated browser test.
