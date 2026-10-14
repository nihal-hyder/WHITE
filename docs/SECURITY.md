# Security design and authorized use

## Authorized use only

WHITE must only be used on websites you own or have explicit, preferably written, permission to
assess. The CLI requires `--authorized` (or an interactive confirmation). The GUI requires a
confirmation checkbox for every scan and, in accounts mode, proof of domain ownership.

## What WHITE does and does not send

- Only `GET` and `HEAD` requests (enforced in `SafeHttpClient.fetch`).
- At most 40 requests and 120 seconds per scan, at least 0.2 s between requests, 10 s per-request
  timeout, 2 MB maximum response body (all configurable within hard bounds).
- No form submission, no POST, no credential guessing, no brute force, no exploitation, no
  denial-of-service testing, no stealth or evasion. Downloaded content is parsed, never executed.
- Opt-in active checks send a unique harmless marker (`wht<random>"'<wht<random>x>`) or a single
  quote in at most three existing URL parameters and only report POTENTIAL indicators.

## Network-boundary (SSRF) protections

Implemented in `src/white/scanner/netsafety.py`:

1. Strict URL validation: `http`/`https` only; no embedded credentials; no backslashes, whitespace or
   control characters; IDNA hostnames; maximum length; ports limited to 80, 443, 8080, 8443.
2. Hostnames such as `localhost`, `*.local`, `*.internal`, `metadata.google.internal` and single-label
   names are refused.
3. IP literals and **every** DNS answer (IPv4 and IPv6) are checked. Loopback, private, link-local,
   multicast, reserved, unspecified, CGNAT/non-global, IPv4-mapped/6to4/Teredo-wrapped internal
   addresses and cloud metadata addresses are refused. If any DNS answer is blocked, the whole
   destination is refused (fail closed).
4. **Connection-level enforcement:** `SafeNetworkBackend` performs resolution and validation inside
   the connection step and connects to the validated IP itself. The address that was checked is the
   address that is used, preventing DNS-rebinding/TOCTOU attacks. TLS SNI and certificate checks still
   use the original hostname.
5. Redirects are never followed automatically. Each `Location` is resolved and re-validated (scheme,
   credentials, port) and its connection goes through the same backend. Maximum 5 redirects.
6. Environment proxies are ignored (`trust_env=False`).
7. Cloud metadata addresses stay blocked even with `--allow-private-network` /
   `WHITE_ALLOW_PRIVATE_TARGETS=true` (development options for scanning your own local servers).

## Web application protections

| Area | Implementation |
| --- | --- |
| Authentication | Supabase Auth (email/password) via its official REST API; WHITE never stores or hashes passwords. |
| Sessions | Random 256-bit opaque cookie (`white_session`, HttpOnly, SameSite=Lax, Secure on HTTPS). Only its SHA-256 is stored. Supabase tokens are encrypted (Fernet, key derived from `WHITE_SECRET_KEY`) in SQLite and refreshed server-side. 7-day absolute and 2-day idle lifetime; recovery sessions last 15 minutes and cannot access the app. |
| Authorization | Every protected route resolves the user server-side. Every repository query is filtered by owner, and in Supabase mode RLS policies enforce `auth.uid() = user_id`. Unknown and foreign IDs both return 404. |
| CSRF | HMAC token bound to a per-browser cookie, required on all state-changing requests (form field or `X-CSRF-Token`), plus Origin/Referer check. Bearer-token API calls are exempt (not sent automatically by browsers). |
| XSS | Jinja2 autoescaping everywhere; strict CSP (`script-src 'self'`, no inline scripts or styles); JSON embedded for charts is escaped so it cannot close the script element. |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY`. |
| DNS rebinding of the local server | `TrustedHostMiddleware` only accepts `127.0.0.1`, `localhost`, `[::1]` and the host of `WHITE_SITE_URL`. |
| Open redirects | `next` parameters must be same-site paths. |
| Brute force / abuse | Login: 10 attempts per IP+email per 15 min. Sign-up/reset emails: 5 per IP per 15 min. Scans: one active per user, 30 s duplicate window, 20 per user per hour, global queue limit. |
| Account enumeration | Password reset and confirmation-resend always show the same message. |
| Downloads | Generated in memory; filenames are sanitised; `Content-Disposition: attachment`. The CLI refuses to overwrite files without `--force`. |
| Error handling | Users see generic messages; no stack traces. `/api/health` reveals only status, version and mode. |
| Secrets | Only the Supabase publishable key is used. Service-role keys, database passwords and JWT secrets are never needed. `.env` is gitignored. |

## Data minimisation and redaction

- Response bodies are held in memory only during a scan and never stored.
- Evidence values are passed through `redact_text` (JWTs, bearer tokens, AWS keys, API keys,
  private keys, `password=`/`token=` patterns) and truncated to 300 characters.
- Cookie values are never recorded (`name=[value hidden]`).
- For an exposed `.env` file only variable **names** are recorded.
- URLs in findings have credentials removed and sensitive query values redacted.

## Serverless (Vercel) mode

- Accounts and a strong `WHITE_SECRET_KEY` are mandatory; otherwise only a configuration notice is served.
- Sessions are Fernet-encrypted cookies (no server storage). Every request re-validates the access
  token with Supabase Auth (cached 30 s), so signing out revokes access.
- Domain verification rows live in Supabase but are only trusted with an HMAC signature made with
  `WHITE_SECRET_KEY`; rows users edit through the public API are ignored.
- Domain verification is always required; private-network targets cannot be enabled.

## Known limitations

- The in-process job manager and in-memory rate limits are per process; they reset on restart and do
  not coordinate between multiple server instances.
- Domain verification state lives in the server's SQLite file; running several servers would need a
  shared store.
- Supabase-mode scan records can be modified by their own owner through the public API (RLS permits
  owners to update their rows). This cannot affect other users.
- The scanner checks only what is visible from outside without authentication.

## Reporting a vulnerability in WHITE

Please open a private security advisory on the GitHub repository rather than a public issue.

## Operator admin console

The `/admin` console is for the operator, separate from user accounts:

- Its own credentials (`WHITE_ADMIN_USER`/`WHITE_ADMIN_PASSWORD`, default `nihal`/`nihal`), verified
  against a PBKDF2-HMAC-SHA256 hash with a constant-time compare. Prefer `WHITE_ADMIN_PASSWORD_HASH`.
- Its own encrypted, time-limited session cookie (`white_admin`, HttpOnly, path `/admin`), login
  rate-limiting, and CSRF protection on its forms.
- Listing all registered users requires the Supabase **service-role** key
  (`WHITE_SUPABASE_SERVICE_KEY`). It is read from the environment, used only by the admin module
  server-side, and never rendered to the browser or logged. Without it, the console shows only
  locally stored scans.
- On a serverless/hosted deployment the console is disabled unless an explicit
  `WHITE_ADMIN_PASSWORD_HASH` is set, so the weak default credentials are never exposed publicly.
