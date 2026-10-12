# Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `white` is not recognised | Activate the virtual environment (`.\.venv\Scripts\Activate.ps1` on Windows, `source .venv/bin/activate` elsewhere) or run `.venv\Scripts\white`. |
| PowerShell refuses to run `Activate.ps1` | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or call `.venv\Scripts\white.exe` directly. |
| `py -3.13` not found / Python too old | WHITE needs Python 3.11+. Install from python.org and recreate the venv. |
| "Target refused: ... loopback/private addresses are not permitted" | By design. For your own development server use `--allow-private-network` (CLI) or `WHITE_ALLOW_PRIVATE_TARGETS=true` (GUI, local only). |
| "Port N is not permitted" | Only ports 80, 443, 8080 and 8443 are allowed. |
| Scan status "failed" | The website could not be reached (DNS failure, timeout, connection refused). The report lists the exact error. No conclusions are drawn. |
| Many checks show "Error" | The main page could not be fetched. Check the address and that the site is online. |
| HTTPS certificate finding on a valid site | WHITE verifies certificates against the `certifi` CA bundle. Corporate TLS inspection proxies are not used (proxies are ignored), but a network that intercepts TLS can cause this. |
| "Your form expired" | The CSRF token did not match (cookie cleared or another tab). Reload the page. |
| HTTP 400 "Invalid host header" | Open WHITE via `127.0.0.1`, `localhost`, or the host in `WHITE_SITE_URL`. |
| Signed out after restarting the server | `WHITE_SECRET_KEY` is not set, so a temporary key was used. Set it in `.env`. |
| "The database rejected the request" when starting a scan | The Supabase migration has not been applied. See `docs/SUPABASE_SETUP.md`. |
| "Ownership of X has not been verified" | Accounts mode requires domain verification. Use the Domains page, or set `WHITE_REQUIRE_DOMAIN_VERIFICATION=false` only for trusted single-user setups. |
| Confirmation/reset email never arrives | Supabase's default mailer is rate-limited (a few emails per hour). Check spam, wait, or configure custom SMTP. |
| Email link opens `localhost:3000` | Set Site URL and Redirect URLs in Supabase Authentication -> URL Configuration. |
| "This link is invalid or has expired" | Links are single-use and expire. Request a new one. |
| DNS verification fails right after adding the record | DNS changes can take minutes to hours to propagate. Retry later, or use the file method. |
| Charts are empty | Charts only show data from completed scans. A single scan cannot show trends. |
| Port 8000 already in use | `white serve --port 8001` (and update `WHITE_SITE_URL` and Supabase redirect URLs). |
