# Deploying WHITE on Vercel (free Hobby plan)

WHITE detects Vercel automatically (`VERCEL=1`) and switches to **serverless mode**:

| Normal server | Serverless mode on Vercel |
| --- | --- |
| Sessions in local SQLite | Encrypted, signed session cookie; re-validated with Supabase on each request (sign-out revokes) |
| Domain verifications in local SQLite | Supabase table `verified_domains`; trusted only with a valid server HMAC signature |
| Scans in background threads | Scan runs inside a request (`POST /api/scans/{id}/run`, max 120 s); progress and cancellation stored in Supabase |
| Optional accounts | **Accounts required.** Without Supabase and a strong `WHITE_SECRET_KEY` the site serves only a configuration notice |
| Optional domain verification | **Always required** |
| Client IP from the socket | Client IP from Vercel's `x-real-ip` / `x-forwarded-for` (for rate limits) |

## Before you start: the rules

- **Vercel Hobby is for personal, non-commercial use only.** Selling WHITE as a service needs a paid plan.
  ([Vercel fair use](https://vercel.com/docs/limits/fair-use-guidelines))
- Vercel's acceptable-use policy forbids undermining other systems or placing undue load on them.
  WHITE's ownership verification, request caps and non-intrusive checks exist to stay within that.
  Keep them enabled. ([Vercel AUP](https://vercel.com/legal/acceptable-use-policy))
- **Do not use a hosted WHITE to scan sites hosted on Vercel Hobby** (including WHITE itself): Vercel
  does not permit security testing of Hobby deployments.
  ([Vercel penetration testing](https://vercel.com/kb/guide/penetration-testing-on-vercel))
- Hosted WHITE can only scan **public** websites whose ownership a user has verified. To test without
  a public site, use the local demo in `demo-site/`.

## Step 1 - Database (once)

Apply both migrations in `supabase/migrations/` to your Supabase project (SQL Editor, or
`supabase db push`). The second one (`20261013095149_white_serverless_support.sql`) adds the
`progress`/`cancel_requested` columns and the `verified_domains` table that serverless mode needs.

## Step 2 - Put the code on GitHub

```powershell
git status          # .env must NOT be listed
git add .
git commit -m "WHITE with serverless support"
git remote add origin https://github.com/<you>/white.git   # a private repository is fine
git push -u origin main
```

## Step 3 - Create the Vercel project

1. Sign in at vercel.com with GitHub (free Hobby plan).
2. **Add New -> Project**, import your repository. Leave **Root Directory** as `./`.
   Vercel finds the FastAPI app in `app.py` (configured in `vercel.json`).
3. Open **Environment Variables** and add:

| Name | Value |
| --- | --- |
| `SUPABASE_URL` | `https://<project-ref>.supabase.co` |
| `SUPABASE_PUBLISHABLE_KEY` | your publishable key (`sb_publishable_...`) - never the secret/service key |
| `WHITE_SECRET_KEY` | output of `python -c "import secrets; print(secrets.token_urlsafe(48))"` |

   `WHITE_SITE_URL` is optional: WHITE uses `https://<your-project>.vercel.app` automatically.
4. Click **Deploy**.

## Step 4 - Check the deployment

- `https://<your-project>.vercel.app/api/health` should return `{"status":"ok", ..., "mode":"supabase"}`.
  `{"status":"misconfigured"}` means a variable from step 3 is missing or too short.
- The homepage should load with the intro animation.

## Step 5 - Supabase Auth settings

Supabase dashboard -> **Authentication -> URL Configuration**:

- Site URL: `https://<your-project>.vercel.app`
- Redirect URLs: `https://<your-project>.vercel.app/auth/callback`

Supabase's built-in email sender is limited to a few messages per hour; for real users configure
custom SMTP (Authentication -> Emails -> SMTP).

## Step 6 - Use it

Sign up, confirm your email, add a domain you own on **Domains**, verify it with the DNS TXT record
or the `/.well-known/white-verify.txt` file, then scan it.

## Limits to know

- Each scan must finish within the function's time limit (WHITE caps scans at 120 s; Hobby allows 300 s).
- Login and email rate limits are kept in memory per server instance, so on Vercel they are
  best-effort; Supabase Auth applies its own limits too. The hourly scan quota is counted in the database.
- If a visitor closes the progress page before the scan starts, it stays queued and is shown as
  interrupted after 10 minutes.
- Supabase free projects can be paused after a period of inactivity; resume them from the dashboard.

## What has and has not been verified

Verified locally: the serverless code paths (cookie sessions, revocation, signed domain records,
request-scoped scans, progress, cancellation, quotas, forwarded client IP, configuration guard),
covered by `tests/integration/test_serverless.py` against a simulated Supabase.

Not verified: an actual deployment on Vercel's infrastructure. If the build fails, check the Vercel
build log for dependency installation errors and confirm the environment variables.
