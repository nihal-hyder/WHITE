# Supabase setup

Supabase is optional. Without it the CLI works fully and the GUI runs in local single-user mode.

Project used during development: `vvbtbgnmlijlxhucynoc` (`https://vvbtbgnmlijlxhucynoc.supabase.co`).

## 1. Environment variables

In `.env` (copied from `.env.example`):

```dotenv
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_PUBLISHABLE_KEY=sb_publishable_...     # Project Settings -> API Keys -> Publishable key
WHITE_SECRET_KEY=<long random string>            # python -c "import secrets; print(secrets.token_urlsafe(48))"
WHITE_SITE_URL=http://127.0.0.1:8000
```

The publishable (or legacy `anon`) key is designed to be public. **Never** put the `service_role` /
secret key in WHITE's configuration; WHITE does not use it.

Run `white doctor --online` to confirm the Auth service is reachable.

## 2. Database schema (migration)

The migration `supabase/migrations/20261012205314_white_initial_schema.sql` creates:

- `public.scans` - one row per scan, owned by `user_id` (FK to `auth.users`, `on delete cascade`),
  with state, timestamps, counts and the full JSON report.
- `public.findings` - a queryable index of findings (FK to `scans`, `on delete cascade`).
- Indexes on `(user_id, created_at)`, `(user_id, target_url, created_at)`, `findings(scan_id)`.
- Row Level Security on both tables with policies allowing users to select/insert/update/delete only
  rows where `auth.uid() = user_id`; finding inserts must also reference the user's own scan.
- `anon` has no privileges on these tables.

Status for project `vvbtbgnmlijlxhucynoc`: **applied** (remote migration version `20261012205314`).
RLS was verified there: a second user could not read, update or insert into the first user's rows
and `anon` could not read the tables.

For a new project, apply it (it only creates new objects) with **one** of:

- Supabase Dashboard -> SQL Editor -> paste the file -> Run, or
- Supabase CLI: `supabase link --project-ref <ref>` then `supabase db push`.

Until the migration is applied, sign-in works but starting a scan in accounts mode fails with
"The database rejected the request".

## 3. Authentication settings (Dashboard -> Authentication)

1. **Sign In / Providers -> Email**: enabled (default). Keep "Confirm email" on for production.
2. **URL Configuration**:
   - Site URL: `http://127.0.0.1:8000` (or your real HTTPS address).
   - Redirect URLs: add `http://127.0.0.1:8000/auth/callback` and `http://localhost:8000/auth/callback`
     (plus the HTTPS equivalents if hosted). Without this, email links send users to the default
     Site URL (`http://localhost:3000`).
3. **Emails / SMTP**: Supabase's built-in email service is heavily rate-limited and intended for
   testing. For real users configure custom SMTP (Authentication -> Emails -> SMTP Settings).
4. Optional, recommended **email templates** (server-side token-hash flow, works even when the link is
   opened in another browser):
   - Confirm signup: `<a href="{{ .SiteURL }}/auth/confirm?token_hash={{ .TokenHash }}&type=signup">Confirm your email</a>`
   - Reset password: `<a href="{{ .SiteURL }}/auth/confirm?token_hash={{ .TokenHash }}&type=recovery">Reset your password</a>`

   With the default templates WHITE uses `/auth/callback`, which reads the tokens from the link's URL
   fragment in the browser and hands them to the server, which validates them with Supabase.

## 4. How WHITE talks to Supabase

- Auth: `POST /auth/v1/signup`, `/token?grant_type=password|refresh_token`, `/recover`, `/verify`,
  `/logout`, `GET/PUT /auth/v1/user`.
- Data: PostgREST `/rest/v1/scans` and `/rest/v1/findings` with `Authorization: Bearer <user JWT>`.
  RLS therefore enforces ownership even if application code were wrong.
- Tokens are stored encrypted server-side; browsers only get an opaque session cookie.

## 5. Verifying RLS after applying the migration

In the SQL editor (as the dashboard's privileged role), check that RLS is enabled:

```sql
select relname, relrowsecurity from pg_class where relname in ('scans', 'findings');
select policyname, cmd from pg_policies where tablename in ('scans', 'findings');
```

Then sign up two test accounts in WHITE, scan with one, and confirm the other cannot see the scan
(the automated tests cover this against a simulated backend; see `docs/TESTING.md`).
