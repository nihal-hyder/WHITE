# WHITE implementation plan and status

Last updated: 2026-10-13.

## Starting point (inspection)

- The repository contained only `CLAUDE.md` (saved as `Claude.md`), an empty `prompt.md`, `.mcp.json`
  (Supabase MCP for project `vvbtbgnmlijlxhucynoc`) and `.claude/settings.local.json`. It was not a Git
  repository. No existing scanner, CLI, GUI, API, tests or dependencies.
- Tools available: Python 3.13.7 (also 3.10.0, which is too old), Node 24, Git 2.55, Microsoft Edge.
- Supabase MCP: connected. The `public` schema had no tables and no migrations. The Auth service is
  healthy; email sign-up is enabled and email confirmation is required (`mailer_autoconfirm: false`).

## Key decisions

| Decision | Reason |
| --- | --- |
| Python-first GUI (FastAPI + Jinja2 + vanilla JS + Chart.js) instead of the Next.js frontend described in `CLAUDE.md` | The build request explicitly asked for "Jinja2, HTML, CSS, and vanilla JavaScript for the GUI" and a simple Python-first architecture. One process, one language, no Node toolchain, and no scanning logic in TypeScript. **This deviates from `CLAUDE.md` section 3; the owner should confirm or update `CLAUDE.md`.** |
| Supabase accessed with the user's own JWT + publishable key (PostgREST), never a service-role key | Row Level Security enforces ownership in the database; no privileged secret exists anywhere in the app. |
| Server-side sessions in SQLite with encrypted tokens; browser only gets an opaque HttpOnly cookie | Supabase tokens never reach browser JavaScript. |
| Domain verification state stored server-side (SQLite), not in Supabase | Users can write to their own Supabase rows directly via the public API, so verification stored there could be forged. |
| stdlib `sqlite3` + SQL migration files instead of SQLAlchemy/Alembic | The schema is small; Supabase migrations are plain SQL in `supabase/migrations/`. `CLAUDE.md` says "SQLAlchemy 2.x where appropriate". |
| Status set: PASS, FINDING, POTENTIAL, INCONCLUSIVE, NOT_APPLICABLE, NOT_TESTED, ERROR | Union of the statuses in `CLAUDE.md` and the build request. |
| Reports: JSON, HTML and PDF (ReportLab) | `CLAUDE.md` asks for HTML, the build request for PDF. |
| Active XSS/SQL indicators are opt-in and report only POTENTIAL | Conservative, bounded and non-destructive, per `CLAUDE.md` section 7. |

## Phases and status

| Phase | Status |
| --- | --- |
| 1. Inspect repository and environment | Done |
| 2. Save plan | Done (this file) |
| 3. Shared scanner engine and safety controls | Done: 21 checks, SSRF-safe transport, budgets, redaction |
| 4. CLI and reporting | Done: `white scan/report/checks/config/doctor/version/serve`; JSON/HTML/PDF |
| 5. Backend, GUI, charts, local persistence | Done: FastAPI, Jinja2 pages, Chart.js dashboard, SQLite |
| 6. Supabase auth, ownership, migrations | Done; tested against a fake Supabase. Migration **applied with the owner's approval** on 2026-10-12 (version `20261012205314`); RLS verified on the live database with a rolled-back two-user test; security advisor: no issues. Real email flows need dashboard configuration (see `SUPABASE_SETUP.md`). |
| 7. Integration | Done: CLI and GUI share `white.scanner` and `white.reporting` |
| 8. Tests, debugging, security review | Done: 158 automated tests passing; ruff clean |
| 9. Documentation | Done |
| 10. Audit | Done: no secrets in tracked files; `.env` ignored |

## Remaining items requiring the owner

1. (Done) Migration applied and RLS verified.
2. Configure Supabase Auth URL settings (Site URL / redirect URLs) and, for production use, custom SMTP.
3. Decide whether to update `CLAUDE.md` to reflect the Python-first GUI.
4. Hosting: the app is designed for local use. Do not host the scanner without checking provider terms.
