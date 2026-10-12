-- WHITE initial schema: user-owned scans and findings with Row Level Security.
-- Prepared for project vvbtbgnmlijlxhucynoc. Review before applying; it only creates new objects.

create table if not exists public.scans (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
    target_url text not null check (char_length(target_url) between 8 and 2048),
    hostname text not null check (char_length(hostname) between 1 and 253),
    state text not null check (state in ('queued', 'running', 'completed', 'completed_with_errors',
                                         'failed', 'cancelled', 'interrupted')),
    active_checks boolean not null default false,
    created_at timestamptz not null default now(),
    started_at timestamptz,
    finished_at timestamptz,
    duration_seconds numeric(10, 2) check (duration_seconds is null or duration_seconds >= 0),
    findings_total integer not null default 0 check (findings_total >= 0),
    high_priority integer not null default 0 check (high_priority >= 0),
    severity_counts jsonb,
    error text check (error is null or char_length(error) <= 1000),
    schema_version text,
    report jsonb
);

comment on table public.scans is 'WHITE scan records. Each row belongs to exactly one auth user.';

create index if not exists scans_user_created_idx on public.scans (user_id, created_at desc);
create index if not exists scans_user_target_idx on public.scans (user_id, target_url, created_at desc);

create table if not exists public.findings (
    id uuid primary key default gen_random_uuid(),
    scan_id uuid not null references public.scans (id) on delete cascade,
    user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
    fingerprint text not null,
    check_id text not null,
    check_version text not null,
    title text not null,
    category text not null,
    status text not null check (status in ('FINDING', 'POTENTIAL')),
    severity text not null check (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    confidence text not null check (confidence in ('HIGH', 'MEDIUM', 'LOW')),
    affected_url text,
    created_at timestamptz not null default now(),
    unique (scan_id, fingerprint)
);

comment on table public.findings is 'Queryable index of findings; the full evidence lives in scans.report.';

create index if not exists findings_scan_idx on public.findings (scan_id);
create index if not exists findings_user_fingerprint_idx on public.findings (user_id, fingerprint);

-- Row Level Security: users can only see and change their own rows.
alter table public.scans enable row level security;
alter table public.findings enable row level security;

create policy "scans_select_own" on public.scans
    for select to authenticated using ((select auth.uid()) = user_id);
create policy "scans_insert_own" on public.scans
    for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "scans_update_own" on public.scans
    for update to authenticated using ((select auth.uid()) = user_id)
    with check ((select auth.uid()) = user_id);
create policy "scans_delete_own" on public.scans
    for delete to authenticated using ((select auth.uid()) = user_id);

create policy "findings_select_own" on public.findings
    for select to authenticated using ((select auth.uid()) = user_id);
create policy "findings_insert_own" on public.findings
    for insert to authenticated with check (
        (select auth.uid()) = user_id
        and exists (select 1 from public.scans s where s.id = scan_id and s.user_id = (select auth.uid()))
    );
create policy "findings_delete_own" on public.findings
    for delete to authenticated using ((select auth.uid()) = user_id);

-- Anonymous visitors get no access at all; signed-in users get only what RLS allows.
revoke all on public.scans from anon;
revoke all on public.findings from anon;
grant select, insert, update, delete on public.scans to authenticated;
grant select, insert, delete on public.findings to authenticated;
