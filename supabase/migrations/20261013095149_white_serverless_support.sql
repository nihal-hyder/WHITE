-- WHITE serverless support: request-scoped scan progress/cancellation and signed domain
-- verification records. Only adds new columns and a new table; existing data is untouched.

alter table public.scans add column if not exists progress jsonb;
alter table public.scans add column if not exists cancel_requested boolean not null default false;

create table if not exists public.verified_domains (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
    hostname text not null check (char_length(hostname) between 1 and 253),
    token text not null check (char_length(token) between 16 and 128),
    created_at timestamptz not null default now(),
    verified_at timestamptz,
    method text check (method is null or method in ('dns', 'file')),
    -- HMAC computed by the WHITE server with its secret key. A row edited by hand through the
    -- public API cannot carry a valid signature, so WHITE will not treat it as verified.
    signature text check (signature is null or char_length(signature) = 64),
    unique (user_id, hostname)
);

comment on table public.verified_domains is 'WHITE domain ownership verification; trusted only with a valid server signature.';

create index if not exists verified_domains_user_idx on public.verified_domains (user_id);

alter table public.verified_domains enable row level security;

create policy "verified_domains_select_own" on public.verified_domains
    for select to authenticated using ((select auth.uid()) = user_id);
create policy "verified_domains_insert_own" on public.verified_domains
    for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "verified_domains_update_own" on public.verified_domains
    for update to authenticated using ((select auth.uid()) = user_id)
    with check ((select auth.uid()) = user_id);
create policy "verified_domains_delete_own" on public.verified_domains
    for delete to authenticated using ((select auth.uid()) = user_id);

revoke all on public.verified_domains from anon;
grant select, insert, update, delete on public.verified_domains to authenticated;
