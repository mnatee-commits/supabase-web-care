-- Deliberately unsafe schema. Each object carries one known problem so the
-- tests can assert that the matching check reports it. Synthetic data only.

-- SEC008: policy lets every signed-in user read every row.
create table public.orders (
  id bigint generated always as identity primary key,
  tenant_id uuid not null,
  user_id uuid not null,
  total numeric(12, 2) not null default 0
);
alter table public.orders enable row level security;
create policy orders_read_all on public.orders
  for select to authenticated using (true);
grant select, insert, update, delete on public.orders to authenticated;

-- SEC001: exposed table with RLS off and a grant to anon.
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid,
  body text
);
grant select, insert on public.notes to anon, authenticated;

-- SEC033: authorization decided by a claim the user can edit.
create table public.profiles (
  id uuid primary key,
  display_name text,
  is_admin boolean not null default false
);
alter table public.profiles enable row level security;
create policy profiles_admin_read on public.profiles
  for select to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
grant select on public.profiles to authenticated;

-- SEC006 + update_without_select: UPDATE policy has no WITH CHECK, and the
-- table has no SELECT policy, so updates silently match zero rows.
create table public.docs (
  id bigint generated always as identity primary key,
  owner_id uuid not null,
  title text
);
alter table public.docs enable row level security;
create policy docs_update_own on public.docs
  for update to authenticated
  using ((select auth.uid()) = owner_id);
grant select, update on public.docs to authenticated;

-- auth_role_deprecated: policy gates on auth.role() instead of a TO clause.
create table public.tickets (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  subject text
);
alter table public.tickets enable row level security;
create policy tickets_signed_in on public.tickets
  for select
  using (auth.role() = 'authenticated');
grant select on public.tickets to anon, authenticated;

-- VIEW001: view over an RLS table without security_invoker.
create view public.orders_view as
  select id, tenant_id, user_id, total from public.orders;
grant select on public.orders_view to anon, authenticated;

-- SEC042: SECURITY DEFINER function in an exposed schema, callable by anon
-- through the default EXECUTE grant to PUBLIC.
create function public.admin_list_profiles()
returns setof public.profiles
language sql
security definer
as $$ select * from public.profiles $$;

-- storage_upsert_incomplete: INSERT-only storage policy, so upsert fails.
create policy "avatars insert" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'avatars');

-- SEC050: storage policy scoped by owner but not by bucket, so it applies to
-- every bucket.
create policy "own files any bucket" on storage.objects
  for select to authenticated
  using (owner = (select auth.uid()));

-- Synthetic rows (no real people, no real identifiers).
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', false);
insert into public.orders (tenant_id, user_id, total) values
  ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-000000000001', 10.00),
  ('00000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-000000000002', 20.00);
insert into public.notes (user_id, body) values
  ('00000000-0000-4000-8000-000000000001', 'synthetic note');

-- An extension created in public, as `create extension` without a schema does.
create extension if not exists pg_trgm with schema public;

-- pg_net's queue as Supabase ships it: schema net and its tables open to PUBLIC, so every
-- role that can log in, the audit role included, may read queued request headers.
create schema net;
grant usage on schema net to public;
create table net.http_request_queue (id bigint primary key, url text, headers jsonb);
create table net._http_response (id bigint primary key, status_code int);
grant all on table net.http_request_queue, net._http_response to public;

-- A batch its creator may edit: the policy pins actor_id, but the table-wide UPDATE lets
-- the creator rewrite the counters the server is meant to keep.
create table public.batches (
  id bigint generated always as identity primary key,
  actor_id uuid not null,
  published_count integer not null default 0,
  notes text
);
alter table public.batches enable row level security;
create policy batches_update_own on public.batches
  for update to authenticated
  using ((select auth.uid()) = actor_id)
  with check ((select auth.uid()) = actor_id);
grant select, update on public.batches to authenticated;
create policy batches_select_own on public.batches
  for select to authenticated
  using ((select auth.uid()) = actor_id);
