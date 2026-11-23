-- Functions that repeat the mistakes the function checks look for. Synthetic
-- schema for a throwaway local Postgres; no real names or data.
create schema if not exists private;

-- Default grants left alone: executable by PUBLIC, and so by anon.
create function public.list_everything() returns int
language sql security definer set search_path = ''
as $$ select 1 $$;

-- Revoked from anon only. Every role is a member of PUBLIC, so it stays open.
create function public.report_everything() returns int
language sql security definer set search_path = ''
as $$ select 1 $$;
revoke execute on function public.report_everything() from anon;

-- PUBLIC revoked, but a grant made directly to anon survives. On Supabase the
-- schema's default privileges create that grant; here it is written out.
create function public.worker_only() returns int
language sql security definer set search_path = ''
as $$ select 1 $$;
revoke all on function public.worker_only() from public;
grant execute on function public.worker_only() to anon, service_role;

-- Closed properly, for contrast.
create function public.staff_report() returns int
language sql security definer set search_path = ''
as $$ select 1 $$;
revoke all on function public.staff_report() from public, anon;
grant execute on function public.staff_report() to authenticated;

-- A guard that asks who the function owner is, instead of who is calling.
create function private.guard() returns void
language plpgsql security definer set search_path = ''
as $$
begin
  perform 'a comment marker -- inside a string must not hide the next line';
  if current_user = 'postgres' then
    return;
  end if;
  raise exception 'ACCESS_DENIED';
end $$;

-- New functions in public are published to the API roles automatically.
alter default privileges in schema public grant execute on functions to anon, authenticated;

-- The platform's own superuser also carries default privileges. A project
-- cannot change them, so they are reported as information, not as a finding.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'supabase_admin') then
    create role supabase_admin superuser nologin;
  end if;
end $$;
alter default privileges for role supabase_admin in schema public grant execute on functions to anon;

-- New tables are granted to the API roles by default: the table-level twin of the line above.
alter default privileges in schema public grant select, insert on tables to anon, authenticated;

-- Extension schemas opened to the API roles (stand-ins for pg_net, Vault and pg_cron).
create schema if not exists net;
create function net.http_post(url text) returns bigint language sql as $$ select 1::bigint $$;
grant usage on schema net to anon, authenticated;
grant execute on function net.http_post(text) to anon;
create schema if not exists vault;
create view vault.decrypted_secrets as select 'k'::text as name, 's'::text as decrypted_secret;
grant usage on schema vault to authenticated;
grant select on vault.decrypted_secrets to authenticated;
create schema if not exists cron;
create function cron.schedule(name text, spec text, command text) returns bigint language sql as $$ select 1::bigint $$;
grant usage on schema cron to authenticated;

-- Realtime: a table published with RLS off, and an open policy on realtime.messages.
create table public.live_feed (id int);
grant select on public.live_feed to anon;
create publication supabase_realtime for table public.live_feed;
create schema if not exists realtime;
create table realtime.messages (id int);
alter table realtime.messages enable row level security;
create policy anyone_listens on realtime.messages for select to anon using (true);
-- Views: one that runs as its owner, one that runs as the caller.
create table public.secret_notes (id int);
alter table public.secret_notes enable row level security;
create view public.owner_view as select id from public.secret_notes;
create view public.invoker_view with (security_invoker = true) as select id from public.secret_notes;
grant select on public.owner_view, public.invoker_view to anon;
-- A schema the API roles may use that the target does not list.
create schema api_extra;
grant usage on schema api_extra to anon;

-- Realtime: reading scoped, sending left open (WITH CHECK true); and a policy open to every signed-in user.
create policy anyone_sends on realtime.messages for all to anon using (id = 1) with check (true);
create policy members_all on realtime.messages for all to authenticated using (true) with check (true);
-- A materialized view the API roles may read: it has no RLS and no security_invoker.
create materialized view public.cached_totals as select count(*) as n from public.secret_notes;
grant select on public.cached_totals to anon;

-- SECURITY DEFINER functions that take a user id. The first trusts it; the second asks who
-- is calling; the third leaves that to a helper; the fourth is closed to the API roles.
create table public.notes (id int primary key, user_id uuid, body text);
alter table public.notes enable row level security;
create function public.notes_of(p_user_id uuid) returns setof public.notes
language sql security definer set search_path = ''
as $$ select * from public.notes where user_id = p_user_id /* should compare with auth.uid() */ $$;
create function public.my_notes(p_user_id uuid) returns setof public.notes
language sql security definer set search_path = ''
as $$ select * from public.notes where user_id = p_user_id and p_user_id = auth.uid() $$;
create function private.is_self(target uuid) returns boolean
language sql stable set search_path = ''
as $$ select target = auth.uid() $$;
create function public.notes_checked(user_id uuid) returns setof public.notes
language plpgsql security definer set search_path = ''
as $$ begin
  if not private.is_self(user_id) then raise exception 'not yours'; end if;
  return query select * from public.notes n where n.user_id = notes_checked.user_id;
end $$;
-- comment only: auth.uid() is not asked in notes_of
revoke all on function public.notes_of(uuid), public.my_notes(uuid), public.notes_checked(uuid) from public, anon;
grant execute on function public.notes_of(uuid), public.my_notes(uuid), public.notes_checked(uuid) to authenticated;
-- The guard is two calls away: require_self() -> current_user_id() -> auth.uid().
create function private.current_user_id() returns uuid language sql stable set search_path = ''
as $$ select auth.uid() $$;
create function private.require_self(target uuid) returns void language plpgsql set search_path = ''
as $$ begin if target is distinct from private.current_user_id() then raise exception 'not yours'; end if; end $$;
create function public.notes_guarded(p_user_id uuid) returns setof public.notes
language plpgsql security definer set search_path = ''
as $$ begin perform private.require_self(p_user_id); return query select * from public.notes where user_id = p_user_id; end $$;
revoke all on function public.notes_guarded(uuid) from public, anon;
grant execute on function public.notes_guarded(uuid) to authenticated;
create function public.notes_admin(p_user_id uuid) returns setof public.notes
language sql security definer set search_path = ''
as $$ select * from public.notes where user_id = p_user_id $$;
revoke all on function public.notes_admin(uuid) from public, anon, authenticated;

-- Policies whose whole condition is "signed in", next to one that asks whose row it is.
create policy members_read on public.notes for select to authenticated using (auth.uid() is not null);
create policy members_add on public.notes for insert to authenticated
  with check ((select auth.role()) = 'authenticated');
create policy own_rows on public.notes for update to authenticated
  using (auth.uid() is not null and user_id = auth.uid());
grant select, insert on public.notes to authenticated;
-- The same kind of policy on a table the API roles hold no privilege on: nothing is open.
create table public.notes_rpc_only (id int primary key, user_id uuid);
alter table public.notes_rpc_only enable row level security;
revoke all on public.notes_rpc_only from anon, authenticated;
create policy signed_in_add on public.notes_rpc_only for insert to authenticated with check (auth.uid() is not null);

-- A helper whose only mention of auth.uid() is in a comment asks nobody; a function that
-- relies on it is still open. Its id is a number, not a uuid.
create function private.write_log(note text) returns void language plpgsql set search_path = ''
as $$ begin
  -- TODO: record auth.uid() here
  null;
end $$;
create function public.notes_by_member(member_id bigint) returns int
language plpgsql security definer set search_path = ''
as $$ begin perform private.write_log('read'); return member_id::int; end $$;
revoke all on function public.notes_by_member(bigint) from public, anon;
grant execute on function public.notes_by_member(bigint) to authenticated;

-- Policies with no condition: one the signed-in users can use, one on a table they cannot touch.
create policy all_open on public.notes for delete to authenticated using (true);
grant delete on public.notes to authenticated;
create policy all_open on public.notes_rpc_only for all to authenticated using (true) with check (true);
