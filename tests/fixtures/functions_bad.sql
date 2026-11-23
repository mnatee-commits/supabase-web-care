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
