-- Functions set up the way the function checks expect. Synthetic schema for a
-- throwaway local Postgres; no real names or data.
create schema if not exists private;

-- Public on purpose: PUBLIC revoked, anon granted by name.
create function public.site_banner() returns text
language sql security definer set search_path = ''
as $$ select 'hello'::text $$;
revoke all on function public.site_banner() from public;
grant execute on function public.site_banner() to anon, authenticated;

-- Staff only.
create function public.staff_report() returns int
language sql security definer set search_path = ''
as $$ select 1 $$;
revoke all on function public.staff_report() from public, anon;
grant execute on function public.staff_report() to authenticated;

-- A guard that identifies the caller. The comment below mentions
-- current_user, and so do a block comment and a string; none of them is code.
create function private.guard() returns void
language plpgsql security definer set search_path = ''
as $$
begin
  -- current_user would name the owner here, so it is not used
  /* nor is current_role,
     which a block comment may mention too */
  if session_user = 'postgres' then
    return;
  end if;
  raise exception 'ACCESS_DENIED: current_user is not consulted';
end $$;
revoke all on function private.guard() from public;
