-- supabase-web-care: remove the audit role.
--
-- Run as an administrator in each database where auditor-role.sql was run.
-- `drop owned` removes grants and settings held by the role in the current
-- database; the role owns no objects, so no data is affected.

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'webcare_auditor') then
    execute 'drop owned by webcare_auditor';
    execute 'drop role webcare_auditor';
  end if;
end $$;
