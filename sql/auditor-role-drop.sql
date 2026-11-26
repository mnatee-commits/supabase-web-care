-- supabase-web-care: remove the audit role.
--
-- Run as an administrator in each database where auditor-role.sql was run.
-- `drop owned` removes grants and settings held by the role in the current
-- database; the role owns no objects, so no data is affected.
--
-- An administrator that is not a superuser (`postgres` on Supabase) may only
-- drop what a role holds after becoming a member of that role, so the script
-- grants itself membership first. Where that is not allowed, the next
-- statement says so and nothing has been removed: run the script as the role
-- that created `webcare_auditor`, or switch its login off instead with
-- `alter role webcare_auditor nologin`.

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'webcare_auditor') then
    -- 'USAGE' asks whether the role's privileges are in effect now. From Postgres 16 the
    -- role that created another is a member of it without inheriting its privileges.
    if not pg_has_role(current_user, 'webcare_auditor', 'USAGE') then
      begin
        if current_setting('server_version_num')::int >= 160000 then
          execute format('grant webcare_auditor to %I with inherit true', current_user);
        else
          execute format('grant webcare_auditor to %I', current_user);
        end if;
      exception when insufficient_privilege then
        null;
      end;
    end if;
    execute 'drop owned by webcare_auditor';
    execute 'drop role webcare_auditor';
  end if;
end $$;
