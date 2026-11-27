-- supabase-web-care: audit role
--
-- Creates `webcare_auditor`, the role the live checks connect as. It can read
-- the system catalog (policies, grants, function definitions) and nothing
-- else: it gets no privilege on any table, no BYPASSRLS, and cannot log in
-- until an administrator gives it a password in step 2.
--
-- What this role can still reach: whatever is granted to PUBLIC. A table or a
-- function left open to PUBLIC is open to this role too, exactly as it is to
-- `anon`. The live checks report such objects; they never call them.
--
-- On Supabase with pg_net enabled, PUBLIC may read net.http_request_queue,
-- where pg_net keeps the headers of queued requests, API keys included. The
-- platform owns schema net, so this cannot be revoked. The checks never read
-- it, and `preflight` warns when the role can; keep the login short-lived (step
-- 2) or turn pg_net off if nothing uses it. See supabase.com/kb, "Custom role
-- inherits privileges that were not explicitly granted".
--
-- Step 1. Run this file once per database as an administrator
--         (psql, or the Supabase SQL editor). Safe to run again.

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'webcare_auditor') then
    create role webcare_auditor
      nologin
      nosuperuser
      nocreatedb
      nocreaterole
      noinherit
      noreplication
      nobypassrls
      connection limit 2;
  end if;
end $$;

-- Defaults for every session of the role. They limit accidents, not intent:
-- a session may change them, so the role's safety rests on having no grants.
alter role webcare_auditor set default_transaction_read_only = on;
alter role webcare_auditor set statement_timeout = '15s';
alter role webcare_auditor set lock_timeout = '2s';
alter role webcare_auditor set idle_in_transaction_session_timeout = '30s';

-- Step 2. Enable login for a limited time. Do this by hand and keep the
--         password out of files, chat, and tickets.
--
--   In psql (preferred: the password is hashed before it leaves your machine,
--   so it does not appear in server logs):
--
--       alter role webcare_auditor login valid until '<YYYY-MM-DD>';
--       \password webcare_auditor
--
--   Where psql is not available, the statement below works, but the password
--   travels in the statement text and may be written to the server log:
--
--       alter role webcare_auditor login password '<long random value>'
--         valid until '<YYYY-MM-DD>';
--
-- Step 3. When the audit is finished, switch login off again:
--
--       alter role webcare_auditor nologin;
--
--   To remove the role entirely, run auditor-role-drop.sql.
