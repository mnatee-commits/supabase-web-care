-- supabase-web-care: catalog checks that pgrls does not cover.
--
-- Each block is one read-only SELECT over the system catalog. It returns two
-- text columns, `location` and `detail`, one row per problem found. No block
-- reads a row from an application table.
--
-- The loader refuses to run anything here that is not a single SELECT.
-- `%(schemas)s` is bound to the list of schemas being checked.

-- check: update_without_select
-- severity: medium
-- title: UPDATE policy on a table with no SELECT policy for the same role
-- why: Postgres must read a row before it can update it. Without a SELECT
--      policy the update matches zero rows and reports success.
select
  quote_ident(p.schemaname) || '.' || quote_ident(p.tablename) || '.' || quote_ident(p.policyname)
    as location,
  'UPDATE policy for ' || array_to_string(p.roles, ', ')
    || ' has no matching SELECT policy; updates will affect 0 rows' as detail
from pg_catalog.pg_policies p
where p.schemaname = any(%(schemas)s)
  and p.cmd = 'UPDATE'
  and p.permissive = 'PERMISSIVE'
  and not exists (
    select 1
    from pg_catalog.pg_policies s
    where s.schemaname = p.schemaname
      and s.tablename = p.tablename
      and s.permissive = 'PERMISSIVE'
      and s.cmd in ('SELECT', 'ALL')
      and (s.roles && p.roles or 'public' = any(s.roles))
  )
order by 1;

-- check: auth_role_deprecated
-- severity: low
-- title: Policy calls the deprecated auth.role()
-- why: Supabase deprecated auth.role() in favour of the TO clause. With
--      anonymous sign-ins enabled, auth.role() = 'authenticated' is also true
--      for anonymous users.
select
  quote_ident(p.schemaname) || '.' || quote_ident(p.tablename) || '.' || quote_ident(p.policyname)
    as location,
  'policy calls auth.role(); name the role in the TO clause instead' as detail
from pg_catalog.pg_policies p
where p.schemaname = any(%(schemas)s)
  and (
    coalesce(p.qual, '') ~ 'auth\.role\(\)'
    or coalesce(p.with_check, '') ~ 'auth\.role\(\)'
  )
order by 1;

-- check: storage_upsert_incomplete
-- severity: low
-- title: Storage policies allow upload but not replace
-- why: A Storage upsert needs INSERT, SELECT and UPDATE on storage.objects.
--      With INSERT alone, new uploads work and replacing a file fails.
--      A policy granted TO public counts for every role. Policies are pooled
--      across buckets, so a role that may upsert in one bucket and only insert
--      in another is not caught; read the bucket conditions for that.
with pol as (
  select p.cmd, p.roles
  from pg_catalog.pg_policies p
  where p.schemaname = 'storage'
    and p.tablename = 'objects'
    and p.permissive = 'PERMISSIVE'
),
named as (
  select distinct r.role_name
  from pol
  cross join lateral unnest(pol.roles) as r(role_name)
),
per_role as (
  select
    n.role_name,
    bool_or(pol.cmd in ('INSERT', 'ALL')) as can_insert,
    bool_or(pol.cmd in ('SELECT', 'ALL')) as can_select,
    bool_or(pol.cmd in ('UPDATE', 'ALL')) as can_update
  from named n
  join pol on n.role_name = any(pol.roles) or 'public' = any(pol.roles)
  group by n.role_name
)
select
  'storage.objects (role ' || role_name || ')' as location,
  'INSERT is allowed but '
    || concat_ws(
         ' and ',
         case when not can_select then 'SELECT' end,
         case when not can_update then 'UPDATE' end
       )
    || ' is not; replacing a file (upsert) will fail' as detail
from per_role
where can_insert and not (can_select and can_update)
order by 1;

-- check: secdef_trusts_current_user
-- severity: medium
-- title: SECURITY DEFINER function reads current_user to identify its caller
-- why: Inside a SECURITY DEFINER function current_user and current_role name
--      the function owner, whoever calls it. A guard built on them lets every
--      caller through. session_user, auth.uid() and the request claims
--      describe the caller. Guards usually live outside the exposed schema, so
--      this block looks at every schema that is not managed by the platform.
select
  quote_ident(n.nspname) || '.' || quote_ident(p.proname)
    || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')' as location,
  'the body reads current_user or current_role, which name the function owner here; '
    || 'if that decides who may proceed, use session_user, auth.uid() or the request claims'
    as detail
from pg_catalog.pg_proc p
join pg_catalog.pg_namespace n on n.oid = p.pronamespace
where p.prosecdef
  and n.nspname !~ '^pg_'
  and n.nspname not in (
    'information_schema', 'auth', 'storage', 'extensions', 'graphql', 'graphql_public',
    'realtime', 'vault', 'pgsodium', 'pgsodium_masks', 'supabase_functions',
    'supabase_migrations', 'net', 'cron', 'pgbouncer', 'pgtle'
  )
  and not exists (
    select 1
    from pg_catalog.pg_depend d
    where d.classid = 'pg_catalog.pg_proc'::regclass
      and d.objid = p.oid
      and d.deptype = 'e'
  )
  -- strings and both kinds of comment go in one left-to-right pass, so a comment marker
  -- inside a string, or a quote inside a comment, does not hide what follows
  and regexp_replace(
        p.prosrc,
        '''(?:[^'']|'''')*''|--[^\n]*|/\*(?:[^*]|\*+[^*/])*\*+/', '', 'g'
      ) ~* '\mcurrent_(user|role)\M'
order by 1;

-- check: default_function_privileges
-- severity: low
-- title: New functions are executable by API roles by default
-- why: Default privileges on the schema grant EXECUTE on every new function
--      to the listed roles. A migration that adds a function and forgets the
--      REVOKE publishes it. A per-schema default can only add privileges; it
--      cannot take away the EXECUTE that Postgres gives PUBLIC. Defaults of
--      the platform's own superuser are reported separately, below.
with scoped as (
  select d.defaclrole, d.defaclnamespace, a.grantee
  from pg_catalog.pg_default_acl d
  cross join lateral pg_catalog.aclexplode(d.defaclacl) a
  join pg_catalog.pg_namespace n on n.oid = d.defaclnamespace
  where d.defaclobjtype = 'f'
    and a.privilege_type = 'EXECUTE'
    and a.grantee <> d.defaclrole
    and n.nspname = any(%(schemas)s)
)
select
  quote_ident(n.nspname) || ' (functions created by ' || r.rolname || ')' as location,
  'every new function is executable by '
    || string_agg(coalesce(g.rolname, 'PUBLIC'), ', ' order by coalesce(g.rolname, 'PUBLIC'))
    || case
         when not exists (
           select 1
           from pg_catalog.pg_default_acl x
           where x.defaclrole = s.defaclrole
             and x.defaclnamespace = 0
             and x.defaclobjtype = 'f'
             and not exists (
               select 1
               from pg_catalog.aclexplode(x.defaclacl) b
               where b.grantee = 0 and b.privilege_type = 'EXECUTE'
             )
         )
         then ', and by PUBLIC through the built-in default'
         else ''
       end
    || ' from the moment it is created; each migration has to revoke what it does not intend'
    as detail
from scoped s
join pg_catalog.pg_namespace n on n.oid = s.defaclnamespace
join pg_catalog.pg_roles r on r.oid = s.defaclrole
left join pg_catalog.pg_roles g on g.oid = s.grantee
where r.rolname <> 'supabase_admin'
group by n.nspname, r.rolname, s.defaclrole
order by 1;

-- check: default_function_privileges_platform
-- severity: info
-- title: Default privileges of the platform's own role (not yours to change)
-- why: supabase_admin is the platform's superuser. A project cannot alter its
--      default privileges, and application migrations do not create functions
--      as this role. Listed so the report is complete; nothing to fix unless a
--      function in a checked schema is owned by supabase_admin.
with scoped as (
  select d.defaclrole, d.defaclnamespace, a.grantee
  from pg_catalog.pg_default_acl d
  cross join lateral pg_catalog.aclexplode(d.defaclacl) a
  join pg_catalog.pg_namespace n on n.oid = d.defaclnamespace
  where d.defaclobjtype = 'f'
    and a.privilege_type = 'EXECUTE'
    and a.grantee <> d.defaclrole
    and n.nspname = any(%(schemas)s)
)
select
  quote_ident(n.nspname) || ' (functions created by ' || r.rolname || ')' as location,
  'every new function is executable by '
    || string_agg(coalesce(g.rolname, 'PUBLIC'), ', ' order by coalesce(g.rolname, 'PUBLIC'))
    || case
         when not exists (
           select 1
           from pg_catalog.pg_default_acl x
           where x.defaclrole = s.defaclrole
             and x.defaclnamespace = 0
             and x.defaclobjtype = 'f'
             and not exists (
               select 1
               from pg_catalog.aclexplode(x.defaclacl) b
               where b.grantee = 0 and b.privilege_type = 'EXECUTE'
             )
         )
         then ', and by PUBLIC through the built-in default'
         else ''
       end
    || ' from the moment it is created; this applies only to functions the platform itself creates'
    as detail
from scoped s
join pg_catalog.pg_namespace n on n.oid = s.defaclnamespace
join pg_catalog.pg_roles r on r.oid = s.defaclrole
left join pg_catalog.pg_roles g on g.oid = s.grantee
where r.rolname = 'supabase_admin'
group by n.nspname, r.rolname, s.defaclrole
order by 1;

-- check: default_table_privileges
-- severity: low
-- title: New tables and sequences are granted to API roles by default
-- why: Default privileges on the schema grant access to every new table (and
--      sequence) to the listed roles from the moment it is created. A migration
--      that adds a table and forgets both the REVOKE and the ALTER TABLE ...
--      ENABLE ROW LEVEL SECURITY serves it through the Data API at once.
--      Supabase has announced that new tables will stop being exposed by
--      default; this check reports what the project's own catalog still grants.
--      service_role is left out: it is the server-side role and bypasses RLS by
--      design. The platform's superuser is left out too; a project cannot change it.
with scoped as (
  select d.defaclrole, d.defaclnamespace, d.defaclobjtype, a.grantee
  from pg_catalog.pg_default_acl d
  cross join lateral pg_catalog.aclexplode(d.defaclacl) a
  join pg_catalog.pg_namespace n on n.oid = d.defaclnamespace
  where d.defaclobjtype in ('r', 'S')
    and a.grantee <> d.defaclrole
    and n.nspname = any(%(schemas)s)
)
select
  quote_ident(n.nspname) || ' (' || case s.defaclobjtype when 'r' then 'tables' else 'sequences' end
    || ' created by ' || r.rolname || ')' as location,
  'every new ' || case s.defaclobjtype when 'r' then 'table' else 'sequence' end || ' is granted to '
    || string_agg(distinct coalesce(g.rolname, 'PUBLIC'), ', ' order by coalesce(g.rolname, 'PUBLIC'))
    || ' from the moment it is created; with row-level security off it is served through the Data API at once, so each migration has to revoke what it does not intend'
    as detail
from scoped s
join pg_catalog.pg_namespace n on n.oid = s.defaclnamespace
join pg_catalog.pg_roles r on r.oid = s.defaclrole
left join pg_catalog.pg_roles g on g.oid = s.grantee
where r.rolname <> 'supabase_admin'
  and (s.grantee = 0 or g.rolname in ('anon', 'authenticated'))
group by n.nspname, r.rolname, s.defaclrole, s.defaclobjtype
order by 1;

-- check: extension_net_callable
-- severity: medium
-- title: API roles may call pg_net, which sends HTTP requests from the database server
-- why: The functions in schema net make the database server fetch any URL. A role
--      that may call them, directly or through a function that runs as the caller,
--      can make the server reach addresses only it can see (SSRF). Some Supabase
--      projects grant them to anon and authenticated from the start (a project made
--      in November 2026 did), so read this as a gate left open, not proof of misuse.
select
  'schema net (role ' || r.rolname || ')' as location,
  r.rolname || ' may call ' || count(*) || ' pg_net functions ('
    || string_agg(p.proname, ', ' order by p.proname)
    || '); schema net is not served by the Data API, so the way in is a function in an '
    || 'exposed schema that runs as the caller and passes a URL on. '
    || case when pg_catalog.pg_get_userbyid(n.nspowner) = current_user
                 or pg_catalog.pg_has_role(current_user, n.nspowner, 'MEMBER')
            then 'Before revoking, find triggers and functions that call net as the signed-in user, '
                 || 'since they would stop working'
            else 'Schema net belongs to ' || pg_catalog.pg_get_userbyid(n.nspowner)
                 || ', so a REVOKE by your role has no effect (Postgres only warns). If nothing uses '
                 || 'pg_net, turn it off (drop extension pg_net, without cascade); otherwise ask '
                 || 'the platform to revoke it, and keep schema net out of the Data API'
       end
    as detail
from pg_catalog.pg_namespace n
join pg_catalog.pg_proc p on p.pronamespace = n.oid
cross join pg_catalog.pg_roles r
where n.nspname = 'net'
  and r.rolname in ('anon', 'authenticated')
  and pg_catalog.has_schema_privilege(r.oid, n.oid, 'USAGE')
  and pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE')
group by r.rolname, n.nspowner
order by 1;

-- check: extension_vault_reachable
-- severity: high
-- title: API roles may read Vault or call its functions
-- why: Supabase Vault keeps secrets (API keys, webhook secrets) in schema vault,
--      and vault.decrypted_secrets shows them in clear text. Only trusted server
--      roles should reach it. pgsodium, which Vault was built on, is checked too.
select
  'schema ' || n.nspname || ' (role ' || r.rolname || ')' as location,
  r.rolname || ' may read ' || reach.relations || ' relations and call '
    || reach.functions || ' functions in ' || n.nspname
    || coalesce(' (' || reach.names || ')', '') as detail
from pg_catalog.pg_namespace n
cross join pg_catalog.pg_roles r
cross join lateral (
  select
    (select count(*) from pg_catalog.pg_class c
      where c.relnamespace = n.oid and c.relkind in ('r', 'v', 'm', 'p')
        and pg_catalog.has_table_privilege(r.oid, c.oid, 'SELECT')) as relations,
    (select count(*) from pg_catalog.pg_proc p
      where p.pronamespace = n.oid and pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE')) as functions,
    (select string_agg(c.relname, ', ' order by c.relname) from pg_catalog.pg_class c
      where c.relnamespace = n.oid and c.relkind in ('r', 'v', 'm', 'p')
        and pg_catalog.has_table_privilege(r.oid, c.oid, 'SELECT')) as names
) reach
where n.nspname in ('vault', 'pgsodium')
  and r.rolname in ('anon', 'authenticated')
  and pg_catalog.has_schema_privilege(r.oid, n.oid, 'USAGE')
  and reach.relations + reach.functions > 0
order by 1;

-- check: extension_cron_reachable
-- severity: medium
-- title: API roles may schedule jobs or read the job list (pg_cron)
-- why: Whoever may call cron.schedule can make the database run a command again
--      and again; the job list in cron.job holds each job's command, which can
--      include keys. Supabase keeps both from anon and authenticated.
select
  'schema cron (role ' || r.rolname || ')' as location,
  r.rolname || ' may call ' || reach.functions || ' pg_cron functions'
    || coalesce(' (' || reach.function_names || ')', '')
    || ' and read ' || reach.relations || ' of its tables' as detail
from pg_catalog.pg_namespace n
cross join pg_catalog.pg_roles r
cross join lateral (
  select
    (select count(*) from pg_catalog.pg_proc p
      where p.pronamespace = n.oid and pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE')) as functions,
    (select string_agg(p.proname, ', ' order by p.proname) from pg_catalog.pg_proc p
      where p.pronamespace = n.oid and pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE')) as function_names,
    (select count(*) from pg_catalog.pg_class c
      where c.relnamespace = n.oid and c.relkind in ('r', 'v', 'p')
        and pg_catalog.has_table_privilege(r.oid, c.oid, 'SELECT')) as relations
) reach
where n.nspname = 'cron'
  and r.rolname in ('anon', 'authenticated')
  and pg_catalog.has_schema_privilege(r.oid, n.oid, 'USAGE')
  and reach.functions + reach.relations > 0
order by 1;

-- check: realtime_table_without_rls
-- severity: high
-- title: Table sent out by Realtime with RLS off
-- why: Realtime sends every change to a table in the supabase_realtime publication to
--      subscribers whose role may read the table, filtered by RLS. With RLS off, anyone
--      who may read it gets every insert, update and delete as it happens.
select
  quote_ident(pt.schemaname) || '.' || quote_ident(pt.tablename) as location,
  'in publication supabase_realtime, RLS is off, and '
    || concat_ws(' and ',
         case when pg_catalog.has_table_privilege('anon', c.oid, 'SELECT') then 'anon' end,
         case when pg_catalog.has_table_privilege('authenticated', c.oid, 'SELECT') then 'authenticated' end)
    || ' may read it, so every change reaches them live' as detail
from pg_catalog.pg_publication_tables pt
join pg_catalog.pg_namespace n on n.nspname = pt.schemaname
join pg_catalog.pg_class c on c.relnamespace = n.oid and c.relname = pt.tablename
where pt.pubname = 'supabase_realtime'
  and not c.relrowsecurity
  and pg_catalog.to_regrole('anon') is not null
  and pg_catalog.to_regrole('authenticated') is not null
  and (pg_catalog.has_table_privilege('anon', c.oid, 'SELECT')
       or pg_catalog.has_table_privilege('authenticated', c.oid, 'SELECT'))
order by 1;

-- check: realtime_messages_open
-- severity: medium
-- title: Realtime Broadcast or Presence open to everyone by an unconditional policy
-- why: Private channels are guarded by RLS policies on realtime.messages. A policy for
--      anon or public whose condition is just true lets anyone join, listen and send.
select
  'realtime.messages.' || quote_ident(p.policyname) as location,
  p.cmd || ' for ' || array_to_string(p.roles, ', ')
    || ' with no condition: anyone with the public key may use every private channel' as detail
from pg_catalog.pg_policies p
where p.schemaname = 'realtime'
  and p.tablename = 'messages'
  and p.permissive = 'PERMISSIVE'
  and p.roles && array['anon', 'public']::name[]
  -- USING and WITH CHECK each on its own: a policy can scope reading and leave sending open
  and (btrim(coalesce(p.qual, '')) in ('true', '(true)')
       or btrim(coalesce(p.with_check, '')) in ('true', '(true)'))
order by 1;

-- check: realtime_messages_open_to_signed_in
-- severity: low
-- title: Realtime Broadcast or Presence open to every signed-in user by an unconditional policy
-- why: A policy for authenticated whose USING or WITH CHECK is just true lets any signed-in
--      user listen to or send on every private channel, across tenants or organisations.
--      Fine for a single team; a leak where users must not see each other's channels.
select
  'realtime.messages.' || quote_ident(p.policyname) as location,
  p.cmd || ' for ' || array_to_string(p.roles, ', ')
    || ' with no condition: every signed-in user may use every private channel; scope it by '
    || 'realtime.topic() if users must not hear each other' as detail
from pg_catalog.pg_policies p
where p.schemaname = 'realtime'
  and p.tablename = 'messages'
  and p.permissive = 'PERMISSIVE'
  and p.roles && array['authenticated']::name[]
  and not (p.roles && array['anon', 'public']::name[])
  and (btrim(coalesce(p.qual, '')) in ('true', '(true)')
       or btrim(coalesce(p.with_check, '')) in ('true', '(true)'))
order by 1;

-- check: view_runs_as_owner
-- severity: medium
-- title: View that API roles may read runs with its owner's rights
-- why: A view reads its tables as the view's owner unless it sets security_invoker,
--      so the tables' RLS does not filter what anon or authenticated see through it.
--      Supabase's advisor calls this security_definer_view.
select
  quote_ident(n.nspname) || '.' || quote_ident(c.relname) as location,
  concat_ws(' and ',
    case when pg_catalog.has_table_privilege('anon', c.oid, 'SELECT') then 'anon' end,
    case when pg_catalog.has_table_privilege('authenticated', c.oid, 'SELECT') then 'authenticated' end)
    || ' may read this view, which runs as its owner, so RLS on its tables does not apply; '
    || 'set security_invoker = true or revoke SELECT' as detail
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where n.nspname = any(%(schemas)s)
  and c.relkind = 'v'
  and pg_catalog.to_regrole('anon') is not null
  and pg_catalog.to_regrole('authenticated') is not null
  and not exists (
    select 1 from unnest(coalesce(c.reloptions, '{}'::text[])) o
    where o ~* '^security_invoker=(true|on|yes|1)$')
  and (pg_catalog.has_table_privilege('anon', c.oid, 'SELECT')
       or pg_catalog.has_table_privilege('authenticated', c.oid, 'SELECT'))
order by 1;

-- check: schema_usable_but_unchecked
-- severity: low
-- title: Schema the API roles may use that these checks do not cover
-- why: The Data API can only serve a schema the API roles have USAGE on. A schema with
--      USAGE for anon or authenticated that is left out of the target's schemas may be
--      served without any of these checks looking at it.
select
  quote_ident(n.nspname) as location,
  concat_ws(' and ',
    case when pg_catalog.has_schema_privilege('anon', n.oid, 'USAGE') then 'anon' end,
    case when pg_catalog.has_schema_privilege('authenticated', n.oid, 'USAGE') then 'authenticated' end)
    || ' may use this schema, which is not in the target''s schemas. That is expected when '
    || 'policies call functions kept there; if the Data API also serves it, add it to the '
    || 'target''s schemas (--with-data-api shows which schemas are served)' as detail
from pg_catalog.pg_namespace n
where not (n.nspname = any(%(schemas)s))
  and n.nspname !~ '^pg_'
  and n.nspname not in (
    'information_schema', 'auth', 'storage', 'extensions', 'graphql', 'graphql_public',
    'realtime', 'vault', 'pgsodium', 'pgsodium_masks', 'supabase_functions',
    'supabase_migrations', 'net', 'cron', 'pgbouncer', 'pgtle', 'pgmq', 'pgmq_public'
  )
  and pg_catalog.to_regrole('anon') is not null
  and pg_catalog.to_regrole('authenticated') is not null
  and (pg_catalog.has_schema_privilege('anon', n.oid, 'USAGE')
       or pg_catalog.has_schema_privilege('authenticated', n.oid, 'USAGE'))
order by 1;

-- check: matview_readable_by_api_roles
-- severity: medium
-- title: Materialized view that API roles may read
-- why: A materialized view stores rows computed by its owner. It cannot have RLS and cannot
--      use security_invoker, so anyone who may read it sees every stored row. Revoke SELECT
--      from the API roles, or move it out of the schemas the Data API serves.
select
  quote_ident(n.nspname) || '.' || quote_ident(c.relname) as location,
  concat_ws(' and ',
    case when pg_catalog.has_table_privilege('anon', c.oid, 'SELECT') then 'anon' end,
    case when pg_catalog.has_table_privilege('authenticated', c.oid, 'SELECT') then 'authenticated' end)
    || ' may read every row this materialized view stores; it cannot have RLS, so revoke '
    || 'SELECT or keep it out of the schemas the Data API serves' as detail
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where n.nspname = any(%(schemas)s)
  and c.relkind = 'm'
  and pg_catalog.to_regrole('anon') is not null
  and pg_catalog.to_regrole('authenticated') is not null
  and (pg_catalog.has_table_privilege('anon', c.oid, 'SELECT')
       or pg_catalog.has_table_privilege('authenticated', c.oid, 'SELECT'))
order by 1;

-- check: secdef_takes_user_id
-- severity: medium
-- title: SECURITY DEFINER function takes a user id from its caller
-- why: Such a function skips RLS. If it acts on the user id it is handed instead of
--      asking who is calling (auth.uid()), any caller can pass someone else's id and
--      read or change that person's data. Reported when an API role may call the
--      function, it has an argument named like a user id, and neither its body nor a
--      function it calls (up to two calls deep) mentions auth.uid(), auth.jwt() or the
--      request's JWT claims.
--      A sign, not proof: read the function. Functions are matched by name, so two with
--      the same name in different schemas are not told apart. Only names and a yes/no about the body
--      leave the database, never the body itself.
select
  quote_ident(n.nspname) || '.' || quote_ident(p.proname)
    || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' as location,
  concat_ws(' and ',
    case when pg_catalog.has_function_privilege('anon', p.oid, 'EXECUTE')
              and pg_catalog.has_schema_privilege('anon', n.oid, 'USAGE') then 'anon' end,
    case when pg_catalog.has_function_privilege('authenticated', p.oid, 'EXECUTE')
              and pg_catalog.has_schema_privilege('authenticated', n.oid, 'USAGE') then 'authenticated' end)
    || ' may call this SECURITY DEFINER function and choose its ' || ids.names
    || '; nothing in it asks who is calling, so a caller could pass another user''s id. '
    || 'Use auth.uid() inside the function, or check that the id is the caller''s' as detail
from pg_catalog.pg_proc p
join pg_catalog.pg_namespace n on n.oid = p.pronamespace
join pg_catalog.pg_language l on l.oid = p.prolang
cross join lateral (
  select string_agg(a.name, ', ' order by a.i) as names
  from unnest(p.proargnames) with ordinality as a(name, i)
  join unnest(coalesce(p.proallargtypes, p.proargtypes::oid[])) with ordinality as t(typ, i) using (i)
  where coalesce(p.proargmodes[a.i], 'i') in ('i', 'b')
    and t.typ in ('uuid'::regtype, 'text'::regtype, 'character varying'::regtype,
                  'bigint'::regtype, 'integer'::regtype, 'smallint'::regtype)
    and a.name ~* '^(p|in|arg|v|target|the)?_*(target_)?(user|usr|owner|profile|member|account|staff|person|author|customer)_?(id|uuid|uid)$'
) ids
where n.nspname = any(%(schemas)s)
  and p.prosecdef
  and p.prokind = 'f'
  and l.lanname in ('sql', 'plpgsql')
  and ids.names is not null
  and pg_catalog.to_regrole('anon') is not null
  and pg_catalog.to_regrole('authenticated') is not null
  and ((pg_catalog.has_function_privilege('anon', p.oid, 'EXECUTE')
        and pg_catalog.has_schema_privilege('anon', n.oid, 'USAGE'))
    or (pg_catalog.has_function_privilege('authenticated', p.oid, 'EXECUTE')
        and pg_catalog.has_schema_privilege('authenticated', n.oid, 'USAGE')))
  -- comments are dropped first, so a note that mentions auth.uid() does not count as a check;
  -- strings are kept (current_setting('request.jwt.claims') is a check), and a "--" inside
  -- one is not taken for a comment
  and regexp_replace(
        p.prosrc,
        '(''(?:[^'']|'''')*'')|--[^\n]*|/\*(?:[^*]|\*+[^*/])*\*+/', '\1', 'g'
      ) !~* 'auth\.(uid|jwt)\s*\(|request\.jwt'
  -- ...and it calls no function that asks who is calling, itself or through one more call
  -- (a guard such as require_owner() that relies on a current_user_id() helper). The names
  -- of those functions are gathered once into one pattern, so each body is matched once.
  and not pg_catalog.texticregexeq(
        regexp_replace(
          p.prosrc,
          '(''(?:[^'']|'''')*'')|--[^\n]*|/\*(?:[^*]|\*+[^*/])*\*+/', '\1', 'g'),
        '\m(' || (
          select coalesce(string_agg(distinct k.name, '|'), '$^')
          from (
            select regexp_replace(p.proname::text, '([^a-z0-9_])', '\\\1', 'gi') as name
            from pg_catalog.pg_proc p
            join pg_catalog.pg_namespace gn on gn.oid = p.pronamespace
            where gn.nspname !~ '^pg_' and gn.nspname not in ('information_schema', 'auth')
              and pg_catalog.texticregexeq(
                    regexp_replace(
                      p.prosrc,
                      '(''(?:[^'']|'''')*'')|--[^\n]*|/\*(?:[^*]|\*+[^*/])*\*+/', '\1', 'g'),
                    'auth\.(uid|jwt)\s*\(|request\.jwt')
            union
            select regexp_replace(p.proname::text, '([^a-z0-9_])', '\\\1', 'gi')
            from pg_catalog.pg_proc p
            join pg_catalog.pg_namespace gn on gn.oid = p.pronamespace
            where gn.nspname !~ '^pg_' and gn.nspname not in ('information_schema', 'auth')
              and pg_catalog.texticregexeq(
                    regexp_replace(
                      p.prosrc,
                      '(''(?:[^'']|'''')*'')|--[^\n]*|/\*(?:[^*]|\*+[^*/])*\*+/', '\1', 'g'),
                    '\m(' || (
                      select coalesce(string_agg(distinct regexp_replace(p.proname::text, '([^a-z0-9_])', '\\\1', 'gi'), '|'), '$^')
                      from pg_catalog.pg_proc p
                      join pg_catalog.pg_namespace gn on gn.oid = p.pronamespace
                      where gn.nspname !~ '^pg_' and gn.nspname not in ('information_schema', 'auth')
                        and pg_catalog.texticregexeq(
                              regexp_replace(
                                p.prosrc,
                                '(''(?:[^'']|'''')*'')|--[^\n]*|/\*(?:[^*]|\*+[^*/])*\*+/', '\1', 'g'),
                              'auth\.(uid|jwt)\s*\(|request\.jwt')
                    ) || ')\s*\(')
          ) k
        ) || ')\s*\(')
order by 1;

-- check: policy_any_signed_in
-- severity: medium
-- title: Policy lets every signed-in user in
-- why: A policy whose whole condition is "the caller is signed in" (auth.uid() is not
--      null, or auth.role() = 'authenticated') does not ask whose row it is. Anyone who
--      signs up reads, or writes, every row; with open sign-up that is close to public.
--      Right for data every member may see, wrong for rows that belong to one user.
--      Left out when no API role holds the privilege on the table, since nothing is open.
select
  quote_ident(p.schemaname) || '.' || quote_ident(p.tablename) || '.' || quote_ident(p.policyname)
    as location,
  p.cmd || ': the only condition is that the caller is signed in ('
    || concat_ws(' and ',
         case when c.using_open then 'USING' end,
         case when c.check_open then 'WITH CHECK' end)
    || '), so every signed-in user gets every row. Compare a column with auth.uid(), or '
    || 'declare the table as meant for all members' as detail
from pg_catalog.pg_policies p
cross join lateral (
  select
    translate(lower(coalesce(p.qual, '')), E' ()\n\t', '') in (
      'auth.uidisnotnull', 'selectauth.uidasuidisnotnull',
      'auth.role=''authenticated''::text', 'selectauth.roleasrole=''authenticated''::text') as using_open,
    translate(lower(coalesce(p.with_check, '')), E' ()\n\t', '') in (
      'auth.uidisnotnull', 'selectauth.uidasuidisnotnull',
      'auth.role=''authenticated''::text', 'selectauth.roleasrole=''authenticated''::text') as check_open
) c
cross join lateral (
  select (quote_ident(p.schemaname) || '.' || quote_ident(p.tablename))::regclass as oid
) t
where p.schemaname = any(%(schemas)s)
  and p.permissive = 'PERMISSIVE'
  and (c.using_open or c.check_open)
  and pg_catalog.to_regrole('anon') is not null
  and pg_catalog.to_regrole('authenticated') is not null
  -- only where an API role the policy applies to holds the privilege it is about (a column
  -- privilege counts); a policy on a table the API roles cannot touch opens nothing
  and exists (
    select 1
    from unnest(array['anon', 'authenticated']) r(role_name),
         unnest(case p.cmd when 'ALL' then array['SELECT', 'INSERT', 'UPDATE', 'DELETE']
                           else array[p.cmd] end) x(privilege)
    where (r.role_name = any(p.roles) or 'public' = any(p.roles))
      and case when x.privilege = 'DELETE'
               then pg_catalog.has_table_privilege(r.role_name, t.oid, x.privilege)
               else pg_catalog.has_any_column_privilege(r.role_name, t.oid, x.privilege) end)
order by 1;

-- check: policy_always_true
-- severity: medium
-- title: Policy lets its roles write every row, with no condition
-- why: USING (true) or WITH CHECK (true) on INSERT, UPDATE, DELETE or ALL lets every caller
--      the policy applies to add, change or remove any row: RLS is on, but this policy
--      filters nothing. Almost never right. A FOR ALL policy counts only where a write
--      privilege is held; with SELECT alone it is left to policy_read_always_true. pgrls reports the same over a direct connection
--      (SEC008, SEC028); this check also runs from a snapshot and through the API.
select
  quote_ident(p.schemaname) || '.' || quote_ident(p.tablename) || '.' || quote_ident(p.policyname)
    as location,
  p.cmd || ' for ' || array_to_string(p.roles, ', ') || ': '
    || concat_ws(' and ',
         case when c.using_true then 'USING (true)' end,
         case when c.check_true then 'WITH CHECK (true)' end)
    || ', so every row is open to them. Add a condition, or declare the table as public on purpose'
    as detail
from pg_catalog.pg_policies p
cross join lateral (
  select
    translate(lower(coalesce(p.qual, '')), E' ()\n\t', '') = 'true' as using_true,
    translate(lower(coalesce(p.with_check, '')), E' ()\n\t', '') = 'true' as check_true
) c
cross join lateral (
  select (quote_ident(p.schemaname) || '.' || quote_ident(p.tablename))::regclass as oid
) t
where p.schemaname = any(%(schemas)s)
  and p.permissive = 'PERMISSIVE'
  and (c.using_true or c.check_true)
  and p.cmd <> 'SELECT'
  and pg_catalog.to_regrole('anon') is not null
  and pg_catalog.to_regrole('authenticated') is not null
  -- only where an API role the policy applies to holds the privilege it is about (a column
  -- privilege counts); a policy on a table the API roles cannot touch opens nothing
  and exists (
    select 1
    from unnest(array['anon', 'authenticated']) r(role_name),
         unnest(case p.cmd when 'ALL' then array['INSERT', 'UPDATE', 'DELETE']
                           else array[p.cmd] end) x(privilege)
    where (r.role_name = any(p.roles) or 'public' = any(p.roles))
      and case when x.privilege = 'DELETE'
               then pg_catalog.has_table_privilege(r.role_name, t.oid, x.privilege)
               else pg_catalog.has_any_column_privilege(r.role_name, t.oid, x.privilege) end)
order by 1;

-- check: policy_read_always_true
-- severity: low
-- title: Policy lets its roles read every row, with no condition
-- why: A SELECT policy with USING (true) shows every row to every caller it applies to.
--      Right for a table that is public on purpose (published posts, feature flags, a
--      product list); wrong for rows that belong to a person or an organisation. Low
--      because it is so often meant: read the table name and decide.
select
  quote_ident(p.schemaname) || '.' || quote_ident(p.tablename) || '.' || quote_ident(p.policyname)
    as location,
  p.cmd || ' for ' || array_to_string(p.roles, ', ') || ': '
    || concat_ws(' and ',
         case when c.using_true then 'USING (true)' end,
         case when c.check_true then 'WITH CHECK (true)' end)
    || ', so they read every row. Fine if the table is public on purpose; otherwise add a condition'
    as detail
from pg_catalog.pg_policies p
cross join lateral (
  select
    translate(lower(coalesce(p.qual, '')), E' ()\n\t', '') = 'true' as using_true,
    translate(lower(coalesce(p.with_check, '')), E' ()\n\t', '') = 'true' as check_true
) c
cross join lateral (
  select (quote_ident(p.schemaname) || '.' || quote_ident(p.tablename))::regclass as oid
) t
where p.schemaname = any(%(schemas)s)
  and p.permissive = 'PERMISSIVE'
  and c.using_true
  and p.cmd in ('SELECT', 'ALL')
  and pg_catalog.to_regrole('anon') is not null
  and pg_catalog.to_regrole('authenticated') is not null
  -- only where an API role the policy applies to holds the privilege it is about (a column
  -- privilege counts); a policy on a table the API roles cannot touch opens nothing
  and exists (
    select 1
    from unnest(array['anon', 'authenticated']) r(role_name),
         unnest(array['SELECT']) x(privilege)
    where (r.role_name = any(p.roles) or 'public' = any(p.roles))
      and case when x.privilege = 'DELETE'
               then pg_catalog.has_table_privilege(r.role_name, t.oid, x.privilege)
               else pg_catalog.has_any_column_privilege(r.role_name, t.oid, x.privilege) end)
  -- a FOR ALL policy is reported here only when no role it applies to can write;
  -- where one can, policy_always_true reports it
  and (p.cmd = 'SELECT' or not exists (
    select 1
    from unnest(array['anon', 'authenticated']) r(role_name)
    where (r.role_name = any(p.roles) or 'public' = any(p.roles))
      and (pg_catalog.has_any_column_privilege(r.role_name, t.oid, 'INSERT')
        or pg_catalog.has_any_column_privilege(r.role_name, t.oid, 'UPDATE')
        or pg_catalog.has_table_privilege(r.role_name, t.oid, 'DELETE'))))
order by 1;
