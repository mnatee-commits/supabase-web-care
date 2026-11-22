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
    || 'exposed schema that runs as the caller and passes a URL on. Before revoking, find '
    || 'triggers and functions that call net as the signed-in user, since they would stop working'
    as detail
from pg_catalog.pg_namespace n
join pg_catalog.pg_proc p on p.pronamespace = n.oid
cross join pg_catalog.pg_roles r
where n.nspname = 'net'
  and r.rolname in ('anon', 'authenticated')
  and pg_catalog.has_schema_privilege(r.oid, n.oid, 'USAGE')
  and pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE')
group by r.rolname
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
