# Checks the toolkit cannot settle

The `webcare` report lists every item below as `NOT_RUN`. Work through the ones the request touches, record the evidence source for each, and leave the rest marked `NOT_RUN` in your own report.

Everything here is read-only. The SQL reads the system catalog and can run as the `webcare_auditor` role.

## Supabase Security Advisor

On the `--via-api` route, `--with-advisors` reads the security lints for you; the manual run below also covers the performance and health advisors.

Supabase's own linter sees project settings the catalog does not show. Call the MCP `get_advisors` tool for the project (security type), or run `supabase db advisors` with a scoped access token. Needs internet, so it cannot run on an isolated machine. Record the project reference and the time of the run.

## Public Storage buckets

A bucket marked public serves every object in it to anyone with the URL, whatever the policies on `storage.objects` say. On the `--via-api` route the toolkit's `storage_buckets` check lists them. Otherwise check the Storage page of the Dashboard, or the Advisor output. The audit role cannot read `storage.buckets`, by design.

## Data API exposure

Open Project Settings → Data API. Confirm the exposed schemas are the intended ones, and note whether new tables are exposed automatically. A table reachable through the API needs both an explicit GRANT to the roles that should reach it and RLS enabled. The two are separate: the grant decides whether the table is reachable, RLS decides which rows.

## SECURITY DEFINER functions

In a project that reaches its tables through functions, this list is the access-control surface. The toolkit covers the mechanical part: a live run reports every SECURITY DEFINER function `anon` may execute and compares it with the target's `expected_anon_functions`, flags functions still open to PUBLIC, guards that read `current_user`, and default privileges that publish new functions; an offline run replays the migration files for the same mistakes. What stays manual is reading the body of each function that remains public.

Without the toolkit, review every row of this query where `anon_may_execute` is true, and every row where `settings` does not pin `search_path`.

```sql
select n.nspname as schema,
       p.proname as function,
       pg_get_function_identity_arguments(p.oid) as arguments,
       has_function_privilege('anon', p.oid, 'EXECUTE') as anon_may_execute,
       has_function_privilege('authenticated', p.oid, 'EXECUTE') as authenticated_may_execute,
       p.proconfig as settings
from pg_catalog.pg_proc p
join pg_catalog.pg_namespace n on n.oid = p.pronamespace
where p.prosecdef
  and n.nspname not in ('pg_catalog', 'information_schema')
order by 1, 2;
```

For each function a client can call, read its body for a check on the caller (`auth.uid()`, a role lookup) before it touches data, and follow the check into any guard function it delegates to. Three things defeat a check that looks present:

- Postgres grants EXECUTE on a new function to PUBLIC, and every role is a member of PUBLIC. `REVOKE ... FROM anon` alone changes nothing.
- On Supabase the schema's default privileges also grant EXECUTE to `anon` and `authenticated` by name. `REVOKE ... FROM PUBLIC` followed by a GRANT to `service_role` leaves those two grants in place.
- Inside a SECURITY DEFINER function `current_user` is the function owner, whoever calls. A guard that tests `current_user` passes every caller. `session_user`, `auth.uid()` and the request claims describe the caller.

When a function is closed, its rollback script must be regenerated: one written from the earlier state re-grants PUBLIC.

## Auth sessions and token lifetime

Deleting a user does not invalidate access tokens already issued. Check the JWT expiry setting, and check that the offboarding path signs the user out or revokes sessions before deletion. For strict cases, sensitive operations should validate `session_id` against `auth.sessions`.

## Authorization read from JWT claims

Claims taken from `app_metadata` or `auth.jwt()` stay as they were until the token is refreshed. Check that a revoked permission stops working within an acceptable time. Claims from `user_metadata` must never drive authorization: the user can edit them (pgrls SEC033 flags this in policies; check application and function code by reading it).

## Edge Functions

For each function, check `verify_jwt` in `supabase/config.toml` or the function settings. Where it is off, the function's own code must establish who is calling before doing anything on their behalf.

## Access tokens used by CI and agents

List where a Supabase access token is configured (CI secrets, agent connectors). Each should be a scoped token limited to the project and permissions its job needs. A classic token reaches every organization and project of the account. Commands that connect with the database password are not limited by token scope.

## Dependency pins

Confirm a lockfile is committed for each package manager in use, and that no workflow installs or runs a tool at `@latest`.

## What the toolkit already ran, for reference

In a live run the toolkit executes the six queries in `sql/extra-checks.sql`: UPDATE policies with no matching SELECT policy, policies calling the deprecated `auth.role()`, Storage policies that allow upload but not replace, SECURITY DEFINER functions that read `current_user`, default privileges that make new functions executable by API roles, and (as information only) the same defaults of the platform's own `supabase_admin` role. It also lists the SECURITY DEFINER functions `anon` may execute. Without the toolkit, those queries can be run by hand as the audit role.

## API logs for functions open to anonymous callers

The toolkit's `--with-logs` check does this for the last 24 hours, counting requests only. What follows is for looking further back, or when that check was not run.

A catalog shows who may call a function, not who did. Before revoking EXECUTE, and as soon as an unintended public function is found, read the API gateway logs for requests to `/rest/v1/rpc/<name>`: which functions are called successfully without a signed-in user, and with which kind of key. Logs expire (two days on some plans), so an exposure older than the retention window can no longer be examined. Leave CORS preflight requests (`OPTIONS`) out; they carry no key and execute nothing. Group by path, key kind and status; do not read request bodies or addresses.

A function that is called only with the secret key can lose its grants to `anon` and `authenticated` safely. A function called with the public key and no user must stay on `expected_anon_functions`, or its caller must change first.

## Changes applied outside the migration history

Compare the migration history table with the migration files in the repository, and ask what was run through the SQL editor or the Management API. A database changed outside its history makes every file-based result wrong in one direction or the other, and makes a rollback written from the files unsafe. Record such changes in the history, or regenerate the files from the live catalog, before relying on an offline check.

## Which site talks to which database

Confirm from the configuration each deployed site actually uses which project it points at, and name databases by project reference in every report. Environment names drift: a database called production in one document can be the trial in another. Check for old deployments that are still reachable and still connected to a database holding real data, and for more than one database receiving the same users' work.
