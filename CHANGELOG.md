# Changelog

Versions before 1.10 were developed inside another repository; this file
summarises them.

## 1.37.0
The database health check (`db_health`) also looks at resources, in the same single
read-only statement:
- `connections_near_limit`: connections in use against `max_connections` less the reserved
  ones (medium from 80%, high from 95%); below that the figure is a note.
- `postgres_end_of_life`: the major version has left community support (medium) or does
  within 180 days (low).
- `extension_update_available` (info): extensions with a newer version on the server.
- `slow_statement` (low): among the five statements that use the most time, those that
  average a second or more over at least 20 calls, named by query id with counts and
  timings only. The text of a statement is never read; the id is looked up in the dashboard.
- The size of the database and its five largest tables are given as a note; the database
  cannot see the plan's disk limit, so nothing is judged.

The added statement ran read-only on a real Postgres 17 project before release.

## 1.36.0
- New check `edge_functions`, from files only: the code under `supabase/functions/<name>/`
  and `verify_jwt` in `supabase/config.toml` (`--functions-dir` names another folder).
  `edge_open_to_anyone` (verify_jwt off and no caller check; high with the service role
  key), `edge_service_role_no_caller_check` (the service role key used without finding out
  who is calling), `edge_cors_any_origin`, and `edge_verify_jwt_off` as information for a
  webhook that checks callers itself. Comments are not read as code, and local files a
  function imports (such as `_shared/cors.ts`) are read with it.
- The check is part of every run that reads files, the GitHub Action included; new focus
  area `edge`; findings carry file and line for SARIF; a baseline can cover them; it
  follows `--changed-since`.
- Limits, stated in the report each time: files cannot show a function deployed with
  `--no-verify-jwt` or switched in the dashboard, and the findings are signs, not proof.

## 1.35.0
Fixes from the fourth outside review (Gemini, 23 November 2026, of 1.26.0 to 1.34.0).
- The real-data question at a terminal: a run from a `--snapshot` file no longer asks,
  since nothing is contacted, unless the anonymous probe would reach the project, and then
  it names the probe and nothing else. The probe is listed in the other routes too. The
  question is written to stderr with the warning, so it never lands in redirected output,
  and it is asked only when both stdin and stderr are a terminal.
- The GitHub Action joins every value to its option with `=`, so a value that starts with
  `-` stays a value; refuses a `sarif` other than true or false; and stops with exit 2 when
  a `migrations` folder named on purpose does not exist, instead of leaving the SQL checks
  out without a word.
- "In short" puts visitors first by rule name, credentials in the source, or a finding
  that names `anon` or `PUBLIC`, instead of loose words in rule names: `realtime` no longer
  lifts the signed-in-only Realtime rule, and a materialized view readable by anon is lifted.
- `report.json` `schema_version` 1.1: `summary.first[]` carries the finding's `message`.
  The schema test now fails on a field the schema does not describe.
- The credential scan skips `.webcare-output`, where the pre-commit hook writes its report.
- `webcare init`: a local target is not asked for a project reference and gets next steps
  for a direct connection; the environment answer is read in any case; the temporary file
  is removed on any interruption, Ctrl-C included.

Reviewed and left as is, with the reason:
- Options switched on in `webcare.toml` (`checks = [...]`) were already listed in the
  question: the file is applied before the question is asked. A test now holds this.
- There is no `--db` flag: a connection string is read only from an environment variable,
  so it never appears in shell history; the message names that variable.
- The wording "the JWT secret in the answer is dropped" was already singular.
- A project reference is 20 lower-case letters on Supabase; digits are not accepted on
  purpose, so a mistyped reference is caught.

## 1.34.1
- `extension_net_callable` no longer advises a REVOKE that cannot work: when schema `net`
  belongs to another role (on Supabase, `supabase_admin`), a REVOKE by the checking role
  only warns. The detail now says so and names the ways that do work: turn pg_net off if
  nothing uses it, or ask the platform to revoke it. Found while drafting a fix on a real
  project, where the owner of `net` was `supabase_admin`.

## 1.34.0
Fixes from the third outside review (Gemini, 23 November 2026, of 1.22.0 to 1.25.0).
- `realtime_messages_open` judged USING and WITH CHECK together, so a policy that scoped
  reading but left sending open (`WITH CHECK (true)`) was missed; each is now judged on its
  own. New `realtime_messages_open_to_signed_in` (low): every signed-in user may use every
  private channel, which matters when users of different organisations must not hear
  each other.
- `view_runs_as_owner` no longer covers materialized views, which cannot use
  `security_invoker`; new `matview_readable_by_api_roles` (medium) says what to do instead.
- `--changed-since` counts a deleted migration as a SQL change, so removing the file that
  enabled RLS no longer skips the SQL checks; git names are read NUL-separated, so Thai or
  spaced file names are no longer lost to git's quoting.
- `parity` is a group of its own: changes since a saved inventory no longer fail
  `--fail-groups security` or ride along with `--group security`.
- Served schemas are compared without regard to case or quotes; the parity note on
  schemas compares sets, not order; the lock-wait message says the time counts from the
  statement's start, since Postgres does not record when a wait began.

Reviewed and left as is, with the reason:
- `--changed-since HEAD^` was already accepted: the revision pattern includes `^`.
- `db_extra_search_path` does not expose functions: PostgREST serves RPC only from the
  schemas in `db_schema`; the extra path only resolves names. It stays a note.
- The `xid_age` and `sequences` parts already sort before their row limit.
- Unindexed foreign keys over a direct connection without the Management API remain
  uncovered; recorded on the roadmap.

## 1.33.0
- report.json carries `schema_version` ("1.0"), and its shape is published in
  `schema/report.schema.json`. Within 1.x fields are only added; statuses and severities
  do not change. The test suite validates real reports against the schema. Rules for
  anything built on it (show NOT_RUN as not known, say when the scope was partial) are in
  `docs/REPORT_FORMAT.md`. Decided with the owner, so others can build an interface on it.

## 1.32.0
- A pause before real data: before `check` or `inventory` of a target that is production
  or holds real data, the tool says which target, which route and what it will read (every
  optional GET listed), and waits for `yes`; anything else stops it before anything is
  contacted. Only at a terminal: in CI, from a script or through an AI assistant, the
  refusal stands and `--owner-approved` is still the way on. Decided with the owner.

## 1.31.0
- `webcare init` writes a target into webcare.toml from four answers: a name, local,
  staging or production, whether it holds real people's data (yes when not answered, so
  the owner-approval guard applies), and the project reference. Asks at a terminal; takes
  flags from an AI assistant. The whole file is checked before it is replaced, a taken
  name is refused, and no key is asked for. It prints the next steps, including how to make
  a narrow access token.
- The skill gains "First run with someone new to this": the same questions one at a time,
  then `init`, a file check, how the person makes a token themselves (never pasted into
  the chat), the database check, and the "In short" page explained first.

## 1.30.0
- report.md opens with "In short": how many problems, the three to act on first, and
  every check that did not run, with a reminder that no result certifies a safe site.
  Ordered by severity; within one severity, findings that reach visitors who are not
  signed in come first, and a target holding real data says so. report.json carries the
  same under `summary`. Decided with the owner for beginners who use the tool through AI.
- Thai lines for all 69 pgrls rules, so the Thai summary explains them too; a test fails
  if pgrls's catalog gains a rule without one.

## 1.29.0
- A GitHub Action (`action.yml`): `uses: mnatee-commits/supabase-web-care@<commit>` runs the
  file checks on a pull request in one step, with inputs for migrations, baseline,
  changed-since, fail-on, SARIF and language. It contacts no database. Inputs reach the
  script only as environment variables and are checked before use; a test fails if an input
  is ever placed in a shell command. `setup-python` is pinned to a commit.
- pre-commit hooks (`.pre-commit-hooks.yaml`): `webcare-secrets` and `webcare-migrations`.
- Tried locally: the action's script found the bad fixture's problems and refused a
  `fail-on` value carrying a shell command. Not yet run on GitHub Actions.

## 1.28.0
- Thai reports explain every finding in Thai: `report.md` with `--lang th` gains a column
  with what the rule means and what to do, next to the English detail, for every rule the
  toolkit has (a test fails when a new rule has no Thai line). Findings from pgrls and from
  Supabase's advisors get one line per source. `report.json` is unchanged.

## 1.27.0
- `--with-platform`: two GETs, of SSL enforcement and network restrictions. SSL off is a
  finding (medium; high for real data); direct connections open to every address are low.
  Both endpoints are beta on Supabase's side, so an answer in an unknown shape is reported
  as not judged, never as safe. New focus area `platform`; `checks = ["platform"]` in the
  target file. Not yet called against a real project.

## 1.26.0
- Storage, bucket by bucket: a bucket where signed-in users may upload but not replace a
  file (no SELECT or UPDATE policy naming that bucket) is a low finding. The table-wide
  `storage_upsert_incomplete` stays for connections that cannot read the bucket list.
  Visitors who are not signed in are left out on purpose: their upload policy is already a
  finding, and the fix is never to give them UPDATE. Ran on a real project.

## 1.25.0
- `check --parity <inventory file>`: takes a new inventory of the same target and reports
  every change since the file was saved (medium for grants, policies, functions and
  default privileges; low for migrations, jobs, buckets and extensions). Another target's
  file is refused. New focus area `parity`.
- `check --changed-since <ref>`: the credential scan reads only files changed since that
  git revision (and untracked ones), and the SQL checks run only when a SQL file changed.
  Live checks are never narrowed, since a database can change without a commit. The
  revision is checked as a plain name and passed after `--end-of-options`, so it cannot
  act as a git option.
- Both from the second outside review's design proposals, with `--changed-since` limited
  to the file checks.

## 1.24.0
- Four catalog checks: `realtime_table_without_rls` (high), `realtime_messages_open`
  (medium), `view_runs_as_owner` (medium) and `schema_usable_but_unchecked` (low). They run
  on a connection, `--via-api` and a snapshot file. New focus area `realtime`.
- `--with-data-api`: one GET of the PostgREST settings, reduced to `db_schema`,
  `db_extra_search_path` and `max_rows` before anything reads it (the answer is documented
  to carry a JWT secret); served schemas the target leaves out are a medium finding. On
  hosted Supabase the served schemas are not stored in the database, so this GET is the
  only way to read them. Also in the target file as `checks = ["data_api"]`.
- The four statements ran on a real project: no Realtime table, no open channel policy, no
  owner-rights view; one schema (`private`) usable by `authenticated`, as its policies need.

## 1.23.0
- Database health (`db_health`), on a connection and `--via-api`: invalid indexes, table
  bloat, transaction-ID age of tables and the database, sessions idle in a transaction,
  lock waits, and sequences near their limit. One SELECT over statistics; no table row, no
  `pg_stats`, no query text, no application name. Over a direct connection the audit role
  cannot see other roles' sessions, and the report says so instead of passing them.
  Unreadable sequences are counted, not estimated.
- `--with-performance` reads Supabase's Performance Advisor (experimental on Supabase's
  side), one step lower in severity than security lints. `checks = ["performance"]` in the
  target file and `--focus health` switch it on.
- Both are in the `health` group. Designed from the second outside review's proposal,
  minus the two checks the Performance Advisor already makes. Ran on a real project.

## 1.22.0
- `--only` names exact checks: report rows (`table_writes`) or single catalog checks
  (`extension_net_callable`); an optional check named this way is switched on. It cannot
  be mixed with `--focus` or `--group`, so a run never means two things at once.
- `--group security` and `--group health` name sets of areas.
- `--fail-groups` chooses which groups decide the exit code; `--fail-groups security`
  reports health findings without failing CI.
- SECURITY.md now lists every way an optional GET endpoint can be asked for (its flag,
  the target's `checks`, a focus, group or `--only` that names it, `--profile full`).
  The second outside review noticed that the old wording promised only the flags.
- From the design proposals in the second review: `--changed-since` and a parity check
  are planned for file checks and a saved inventory; a database health module is next.

## 1.21.0
- Focused runs: `--focus` with one or more areas (`secrets`, `functions`, `tables`,
  `storage`, `extensions`, `auth`, `advisors`, `health`) runs only their checks, and
  inside the catalog checks only theirs; an area that needs an optional `--via-api`
  check switches it on. `--profile quick` checks files only; `--profile full` switches
  every optional check on. Checks left out keep a row marked `NOT_RUN` with the reason,
  the report names its scope, and the exit code does not count them. Asked for by the
  owner, so that a growing set of checks can be run one area at a time.

## 1.20.0
- Three catalog checks for extension schemas the API roles should not reach:
  `extension_net_callable` (medium: `anon` or `authenticated` may call pg_net, which sends
  HTTP requests from the database server), `extension_vault_reachable` (high: they may
  read Vault or pgsodium, or call their functions) and `extension_cron_reachable` (medium:
  they may schedule pg_cron jobs or read the job list). They run on every route that runs
  the catalog checks: a connection, `--via-api` and a snapshot file. On a Supabase project
  created in November 2026 both roles could call all 12 pg_net functions from the start,
  so read that finding as an open gate, and check for functions that call pg_net as the
  signed-in user before revoking.

## 1.19.0
Fixes from the second outside review (Gemini, 23 November 2026, of 1.16.0 to 1.18.0).
- `table_writes`: a write privilege on a table with RLS off is reported even when the
  table is declared in `expected_table_writes` (before, a declared table was skipped).
  A view that runs with its owner's rights (no `security_invoker = true`) counts as
  unguarded, since the base tables' RLS does not apply to the caller; a foreign table
  cannot have RLS and is told so. TRUNCATE held by `anon` is now a low finding. Tables
  with RLS off come first, so the row limit can never hide them.
- Connection strings: `hostaddr` is refused, because it sends the connection to that
  address whatever `host` says, past both the target match and the TLS rule. An
  upper-case `sslmode` gets a clear message.
- Function privileges from SQL files: argument types from other schemas stay apart
  (`v1.payload` is not `v2.payload`); `ALTER FUNCTION ... RENAME TO` and `SET SCHEMA`
  carry a function and its privileges to the new name.
- `secdef_trusts_current_user`: strings and comments are removed in one pass, so a
  comment marker inside a string no longer hides the code after it.
- Database password rule: quoted values may hold `#` and other symbols; JSON keys and
  prefixed names (`NEXT_PUBLIC_DB_PASSWORD`) are matched; a `$` inside single quotes
  is a literal; code that reads a password (`process.env.X`, `os.getenv(...)`,
  `z.string()`) and multi-word placeholders are no longer reported.
- SARIF: paths with brackets (Next.js route groups) are placed; statements spread over
  several lines and names in comments are handled; a finding is left out rather than
  placed on the wrong file when two given SQL files share a name or the file lies
  outside the current directory; every result carries a fingerprint that survives
  line moves. Two scanned folders with the same name are told apart by their path.
- Release workflow: the version is checked as a whole string, so a value with a line
  break cannot add variables; write permission is granted to the job only; the
  checkout action is pinned to a commit.

Reviewed and left as is, with the reason:
- An `INSERT` policy `TO public` gives every role INSERT on `storage.objects`, so
  reporting a role that also lacks UPDATE is right.
- `ALTER DEFAULT PRIVILEGES IN SCHEMA ... REVOKE EXECUTE ... FROM PUBLIC` changes
  nothing in Postgres; only the global default carries PUBLIC's EXECUTE.
- `checks = [...]` from the target file is applied before a refusal is reported.
- Commands in `expected_table_writes` are lower-cased and validated when the file loads.
- `.output` and `out` are not skipped, so they are already scanned;
  `SUPABASE_JWT_SECRET` and `GOTRUE_JWT_SECRET` match the existing `*JWT_SECRET*` rule.
- `pyproject.toml` keeps exact pins: these are the versions that were reviewed.

## 1.18.0
Fixes from an outside review of 1.16.0 (Gemini, 23 November 2026).
- Function privileges from SQL files: overloads are now kept apart. Before, a second
  `CREATE FUNCTION` with the same name and other argument types replaced the first in
  the replay, so an open `SECURITY DEFINER` overload could go unreported; a GRANT,
  REVOKE, ALTER or DROP naming argument types now touches that overload only.
- Database connections to a host that is not loopback or private must be encrypted:
  `sslmode=require` is added when none is given, and `disable`, `allow` and `prefer`
  are refused. Applies to the toolkit's own connection and to pgrls.
- Credential scan: new rule for database passwords assigned to `PGPASSWORD`,
  `POSTGRES_PASSWORD`, `SUPABASE_DB_PASSWORD`, `DB_PASSWORD` or `DATABASE_PASSWORD`;
  `--include-build` scans build output; with several roots, `.` is named by its folder.
- A refused `--via-api` run now gives the refusal as the reason for every check asked
  for, not "not asked for". A probe with no database connection and no `--table` says
  so instead of failing quietly.
- `storage_upsert_incomplete` counts policies granted to `public`;
  `secdef_trusts_current_user` ignores block comments; the log summary compares
  function names without regard to case; `inventory` sorts policy roles, so the same
  roles in another order are no longer a difference.
- `pyproject.toml`: `pip install .` installs a `webcare` command, with the SQL files
  inside the package. `requirements.txt` names every direct dependency.
- Documents brought up to date: Security Advisor is read by `--with-advisors`; four
  optional GET endpoints; CI no longer needs a deploy key now that the repository is public.

## 1.17.0
- Releases: pushing a tag `vX.Y.Z`, or running the `release` workflow on main, publishes a
  GitHub Release whose notes are this file's
  section for that version. The tag must match `webcare/__init__.py`.
- New check `table_writes`, on `--via-api` and over a connection: which tables and views
  `anon` and `authenticated` may insert, update or delete, judged against the target's new
  `expected_table_writes`. A write on a table with RLS off is always reported; TRUNCATE
  is noted. The statement ran on a real Supabase project (Postgres 17).
- `--sarif` writes `report.sarif` (SARIF 2.1.0) with the findings that can be tied to a
  file line, and counts the rest. The example CI workflow has an optional upload step.
  Not yet uploaded to GitHub code scanning.

## 1.16.0
- New `inventory` and `compare` commands. `inventory` saves what one database is made
  of (RLS state, table and column grants, default privileges, function and policy facts,
  extensions, migration history, scheduled jobs, buckets) through a connection or
  `--via-api`; function bodies and policy expressions leave only as md5 hashes.
  `compare` reports what differs between two files, contacts nothing, and exits 1 on any
  difference. The statements ran on a real Supabase project (Postgres 17); the whole
  command has run against the test database only.

## 1.15.0
- A target can switch optional checks on with `checks = [...]` and set `lang` in
  `webcare.toml`. Flags on the command line still win; the report notes which checks
  the file switched on. `--lang` no longer has a fixed default: it falls back to the
  target's `lang`, then `WEBCARE_LANG`, then English.

## 1.14.1
- `--with-advisors`: the real endpoint answers with one entry per flagged object, not one per
  lint. 1.13.0 and 1.14.0 counted each entry as one object and named none; entries are now
  grouped by lint name, so counts, object names and `advisors_ignore` totals are right.
  Found when the first run against a real project showed "(1)" for a lint of 328 objects.

## 1.14.0
- New catalog check `default_table_privileges`: reports when the schema's default
  privileges grant every new table or sequence to `anon`, `authenticated` or `PUBLIC`.
  The table-level twin of `default_function_privileges`; low severity.

## 1.13.0
- `--with-advisors`: reads Supabase's own security lints through the Management API
  (`advisors_read`). Findings carry a count and the first few object names; lints
  the owner has reviewed go in a target's `advisors_ignore` and are counted, not
  hidden. Not yet run against the real endpoint.

## 1.12.0
- Run against a real project through the Management API with `--lang th`: every row
  matched the 1.11.1 run, and an independent secret scan of this repository found nothing.
- READMEs gain a "Use it together with" section (pgrls, Security Advisor,
  Supabase's skills) and name the projects credited.
- `report.md` can be written in English or Thai: `--lang en` (now the default)
  or `--lang th`, or set `WEBCARE_LANG`. `report.json` records the language
  and carries the manual items in it. **Changed default:** reports were Thai
  only before; pass `--lang th` to keep that.
- Version 1.11.1 was run against a real project through the Management API
  with every optional check on; results matched the 1.9.0 run.
- English editions of the manual and of the two guides in `docs/`.
- READMEs state that the Management API route does not lint RLS policies
  and that the checks certify nothing.

## 1.11.1
- The access token is now read from `WEBCARE_ACCESS_TOKEN` by default, not
  `SUPABASE_ACCESS_TOKEN`, so an account-wide token set for the Supabase CLI
  is never picked up by accident. `--token-env` still names another variable.

## 1.11.0
- `expected_cron_jobs` on a target: a scheduled job that should exist but is absent
  or switched off is reported. Without it, a database with no jobs passed.

## 1.10.0
- `--write-baseline` and `--baseline` for the checks that read SQL files, so
  a project with existing migrations can fail only on what a change adds.
- Example GitHub Actions workflow for a site's repository, and this
  repository's own test workflow.
- Licence (MIT), credits and security policy added on becoming its own repository.

## 1.9.0
- Optional check of sign-in settings (`--with-auth-config`). The endpoint's
  answer is reduced to an allowlist so that no secret is kept.

## 1.8.0
- Storage buckets: public access, anonymous writes, upload limits, policies
  that name no bucket.

## 1.7.0
- Optional 24-hour API log summary, counts only (`--with-logs`).

## 1.6.0
- Optional check of the platform's backup list (`--with-backups`).

## 1.5.0 and 1.5.1
- Scheduled jobs (pg_cron) that failed or stopped.
- Default privileges of the platform's own role reported as information.

## 1.4.0
- Fetch the catalog snapshot through the Management API read-only endpoint
  (`--via-api`), for machines that cannot reach Postgres.

## 1.3.0
- Catalog snapshots: judge a saved, read-only snapshot without a connection.

## 1.2.0
- Who may call `SECURITY DEFINER` functions, from SQL files and from the
  live catalog, against a declared allowlist.

## 1.0.0 and 1.1.0
- Credential scan, pgrls runner, audit role, anonymous HEAD probe, Thai report.
