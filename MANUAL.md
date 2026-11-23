# supabase-web-care: manual

Read-only tools and a skill for looking after a website built on Supabase or
PostgreSQL. They check for credentials left in code, RLS policies, who may
call functions, and what a visitor who is not signed in can read. No row of an
application table is read at any step.

This is the English edition of [README_TH.md](README_TH.md). The short
overview is in [README.md](README.md).

`report.md` is written in English by default. Pass `--lang th`, or set
`WEBCARE_LANG=th`, for a Thai report. Finding messages themselves are in
English in both.

## Read this first

- **Tested against two real projects, both the author's.** Everything else
  was tested against local stand-ins. A project shaped differently may hit
  rough edges; try it on your own staging project first.
- **The `--via-api` route does not check RLS policies.** Most Supabase sites
  let the browser read and write tables directly and rely on RLS. For those
  sites the policy check matters most, and it runs only from SQL files or over
  a direct database connection (through pgrls). On the `--via-api` route the
  report shows `rls_live` as `NOT_RUN`. Do not read the rest of that report as covering your tables. Adding `--with-advisors` brings in Supabase's own security lints, which include several RLS checks (RLS off, always-true policies); that narrows the gap but is not pgrls's policy analysis.
- **It certifies nothing.** The checks follow Supabase's own guidance. They
  are not mapped to OWASP, to a privacy law, or to a health-data standard, and
  a clean report is not evidence of compliance.
- **A report with no findings does not mean the site is secure.** The tool
  reports what it checked and shows everything it did not check as `NOT_RUN`.
  It does not replace a review by someone who knows the system.

## What is in this repository

| Part | Purpose |
|---|---|
| `skills/supabase-web-care/SKILL.md` | The skill for AI agents: method, prohibitions, how to read results |
| `CHAT-INSTRUCTIONS.md` | The same text, for chat platforms without a skill system |
| `webcare/` | The Python toolkit: credential scan, pgrls runner, function privileges, catalog checks, anonymous access, Storage buckets, sign-in settings, scheduled jobs (pg_cron), backups, log summary, report |
| `sql/auditor-role.sql` | Creates the `webcare_auditor` role, which can read the system catalog only |
| `sql/extra-checks.sql` | Seven SELECT statements covering what pgrls does not |
| `sql/catalog-snapshot.sql` | One SELECT that takes a snapshot of the database structure, for machines that cannot reach the database |
| `docs/OFFLINE_VM.md` | Step-by-step run on a machine cut off from the internet, and the list of what has not been verified |
| `docs/CI.md` | Checking migrations on every pull request |
| `tests/` | Test suite and sample schemas (synthetic data only) |

The work is done in three layers, and only the third is written here.

1. **Official:** the `supabase` and `supabase-postgres-best-practices` skills, and Supabase's Security Advisor
2. **pgrls 0.57.1**, used as published, unmodified
3. **This repository:** the skill, the toolkit and the SQL above

## Getting started

Python 3.11 or later is required.

```bash
cd supabase-web-care
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.lock
```

### Check from files (no key and no connection of any kind)

```bash
python -m webcare check --repo <web project folder> --migrations <migrations folder>
```

Results go to `webcare-output/report.md` and `report.json`. Files whose
names start with `ROLLBACK_` are skipped. If file names do not sort in the
order the migrations were actually applied, name the files one by one with
`--sql-file` instead.

A file check cannot run every pgrls rule. Rules about `SECURITY DEFINER`
functions, views and default privileges need a database. The report names the
rules that did not run, every time.

Function privileges are checked from files by the toolkit itself (the
`functions_static` check). It replays CREATE FUNCTION, GRANT, REVOKE, ALTER
FUNCTION and DROP FUNCTION in file order and reports `SECURITY DEFINER`
functions that

- are still executable by `PUBLIC`, including the case where only `anon` was revoked, which closes nothing
- were revoked from `PUBLIC` but not from `anon`, which on Supabase can still call them through the schema's default privileges
- use `current_user` in their body, which in such a function means the owner, not the caller
- do not set `search_path`

A project that already has old migrations can adopt this without fixing them
first. Run once with `--write-baseline webcare-baseline.json` to record what is
found today, then run with `--baseline webcare-baseline.json`. The report then
counts only what is new and always says how many findings the baseline
covered. A baseline works for checks that read SQL files only; a leaked
credential or a finding from a live system cannot be excused this way. See
`docs/CI.md` for wiring this into CI.

Use this step to check a new migration before applying it. The result depends
on file order: if the file that revokes a privilege is read before the file
that creates the function, the function counts as still open.

### Check from the database

1. Have the database administrator run `sql/auditor-role.sql`, then set a password as described in step 2 of that file.
2. Copy `webcare.example.toml` to `webcare.toml` and declare a target.
3. Put the connection string in an environment variable and run:

```bash
export WEBCARE_DATABASE_URL='postgresql://webcare_auditor:<password>@<host>:<port>/<database>'
python -m webcare preflight --target <target name>     # what this role is able to do
python -m webcare check --target <target name> --repo <code folder> --migrations <migrations folder>
```

The database check reports every `SECURITY DEFINER` function that a visitor
who is not signed in may call (the `functions_live` check). Read each one's
code, then list the ones that are meant to be open in
`expected_anon_functions` for that target in `webcare.toml`. From then on any
other function open to anonymous callers is reported as high, and listed
functions that are no longer callable are reported too. Run it again after
every change to see that nothing was opened or lost.

If the target declares `rest` and `WEBCARE_ANON_KEY` holds a public key (anon
or publishable), the tool sends one HEAD request per table to see whether an
anonymous visitor sees rows. A HEAD request has no response body, so no row is
downloaded.

### When the machine cannot reach the database

Some machines can only make web connections and cannot reach Postgres at all.
There are two routes. Both use a catalog snapshot: the result of one read-only
SELECT.

**Route 1: the tool fetches it through the Supabase Management API (more convenient)**

Declare the target's `project_ref` in `webcare.toml`, then run:

```bash
export WEBCARE_ACCESS_TOKEN='<account access token>'
python -m webcare check --target <target name> --via-api --skip secrets --skip static
unset WEBCARE_ACCESS_TOKEN
```

- The tool sends at most six requests: the snapshot statement once, up to two
  statements for Storage, one for table privileges, and up to two for scheduled jobs. Each is a single
  SELECT built by the tool, sent to the project's read-only query endpoint
  (`/database/query/read-only`), which Supabase runs as
  `supabase_read_only_user`. Writes are therefore refused on Supabase's side
  whatever the tool sends. Apart from the three optional GET requests
  described below, no other endpoint is called, and the tool accepts no SQL
  from outside.
- **Storage (`storage_buckets`)** reports buckets that are public without
  being listed in `expected_public_buckets` (medium), buckets where a policy
  lets anonymous visitors write files (medium) or read them although the
  bucket is private (low), buckets with no size or type limit (low), and
  `storage.objects` policies that name no bucket and so apply to all of them.
  It reads the bucket list and facts about policies only. It reads no row of
  `storage.objects`, so it sees no file name and no file content. Like the
  scheduled-jobs check, it gives a result on the `--via-api` route.
- **Scheduled jobs (`health_cron`)** reports pg_cron jobs whose latest run
  failed (medium), that failed within the window (low), or that are active but
  never started (low). The window is 7 days; change it with `--cron-days`. A
  database with no jobs at all passes this check, so if the system depends on
  jobs, list them in `expected_cron_jobs`; a listed job that is absent or
  switched off is reported as medium. The tool reads job names, schedules,
  counts and times. It does not read the command a job runs or the message a
  run returned, because those two fields can hold keys or real data. This
  check gives a result on `--via-api` only. Connected as `webcare_auditor` it
  is `NOT_RUN`, because pg_cron shows each role only its own jobs.
- **Supabase's own security lints (`advisors`)** run only with `--with-advisors`. One more GET reads the platform's Security Advisor: lint names, and the names of the objects they flag. Several of its lints are RLS checks. A lint can name hundreds of objects, so a finding shows the count and the first few names. List lints you have reviewed and accept (for example functions that signed-in users may call by design) in the target's `advisors_ignore`; they are counted in a note, never hidden, and you must not add an entry to make a new finding go away. Supabase documents the `advisors_read` permission for this. It is the platform's verdict, not pgrls's analysis of what each policy lets a caller do.
- **Backups (`health_backups`)** runs only with `--with-backups`. One more GET
  reads the project's backup list, which holds dates and statuses only. It
  reports when no completed backup exists (high for real data, low for
  synthetic), when the newest is older than 48 hours without point-in-time
  recovery, or when the latest attempt failed. Supabase documents the
  `backups_read` permission for this. A backup in the list is not a tested
  restore; trying a restore is still a job for a person.
- **Log summary (`health_logs`)** runs only with `--with-logs`. One more GET
  carries a fixed counting query: requests of the last 24 hours grouped by
  service, table or function name, method, status, kind of key and signed in
  or not. It reports server errors (5xx), bursts of refused requests
  (401/403), and functions called successfully without signing in although
  they are not in `expected_anon_functions`. The query asks for no IP address,
  user id, query string, header value or request body, and drops Storage file
  names. Supabase documents the `analytics_logs_read` permission for this.
  Supabase keeps logs for a limited number of days depending on plan, and this
  check sees 24 hours per run.
- **Sign-in settings (`auth_config`)** runs only with `--with-auth-config`.
  One more GET reads the Supabase Auth configuration. It reports open sign-up
  that was not declared (`expected_open_signup`), anonymous sign-ins,
  unconfirmed e-mail, short passwords, no leaked-password check, no second
  factor, long-lived tokens, refresh tokens that are not rotated, sessions
  that never expire, and redirect lists that are too wide. **That endpoint's
  answer also contains secrets** (the mail server password, OAuth and hook
  secrets). The tool therefore copies a fixed list of settings and discards
  the rest at once, without reading, storing or showing it. Those secrets
  still pass through the memory of the machine that runs the check for a
  moment, so run it only on a machine you trust. Supabase documents the
  `auth_config_read` permission for this.
- **Tables the API roles may write to (`table_writes`)** runs on this route and over a direct connection. One SELECT asks Postgres which tables and views `anon` and `authenticated` may INSERT, UPDATE or DELETE, counting privileges given to `PUBLIC`, to roles they belong to, and on single columns, and whether RLS is on. A write privilege on a table with RLS off is reported at once (high for `anon`, medium for `authenticated`). Declare the writes the site needs in `expected_table_writes`, for example `{ anon = ["public.feedback:insert"], authenticated = ["public.notes", "public.profiles:update"] }`; every other write privilege is then reported per table (medium for `anon`, low for `authenticated`). Without a declaration each role gets one finding that counts and names its writable tables. TRUNCATE ignores RLS and is noted separately. Privileges only; no row is read.
- **Optional checks can be switched on in the target file.** Add `checks = ["advisors", "auth_config", "backups", "logs"]` and `lang = "th"` to a target in `webcare.toml`, and one short command runs them all. Flags on the command line still win, and the report says which checks the file switched on.
- **The token is read from `WEBCARE_ACCESS_TOKEN`**, not from
  `SUPABASE_ACCESS_TOKEN`. That second name is what the Supabase CLI reads,
  and on a developer's machine it usually holds an account-wide token that can
  write. An audit should be handed its own narrow token and never pick up a
  broad one that happens to be set. Do not use a classic or organisation-wide
  token with this tool.
- **The token can do more than its permission name says.** When this was
  tried on 22 November 2026, a fine-grained token created with Database Read
  alone could read the backup list, the logs (which contain users' IP
  addresses) and the sign-in settings (which contain secrets). Treat it like
  an administrator key: one project, the shortest life you can, kept in an
  environment variable only, and revoked as soon as the run is over.
- The token is a stronger credential than the audit role. Through the same
  endpoint it can read table rows, although the tool never asks for any.
- A target that is production or holds real data needs `--owner-approved`,
  exactly as with a direct connection.

**Route 2: an administrator runs the statement and hands over a file (the tool holds no credential at all)**

The administrator runs the statement through a route they already have (the
SQL Editor, for example), saves the result to a file, and the tool judges
that file.

```bash
python -m webcare snapshot-sql --target <target name> > snapshot.sql   # prints the statement, contacts nothing
# the administrator runs snapshot.sql and saves the whole JSON result, e.g. as staging.json
python -m webcare check --snapshot staging.json --target <target name> --skip secrets --skip static
```

- The statement is a single SELECT over the system catalog, built from the same SQL the connected checks use, so both paths judge alike.
- The file holds names of schemas, tables, policies and functions, and yes/no facts. It holds no function body, no policy expression and no data row.
- The file carries the target's name as a label. The tool refuses a file whose label does not match `--target`, so that one database's result is not judged against another's allowlist. The tool cannot verify which database a file really came from; whoever ran the statement answers for that label.
- Neither route can run pgrls against the database, so the "RLS policies from the live catalog" row is `NOT_RUN`. The extra catalog checks and the function check run in full.
- If the target declares `rest` and `WEBCARE_ANON_KEY` is set, the HEAD probe still works, using the table list from the snapshot.
- A snapshot file carries no Storage, scheduled-job, backup, log or sign-in information; those need route 1.

### Checking one area at a time

`--focus` runs only the checks of the areas named, comma-separated or repeated:

| Area | What it covers |
|---|---|
| `secrets` | credentials left in the source tree |
| `functions` | who may call `SECURITY DEFINER` functions, from files and the catalog; guards that trust `current_user`; default privileges of new functions |
| `tables` | RLS policies (pgrls), table write privileges, default privileges of new tables, what an anonymous visitor can read |
| `storage` | Storage policies and buckets |
| `extensions` | pg_net, Vault and pg_cron reachable by the API roles |
| `auth` | sign-in settings (switches `--with-auth-config` on) |
| `advisors` | Supabase's own security lints (switches `--with-advisors` on) |
| `health` | scheduled jobs, backups and the log summary (switches `--with-backups` and `--with-logs` on) |

```bash
python -m webcare check --target staging --via-api --focus extensions
python -m webcare check --target staging --via-api --focus functions,tables
```

`--group security` or `--group health` names a set of areas at once (security is every
area except health). `--only` names exact checks instead: report rows such as
`table_writes`, or single catalog checks such as `extension_net_callable`; it cannot be
mixed with `--focus` or `--group`.

`--fail-groups security` lets only security results decide the exit code, so in CI a
health finding (an old backup, a failed job) is reported without failing the build.

`--profile quick` checks files only and contacts nothing; `--profile full` switches every
optional `--via-api` check on. Every check left out still has a row, marked `NOT_RUN`
with the reason, and the report's header names the scope, so a focused report is never
read as a whole one. A check left out by the focus does not make the exit code 2.

### Comparing two environments

Staging and production that drift apart are a common cause of trouble: a job
that exists in one only, a column restriction applied to one and not the other,
a migration that never reached production. Save an inventory of each, then
compare the two files.

```bash
python -m webcare inventory --target staging --via-api --out staging.inv.json
python -m webcare inventory --target production --via-api --owner-approved --out production.inv.json
python -m webcare compare staging.inv.json production.inv.json --lang th
```

- `inventory` works over either route: a direct connection as `webcare_auditor`, or `--via-api`. It sends single SELECT statements only, the same way the checks do, and the same refusals apply (`--owner-approved` for real data or production).
- It reads, for the schemas declared on the target: tables and views with their RLS state and the privileges of `anon`, `authenticated`, `service_role` and `PUBLIC`; column privileges; default privileges; functions (`SECURITY DEFINER` or not, whether `anon` and `authenticated` may call them, whether `search_path` is pinned); policies (command, roles, permissive or not); extensions; the migration history; scheduled job names and schedules; and buckets.
- **Function bodies and policy expressions leave the database only as md5 hashes.** Two environments with the same hash have the same text; a different hash tells you to read both in their own databases. The file holds no data row, no function body and no policy expression.
- A part the route cannot see is recorded as "not read" with the reason (for example the migration history is not readable by `webcare_auditor`, or pg_cron is not installed), and `compare` reports it as "not compared" instead of guessing.
- `compare` contacts nothing. It writes `compare.md` and `compare.json`: for each part, what only the first has, what only the second has, and what differs. It exits 1 when anything differs, so it can gate a deploy.
- An inventory file holds names of tables, columns, functions, policies, migrations and jobs. Store it as you would a report.

## Guard rails

The tool refuses, and contacts nothing, when

- the target is not declared in `webcare.toml`, or the connection points somewhere other than what was declared
- the target is production or holds real data and `--owner-approved` was not given (give it only after the system's owner has approved that target in their own words)
- the connecting role is a superuser, can bypass RLS, or can write to application tables
- the key supplied is not a public key
- the installed pgrls is not the reviewed version (0.57.1)
- a snapshot file's label does not match the target, is still the default label, or does not cover the target's schemas
- `--via-api` is used but the target declares no `project_ref`, or the value supplied is a project key (secret, service_role, publishable) rather than an account access token

Passwords and keys are taken from environment variables only. They do not
appear in reports, error messages or the process list.

## Reading the results

- `NOT_RUN` and `ERROR` mean the answer is not known yet. They do not mean safe.
- pgrls severities are general Postgres advice and must be read against the system's design. For example, a table with RLS enabled, no policies, and access only through functions gets SEC009 and SEC002 although that design is deliberate.
- "RLS not enabled" (SEC001, SEC032) from a file check can be wrong when the set of files is not the full history, for example when the file that creates a table is present and the file that enables RLS is not. Always confirm against the database.
- **Never run SQL that a tool suggests straight away.** Treat it as a draft for a person to review.
- Every report lists 11 items that need a manual check. How to do each is in `skills/supabase-web-care/references/manual-checklist.md`.

To switch off a rule or exempt an object after a decision has been made, write
a `pgrls.toml` and pass it with `--pgrls-config`, for example:

```toml
[lint.rules.SEC016]
allowlist = ["service_role"]   # service_role bypasses RLS by Supabase's design
```

## Installing the skill

| Platform | How |
|---|---|
| **Claude Code, Codex, Gemini CLI** | Copy the `skills/supabase-web-care` folder to `<repo>/.agents/skills/` (or `.claude/skills/`, `.gemini/skills/`). The `webcare` toolkit can be used on these platforms because they can run commands. |
| **ChatGPT (Skills menu)** | Zip the `skills/supabase-web-care` folder and upload it under Plugins → Skills → Create. |
| **ChatGPT Project, Gemini Gem** | Paste the contents of `CHAT-INSTRUCTIONS.md` into the instructions box. Only review of attached files is possible there. |

## Limits

- The credential scan looks at files on disk only, not at git history. A key that was committed and later removed is still in the history and must be rotated.
- The credential scan skips build output (`dist`, `build`, `.next`, `.nuxt`, `.svelte-kit`) unless given `--include-build`. Build the site and scan with that flag to see what the browser receives.
- A connection to a database host that is not loopback or private must be encrypted: `sslmode=require` is added when the connection string names none, and `disable`, `allow` and `prefer` are refused, because libpq falls back to plain text with them. For a hostname on a private network without TLS, use its IP address. `hostaddr` is refused, because it would send the connection somewhere other than the host the target declares. Against production, prefer `sslmode=verify-full` with the provider's root certificate, which also checks who answers.
- The anonymous-access probe has been tested against a stand-in server only, not against a real PostgREST. See the "not verified" list in `docs/OFFLINE_VM.md`.
- Security Advisor needs the internet. `--via-api --with-advisors` reads it; otherwise run it separately, through the Supabase MCP server or CLI.
- The function checks look at EXECUTE privileges and patterns in the code. They do not judge whether a function's body checks its caller correctly. A function listed in `expected_anon_functions` still needs someone to read its code.
- The log summary covers the last 24 hours only and counts requests; it cannot tell you whether a function that was open in the past was called before that window. The manual checklist describes how to look further back.
- The `webcare_auditor` role can reach whatever is granted to `PUBLIC`, like every role. The tool reports such objects and does not use them.

## Testing the toolkit

```bash
pip install --require-hashes -r requirements-dev.lock
python -m pytest tests
```

Tests that need a database run when `WEBCARE_TEST_ADMIN_DSN` points at a
Postgres on 127.0.0.1 with a superuser account. The suite creates and drops
its own scratch databases and changes the password of the `webcare_auditor`
role on that cluster. **Use a throwaway cluster that holds no real data.**

## Use it together with

- **pgrls** is the RLS analyser this toolkit calls. For a site whose browser code reads and writes tables directly, use pgrls itself as well: lint migrations in CI, and run `pgrls verify` against a staging database or a Supabase branch. Its probing mode inserts test rows inside a transaction it rolls back and needs an administrator role, so keep that mode off production.
- **Supabase Security Advisor** (dashboard, `supabase db advisors`, or the MCP `get_advisors` tool) is the platform's own check and sees things this toolkit does not. Run it every time.
- **Supabase's official agent skills**, `supabase` and `supabase-postgres-best-practices`. The skill here tells an agent to consult them and adds a working method and guard rails on top.

## Origin and licences of the parts

- **pgrls** (MIT): installed from PyPI at the pinned version. The files in the 0.57.1 wheel match the upstream `v0.57.1` tag file for file (checked 2026-11-22).
- **Supabase's official skills** (`supabase`, `supabase-postgres-best-practices`): this skill refers to them and does not copy their text.
- **database-sentinel**: the ideas of scanning a web project for leaked keys, probing with HEAD requests, and enforcing read-only in two layers come from it. Each was written again from scratch; none of its code is included, and its AGPL-licensed parts were not copied.
- **supabase-security-skill**: reviewed while designing the guard rails.

See [CREDITS.md](CREDITS.md) for the full list.
