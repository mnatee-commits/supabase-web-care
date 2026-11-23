# supabase-web-care

Read-only security and health checks for websites built on Supabase or
PostgreSQL, with a skill that tells an AI agent how to use them safely.

Full manual: [MANUAL.md](MANUAL.md) (English) · [README_TH.md](README_TH.md) (ไทย).

## Read this first

- **Tested against two real projects, both the author's.** Everything else was
  tested against local stand-ins. Expect rough edges on a project that is
  shaped differently, and try it on a staging project first.
- **Through the Management API route, RLS policies are not checked.** Most
  Supabase sites let the browser read and write tables directly and rely on
  RLS; for them the policy check is the one that matters most. It runs from
  SQL files or from a direct database connection (through pgrls), not through
  `--via-api`. On that route the report shows `rls_live` as `NOT_RUN`. Do not read the rest of that report as covering your tables. Adding `--with-advisors` brings in Supabase's own security lints, which include several RLS checks (RLS off, always-true policies); that narrows the gap but is not pgrls's policy analysis.
- **It certifies nothing.** The checks follow Supabase's own guidance. They
  are not a mapping to OWASP, to a privacy law, or to any health-data or
  industry standard, and a clean report is not evidence of compliance.
- **A clean report does not mean a site is secure.** The tool reports what it
  checked and marks everything it did not check as `NOT_RUN`. It does not
  replace a review by someone who knows the application.
- **It never writes, and never calls your functions.** Checks read the system
  catalog, counts and settings. Rows of application tables are not read.
- **The access token it can use is powerful.** A fine-grained Supabase token
  with only "Database Read" could also read logs, backups and the Auth
  configuration (which contains secrets) when this was tried. Scope it to one
  project, keep it short-lived, and revoke it when the run is over.

## What it checks

| Check | From |
|---|---|
| Credentials left in a source tree | files |
| RLS policies (through pgrls) | SQL files, or a database connection |
| Who may call `SECURITY DEFINER` functions, against a declared allowlist | SQL files, database, or Management API |
| Policy and default-privilege problems pgrls does not cover | database or Management API |
| Extension schemas the API roles may reach: pg_net (outbound HTTP), Vault, pg_cron | database or Management API |
| Storage buckets: public access, anonymous writes, upload limits | Management API |
| Tables `anon` and `authenticated` may write to, against a declared list | database or Management API |
| Scheduled jobs (pg_cron) that failed or stopped | Management API |
| Whether the platform holds a backup | Management API, opt-in |
| 24-hour API log summary, counts only | Management API, opt-in |
| Sign-in settings, reduced to an allowlist so no secret is kept | Management API, opt-in |
| Supabase's own security lints (Security Advisor) | Management API, opt-in |
| What an anonymous visitor can read (HEAD requests only) | Data API |
| What differs between two environments (`inventory`, then `compare`) | database or Management API |

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.lock   # every file checked against a hash
# or: pip install .   then run `webcare` instead of `python -m webcare`
python -m webcare check --repo <web project> --migrations <migrations folder>
```

Live checks need a target declared in `webcare.toml`; copy
`webcare.example.toml`. Credentials come from environment variables only.

To check migrations on every pull request, see [docs/CI.md](docs/CI.md) and
the example workflow in `docs/examples/`. `--sarif` also writes `report.sarif`, so
code scanning can show findings on the lines of a pull request. What has and has not been verified
against a real system is listed at the end of [docs/OFFLINE_VM.md](docs/OFFLINE_VM.md).

`--focus functions,tables` (or any of `secrets`, `storage`, `extensions`, `auth`,
`advisors`, `health`) checks only those areas; `--profile quick` checks files only.
`--only table_writes` names exact checks, and `--fail-groups security` keeps health
findings from failing CI. What is left out is listed as `NOT_RUN`.

`report.md` is written in English by default; pass `--lang th` (or set `WEBCARE_LANG=th`) for Thai.

What is done, in progress and planned is in [ROADMAP.md](ROADMAP.md).

Each version is published as a [GitHub Release](https://github.com/mnatee-commits/supabase-web-care/releases);
watch the repository for releases to hear about new ones. Pin a release's commit,
not a branch, in CI.

## Use it together with

This toolkit is a thin layer. It is meant to sit beside these, not replace them.

- **[pgrls](https://github.com/pgrls/pgrls)** is the RLS analyser this toolkit
  calls. For a site whose browser code reads and writes tables directly, use
  pgrls itself as well: lint migrations in CI, and run `pgrls verify` against
  a staging database or a Supabase branch. Its probing mode inserts test rows
  inside a transaction it rolls back and needs an administrator role, so keep
  that mode off production.
- **Supabase Security Advisor** (dashboard, `supabase db advisors`, or the MCP
  `get_advisors` tool) is the platform's own check and sees things this
  toolkit does not. `--with-advisors` reads it through the Management API;
  without that route the report lists it as not run, so run it yourself.
- **Supabase's official agent skills**, `supabase` and
  `supabase-postgres-best-practices`. The skill in this repository tells an
  agent to consult them and adds a working method and guard rails on top.

## Licence and credits

MIT, see [LICENSE](LICENSE). To report a security problem, see
[SECURITY.md](SECURITY.md).

- **pgrls** (MIT) does the RLS analysis. It is installed at a pinned version
  and run unmodified.
- **[database-sentinel](https://github.com/Farenhytee/database-sentinel)**
  is where three ideas here come from, each written again from scratch:
  scanning a web project for leaked keys, probing anonymous access with HEAD
  requests so no row is downloaded, and enforcing read-only in two layers.
  None of its code is included.
- **Supabase's agent skills** guided the working method in the skill.
- **[supabase-security-skill](https://github.com/Perufitlife/supabase-security-skill)**
  was reviewed while designing the guard rails.

Details are in [CREDITS.md](CREDITS.md).
