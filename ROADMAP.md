# Roadmap

Status as of 22 November 2026. Each item says where it stands. "Verified" means
it has run against a real Supabase project, not only against the test suite.

## Done

| Version | What | Verified |
|---|---|---|
| 1.0–1.1 | Credential scan, pgrls runner, audit role, anonymous HEAD probe, report | Partly: the HEAD probe has not run against a real PostgREST |
| 1.2 | Who may call `SECURITY DEFINER` functions, from SQL files and from the catalog | Yes |
| 1.3–1.4 | Catalog snapshot; the Management API read-only route (`--via-api`) | Yes |
| 1.5 | Scheduled jobs (pg_cron) | Yes |
| 1.6 | Backups held by the platform (`--with-backups`) | Yes |
| 1.7 | 24-hour API log summary, counts only (`--with-logs`) | Yes |
| 1.8 | Storage buckets | Yes |
| 1.9 | Sign-in settings, reduced to an allowlist (`--with-auth-config`) | Yes |
| 1.10 | Baseline for file checks; CI examples | Locally; the example workflow has not run on GitHub Actions |
| 1.11 | Scheduled jobs a target expects (`expected_cron_jobs`) | Yes |
| 1.12 | Report in English or Thai (`--lang`) | Yes |
| 1.13–1.14.1 | Supabase's own security lints (`--with-advisors`); default privileges of new tables | 1.14.0 ran against a real project and showed the parser counted wrongly; fixed in 1.14.1, not yet re-run |
| 1.15 | Optional checks and report language switched on from the target file | Test suite only; the switch reuses checks that are verified |
| 1.16 | Comparing two environments (`inventory`, `compare`) | Statements ran on a real project; the whole command against the test database only |
| 1.17 | Declared table grants (`table_writes`, `expected_table_writes`); SARIF output (`--sarif`) | The table statement ran on a real project; SARIF has not been uploaded to GitHub yet |
| 1.18 | Fixes from an outside review: function overloads, TLS for database connections, password variables, build output, `pip install .` | Test suite; the changed catalog checks ran on a real project |
| 1.19 | Fixes from a second outside review: views and declared tables in `table_writes`, `hostaddr`, renamed functions, SARIF placement, release workflow | Test suite; the changed checks ran on a real project |
| 1.20 | Extension schemas the API roles may reach (pg_net, Vault, pg_cron) | Yes: found the pg_net grant on a real project |
| 1.21 | Focused runs (`--focus`, `--profile`) | Test suite, including a focused run against the test database |
| 1.22 | `--only`, `--group`, `--fail-groups` | Test suite |
| 1.23 | Database health (`db_health`) and Supabase's Performance Advisor (`--with-performance`) | The health statement ran on a real project; the Performance Advisor answer has not been read yet |
| 1.24 | Realtime, owner-rights views, unchecked schemas; Data API settings (`--with-data-api`) | The catalog statements ran on a real project; the PostgREST settings endpoint has not been called yet |
| 1.25 | `--parity` (changes since a saved inventory) and `--changed-since` (file checks only) | Test suite, including a parity run against the test database; the inventory statements ran on a real project in 1.16 |
| 1.26 | Storage upload-and-replace judged per bucket | Yes |
| 1.27 | SSL enforcement and network restrictions (`--with-platform`) | Test suite only; the endpoints have not been called against a real project |
| 1.28 | Thai explanation of every finding in Thai reports | Test suite |
| 1.29 | GitHub Action and pre-commit hooks | The action's script ran locally; not yet on GitHub Actions |
| 1.30 | "In short" summary on the first page of report.md; Thai lines for every pgrls rule | Test suite |
| 1.31 | `webcare init` and first-run steps in the skill | Test suite |
| 1.32 | A yes at the terminal before checking real data | Test suite |
| 1.33 | Stable report.json: `schema_version` and a published JSON Schema | Test suite validates real reports |
| 1.34 | Fixes from the third outside review: Realtime policies, materialized views, deleted migrations, parity group | The changed statements ran on a real project |
| 1.34.1 | pg_net advice says when a REVOKE cannot work | Found on a real project |
| 1.35 | Fixes from the fourth outside review: real-data question, Action inputs, In short order, report schema 1.1 | Tests run the Action's script |
| 1.36 | Edge Functions read from files: verify_jwt, service role without a caller check, any-origin CORS | Run on one real function's code; no deployed function was compared |
| 1.37 | Database health also covers connections, size, version support, extension updates and slow statements | The statement ran on a real project |
| 1.38 | Functions that take a user id without asking who is calling; policies open to every signed-in user; keys of six more services | Both checks ran on a real project, which changed them |
| 1.39 | Fixes from the fifth outside review: Edge Functions config, shared helpers and baseline keys; policies with no condition | The changed statements ran on a real project |
| 1.39.1 | Four edge cases from the review of 1.39.0 | The changed statements ran on a real project |
| 1.39.2 | Audit-role removal for a non-superuser administrator; `db_health` with statement statistics in a closed schema; column-grant count in `inventory` | Found on a local Supabase database (Postgres 17.12); fixed and tested on Postgres 16, not yet re-run on Supabase |
| 1.40.0 | SECURITY DEFINER functions in a schema visitors may not use are no longer reported as callable | The changed statement ran on a real project; tested on Postgres 16 |
| 1.41.0 | The audit role warns when it can read pg_net's queue; TRUNCATE and the other unused privileges of `authenticated` are reported; extensions in public are reported | Tested on Postgres 16 with stand-ins; MAINTAIN needs Postgres 17 |

## In progress

Nothing at the moment.

## Planned, not started

Nothing at the moment; the plan decided with the owner on 23 November 2026 is done (1.30–1.33).

1. **Unindexed foreign keys without the Management API.** The Performance Advisor
   (`--with-performance`) reports them, but a run over a direct connection alone does not
   (noted by the third review).
2. **Ready for first outside users** (agreed with the owner on 23 November 2026; after the
   checks against a real project through the Management API have passed):
   a five-minute start in the README that begins with the file checks and needs no key;
   sample reports in English and Thai from a made-up database; issue templates for a
   problem and for a suggestion.
3. **Declared extensions.** Let the target file say that pg_net is used on purpose, with a
   reason: the finding stays in the report as info and no longer fails a security gate,
   and returns to medium if schema `net` is served by the Data API (suggested by the
   focused review of 23 November 2026).

## Waiting on a decision

1. **Probing as a signed-in test user.** Policies that exist but restrict too
   little are a common cause of leaks, and only a signed-in request shows them.
   Signing in writes session rows, and may write an application's own audit
   rows, so this needs a design that the owner of each project accepts. Staging
   only.

## Not planned

- **Scanning a deployed site's JavaScript for keys.** The `bundle` mode of
  [supabase-security-scanner](https://github.com/AlexandreCavalcantee/supabase-security-scanner)
  does this well. Use it at a pinned commit, installed without install scripts.
  Its `probe` mode downloads one real row per readable table; do not point it at
  real data.
- **Other databases** (Firebase, Neon and so on), until someone asks.
- **Mapping to standards or laws.** The tool certifies nothing; see the README.

## Rules every change follows

- Read only. Never call a project's functions, never read rows of application tables.
- A check that talks to an API is not done until it has run against the real endpoint once.
- What has not been verified is listed in [docs/OFFLINE_VM.md](docs/OFFLINE_VM.md).
