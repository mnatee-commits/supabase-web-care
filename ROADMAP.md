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

## In progress

Nothing at the moment.

## Planned, not started

Decided with the owner on 23 November 2026: make the tool easy for beginners who use it
through an AI assistant, without making it less thorough for specialists.

1. **A stable report.json for others to build on.** A `schema_version` field, a published
   JSON Schema, and a promise not to break the shape within a major version, so others
   can build dashboards or a point-and-click interface on top of the tool.

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
