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

## In progress

1. **Optional checks switched on from the target file.** Today every optional
   check needs its own flag. A target should be able to say which optional checks
   it wants, so one short command runs everything.
2. **Comparing two targets.** Save an inventory of each target (migration
   history, RLS state, table and column grants, default privileges, scheduled
   jobs, functions callable without signing in), then report what differs. Two
   environments that drift apart was the most common real finding while this
   tool was being built: a backup script pointing at the wrong database, jobs
   that existed in one environment only, a column restriction applied to one
   environment and not the other.

## Planned, not started

3. **Declared table grants.** Let a target state which tables each API role may
   write to, so that write privileges left over from defaults are reported.
4. **SARIF output**, so CI can show findings on the lines of a pull request.
5. **Platform settings** such as SSL enforcement and network restrictions. The
   Management API endpoints for these have not been checked yet.
6. **Thai text for each finding's detail.** Headings are translated already.

## Waiting on a decision

7. **Probing as a signed-in test user.** Policies that exist but restrict too
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
