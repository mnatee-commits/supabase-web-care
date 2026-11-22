# Changelog

Versions before 1.10 were developed inside another repository; this file
summarises them.

## 1.17.0
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
