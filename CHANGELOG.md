# Changelog

Versions before 1.10 were developed inside another repository; this file
summarises them.

## 1.12.0
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
