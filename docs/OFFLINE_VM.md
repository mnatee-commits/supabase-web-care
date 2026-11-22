# Running on a machine cut off from the internet

For whoever runs the toolkit on a private machine (a VM) that holds both a
stand-in database and a real one, whether a person or an AI agent. Follow the
order: each step is a condition for the next.

Thai edition: [OFFLINE_VM_TH.md](OFFLINE_VM_TH.md).

The toolkit never reaches the internet on its own at any step, except for the
anonymous-access probe, which contacts only the URL declared in `webcare.toml`.

## 1. Prepare the install bundle (while still online)

The wheels of `pgrls`, `z3-solver`, `pglast` and `psycopg-binary` depend on the
operating system, CPU type and Python version, so they have to be downloaded on
a machine that matches the VM. The easiest way is to run this on the VM itself
before cutting the network.

```bash
cd supabase-web-care
scripts/make_offline_bundle.sh        # downloads wheels into wheelhouse/ and checks every hash
```

Python 3.11 or later is required. The script downloads only the packages and
versions named in `requirements-dev.lock` and stops if a hash does not match.

## 2. Cut the network, then install

```bash
scripts/install_offline.sh            # creates .venv and installs from wheelhouse/ only
. .venv/bin/activate
python -m webcare --version
pgrls --version                        # must print 0.57.1
```

## 3. Test the toolkit itself

```bash
python -m pytest tests
```

Without `WEBCARE_TEST_ADMIN_DSN` the tests that need a database are skipped.
The rest should all pass.

The database tests create the `webcare_auditor` role, change its password, and
disable its login when they finish. **Never point this variable at the same
Postgres that holds the real database.** To run this part, use a separate
Postgres set up for experiments only.

## 4. Check from files first

```bash
python -m webcare check --repo <web project folder> --migrations <migrations folder>
```

This step connects to no database. Results are in `webcare-output/report.md`.
If the current folder is not writable, pass `--out-dir <writable folder>`, or
`--json` to print the report to the screen.

Good to know at this step:

- Use `webcare check` rather than calling `pgrls` directly. It skips `ROLLBACK_*` files, drops known false results for schemas that Supabase manages, and scans for credentials in the same run.
- If the migration files are not the full history, "RLS not enabled" (SEC001, SEC032) can be reported wrongly. A trial on 22 November 2026 with 37 files hit this for three tables that the staging database did have RLS on. Confirm against the database every time.
- Twenty-five pgrls rules about `SECURITY DEFINER` functions, views and indexes do not run at this step. Continue with step 5.
- `SECURITY DEFINER` function privileges are checked from files by the toolkit itself at this step (the "SECURITY DEFINER functions from SQL files" row). The result depends on file order; if file names do not sort in the order they were applied, name files one by one with `--sql-file`.

## 5. The stand-in database

1. In the stand-in database, run `sql/auditor-role.sql` as an administrator, then enable login and set a password as in step 2 of that file (use `\password` in psql).
2. Copy `webcare.example.toml` to `webcare.toml` and declare a target. Write `data = "synthetic"` only when that database holds no real data at all.
3. Run:

```bash
export WEBCARE_DATABASE_URL='postgresql://webcare_auditor:<password>@127.0.0.1:<port>/<stand-in database>'
python -m webcare preflight --target sim
python -m webcare check --target sim --repo <code folder> --migrations <migrations folder>
```

The report has a row "SECURITY DEFINER functions callable without signing in".
On the first run it lists every open function at medium. Read each one's code,
then list the ones meant to be open in `expected_anon_functions` for the target
in `webcare.toml`. The next run should be PASS, and any function opened outside
that list shows as high.

A correct `preflight` result is `superuser=False`, `bypassrls=False`,
`writable tables=0`, and a last line starting with `ok:`. If
`readable relations` is above 0, some table is granted to `PUBLIC`, which
should be recorded as a finding.

If the VM runs a local Supabase (with PostgREST), add
`rest = "http://127.0.0.1:<port>"` to the target, set `WEBCARE_ANON_KEY` to a
public key, and run `check` again. The anonymous-access probe then runs too.

### When the VM cannot reach Postgres

If `preflight` ends in a timeout both directly and through the pooler, the
VM's network lets only web connections out. Do not try other ports. Use a
catalog snapshot instead. There are two routes.

**Route 1: the tool fetches it through the Management API**

1. Add `project_ref = "<project reference>"` to the target in `webcare.toml`.
2. Create a fine-grained access token for that project with Database Read only and a short life.
3. Run:

```bash
export WEBCARE_ACCESS_TOKEN='<token>'
python -m webcare check --target <target name> --via-api --skip secrets --skip static
unset WEBCARE_ACCESS_TOKEN
```

The tool sends up to five single SELECT statements to the project's read-only
endpoint. HTTP 403 means the token lacks Database Read for that project.
Revoke the token when you are done.

**Route 2: an administrator runs the statement and hands over a file**

1. On the VM: `python -m webcare snapshot-sql --target <target name> > snapshot.sql`
2. The administrator runs `snapshot.sql` in that project's SQL Editor (check the project reference in the URL first) and saves the whole JSON result to a file.
3. On the VM: `python -m webcare check --snapshot <file> --target <target name> --skip secrets --skip static`

Neither route needs the role or `WEBCARE_DATABASE_URL`. The "RLS policies from
the live catalog (pgrls)" row is `NOT_RUN` because pgrls needs a connection.
A snapshot file holds names and yes/no facts only; store it as you would a
report.

## 6. The real database (needs approval first)

Do this step only after the system's owner has approved it in their own words.

1. Declare a separate target with `data = "real"`, even if the database is on the local machine.
2. Create the `webcare_auditor` role in that database as in step 5.
3. Run with `--owner-approved`:

```bash
export WEBCARE_DATABASE_URL='postgresql://webcare_auditor:<password>@127.0.0.1:<port>/<real database>'
python -m webcare preflight --target real --owner-approved
python -m webcare check --target real --owner-approved --skip secrets --skip static
```

The tool reads the system catalog only (policies, privileges, function
definitions). The `webcare_auditor` role has no SELECT on any table, so it
cannot read a data row even if someone tries to make it. Never use
`--allow-privileged-role` against a real database; the tool refuses anyway.

## 7. Sending results back

`report.md` and `report.json` hold names of schemas, tables, policies and
functions. They hold no data row, password or key. Read the files before
passing them on, every time, and store them under your project's rules. The
`webcare-output/` folder and `webcare.toml` are already kept out of git.

What to report back:

- the result of `python -m pytest tests` (passed, skipped, failed)
- the `preflight` result for each target
- the summary table from each target's `report.md`
- which items under "Not verified" below you tested, and what happened

## 8. Clean up

```sql
alter role webcare_auditor nologin;      -- disable login when the check is over
```

If the role will not be used again, run `sql/auditor-role-drop.sql` in every
database where it was created, and clear `WEBCARE_DATABASE_URL` and
`WEBCARE_ANON_KEY` from the shell.

## Not verified

"The author's staging project" below is a real Supabase project holding
synthetic data. Dates are 22 November 2026 unless stated.

| Topic | Status | How to verify |
|---|---|---|
| Reading a real PostgREST's `Content-Range` (`0-0/*` = rows visible, `*/*` = none) | Not tested. Tested against a stand-in server that answers as the PostgREST documentation describes. | Run step 5 against a local Supabase and compare with tables known to be readable and unreadable by anon |
| Sending a publishable key (`sb_publishable_…`) in the `apikey` header alone | Not tested | Run step 5 with a publishable key |
| `check --via-api` against the real Management API | Passed on the author's staging project with version 1.4, using a fine-grained token with Database Read for that project only. It found the 19 functions callable without signing in, matching the declared list. A token without that permission got HTTP 403 and the tool stopped and said why. | Nothing further |
| Scheduled jobs (`health_cron`) | Passed on the author's staging project through the Management API with version 1.5.1 (pg_cron 1.6.4): all 3 jobs seen, no failed run, matching a direct read of the database. A job that actually failed was tested against a stand-in only. `expected_cron_jobs` passed on the same project with version 1.11.1: the three real jobs were accepted, and a deliberately wrong name produced exactly one medium finding. | Nothing further |
| Security Advisor lints (`advisors`, `--with-advisors`) | Not tested against the real endpoint. The answer's shape was taken from the Supabase reference and from what the Supabase MCP `get_advisors` tool returned for the author's staging project (4 kinds of lint, one of them naming 328 objects). The parser accepts the wrapper variants, but the endpoint itself has not been called by this tool. The token permission `advisors_read` is as documented, not tried. | Run `check --target <name> --via-api --with-advisors` and compare with the Advisor page of the dashboard |
| Backups (`health_backups`, `--with-backups`) | Passed on the author's staging project with version 1.6.0: HTTP 200 and a low "no completed backup" finding. On a second real project holding real data the same finding was high, as designed. A token created with Database Read alone could read the backup list, although Supabase's reference names `backups_read`. A project that does have backups was tested with made-up data only. | Run against a project with backups and compare dates with Supabase's Backups page |
| Log summary (`health_logs`, `--with-logs`) | Passed on the author's staging project with version 1.7.0: 3,411 requests counted in 24 hours, no server error, no function outside the list called without signing in. A token created with Database Read alone could read the logs, although the reference names `analytics_logs_read`. Assume such a token can read logs, which contain users' IP addresses, and revoke it right after use. | Nothing further |
| Storage (`storage_buckets`) | Passed through the Management API with version 1.8.0 on two real projects: 2 buckets each, all private, nothing to report. Public buckets and policies open to anonymous visitors were tested with made-up data only. | Run against a project with a public bucket and compare with Supabase's Storage page |
| Sign-in settings (`auth_config`, `--with-auth-config`) | Passed on the author's staging project with version 1.9.0: every allowlisted setting present, names as documented, no secret in the report. A token created with Database Read alone could read this endpoint, although the reference names `auth_config_read`. **Assume a Database Read token can read the sign-in system's secrets** (mail password, OAuth and hook secrets). | Nothing further |
| Baseline (`--write-baseline`, `--baseline`) and the example CI workflow | Tested locally against 14 real migration files (60 findings recorded, next run passed). The example workflow has not run on GitHub Actions. | Follow `docs/CI.md` in a site's repository |
| Connecting through Supabase's pooler (Supavisor) | Not tested. The VM used on that day could not reach Postgres directly or through the pooler (network timeout). | Test from a machine that can reach Postgres, with a session pooler connection string |
| `sql/auditor-role.sql` on a real Supabase project, where the administrator is not a superuser | The role was created without error on the author's staging project (Postgres 17.11). Logging in as that role has not been tested, because the VM could not reach Postgres. | Run `preflight` from a machine that can reach Postgres |
| Catalog snapshot (`snapshot-sql`, `check --snapshot`) on a real Supabase project | The statement ran on the author's staging project (Postgres 17.11) and found the 19 functions callable without signing in, matching Security Advisor's lint 0028. Saving the SQL Editor's result to a file and feeding it to the tool has not been tested. | Follow "When the VM cannot reach Postgres" |
| Postgres versions other than 16 | The 1.1 test suite passed on Postgres 17.12 on the VM. Checks added later were tested on 16, and in CI on 16. | Run `python -m pytest tests` again on the VM |
