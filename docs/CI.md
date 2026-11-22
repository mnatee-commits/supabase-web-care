# CI: check migrations on every change

For the repository that holds your site's migrations, when you want GitHub
Actions to check them automatically. This check reads files only. It does not
connect to a database and needs no Supabase key.

Thai edition: [CI_TH.md](CI_TH.md).

**Status:** the example workflow has not yet been run on GitHub Actions. The
commands inside it were tested locally.

## Steps

1. **Create a baseline once**, locally, from the migrations you already have.

   ```bash
   python -m webcare check --skip secrets --migrations supabase/migrations \
     --write-baseline webcare-baseline.json
   ```

   Read this first report to the end. A finding that is still a real problem
   in the database should be fixed, not recorded and forgotten. Then commit
   `webcare-baseline.json`.

2. **Copy** `docs/examples/webcare-migrations.yml` to `.github/workflows/` in
   the site's repository and edit the three values marked in the file.

3. **While this toolkit's repository is private**, the site's repository needs
   read access to it. Create a read-only deploy key on this repository and
   store its private half as a secret named `WEBCARE_DEPLOY_KEY` in the site's
   repository. Once this repository is public, delete the secret and the
   `ssh-key` line.

## What the workflow does

- Checks `SECURITY DEFINER` function privileges and RLS policies from all migration files, in file-name order
- Counts findings that are in the baseline without failing on them
- Fails on a new finding of high severity (change with `--fail-on`)
- Attaches `report.md` to the run as an artifact

## Limits

- The result depends on file order. If file names do not sort in the order the migrations were applied, name files one by one with `--sql-file`.
- Files whose names start with `ROLLBACK_` are skipped.
- A file check cannot see what was changed directly in the database without a migration. Pair it with a periodic check against the live system.
- A baseline entry names a rule, an object and a file, not a line number. A new finding of the same rule on the same object in the same file therefore counts as already covered.
- Always pin the toolkit to a commit you have reviewed. Never use a branch name.
