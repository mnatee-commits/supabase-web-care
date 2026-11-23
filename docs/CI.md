# CI: check migrations on every change

For the repository that holds your site's migrations, when you want GitHub
Actions to check them automatically. This check reads files only. It does not
connect to a database and needs no Supabase key.

Thai edition: [CI_TH.md](CI_TH.md).

**Status:** the example workflow has not yet been run on GitHub Actions. The
commands inside it were tested locally.

## The shortest way: the action

In the site's repository, `.github/workflows/webcare.yml`:

```yaml
name: webcare
on: pull_request
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
          fetch-depth: 0               # only needed for changed-since
      - uses: mnatee-commits/supabase-web-care@<full commit hash of a release>
        with:
          migrations: supabase/migrations
          changed-since: origin/${{ github.base_ref }}   # optional
          fail-on: high
          lang: th                     # optional
```

Pin the action to the full commit hash of a release you have read, never to a branch or
tag name. The action checks files only (`--skip live --skip probe`) and contacts no
database. Its inputs reach the script as environment variables and are checked before
use, so no input becomes part of a shell command. For the longer, hand-written workflow,
read on.

## pre-commit

With [pre-commit](https://pre-commit.com), add to `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/mnatee-commits/supabase-web-care
  rev: v1.29.0
  hooks:
    - id: webcare-secrets
    - id: webcare-migrations
      args: [--migrations, supabase/migrations]
```

`webcare-secrets` scans the files being committed; `webcare-migrations` runs the SQL
checks whenever a `.sql` file is committed. Both read files only.

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

3. **Pin a release.** Use the full commit hash of a release you have read
   (see the repository's Releases page), never a branch name. This repository
   is public, so no key is needed to fetch it.

## What the workflow does

- Checks `SECURITY DEFINER` function privileges and RLS policies from all migration files, in file-name order
- Counts findings that are in the baseline without failing on them
- Fails on a new finding of high severity (change with `--fail-on`)
- Attaches `report.md` to the run as an artifact

## Only what a pull request changed

Add `--changed-since origin/main` (fetch the base branch first, for example with
`fetch-depth: 0` on `actions/checkout`). The credential scan then reads only the files the
pull request changed, and the SQL checks run only when a SQL file changed. The report's
scope line says so.

## Findings on the lines of a pull request

Add `--sarif` to the check, and the tool also writes `webcare-output/report.sarif`.
The commented step at the end of the example workflow uploads it, so GitHub shows
each finding on the line of the migration that caused it. This needs a public
repository, or GitHub Code Security on a private one, and `security-events: write`.

The file holds only findings tied to a file line: credentials, function privileges
replayed from SQL files, and pgrls findings, placed on the first statement in the
given files that creates the table, view, function or policy (a text search, not a
parse). Everything else stays in `report.md`, and the file records how many
findings it left out. An empty SARIF file is not a clean report.

## Limits

- The result depends on file order. If file names do not sort in the order the migrations were applied, name files one by one with `--sql-file`.
- Files whose names start with `ROLLBACK_` are skipped.
- A file check cannot see what was changed directly in the database without a migration. Pair it with a periodic check against the live system.
- A baseline entry names a rule, an object and a file, not a line number. A new finding of the same rule on the same object in the same file therefore counts as already covered.
- Always pin the toolkit to a commit you have reviewed. Never use a branch name.
