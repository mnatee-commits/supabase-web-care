# Security

## Reporting a problem

If you find a way this toolkit could write to a database, read rows of an
application table, call a project's functions, leak a credential it was given,
or report a system as clean when it is not, please write to
**prinnmesz@gmail.com** before opening a public issue. Include the version
(`python -m webcare --version`) and the smallest input that shows it.

Please do not send real credentials, real project references, or data from a
real system. A description and a synthetic example are enough.

## What the toolkit promises

- Every statement it sends to a database is a single SELECT that it built
  itself; a guard refuses anything else before it leaves.
- Through the Supabase Management API it uses the read-only query endpoint,
  and eight GET endpoints (backups, logs, sign-in settings, Data API settings, SSL
  enforcement, network restrictions, security and performance advisors)
  only when asked for: by their own `--with-*` flag, by the target's `checks` list,
  by a `--focus`, `--group` or `--only` that names their area or check, or by
  `--profile full`. A run that asks for none of these calls none of them.
- It never calls a project's RPC functions and never sends INSERT, PATCH or
  DELETE to a Data API.
- Credentials come from environment variables and are not written to reports.

If you see it break one of these, that is a security bug.

## What it does not promise

A report with no findings does not mean a site is secure. The checks cover
what `README.md` lists and nothing else, and they have been run against two
real projects only.
