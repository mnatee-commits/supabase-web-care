# report.json: a format to build on

`webcare check` writes `report.json` next to `report.md`. Dashboards, a point-and-click
interface, or another team's tooling can read it instead of the Markdown.

The shape is published in [`schema/report.schema.json`](../schema/report.schema.json)
(JSON Schema, draft 2020-12), and every report carries `schema_version`.

## The promise

Within `schema_version` 1.x:

- fields are only ever **added**; none is removed, renamed or given another type;
- a check's `status` is always one of `PASS`, `FINDINGS`, `NOT_RUN`, `ERROR`;
- a finding's `severity` is always one of `high`, `medium`, `low`, `info`.

A change that breaks any of these raises the major number to 2. The test suite validates
real reports against the schema on every change.

## What to read

| Field | Meaning |
|---|---|
| `summary.findings` | how many findings of each severity |
| `summary.first` | the findings to act on first, in order |
| `summary.not_checked` | every check that did not run or failed, with its reason |
| `checks[]` | each check: `id`, `title`, `status`, `evidence`, `reason`, `findings[]`, `notes[]` |
| `manual[]` | the items no script can settle; always `NOT_RUN` |
| `scope` | set when only part of the checks ran (`--focus`, `--only`, `--profile`, `--changed-since`) |

## Rules for anything built on it

- Show `NOT_RUN` and `ERROR` as "not known", never as passed. A page with no finding and
  checks in `summary.not_checked` has not shown that the site is safe.
- When `scope` is set, say that only part of the site was checked.
- `check.id` and `finding.rule` are stable names for code; `title` and `message` are for
  people and may be reworded.
- `report.json` holds names of tables, functions, policies and the like, never a data row,
  key or password. Store and share it as you would the report itself.
