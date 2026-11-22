"""Site health: scheduled jobs (pg_cron) that failed or stopped running.

Two read-only statements. The first asks whether pg_cron is installed and
whether the connected role is able to see every job; it cannot fail on a
database without pg_cron. Only when it says yes is the second one sent.

What is read: job names, schedules, whether a job is active, and counts and
times of its runs. What is never read: the command a job runs and the message
a run returned. Commands often carry request headers with keys, and messages
can quote rows.

pg_cron protects its tables with row-level security, so a role sees only its
own jobs unless it has BYPASSRLS. The audit role has no such attribute by
design; through a direct connection this check therefore reports NOT_RUN and
says why. The Management API read-only route runs as a role that does see
every job.
"""

from __future__ import annotations

import json
from typing import Callable, Sequence

from . import live
from .model import ERROR, NOT_RUN, CheckResult, Finding

PROBE_FORMAT = "webcare-health-probe/1"
FORMAT = "webcare-health/1"
TITLE = "Scheduled jobs (pg_cron) that failed or stopped running"
DEFAULT_WINDOW_DAYS = 7
MAX_WINDOW_DAYS = 90
MAX_JOBS = 500
SOURCE = "health"

# Looked up through pg_class, not to_regclass: naming a schema the role may not
# use raises an error, and the probe must answer on every database.
def build_probe(schema: str, tables: tuple[str, ...]) -> str:
    """A SELECT saying whether `schema`.`tables` exist and whether this role sees every row."""
    names = ", ".join(f"'{table}'" for table in tables)
    return f"""with wanted as (
  select c.oid, c.relrowsecurity
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
   where n.nspname = '{schema}' and c.relkind in ('r', 'p') and c.relname in ({names})
)
select jsonb_build_object(
  'format', '{PROBE_FORMAT}',
  'role', current_user::text,
  'installed', (select count(*) = {len(tables)} from wanted),
  'readable', coalesce((
    select pg_catalog.has_schema_privilege(n.oid, 'USAGE') from pg_catalog.pg_namespace n where n.nspname = '{schema}'
  ), false) and coalesce((select bool_and(pg_catalog.has_table_privilege(t.oid, 'SELECT')) from wanted t), false),
  'row_security', coalesce((select bool_or(t.relrowsecurity) from wanted t), false),
  'sees_every_row', coalesce((
    select r.rolsuper or r.rolbypassrls from pg_catalog.pg_roles r where r.rolname = current_user
  ), false)
) as probe"""


PROBE_SQL = build_probe("cron", ("job", "job_run_details"))


def build_sql(window_days: int = DEFAULT_WINDOW_DAYS) -> str:
    """One SELECT returning every job with its run counts as a single JSON value."""
    days = int(window_days)
    if not 1 <= days <= MAX_WINDOW_DAYS:
        raise ValueError(f"the window must be between 1 and {MAX_WINDOW_DAYS} days")
    return f"""select jsonb_build_object(
  'format', '{FORMAT}',
  'taken_at', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
  'window_days', {days},
  'jobs', coalesce((
    select jsonb_agg(to_jsonb(q)) from (
      select j.jobid as job_id,
             coalesce(j.jobname, 'job ' || j.jobid)::text as job_name,
             j.schedule::text as schedule,
             j.active as active,
             count(d.runid) as runs,
             count(d.runid) filter (where d.status = 'failed') as failed,
             to_char(max(d.start_time) at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as last_start,
             (select f.status::text from cron.job_run_details f
               where f.jobid = j.jobid and f.status in ('succeeded', 'failed')
               order by f.start_time desc nulls last, f.runid desc limit 1) as last_outcome
        from cron.job j
        left join cron.job_run_details d
          on d.jobid = j.jobid and d.start_time > now() - interval '{days} days'
       group by j.jobid, j.jobname, j.schedule, j.active
       order by j.jobid
       limit {MAX_JOBS}
    ) q
  ), '[]'::jsonb)
) as health"""


def unwrap(data, key: str, wanted_format: str):
    """Accept the wrappers drivers and APIs put around a single JSON value."""
    for _ in range(4):
        if isinstance(data, (list, tuple)) and len(data) == 1:
            data = data[0]
        elif isinstance(data, dict) and key in data and "format" not in data:
            data = data[key]
        elif isinstance(data, str):
            try:
                data = json.loads(data)
            except ValueError:
                break
        else:
            break
    if not isinstance(data, dict) or data.get("format") != wanted_format:
        return None
    return data


def why_not(probe: dict) -> str:
    """Empty when the jobs can be read in full; otherwise the reason they cannot."""
    if not probe.get("installed"):
        return "pg_cron is not installed in this database, so there are no scheduled jobs to check"
    role = probe.get("role", "the connected role")
    if not probe.get("readable"):
        return f"role {role} may not read the pg_cron tables"
    if probe.get("row_security") and not probe.get("sees_every_row"):
        return (
            f"pg_cron shows a role only its own jobs, and role {role} owns none it can vouch "
            "for; an empty answer would not mean that no job failed. Use the Management API "
            "route (--via-api), or read cron.job_run_details as the role that owns the jobs."
        )
    return ""


def _missing(result: CheckResult, names: Sequence[str], present: set[str], why: str) -> None:
    for name in names:
        if name not in present:
            result.findings.append(
                Finding(
                    SOURCE, "expected_cron_job_missing", "medium", f"cron job {name!r}",
                    f"listed in expected_cron_jobs, but {why}; whatever it was meant to do "
                    "is not happening",
                )
            )


def judge(result: CheckResult, report: dict, expected_jobs: Sequence[str] = ()) -> CheckResult:
    jobs = [job for job in report.get("jobs", []) if isinstance(job, dict)]
    days = report.get("window_days", DEFAULT_WINDOW_DAYS)
    _missing(
        result, expected_jobs, {str(job.get("job_name")) for job in jobs if job.get("active")},
        "no active job with this name is scheduled",
    )

    def add(rule: str, severity: str, job: dict, message: str) -> None:
        result.findings.append(
            Finding(SOURCE, rule, severity, f"cron job {job.get('job_name')!r}", message)
        )

    for job in jobs:
        runs, failed = int(job.get("runs") or 0), int(job.get("failed") or 0)
        schedule = job.get("schedule")
        if not job.get("active"):
            add("cron_job_inactive", "info", job, f"the job is switched off (schedule {schedule})")
            continue
        if job.get("last_outcome") == "failed":
            add(
                "cron_job_last_run_failed", "medium", job,
                f"the most recent finished run failed; {failed} of {runs} runs failed in the "
                f"last {days} days (schedule {schedule}, last start {job.get('last_start')})",
            )
        elif failed:
            add(
                "cron_job_failed_in_window", "low", job,
                f"{failed} of {runs} runs failed in the last {days} days; the most recent "
                f"finished run succeeded (schedule {schedule})",
            )
        elif runs == 0:
            add(
                "cron_job_no_recent_run", "low", job,
                f"the job is active but no run started in the last {days} days (schedule "
                f"{schedule}); expected only for a schedule rarer than that",
            )
    result.notes.append(
        f"{len(jobs)} scheduled jobs examined over the last {days} days, as of "
        f"{report.get('taken_at', 'an unknown time')}; job commands and run messages were not read"
    )
    if len(jobs) >= MAX_JOBS:
        result.notes.append(f"only the first {MAX_JOBS} jobs were examined")
    return result.finish()


def run(
    ask: Callable[[str], object], evidence: str, window_days: int = DEFAULT_WINDOW_DAYS,
    expected_jobs: Sequence[str] = (),
) -> CheckResult:
    """Run the check through `ask`, which sends one SELECT and returns its result."""
    result = CheckResult(id="health_cron", title=TITLE, evidence=evidence)
    statement = build_sql(window_days)
    for sql in (PROBE_SQL, statement):
        live.assert_single_select(sql)  # the only statements this check may send

    probe = unwrap(ask(PROBE_SQL), "probe", PROBE_FORMAT)
    if probe is None:
        result.status, result.reason = ERROR, "the answer to the pg_cron probe was not understood"
        return result
    reason = why_not(probe)
    if reason and expected_jobs and not probe.get("installed"):
        _missing(result, expected_jobs, set(), "pg_cron is not installed in this database")
        return result.finish()
    if reason:
        result.status, result.reason = NOT_RUN, reason
        return result
    report = unwrap(ask(statement), "health", FORMAT)
    if report is None or not isinstance(report.get("jobs"), list):
        result.status, result.reason = ERROR, "the answer to the scheduled-jobs query was not understood"
        return result
    return judge(result, report, expected_jobs)


def run_on_connection(
    connection, evidence: str, window_days: int = DEFAULT_WINDOW_DAYS, expected_jobs: Sequence[str] = ()
) -> CheckResult:
    def ask(sql: str):
        try:
            return connection.execute(sql).fetchone()
        finally:
            connection.rollback()  # nothing is held open between statements

    try:
        return run(ask, evidence, window_days, expected_jobs)
    except Exception as error:  # a failed query must not take the other checks down
        failed = CheckResult(id="health_cron", title=TITLE, evidence=evidence, status=ERROR)
        failed.reason = f"the scheduled-jobs query failed ({type(error).__name__})"
        return failed
