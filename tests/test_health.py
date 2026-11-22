import json

import pytest

from webcare import health, live
from webcare.model import CheckResult


def job(**fields):
    base = dict(job_id=1, job_name="nightly", schedule="0 18 * * *", active=True, runs=7, failed=0,
                last_start="2026-01-01T18:00:00Z", last_outcome="succeeded")
    base.update(fields)
    return base


def judged(*jobs):
    report = {"format": health.FORMAT, "taken_at": "2026-01-02T00:00:00Z", "window_days": 7, "jobs": list(jobs)}
    return health.judge(CheckResult(id="health_cron", title=health.TITLE), report)


def rules(result):
    return {(finding.rule, finding.severity) for finding in result.findings}


def test_both_statements_are_single_selects_that_never_name_commands_or_messages():
    for sql in (health.PROBE_SQL, health.build_sql(), health.build_sql(90)):
        live.assert_single_select(sql)
        assert "command" not in sql and "return_message" not in sql
    for days in (0, 91):
        with pytest.raises(ValueError):
            health.build_sql(days)


def test_healthy_jobs_pass_and_no_jobs_pass():
    assert judged(job()).status == "PASS"
    result = judged()
    assert result.status == "PASS" and "0 scheduled jobs" in result.notes[0]


def test_each_kind_of_trouble_has_its_own_rule():
    assert rules(judged(job(last_outcome="failed", failed=3))) == {("cron_job_last_run_failed", "medium")}
    assert rules(judged(job(failed=1))) == {("cron_job_failed_in_window", "low")}
    assert rules(judged(job(runs=0, last_start=None, last_outcome="succeeded"))) == {("cron_job_no_recent_run", "low")}
    off = judged(job(active=False, last_outcome="failed", failed=2))
    assert rules(off) == {("cron_job_inactive", "info")} and off.status == "PASS"


@pytest.mark.parametrize("probe, text", [
    (dict(installed=False), "not installed"),
    (dict(installed=True, readable=False, role="r"), "may not read"),
    (dict(installed=True, readable=True, row_security=True, sees_every_row=False, role="r"), "only its own jobs"),
])
def test_a_role_that_cannot_see_every_job_is_not_run_and_sends_no_job_query(probe, text):
    asked = []

    def ask(sql):
        asked.append(sql)
        return [{"probe": dict(probe, format=health.PROBE_FORMAT)}]

    result = health.run(ask, "evidence")
    assert result.status == "NOT_RUN" and text in result.reason and len(asked) == 1


def test_answers_that_are_not_understood_are_errors_not_passes():
    assert health.run(lambda sql: [{"unexpected": 1}], "e").status == "ERROR"
    probe = {"format": health.PROBE_FORMAT, "installed": True, "readable": True, "row_security": False}
    answers = iter([json.dumps(probe), [{"health": {"format": health.FORMAT}}]])
    assert health.run(lambda sql: next(answers), "e").status == "ERROR"


def test_against_a_database_with_pg_cron_tables(pg):
    """The owner of the jobs sees them all; the audit role is told it cannot."""
    import psycopg
    from psycopg.rows import dict_row

    with psycopg.connect(pg.admin_cron, row_factory=dict_row) as connection:
        result = health.run_on_connection(connection, "local")
    found = {finding.location: finding.rule for finding in result.findings}
    assert found == {
        "cron job 'broken'": "cron_job_last_run_failed",
        "cron job 'recovered'": "cron_job_failed_in_window",
        "cron job 'silent'": "cron_job_no_recent_run",
        "cron job 'switched_off'": "cron_job_inactive",
    }
    assert result.status == "FINDINGS" and "6 scheduled jobs" in result.notes[0]
    assert "MARKER" not in json.dumps(result.to_dict())

    connection = live.connect(pg.auditor_cron)
    try:
        result = health.run_on_connection(connection, "local")
    finally:
        connection.close()
    assert result.status == "NOT_RUN" and "may not read" in result.reason


def test_a_database_without_pg_cron_is_not_run(pg):
    connection = live.connect(pg.auditor_good)
    try:
        result = health.run_on_connection(connection, "local")
    finally:
        connection.close()
    assert result.status == "NOT_RUN" and "not installed" in result.reason


def test_jobs_the_target_expects_must_exist_and_be_active():
    report = {"format": health.FORMAT, "taken_at": "t", "window_days": 7,
              "jobs": [job(job_name="nightly"), job(job_id=2, job_name="paused", active=False)]}
    result = health.judge(CheckResult(id="health_cron", title=health.TITLE), report, ("nightly", "paused", "absent"))
    missing = {f.location for f in result.findings if f.rule == "expected_cron_job_missing"}
    assert missing == {"cron job 'paused'", "cron job 'absent'"} and result.status == "FINDINGS"


def test_a_database_with_no_jobs_passes_only_when_none_are_expected():
    probe = {"format": health.PROBE_FORMAT, "installed": True, "readable": True, "row_security": False}
    empty = {"format": health.FORMAT, "taken_at": "t", "window_days": 7, "jobs": []}

    def ask(sql):
        return [{"probe": probe}] if health.PROBE_FORMAT in sql else [{"health": empty}]

    assert health.run(ask, "e").status == "PASS"
    expecting = health.run(ask, "e", expected_jobs=("nightly",))
    assert expecting.status == "FINDINGS" and expecting.findings[0].severity == "medium"

    absent = health.run(lambda sql: [{"probe": {"format": health.PROBE_FORMAT, "installed": False}}], "e", expected_jobs=("nightly",))
    assert absent.status == "FINDINGS" and "not installed" in absent.findings[0].message
