from datetime import datetime, timedelta, timezone

from webcare import backups
from webcare.model import CheckResult
from webcare.targets import Target

NOW = datetime(2026, 1, 10, 12, 0, tzinfo=timezone.utc)
REF = "abcdefghijklmnopqrst"


def judged(answer, data="real", env="staging"):
    target = Target(name="t", env=env, data=data, project_ref=REF)
    return backups.judge(CheckResult(id="health_backups", title=backups.TITLE), answer, target, NOW)


def answer(*entries, pitr=False, physical=None):
    return {"region": "x", "walg_enabled": bool(physical), "pitr_enabled": pitr,
            "backups": [{"id": i, "is_physical_backup": False, "status": status, "inserted_at": when}
                        for i, (status, when) in enumerate(entries)],
            "physical_backup_data": physical or {}}


def rules(result):
    return {(finding.rule, finding.severity) for finding in result.findings}


def test_a_recent_completed_backup_passes_and_says_it_is_not_a_tested_restore():
    result = judged(answer(("COMPLETED", "2026-01-10T01:00:00Z"), ("COMPLETED", "2026-01-09T01:00:00.123Z")))
    assert result.status == "PASS"
    assert any("2026-01-10 01:00" in note for note in result.notes)
    assert any("not a tested restore" in note for note in result.notes)


def test_no_backup_is_high_for_real_data_and_low_for_synthetic():
    assert rules(judged(answer())) == {("backup_none", "high")}
    assert rules(judged(answer(("REMOVED", "2026-01-09T01:00:00Z")), data="synthetic")) == {("backup_none", "low")}
    assert rules(judged(answer(), data="synthetic", env="production")) == {("backup_none", "high")}


def test_stale_and_failed_backups_are_reported():
    assert rules(judged(answer(("COMPLETED", "2026-01-05T01:00:00Z")))) == {("backup_stale", "medium")}
    assert judged(answer(("COMPLETED", "2026-01-05T01:00:00Z")), ).findings[0].message.count("5 days") == 1
    assert judged(answer(("COMPLETED", "2026-01-05T01:00:00Z"), pitr=True)).status == "PASS"
    assert rules(judged(answer(("COMPLETED", "2026-01-10T01:00:00Z"), ("FAILED", "2026-01-10T11:00:00Z")))) == {
        ("backup_last_failed", "medium")
    }


def test_physical_backups_count_and_an_odd_answer_is_an_error():
    recent = int((NOW - timedelta(hours=3)).timestamp())
    assert judged(answer(physical={"latest_physical_backup_date_unix": recent})).status == "PASS"
    assert judged({"backups": "none"}).status == "ERROR"
    assert judged([]).status == "ERROR"
