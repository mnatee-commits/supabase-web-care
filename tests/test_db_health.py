import re

import pytest

from webcare import db_health, live
from webcare.model import CheckResult


def report(**parts):
    base = {"format": db_health.FORMAT, "taken_at": "now", "sees_other_sessions": True,
            "database_xid_age": 1000, "invalid_indexes": [], "bloat": [], "xid_age": [],
            "idle_in_transaction": [], "lock_waits": [], "sequences": [], "sequences_unreadable": 0}
    base.update(parts)
    return base


def judged(**parts):
    return db_health.judge(CheckResult(id="db_health", title=db_health.TITLE), report(**parts))


def found(result):
    return {(f.rule, f.severity, f.location) for f in result.findings}


def test_the_statement_is_one_select_that_reads_no_rows_samples_or_query_text():
    sql = db_health.build_sql()
    live.assert_single_select(sql)
    assert "pg_stats " not in sql and "pg_stats\n" not in sql and not re.search(r"\bpg_stats\b", sql)
    assert not re.search(r"\ba\.query\b", sql) and "application_name" not in sql
    assert "pg_sequence_last_value" in sql and "has_sequence_privilege" in sql


def test_a_quiet_database_passes():
    result = judged()
    assert result.status == "PASS" and "no table row" in result.notes[-1]


def test_each_part_is_judged_with_its_thresholds():
    result = judged(
        invalid_indexes=[{"index_name": "public.i", "table_name": "public.t", "bytes": 8192}],
        bloat=[{"table_name": "public.small", "dead_rows": 12000, "dead_ratio": 0.3, "last_vacuum": None},
               {"table_name": "public.big", "dead_rows": 200000, "dead_ratio": 0.6, "last_vacuum": None}],
        xid_age=[{"table_name": "public.old", "xid_age": 1300000000}],
        database_xid_age=600000000,
        idle_in_transaction=[{"role_name": "app", "state": "idle in transaction", "sessions": 2,
                              "longest_seconds": 400}],
        lock_waits=[{"role_name": "app", "sessions": 1, "longest_seconds": 90}],
        sequences=[{"sequence_name": "public.s", "data_type": "integer", "max_value": 2147483647,
                    "last_value": 2000000000, "used": 0.93}],
    )
    assert found(result) == {
        ("invalid_index", "medium", "public.i"),
        ("table_bloat", "medium", "public.small"),
        ("table_bloat", "high", "public.big"),
        ("xid_age", "high", "public.old"),
        ("xid_age", "medium", "database"),
        ("idle_in_transaction", "medium", "role app"),
        ("lock_wait", "medium", "role app"),
        ("sequence_near_limit", "high", "public.s"),
    }


def test_sessions_not_visible_are_said_to_be_unchecked_not_clean():
    result = judged(sees_other_sessions=False, sequences_unreadable=4,
                    idle_in_transaction=[{"role_name": "x", "state": "idle in transaction",
                                          "sessions": 1, "longest_seconds": 9999}])
    assert result.findings == []
    assert any("not visible" in note for note in result.notes)
    assert any("4 sequences could not be read" in note and "nothing is estimated" in note for note in result.notes)


def test_against_the_test_database(pg):
    import psycopg

    with psycopg.connect(pg.auditor_bad) as connection:
        result = db_health.run_on_connection(connection, "test database")
    assert result.status in ("PASS", "FINDINGS"), result.reason
    assert any("not visible" in note for note in result.notes)  # the audit role lacks pg_read_all_stats
