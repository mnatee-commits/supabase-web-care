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


def test_the_statement_never_selects_the_text_of_a_statement():
    sql = db_health.build_sql()
    assert "pg_stat_statements" in sql and "queryid" in sql
    assert not re.search(r"\bs\.query\b", sql) and "s.*" not in sql


def test_connections_size_versions_and_slow_statements():
    from datetime import date

    parts = dict(
        connections={"in_use": 55, "max": 60, "reserved": 3},
        database_bytes=3 * (1 << 30),
        largest_tables=[{"table_name": "public.big", "bytes": 2 * (1 << 30)}],
        server_version_num=140012,
        extension_updates=[{"name": "pg_net", "installed_version": "0.14.0", "default_version": "0.20.4"}],
        statements=[{"query_id": "42", "calls": 500, "mean_ms": 2300.0, "total_ms": 1150000, "rows": 1},
                    {"query_id": "43", "calls": 3, "mean_ms": 9000.0, "total_ms": 27000, "rows": 1},
                    {"query_id": "44", "calls": 90000, "mean_ms": 4.0, "total_ms": 360000, "rows": 1}],
    )
    result = db_health.judge(CheckResult(id="db_health", title=db_health.TITLE), report(**parts), today=date(2026, 11, 23))
    assert found(result) == {
        ("connections_near_limit", "high", "database"),      # 55 of 57 usable
        ("postgres_end_of_life", "medium", "database"),      # 14 ended on 2026-11-12
        ("extension_update_available", "info", "extensions"),
        ("slow_statement", "low", "query id 42"),            # slow and often; 43 ran too few times, 44 is fast
    }
    assert any("database size: 3.0 GB" in note and "public.big 2.0 GB" in note for note in result.notes)
    soon = db_health.judge(CheckResult(id="db_health", title=db_health.TITLE),
                           report(server_version_num=150010, connections={"in_use": 9, "max": 60, "reserved": 3}),
                           today=date(2027, 8, 1))
    assert found(soon) == {("postgres_end_of_life", "low", "database")}
    assert any("connections in use: 9 of 57" in note for note in soon.notes)
    calm = db_health.judge(CheckResult(id="db_health", title=db_health.TITLE), report(server_version_num=170011),
                           today=date(2026, 11, 23))
    assert calm.findings == [] and any("pg_stat_statements is not installed" in note for note in calm.notes)


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
    assert any(note.startswith("database size:") for note in result.notes)
    assert any(note.startswith("connections in use:") for note in result.notes)
