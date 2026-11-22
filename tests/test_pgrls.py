from pathlib import Path

import pytest

from conftest import FAKE_PASSWORD, FIXTURES, fake_pg_url
from webcare import PINNED_PGRLS_VERSION, pgrls_runner
from webcare.model import CheckResult

executable = pgrls_runner.find_pgrls()
needs_pgrls = pytest.mark.skipif(
    executable is None or pgrls_runner.installed_version(executable) != PINNED_PGRLS_VERSION,
    reason=f"pgrls {PINNED_PGRLS_VERSION} is not installed",
)


def lint(**kwargs) -> CheckResult:
    return pgrls_runner.run_lint(CheckResult(id="t", title="t"), **kwargs)


def test_migration_files_are_ordered_and_rollbacks_left_out(tmp_path):
    for name in ("b_second.sql", "a_first.sql", "ROLLBACK_a_first.sql", "c.down.sql", "notes.txt"):
        (tmp_path / name).write_text("select 1;")
    files = pgrls_runner.collect_sql_files(tmp_path)
    assert [path.name for path in files] == ["a_first.sql", "b_second.sql"]


def test_missing_pgrls_is_reported_as_not_run(monkeypatch):
    monkeypatch.setattr(pgrls_runner, "find_pgrls", lambda: None)
    result = lint(sql_files=[FIXTURES / "clean.sql"])
    assert result.status == "NOT_RUN" and "not installed" in result.reason


def test_unreviewed_pgrls_version_is_not_run(monkeypatch):
    monkeypatch.setattr(pgrls_runner, "find_pgrls", lambda: "/usr/bin/true")
    monkeypatch.setattr(pgrls_runner, "installed_version", lambda _: "9.9.9")
    result = lint(sql_files=[FIXTURES / "clean.sql"])
    assert result.status == "NOT_RUN" and "9.9.9" in result.reason


@needs_pgrls
def test_offline_lint_finds_the_planted_problems():
    result = lint(sql_files=[FIXTURES / "vulnerable.sql"])
    assert result.status == "FINDINGS"
    found = {(f.rule, f.location) for f in result.findings}
    assert ("SEC001", "public.notes") in found
    assert ("SEC008", "public.orders.orders_read_all") in found
    assert ("SEC033", "public.profiles.profiles_admin_read") in found
    # Offline, pgrls cannot see storage.objects' columns, so it flags the table
    # for review instead of naming the unscoped policy; the live check names it.
    assert ("SEC050", "storage.objects") in found
    # The SQL does not define storage.objects, so its RLS state is unknown here.
    assert not any(f.rule == "SEC032" and f.location.startswith("storage.") for f in result.findings)
    assert any("left out" in note for note in result.notes)
    assert any("only as complete as the SQL files" in note for note in result.notes)
    assert any("need a live database" in note and "VIEW001" in note for note in result.notes)


@needs_pgrls
def test_offline_lint_of_clean_schema_has_nothing_serious():
    result = lint(sql_files=[FIXTURES / "clean.sql"])
    assert not [f for f in result.findings if f.severity in ("high", "medium")]


@needs_pgrls
def test_broken_sql_is_an_error_not_a_pass(tmp_path):
    broken = tmp_path / "broken.sql"
    broken.write_text("create tabel oops (;")
    result = lint(sql_files=[broken])
    assert result.status == "ERROR" and result.reason


@needs_pgrls
def test_live_lint_reaches_the_catalog_only_rules(pg):
    result = lint(schemas=["public"], database_url=pg.auditor_bad)
    found = {(f.rule, f.location) for f in result.findings}
    assert ("VIEW001", "public.orders_view") in found
    assert ("SEC042", "public.admin_list_profiles") in found
    assert ("SEC033", "public.profiles.profiles_admin_read") in found
    assert not any("need a live database" in note for note in result.notes)


@needs_pgrls
def test_storage_pass_runs_only_the_policy_rules(pg):
    result = lint(schemas=["storage"], database_url=pg.auditor_bad, rules=pgrls_runner.STORAGE_RULES)
    assert {f.rule for f in result.findings} == {"SEC050"}


@needs_pgrls
def test_connection_string_never_reaches_the_report(pg):
    wrong = pg.auditor_bad.replace("webcare_auditor", "webcare_nobody")
    result = lint(schemas=["public"], database_url=wrong)
    assert result.status == "ERROR"
    password = pg.auditor_bad.split("password=")[1].split()[0]
    assert password not in result.reason


def test_scrub_removes_the_connection_string_and_password():
    pytest.importorskip("psycopg")
    url = fake_pg_url()
    line = f"could not parse {url}; password {FAKE_PASSWORD} rejected"
    scrubbed = pgrls_runner._scrub(line, url)
    assert FAKE_PASSWORD not in scrubbed and "***" in scrubbed
    assert pgrls_runner._scrub("plain", None) == "plain"


@needs_pgrls
def test_privileged_role_lint_runs_with_read_only_transactions(pg):
    result = lint(schemas=["public"], database_url=pg.admin_bad, force_read_only=True)
    assert result.status == "FINDINGS"
    assert ("SEC042", "public.admin_list_profiles") in {(f.rule, f.location) for f in result.findings}


@needs_pgrls
def test_partial_history_is_called_out(tmp_path):
    # The table is created here; the migration that enabled RLS is "missing".
    partial = tmp_path / "0002_later.sql"
    partial.write_text(
        "create table public.case_notes (id bigint primary key, owner_id uuid not null);\n"
        "grant select on public.case_notes to authenticated;\n"
    )
    result = lint(sql_files=[partial])
    assert ("SEC001", "public.case_notes") in {(f.rule, f.location) for f in result.findings}
    assert any("finding is false" in note for note in result.notes)


@needs_pgrls
def test_clean_offline_run_carries_no_history_caveat():
    result = lint(sql_files=[FIXTURES / "clean.sql"])
    assert not any("only as complete as the SQL files" in note for note in result.notes)
