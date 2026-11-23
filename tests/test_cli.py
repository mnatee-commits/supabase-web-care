import json

import pytest

from conftest import FIXTURES, make_jwt
from webcare import PINNED_PGRLS_VERSION, pgrls_runner
from webcare.cli import main

executable = pgrls_runner.find_pgrls()
needs_pgrls = pytest.mark.skipif(
    executable is None or pgrls_runner.installed_version(executable) != PINNED_PGRLS_VERSION,
    reason=f"pgrls {PINNED_PGRLS_VERSION} is not installed",
)


def statuses(out_dir) -> dict[str, str]:
    report = json.loads((out_dir / "report.json").read_text())
    return {check["id"]: check["status"] for check in report["checks"]}


@pytest.fixture(autouse=True)
def no_ambient_credentials(monkeypatch):
    for name in ("WEBCARE_DATABASE_URL", "WEBCARE_ANON_KEY", "DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)


def test_secrets_command_exit_codes(tmp_path, capsys):
    (tmp_path / "ok.txt").write_text("fine")
    assert main(["secrets", str(tmp_path)]) == 0
    token = make_jwt({"role": "service_role", "iss": "supabase"})
    (tmp_path / "leak.env").write_text(f"KEY={token}\n")
    assert main(["secrets", str(tmp_path)]) == 1
    assert main(["secrets", str(tmp_path), "--fail-on", "never"]) == 0
    assert token not in capsys.readouterr().out


@needs_pgrls
def test_offline_check_writes_a_report_and_fails_on_high(tmp_path):
    out = tmp_path / "out"
    code = main(
        ["check", "--repo", str(FIXTURES), "--sql-file", str(FIXTURES / "vulnerable.sql"), "--out-dir", str(out)]
    )
    assert code == 1
    assert statuses(out) == {
        "secrets": "PASS",
        "rls_static": "FINDINGS",
        "functions_static": "FINDINGS",
        "rls_live": "NOT_RUN",
        "extra_live": "NOT_RUN",
        "functions_live": "NOT_RUN",
        "storage_buckets": "NOT_RUN",
        "table_writes": "NOT_RUN",
        "advisors": "NOT_RUN",
        "auth_config": "NOT_RUN",
        "health_cron": "NOT_RUN",
        "health_backups": "NOT_RUN",
        "health_logs": "NOT_RUN",
        "db_health": "NOT_RUN",
        "data_api": "NOT_RUN",
        "advisors_performance": "NOT_RUN",
        "anon_probe": "NOT_RUN",
    }
    markdown = (out / "report.md").read_text()
    assert "Items that need a manual check" in markdown and "Supabase Security Advisor" in markdown
    manual = json.loads((out / "report.json").read_text())["manual"]
    assert manual and all(item["status"] == "NOT_RUN" for item in manual)


@needs_pgrls
def test_clean_schema_exits_zero_and_migrations_directory_works(tmp_path):
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "0001_init.sql").write_text((FIXTURES / "clean.sql").read_text())
    (migrations / "ROLLBACK_0001_init.sql").write_text("drop table public.orders;")
    out = tmp_path / "out"
    code = main(["check", "--repo", str(migrations), "--migrations", str(migrations), "--out-dir", str(out)])
    assert code == 0
    report = json.loads((out / "report.json").read_text())
    static = next(check for check in report["checks"] if check["id"] == "rls_static")
    assert "0001_init.sql" in static["evidence"] and "ROLLBACK" not in static["evidence"]


def test_function_mistakes_in_migrations_fail_the_offline_check(tmp_path):
    pytest.importorskip("pglast")
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "0001_report.sql").write_text(
        "create function public.monthly_report() returns int language sql security definer "
        "set search_path = '' as $$ select 1 $$;\n"
        "revoke execute on function public.monthly_report() from anon;\n"
    )
    out = tmp_path / "out"
    code = main(
        ["check", "--skip", "secrets", "--migrations", str(migrations), "--out-dir", str(out),
         "--allow-pgrls-version-mismatch"]
    )
    report = json.loads((out / "report.json").read_text())
    functions = next(check for check in report["checks"] if check["id"] == "functions_static")
    assert functions["status"] == "FINDINGS"
    assert [f["rule"] for f in functions["findings"]] == ["secdef_public_execute"]
    assert "0001_report.sql:1" in functions["findings"][0]["location"]
    assert code in (1, 2)  # 1 with pgrls installed; 2 when the pgrls half could not run
    assert "SECURITY DEFINER functions" in (out / "report.md").read_text()


def test_no_sql_given_is_not_run_without_failing(tmp_path):
    (tmp_path / "ok.txt").write_text("fine")
    out = tmp_path / "out"
    assert main(["check", "--repo", str(tmp_path), "--exclude", "out/*", "--out-dir", str(out)]) == 0
    assert statuses(out)["rls_static"] == "NOT_RUN"
    assert statuses(out)["functions_static"] == "NOT_RUN"


def test_missing_sql_file_is_an_error(tmp_path):
    out = tmp_path / "out"
    code = main(["check", "--skip", "secrets", "--sql-file", str(tmp_path / "absent.sql"), "--out-dir", str(out)])
    assert code == 2 and statuses(out)["rls_static"] == "ERROR"


def test_requested_target_that_cannot_run_exits_two(tmp_path):
    out = tmp_path / "out"
    code = main(
        ["check", "--skip", "secrets", "--skip", "static", "--target", "staging",
         "--config", str(tmp_path / "absent.toml"), "--out-dir", str(out)]
    )
    assert code == 2
    assert statuses(out)["rls_live"] == "NOT_RUN"


@needs_pgrls
def test_live_check_end_to_end(pg, tmp_path, monkeypatch):
    monkeypatch.setenv("WEBCARE_DATABASE_URL", pg.auditor_bad)
    out = tmp_path / "out"
    code = main(
        ["check", "--skip", "secrets", "--skip", "static", "--target", "bad",
         "--config", str(pg.config), "--out-dir", str(out)]
    )
    assert code == 1
    assert statuses(out) == {
        "rls_live": "FINDINGS",
        "storage_live": "FINDINGS",
        "extra_live": "FINDINGS",
        "functions_live": "FINDINGS",
        "storage_buckets": "NOT_RUN",
        "table_writes": "FINDINGS",
        "advisors": "NOT_RUN",
        "auth_config": "NOT_RUN",
        "health_cron": "NOT_RUN",
        "health_backups": "NOT_RUN",
        "health_logs": "NOT_RUN",
        "db_health": "PASS",
        "data_api": "NOT_RUN",
        "advisors_performance": "NOT_RUN",
        "anon_probe": "NOT_RUN",
    }
    text = (out / "report.json").read_text() + (out / "report.md").read_text()
    password = pg.auditor_bad.split("password=")[1].split()[0]
    assert password not in text


@needs_pgrls
def test_live_check_refuses_real_data_without_the_owner(pg, tmp_path, monkeypatch):
    monkeypatch.setenv("WEBCARE_DATABASE_URL", pg.auditor_bad)
    out = tmp_path / "out"
    arguments = ["check", "--skip", "secrets", "--skip", "static", "--target", "real-copy",
                 "--config", str(pg.config), "--out-dir", str(out)]
    assert main(arguments) == 2
    assert statuses(out)["rls_live"] == "NOT_RUN"
    assert main(arguments + ["--owner-approved"]) == 1
    assert statuses(out)["rls_live"] == "FINDINGS"


def test_preflight_reports_the_role(pg, monkeypatch, capsys):
    monkeypatch.setenv("WEBCARE_DATABASE_URL", pg.auditor_bad)
    assert main(["preflight", "--target", "bad", "--config", str(pg.config)]) == 0
    assert "cannot write to application tables" in capsys.readouterr().out
    monkeypatch.setenv("WEBCARE_DATABASE_URL", pg.admin_bad)
    assert main(["preflight", "--target", "bad", "--config", str(pg.config)]) == 2
    assert "superuser" in capsys.readouterr().err


def test_unwritable_out_dir_still_reports(tmp_path, capsys):
    (tmp_path / "ok.txt").write_text("fine")
    blocker = tmp_path / "not_a_folder"
    blocker.write_text("a file where a folder was expected")
    code = main(["check", "--repo", str(tmp_path), "--out-dir", str(blocker / "out")])
    captured = capsys.readouterr()
    assert code == 0
    assert "could not write the report" in captured.err
    assert "secrets" in captured.out and "report:" not in captured.out
    code = main(["check", "--repo", str(tmp_path), "--out-dir", str(blocker / "out"), "--json"])
    assert code == 0 and '"checks"' in capsys.readouterr().out


def test_the_report_is_english_by_default_and_thai_on_request(tmp_path, monkeypatch):
    monkeypatch.delenv("WEBCARE_LANG", raising=False)
    common = ["check", "--skip", "static", "--repo", str(tmp_path)]

    def run(*extra):
        out = tmp_path / ("out" + "".join(extra).replace("-", ""))
        assert main(common + ["--out-dir", str(out), *extra]) == 0
        return (out / "report.md").read_text(), json.loads((out / "report.json").read_text())

    english, record = run()
    assert "# Supabase Web Care report" in english and "## Summary" in english
    assert not any("\u0e00" <= character <= "\u0e7f" for character in english)  # no Thai left behind
    assert record["language"] == "en" and len(record["manual"]) == 11
    assert all(item["title"] and item["how"] for item in record["manual"])

    thai, record = run("--lang", "th")
    assert "# รายงาน Supabase Web Care" in thai and "## สรุป" in thai
    assert record["language"] == "th" and "ตรวจ" in record["manual"][-1]["how"]
    assert english.count("\n") == thai.count("\n")  # same structure, line for line

    # the environment variable sets the default; an unknown value falls back to English
    for value, heading in (("th", "# รายงาน Supabase Web Care"), ("xx", "# Supabase Web Care report")):
        monkeypatch.setenv("WEBCARE_LANG", value)
        out = tmp_path / f"env-{value}"
        assert main(common + ["--out-dir", str(out)]) == 0
        assert heading in (out / "report.md").read_text()
