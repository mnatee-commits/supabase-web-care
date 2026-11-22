import json

from conftest import FIXTURES
from webcare import sarif
from webcare.cli import main
from webcare.model import CheckResult, Finding


def test_file_findings_are_placed_and_the_rest_are_counted(tmp_path, monkeypatch):
    migration = tmp_path / "001_init.sql"
    migration.write_text(
        "-- setup\ncreate table if not exists public.notes (id int);\n"
        'create policy "notes read" on public.notes for select using (true);\n'
    )
    app = tmp_path / "app"
    app.mkdir()
    (app / "config.js").write_text("x\n")
    checks = [
        CheckResult(id="rls_static", title="t", findings=[
            Finding("pgrls", "SEC001", "high", "public.notes", "RLS is not enabled"),
            Finding("pgrls", "SEC005", "medium", "public.notes.notes read", "always true"),
            Finding("pgrls", "SEC009", "low", "public.elsewhere", "no file creates this"),
        ]),
        CheckResult(id="functions_static", title="t", findings=[
            Finding("functions_static", "anon_exec", "high", "public.f (001_init.sql:2)", "anon may call"),
        ]),
        CheckResult(id="secrets", title="t", findings=[
            Finding("secret_scan", "jwt", "high", "config.js:1", "a key [redacted]"),
            Finding("secret_scan", "publishable", "info", "config.js:1", "public key"),
        ]),
        CheckResult(id="table_writes", title="t", findings=[
            Finding("table_writes", "anon_write_undeclared", "medium", "public.notes", "anon may insert"),
        ]),
    ]
    monkeypatch.chdir(tmp_path)
    data = sarif.build(checks, [app], [migration])
    run = data["runs"][0]
    placed = {(r["ruleId"], r["level"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
               r["locations"][0]["physicalLocation"]["region"]["startLine"]) for r in run["results"]}
    assert placed == {
        ("pgrls/SEC001", "error", "001_init.sql", 2),
        ("pgrls/SEC005", "warning", "001_init.sql", 3),
        ("functions_static/anon_exec", "error", "001_init.sql", 2),
        ("secret_scan/jwt", "error", "app/config.js", 1),
    }
    assert run["properties"]["findings_without_a_file_line"] == 2  # unknown object, live finding; info skipped
    assert data["version"] == "2.1.0" and {r["id"] for r in run["tool"]["driver"]["rules"]} >= {"pgrls/SEC001"}


def test_check_writes_report_sarif_only_when_asked(tmp_path):
    out = tmp_path / "out"
    args = ["check", "--skip", "secrets", "--sql-file", str(FIXTURES / "vulnerable.sql"), "--out-dir", str(out)]
    main(args)
    assert not (out / "report.sarif").exists()
    main(args + ["--sarif"])
    data = json.loads((out / "report.sarif").read_text())
    assert data["runs"][0]["tool"]["driver"]["name"] == "supabase-web-care"
