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


def test_hard_cases_are_placed_right_or_left_out(tmp_path, monkeypatch):
    first, second = tmp_path / "schemas", tmp_path / "migrations"
    first.mkdir()
    second.mkdir()
    (first / "init.sql").write_text("select 1;\n")
    (second / "init.sql").write_text("select 1;\n" * 5)
    sql = tmp_path / "002_policies.sql"
    sql.write_text(
        "-- create table public.notes is described here, not created\n"
        "create table public.notes (id int);\n"
        'create policy "notes read"\n  on public.notes for select using (true);\n'
    )
    app = tmp_path / "app"
    (app / "src" / "app" / "(dashboard)").mkdir(parents=True)
    (app / "src" / "app" / "(dashboard)" / "actions.ts").write_text("x\n")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.sql"
    outside.write_text("create table public.far (id int);\n")
    checks = [
        CheckResult(id="secrets", title="t", findings=[
            Finding("secret_scan", "jwt", "high", "src/app/(dashboard)/actions.ts:1", "a key")]),
        CheckResult(id="rls_static", title="t", findings=[
            Finding("pgrls", "SEC001", "high", "public.notes", "no RLS"),
            Finding("pgrls", "SEC005", "medium", "public.notes.notes read", "always true"),
            Finding("pgrls", "SEC001", "high", "public.far", "outside the tree")]),
        CheckResult(id="functions_static", title="t", findings=[
            Finding("functions_static", "x", "high", "public.f (init.sql:3)", "which init.sql?")]),
    ]
    monkeypatch.chdir(tmp_path)
    run = sarif.build(checks, [app], [first / "init.sql", second / "init.sql", sql, outside])["runs"][0]
    placed = {(r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
               r["locations"][0]["physicalLocation"]["region"]["startLine"]) for r in run["results"]}
    assert placed == {
        ("secret_scan/jwt", "app/src/app/(dashboard)/actions.ts", 1),
        ("pgrls/SEC001", "002_policies.sql", 2),  # the comment on line 1 is not a statement
        ("pgrls/SEC005", "002_policies.sql", 3),  # CREATE POLICY and ON on separate lines
    }
    assert run["properties"]["findings_without_a_file_line"] == 2  # outside the tree; ambiguous init.sql
    assert all(len(r["partialFingerprints"]["webcareFinding/v1"]) == 32 for r in run["results"])


def test_same_named_roots_are_told_apart(tmp_path, monkeypatch):
    from webcare import secret_scan

    one, two = tmp_path / "apps" / "api", tmp_path / "services" / "api"
    for root in (one, two):
        root.mkdir(parents=True)
        (root / "k.txt").write_text(f"sb_secret_{'c' * 24}\n")
    monkeypatch.chdir(tmp_path)
    found = secret_scan.run([one, two]).findings
    assert sorted(f.location for f in found) == ["apps/api/k.txt:1", "services/api/k.txt:1"]
    checks = [CheckResult(id="secrets", title="t", findings=found)]
    uris = sorted(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                  for r in sarif.build(checks, [one, two], [])["runs"][0]["results"])
    assert uris == ["apps/api/k.txt", "services/api/k.txt"]
