import json

import pytest

from conftest import FIXTURES
from webcare import baseline
from webcare.cli import main
from webcare.model import CheckResult, Finding, Refusal

pytest.importorskip("pglast")


def check(check_id, *findings):
    result = CheckResult(id=check_id, title=check_id)
    result.findings = [Finding("t", rule, severity, location, "m") for rule, severity, location in findings]
    return result.finish()


def test_line_numbers_do_not_matter_and_only_file_checks_are_recorded(tmp_path):
    checks = [
        check("functions_static", ("secdef_public_execute", "high", "public.f() (a.sql:10)"), ("x", "info", "public.g()")),
        check("secrets", ("jwt", "high", "app.js:3")),
        check("functions_live", ("secdef_anon_executable", "high", "public.f()")),
    ]
    path = tmp_path / "b.json"
    assert baseline.write(path, checks) == 1
    assert json.loads(path.read_text())["findings"] == [
        {"check": "functions_static", "rule": "secdef_public_execute", "location": "public.f() (a.sql)"}
    ]
    moved = [
        check("functions_static", ("secdef_public_execute", "high", "public.f() (a.sql:42)"),
              ("secdef_public_execute", "high", "public.new() (b.sql:1)")),
        check("secrets", ("jwt", "high", "app.js:3")),
    ]
    baseline.apply(moved, baseline.load(path), "b.json")
    assert [f.location for f in moved[0].findings] == ["public.new() (b.sql:1)"]
    assert moved[0].status == "FINDINGS" and "1 findings already recorded" in moved[0].notes[0]
    assert len(moved[1].findings) == 1  # a credential is never accepted by a baseline


def test_a_fully_baselined_check_passes_and_stale_entries_are_reported(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"format": baseline.FORMAT, "findings": [
        {"check": "rls_static", "rule": "SEC001", "location": "public.t"},
        {"check": "rls_static", "rule": "SEC001", "location": "public.gone"},
    ]}))
    result = check("rls_static", ("SEC001", "high", "public.t"))
    baseline.apply([result], baseline.load(path), "b.json")
    assert result.status == "PASS" and "1 of its entries no longer match" in result.notes[0]


@pytest.mark.parametrize("content", [
    "not json", "[]", json.dumps({"format": "other", "findings": []}),
    json.dumps({"format": baseline.FORMAT, "findings": [{"check": "secrets", "rule": "jwt", "location": "x"}]}),
    json.dumps({"format": baseline.FORMAT, "findings": [{"check": "rls_static"}]}),
])
def test_a_baseline_that_is_malformed_or_reaches_too_far_is_refused(tmp_path, content):
    path = tmp_path / "b.json"
    path.write_text(content)
    with pytest.raises(Refusal):
        baseline.load(path)


def test_cli_round_trip(tmp_path, capsys):
    out, base = tmp_path / "out", tmp_path / "base.json"
    common = ["check", "--skip", "secrets", "--sql-file", str(FIXTURES / "functions_bad.sql"), "--out-dir", str(out)]
    assert main(common) == 1
    assert main(common + ["--write-baseline", str(base)]) == 1  # writing does not excuse this run
    assert main(common + ["--baseline", str(base)]) == 0
    report = json.loads((out / "report.json").read_text())
    functions = next(c for c in report["checks"] if c["id"] == "functions_static")
    assert functions["status"] == "PASS" and "are not counted" in " ".join(functions["notes"])
    assert main(common + ["--baseline", str(tmp_path / "missing.json")]) == 2
    capsys.readouterr()
