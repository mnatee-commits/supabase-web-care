import json
import shutil
import subprocess

import pytest

from conftest import FIXTURES
from webcare import changes, inventory, parity
from webcare.cli import main
from webcare.model import CheckResult, Refusal

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def git(directory, *arguments):
    subprocess.run(["git", "-C", str(directory), *arguments], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
                        "HOME": str(directory), "PATH": "/usr/bin:/bin"})


@pytest.mark.parametrize("ref", ["--output=/tmp/x", "-p", "", "a b", "HEAD;rm"])
def test_option_like_or_odd_refs_are_refused(ref):
    with pytest.raises(Refusal):
        changes.check_ref(ref)


@needs_git
def test_only_changed_files_are_scanned_and_sql_checks_wait_for_a_sql_change(tmp_path):
    repo = tmp_path / "site"
    (repo / "migrations").mkdir(parents=True)
    old_key = "sb_secret_" + "o" * 24
    (repo / "old.js").write_text(f"const k = '{old_key}';\n")
    (repo / "migrations" / "001.sql").write_text("create table public.t (id int);\n")
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "first")
    new_key = "sb_secret_" + "n" * 24
    (repo / "new.js").write_text(f"const k = '{new_key}';\n")
    out = tmp_path / "out"
    code = main(["check", "--repo", str(repo), "--migrations", str(repo / "migrations"),
                 "--changed-since", "HEAD", "--out-dir", str(out)])
    report = json.loads((out / "report.json").read_text())
    checks = {check["id"]: check for check in report["checks"]}
    assert [f["location"] for f in checks["secrets"]["findings"] if f["severity"] == "high"] == ["new.js:1"]
    assert checks["rls_static"]["status"] == "NOT_RUN" and "no SQL file changed" in checks["rls_static"]["reason"]
    assert "files changed since HEAD" in report["scope"] and code == 1
    assert main(["check", "--repo", str(repo), "--changed-since=-p", "--out-dir", str(out)]) == 2


def inv(label="staging", tables=None, functions=None):
    return {"format": inventory.FORMAT, "label": label, "taken_at": "2026-11-20T00:00:00Z",
            "tool_version": "1.24.0", "schemas": ["public"],
            "parts": {name: {"rows": {}} for name in inventory.PART_ORDER} | {
                "tables": {"rows": tables or {}}, "functions": {"rows": functions or {}},
                "cron_jobs": {"not_read": "pg_cron is not installed"}}}


def test_parity_reports_what_changed_and_how_much_it_matters():
    saved = inv(tables={"public.a": {"rls": True}}, functions={"public.f()": {"anon": False}})
    now = inv(tables={"public.a": {"rls": False}, "public.b": {"rls": True}}, functions={"public.f()": {"anon": False}})
    result = parity.judge(CheckResult(id="parity", title="t"), saved, now)
    assert {(f.rule, f.severity) for f in result.findings} == {("parity_tables", "medium")}
    message = result.findings[0].message
    assert "1 added (public.b)" in message and "1 changed in rls" in message and "(public.a)" in message
    assert any("cron_jobs not compared" in note for note in result.notes)
    assert parity.judge(CheckResult(id="parity", title="t"), saved, saved).status == "PASS"


def test_parity_refuses_another_targets_inventory(tmp_path):
    path = tmp_path / "trial.inv.json"
    path.write_text(json.dumps(inv(label="trial")))
    from webcare.targets import Target

    result = parity.run(lambda sql: None, Target(name="staging", env="staging", data="synthetic"), path, "x")
    assert result.status == "ERROR" and "compare like with like" in result.reason


def test_parity_against_the_test_database(pg, tmp_path, monkeypatch):
    monkeypatch.setenv("WEBCARE_DATABASE_URL", pg.auditor_good)
    saved = tmp_path / "good.inv.json"
    assert main(["inventory", "--target", "good", "--config", str(pg.config), "--out", str(saved)]) == 0
    out = tmp_path / "out"
    main(["check", "--target", "good", "--config", str(pg.config), "--parity", str(saved), "--only", "parity",
          "--out-dir", str(out)])
    checks = {check["id"]: check for check in json.loads((out / "report.json").read_text())["checks"]}
    assert checks["parity"]["status"] == "PASS", checks["parity"]
