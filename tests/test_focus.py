import argparse
import json

import pytest

from conftest import FIXTURES
from webcare import focus, live
from webcare.cli import main
from webcare.model import CheckResult, Finding


def test_every_catalog_check_belongs_to_an_area():
    covered = set().union(*(area.catalog for area in focus.AREAS.values()))
    assert {check.id for check in live.load_extra_checks()} == covered


def test_areas_parse_from_commas_and_repeats_and_unknown_ones_are_refused():
    assert focus.parse(["tables,functions", "functions"]) == ("functions", "tables")
    with pytest.raises(ValueError, match="unknown --focus area"):
        focus.parse(["everything"])


def test_prepare_turns_areas_into_skips_and_optional_checks():
    args = argparse.Namespace(with_advisors=True, with_auth_config=False, with_backups=False, with_logs=False)
    skip = set()
    focus.Plan(("health",)).prepare(args, skip)
    assert skip == {"secrets", "static", "probe"}
    assert (args.with_advisors, args.with_backups, args.with_logs) == (False, True, True)
    skip = set()
    focus.Plan((), "quick").prepare(args, skip)
    assert skip == {"live", "probe"}
    focus.Plan((), "full").prepare(args, set())
    assert args.with_advisors and args.with_auth_config


def test_apply_leaves_out_other_checks_and_other_catalog_findings():
    extra = CheckResult(id="extra_live", title="t", status="FINDINGS", findings=[
        Finding("live", "extension_net_callable", "medium", "schema net (role anon)", "x"),
        Finding("live", "default_table_privileges", "low", "public", "y"),
    ])
    checks = [CheckResult(id="secrets", title="t", status="PASS"), extra]
    requested = {"secrets", "extra_live"}
    out = focus.Plan(("extensions",)).apply(checks, requested)
    assert out[0].status == "NOT_RUN" and "focus: extensions" in out[0].reason
    assert requested == {"extra_live"}
    assert [f.rule for f in out[1].findings] == ["extension_net_callable"]
    assert "1 findings of other catalog checks left out" in out[1].notes[-1]
    only_other = focus.Plan(("functions",)).apply(
        [CheckResult(id="extra_live", title="t", status="FINDINGS", findings=[extra.findings[0]])], set())
    assert only_other[0].status == "PASS"


def test_a_focused_run_says_so_and_does_not_fail_for_what_it_left_out(tmp_path):
    out = tmp_path / "out"
    code = main(["check", "--repo", str(FIXTURES), "--focus", "secrets", "--out-dir", str(out)])
    report = json.loads((out / "report.json").read_text())
    statuses = {check["id"]: check["status"] for check in report["checks"]}
    assert statuses["secrets"] in ("PASS", "FINDINGS")
    assert statuses["rls_static"] == "NOT_RUN" and statuses["extra_live"] == "NOT_RUN"
    assert report["scope"] == "focus: secrets"
    assert "Scope (only part of the checks ran): focus: secrets" in (out / "report.md").read_text()
    assert code in (0, 1)
    assert main(["check", "--focus", "nothing", "--out-dir", str(out)]) == 2  # refused
    main(["check", "--sql-file", str(FIXTURES / "vulnerable.sql"), "--focus", "tables", "--out-dir", str(out)])
    ids = [check["id"] for check in json.loads((out / "report.json").read_text())["checks"]]
    assert ids[0] == "secrets" and "rls_static" in ids


def test_a_focused_live_run_keeps_only_the_catalog_checks_of_its_area(pg, tmp_path, monkeypatch):
    monkeypatch.setenv("WEBCARE_DATABASE_URL", pg.auditor_fbad)
    out = tmp_path / "out"
    main(["check", "--target", "fbad", "--config", str(pg.config), "--focus", "extensions",
          "--out-dir", str(out)])
    checks = {check["id"]: check for check in json.loads((out / "report.json").read_text())["checks"]}
    rules = {finding["rule"] for finding in checks["extra_live"]["findings"]}
    assert rules == {"extension_net_callable", "extension_vault_reachable", "extension_cron_reachable"}
    for left_out in ("rls_live", "functions_live", "table_writes", "secrets"):
        assert checks[left_out]["status"] == "NOT_RUN" and "focus: extensions" in checks[left_out]["reason"]
