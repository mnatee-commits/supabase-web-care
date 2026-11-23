

def test_thai_report_explains_each_finding_in_thai_and_keeps_the_english_detail():
    from webcare.explain_th import RULES, explain
    from webcare.model import CheckResult, Finding
    from webcare.report import Report

    checks = [CheckResult(id="extra_live", title="t", status="FINDINGS", findings=[
        Finding("live", "view_runs_as_owner", "medium", "public.v", "anon may read this view"),
        Finding("pgrls", "SEC001", "high", "public.t", "RLS is not enabled"),
        Finding("parity", "parity_tables", "medium", "tables", "since then: 1 added"),
    ])]
    markdown = Report(checks=checks, source="s", target="t", lang="th").to_markdown()
    assert "security_invoker = true" in markdown and "anon may read this view" in markdown
    assert "ตารางนี้ไม่ได้เปิด RLS" in markdown and "ส่วน tables เปลี่ยนไป" in markdown
    english = Report(checks=checks, source="s", target="t", lang="en").to_markdown()
    assert "ความหมาย" not in english and "| Severity | Rule | Location | Detail |" in english
    assert all(text.strip() for text in RULES.values())
    assert explain(Finding("x", "never_heard_of", "low", "l", "m")) == ""


def test_every_rule_in_the_code_has_a_thai_explanation():
    import re

    from conftest import ROOT
    from webcare import live
    from webcare.explain_th import RULES

    source = "\n".join(path.read_text() for path in (ROOT / "webcare").glob("*.py"))
    rules = set(re.findall(r'"([a-z][a-z0-9_]+)",\s*(?:"(?:high|medium|low|info)"|severity|"high" if|"medium" if|"low" if)', source))
    rules |= set(re.findall(r'rule="([a-z_]+)"', source)) | set(re.findall(r'_(?:fixed|key)\("([a-z_]+)"', source))
    rules |= {check.id for check in live.load_extra_checks()}
    rules |= {f"{role}_{suffix}" for role in ("anon", "authenticated")
              for suffix in ("write_without_rls", "write_undeclared", "writes_not_declared")}
    assert sorted(rules - set(RULES) - {"high", "medium", "low", "info", "error", "warning"}) == []


def test_every_pgrls_rule_has_a_thai_line():
    import shutil
    import subprocess

    import pytest

    from webcare.explain_th import PGRLS

    executable = shutil.which("pgrls")
    if executable is None:
        pytest.skip("pgrls is not installed")
    catalog = subprocess.run([executable, "explain"], capture_output=True, text=True, check=True).stdout
    rules = {line.split()[0] for line in catalog.splitlines() if line[:3] in ("SEC", "PER", "HYG", "VIE")}
    assert rules and sorted(rules - set(PGRLS)) == []


def test_the_summary_puts_first_things_first_and_never_hides_what_did_not_run():
    from webcare.model import CheckResult, Finding
    from webcare.report import Report

    checks = [
        CheckResult(id="extra_live", title="t", status="FINDINGS", findings=[
            Finding("live", "default_table_privileges", "medium", "public", "x"),
            Finding("live", "view_runs_as_owner", "medium", "public.v", "anon and authenticated may read this view"),
            Finding("live", "invalid_index", "low", "public.i", "z")]),
        CheckResult(id="table_writes", title="t", status="FINDINGS", findings=[
            Finding("table_writes", "anon_write_without_rls", "high", "public.t", "w")]),
        CheckResult(id="advisors", title="t", status="NOT_RUN", reason="not asked for"),
    ]
    report = Report(checks=checks, source="s", target="t", real_data=True)
    assert [f.rule for _, f in report.first_findings()] == [
        "anon_write_without_rls", "view_runs_as_owner", "default_table_privileges"]
    text = report.to_markdown()
    assert text.index("## In short") < text.index("## Summary")
    assert "1 of 3 checks did not run** (advisors)" in text and "every finding touches real people's data" in text
    clean = Report(checks=[CheckResult(id="advisors", title="t", status="NOT_RUN")], source="s", target="t",
                   lang="th").to_markdown()
    assert "ไม่พบปัญหาในการตรวจที่ได้ทำ" in clean and "ยังไม่ได้ตรวจ 1 จาก 1 หัวข้อ" in clean
    assert report.to_dict()["summary"]["first"][0]["rule"] == "anon_write_without_rls"


def test_visitors_come_first_only_when_a_finding_reaches_them():
    from webcare.model import CheckResult, Finding
    from webcare.report import Report

    check = CheckResult(id="extra_live", title="t", status="FINDINGS", findings=[
        Finding("live", "auth_role_deprecated", "medium", "public.a", "uses auth.role()"),
        Finding("live", "matview_readable_by_api_roles", "medium", "public.m", "anon may read every row"),
        Finding("live", "realtime_messages_open_to_signed_in", "medium", "realtime.messages.p",
                "ALL for authenticated with no condition"),
        Finding("live", "view_runs_as_owner", "medium", "public.v", "authenticated may read this view"),
        Finding("advisor", "unindexed_foreign_keys", "medium", "public.k", "foreign key without an index"),
    ])
    first = [f.rule for _, f in Report(checks=[check], source="s", target="t").first_findings(5)]
    assert first[0] == "matview_readable_by_api_roles"
    assert first[1:] == sorted(first[1:])  # the rest only by name: none of them reaches visitors
