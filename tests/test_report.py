

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
    assert "ผลของ pgrls" in markdown and "ส่วน tables เปลี่ยนไป" in markdown
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
    rules |= set(re.findall(r'rule="([a-z_]+)"', source)) | set(re.findall(r'_fixed\("([a-z_]+)"', source))
    rules |= {check.id for check in live.load_extra_checks()}
    rules |= {f"{role}_{suffix}" for role in ("anon", "authenticated")
              for suffix in ("write_without_rls", "write_undeclared", "writes_not_declared")}
    assert sorted(rules - set(RULES) - {"high", "medium", "low", "info", "error", "warning"}) == []
