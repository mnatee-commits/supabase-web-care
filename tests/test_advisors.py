import pytest

from webcare import advisors
from webcare.model import CheckResult, Refusal
from webcare.targets import Target, load_targets

REF = "abcdefghijklmnopqrst"


def lint(name="rls_disabled_in_public", level="ERROR", count=1, names=("orders",), **extra):
    base = {"name": name, "title": name.replace("_", " ").title(), "level": level, "description": "d",
            "count": count, "findings": [{"metadata": {"schema": "public", "name": n}} for n in names]}
    base.update(extra)
    return base


def judged(answer, ignore=()):
    target = Target(name="t", env="staging", data="synthetic", project_ref=REF, advisors_ignore=tuple(ignore))
    return advisors.judge(CheckResult(id="advisors", title=advisors.TITLE), answer, target)


def rules(result):
    return {(f.rule, f.severity) for f in result.findings}


def test_every_wrapper_the_answer_may_come_in_is_read():
    one = [lint()]
    for answer in ({"lints": one}, {"result": {"lints": one}}, {"result": {"result": {"lints": one}}}, one):
        assert rules(judged(answer)) == {("rls_disabled_in_public", "high")}


def test_levels_map_to_severities_and_info_is_not_a_problem():
    result = judged({"lints": [lint("a_lint", "WARN"), lint("b_lint", "INFO"), lint("c_lint", "mystery")]})
    assert rules(result) == {("a_lint", "medium"), ("b_lint", "info"), ("c_lint", "medium")}
    assert judged({"lints": [lint("b_lint", "INFO")]}).status == "PASS"


def test_a_lint_naming_hundreds_of_objects_is_one_short_finding():
    names = [f"fn_{i}" for i in range(400)]
    result = judged({"lints": [lint("big_lint", "WARN", count=400, names=names)]})
    message = result.findings[0].message
    assert len(result.findings) == 1 and "400 objects" in message and "and 395 more" in message
    assert "fn_5" not in message and len(message) < 600


def test_ignored_lints_are_counted_and_stale_entries_are_reported():
    result = judged({"lints": [lint("big_lint", "WARN", count=328, names=["x"]), lint("rls_disabled_in_public")]},
                    ignore=["big_lint", "gone_lint"])
    assert rules(result) == {("rls_disabled_in_public", "high")}
    notes = " ".join(result.notes)
    assert "big_lint (328)" in notes and "gone_lint" in notes and "can be removed" in notes


def test_only_a_supabase_link_survives_and_text_is_shortened():
    ok = judged({"lints": [lint(remediation="https://supabase.com/docs/x")]}).findings[0].message
    bad = judged({"lints": [lint(remediation="https://evil.example/x", description="x " * 500)]}).findings[0].message
    assert "See https://supabase.com/docs/x" in ok
    assert "evil.example" not in bad and len(bad) < 500


def test_an_answer_that_is_not_a_lint_list_is_an_error_not_a_pass():
    for answer in ({"message": "no"}, [], "text", None, {"lints": "none"}):
        result = judged(answer)
        assert result.status == ("PASS" if answer == [] else "ERROR"), answer


def test_advisors_ignore_must_look_like_lint_names(tmp_path):
    config = tmp_path / "webcare.toml"
    base = 'name = "t"\nenv = "staging"\ndata = "synthetic"\n'
    config.write_text(f'[[target]]\n{base}advisors_ignore = ["rls_enabled_no_policy"]\n')
    assert load_targets(config)["t"].advisors_ignore == ("rls_enabled_no_policy",)
    config.write_text(f'[[target]]\n{base}advisors_ignore = ["Not A Lint; drop table"]\n')
    with pytest.raises(Refusal):
        load_targets(config)
