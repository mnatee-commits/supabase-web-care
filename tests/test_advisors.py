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


def flat(name, objects, level="WARN"):
    """The shape the platform's endpoint answers with: one entry per flagged object."""
    return [{"name": name, "title": name.replace("_", " ").title(), "level": level, "description": "d",
             "metadata": {"schema": "public", "name": obj, "type": "table"}, "cache_key": f"{name}_{obj}"}
            for obj in objects]


def test_one_entry_per_object_is_counted_and_named_like_the_grouped_shape():
    answer = flat("rls_disabled_in_public", ["orders", "notes"], "ERROR") + flat("big_lint", [f"fn_{i}" for i in range(400)])
    result = judged(answer)
    assert rules(result) == {("rls_disabled_in_public", "high"), ("big_lint", "medium")}
    by = {f.rule: f.message for f in result.findings}
    assert "2 objects (for example public.orders, public.notes)" in by["rls_disabled_in_public"]
    assert "400 objects" in by["big_lint"] and "and 395 more" in by["big_lint"] and "fn_5" not in by["big_lint"]
    assert "2 kinds of lint returned, 402 objects" in result.notes[0]


def test_ignoring_a_lint_in_the_flat_shape_counts_every_entry():
    answer = flat("big_lint", [f"fn_{i}" for i in range(328)]) + flat("rls_disabled_in_public", ["orders"], "ERROR")
    result = judged(answer, ignore=["big_lint"])
    assert rules(result) == {("rls_disabled_in_public", "high")}
    assert "big_lint (328)" in " ".join(result.notes)


def test_both_shapes_in_one_answer_add_up():
    answer = [lint("mixed_lint", "WARN", count=3, names=["a", "b", "c"])] + flat("mixed_lint", ["d", "e"])
    result = judged(answer)
    assert len(result.findings) == 1 and "5 objects" in result.findings[0].message


def test_an_entry_without_metadata_still_counts():
    result = judged([{"name": "auth_leaked_password_protection", "level": "WARN", "title": "Leaked", "description": "off"}])
    assert "1 object." in result.findings[0].message and "for example" not in result.findings[0].message
