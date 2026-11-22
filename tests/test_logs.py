from datetime import datetime, timezone

from webcare import live, logs
from webcare.model import CheckResult
from webcare.targets import Target

REF = "abcdefghijklmnopqrst"


def row(target="", status=200, requests=1, service="rest", key_kind="public", signed_in=0, method="POST"):
    return {"service": service, "target": target, "method": method, "status": str(status),
            "key_kind": key_kind, "signed_in": signed_in, "requests": requests}


def judged(*rows, expected=()):
    target = Target(name="t", env="staging", data="synthetic", project_ref=REF, expected_anon_functions=tuple(expected))
    result = CheckResult(id="health_logs", title=logs.TITLE)
    return logs.judge(result, {"result": list(rows)}, target, "start", "end")


def found(result):
    return {(f.rule, f.severity, f.location) for f in result.findings}


def test_the_query_is_one_select_and_asks_for_nothing_personal():
    live.assert_single_select(logs.SQL)
    lowered = logs.SQL.lower()
    for word in ("ip", "user_agent", "referer", "search", "email", "cf_", "x_forwarded", "body"):
        assert word not in lowered.replace("multiif", "").replace("description", ""), word
    assert "payload.subject'] = ''" in logs.SQL  # used only as signed in / not signed in
    assert logs.window(datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)) == (
        "2026-01-01T03:04:00Z", "2026-01-02T03:04:00Z"
    )


def test_a_quiet_log_passes_and_states_what_was_not_read():
    result = judged(row("profiles", method="GET", signed_in=1, requests=500), row("", 400, 20, service="auth"))
    assert result.status == "PASS"
    assert "520 requests" in result.notes[0] and "no IP address" in result.notes[1]


def test_anonymous_function_calls_are_judged_against_the_allowlist():
    rows = (row("rpc/site_banner", requests=9), row("rpc/admin_tool", requests=2),
            row("rpc/admin_tool", 401, 4), row("rpc/internal", key_kind="secret"), row("rpc/mine", signed_in=1))
    assert found(judged(*rows, expected=["public.site_banner()"])) == {
        ("log_anon_rpc_unexpected", "medium", "rpc/admin_tool")
    }
    assert found(judged(*rows, expected=["site_banner", "public.admin_tool(text, uuid)"])) == set()
    undeclared = judged(*rows)
    assert undeclared.status == "PASS" and "2 functions were called successfully" in undeclared.notes[0]


def test_server_errors_and_refusals_have_thresholds():
    assert found(judged(row("orders", 500, 4, method="GET"))) == set()
    assert found(judged(row("orders", 500, 3), row("orders", 503, 2))) == {("log_server_errors", "low", "rest/orders")}
    assert found(judged(row("", 502, 60, service="functions"))) == {("log_server_errors", "medium", "functions")}
    assert found(judged(row("orders", 401, 30), row("orders", 403, 25))) == {("log_denied_burst", "low", "rest/orders")}
    assert found(judged(row("", 401, 600, service="auth"))) == {("log_denied_burst", "medium", "auth")}


def test_an_error_answer_or_a_truncated_one_is_said():
    target = Target(name="t", env="staging", data="synthetic", project_ref=REF)
    for answer in ({"result": [], "error": "bad query"}, {"error": {"code": 400}}, []):
        assert logs.judge(CheckResult(id="health_logs", title=logs.TITLE), answer, target, "a", "b").status == "ERROR"
    many = judged(*[row(f"t{i}", method="GET", signed_in=1) for i in range(logs.MAX_GROUPS)])
    assert any("largest groups" in note for note in many.notes)
