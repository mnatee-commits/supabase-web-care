import json
import shutil

from conftest import FIXTURES
from webcare import edge_functions
from webcare.cli import main

EDGE = FIXTURES / "edge"


def by_function(result):
    found = {}
    for finding in result.findings:
        name = finding.message.split()[1].rstrip(":")
        found.setdefault(name, []).append((finding.rule, finding.severity))
    return found


def test_each_kind_of_function_is_judged_from_its_files():
    result = edge_functions.run([EDGE])
    assert result.status == "FINDINGS" and "6 Edge Functions" in result.evidence
    found = by_function(result)
    # verify_jwt off, service role, and the only "check" is inside a comment
    assert found["open-hook"] == [("edge_open_to_anyone", "high")]
    # verify_jwt off, but the webhook signature is checked
    assert found["stripe-hook"] == [("edge_verify_jwt_off", "info")]
    # not in config.toml: the platform checks the JWT, yet any signed-in user gets full rights;
    # the wildcard origin comes from the shared file it imports
    assert found["admin-task"] == [("edge_service_role_no_caller_check", "medium"), ("edge_cors_any_origin", "low")]
    # asks who the caller is before using the service role, and names its origin
    assert "whoami" not in found
    # imports corsHeaders from a helper file that also holds an unused requireUser(): not a check
    assert found["export-all"] == [("edge_service_role_no_caller_check", "medium")]
    # calls the helper's guard under another name: that is a check
    assert "my-profile" not in found
    assert any("admin-task" in note and "not named in config.toml" in note for note in result.notes)
    assert any("--no-verify-jwt" in note for note in result.notes)


def test_locations_point_at_the_line(monkeypatch):
    monkeypatch.chdir(EDGE)
    result = edge_functions.run([EDGE])
    locations = {finding.rule: finding.location for finding in result.findings}
    assert locations["edge_open_to_anyone"] == "supabase/functions/open-hook/index.ts:5"
    # code in a shared file is reported at the line that imports it, and named in the message
    assert locations["edge_cors_any_origin"] == "supabase/functions/admin-task/index.ts:2"
    cors = next(f for f in result.findings if f.rule == "edge_cors_any_origin")
    assert "(in supabase/functions/_shared/cors.ts:3)" in cors.message


def test_no_functions_is_not_run_and_a_missing_folder_is_an_error(tmp_path):
    assert edge_functions.run([tmp_path]).status == "NOT_RUN"
    result = edge_functions.run([tmp_path], [tmp_path / "nowhere"])
    assert result.status == "ERROR" and "not found" in result.reason


def test_a_folder_named_on_purpose_is_read_without_a_config(tmp_path):
    shutil.copytree(EDGE / "supabase" / "functions" / "admin-task", tmp_path / "edge" / "admin-task")
    result = edge_functions.run([tmp_path], [tmp_path / "edge"])
    assert [f.rule for f in result.findings] == ["edge_service_role_no_caller_check"]
    assert any("no supabase/config.toml" in note for note in result.notes)


def test_a_credential_read_without_a_verifying_call_is_low(tmp_path):
    folder = tmp_path / "supabase" / "functions" / "f"
    folder.mkdir(parents=True)
    (folder / "index.ts").write_text(
        'const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");\n'
        'Deno.serve((req) => { const t = req.headers.get("authorization"); return new Response(t); });\n')
    result = edge_functions.run([tmp_path])
    assert [(f.rule, f.severity) for f in result.findings] == [("edge_service_role_no_caller_check", "low")]


def test_only_changed_functions_trigger_the_check(tmp_path):
    other = (tmp_path / "x.ts").resolve()
    assert edge_functions.run([EDGE], changed={other}, changed_since="HEAD").status == "NOT_RUN"
    touched = (EDGE / "supabase" / "config.toml").resolve()
    assert edge_functions.run([EDGE], changed={touched}, changed_since="HEAD").status == "FINDINGS"


def test_check_command_reports_edge_functions_and_focus_takes_it(tmp_path):
    out = tmp_path / "o"
    code = main(["check", "--repo", str(EDGE), "--skip", "secrets", "--out-dir", str(out), "--lang", "th"])
    report = json.loads((out / "report.json").read_text())
    edge = next(check for check in report["checks"] if check["id"] == "edge_functions")
    assert code == 1 and edge["status"] == "FINDINGS"
    assert report["summary"]["first"][0]["rule"] == "edge_open_to_anyone"
    assert "ปิดการตรวจ JWT" in (out / "report.md").read_text()
    out = tmp_path / "f"
    main(["check", "--repo", str(EDGE), "--focus", "edge", "--out-dir", str(out)])
    statuses = {c["id"]: c["status"] for c in json.loads((out / "report.json").read_text())["checks"]}
    assert statuses["edge_functions"] == "FINDINGS" and statuses["secrets"] == "NOT_RUN"


def test_sarif_points_at_the_function_file(tmp_path, monkeypatch):
    monkeypatch.chdir(EDGE)
    main(["check", "--repo", ".", "--skip", "secrets", "--sarif", "--out-dir", str(tmp_path)])
    results = json.loads((tmp_path / "report.sarif").read_text())["runs"][0]["results"]
    spots = {r["ruleId"]: r["locations"][0]["physicalLocation"] for r in results if r.get("locations")}
    place = spots["edge_functions/edge_open_to_anyone"]
    assert place["artifactLocation"]["uri"] == "supabase/functions/open-hook/index.ts" and place["region"]["startLine"] == 5


def test_config_reaches_a_folder_named_on_purpose_when_supabase_functions_is_absent(tmp_path):
    (tmp_path / "supabase").mkdir()
    (tmp_path / "supabase" / "config.toml").write_text("[functions.open-hook]\nverify_jwt = false\n")
    shutil.copytree(EDGE / "supabase" / "functions" / "open-hook", tmp_path / "edge" / "open-hook")
    result = edge_functions.run([tmp_path], [tmp_path / "edge"])
    assert [(f.rule, f.severity) for f in result.findings] == [("edge_open_to_anyone", "high")]


def test_two_functions_sharing_a_helper_never_share_a_location(tmp_path):
    from webcare import baseline

    shared = tmp_path / "supabase" / "functions"
    shutil.copytree(EDGE / "supabase" / "functions" / "_shared", shared / "_shared")
    for name in ("first", "second"):
        shutil.copytree(EDGE / "supabase" / "functions" / "admin-task", shared / name)
    result = edge_functions.run([tmp_path])
    keys = [baseline.key("edge_functions", f.rule, f.location) for f in result.findings]
    assert len(keys) == 4 and len(set(keys)) == 4
