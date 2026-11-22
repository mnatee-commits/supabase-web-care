import json

import pytest

from conftest import ROOT
from webcare import live, snapshot
from webcare.cli import main
from webcare.model import Refusal
from webcare.targets import Target, get_target


def make_snapshot(**overrides) -> dict:
    data = {
        "format": snapshot.FORMAT,
        "label": "staging",
        "taken_at": "2026-01-02T03:04:05Z",
        "server_version": "17.0",
        "database": "postgres",
        "schemas": ["public"],
        "anon_role_exists": True,
        "definer_functions": [
            {"schema_name": "public", "function_name": "site_banner", "arg_types": "",
             "public_may": False, "anon_may": True},
            {"schema_name": "public", "function_name": "report", "arg_types": "text, uuid",
             "public_may": True, "anon_may": True},
            {"schema_name": "public", "function_name": "staff_only", "arg_types": "",
             "public_may": False, "anon_may": False},
        ],
        "anon_readable": {"public": ["notes"]},
        "extra": {
            "update_without_select": [],
            "auth_role_deprecated": [],
            "storage_upsert_incomplete": [],
            "secdef_trusts_current_user": [
                {"location": "private.guard()", "detail": "the body reads current_user"}
            ],
            "default_function_privileges": [],
            "default_function_privileges_platform": [],
            "default_table_privileges": [],
        },
    }
    data.update(overrides)
    return data


def write(tmp_path, data, name="snap.json"):
    path = tmp_path / name
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


def target(name="staging", **fields) -> Target:
    return Target(name=name, env="staging", data="synthetic", **fields)


def test_committed_statement_matches_the_generator_and_is_one_select():
    text = (ROOT / "sql" / "catalog-snapshot.sql").read_text()
    assert text == snapshot.build_sql(("public",), snapshot.DEFAULT_LABEL)
    body = "\n".join(line for line in text.splitlines() if not line.strip().startswith("--"))
    live.assert_single_select(body)
    for check in live.load_extra_checks():
        assert f"'{check.id}'" in text  # every live catalog check travels in the snapshot
    assert "prosrc" not in text.replace("p.prosrc,\n", "")  # bodies are tested, never returned


@pytest.mark.parametrize("schemas, label", [
    (["public; drop table x"], "ok"),
    (["Public"], "ok"),
    ([], "ok"),
    (["public"], "bad label"),
    (["public"], "x'y"),
])
def test_statement_refuses_names_it_cannot_write_safely(schemas, label):
    with pytest.raises(Refusal):
        snapshot.build_sql(schemas, label)


def test_load_accepts_the_wrappers_tools_put_around_the_result(tmp_path):
    data = make_snapshot()
    for index, wrapped in enumerate([
        data,
        [{"snapshot": data}],
        {"snapshot": json.dumps(data)},
        json.dumps(json.dumps(data)),
    ]):
        assert snapshot.load(write(tmp_path, wrapped, f"s{index}.json"))["label"] == "staging"


@pytest.mark.parametrize("content", [
    "not json",
    json.dumps({"format": "something-else"}),
    json.dumps([{"other": 1}]),
    json.dumps({**make_snapshot(), "definer_functions": [{"function_name": "x"}]}),
    json.dumps({k: v for k, v in make_snapshot().items() if k != "extra"}),
])
def test_load_refuses_files_that_are_not_snapshots(tmp_path, content):
    with pytest.raises(Refusal):
        snapshot.load(write(tmp_path, content))


def test_snapshot_is_judged_like_a_live_catalog(tmp_path):
    path = write(tmp_path, make_snapshot())
    data = snapshot.load(path)
    extra, functions = snapshot.run_checks(data, path, target())
    assert [f.rule for f in extra.findings] == ["secdef_trusts_current_user"]
    assert "labelled 'staging'" in extra.evidence and "was not verified" in extra.evidence
    found = {f.location: (f.rule, f.severity) for f in functions.findings}
    assert found == {
        "public.site_banner()": ("secdef_anon_executable", "medium"),
        "public.report(text, uuid)": ("secdef_anon_executable", "medium"),
    }

    allowed = target(expected_anon_functions=("public.site_banner()", "public.gone()"))
    _extra, functions = snapshot.run_checks(data, path, allowed)
    assert {f.location: (f.rule, f.severity) for f in functions.findings} == {
        "public.report(text, uuid)": ("secdef_anon_executable", "high"),
        "public.gone()": ("expected_anon_function_missing", "low"),
    }


def test_snapshot_from_an_older_statement_says_what_it_could_not_judge(tmp_path):
    data = make_snapshot()
    del data["extra"]["default_function_privileges"]
    path = write(tmp_path, data)
    extra, _functions = snapshot.run_checks(snapshot.load(path), path, None)
    assert any("default_function_privileges: not in this snapshot" in note for note in extra.notes)


def test_a_snapshot_is_only_judged_against_the_target_it_names(tmp_path):
    data = make_snapshot()
    snapshot.ensure_matches(data, target("staging"))
    with pytest.raises(Refusal, match="labelled 'staging' but the target is 'production'"):
        snapshot.ensure_matches(data, target("production"))
    with pytest.raises(Refusal, match="default label"):
        snapshot.ensure_matches(make_snapshot(label=snapshot.DEFAULT_LABEL), target("staging"))
    with pytest.raises(Refusal, match="private"):
        snapshot.ensure_matches(data, target("staging", schemas=("public", "private")))


def run_cli(tmp_path, capsys, *arguments):
    out = tmp_path / "out"
    code = main(["check", "--skip", "secrets", "--skip", "static", "--out-dir", str(out), *arguments])
    capsys.readouterr()
    report = json.loads((out / "report.json").read_text())
    return code, {check["id"]: check for check in report["checks"]}, report


def test_check_from_a_snapshot_needs_no_database(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("WEBCARE_DATABASE_URL", raising=False)
    config = tmp_path / "webcare.toml"
    config.write_text(
        '[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\n'
        'expected_anon_functions = ["public.site_banner()"]\n'
    )
    path = write(tmp_path, [{"snapshot": make_snapshot()}])
    code, checks, report = run_cli(
        tmp_path, capsys, "--snapshot", str(path), "--target", "staging", "--config", str(config)
    )
    assert code == 1  # public.report is outside the allowlist: high
    assert checks["rls_live"]["status"] == "NOT_RUN" and "pgrls needs a database" in checks["rls_live"]["reason"]
    assert checks["extra_live"]["status"] == "FINDINGS"
    assert checks["functions_live"]["status"] == "FINDINGS"
    assert checks["anon_probe"]["status"] == "NOT_RUN"
    assert "snapshot" in report["target"]

    # Wrong target: nothing is judged, and the run says so instead of passing.
    config.write_text(config.read_text().replace('name = "staging"', 'name = "production"').replace('env = "staging"', 'env = "production"'))
    code, checks, _report = run_cli(
        tmp_path, capsys, "--snapshot", str(path), "--target", "production", "--config", str(config)
    )
    assert code == 2
    assert checks["functions_live"]["status"] == "NOT_RUN"
    assert "labelled 'staging'" in checks["functions_live"]["reason"]


def test_snapshot_sql_command(tmp_path, capsys):
    assert main(["snapshot-sql", "--label", "staging", "--schema", "public", "--schema", "private"]) == 0
    text = capsys.readouterr().out
    assert "'label', 'staging'" in text and "array['public', 'private']::text[]" in text
    assert main(["snapshot-sql"]) == 2
    assert main(["snapshot-sql", "--label", "bad label"]) == 2
    config = tmp_path / "webcare.toml"
    config.write_text('[[target]]\nname = "trial"\nenv = "production"\ndata = "real"\nschemas = ["public", "app"]\n')
    capsys.readouterr()
    assert main(["snapshot-sql", "--target", "trial", "--config", str(config)]) == 0
    text = capsys.readouterr().out
    assert "'label', 'trial'" in text and "array['public', 'app']::text[]" in text


def take(dsn, label):
    connection = live.connect(dsn)  # read-only session, as the audit role
    try:
        return connection.execute(snapshot.build_sql(("public",), label)).fetchone()["snapshot"]
    finally:
        connection.close()


def test_snapshot_taken_by_the_audit_role_gives_the_same_findings_as_a_live_run(pg, tmp_path):
    for name, dsn in (("fbad", pg.auditor_fbad), ("fgood", pg.auditor_fgood)):
        declared = get_target(pg.config, name)
        path = write(tmp_path, json.dumps([{"snapshot": take(dsn, name)}], default=str), f"{name}.json")
        data = snapshot.load(path)
        snapshot.ensure_matches(data, declared)
        from_file = snapshot.run_checks(data, path, declared)

        connection, _endpoint, _facts = live.open_checked(declared, dsn, False, False)
        try:
            from_live = [
                live.run_extra_checks(connection, declared.schemas, "live"),
                live.run_function_exposure(connection, declared, "live"),
            ]
        finally:
            connection.close()
        for file_result, live_result in zip(from_file, from_live):
            assert file_result.id == live_result.id and file_result.status == live_result.status
            key = lambda f: (f.rule, f.severity, f.location, f.message)  # noqa: E731
            assert sorted(map(key, file_result.findings)) == sorted(map(key, live_result.findings))
        assert not any("not in this snapshot" in note for note in from_file[0].notes)

    bad = snapshot.load(tmp_path / "fbad.json")
    assert len(bad["definer_functions"]) == 4 and bad["anon_role_exists"] is True
    text = (tmp_path / "fbad.json").read_text()
    assert "ACCESS_DENIED" not in text and "raise exception" not in text  # no function bodies


def test_snapshot_lists_relations_anon_may_read(pg, tmp_path):
    data = take(pg.auditor_bad, "bad")
    assert "notes" in data["anon_readable"]["public"]
