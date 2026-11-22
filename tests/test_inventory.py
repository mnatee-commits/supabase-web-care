import json
import re

import pytest

from webcare import inventory, live
from webcare.cli import main
from webcare.model import Refusal


def _without_md5_calls(sql: str) -> str:
    """The statement with every md5(...) call removed, parentheses balanced."""
    out, i = [], 0
    while True:
        start = sql.find("md5(", i)
        if start < 0:
            return "".join(out) + sql[i:]
        out.append(sql[i:start])
        depth, j = 0, start + 3
        while True:
            depth += {"(": 1, ")": -1}.get(sql[j], 0)
            j += 1
            if depth == 0:
                break
        i = j


def test_every_statement_is_one_select_and_bodies_and_expressions_leave_only_as_hashes():
    for sql in inventory.statements(["public", "private"]):
        live.assert_single_select(sql)
        rest = _without_md5_calls(sql)
        for column in ("prosrc", "qual", "with_check"):
            assert not re.search(rf"\b{column}\b", rest), f"{column} is read outside md5() in: {sql[:80]}"
    assert "md5(p.prosrc)" in "".join(inventory.statements(["public"]))
    with pytest.raises(Refusal):
        inventory.collect(lambda sql: None, type("T", (), {"schemas": ("Public; drop",), "name": "t", "project_ref": None})())


def inv(label, **parts):
    return {"format": inventory.FORMAT, "label": label, "project_ref": None, "taken_at": "t",
            "parts": {name: ({"rows": rows} if isinstance(rows, dict) else {"not_read": rows})
                      for name, rows in parts.items()}}


def test_compare_reports_keys_on_one_side_and_fields_that_differ():
    first = inv("staging",
                migrations={"1": "a", "2": "name_hash"},
                tables={"public.t": {"rls": True, "grants": {"authenticated": ["INSERT"]}}},
                column_grants={"public.t.id": {"authenticated": ["SELECT"]}},
                cron_jobs={"nightly": {"schedule": "0 1 * * *", "active": True}},
                buckets="no storage.buckets table")
    second = inv("trial",
                 migrations={"1": "a"},
                 tables={"public.t": {"rls": True, "grants": {"authenticated": ["INSERT", "SELECT", "UPDATE"]}}},
                 column_grants={},
                 cron_jobs={},
                 buckets={})
    result = inventory.compare(first, second)
    assert result["migrations"]["only_first"] == ["2"] and result["migrations"]["same"] == 1
    assert result["tables"]["changed"]["public.t"] == [
        'grants.authenticated: ["INSERT"] → ["INSERT", "SELECT", "UPDATE"]'
    ]
    assert result["column_grants"]["only_first"] == ["public.t.id"]
    assert result["cron_jobs"]["only_first"] == ["nightly"]
    assert "staging: no storage.buckets table" in result["buckets"]["not_compared"]
    assert "not in the file" in result["functions"]["not_compared"]
    assert inventory.differences(result) == 4
    markdown = inventory.to_markdown(first, second, result, "th")
    assert "# เทียบบัญชีรายการสองฐาน" in markdown and "`public.t`" in markdown
    assert inventory.differences(inventory.compare(first, first)) == 0


def test_a_long_list_is_cut_in_the_markdown_but_kept_in_the_result():
    many = {f"public.t{i}": {"rls": True} for i in range(150)}
    result = inventory.compare(inv("a", tables=many), inv("b", tables={}))
    markdown = inventory.to_markdown(inv("a"), inv("b"), result)
    assert len(result["tables"]["only_first"]) == 150 and "and 90 more" in markdown


def test_files_that_are_not_inventories_are_refused(tmp_path):
    path = tmp_path / "x.json"
    for content in ("not json", "[]", json.dumps({"format": "other", "parts": {}})):
        path.write_text(content)
        with pytest.raises(Refusal):
            inventory.load(path)


def test_inventory_and_compare_against_two_databases(pg, tmp_path, monkeypatch, capsys):
    files = {}
    for name, dsn in (("bad", pg.auditor_bad), ("good", pg.auditor_good)):
        monkeypatch.setenv("WEBCARE_DATABASE_URL", dsn)
        out = tmp_path / f"{name}.json"
        assert main(["inventory", "--target", name, "--config", str(pg.config), "--out", str(out)]) == 0
        files[name] = out
    data = json.loads(files["bad"].read_text())
    assert data["parts"]["tables"]["rows"] and data["parts"]["functions"]["rows"] is not None
    assert "supabase_migrations" in data["parts"]["migrations"]["not_read"]
    assert "not installed" in data["parts"]["cron_jobs"]["not_read"]
    text = files["bad"].read_text()
    assert "auth.uid()" not in text  # policy expressions and function bodies stay in the database

    out_dir = tmp_path / "cmp"
    assert main(["compare", str(files["bad"]), str(files["good"]), "--out-dir", str(out_dir)]) == 1
    result = json.loads((out_dir / "compare.json").read_text())["parts"]
    assert inventory.differences(result) > 0
    assert main(["compare", str(files["bad"]), str(files["bad"]), "--out-dir", str(out_dir)]) == 0
    assert "0 differences" in capsys.readouterr().out
