import pytest

from webcare import live, table_writes
from webcare.model import CheckResult, Refusal
from webcare.targets import Target, load_targets


def row(table, role="authenticated", writes=("insert", "update", "delete"), rls=True, kind="r",
        columns_only=(), truncate=False, invoker=False):
    return {"table_name": table, "role": role, "writes": list(writes), "rls": rls, "kind": kind,
            "columns_only": list(columns_only), "may_truncate": truncate, "security_invoker": invoker}


def judged(*rows, declared=None):
    pairs = tuple((role, tuple(entries)) for role, entries in (declared or {}).items())
    target = Target(name="t", env="staging", data="synthetic", table_writes=pairs)
    report = {"format": table_writes.FORMAT, "taken_at": "now", "roles": ["anon", "authenticated"],
              "tables": list(rows)}
    return table_writes.judge(CheckResult(id="table_writes", title=table_writes.TITLE), report, target)


def found(result):
    return {(f.rule, f.severity, f.location) for f in result.findings}


def test_the_statement_is_one_select_that_reads_privileges_only():
    sql = table_writes.build_sql(["public", "app's"])
    live.assert_single_select(sql)
    assert "'app''s'" in sql and "has_table_privilege" in sql
    assert "pg_policies" not in sql and "polqual" not in sql


def test_nothing_writable_passes():
    assert judged().status == "PASS"


def test_without_a_declaration_each_role_gets_one_summary():
    result = judged(row("public.a"), row("public.b", role="anon", writes=("insert",)))
    assert found(result) == {
        ("authenticated_writes_not_declared", "low", "role authenticated"),
        ("anon_writes_not_declared", "medium", "role anon"),
    }


def test_a_write_without_rls_is_always_reported_by_table():
    result = judged(row("public.open", role="anon", rls=False), row("public.mine", rls=False))
    assert found(result) == {
        ("anon_write_without_rls", "high", "public.open"),
        ("authenticated_write_without_rls", "medium", "public.mine"),
    }


def test_declared_writes_pass_and_extra_commands_are_reported():
    declared = {"authenticated": ["public.notes", "profiles:update"], "anon": ["public.feedback:insert"]}
    result = judged(
        row("public.notes"),
        row("public.profiles", writes=("update",), columns_only=("update",)),
        row("public.feedback", role="anon", writes=("insert",)),
        declared=declared,
    )
    assert result.status == "PASS"
    result = judged(row("public.profiles", writes=("update", "delete")), row("public.other", role="anon"),
                    declared=declared)
    assert found(result) == {
        ("authenticated_write_undeclared", "low", "public.profiles"),
        ("anon_write_undeclared", "medium", "public.other"),
    }
    assert any("cannot write to" in note and "public.notes" in note for note in result.notes)


def test_columns_only_and_truncate_are_named():
    result = judged(row("public.p", writes=("update",), columns_only=("update",), truncate=True),
                    declared={"authenticated": ["public.q"]})
    assert "update (some columns)" in result.findings[0].message
    assert any("TRUNCATE ignores RLS" in note for note in result.notes)
    anon = judged(row("public.p", role="anon", writes=(), truncate=True))
    assert found(anon) == {("anon_truncate", "low", "role anon")}


def test_a_declared_table_with_rls_off_is_still_reported():
    result = judged(row("public.notes", rls=False), declared={"authenticated": ["public.notes"]})
    assert found(result) == {("authenticated_write_without_rls", "medium", "public.notes")}


def test_views_and_foreign_tables_are_judged_by_what_guards_them():
    owner_view = judged(row("public.v", role="anon", kind="v", rls=False), declared={"anon": ["public.v"]})
    assert found(owner_view) == {("anon_write_without_rls", "high", "public.v")}
    assert "security_invoker" in owner_view.findings[0].message
    invoker_view = judged(row("public.v", kind="v", rls=False, invoker=True), declared={"authenticated": ["public.v"]})
    assert invoker_view.status == "PASS"
    foreign = judged(row("public.f", kind="f", rls=False))
    assert "foreign table cannot have RLS" in foreign.findings[0].message


def test_target_file_entries_are_validated(tmp_path):
    base = '[[target]]\nname = "s"\nenv = "staging"\ndata = "synthetic"\n'
    good = tmp_path / "good.toml"
    good.write_text(base + 'expected_table_writes = { authenticated = ["public.Notes:insert,update"] }\n')
    assert load_targets(good)["s"].expected_table_writes == {"authenticated": ("public.notes:insert,update",)}
    for bad in ('{ service_role = ["a"] }', '{ anon = "a" }', '{ anon = ["a:select"] }', '["a"]'):
        path = tmp_path / "bad.toml"
        path.write_text(base + f"expected_table_writes = {bad}\n")
        with pytest.raises(Refusal):
            load_targets(path)


def test_against_the_test_database(pg):
    import psycopg

    targets = load_targets(pg.config)
    with psycopg.connect(pg.auditor_bad) as connection:
        result = table_writes.run_on_connection(connection, targets["bad"], "test database")
    assert result.status in ("PASS", "FINDINGS"), result.reason
    assert result.notes[-1].endswith("privileges only, no row read")
