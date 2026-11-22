import pytest

from webcare import functions_static

pytest.importorskip("pglast")

DEFINER = "language sql security definer set search_path = '' as $$ select 1 $$"


def run(tmp_path, *files):
    paths = []
    for index, text in enumerate(files, start=1):
        path = tmp_path / f"{index:04d}_migration.sql"
        path.write_text(text)
        paths.append(path)
    return functions_static.run(paths)


def rules(result):
    return sorted((finding.rule, finding.location.split(" ")[0]) for finding in result.findings)


def test_revoking_from_anon_alone_leaves_the_function_open(tmp_path):
    result = run(
        tmp_path,
        f"create function public.report() returns int {DEFINER};\n"
        "revoke execute on function public.report() from anon;\n",
    )
    assert rules(result) == [("secdef_public_execute", "public.report")]
    finding = result.findings[0]
    assert finding.severity == "high" and "A REVOKE from anon does not close it" in finding.message
    assert finding.location == "public.report (0001_migration.sql:1)"
    assert result.status == "FINDINGS"


def test_revoking_from_public_alone_leaves_the_direct_anon_grant(tmp_path):
    result = run(
        tmp_path,
        f"create function public.worker() returns int {DEFINER};\n"
        "revoke all on function public.worker() from public;\n"
        "grant execute on function public.worker() to service_role;\n",
    )
    assert rules(result) == [("secdef_anon_not_revoked", "public.worker")]
    assert result.findings[0].severity == "medium"


def test_a_function_closed_properly_is_clean(tmp_path):
    result = run(
        tmp_path,
        "-- staff only\n\n"
        f"create or replace function app.staff_report(p_month text) returns int {DEFINER};\n"
        "revoke all on function app.staff_report(text) from public, anon;\n"
        "grant execute on function app.staff_report(text) to authenticated, service_role;\n",
    )
    assert result.status == "PASS" and not result.findings
    assert "1 functions defined, 1 of them SECURITY DEFINER" in result.evidence


def test_intended_public_function_is_listed_as_information_only(tmp_path):
    result = run(
        tmp_path,
        f"create function public.site_banner() returns int {DEFINER};\n"
        "revoke all on function public.site_banner() from public;\n"
        "grant execute on function public.site_banner() to anon, authenticated;\n",
    )
    assert rules(result) == [("secdef_anon_granted", "public.site_banner")]
    assert result.status == "PASS"  # an inventory entry, not a problem


def test_missing_search_path_and_fix_by_alter(tmp_path):
    create = (
        "create function public.lookup() returns int language sql security definer "
        "as $$ select 1 $$;\nrevoke all on function public.lookup() from public, anon;\n"
    )
    assert rules(run(tmp_path, create)) == [("secdef_no_search_path", "public.lookup")]
    fixed = run(tmp_path, create, "alter function public.lookup() set search_path = '';\n")
    assert fixed.status == "PASS"
    reset = run(
        tmp_path, create, "alter function public.lookup() set search_path = '';\n",
        "alter function public.lookup() reset search_path;\n",
    )
    assert rules(reset) == [("secdef_no_search_path", "public.lookup")]


def test_invoker_functions_are_ignored_until_made_definer(tmp_path):
    create = "create function public.plain() returns int language sql as $$ select 1 $$;\n"
    assert run(tmp_path, create).status == "PASS"
    result = run(tmp_path, create, "alter function public.plain() security definer;\n")
    assert rules(result) == [
        ("secdef_no_search_path", "public.plain"),
        ("secdef_public_execute", "public.plain"),
    ]


def test_revoke_on_all_functions_in_schema_covers_earlier_functions_only(tmp_path):
    result = run(
        tmp_path,
        f"create function app.early() returns int {DEFINER};\n"
        "revoke all on all functions in schema app from public, anon;\n"
        f"create function app.late() returns int {DEFINER};\n",
    )
    assert rules(result) == [("secdef_public_execute", "app.late")]


def test_replace_keeps_privileges_but_drop_and_create_resets_them(tmp_path):
    closed = (
        f"create function public.f() returns int {DEFINER};\n"
        "revoke all on function public.f() from public, anon;\n"
    )
    replaced = run(tmp_path, closed, f"create or replace function public.f() returns int {DEFINER};\n")
    assert replaced.status == "PASS"
    recreated = run(
        tmp_path, closed,
        f"drop function public.f();\ncreate function public.f() returns int {DEFINER};\n",
    )
    assert rules(recreated) == [("secdef_public_execute", "public.f")]
    assert "0002_migration.sql:2" in recreated.findings[0].location


def test_global_default_privileges_change_what_new_functions_get(tmp_path):
    result = run(
        tmp_path,
        "alter default privileges revoke execute on functions from public;\n"
        f"create function public.after_default() returns int {DEFINER};\n",
    )
    # PUBLIC is gone by default, but nothing was said about anon.
    assert rules(result) == [("secdef_anon_not_revoked", "public.after_default")]
    assert any("default privileges" in note for note in result.notes)

    scoped = run(
        tmp_path,
        "alter default privileges in schema public revoke execute on functions from public;\n"
        f"create function public.still_open() returns int {DEFINER};\n",
    )
    # A per-schema default cannot remove the built-in grant to PUBLIC.
    assert rules(scoped) == [("secdef_public_execute", "public.still_open")]


def test_unparseable_file_is_reported_and_the_rest_still_runs(tmp_path):
    result = run(
        tmp_path,
        "this is not sql at all (;\n",
        f"create function public.g() returns int {DEFINER};\n",
    )
    assert rules(result) == [("secdef_public_execute", "public.g")]
    assert any("0001_migration.sql" in note and "skipped" in note for note in result.notes)

    broken = run(tmp_path, "still not sql (;\n")
    assert broken.status == "ERROR" and "0001_migration.sql" in broken.reason


def test_the_same_mistake_outside_the_exposed_schema_is_low(tmp_path):
    result = run(tmp_path, f"create function private.helper() returns int {DEFINER};\n")
    assert [(f.rule, f.severity) for f in result.findings] == [("secdef_public_execute", "low")]
    assert "assumed not to be served by the API" in result.findings[0].message

    closed_for_public = run(
        tmp_path,
        f"create function private.helper() returns int {DEFINER};\n"
        "revoke all on function private.helper() from public;\n",
    )
    assert closed_for_public.status == "PASS"  # anon has no way into a private schema


def test_guard_that_reads_current_user_is_flagged_but_comments_and_strings_are_not(tmp_path):
    guard = (
        "create function private.guard() returns void language plpgsql security definer "
        "set search_path = '' as $$\nbegin\n  {line}\n  raise exception 'DENIED';\nend $$;\n"
        "revoke all on function private.guard() from public;\n"
    )
    bad = run(tmp_path, guard.format(line="if current_user in ('postgres') then return; end if;"))
    assert rules(bad) == [("secdef_trusts_current_user", "private.guard")]
    good = run(
        tmp_path,
        guard.format(
            line="-- current_user names the owner here\n  /* current_role too */\n"
            "  if session_user = 'postgres' then return; end if;\n"
            "  perform 'current_user is only text here';"
        ),
    )
    assert good.status == "PASS" and not good.findings


def test_do_blocks_are_called_out(tmp_path):
    result = run(tmp_path, "do $$ begin perform 1; end $$;\n")
    assert result.status == "PASS"
    assert any("DO block" in note for note in result.notes)


def test_overloads_are_kept_apart(tmp_path):
    # A second overload must not hide the first, and a REVOKE naming one overload
    # must not close the other; a statement with no argument list covers both.
    result = run(
        tmp_path,
        f"create function public.search(q integer) returns int {DEFINER};\n",
        "create function public.search(q text) returns int language sql as $$ select 1 $$;\n"
        "revoke all on function public.search(text) from public, anon;\n",
    )
    assert rules(result) == [("secdef_public_execute", "public.search")]
    assert "0001_migration.sql:1" in result.findings[0].location
    closed_one = run(
        tmp_path,
        f"create function public.search(q integer) returns int {DEFINER};\n"
        f"create function public.search(q text, out n int) returns int {DEFINER};\n"
        "revoke all on function public.search(int4) from public, anon;\n",
    )
    assert [f.location for f in closed_one.findings] == ["public.search (0001_migration.sql:2)"]
    closed_all = run(
        tmp_path,
        f"create function public.search(q integer) returns int {DEFINER};\n"
        f"create function public.search(q text) returns int {DEFINER};\n"
        "revoke all on function public.search from public, anon;\n",
    )
    assert closed_all.findings == []
    dropped = run(
        tmp_path,
        f"create function public.search(q integer) returns int {DEFINER};\n"
        f"create function public.search(q text) returns int {DEFINER};\n"
        "drop function public.search(text);\n",
    )
    assert [f.location for f in dropped.findings] == ["public.search (0001_migration.sql:1)"]
