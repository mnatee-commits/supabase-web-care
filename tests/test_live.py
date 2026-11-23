import pytest

from webcare import live
from webcare.model import Refusal
from webcare.targets import get_target

psycopg = pytest.importorskip("psycopg")


def test_extra_checks_file_holds_only_selects():
    checks = live.load_extra_checks()
    assert [check.id for check in checks] == [
        "update_without_select",
        "auth_role_deprecated",
        "storage_upsert_incomplete",
        "secdef_trusts_current_user",
        "default_function_privileges",
        "default_function_privileges_platform",
        "default_table_privileges",
        "extension_net_callable",
        "extension_vault_reachable",
        "extension_cron_reachable",
        "realtime_table_without_rls",
        "realtime_messages_open",
        "realtime_messages_open_to_signed_in",
        "view_runs_as_owner",
        "schema_usable_but_unchecked",
        "matview_readable_by_api_roles",
    ]


@pytest.mark.parametrize(
    "sql",
    [
        "delete from public.orders",
        "select 1; drop table public.orders",
        "with gone as (delete from public.orders returning *) select * from gone",
        "select pg_catalog.set_config('x', 'y', false); select 1",
        "update public.orders set total = 0",
        "",
    ],
)
def test_non_select_statements_are_refused(sql):
    with pytest.raises(Refusal):
        live.assert_single_select(sql)


def test_keywords_inside_string_literals_are_allowed():
    live.assert_single_select("select 'UPDATE' as cmd, 'drop; it''s fine' as note")


def test_audit_role_is_accepted_and_reads_no_rows(pg):
    target = get_target(pg.config, "bad")
    connection, endpoint, facts = live.open_checked(target, pg.auditor_bad, False, False)
    try:
        assert endpoint.user == "webcare_auditor"
        assert not facts.privileged and facts.tx_read_only
        assert facts.relations_total > 0
        assert facts.relations_readable == 0 and facts.relations_writable == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("select count(*) from public.orders")
    finally:
        connection.close()


def test_session_is_read_only_even_for_an_administrator(pg):
    connection = live.connect(pg.admin_bad)
    try:
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            connection.execute("create table public.should_not_exist (id int)")
        connection.rollback()
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            connection.execute("delete from public.orders")
    finally:
        connection.close()


def test_privileged_role_is_refused_unless_overridden(pg):
    target = get_target(pg.config, "bad")
    with pytest.raises(Refusal, match="superuser"):
        live.open_checked(target, pg.admin_bad, False, False)
    connection, _, facts = live.open_checked(target, pg.admin_bad, False, True)
    connection.close()
    assert facts.privileged


def test_override_is_not_available_for_real_data(pg):
    for name in ("real-copy", "prod"):
        target = get_target(pg.config, name)
        with pytest.raises(Refusal, match="owner"):
            live.open_checked(target, pg.auditor_bad, False, False)
        with pytest.raises(Refusal, match="throwaway"):
            live.open_checked(target, pg.admin_bad, True, True)
    connection, _, _ = live.open_checked(get_target(pg.config, "real-copy"), pg.auditor_bad, True, False)
    connection.close()


def test_wrong_database_is_refused_before_connecting(pg):
    with pytest.raises(Refusal, match="Refusing to connect"):
        live.open_checked(get_target(pg.config, "good"), pg.auditor_bad, False, False)


def test_extra_checks_on_both_schemas(pg):
    def run(dsn):
        connection = live.connect(dsn)
        try:
            return live.run_extra_checks(connection, ["public"], "test")
        finally:
            connection.close()

    bad = run(pg.auditor_bad)
    assert bad.status == "FINDINGS"
    assert {(f.rule, f.location) for f in bad.findings} == {
        ("update_without_select", "public.docs.docs_update_own"),
        ("auth_role_deprecated", "public.tickets.tickets_signed_in"),
        ("storage_upsert_incomplete", "storage.objects (role authenticated)"),
        ("view_runs_as_owner", "public.orders_view"),  # a view anon reads, without security_invoker
    }
    good = run(pg.auditor_good)
    assert good.status == "PASS" and not good.findings


def test_anon_readable_relations_come_from_grants(pg):
    connection = live.connect(pg.auditor_bad)
    try:
        assert live.anon_readable_relations(connection, "public") == ["notes", "orders_view", "tickets"]
        assert live.schema_exists(connection, "storage")
        assert not live.schema_exists(connection, "no_such_schema")
    finally:
        connection.close()


def _open(pg, name, dsn):
    target = get_target(pg.config, name)
    connection, _endpoint, _facts = live.open_checked(target, dsn, False, False)
    return target, connection


def _by_rule(result):
    grouped = {}
    for finding in result.findings:
        grouped.setdefault(finding.rule, []).append(finding)
    return grouped


def test_functions_open_to_anon_are_reported_with_the_route(pg):
    target, connection = _open(pg, "fbad", pg.auditor_fbad)
    try:
        result = live.run_function_exposure(connection, target, "test")
    finally:
        connection.close()
    found = {f.location: f for f in _by_rule(result)["secdef_anon_executable"]}
    assert set(found) == {
        "public.list_everything()",
        "public.report_everything()",
        "public.worker_only()",
    }
    # No allowlist declared yet, so these still need triage: medium, not high.
    assert {f.severity for f in found.values()} == {"medium"}
    assert "gives to PUBLIC" in found["public.report_everything()"].message
    assert "directly to anon" in found["public.worker_only()"].message
    assert result.status == "FINDINGS"
    assert any("declares no expected_anon_functions" in note for note in result.notes)


def test_declared_public_functions_are_quiet_and_new_ones_are_high(pg):
    target, connection = _open(pg, "fgood", pg.auditor_fgood)
    try:
        clean = live.run_function_exposure(connection, target, "test")
    finally:
        connection.close()
    assert clean.status == "PASS" and not clean.findings

    target, connection = _open(pg, "fgood-undeclared", pg.auditor_fgood)
    try:
        undeclared = live.run_function_exposure(connection, target, "test")
    finally:
        connection.close()
    assert [f.location for f in undeclared.findings] == ["public.site_banner()"]


def test_allowlist_entries_that_match_nothing_are_reported(pg):
    target, connection = _open(pg, "fgood-stale", pg.auditor_fgood)
    try:
        result = live.run_function_exposure(connection, target, "test")
    finally:
        connection.close()
    grouped = _by_rule(result)
    assert "secdef_anon_executable" not in grouped  # the bare name matched site_banner
    missing = grouped["expected_anon_function_missing"]
    assert [f.location for f in missing] == ["public.retired_page(text, uuid)"]
    assert missing[0].severity == "low"


def test_an_allowlist_makes_unlisted_functions_high(pg, tmp_path):
    config = tmp_path / "webcare.toml"
    declared = get_target(pg.config, "fbad")
    config.write_text(
        f'[[target]]\nname = "fbad"\nenv = "local"\ndata = "synthetic"\ndb = "{declared.db}"\n'
        'expected_anon_functions = ["public.list_everything()"]\n'
    )
    target = get_target(config, "fbad")
    connection, _endpoint, _facts = live.open_checked(target, pg.auditor_fbad, False, False)
    try:
        result = live.run_function_exposure(connection, target, "test")
    finally:
        connection.close()
    grouped = _by_rule(result)
    assert {f.location: f.severity for f in grouped["secdef_anon_executable"]} == {
        "public.report_everything()": "high",
        "public.worker_only()": "high",
    }
    # Allowed for anon, but still open to every role through PUBLIC.
    assert [f.location for f in grouped["secdef_public_execute"]] == ["public.list_everything()"]


def test_guard_that_trusts_current_user_and_default_privileges_are_found(pg):
    target, connection = _open(pg, "fbad", pg.auditor_fbad)
    try:
        result = live.run_extra_checks(connection, target.schemas, "test")
    finally:
        connection.close()
    grouped = _by_rule(result)
    assert [f.location for f in grouped["secdef_trusts_current_user"]] == ["private.guard()"]
    defaults = grouped["default_function_privileges"]
    assert len(defaults) == 1 and defaults[0].location.startswith("public (functions created by ")
    assert "anon, authenticated" in defaults[0].message
    assert "PUBLIC through the built-in default" in defaults[0].message
    assert "supabase_admin" not in defaults[0].location
    platform = grouped["default_function_privileges_platform"]
    assert [f.severity for f in platform] == ["info"] and "supabase_admin" in platform[0].location
    tables = grouped["default_table_privileges"]
    assert len(tables) == 1 and tables[0].location.startswith("public (tables created by ")
    assert "anon, authenticated" in tables[0].message and "service_role" not in tables[0].message
    assert tables[0].severity == "low"
    net = grouped["extension_net_callable"]
    assert sorted(f.location for f in net) == ["schema net (role anon)", "schema net (role authenticated)"]
    assert net[0].severity == "medium" and "http_post" in net[0].message
    vault = grouped["extension_vault_reachable"]
    assert [(f.location, f.severity) for f in vault] == [("schema vault (role authenticated)", "high")]
    assert "decrypted_secrets" in vault[0].message
    cron = grouped["extension_cron_reachable"]
    assert [f.location for f in cron] == ["schema cron (role authenticated)"] and "schedule" in cron[0].message
    assert [(f.location, f.severity) for f in grouped["realtime_table_without_rls"]] == [("public.live_feed", "high")]
    assert sorted(f.location for f in grouped["realtime_messages_open"]) == [
        "realtime.messages.anyone_listens", "realtime.messages.anyone_sends"]
    assert [f.location for f in grouped["realtime_messages_open_to_signed_in"]] == ["realtime.messages.members_all"]
    assert [f.location for f in grouped["matview_readable_by_api_roles"]] == ["public.cached_totals"]
    assert [f.location for f in grouped["view_runs_as_owner"]] == ["public.owner_view"]
    assert "public.invoker_view" not in " ".join(f.location for f in grouped["view_runs_as_owner"])
    assert "api_extra" in [f.location for f in grouped["schema_usable_but_unchecked"]]
    assert not any("could not run" in note for note in result.notes)


def test_comments_and_strings_naming_current_user_do_not_count(pg):
    target, connection = _open(pg, "fgood", pg.auditor_fgood)
    try:
        result = live.run_extra_checks(connection, target.schemas, "test")
    finally:
        connection.close()
    grouped = _by_rule(result)
    assert "secdef_trusts_current_user" not in grouped
    assert "default_function_privileges" not in grouped
    assert "default_table_privileges" not in grouped
    assert not any(rule.startswith(("extension_", "realtime_", "view_runs")) for rule in grouped)
    assert not any("could not run" in note for note in result.notes)
