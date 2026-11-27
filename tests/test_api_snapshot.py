import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from test_snapshot import make_snapshot
from urllib.parse import parse_qs, urlsplit

from webcare import api_snapshot, auth_config, db_health, health, live, logs, snapshot, storage_buckets, table_writes
from webcare.cli import main
from webcare.model import Refusal
from webcare.targets import Target, get_target

REF = "abcdefghijklmnopqrst"
TOKEN = "sb" + "p_" + "0f" * 20  # shaped like an access token, built at run time
PATH = f"/v1/projects/{REF}/database/query/read-only"


class FakeManagementApi(BaseHTTPRequestHandler):
    seen: list = []
    mode = "ok"
    probe = {"format": health.PROBE_FORMAT, "role": "supabase_read_only_user", "installed": True,
             "readable": True, "row_security": True, "sees_every_row": True}
    jobs = [{"job_id": 1, "job_name": "nightly", "schedule": "0 18 * * *", "active": True,
             "runs": 7, "failed": 0, "last_start": "2026-01-01T18:00:00Z", "last_outcome": "succeeded"}]

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode()
        headers = {name.lower(): value for name, value in self.headers.items()}
        type(self).seen.append((self.command, self.path, headers, body))
        mode = type(self).mode
        if mode == "redirect":
            self.send_response(307)
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
            self.end_headers()
            return
        if mode.isdigit():
            self.send_response(int(mode))
            self.end_headers()
            self.wfile.write(json.dumps({"message": f"token {headers.get('authorization')}"}).encode())
            return
        query = json.loads(body)["query"]
        answer = None
        if health.PROBE_FORMAT in query:
            answer = [{"probe": type(self).probe}]
        elif f"'{storage_buckets.FORMAT}'" in query:
            answer = [{"storage": {"format": storage_buckets.FORMAT, "taken_at": "2026-01-02T00:00:00Z",
                                   "buckets": type(self).buckets, "unscoped_policies": []}}]
        elif f"'{db_health.FORMAT}'" in query:
            answer = [{"db_health": {"format": db_health.FORMAT, "taken_at": "2026-01-02T00:00:00Z",
                                     "sees_other_sessions": True, "database_xid_age": 1000,
                                     "invalid_indexes": [], "bloat": [], "xid_age": [],
                                     "idle_in_transaction": [], "lock_waits": [], "sequences": [],
                                     "sequences_unreadable": 0}}]
        elif f"'{table_writes.FORMAT}'" in query:
            answer = [{"table_writes": {"format": table_writes.FORMAT, "taken_at": "2026-01-02T00:00:00Z",
                                        "roles": ["anon", "authenticated"], "tables": []}}]
        elif f"'{health.FORMAT}'" in query:
            answer = [{"health": {"format": health.FORMAT, "taken_at": "2026-01-02T00:00:00Z",
                                  "window_days": 7, "jobs": type(self).jobs}}]
        if answer is not None:
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(answer).encode())
            return
        label = re.search(r"'label', '([^']+)'", query).group(1)
        if mode == "wrong_label":
            label = "something-else"
        payload = "not json" if mode == "garbage" else json.dumps([{"snapshot": make_snapshot(label=label)}])
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())

    def _unexpected(self):
        type(self).seen.append((self.command, self.path, {}, ""))
        self.send_response(500)
        self.end_headers()

    advisors = (
        [{"name": "rls_disabled_in_public", "title": "RLS Disabled in Public", "level": "ERROR", "facing": "EXTERNAL",
          "categories": ["SECURITY"], "description": "Table is public but RLS is not enabled.",
          "remediation": "https://supabase.com/docs/guides/database/database-linter?lint=0013_rls_disabled_in_public",
          "metadata": {"schema": "public", "name": name, "type": "table"}, "cache_key": f"rls_{name}"}
         for name in ("orders", "notes")]
        + [{"name": "authenticated_security_definer_function_executable", "title": "Signed-in users can execute",
            "level": "WARN", "facing": "EXTERNAL", "categories": ["SECURITY"],
            "description": "Functions run with the owner's privileges.", "remediation": "https://example.invalid/x",
            "metadata": {"schema": "public", "name": f"fn_{i}", "type": "function"}, "cache_key": f"fn_{i}"}
           for i in range(300)]
    )
    auth = {"disable_signup": False, "external_anonymous_users_enabled": False, "mailer_autoconfirm": False,
            "password_min_length": 6, "password_hibp_enabled": True, "mfa_totp_verify_enabled": True,
            "jwt_exp": 3600, "refresh_token_rotation_enabled": True, "security_captcha_enabled": True,
            "site_url": "https://app.example.com", "uri_allow_list": "https://app.example.com/**",
            "smtp_host": "MARKER-mail.example.com", "smtp_pass": "MARKER-smtp-pass",
            "external_google_secret": "MARKER-oauth", "security_captcha_secret": "MARKER-captcha",
            "hook_custom_access_token_secrets": "MARKER-hook", "sms_twilio_auth_token": "MARKER-sms",
            "smtp_user": "MARKER-user", "external_google_client_id": "MARKER-client"}
    buckets = [{"bucket": "files", "public": False, "policies": 1, "anon_commands": [],
                "has_size_limit": True, "has_type_list": False}]
    log_rows = [
        {"service": "rest", "target": "rpc/site_banner", "method": "POST", "status": "200",
         "key_kind": "public", "signed_in": 0, "requests": 40},
        {"service": "rest", "target": "rpc/admin_tool", "method": "POST", "status": "200",
         "key_kind": "public", "signed_in": 0, "requests": 3},
    ]
    backups = {"region": "x", "walg_enabled": False, "pitr_enabled": False, "physical_backup_data": {},
               "backups": []}

    def do_GET(self):
        headers = {name.lower(): value for name, value in self.headers.items()}
        type(self).seen.append((self.command, self.path, headers, ""))
        if urlsplit(self.path).path == f"/v1/projects/{REF}/analytics/endpoints/logs":
            status = 403 if type(self).mode == "logs_403" else 200
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"result": type(self).log_rows} if status == 200 else {"message": "no"}).encode())
            return
        if self.path in (f"/v1/projects/{REF}/ssl-enforcement", f"/v1/projects/{REF}/network-restrictions"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            answer = ({"currentConfig": {"database": False}, "appliedSuccessfully": True}
                      if self.path.endswith("ssl-enforcement") else
                      {"entitlement": "allowed", "config": {"dbAllowedCidrs": ["0.0.0.0/0"], "dbAllowedCidrsV6": ["::/0"]},
                       "status": "applied"})
            self.wfile.write(json.dumps(answer).encode())
            return
        if self.path == f"/v1/projects/{REF}/postgrest":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"db_schema": "public, graphql_public, reports", "max_rows": 1000,
                                         "db_extra_search_path": "public, extensions",
                                         "jwt_secret": "super-secret-jwt-value-never-kept"}).encode())
            return
        if self.path == f"/v1/projects/{REF}/advisors/performance":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            lint = {"name": "unindexed_foreign_keys", "level": "INFO", "title": "Unindexed foreign keys",
                    "description": "x", "metadata": {"schema": "public", "name": "orders"}}
            slow = {"name": "auth_rls_initplan", "level": "WARN", "title": "Auth RLS Initialization Plan",
                    "description": "y", "metadata": {"schema": "public", "name": "notes"}}
            self.wfile.write(json.dumps({"lints": [lint, slow]}).encode())
            return
        if self.path == f"/v1/projects/{REF}/advisors/security":
            status = 403 if type(self).mode == "advisors_403" else 200
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"lints": type(self).advisors} if status == 200 else {"message": "no"}).encode())
            return
        if self.path == f"/v1/projects/{REF}/config/auth":
            status = 403 if type(self).mode == "auth_403" else 200
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(type(self).auth if status == 200 else {"message": "no"}).encode())
            return
        if self.path != f"/v1/projects/{REF}/database/backups":
            self.send_response(500)
            self.end_headers()
            return
        status = 403 if type(self).mode == "backups_403" else 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(type(self).backups if status == 200 else {"message": "no"}).encode())

    do_HEAD = do_PATCH = do_DELETE = do_PUT = _unexpected

    def log_message(self, *args):
        pass


@pytest.fixture
def api(monkeypatch):
    FakeManagementApi.seen = []
    FakeManagementApi.mode = "ok"
    server = HTTPServer(("127.0.0.1", 0), FakeManagementApi)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(api_snapshot, "API_BASE", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("WEBCARE_ACCESS_TOKEN", TOKEN)
    yield FakeManagementApi
    server.shutdown()


def target(**fields) -> Target:
    defaults = dict(name="staging", env="staging", data="synthetic", project_ref=REF)
    defaults.update(fields)
    return Target(**defaults)


def test_one_read_only_request_carrying_only_the_snapshot_statement(api):
    data, origin = api_snapshot.fetch(target(schemas=("public", "private")), owner_approved=False)
    assert data["label"] == "staging"
    assert REF in origin and "read-only query endpoint" in origin and "supabase_read_only_user" in origin
    assert TOKEN not in origin

    assert len(api.seen) == 1
    method, path, headers, body = api.seen[0]
    assert (method, path) == ("POST", PATH)
    assert headers["authorization"] == f"Bearer {TOKEN}"
    sent = json.loads(body)
    assert list(sent) == ["query"]  # no parameters, nothing else
    expected = snapshot.statement_body(snapshot.build_sql(("public", "private"), "staging"))
    assert sent["query"] == expected
    live.assert_single_select(sent["query"])


@pytest.mark.parametrize("status, hint", [
    ("401", "rejected"),
    ("403", "database_read"),
    ("404", "no project"),
    ("429", "rate limit"),
    ("500", "refused the request"),
])
def test_api_errors_are_refusals_that_never_echo_the_token(api, status, hint):
    api.mode = status
    with pytest.raises(Refusal) as refusal:
        api_snapshot.fetch(target(), owner_approved=False)
    message = str(refusal.value)
    assert f"HTTP {status}" in message and hint in message
    assert TOKEN not in message and "Bearer" not in message


def test_a_redirect_is_not_followed(api):
    api.mode = "redirect"
    with pytest.raises(Refusal, match="HTTP 307"):
        api_snapshot.fetch(target(), owner_approved=False)
    assert len(api.seen) == 1  # the token went nowhere else


@pytest.mark.parametrize("mode, text", [
    ("garbage", "not JSON"),
    ("wrong_label", "does not carry the label"),
])
def test_an_answer_that_is_not_the_snapshot_asked_for_is_refused(api, mode, text):
    api.mode = mode
    with pytest.raises(Refusal, match=text):
        api_snapshot.fetch(target(), owner_approved=False)


@pytest.mark.parametrize("value, text", [
    ("", "is not set"),
    ("sb_secret_" + "x" * 20, "project API key"),
    ("sb_publishable_" + "x" * 20, "project API key"),
    ("eyJ" + "x" * 20, "project API key"),
    ("sbp_has a space", "whitespace"),
])
def test_values_that_are_not_an_access_token_are_refused_before_any_request(api, monkeypatch, value, text):
    monkeypatch.setenv("WEBCARE_ACCESS_TOKEN", value)
    with pytest.raises(Refusal, match=text):
        api_snapshot.fetch(target(), owner_approved=False)
    assert api.seen == []


def test_guard_rails_stop_before_any_request(api):
    with pytest.raises(Refusal, match="declares no project_ref"):
        api_snapshot.fetch(target(project_ref=None), owner_approved=False)
    with pytest.raises(Refusal, match="owner"):
        api_snapshot.fetch(target(env="production", data="real"), owner_approved=False)
    assert api.seen == []
    data, _origin = api_snapshot.fetch(target(env="production", data="real"), owner_approved=True)
    assert data["label"] == "staging" and len(api.seen) == 1


def test_only_https_or_loopback_is_ever_contacted():
    assert api_snapshot.endpoint(REF) == f"https://api.supabase.com{PATH}"
    with pytest.raises(Refusal, match="https"):
        api_snapshot.endpoint(REF, "http://api.example.com")
    with pytest.raises(Refusal, match="https"):
        api_snapshot.endpoint(REF, "ftp://api.supabase.com")


def test_project_ref_must_look_like_one(tmp_path):
    config = tmp_path / "webcare.toml"
    entry = '[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{}"\n'
    config.write_text(entry.format(REF))
    assert get_target(config, "staging").project_ref == REF
    for bad in ("short", REF.upper(), REF + "x", "abcdefghij-lmnopqrst", "../../../etc/passwdxxx"):
        config.write_text(entry.format(bad))
        with pytest.raises(Refusal, match="project_ref"):
            get_target(config, "staging")


def run_cli(tmp_path, capsys, *arguments):
    out = tmp_path / "out"
    code = main(["check", "--skip", "secrets", "--skip", "static", "--out-dir", str(out), *arguments])
    captured = capsys.readouterr()
    text = (out / "report.json").read_text() + (out / "report.md").read_text() + captured.out + captured.err
    report = json.loads((out / "report.json").read_text())
    return code, {check["id"]: check for check in report["checks"]}, text


def test_check_via_api_end_to_end(api, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("WEBCARE_DATABASE_URL", raising=False)
    config = tmp_path / "webcare.toml"
    config.write_text(
        f'[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n'
        'expected_anon_functions = ["public.site_banner()"]\n'
    )
    code, checks, text = run_cli(tmp_path, capsys, "--via-api", "--target", "staging", "--config", str(config))
    assert code == 1  # the fake catalog has one function outside the allowlist
    assert checks["rls_live"]["status"] == "NOT_RUN"
    assert checks["extra_live"]["status"] == "FINDINGS"
    assert checks["functions_live"]["status"] == "FINDINGS"
    assert "read-only query endpoint" in checks["functions_live"]["evidence"]
    assert TOKEN not in text
    assert checks["health_cron"]["status"] == "PASS"
    assert "Management API" in checks["health_cron"]["evidence"]
    assert checks["storage_buckets"]["status"] == "PASS"
    assert checks["table_writes"]["status"] == "PASS"
    assert checks["db_health"]["status"] == "PASS"
    # the snapshot, a probe and a query each for Storage and pg_cron, table privileges, database health
    assert [(method, path) for method, path, _, _ in api.seen] == [("POST", PATH)] * 7
    for _, _, _, body in api.seen:
        live.assert_single_select(json.loads(body)["query"])

    api.seen.clear()
    api.probe = dict(api.probe, installed=False)
    code, checks, text = run_cli(tmp_path, capsys, "--via-api", "--target", "staging", "--config", str(config))
    assert checks["health_cron"]["status"] == "NOT_RUN" and "not installed" in checks["health_cron"]["reason"]
    assert checks["storage_buckets"]["status"] == "NOT_RUN"
    assert len(api.seen) == 5 and code == 1  # probes, table privileges and health only; a missing pg_cron or Storage is not a failure
    api.probe = dict(api.probe, installed=True)

    api.mode = "403"
    code, checks, text = run_cli(tmp_path, capsys, "--via-api", "--target", "staging", "--config", str(config))
    assert code == 2 and checks["functions_live"]["status"] == "NOT_RUN"
    assert "database_read" in checks["functions_live"]["reason"] and TOKEN not in text


def test_via_api_needs_a_target_and_excludes_a_snapshot_file(api, tmp_path, capsys):
    code, checks, _text = run_cli(tmp_path, capsys, "--via-api")
    assert code == 2 and "needs --target" in checks["functions_live"]["reason"]
    config = tmp_path / "webcare.toml"
    config.write_text(f'[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n')
    path = tmp_path / "s.json"
    path.write_text(json.dumps(make_snapshot()))
    code, checks, _text = run_cli(
        tmp_path, capsys, "--via-api", "--snapshot", str(path), "--target", "staging", "--config", str(config)
    )
    assert code == 2 and "not both" in checks["functions_live"]["reason"]
    assert api.seen == []


def test_backup_list_is_read_only_when_asked_and_is_one_get(api, tmp_path, capsys):
    config = tmp_path / "webcare.toml"
    config.write_text(
        f'[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n'
    )
    arguments = ("--via-api", "--target", "staging", "--config", str(config))
    _code, checks, _text = run_cli(tmp_path, capsys, *arguments)
    assert checks["health_backups"]["status"] == "NOT_RUN" and "--with-backups" in checks["health_backups"]["reason"]
    assert all(method == "POST" for method, _, _, _ in api.seen)

    api.seen.clear()
    _code, checks, text = run_cli(tmp_path, capsys, *arguments, "--with-backups")
    gets = [(method, path) for method, path, _, _ in api.seen if method != "POST"]
    assert gets == [("GET", f"/v1/projects/{REF}/database/backups")]
    backup = checks["health_backups"]
    assert backup["status"] == "FINDINGS" and backup["findings"][0]["rule"] == "backup_none"
    assert backup["findings"][0]["severity"] == "low" and TOKEN not in text

    api.mode = "backups_403"
    _code, checks, text = run_cli(tmp_path, capsys, *arguments, "--with-backups")
    assert checks["health_backups"]["status"] == "ERROR" and "backups_read" in checks["health_backups"]["reason"]
    assert checks["functions_live"]["status"] == "FINDINGS" and TOKEN not in text


def test_log_summary_is_read_only_when_asked_and_carries_only_the_fixed_query(api, tmp_path, capsys):
    config = tmp_path / "webcare.toml"
    config.write_text(
        f'[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n'
        'expected_anon_functions = ["public.site_banner()"]\n'
    )
    arguments = ("--via-api", "--target", "staging", "--config", str(config))
    _code, checks, _text = run_cli(tmp_path, capsys, *arguments)
    assert checks["health_logs"]["status"] == "NOT_RUN" and "--with-logs" in checks["health_logs"]["reason"]
    assert all(method == "POST" for method, _, _, _ in api.seen)

    api.seen.clear()
    _code, checks, text = run_cli(tmp_path, capsys, *arguments, "--with-logs")
    gets = [path for method, path, _, _ in api.seen if method == "GET"]
    assert len(gets) == 3 and all(urlsplit(g).path == f"/v1/projects/{REF}/analytics/endpoints/logs" for g in gets)
    sent = [parse_qs(urlsplit(g).query) for g in gets]
    assert [q["sql"] for q in sent] == [[logs.SQL], [logs.TREND_SQL], [logs.TREND_SQL]]
    assert all(set(q) == {"sql", "iso_timestamp_start", "iso_timestamp_end"} for q in sent)
    assert sent[2]["iso_timestamp_end"] == sent[1]["iso_timestamp_start"]  # the 24 hours before
    found = [(f["rule"], f["location"]) for f in checks["health_logs"]["findings"]]
    assert found == [("log_anon_rpc_unexpected", "rpc/admin_tool")] and TOKEN not in text

    api.mode = "logs_403"
    _code, checks, text = run_cli(tmp_path, capsys, *arguments, "--with-logs")
    assert checks["health_logs"]["status"] == "ERROR" and "analytics_logs_read" in checks["health_logs"]["reason"]
    assert TOKEN not in text

    with pytest.raises(Refusal):
        api_snapshot.log_summary(target(), False, "select ip from logs", "a", "b")


def test_auth_settings_are_read_only_when_asked_and_no_secret_survives(api, tmp_path, capsys):
    config = tmp_path / "webcare.toml"
    config.write_text(
        f'[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n'
    )
    arguments = ("--via-api", "--target", "staging", "--config", str(config))
    _code, checks, _text = run_cli(tmp_path, capsys, *arguments)
    assert checks["auth_config"]["status"] == "NOT_RUN" and "--with-auth-config" in checks["auth_config"]["reason"]
    assert all(method == "POST" for method, _, _, _ in api.seen)

    api.seen.clear()
    _code, checks, text = run_cli(tmp_path, capsys, *arguments, "--with-auth-config")
    assert [path for method, path, _, _ in api.seen if method == "GET"] == [f"/v1/projects/{REF}/config/auth"]
    rules = {finding["rule"] for finding in checks["auth_config"]["findings"]}
    assert rules == {"auth_signup_open", "auth_password_short"}
    assert "MARKER" not in text and TOKEN not in text

    kept = api_snapshot.auth_settings(target(), False)
    assert "MARKER" not in json.dumps(kept) and kept["custom_mail_server"] is True
    assert set(kept) <= set(auth_config.KEPT) | {"custom_mail_server"}

    api.mode = "auth_403"
    _code, checks, text = run_cli(tmp_path, capsys, *arguments, "--with-auth-config")
    assert checks["auth_config"]["status"] == "ERROR" and "auth_config_read" in checks["auth_config"]["reason"]


def test_advisors_are_read_only_when_asked_and_a_long_lint_stays_short(api, tmp_path, capsys):
    config = tmp_path / "webcare.toml"
    config.write_text(
        f'[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n'
        'advisors_ignore = ["authenticated_security_definer_function_executable"]\n'
    )
    arguments = ("--via-api", "--target", "staging", "--config", str(config))
    _code, checks, _text = run_cli(tmp_path, capsys, *arguments)
    assert checks["advisors"]["status"] == "NOT_RUN" and "--with-advisors" in checks["advisors"]["reason"]
    assert all(method == "POST" for method, _, _, _ in api.seen)

    api.seen.clear()
    code, checks, text = run_cli(tmp_path, capsys, *arguments, "--with-advisors")
    assert [path for method, path, _, _ in api.seen if method == "GET"] == [f"/v1/projects/{REF}/advisors/security"]
    advisor = checks["advisors"]
    assert [(f["rule"], f["severity"]) for f in advisor["findings"]] == [("rls_disabled_in_public", "high")]
    assert "2 objects (for example public.orders, public.notes)" in advisor["findings"][0]["message"]
    assert "authenticated_security_definer_function_executable (300)" in " ".join(advisor["notes"])
    assert "fn_17" not in text and TOKEN not in text and code == 1

    api.mode = "advisors_403"
    _code, checks, _text = run_cli(tmp_path, capsys, *arguments, "--with-advisors")
    assert checks["advisors"]["status"] == "ERROR" and "advisors_read" in checks["advisors"]["reason"]


def test_the_target_file_can_switch_on_optional_checks_and_the_language(api, tmp_path, capsys):
    config = tmp_path / "webcare.toml"
    config.write_text(
        f'[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n'
        'checks = ["advisors", "backups"]\nlang = "th"\n'
    )
    arguments = ("--via-api", "--target", "staging", "--config", str(config))
    _code, checks, _text = run_cli(tmp_path, capsys, *arguments)
    gets = sorted(path for method, path, _, _ in api.seen if method == "GET")
    assert gets == [f"/v1/projects/{REF}/advisors/security", f"/v1/projects/{REF}/database/backups"]
    assert checks["advisors"]["status"] != "NOT_RUN" and checks["health_backups"]["status"] != "NOT_RUN"
    assert checks["auth_config"]["status"] == "NOT_RUN" and checks["health_logs"]["status"] == "NOT_RUN"
    assert any("switched on by the target" in note for note in checks["advisors"]["notes"])
    assert "# รายงาน Supabase Web Care" in (tmp_path / "out" / "report.md").read_text()

    _code, _checks, _text = run_cli(tmp_path, capsys, *arguments, "--lang", "en")
    assert "# Supabase Web Care report" in (tmp_path / "out" / "report.md").read_text()


def test_unknown_optional_checks_and_languages_are_refused(tmp_path):
    base = f'[[target]]\nname = "t"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n'
    for extra in ('checks = ["advisors", "everything"]\n', 'checks = "advisors"\n', 'lang = "fr"\n'):
        config = tmp_path / "webcare.toml"
        config.write_text(base + extra)
        with pytest.raises(Refusal):
            get_target(config, "t")


def test_a_refused_api_run_gives_the_real_reason_for_every_check_asked_for(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(api_snapshot.DEFAULT_TOKEN_ENV, raising=False)
    config = tmp_path / "webcare.toml"
    config.write_text(f'[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n')
    code, checks, _ = run_cli(tmp_path, capsys, "--via-api", "--with-advisors", "--target", "staging",
                              "--config", str(config))
    assert code == 2
    for check_id in ("advisors", "storage_buckets", "table_writes", "health_cron"):
        assert checks[check_id]["status"] == "NOT_RUN"
        assert "not asked for" not in checks[check_id]["reason"]
        assert api_snapshot.DEFAULT_TOKEN_ENV in checks[check_id]["reason"], checks[check_id]["reason"]


def test_performance_advisors_are_read_only_when_asked(api, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("WEBCARE_DATABASE_URL", raising=False)
    config = tmp_path / "webcare.toml"
    config.write_text(f'[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n')
    code, checks, _ = run_cli(tmp_path, capsys, "--via-api", "--target", "staging", "--config", str(config))
    assert checks["advisors_performance"]["status"] == "NOT_RUN"
    assert "--with-performance" in checks["advisors_performance"]["reason"]
    api.seen.clear()
    code, checks, _ = run_cli(tmp_path, capsys, "--via-api", "--with-performance", "--target", "staging",
                              "--config", str(config))
    assert [path for method, path, _, _ in api.seen if method == "GET"] == [f"/v1/projects/{REF}/advisors/performance"]
    found = {(f["rule"], f["severity"]) for f in checks["advisors_performance"]["findings"]}
    assert found == {("unindexed_foreign_keys", "info"), ("auth_rls_initplan", "low")}
    assert "experimental" in " ".join(checks["advisors_performance"]["notes"])


def test_data_api_settings_keep_only_the_allowlist(api, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("WEBCARE_DATABASE_URL", raising=False)
    config = tmp_path / "webcare.toml"
    config.write_text(f'[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n')
    code, checks, text = run_cli(tmp_path, capsys, "--via-api", "--with-data-api", "--target", "staging",
                                 "--config", str(config))
    found = [(f["rule"], f["location"]) for f in checks["data_api"]["findings"]]
    assert found == [("served_schema_unchecked", "schema reports")]
    assert "super-secret-jwt-value-never-kept" not in text and "jwt_secret" not in text
    assert "row cap per request: 1000" in " ".join(checks["data_api"]["notes"])


def test_platform_settings_are_read_only_when_asked(api, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("WEBCARE_DATABASE_URL", raising=False)
    config = tmp_path / "webcare.toml"
    config.write_text(f'[[target]]\nname = "staging"\nenv = "staging"\ndata = "synthetic"\nproject_ref = "{REF}"\n')
    api.seen.clear()
    code, checks, _ = run_cli(tmp_path, capsys, "--via-api", "--with-platform", "--target", "staging",
                              "--config", str(config))
    gets = [path for method, path, _, _ in api.seen if method == "GET"]
    assert gets == [f"/v1/projects/{REF}/ssl-enforcement", f"/v1/projects/{REF}/network-restrictions"]
    found = {(f["rule"], f["severity"]) for f in checks["platform"]["findings"]}
    assert found == {("ssl_not_enforced", "medium"), ("database_open_to_every_address", "low")}


def test_served_schema_names_are_compared_without_regard_to_case():
    from webcare import data_api
    from webcare.model import CheckResult
    from webcare.targets import Target

    target = Target(name="t", env="staging", data="synthetic", schemas=("public", "reports"))
    result = data_api.judge(CheckResult(id="data_api", title="t"),
                            {"db_schema": "Public, \"reports\", graphql_public"}, target)
    assert result.findings == []
