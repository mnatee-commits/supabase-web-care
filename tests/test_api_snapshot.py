import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from test_snapshot import make_snapshot
from urllib.parse import parse_qs, urlsplit

from webcare import api_snapshot, auth_config, health, live, logs, snapshot, storage_buckets
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
    # the snapshot, then a probe and a query each for Storage and pg_cron: all to the read-only endpoint
    assert [(method, path) for method, path, _, _ in api.seen] == [("POST", PATH)] * 5
    for _, _, _, body in api.seen:
        live.assert_single_select(json.loads(body)["query"])

    api.seen.clear()
    api.probe = dict(api.probe, installed=False)
    code, checks, text = run_cli(tmp_path, capsys, "--via-api", "--target", "staging", "--config", str(config))
    assert checks["health_cron"]["status"] == "NOT_RUN" and "not installed" in checks["health_cron"]["reason"]
    assert checks["storage_buckets"]["status"] == "NOT_RUN"
    assert len(api.seen) == 3 and code == 1  # probes only; a missing pg_cron or Storage is not a failure
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
    assert len(gets) == 1 and urlsplit(gets[0]).path == f"/v1/projects/{REF}/analytics/endpoints/logs"
    sent = parse_qs(urlsplit(gets[0]).query)
    assert sent["sql"] == [logs.SQL] and set(sent) == {"sql", "iso_timestamp_start", "iso_timestamp_end"}
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
