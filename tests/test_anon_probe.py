import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from conftest import make_jwt
from webcare import anon_probe
from webcare.model import Refusal
from webcare.targets import Target

# What a PostgREST server answers to HEAD /rest/v1/<name>?select=*&limit=1.
RESPONSES = {
    "open": (200, {"Content-Range": "0-0/*"}),
    "counted": (206, {"Content-Range": "0-0/42"}),
    "empty": (200, {"Content-Range": "*/*"}),
    "denied": (401, {}),
    "missing": (404, {}),
    "moved": (302, {"Location": "http://127.0.0.1:9/elsewhere"}),
    "odd": (200, {}),
}


class FakeApi(BaseHTTPRequestHandler):
    seen: list = []

    def _record(self):
        # Header names are case-insensitive on the wire; store them lowercased.
        headers = {name.lower(): value for name, value in self.headers.items()}
        type(self).seen.append((self.command, self.path, headers))

    def do_HEAD(self):
        self._record()
        name = self.path.split("/rest/v1/")[-1].split("?")[0]
        status, headers = RESPONSES.get(name, (404, {}))
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()

    def _unexpected(self):
        self._record()
        self.send_response(500)
        self.end_headers()

    do_GET = do_POST = do_PATCH = do_DELETE = do_PUT = _unexpected

    def log_message(self, *args):
        pass


@pytest.fixture
def api(monkeypatch):
    FakeApi.seen = []
    server = HTTPServer(("127.0.0.1", 0), FakeApi)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("WEBCARE_ANON_KEY", make_jwt({"role": "anon", "iss": "supabase"}))
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def target(url, **overrides):
    values = dict(name="sim", env="local", data="synthetic", rest=url)
    values.update(overrides)
    return Target(**values)


@pytest.mark.parametrize(
    "status, content_range, outcome",
    [
        (200, "0-0/*", anon_probe.VISIBLE),
        (206, "0-24/3573458", anon_probe.VISIBLE),
        (200, "*/*", anon_probe.NO_ROWS),
        (200, "*/0", anon_probe.NO_ROWS),
        (416, None, anon_probe.NO_ROWS),
        (200, None, anon_probe.REACHABLE_UNKNOWN),
        (401, None, anon_probe.DENIED),
        (403, None, anon_probe.DENIED),
        (404, None, anon_probe.NOT_EXPOSED),
        (302, None, anon_probe.UNKNOWN),
        (500, None, anon_probe.UNKNOWN),
    ],
)
def test_classify(status, content_range, outcome):
    assert anon_probe.classify(status, content_range) == outcome


def test_only_public_keys_are_accepted():
    assert anon_probe.check_public_key(make_jwt({"role": "anon"})) == "anon_jwt"
    assert anon_probe.check_public_key("sb_" + "publishable_" + "x" * 24) == "publishable"
    for key in (
        make_jwt({"role": "service_role"}),
        make_jwt({"role": "authenticated", "sub": "u"}),
        "sb_" + "secret_" + "x" * 24,
        "not-a-key",
        "",
    ):
        with pytest.raises(Refusal):
            anon_probe.check_public_key(key)


def test_probe_reports_visible_rows_and_sends_only_head(api):
    result = anon_probe.run(
        target(api), api, ["open", "counted", "empty", "denied", "missing", "moved", "odd"], delay=0
    )
    assert result.status == "FINDINGS"
    found = {(f.rule, f.location) for f in result.findings}
    assert found == {
        ("anon_can_read_rows", "public.open"),
        ("anon_can_read_rows", "public.counted"),
        ("anon_reachable_unclear", "public.odd"),
    }
    assert {method for method, _, _ in FakeApi.seen} == {"HEAD"}
    assert len(FakeApi.seen) == 7  # one request per table; the redirect was not followed
    assert all(path.endswith("?select=*&limit=1") for _, path, _ in FakeApi.seen)
    headers = FakeApi.seen[0][2]
    assert headers["apikey"] == headers["authorization"].removeprefix("Bearer ")


def test_publishable_key_is_sent_as_apikey_only(api, monkeypatch):
    monkeypatch.setenv("WEBCARE_ANON_KEY", "sb_" + "publishable_" + "x" * 24)
    result = anon_probe.run(target(api), api, ["empty"], delay=0)
    assert result.status == "PASS"
    headers = FakeApi.seen[0][2]
    assert "authorization" not in headers and headers["apikey"].startswith("sb_publishable_")


def test_other_schema_uses_accept_profile(api):
    anon_probe.run(target(api), api, ["empty"], schema="api", delay=0)
    assert FakeApi.seen[0][2]["accept-profile"] == "api"


def test_expected_public_tables_are_noted_not_flagged(api):
    result = anon_probe.run(target(api, expected_public=("open",)), api, ["open"], delay=0)
    assert result.status == "PASS" and not result.findings
    assert any("declared as expected" in note for note in result.notes)


@pytest.mark.parametrize(
    "overrides, url, tables, reason",
    [
        ({}, "http://127.0.0.1:1", ["open"], "Refusing to probe"),
        ({"data": "real"}, None, ["open"], "owner"),
        ({"env": "production"}, None, ["open"], "owner"),
        ({}, None, ["open; drop"], "not plain identifiers"),
        ({}, None, ["rpc/do_thing"], "not plain identifiers"),
        ({}, None, [], "no tables"),
    ],
)
def test_refusals_send_nothing(api, overrides, url, tables, reason):
    result = anon_probe.run(target(api, **overrides), url or api, tables, delay=0)
    assert result.status == "NOT_RUN" and reason in result.reason
    assert FakeApi.seen == []


def test_secret_key_is_refused_before_any_request(api, monkeypatch):
    monkeypatch.setenv("WEBCARE_ANON_KEY", make_jwt({"role": "service_role"}))
    result = anon_probe.run(target(api), api, ["open"], delay=0)
    assert result.status == "NOT_RUN" and "service_role" in result.reason
    assert FakeApi.seen == []


def test_owner_approval_allows_a_real_data_target(api):
    result = anon_probe.run(target(api, data="real"), api, ["empty"], owner_approved=True, delay=0)
    assert result.status == "PASS"


def test_unreachable_api_is_an_error(monkeypatch):
    monkeypatch.setenv("WEBCARE_ANON_KEY", make_jwt({"role": "anon"}))
    url = "http://127.0.0.1:9"
    result = anon_probe.run(target(url), url, ["open"], delay=0)
    assert result.status == "ERROR"
