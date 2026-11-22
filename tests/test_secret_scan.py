import json

from conftest import FAKE_PASSWORD, ROOT, fake_pg_url, make_jwt
from webcare import secret_scan
from webcare.secret_scan import ALLOW_MARKER, scan_text


def rules(text: str) -> dict[str, str]:
    return {finding.rule: finding.severity for finding in scan_text(text, "app.js")}


def test_service_role_jwt_is_high():
    token = make_jwt({"role": "service_role", "iss": "supabase", "ref": "abcdefghijklmnopqrst"})
    assert rules(f'const key = "{token}"') == {"supabase_service_role_jwt": "high"}


def test_local_demo_service_role_jwt_is_low():
    token = make_jwt({"role": "service_role", "iss": "supabase-demo"})
    assert rules(token) == {"supabase_local_service_role_jwt": "low"}


def test_anon_jwt_is_inventory_only():
    token = make_jwt({"role": "anon", "iss": "supabase"})
    assert rules(token) == {"supabase_anon_jwt": "info"}


def test_user_session_jwt_is_medium():
    token = make_jwt({"sub": "00000000-0000-4000-8000-000000000001", "exp": 1})
    assert rules(token) == {"jwt_token": "medium"}


def test_supabase_key_formats():
    secret_key = "sb_" + "secret_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
    publishable = "sb_" + "publishable_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
    access_token = "sbp" + "_" + "0123456789abcdef" * 2 + "01234567"
    assert rules(secret_key) == {"supabase_secret_key": "high"}
    assert rules(publishable) == {"supabase_publishable_key": "info"}
    assert rules(access_token) == {"supabase_access_token": "high"}


def test_secret_named_public_env_variable():
    assert rules("NEXT_PUBLIC_" + "SUPABASE_SERVICE_ROLE_KEY=whatever") == {
        "secret_in_public_env_name": "high"
    }
    assert rules("NEXT_PUBLIC_SUPABASE_URL=https://example.supabase.co") == {}


def test_postgres_url_passwords():
    assert rules(fake_pg_url(host="db.example.supabase.co")) == {"postgres_url_password": "high"}
    assert rules(fake_pg_url(password="[YOUR-PASSWORD]")) == {}
    assert rules(fake_pg_url(password="{password}")) == {}
    assert rules(fake_pg_url(password="postgres", host="127.0.0.1", user="postgres")) == {}
    assert rules(fake_pg_url(host="localhost")) == {"postgres_url_password_local": "low"}


def test_libpq_keyword_string_but_not_code():
    assert rules("host=db.example.com dbname=app user=app password=" + FAKE_PASSWORD) == {
        "postgres_dsn_password": "medium"
    }
    assert rules('connect(dbname=name, user="app", password=password_variable)') == {}


def test_jwt_secret_assignment():
    value = "k9" * 20
    assert rules(f"SUPABASE_JWT_SECRET={value}") == {"jwt_secret_assignment": "high"}
    default = "super-secret-jwt-token-with-at-least-32-characters-long"
    assert rules(f"JWT_SECRET={default}") == {}


def test_private_key_block():
    assert rules("-----BEGIN " + "PRIVATE KEY-----") == {"private_key_block": "high"}


def test_allow_marker_silences_a_line():
    token = make_jwt({"role": "service_role"})
    assert rules(f"{token}  // {ALLOW_MARKER} test fixture") == {}


def test_findings_never_contain_the_value(tmp_path):
    token = make_jwt({"role": "service_role", "iss": "supabase"})
    (tmp_path / "app.js").write_text(f'const k = "{token}"\nconst u = "{fake_pg_url()}"\n')
    result = secret_scan.run([tmp_path])
    assert result.status == "FINDINGS"
    assert {f.location for f in result.findings} == {"app.js:1", "app.js:2"}
    dumped = json.dumps(result.to_dict())
    assert token not in dumped and FAKE_PASSWORD not in dumped


def test_tree_walk_skips_what_it_should(tmp_path):
    token = make_jwt({"role": "service_role", "iss": "supabase"})
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text(token)
    (tmp_path / "image.bin").write_bytes(b"\x00\x01" + token.encode())
    (tmp_path / "big.txt").write_text(token + "x" * 200)
    (tmp_path / "skipme").mkdir()
    (tmp_path / "skipme" / "fixture.txt").write_text(token)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.ts").write_text(token)
    findings, stats = secret_scan.scan_tree(tmp_path, excludes=["skipme/*"], max_bytes=150)
    assert [f.location for f in findings] == ["src/config.ts:1"]
    assert (stats.files_scanned, stats.skipped_binary, stats.skipped_large) == (1, 1, 1)


def test_clean_tree_passes_and_missing_path_errors(tmp_path):
    (tmp_path / "readme.md").write_text("nothing to see")
    assert secret_scan.run([tmp_path]).status == "PASS"
    assert secret_scan.run([tmp_path / "absent"]).status == "ERROR"


def test_this_toolkit_carries_no_credentials():
    result = secret_scan.run([ROOT])
    assert result.status == "PASS", [(f.rule, f.location) for f in result.findings]
