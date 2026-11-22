import pytest

from conftest import FAKE_PASSWORD, fake_pg_url
from webcare.model import Refusal
from webcare.targets import get_target, load_targets

pytest.importorskip("psycopg")

CONFIG = """
[[target]]
name = "sim"
env = "local"
data = "synthetic"
db = "127.0.0.1:5432/app_sim"
rest = "http://127.0.0.1:54321"
expected_public = ["public_content"]

[[target]]
name = "copy"
env = "local"
data = "real"
db = "127.0.0.1:5432/app_copy"

[[target]]
name = "staging"
env = "staging"
data = "synthetic"
db = "db.example.supabase.co:5432/postgres"
rest = "https://example.supabase.co"
"""


@pytest.fixture
def config(tmp_path):
    path = tmp_path / "webcare.toml"
    path.write_text(CONFIG)
    return path


def test_declared_targets_load(config):
    targets = load_targets(config)
    assert set(targets) == {"sim", "copy", "staging"}
    assert targets["sim"].schemas == ("public",)
    assert targets["sim"].expected_public == ("public_content",)


def test_missing_file_and_unknown_target_are_refused(config, tmp_path):
    with pytest.raises(Refusal, match="no target file"):
        load_targets(tmp_path / "absent.toml")
    with pytest.raises(Refusal, match="not declared"):
        get_target(config, "production")


@pytest.mark.parametrize(
    "body, message",
    [
        ('[[target]]\nname = "a"\nenv = "prod"\ndata = "real"\n', "env"),
        ('[[target]]\nname = "a"\nenv = "local"\ndata = "fake"\n', "data"),
        ('[[target]]\nname = "a"\nenv = "local"\ndata = "real"\ndb = "nohost"\n', "host:port/database"),
        ('[[target]]\nname = "a"\nenv = "local"\ndata = "real"\nrest = "http://example.com"\n', "plain http"),
        ('[[target]]\nname = "a"\nenv = "local"\ndata = "real"\nrest = "https://example.com/rest/v1"\n', "bare origin"),
    ],
)
def test_invalid_declarations_are_refused(tmp_path, body, message):
    path = tmp_path / "webcare.toml"
    path.write_text(body)
    with pytest.raises(Refusal, match=message):
        load_targets(path)


def test_duplicate_names_are_refused(tmp_path):
    path = tmp_path / "webcare.toml"
    entry = '[[target]]\nname = "a"\nenv = "local"\ndata = "synthetic"\n'
    path.write_text(entry + entry)
    with pytest.raises(Refusal, match="twice"):
        load_targets(path)


def test_real_data_and_production_need_the_owner(config):
    get_target(config, "sim").ensure_allowed(owner_approved=False)
    get_target(config, "staging").ensure_allowed(owner_approved=False)
    with pytest.raises(Refusal, match="owner"):
        get_target(config, "copy").ensure_allowed(owner_approved=False)
    get_target(config, "copy").ensure_allowed(owner_approved=True)


def test_connection_string_must_match_the_declaration(config):
    sim = get_target(config, "sim")
    endpoint = sim.ensure_db_matches(fake_pg_url(host="127.0.0.1", database="app_sim"))
    assert endpoint.describe() == "auditor@127.0.0.1:5432/app_sim"
    with pytest.raises(Refusal, match="Refusing to connect"):
        sim.ensure_db_matches(fake_pg_url(host="127.0.0.1", database="app_copy"))
    with pytest.raises(Refusal, match="Refusing to connect"):
        sim.ensure_db_matches("host=10.0.0.5 port=5432 dbname=app_sim user=auditor")
    with pytest.raises(Refusal, match="exactly one TCP host"):
        sim.ensure_db_matches("postgresql://auditor@127.0.0.1,10.0.0.5/app_sim")


def test_refusal_text_never_echoes_the_password(config):
    sim = get_target(config, "sim")
    with pytest.raises(Refusal) as caught:
        sim.ensure_db_matches(fake_pg_url(host="10.9.9.9", database="other"))
    assert FAKE_PASSWORD not in str(caught.value)


def test_rest_url_must_match_the_declaration(config):
    sim = get_target(config, "sim")
    assert sim.ensure_rest_matches("http://127.0.0.1:54321/") == "http://127.0.0.1:54321"
    with pytest.raises(Refusal, match="Refusing to probe"):
        sim.ensure_rest_matches("https://example.supabase.co")
    with pytest.raises(Refusal, match="no `rest`"):
        get_target(config, "copy").ensure_rest_matches("http://127.0.0.1:54321")


def test_public_database_hosts_must_use_tls():
    from webcare.targets import with_tls

    local = "host=127.0.0.1 port=5432 dbname=app user=a password=p"
    assert with_tls(local) == local
    assert with_tls("host=localhost dbname=app") == "host=localhost dbname=app"
    assert "sslmode=require" in with_tls("host=db.example.supabase.co dbname=postgres user=a")
    assert with_tls("postgresql://a@db.example.com:5432/app").endswith("/app?sslmode=require")
    assert with_tls("postgresql://a@db.example.com/app?application_name=x").endswith("&sslmode=require")
    kept = "host=db.example.com dbname=app sslmode=verify-full"
    assert with_tls(kept) == kept
    for weak in ("disable", "allow", "prefer"):
        with pytest.raises(Refusal, match="sslmode"):
            with_tls(f"host=db.example.com dbname=app sslmode={weak}")
