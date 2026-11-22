"""Shared fixtures.

The live-database tests need a throwaway local Postgres. Point
WEBCARE_TEST_ADMIN_DSN at a superuser login on 127.0.0.1 and they create two
scratch databases, load the synthetic fixtures, and drop the databases again.
Without that variable they are skipped. The tests refuse any host that is not
loopback, so they cannot be aimed at a shared server by mistake.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT))

ADMIN_ENV = "WEBCARE_TEST_ADMIN_DSN"


def make_jwt(payload: dict) -> str:
    """Build a JWT-shaped string at run time, so no key-like text sits in the repo."""

    def encode(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{encode({'alg': 'HS256', 'typ': 'JWT'})}.{encode(payload)}.{'s' * 43}"


FAKE_PASSWORD = "Zr8k" + "Q2mV" + "x4Tn"


def fake_pg_url(password=FAKE_PASSWORD, host="db.example.com", port=5432, database="app", user="auditor"):
    return f"postgresql://{user}:{password}@{host}:{port}/{database}"


@pytest.fixture(scope="session")
def pg(tmp_path_factory):
    admin_dsn = os.environ.get(ADMIN_ENV)
    if not admin_dsn:
        pytest.skip(f"{ADMIN_ENV} is not set; live database tests skipped")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    info = conninfo_to_dict(admin_dsn)
    if info.get("host") not in ("127.0.0.1", "localhost", "::1"):
        pytest.exit(f"{ADMIN_ENV} must point at a loopback host", returncode=2)
    host, port = info["host"], int(info.get("port") or 5432)

    tag = secrets.token_hex(4)
    names = {
        "bad": f"webcare_t_bad_{tag}",
        "good": f"webcare_t_good_{tag}",
        "fbad": f"webcare_t_fbad_{tag}",
        "fgood": f"webcare_t_fgood_{tag}",
        "cron": f"webcare_t_cron_{tag}",
    }
    auditor_password = secrets.token_urlsafe(24)

    def admin(dbname: str):
        return psycopg.connect(make_conninfo(admin_dsn, dbname=dbname), autocommit=True)

    with admin(info.get("dbname") or "postgres") as connection:
        for name in names.values():
            connection.execute(f'create database "{name}" encoding \'UTF8\' template template0')
    stub = (FIXTURES / "supabase_stub.sql").read_text()
    role_sql = (ROOT / "sql" / "auditor-role.sql").read_text()
    for key, fixture in (
        ("bad", "vulnerable.sql"),
        ("good", "clean.sql"),
        ("fbad", "functions_bad.sql"),
        ("fgood", "functions_good.sql"),
        ("cron", "cron_stub.sql"),
    ):
        with admin(names[key]) as connection:
            connection.execute(stub)
            connection.execute((FIXTURES / fixture).read_text())
            connection.execute(role_sql)
            connection.execute(
                psycopg.sql.SQL(
                    "alter role webcare_auditor login password {} valid until 'tomorrow'"
                ).format(psycopg.sql.Literal(auditor_password))
            )

    def auditor(dbname: str) -> str:
        return make_conninfo(admin_dsn, dbname=dbname, user="webcare_auditor", password=auditor_password)

    config = tmp_path_factory.mktemp("config") / "webcare.toml"
    config.write_text(
        "".join(
            f'[[target]]\nname = "{target}"\nenv = "{env}"\ndata = "{data}"\n'
            f'db = "{host}:{port}/{names[key]}"\n\n'
            for target, env, data, key in (
                ("bad", "local", "synthetic", "bad"),
                ("good", "local", "synthetic", "good"),
                ("real-copy", "local", "real", "bad"),
                ("prod", "production", "real", "bad"),
                ("fbad", "local", "synthetic", "fbad"),
                ("fgood-undeclared", "local", "synthetic", "fgood"),
            )
        )
        + f'[[target]]\nname = "fgood"\nenv = "local"\ndata = "synthetic"\n'
        f'db = "{host}:{port}/{names["fgood"]}"\n'
        'expected_anon_functions = ["public.site_banner()"]\n\n'
        + f'[[target]]\nname = "fgood-stale"\nenv = "local"\ndata = "synthetic"\n'
        f'db = "{host}:{port}/{names["fgood"]}"\n'
        'expected_anon_functions = ["site_banner", "public.retired_page(text, uuid)"]\n\n'
    )

    yield SimpleNamespace(
        config=config,
        auditor_bad=auditor(names["bad"]),
        auditor_good=auditor(names["good"]),
        auditor_fbad=auditor(names["fbad"]),
        auditor_fgood=auditor(names["fgood"]),
        admin_bad=make_conninfo(admin_dsn, dbname=names["bad"]),
        auditor_cron=auditor(names["cron"]),
        admin_cron=make_conninfo(admin_dsn, dbname=names["cron"]),
    )

    with admin(info.get("dbname") or "postgres") as connection:
        connection.execute("alter role webcare_auditor nologin")
        for name in names.values():
            connection.execute(f'drop database if exists "{name}" with (force)')
