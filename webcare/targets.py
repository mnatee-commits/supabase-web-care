"""Declared targets for live checks.

A live check (database connection or HTTP probe) only runs against a target
that is written down in webcare.toml. The connection details supplied at run
time must match the declaration, so a stray environment variable pointing at
the wrong database fails closed instead of being audited by accident.

Offline checks (secret scan, static SQL lint) need no target.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from .model import Refusal

ENVIRONMENTS = ("local", "staging", "production")
DATA_KINDS = ("synthetic", "real")
DEFAULT_CONFIG_NAME = "webcare.toml"
APPROVAL_FLAG = "--owner-approved"
_PROJECT_REF = re.compile(r"^[a-z]{20}$")


@dataclass(frozen=True)
class Target:
    name: str
    env: str
    data: str
    db: Optional[str] = None  # "host:port/database"
    rest: Optional[str] = None  # "scheme://host[:port]"
    schemas: tuple[str, ...] = ("public",)
    project_ref: Optional[str] = None  # Supabase project reference, for --via-api
    expected_public: tuple[str, ...] = field(default_factory=tuple)
    # SECURITY DEFINER functions anon is meant to call: "name", "schema.name",
    # or either form with the argument types, e.g. "public.find(text, uuid)".
    expected_anon_functions: tuple[str, ...] = field(default_factory=tuple)
    expected_public_buckets: tuple[str, ...] = field(default_factory=tuple)
    expected_open_signup: bool = False  # anyone may create an account, on purpose
    advisors_ignore: tuple[str, ...] = field(default_factory=tuple)  # Security Advisor lints already reviewed
    expected_cron_jobs: tuple[str, ...] = field(default_factory=tuple)  # pg_cron jobs that must exist

    @property
    def needs_owner_approval(self) -> bool:
        return self.env == "production" or self.data == "real"

    def describe(self) -> str:
        return f"{self.name} (env={self.env}, data={self.data})"

    def ensure_allowed(self, owner_approved: bool) -> None:
        if self.needs_owner_approval and not owner_approved:
            raise Refusal(
                f"target {self.describe()} holds production or real data. Live checks "
                f"against it need the owner's own go-ahead; rerun with {APPROVAL_FLAG} "
                "only after the owner has said so in their own words."
            )

    def ensure_db_matches(self, dsn: str) -> "DbEndpoint":
        endpoint = parse_dsn(dsn)
        if self.db is None:
            raise Refusal(f"target {self.name!r} declares no `db`, so it has no database to check")
        if endpoint.key != _normalize_db(self.db, self.name):
            raise Refusal(
                f"the connection string points at {endpoint.key}, but target "
                f"{self.name!r} declares {self.db}. Refusing to connect."
            )
        return endpoint

    def ensure_rest_matches(self, url: str) -> str:
        if self.rest is None:
            raise Refusal(f"target {self.name!r} declares no `rest`, so it has no API to probe")
        declared = _origin(self.rest, f"target {self.name!r} rest")
        supplied = _origin(url, "the REST URL")
        if declared != supplied:
            raise Refusal(
                f"the REST URL points at {supplied}, but target {self.name!r} "
                f"declares {declared}. Refusing to probe."
            )
        return declared


@dataclass(frozen=True)
class DbEndpoint:
    host: str
    port: int
    database: str
    user: str

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}/{self.database}"

    def describe(self) -> str:
        """Safe to print: carries no password."""
        return f"{self.user}@{self.key}"


def parse_dsn(dsn: str) -> DbEndpoint:
    """Extract host, port, database and user from a libpq connection string."""
    try:
        from psycopg.conninfo import conninfo_to_dict
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise Refusal(
            "live database checks need psycopg, which is installed together with pgrls"
        ) from error
    try:
        info = conninfo_to_dict(dsn)
    except Exception:
        # psycopg's message can echo the string, which may hold a password.
        raise Refusal("the database connection string could not be parsed") from None
    host = str(info.get("host") or "")
    if not host or "," in host or host.startswith("/"):
        raise Refusal(
            "the connection string must name exactly one TCP host "
            "(no socket paths, no host lists)"
        )
    database = str(info.get("dbname") or "")
    if not database:
        raise Refusal("the connection string must name a database")
    try:
        port = int(info.get("port") or 5432)
    except ValueError:
        raise Refusal("the connection string has a port that is not a number") from None
    return DbEndpoint(
        host=host.lower(), port=port, database=database, user=str(info.get("user") or "")
    )


def _normalize_db(declared: str, target_name: str) -> str:
    try:
        address, database = declared.rsplit("/", 1)
        host, port = address.rsplit(":", 1)
        return f"{host.lower()}:{int(port)}/{database}"
    except ValueError:
        raise Refusal(
            f"target {target_name!r}: `db` must look like host:port/database, got {declared!r}"
        ) from None


def _is_private_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private


def _origin(url: str, label: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise Refusal(f"{label} must be an http(s) URL with a host")
    if parts.username or parts.password:
        raise Refusal(f"{label} must not carry credentials")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise Refusal(f"{label} must be a bare origin such as https://example.supabase.co")
    host = parts.hostname.lower()
    if parts.scheme == "http" and not _is_private_host(host):
        raise Refusal(
            f"{label} uses plain http for a public host; the API key would travel unencrypted"
        )
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.scheme}://{host}:{port}"


def load_targets(path: Path) -> dict[str, Target]:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise Refusal(
            f"no target file at {path}. Live checks only run against targets declared "
            "there; copy webcare.example.toml to webcare.toml and fill it in."
        ) from None
    except tomllib.TOMLDecodeError as error:
        raise Refusal(f"{path} is not valid TOML: {error}") from None

    targets: dict[str, Target] = {}
    for entry in raw.get("target", []):
        name = str(entry.get("name", "")).strip()
        env = entry.get("env")
        data = entry.get("data")
        if not name:
            raise Refusal(f"{path}: every [[target]] needs a name")
        if name in targets:
            raise Refusal(f"{path}: target {name!r} is declared twice")
        if env not in ENVIRONMENTS:
            raise Refusal(f"{path}: target {name!r} needs env = one of {', '.join(ENVIRONMENTS)}")
        if data not in DATA_KINDS:
            raise Refusal(f"{path}: target {name!r} needs data = one of {', '.join(DATA_KINDS)}")
        db = entry.get("db")
        rest = entry.get("rest")
        if db is not None:
            _normalize_db(str(db), name)
        if rest is not None:
            _origin(str(rest), f"target {name!r} rest")
        project_ref = entry.get("project_ref")
        if project_ref is not None and not _PROJECT_REF.match(str(project_ref)):
            raise Refusal(
                f"{path}: target {name!r} has a project_ref that is not a Supabase project "
                "reference (20 lower-case letters)"
            )
        schemas = tuple(str(s) for s in entry.get("schemas", ["public"]))
        if not schemas:
            raise Refusal(f"{path}: target {name!r} has an empty `schemas` list")
        targets[name] = Target(
            name=name,
            env=env,
            data=data,
            db=str(db) if db is not None else None,
            rest=str(rest) if rest is not None else None,
            schemas=schemas,
            project_ref=str(project_ref) if project_ref is not None else None,
            expected_public=tuple(str(t) for t in entry.get("expected_public", [])),
            expected_anon_functions=tuple(
                str(f) for f in entry.get("expected_anon_functions", [])
            ),
            expected_public_buckets=tuple(str(b) for b in entry.get("expected_public_buckets", [])),
            expected_open_signup=entry.get("expected_open_signup") is True,
            advisors_ignore=_lint_names(entry.get("advisors_ignore", []), path, name),
            expected_cron_jobs=tuple(str(j) for j in entry.get("expected_cron_jobs", [])),
        )
    return targets


def _lint_names(value, path: Path, target: str) -> tuple[str, ...]:
    names = tuple(str(item) for item in value) if isinstance(value, list) else ()
    for item in names:
        if not re.fullmatch(r"[a-z0-9_]{3,80}", item):
            raise Refusal(
                f"{path}: target {target!r} lists advisors_ignore entry {item!r}, which is not "
                "a lint name such as authenticated_security_definer_function_executable"
            )
    return names


def get_target(path: Path, name: str) -> Target:
    targets = load_targets(path)
    if name not in targets:
        known = ", ".join(sorted(targets)) or "none"
        raise Refusal(f"target {name!r} is not declared in {path} (declared: {known})")
    return targets[name]
