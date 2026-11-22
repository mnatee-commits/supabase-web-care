"""Read-only access to a live database for catalog checks.

Safety here rests on what the connecting role is able to do, which is checked
before anything else runs, and not on trusting a setting the session could
change. A role that is superuser, bypasses RLS, or can write to application
tables is refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .model import ERROR, CheckResult, Finding, Refusal
from .targets import DbEndpoint, Target

EXTRA_CHECKS_FILE = Path(__file__).resolve().parent.parent / "sql" / "extra-checks.sql"
RELATION_KINDS = ("r", "p", "v", "m", "f")
OVERRIDE_FLAG = "--allow-privileged-role"
MAX_ROWS_PER_EXTRA_CHECK = 500
EXTRA_TITLE = "Catalog checks beyond pgrls (policies, Storage, function guards, default privileges)"
FUNCTIONS_TITLE = "SECURITY DEFINER functions callable without signing in"

_WRITE_WORDS = re.compile(
    r"\b(insert|update|delete|merge|truncate|drop|alter|create|grant|revoke|copy|call|do|"
    r"set|reset|vacuum|analyze|reindex|cluster|lock|comment|refresh|execute|prepare|"
    r"listen|notify|begin|commit|rollback|savepoint|import|security)\b",
    re.IGNORECASE,
)

_ROLE_FACTS_SQL = """
select current_user as role_name,
       r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolreplication,
       current_setting('transaction_read_only') as tx_read_only,
       current_setting('server_version') as server_version,
       current_database() as database_name,
       (select coalesce(array_agg(g.rolname::text order by g.rolname), '{}')
          from pg_catalog.pg_auth_members m
          join pg_catalog.pg_roles g on g.oid = m.roleid
         where m.member = r.oid) as member_of
  from pg_catalog.pg_roles r
 where r.rolname = current_user
"""

_REACH_SQL = """
select count(*) as total,
       count(*) filter (where has_table_privilege(c.oid, 'SELECT')) as readable,
       count(*) filter (
         where c.relkind in ('r', 'p')
           and (has_table_privilege(c.oid, 'INSERT')
             or has_table_privilege(c.oid, 'UPDATE')
             or has_table_privilege(c.oid, 'DELETE')
             or has_table_privilege(c.oid, 'TRUNCATE'))
       ) as writable
  from pg_catalog.pg_class c
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
 where n.nspname = any(%(schemas)s)
   and c.relkind::text = any(%(kinds)s)
"""

_ANON_READABLE_SQL = """
select c.relname::text as relation
  from pg_catalog.pg_class c
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
 where n.nspname = %(schema)s
   and c.relkind::text = any(%(kinds)s)
   and exists (select 1 from pg_catalog.pg_roles where rolname = 'anon')
   and has_table_privilege('anon', c.oid, 'SELECT')
 order by 1
"""

_DEFINER_FUNCTIONS_SQL = """
select n.nspname::text as schema_name,
       p.proname::text as function_name,
       pg_catalog.oidvectortypes(p.proargtypes) as arg_types,
       (p.proacl is null or exists (
          select 1 from pg_catalog.aclexplode(p.proacl) a
           where a.grantee = 0 and a.privilege_type = 'EXECUTE')) as public_may,
       case when exists (select 1 from pg_catalog.pg_roles where rolname = 'anon')
            then pg_catalog.has_function_privilege('anon', p.oid, 'EXECUTE')
            else false end as anon_may
  from pg_catalog.pg_proc p
  join pg_catalog.pg_namespace n on n.oid = p.pronamespace
 where n.nspname = any(%(schemas)s)
   and p.prosecdef
 order by 1, 2, 3
"""


@dataclass(frozen=True)
class RoleFacts:
    role_name: str
    superuser: bool
    bypass_rls: bool
    create_role: bool
    create_db: bool
    replication: bool
    tx_read_only: bool
    server_version: str
    database: str
    member_of: tuple[str, ...]
    relations_total: int
    relations_readable: int
    relations_writable: int

    @property
    def privileged(self) -> bool:
        return self.superuser or self.bypass_rls or self.relations_writable > 0

    def problems(self) -> list[str]:
        found = []
        if self.superuser:
            found.append("is a superuser")
        if self.bypass_rls:
            found.append("bypasses row level security")
        if self.relations_writable:
            found.append(f"can write to {self.relations_writable} application tables")
        return found

    def summary(self) -> str:
        return (
            f"role {self.role_name} on database {self.database} "
            f"(Postgres {self.server_version}): superuser={self.superuser}, "
            f"bypassrls={self.bypass_rls}, read-only transaction={self.tx_read_only}, "
            f"readable relations={self.relations_readable}/{self.relations_total}, "
            f"writable tables={self.relations_writable}"
        )


def connect(dsn: str):
    """Open a session that is read-only at the session and transaction level."""
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise Refusal(
            "live database checks need psycopg, which is installed together with pgrls"
        ) from error
    try:
        connection = psycopg.connect(dsn, connect_timeout=10, row_factory=dict_row)
    except psycopg.Error as error:
        # The driver's message can echo connection details; keep only its class.
        raise Refusal(f"could not connect to the database ({type(error).__name__})") from None
    connection.autocommit = True
    connection.execute("set default_transaction_read_only = on")
    connection.execute("set statement_timeout = '15s'")
    connection.execute("set lock_timeout = '2s'")
    connection.autocommit = False
    connection.read_only = True
    return connection


def role_facts(connection, schemas: Iterable[str]) -> RoleFacts:
    schemas = list(schemas)
    row = connection.execute(_ROLE_FACTS_SQL).fetchone()
    reach = connection.execute(
        _REACH_SQL, {"schemas": schemas, "kinds": list(RELATION_KINDS)}
    ).fetchone()
    connection.rollback()
    return RoleFacts(
        role_name=row["role_name"],
        superuser=row["rolsuper"],
        bypass_rls=row["rolbypassrls"],
        create_role=row["rolcreaterole"],
        create_db=row["rolcreatedb"],
        replication=row["rolreplication"],
        tx_read_only=row["tx_read_only"] == "on",
        server_version=row["server_version"],
        database=row["database_name"],
        member_of=tuple(row["member_of"]),
        relations_total=reach["total"],
        relations_readable=reach["readable"],
        relations_writable=reach["writable"],
    )


def ensure_role_is_safe(facts: RoleFacts, allow_privileged: bool) -> None:
    problems = facts.problems()
    if problems and not allow_privileged:
        raise Refusal(
            f"the connecting role {facts.role_name} {' and '.join(problems)}. Connect as the "
            f"audit role from sql/auditor-role.sql instead. For a throwaway local database "
            f"with synthetic data only, {OVERRIDE_FLAG} skips this check."
        )


def open_checked(
    target: Target,
    dsn: str,
    owner_approved: bool,
    allow_privileged: bool,
) -> tuple[object, DbEndpoint, RoleFacts]:
    """Apply every guard rail, then return an open read-only connection."""
    target.ensure_allowed(owner_approved)
    endpoint = target.ensure_db_matches(dsn)
    if allow_privileged and target.needs_owner_approval:
        raise Refusal(
            f"{OVERRIDE_FLAG} is for throwaway databases with synthetic data. Target "
            f"{target.describe()} does not qualify."
        )
    connection = connect(dsn)
    try:
        facts = role_facts(connection, target.schemas)
        ensure_role_is_safe(facts, allow_privileged)
    except BaseException:
        connection.close()
        raise
    return connection, endpoint, facts


def schema_exists(connection, schema: str) -> bool:
    row = connection.execute(
        "select 1 as found from pg_catalog.pg_namespace where nspname = %(schema)s",
        {"schema": schema},
    ).fetchone()
    connection.rollback()
    return row is not None


def anon_readable_relations(connection, schema: str) -> list[str]:
    rows = connection.execute(
        _ANON_READABLE_SQL, {"schema": schema, "kinds": list(RELATION_KINDS)}
    ).fetchall()
    connection.rollback()
    return [row["relation"] for row in rows]


@dataclass(frozen=True)
class ExtraCheck:
    id: str
    severity: str
    title: str
    sql: str


def assert_single_select(sql: str) -> None:
    """Refuse anything that is not one plain SELECT statement."""
    body = re.sub(r"'(?:[^']|'')*'", "''", sql)  # ignore string literals
    stripped = body.strip().rstrip(";").strip()
    first_word = stripped.split(None, 1)[0].lower() if stripped else ""
    if first_word not in ("select", "with"):
        raise Refusal("an extra check does not start with SELECT or WITH")
    if ";" in stripped:
        raise Refusal("an extra check holds more than one statement")
    word = _WRITE_WORDS.search(stripped)
    if word:
        raise Refusal(f"an extra check contains the keyword {word.group(0)!r}")


def load_extra_checks(path: Path = EXTRA_CHECKS_FILE) -> list[ExtraCheck]:
    checks: list[ExtraCheck] = []
    current: dict | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("-- check:"):
            if current:
                checks.append(_finish_check(current))
            current = {"id": stripped.split(":", 1)[1].strip(), "lines": []}
        elif current is None:
            continue
        elif stripped.startswith("-- severity:"):
            current["severity"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("-- title:"):
            current["title"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("--"):
            continue
        else:
            current["lines"].append(line)
    if current:
        checks.append(_finish_check(current))
    return checks


def _finish_check(raw: dict) -> ExtraCheck:
    sql = "\n".join(raw["lines"]).strip().rstrip(";").strip()
    assert_single_select(sql)
    if raw.get("severity") not in ("high", "medium", "low", "info") or not raw.get("title"):
        raise Refusal(f"extra check {raw['id']!r} needs a valid severity and a title")
    return ExtraCheck(id=raw["id"], severity=raw["severity"], title=raw["title"], sql=sql)


def run_extra_checks(connection, schemas: Iterable[str], evidence: str) -> CheckResult:
    result = CheckResult(
        id="extra_live",
        title=EXTRA_TITLE,
        evidence=evidence,
    )
    try:
        checks = load_extra_checks()
    except (OSError, Refusal) as error:
        result.status = "ERROR"
        result.reason = f"could not load sql/extra-checks.sql: {error}"
        return result
    import psycopg

    params = {"schemas": list(schemas)}
    for check in checks:
        try:
            rows = connection.execute(check.sql, params).fetchmany(MAX_ROWS_PER_EXTRA_CHECK)
        except psycopg.Error as error:
            connection.rollback()
            result.notes.append(f"{check.id}: could not run ({type(error).__name__})")
            continue
        connection.rollback()
        add_extra_findings(result, check, rows)
    return finish_extra_checks(result)


def add_extra_findings(result: CheckResult, check: ExtraCheck, rows) -> None:
    for row in rows:
        result.findings.append(
            Finding(
                source="extra_live",
                rule=check.id,
                severity=check.severity,
                location=str(row["location"]),
                message=f"{check.title}. {row['detail']}",
            )
        )


def finish_extra_checks(result: CheckResult) -> CheckResult:
    result.notes.append(
        "Role matching in update_without_select compares the roles named on the "
        "policies and does not follow role inheritance."
    )
    return result.finish()


def _function_keys(schema: str, name: str, arg_types: str) -> set[str]:
    """Every spelling an allowlist entry may use for one function."""
    compact = arg_types.replace(" ", "").lower()
    schema, name = schema.lower(), name.lower()
    return {name, f"{schema}.{name}", f"{name}({compact})", f"{schema}.{name}({compact})"}


def run_function_exposure(connection, target: Target, evidence: str) -> CheckResult:
    """SECURITY DEFINER functions a visitor who is not signed in may execute.

    In a schema reached only through functions, these functions are the access
    control. The check compares what `anon` may execute with the functions the
    target declares as public on purpose, in both directions.
    """
    result = CheckResult(id="functions_live", title=FUNCTIONS_TITLE, evidence=evidence)
    import psycopg

    schemas = list(target.schemas)
    try:
        rows = connection.execute(_DEFINER_FUNCTIONS_SQL, {"schemas": schemas}).fetchall()
        anon_exists = connection.execute(
            "select exists (select 1 from pg_catalog.pg_roles where rolname = 'anon') as found"
        ).fetchone()["found"]
    except psycopg.Error as error:
        connection.rollback()
        result.status = ERROR
        result.reason = f"could not read function privileges ({type(error).__name__})"
        return result
    connection.rollback()
    return judge_function_exposure(
        result, rows, anon_exists, schemas, target.expected_anon_functions
    )


def judge_function_exposure(
    result: CheckResult,
    rows,
    anon_exists: bool,
    schemas: list[str],
    expected_anon_functions: Iterable[str],
) -> CheckResult:
    """Turn rows of SECURITY DEFINER functions into findings.

    Shared by the live check and the snapshot check, so both judge alike.
    """
    expected = {entry.replace(" ", "").lower(): entry for entry in expected_anon_functions}
    matched: set[str] = set()
    callable_by_anon = 0
    for row in rows:
        location = f"{row['schema_name']}.{row['function_name']}({row['arg_types']})"
        keys = _function_keys(row["schema_name"], row["function_name"], row["arg_types"])
        allowed = keys & expected.keys()
        if row["anon_may"]:
            callable_by_anon += 1
            matched |= allowed
        if row["anon_may"] and not allowed:
            route = (
                "through the EXECUTE that every new function gives to PUBLIC"
                if row["public_may"]
                else "through a grant made directly to anon"
            )
            result.findings.append(
                Finding(
                    source="functions_live",
                    rule="secdef_anon_executable",
                    severity="high" if expected else "medium",
                    location=location,
                    message=(
                        f"SECURITY DEFINER function can be executed without signing in, {route}. "
                        "It runs with its owner's rights, so its body is the only access "
                        "control. Revoke EXECUTE from PUBLIC and anon, or list the function "
                        "in expected_anon_functions after reading what it does."
                    ),
                )
            )
        elif row["public_may"]:
            result.findings.append(
                Finding(
                    source="functions_live",
                    rule="secdef_public_execute",
                    severity="medium",
                    location=location,
                    message=(
                        "PUBLIC holds EXECUTE on this SECURITY DEFINER function. Every role is "
                        "a member of PUBLIC, so a REVOKE from one role does not close it. "
                        "Revoke from PUBLIC and grant the roles that need it by name."
                    ),
                )
            )
    for key in sorted(expected.keys() - matched):
        result.findings.append(
            Finding(
                source="functions_live",
                rule="expected_anon_function_missing",
                severity="low",
                location=expected[key],
                message=(
                    "Listed in expected_anon_functions, but no SECURITY DEFINER function of "
                    "that name is executable by anon. Either the page that calls it is "
                    "broken or the list is out of date."
                ),
            )
        )

    result.notes.append(
        f"{len(rows)} SECURITY DEFINER functions in {', '.join(schemas)}; anon may execute "
        f"{callable_by_anon}; {len(matched)} allowlist entries matched"
    )
    if not anon_exists:
        result.notes.append("this database has no role named anon, so only PUBLIC grants were judged")
    elif callable_by_anon and not expected:
        result.notes.append(
            "The target declares no expected_anon_functions. After reading each function, list "
            "the ones that are public on purpose there; later runs then report only new ones, "
            "at high severity."
        )
    result.notes.append(
        "This reads EXECUTE privileges only. It does not check USAGE on the schema, whether "
        "the Data API exposes the schema, or what the function body does."
    )
    return result.finish()
