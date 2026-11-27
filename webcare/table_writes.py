"""Which tables the API roles may write to, against what the target declares.

One read-only statement. For each table, view and foreign table in the
target's schemas it asks Postgres whether `anon` and `authenticated` hold
INSERT, UPDATE or DELETE, counting privileges given to PUBLIC and to roles
they belong to, and privileges on single columns. It also asks about TRUNCATE,
REFERENCES, TRIGGER and (Postgres 17) MAINTAIN, which the Data API never uses
but which Supabase's default privileges grant to both roles, and whether RLS is
on. It reads no row of any table and no policy expression.

A privilege is the first gate; RLS policies are the second. A write privilege
on a table with RLS on is not a hole by itself, but it is the gate that a
missing or loose policy opens onto, and Supabase used to grant every new table
to both roles by default. The target lists the writes it means to allow in
`expected_table_writes`; everything else is reported.
"""

from __future__ import annotations

from typing import Callable

from . import health, live
from .model import ERROR, CheckResult, Finding
from .targets import TABLE_WRITE_COMMANDS, TABLE_WRITE_ROLES, Target

FORMAT = "webcare-table-writes/1"
TITLE = "Tables the API roles may write to"
SOURCE = "table_writes"
MAX_ROWS = 5000
SHOWN = 8


def build_sql(schemas) -> str:
    names = ", ".join("'" + s.replace("'", "''") + "'" for s in schemas)
    roles = ", ".join(f"'{role}'" for role in TABLE_WRITE_ROLES)
    return f"""select jsonb_build_object(
  'format', '{FORMAT}',
  'taken_at', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
  'roles', coalesce((select jsonb_agg(r.rolname order by r.rolname) from pg_catalog.pg_roles r where r.rolname in ({roles})), '[]'::jsonb),
  'tables', coalesce((
    select jsonb_agg(to_jsonb(q) order by q.table_name, q.role) from (
      select w.table_name, w.kind, w.rls, w.security_invoker, w.role,
             array_remove(array[
               case when w.ins then 'insert' end,
               case when w.upd then 'update' end,
               case when w.del then 'delete' end], null) as writes,
             array_remove(array[
               case when w.ins and not w.ins_all then 'insert' end,
               case when w.upd and not w.upd_all then 'update' end], null) as columns_only,
             w.trunc as may_truncate,
             array_remove(array[
               case when w.refs then 'references' end,
               case when w.trig then 'trigger' end,
               case when w.maint then 'maintain' end], null) as unused
        from (
          select n.nspname || '.' || c.relname as table_name, c.relkind::text as kind,
                 c.relrowsecurity as rls, r.rolname::text as role,
                 exists (select 1 from unnest(coalesce(c.reloptions, '{{}}'::text[])) o
                          where o ~* '^security_invoker=(true|on|yes|1)$') as security_invoker,
                 pg_catalog.has_any_column_privilege(r.oid, c.oid, 'INSERT') as ins,
                 pg_catalog.has_table_privilege(r.oid, c.oid, 'INSERT') as ins_all,
                 pg_catalog.has_any_column_privilege(r.oid, c.oid, 'UPDATE') as upd,
                 pg_catalog.has_table_privilege(r.oid, c.oid, 'UPDATE') as upd_all,
                 pg_catalog.has_table_privilege(r.oid, c.oid, 'DELETE') as del,
                 pg_catalog.has_table_privilege(r.oid, c.oid, 'TRUNCATE') as trunc,
                 pg_catalog.has_table_privilege(r.oid, c.oid, 'REFERENCES') as refs,
                 pg_catalog.has_table_privilege(r.oid, c.oid, 'TRIGGER') as trig,
                 case when current_setting('server_version_num')::int >= 170000
                      then pg_catalog.has_table_privilege(r.oid, c.oid, 'MAINTAIN')
                      else false end as maint
            from pg_catalog.pg_class c
            join pg_catalog.pg_namespace n on n.oid = c.relnamespace
            cross join pg_catalog.pg_roles r
           where n.nspname = any(array[{names}]::text[])
             and c.relkind in ('r', 'p', 'v', 'f')
             and r.rolname in ({roles})
        ) w
       where w.ins or w.upd or w.del or w.trunc or w.refs or w.trig or w.maint
       order by w.rls, 1, 4
       limit {MAX_ROWS}
    ) q
  ), '[]'::jsonb)
) as table_writes"""


def _declared(target: Target) -> dict[str, dict[str, set[str]]]:
    """role -> table -> commands the target allows."""
    allowed: dict[str, dict[str, set[str]]] = {role: {} for role in TABLE_WRITE_ROLES}
    for role, entries in target.expected_table_writes.items():
        for entry in entries:
            table, _, commands = entry.partition(":")
            table = table.strip().lower()
            if "." not in table:
                table = "public." + table
            wanted = {c.strip() for c in commands.split(",") if c.strip()} or set(TABLE_WRITE_COMMANDS)
            allowed[role].setdefault(table, set()).update(wanted)
    return allowed


def _unguarded(row: dict) -> str:
    """Why RLS does not stand behind this object's write privilege, or "" when it does."""
    kind = row.get("kind")
    if kind == "v":
        if row.get("security_invoker"):
            return ""  # the base tables' RLS applies to the caller
        return ("the view runs with its owner's rights, so the base tables' RLS does not apply "
                "to the caller. Set security_invoker = true on the view, or revoke the privilege.")
    if kind == "f":
        return ("a foreign table cannot have RLS, so nothing else stops it. Revoke the privilege.")
    if not row.get("rls"):
        return "RLS is off, so nothing else stops it. Turn RLS on or revoke the privilege."
    return ""


def _list(names: list[str]) -> str:
    shown = ", ".join(names[:SHOWN])
    return shown + (f" and {len(names) - SHOWN} more" if len(names) > SHOWN else "")


def judge(result: CheckResult, report: dict, target: Target) -> CheckResult:
    rows = [row for row in report.get("tables", []) if isinstance(row, dict)]
    present_roles = {str(role) for role in report.get("roles", [])}
    declared = _declared(target)
    any_declared = bool(target.expected_table_writes)

    def add(rule: str, severity: str, location: str, message: str) -> None:
        result.findings.append(Finding(SOURCE, rule, severity, location, message))

    undeclared: dict[str, list[str]] = {role: [] for role in TABLE_WRITE_ROLES}
    truncate: dict[str, list[str]] = {role: [] for role in TABLE_WRITE_ROLES}
    unused: dict[str, dict[str, list[str]]] = {role: {} for role in TABLE_WRITE_ROLES}
    seen: dict[str, set[str]] = {role: set() for role in TABLE_WRITE_ROLES}
    for row in rows:
        role, table = str(row.get("role")), str(row.get("table_name")).lower()
        if role not in declared:
            continue
        if row.get("may_truncate"):
            truncate[role].append(table)
        for privilege in row.get("unused") or []:
            unused[role].setdefault(str(privilege).upper(), []).append(table)
        writes = {str(w) for w in row.get("writes") or []}
        if not writes:
            continue
        seen[role].add(table)
        partial = {str(c) for c in row.get("columns_only") or []}

        def how(commands) -> str:
            return ", ".join(f"{c} (some columns)" if c in partial else c for c in sorted(commands))

        unguarded = _unguarded(row)
        if unguarded:
            # Declared or not: nothing but the privilege stands in the way.
            add(
                f"{role}_write_without_rls", "high" if role == "anon" else "medium", table,
                f"{role} may {how(writes)} and {unguarded}",
            )
            continue
        extra = writes - declared[role].get(table, set())
        if not extra:
            continue
        if any_declared:
            add(
                f"{role}_write_undeclared", "medium" if role == "anon" else "low", table,
                f"{role} may {how(extra)}, which expected_table_writes does not list. RLS policies "
                "are then the only gate; revoke the privilege, or list it after reading the policies.",
            )
        else:
            undeclared[role].append(f"{table} ({how(extra)})")
    for role, tables in undeclared.items():
        if tables:
            add(
                f"{role}_writes_not_declared", "medium" if role == "anon" else "low", f"role {role}",
                f"{role} may write to {len(tables)} tables or views protected only by RLS policies: "
                f"{_list(tables)}. The target declares no expected_table_writes; list the writes "
                "the site needs and revoke the rest.",
            )
    for role, tables in truncate.items():
        if not tables:
            continue
        text = (f"{role} holds TRUNCATE on {len(tables)} tables ({_list(tables)}). TRUNCATE ignores "
                "RLS; the Data API never issues it, but a function running as the caller could. "
                "Revoke it with the write privileges you do not need.")
        add(f"{role}_truncate", "low", f"role {role}", text)
    for role, by_privilege in unused.items():
        if not by_privilege:
            continue
        parts = "; ".join(f"{privilege} on {len(tables)} ({_list(tables)})"
                          for privilege, tables in sorted(by_privilege.items()))
        add(
            f"{role}_unused_table_privileges", "info", f"role {role}",
            f"{role} holds privileges the Data API never uses: {parts}. They come from the "
            "schema's default privileges and need a SQL session running as the role; revoke "
            "them together with TRUNCATE.",
        )
    for role, tables in declared.items():
        stale = sorted(set(tables) - seen[role])
        if stale:
            result.notes.append(
                f"expected_table_writes lists {len(stale)} tables {role} cannot write to "
                f"({_list(stale)}); remove those entries so they cannot excuse a future grant"
            )
    missing = [role for role in TABLE_WRITE_ROLES if role not in present_roles]
    if missing:
        result.notes.append(f"role {', '.join(missing)} does not exist in this database")
    result.notes.append(
        f"{len({str(r.get('table_name')) for r in rows})} tables with a write privilege for "
        f"{' or '.join(TABLE_WRITE_ROLES)}, as of {report.get('taken_at', 'an unknown time')}; "
        "privileges only, no row read"
    )
    if len(rows) >= MAX_ROWS:
        result.notes.append(f"only the first {MAX_ROWS} entries were examined")
    return result.finish()


def run(ask: Callable[[str], object], target: Target, evidence: str) -> CheckResult:
    result = CheckResult(id="table_writes", title=TITLE, evidence=evidence)
    sql = build_sql(target.schemas)
    live.assert_single_select(sql)
    report = health.unwrap(ask(sql), "table_writes", FORMAT)
    if report is None or not isinstance(report.get("tables"), list):
        result.status, result.reason = ERROR, "the answer to the table-privilege query was not understood"
        return result
    return judge(result, report, target)


def run_on_connection(connection, target: Target, evidence: str) -> CheckResult:
    def ask(sql: str):
        try:
            return connection.execute(sql).fetchone()
        finally:
            connection.rollback()

    try:
        return run(ask, target, evidence)
    except Exception as error:  # a failed query must not take the other checks down
        failed = CheckResult(id="table_writes", title=TITLE, evidence=evidence, status=ERROR)
        failed.reason = f"the table-privilege query failed ({type(error).__name__})"
        return failed
