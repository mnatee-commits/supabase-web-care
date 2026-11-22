"""Inventory of one database, and the differences between two.

`webcare inventory` saves what a database is made of: its migration history,
tables with their RLS state and grants, column grants, default privileges,
functions (with a hash of each body), policies (with a hash of each expression),
extensions, scheduled jobs and Storage buckets. `webcare compare` reports what
differs between two such files.

Two environments that drift apart are a common cause of trouble: a migration
applied to one and not the other, a column restriction that only staging has, a
job that only exists in one place. Comparing inventories finds those without
anyone having to know where to look.

What a file holds: names, yes/no facts, privilege names, version strings and
md5 hashes. It holds no row of any application table, no function body and no
policy expression; two bodies or expressions are compared by their hash only.
Every statement is a single SELECT built here. Parts that may be missing (the
migration history, pg_cron, Storage) are probed first, so a database without
them is read without error and the file says why that part is absent.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import __version__, health, live, storage_buckets
from .model import Refusal
from .snapshot import _IDENTIFIER, _text_array
from .targets import Target

FORMAT = "webcare-inventory/1"
PART_FORMAT = "webcare-inventory-part/1"
MAX_BYTES = 20 * 1024 * 1024
_ROLES = "('anon', 'authenticated', 'service_role')"


def _part(name: str, rows_sql: str) -> str:
    return (
        f"select jsonb_build_object('format', '{PART_FORMAT}', 'part', '{name}', 'rows', "
        f"coalesce(({rows_sql}), '{{}}'::jsonb)) as part"
    )


def _privileges(acl_expression: str, roles_filter: bool = True) -> str:
    """{role: [privileges]} for an aclitem[] expression."""
    where = f"where a.grantee = 0 or r.rolname in {_ROLES}" if roles_filter else ""
    return (
        "select jsonb_object_agg(g.who, g.privs) from ("
        "select coalesce(r.rolname, 'PUBLIC') as who, "
        "jsonb_agg(distinct a.privilege_type order by a.privilege_type) as privs "
        f"from pg_catalog.aclexplode({acl_expression}) a "
        f"left join pg_catalog.pg_roles r on r.oid = a.grantee {where} group by 1) g"
    )


def plain_parts(schemas: list[str]) -> dict[str, str]:
    """Parts that every Postgres has. Each is one SELECT returning one JSON value."""
    s = _text_array(schemas)
    return {
        "tables": _part("tables", f"""select jsonb_object_agg(q.k, q.v) from (
  select n.nspname || '.' || c.relname as k,
         jsonb_build_object(
           'kind', c.relkind::text,
           'rls', c.relrowsecurity,
           'force_rls', c.relforcerowsecurity,
           'grants', coalesce(({_privileges("coalesce(c.relacl, pg_catalog.acldefault('r', c.relowner))")}), '{{}}'::jsonb)
         ) as v
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
   where n.nspname = any({s}) and c.relkind in ('r', 'p', 'v', 'm', 'f')
) q"""),
        "column_grants": _part("column_grants", f"""select jsonb_object_agg(t.k, t.v) from (
  select q.k, jsonb_object_agg(q.who, q.privs) as v from (
    select n.nspname || '.' || c.relname || '.' || att.attname as k,
           coalesce(r.rolname, 'PUBLIC') as who,
           jsonb_agg(distinct x.privilege_type order by x.privilege_type) as privs
      from pg_catalog.pg_attribute att
      join pg_catalog.pg_class c on c.oid = att.attrelid
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      cross join lateral pg_catalog.aclexplode(att.attacl) x
      left join pg_catalog.pg_roles r on r.oid = x.grantee
     where n.nspname = any({s}) and att.attnum > 0 and not att.attisdropped and att.attacl is not null
       and (x.grantee = 0 or r.rolname in {_ROLES})
     group by 1, 2
  ) q group by q.k
) t"""),
        "default_acl": _part("default_acl", f"""select jsonb_object_agg(q.k, q.v) from (
  select pg_catalog.pg_get_userbyid(d.defaclrole) || '|'
           || case when d.defaclnamespace = 0 then 'GLOBAL' else d.defaclnamespace::regnamespace::text end
           || '|' || d.defaclobjtype::text as k,
         coalesce(({_privileges("d.defaclacl", roles_filter=False)}), '{{}}'::jsonb) as v
    from pg_catalog.pg_default_acl d
) q"""),
        "functions": _part("functions", f"""select jsonb_object_agg(q.k, q.v) from (
  select n.nspname || '.' || p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' as k,
         jsonb_build_object(
           'secdef', p.prosecdef,
           'anon', case when pg_catalog.to_regrole('anon') is not null
                        then pg_catalog.has_function_privilege('anon', p.oid, 'EXECUTE') end,
           'authenticated', case when pg_catalog.to_regrole('authenticated') is not null
                                 then pg_catalog.has_function_privilege('authenticated', p.oid, 'EXECUTE') end,
           'search_path_pinned', exists (
             select 1 from unnest(coalesce(p.proconfig, '{{}}'::text[])) cfg where cfg like 'search_path=%'),
           'body_md5', md5(p.prosrc)
         ) as v
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = any({s}) and p.prokind in ('f', 'p')
     and not exists (select 1 from pg_catalog.pg_depend d where d.objid = p.oid and d.deptype = 'e')
) q"""),
        "policies": _part("policies", f"""select jsonb_object_agg(q.k, q.v) from (
  select pol.schemaname || '.' || pol.tablename || '.' || pol.policyname as k,
         jsonb_build_object(
           'command', pol.cmd,
           'permissive', pol.permissive,
           'roles', to_jsonb(pol.roles),
           'expression_md5', md5(coalesce(pol.qual, '') || '|' || coalesce(pol.with_check, ''))
         ) as v
    from pg_catalog.pg_policies pol
   where pol.schemaname = any({s})
) q"""),
        "extensions": _part("extensions", """select jsonb_object_agg(e.extname, e.extversion)
    from pg_catalog.pg_extension e"""),
    }


MIGRATIONS_PROBE = health.build_probe("supabase_migrations", ("schema_migrations",))


def _migrations_why_not(probe: dict) -> str:
    if not probe.get("installed"):
        return "this database has no supabase_migrations.schema_migrations table"
    if not probe.get("readable"):
        return f"role {probe.get('role', 'the connected role')} may not read the migration history"
    return ""


GUARDED_PARTS = {
    "migrations": (
        MIGRATIONS_PROBE, _migrations_why_not,
        _part("migrations", """select jsonb_object_agg(m.version, to_jsonb(m) ->> 'name')
    from supabase_migrations.schema_migrations m"""),
    ),
    "cron_jobs": (
        health.PROBE_SQL, health.why_not,
        _part("cron_jobs", """select jsonb_object_agg(coalesce(j.jobname, 'job ' || j.jobid),
           jsonb_build_object('schedule', j.schedule, 'active', j.active))
    from cron.job j"""),
    ),
    "buckets": (
        storage_buckets.PROBE_SQL, storage_buckets.why_not,
        _part("buckets", """select jsonb_object_agg(b.id, jsonb_build_object('public', b.public))
    from storage.buckets b"""),
    ),
}


def statements(schemas: list[str]) -> list[str]:
    """Every statement this module may send, for the single-SELECT guard and for tests."""
    parts = list(plain_parts(schemas).values())
    for probe, _why, sql in GUARDED_PARTS.values():
        parts += [probe, sql]
    return parts


def _rows(answer, name: str) -> dict:
    part = health.unwrap(answer, "part", PART_FORMAT)
    if part is None or part.get("part") != name or not isinstance(part.get("rows"), dict):
        raise Refusal(f"the answer for the {name} part was not understood")
    return part["rows"]


def collect(ask: Callable[[str], object], target: Target) -> dict:
    """Read every part through `ask`, which sends one SELECT and returns its answer."""
    schemas = list(target.schemas)
    for schema in schemas:
        if not _IDENTIFIER.match(schema):
            raise Refusal(f"schema name {schema!r} is not a plain lower-case identifier")
    for sql in statements(schemas):
        live.assert_single_select(sql)

    parts: dict[str, dict] = {}
    for name, sql in plain_parts(schemas).items():
        parts[name] = {"rows": _rows(ask(sql), name)}
    for name, (probe_sql, why_not, sql) in GUARDED_PARTS.items():
        probe = health.unwrap(ask(probe_sql), "probe", health.PROBE_FORMAT)
        if probe is None:
            parts[name] = {"not_read": "the probe answer was not understood"}
            continue
        reason = why_not(probe)
        parts[name] = {"not_read": reason} if reason else {"rows": _rows(ask(sql), name)}
    return {
        "format": FORMAT,
        "label": target.name,
        "project_ref": target.project_ref,
        "taken_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool_version": __version__,
        "schemas": schemas,
        "parts": parts,
    }


def connection_asker(connection):
    def ask(sql: str):
        try:
            return connection.execute(sql).fetchone()
        finally:
            connection.rollback()

    return ask


def write(path: Path, inventory: dict) -> None:
    path.write_text(json.dumps(inventory, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def load(path: Path) -> dict:
    try:
        if path.stat().st_size > MAX_BYTES:
            raise Refusal(f"inventory file {path.name} is larger than {MAX_BYTES // (1024 * 1024)} MB")
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise Refusal(f"could not read inventory file {path} ({type(error).__name__})") from None
    except ValueError:
        raise Refusal(f"inventory file {path.name} is not valid JSON") from None
    if not isinstance(data, dict) or data.get("format") != FORMAT or not isinstance(data.get("parts"), dict):
        raise Refusal(f"{path.name} is not an inventory in format {FORMAT}; make it with `webcare inventory`")
    return data


# ---- comparing ------------------------------------------------------------

PART_ORDER = ("migrations", "tables", "column_grants", "policies", "functions",
              "default_acl", "cron_jobs", "buckets", "extensions")
MAX_LINES_PER_KIND = 60


def _short(value) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return text if len(text) <= 120 else text[:119] + "…"


def _field_differences(a, b, path: str = "") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        out: list[str] = []
        for key in sorted(set(a) | set(b)):
            out += _field_differences(a.get(key), b.get(key), f"{path}.{key}" if path else str(key))
        return out
    return [] if a == b else [f"{path or 'value'}: {_short(a)} → {_short(b)}"]


def compare(first: dict, second: dict) -> dict:
    """Per part: keys only in the first, only in the second, and keys whose values differ."""
    result: dict[str, dict] = {}
    for name in PART_ORDER:
        a, b = first["parts"].get(name), second["parts"].get(name)
        if not isinstance(a, dict) or not isinstance(b, dict) or "rows" not in a or "rows" not in b:
            reasons = []
            for label, part in ((first["label"], a), (second["label"], b)):
                if not isinstance(part, dict):
                    reasons.append(f"{label}: not in the file")
                elif "rows" not in part:
                    reasons.append(f"{label}: {part.get('not_read', 'not read')}")
            result[name] = {"not_compared": "; ".join(reasons)}
            continue
        rows_a, rows_b = a["rows"], b["rows"]
        changed = {}
        for key in sorted(set(rows_a) & set(rows_b)):
            fields = _field_differences(rows_a[key], rows_b[key])
            if fields:
                changed[key] = fields
        result[name] = {
            "only_first": sorted(set(rows_a) - set(rows_b)),
            "only_second": sorted(set(rows_b) - set(rows_a)),
            "changed": changed,
            "same": len(set(rows_a) & set(rows_b)) - len(changed),
        }
    return result


def differences(result: dict) -> int:
    return sum(
        len(part["only_first"]) + len(part["only_second"]) + len(part["changed"])
        for part in result.values() if "not_compared" not in part
    )


TEXT = {
    "en": {
        "title": "# Inventory comparison", "first": "First", "second": "Second",
        "total": "Differences in all", "not_compared": "Not compared", "same": "identical",
        "only": "Only in", "changed": "Different", "more": "and {n} more; all are in the JSON output",
        "note": "Hashes stand for function bodies and policy expressions, which the files do not hold. "
                "A difference is not always a mistake: decide for each whether it is intended.",
    },
    "th": {
        "title": "# เทียบบัญชีรายการสองฐาน", "first": "ฐานแรก", "second": "ฐานที่สอง",
        "total": "จำนวนจุดที่ต่างทั้งหมด", "not_compared": "ไม่ได้เทียบ", "same": "เหมือนกัน",
        "only": "มีเฉพาะใน", "changed": "ต่างกัน", "more": "และอีก {n} รายการ ดูทั้งหมดในผลแบบ JSON",
        "note": "ค่าแฮชใช้แทนโค้ดของฟังก์ชันและเงื่อนไขของ policy ซึ่งไม่ได้เก็บไว้ในไฟล์ "
                "จุดที่ต่างไม่ได้แปลว่าผิดเสมอ ต้องตัดสินทีละจุดว่าตั้งใจหรือไม่",
    },
}


def to_markdown(first: dict, second: dict, result: dict, lang: str = "en") -> str:
    t = TEXT["th" if lang == "th" else "en"]
    lines = [
        t["title"], "",
        f"- {t['first']}: {first['label']} ({first.get('project_ref') or '-'}), {first.get('taken_at')}",
        f"- {t['second']}: {second['label']} ({second.get('project_ref') or '-'}), {second.get('taken_at')}",
        f"- {t['total']}: {differences(result)}", "", t["note"],
    ]
    for name in PART_ORDER:
        part = result[name]
        lines += ["", f"## {name}", ""]
        if "not_compared" in part:
            lines.append(f"- {t['not_compared']}: {part['not_compared']}")
            continue
        lines.append(f"- {t['same']}: {part['same']}")
        for label, keys in ((first["label"], part["only_first"]), (second["label"], part["only_second"])):
            if keys:
                lines.append(f"- {t['only']} {label} ({len(keys)}):")
                lines += [f"  - `{key}`" for key in keys[:MAX_LINES_PER_KIND]]
                if len(keys) > MAX_LINES_PER_KIND:
                    lines.append(f"  - {t['more'].format(n=len(keys) - MAX_LINES_PER_KIND)}")
        if part["changed"]:
            lines.append(f"- {t['changed']} ({len(part['changed'])}):")
            for key in list(part["changed"])[:MAX_LINES_PER_KIND]:
                for field in part["changed"][key][:5]:
                    lines.append(f"  - `{key}` {field}")
            if len(part["changed"]) > MAX_LINES_PER_KIND:
                lines.append(f"  - {t['more'].format(n=len(part['changed']) - MAX_LINES_PER_KIND)}")
    return "\n".join(lines) + "\n"
