"""Database health: what Supabase's advisors do not report.

One read-only statement, on a direct connection or through `--via-api`:

- indexes left invalid by a CREATE INDEX CONCURRENTLY that failed
- tables with many dead rows (bloat), and tables or the database near
  transaction-ID wraparound
- sessions left idle inside a transaction, and sessions waiting on a lock
- sequences close to the largest value they can give
- connections in use against the limit, the size of the database and its largest
  tables, a Postgres version near the end of its support, extensions with a newer
  version on the server, and the statements that take the most time

It reads system statistics and catalog facts only: no table row, no
`pg_stats` (whose sample values are table data), no query text from
`pg_stat_activity` or `pg_stat_statements`, and no application name. Slow
statements are named by their query id, with counts and timings only; the owner
looks the id up in the dashboard. Sessions of other roles are
visible only to a role with `pg_read_all_stats`; without it that part is
reported as not seen, never as clean. A sequence's current value is read only
where the connected role may read the sequence; the others are counted, not
guessed.

Unindexed foreign keys and RLS policies that call auth.uid() for every row are
left to Supabase's Performance Advisor (`--with-performance`), which already
reports them.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Callable, Optional

from . import health, live
from .model import ERROR, CheckResult, Finding

FORMAT = "webcare-db-health/1"
TITLE = ("Database health: invalid indexes, bloat, transaction age, idle sessions, sequences, "
         "connections, size, versions, slow statements")
SOURCE = "db_health"
SKIPPED_SCHEMAS = ("information_schema", "pg_toast")
MAX_ROWS = 200
TOP_STATEMENTS = 5
TOP_TABLES = 5
# Last day of community support per major version (postgresql.org/support/versioning).
END_OF_LIFE = {12: date(2024, 11, 21), 13: date(2025, 11, 13), 14: date(2026, 11, 12), 15: date(2027, 11, 11),
               16: date(2028, 11, 9), 17: date(2029, 11, 8), 18: date(2030, 11, 14)}
END_OF_LIFE_WARNING_DAYS = 180
# Read through query_to_xml because the view's schema differs between installations
# (`extensions` on Supabase, `public` elsewhere) and a name that does not exist would fail
# the whole statement. Counts and timings only: the `query` column is never selected.
_STATEMENTS_INNER = (
    "select jsonb_agg(to_jsonb(q))::text as j from ("
    "select s.queryid::text as query_id, s.calls, round(s.total_exec_time::numeric) as total_ms, "
    "round(s.mean_exec_time::numeric, 1) as mean_ms, s.rows "
    "from %s s where s.queryid is not null and s.dbid = "
    "(select d.oid from pg_catalog.pg_database d where d.datname = current_database()) "
    f"order by s.total_exec_time desc limit {TOP_STATEMENTS}) q"
)


@dataclass(frozen=True)
class Thresholds:
    dead_rows: int = 10_000
    dead_ratio: float = 0.20
    dead_rows_high: int = 100_000
    dead_ratio_high: float = 0.50
    # Autovacuum starts forced freezing at 200 million by default and Postgres stops
    # accepting writes near 2 billion, so these leave room to act without crying wolf.
    xid_age_medium: int = 500_000_000
    xid_age_high: int = 1_200_000_000
    idle_seconds: int = 5 * 60
    idle_seconds_high: int = 30 * 60
    lock_wait_seconds: int = 60
    sequence_used: float = 0.75
    sequence_used_high: float = 0.90
    connections_used: float = 0.80
    connections_used_high: float = 0.95
    # A statement is worth a look when it is slow on average and has run often enough
    # for the average to mean something.
    slow_mean_ms: float = 1000.0
    slow_calls: int = 20


DEFAULT = Thresholds()


def build_sql(t: Thresholds = DEFAULT) -> str:
    skipped = ", ".join(f"'{name}'" for name in SKIPPED_SCHEMAS)
    return f"""select jsonb_build_object(
  'format', '{FORMAT}',
  'taken_at', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
  'sees_other_sessions', pg_catalog.pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER')
      or (select r.rolsuper from pg_catalog.pg_roles r where r.rolname = current_user),
  'database_xid_age', (select pg_catalog.age(d.datfrozenxid) from pg_catalog.pg_database d
                        where d.datname = current_database()),
  'invalid_indexes', coalesce((select jsonb_agg(to_jsonb(q)) from (
      select n.nspname || '.' || ic.relname as index_name, n.nspname || '.' || tc.relname as table_name,
             pg_catalog.pg_relation_size(ic.oid) as bytes
        from pg_catalog.pg_index i
        join pg_catalog.pg_class ic on ic.oid = i.indexrelid
        join pg_catalog.pg_class tc on tc.oid = i.indrelid
        join pg_catalog.pg_namespace n on n.oid = ic.relnamespace
       where not i.indisvalid and n.nspname !~ '^pg_' and n.nspname not in ({skipped})
       order by 1 limit {MAX_ROWS}) q), '[]'::jsonb),
  'bloat', coalesce((select jsonb_agg(to_jsonb(q)) from (
      select s.schemaname || '.' || s.relname as table_name, s.n_dead_tup as dead_rows,
             s.n_live_tup as live_rows,
             round(s.n_dead_tup::numeric / nullif(s.n_live_tup + s.n_dead_tup, 0), 3) as dead_ratio,
             to_char(greatest(s.last_autovacuum, s.last_vacuum) at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as last_vacuum
        from pg_catalog.pg_stat_user_tables s
       where s.n_dead_tup >= {t.dead_rows}
         and s.n_dead_tup::numeric / nullif(s.n_live_tup + s.n_dead_tup, 0) >= {t.dead_ratio}
       order by s.n_dead_tup desc limit {MAX_ROWS}) q), '[]'::jsonb),
  'xid_age', coalesce((select jsonb_agg(to_jsonb(q)) from (
      select n.nspname || '.' || c.relname as table_name, pg_catalog.age(c.relfrozenxid) as xid_age
        from pg_catalog.pg_class c
        join pg_catalog.pg_namespace n on n.oid = c.relnamespace
       where c.relkind in ('r', 'm', 't') and c.relfrozenxid <> '0'::xid
         and pg_catalog.age(c.relfrozenxid) >= {t.xid_age_medium}
       order by 2 desc limit {MAX_ROWS}) q), '[]'::jsonb),
  'idle_in_transaction', coalesce((select jsonb_agg(to_jsonb(q)) from (
      select coalesce(a.usename::text, 'unknown') as role_name, a.state,
             count(*) as sessions,
             max(extract(epoch from now() - coalesce(a.state_change, a.xact_start)))::bigint as longest_seconds
        from pg_catalog.pg_stat_activity a
       where a.datname = current_database() and a.pid <> pg_catalog.pg_backend_pid()
         and a.state in ('idle in transaction', 'idle in transaction (aborted)')
         and coalesce(a.state_change, a.xact_start) <= now() - interval '{t.idle_seconds} seconds'
       group by 1, 2 order by 1, 2) q), '[]'::jsonb),
  'lock_waits', coalesce((select jsonb_agg(to_jsonb(q)) from (
      select coalesce(a.usename::text, 'unknown') as role_name, count(*) as sessions,
             max(extract(epoch from now() - coalesce(a.query_start, a.state_change)))::bigint as longest_seconds
        from pg_catalog.pg_stat_activity a
       where a.datname = current_database() and a.pid <> pg_catalog.pg_backend_pid()
         and a.wait_event_type = 'Lock'
         and coalesce(a.query_start, a.state_change) <= now() - interval '{t.lock_wait_seconds} seconds'
       group by 1 order by 1) q), '[]'::jsonb),
  'sequences', coalesce((select jsonb_agg(to_jsonb(q)) from (
      select v.sequence_name, v.data_type, v.max_value, v.last_value,
             round((v.last_value - v.min_value)::numeric / nullif(v.max_value - v.min_value, 0), 4) as used
        from (
          select n.nspname || '.' || c.relname as sequence_name,
                 pg_catalog.format_type(s.seqtypid, null) as data_type,
                 s.seqmin as min_value, s.seqmax as max_value,
                 case when c.relkind = 'S' and pg_catalog.has_sequence_privilege(c.oid, 'SELECT, USAGE')
                      then pg_catalog.pg_sequence_last_value(c.oid) end as last_value
            from pg_catalog.pg_sequence s
            join pg_catalog.pg_class c on c.oid = s.seqrelid
            join pg_catalog.pg_namespace n on n.oid = c.relnamespace
           where not s.seqcycle and s.seqincrement > 0
             and n.nspname !~ '^pg_' and n.nspname not in ({skipped})
        ) v
       where v.last_value is not null
         and (v.last_value - v.min_value)::numeric / nullif(v.max_value - v.min_value, 0) >= {t.sequence_used}
       order by 5 desc limit {MAX_ROWS}) q), '[]'::jsonb),
  'sequences_unreadable', (select count(*) from pg_catalog.pg_sequence s
                             join pg_catalog.pg_class c on c.oid = s.seqrelid
                             join pg_catalog.pg_namespace n on n.oid = c.relnamespace
                            where not s.seqcycle and n.nspname !~ '^pg_' and n.nspname not in ({skipped})
                              and c.relkind = 'S'
                              and not (case when c.relkind = 'S'
                                            then pg_catalog.has_sequence_privilege(c.oid, 'SELECT, USAGE') end)),
  'connections', (select jsonb_build_object(
      'in_use', (select coalesce(sum(d.numbackends), 0) from pg_catalog.pg_stat_database d),
      'max', pg_catalog.current_setting('max_connections')::int,
      'reserved', pg_catalog.current_setting('superuser_reserved_connections')::int
                  + coalesce(pg_catalog.current_setting('reserved_connections', true)::int, 0))),
  'database_bytes', pg_catalog.pg_database_size(current_database()),
  'largest_tables', coalesce((select jsonb_agg(to_jsonb(q)) from (
      select n.nspname || '.' || c.relname as table_name, pg_catalog.pg_total_relation_size(c.oid) as bytes
        from pg_catalog.pg_class c
        join pg_catalog.pg_namespace n on n.oid = c.relnamespace
       where c.relkind in ('r', 'm') and n.nspname !~ '^pg_' and n.nspname not in ({skipped})
       order by 2 desc limit {TOP_TABLES}) q), '[]'::jsonb),
  'server_version_num', pg_catalog.current_setting('server_version_num')::int,
  'extension_updates', coalesce((select jsonb_agg(to_jsonb(q)) from (
      select e.name, e.installed_version, e.default_version
        from pg_catalog.pg_available_extensions e
       where e.installed_version is not null and e.installed_version <> e.default_version
       order by 1 limit {MAX_ROWS}) q), '[]'::jsonb),
  'statements', (select case
      when r.rel is not null and pg_catalog.has_table_privilege(r.rel, 'SELECT')
      then coalesce(((xpath('/row/j/text()', pg_catalog.query_to_xml(
             pg_catalog.format('{_STATEMENTS_INNER}', r.rel), false, true, '')))[1])::text::jsonb, '[]'::jsonb)
      end
      from (select (select pg_catalog.format('%I.pg_stat_statements', n.nspname)
                      from pg_catalog.pg_extension e
                      join pg_catalog.pg_namespace n on n.oid = e.extnamespace
                     where e.extname = 'pg_stat_statements') as rel) r)
) as db_health"""


def _rows(report: dict, key: str) -> list[dict]:
    return [row for row in report.get(key) or [] if isinstance(row, dict)]


def _minutes(seconds) -> str:
    seconds = int(seconds or 0)
    return f"{seconds // 60} minutes" if seconds >= 120 else f"{seconds} seconds"


def _size(count) -> str:
    count = int(count or 0)
    for unit, size in (("GB", 1 << 30), ("MB", 1 << 20)):
        if count >= size:
            return f"{count / size:.1f} {unit}"
    return f"{count // 1024} kB"


def judge(result: CheckResult, report: dict, t: Thresholds = DEFAULT, today: Optional[date] = None) -> CheckResult:
    today = today or date.today()

    def add(rule: str, severity: str, location: str, message: str) -> None:
        result.findings.append(Finding(SOURCE, rule, severity, location, message))

    for row in _rows(report, "invalid_indexes"):
        add("invalid_index", "medium", str(row.get("index_name")),
            f"index on {row.get('table_name')} is invalid (a CREATE INDEX CONCURRENTLY that did not "
            f"finish); it is updated on every write yet never used. Drop it and build it again, "
            f"both CONCURRENTLY ({int(row.get('bytes') or 0) // 1024} kB).")
    for row in _rows(report, "bloat"):
        dead, ratio = int(row.get("dead_rows") or 0), float(row.get("dead_ratio") or 0)
        severity = "high" if dead >= t.dead_rows_high and ratio >= t.dead_ratio_high else "medium"
        add("table_bloat", severity, str(row.get("table_name")),
            f"{dead} dead rows ({ratio:.0%} of the table); last vacuum {row.get('last_vacuum') or 'never'}. "
            "Autovacuum is not keeping up: lower autovacuum_vacuum_scale_factor on this table.")
    for row in _rows(report, "xid_age"):
        age = int(row.get("xid_age") or 0)
        add("xid_age", "high" if age >= t.xid_age_high else "medium", str(row.get("table_name")),
            f"oldest unfrozen transaction ID is {age:,} transactions old; Postgres stops accepting "
            "writes near 2 billion. Run VACUUM (FREEZE) on it and find what keeps autovacuum away.")
    database_age = int(report.get("database_xid_age") or 0)
    if database_age >= t.xid_age_medium:
        add("xid_age", "high" if database_age >= t.xid_age_high else "medium", "database",
            f"the database's oldest unfrozen transaction ID is {database_age:,} transactions old")
    if report.get("sees_other_sessions"):
        for row in _rows(report, "idle_in_transaction"):
            longest = int(row.get("longest_seconds") or 0)
            aborted = "aborted" in str(row.get("state"))
            add("idle_in_transaction", "high" if longest >= t.idle_seconds_high or aborted else "medium",
                f"role {row.get('role_name')}",
                f"{row.get('sessions')} session(s) {row.get('state')} for up to {_minutes(longest)}; they "
                "hold locks and stop vacuum from cleaning up. Set idle_in_transaction_session_timeout "
                "for this role.")
        for row in _rows(report, "lock_waits"):
            add("lock_wait", "medium", f"role {row.get('role_name')}",
                f"{row.get('sessions')} session(s) waiting on a lock, in statements running for up to "
                f"{_minutes(row.get('longest_seconds'))} (Postgres does not record when the wait began)")
    else:
        result.notes.append(
            "sessions of other roles were not visible to the connected role (it lacks "
            "pg_read_all_stats), so idle transactions and lock waits were not checked; "
            "--via-api sees them"
        )
    for row in _rows(report, "sequences"):
        used = float(row.get("used") or 0)
        add("sequence_near_limit", "high" if used >= t.sequence_used_high else "medium",
            str(row.get("sequence_name")),
            f"{used:.0%} of its range used ({row.get('last_value')} of {row.get('max_value')}, "
            f"{row.get('data_type')}); inserts fail when it runs out. Move it and its column to bigint.")
    unreadable = int(report.get("sequences_unreadable") or 0)
    if unreadable:
        result.notes.append(
            f"{unreadable} sequences could not be read by the connected role, so how much of their "
            "range is used is not known; nothing is estimated for them"
        )
    connections = report.get("connections") if isinstance(report.get("connections"), dict) else None
    if connections:
        in_use, usable = int(connections.get("in_use") or 0), int(connections.get("max") or 0) - int(connections.get("reserved") or 0)
        if usable > 0:
            used = in_use / usable
            if used >= t.connections_used:
                add("connections_near_limit", "high" if used >= t.connections_used_high else "medium", "database",
                    f"{in_use} of {usable} connections in use ({used:.0%}); new connections are refused when "
                    "they run out. Connect through the pooler in transaction mode, and look for clients "
                    "that open connections and never close them.")
            else:
                result.notes.append(f"connections in use: {in_use} of {usable} ({used:.0%})")
    if report.get("database_bytes") is not None:
        largest = ", ".join(f"{row.get('table_name')} {_size(row.get('bytes'))}" for row in _rows(report, "largest_tables"))
        result.notes.append(
            f"database size: {_size(report.get('database_bytes'))}"
            + (f"; largest tables with their indexes: {largest}" if largest else "")
            + ". Compare with the disk size of your plan; the database cannot see that limit"
        )
    version = int(report.get("server_version_num") or 0)
    major = version // 10000
    if major in END_OF_LIFE:
        days = (END_OF_LIFE[major] - today).days
        if days < 0:
            add("postgres_end_of_life", "medium", "database",
                f"Postgres {major} left community support on {END_OF_LIFE[major].isoformat()}: no more "
                "security fixes. Plan the upgrade to a supported major version.")
        elif days <= END_OF_LIFE_WARNING_DAYS:
            add("postgres_end_of_life", "low", "database",
                f"Postgres {major} leaves community support on {END_OF_LIFE[major].isoformat()} "
                f"({days} days from now). Plan the upgrade to a newer major version.")
    elif major:
        result.notes.append(f"Postgres {major}: its end of support is not known to this version of the toolkit")
    updates = _rows(report, "extension_updates")
    if updates:
        names = ", ".join(f"{row.get('name')} {row.get('installed_version')} -> {row.get('default_version')}"
                          for row in updates)
        add("extension_update_available", "info", "extensions",
            f"a newer version is on the server for: {names}. Read each extension's release notes, then "
            "ALTER EXTENSION ... UPDATE on staging first")
    statements = report.get("statements")
    if statements is None:
        result.notes.append("pg_stat_statements is not installed or not readable, so slow statements were not looked at")
    else:
        for row in [row for row in statements if isinstance(row, dict)]:
            mean, calls = float(row.get("mean_ms") or 0), int(row.get("calls") or 0)
            if mean >= t.slow_mean_ms and calls >= t.slow_calls:
                add("slow_statement", "low", f"query id {row.get('query_id')}",
                    f"takes {mean:,.0f} ms on average over {calls:,} calls ({float(row.get('total_ms') or 0) / 1000:,.0f} s "
                    "in total), among the statements that use the most time. Find this id under Query "
                    "Performance in the dashboard; the statement's text was not read")
        if not report.get("sees_other_sessions"):
            result.notes.append(
                "only the connected role's own statements are visible in pg_stat_statements "
                "(it lacks pg_read_all_stats); --via-api sees all of them"
            )
    result.notes.append(
        f"statistics and catalog facts as of {report.get('taken_at', 'an unknown time')}; no table "
        "row, no pg_stats and no query text was read"
    )
    return result.finish()


def run(ask: Callable[[str], object], evidence: str, t: Thresholds = DEFAULT) -> CheckResult:
    result = CheckResult(id="db_health", title=TITLE, evidence=evidence)
    sql = build_sql(t)
    live.assert_single_select(sql)
    report = health.unwrap(ask(sql), "db_health", FORMAT)
    if report is None:
        result.status, result.reason = ERROR, "the answer to the database health query was not understood"
        return result
    return judge(result, report, t)


def run_on_connection(connection, evidence: str) -> CheckResult:
    def ask(sql: str):
        try:
            return connection.execute(sql).fetchone()
        finally:
            connection.rollback()

    try:
        return run(ask, evidence)
    except Exception as error:  # a failed query must not take the other checks down
        failed = CheckResult(id="db_health", title=TITLE, evidence=evidence, status=ERROR)
        failed.reason = f"the database health query failed ({type(error).__name__})"
        return failed

