"""Database health: what Supabase's advisors do not report.

One read-only statement, on a direct connection or through `--via-api`:

- indexes left invalid by a CREATE INDEX CONCURRENTLY that failed
- tables with many dead rows (bloat), and tables or the database near
  transaction-ID wraparound
- sessions left idle inside a transaction, and sessions waiting on a lock
- sequences close to the largest value they can give

It reads system statistics and catalog facts only: no table row, no
`pg_stats` (whose sample values are table data), no query text from
`pg_stat_activity`, and no application name. Sessions of other roles are
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
from typing import Callable

from . import health, live
from .model import ERROR, CheckResult, Finding

FORMAT = "webcare-db-health/1"
TITLE = "Database health: invalid indexes, bloat, transaction age, idle sessions, sequences"
SOURCE = "db_health"
SKIPPED_SCHEMAS = ("information_schema", "pg_toast")
MAX_ROWS = 200


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
                                            then pg_catalog.has_sequence_privilege(c.oid, 'SELECT, USAGE') end))
) as db_health"""


def _rows(report: dict, key: str) -> list[dict]:
    return [row for row in report.get(key) or [] if isinstance(row, dict)]


def _minutes(seconds) -> str:
    seconds = int(seconds or 0)
    return f"{seconds // 60} minutes" if seconds >= 120 else f"{seconds} seconds"


def judge(result: CheckResult, report: dict, t: Thresholds = DEFAULT) -> CheckResult:
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

