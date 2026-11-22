"""Storage: buckets that are public, and who may write to them.

Two read-only statements, like the scheduled-jobs check: a probe that cannot
fail, then one SELECT. What is read: each bucket's id, whether it is public,
whether it has upload limits, and which commands its policies give to visitors
who are not signed in. No row of storage.objects is read, so no file name and
no file content, and no policy expression leaves the database.

A policy counts as belonging to a bucket when its expression quotes the
bucket's id. A policy that names buckets some other way (through a function,
for example) is reported as applying to every bucket; read it before acting.

storage.buckets is protected by row-level security, so the audit role sees no
bucket through a direct connection and this check reports NOT_RUN there.
"""

from __future__ import annotations

from typing import Callable

from . import health, live
from .model import ERROR, NOT_RUN, CheckResult, Finding
from .targets import Target

FORMAT = "webcare-storage/1"
TITLE = "Storage buckets: public access and who may upload"
SOURCE = "storage"
MAX_BUCKETS = 200
PROBE_SQL = health.build_probe("storage", ("buckets",))
_WRITES = {"INSERT", "UPDATE", "DELETE", "ALL"}

SQL = f"""with pol as (
  select p.policyname::text as policy, p.cmd::text as command, p.roles::text[] as roles,
         coalesce(p.qual, '') || ' ' || coalesce(p.with_check, '') as expr
    from pg_catalog.pg_policies p
   where p.schemaname = 'storage' and p.tablename = 'objects' and p.permissive = 'PERMISSIVE'
)
select jsonb_build_object(
  'format', '{FORMAT}',
  'taken_at', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
  'buckets', coalesce((
    select jsonb_agg(to_jsonb(q)) from (
      select b.id::text as bucket,
             b.public as public,
             b.file_size_limit is not null as has_size_limit,
             b.allowed_mime_types is not null as has_type_list,
             (select count(*) from pol where position(quote_literal(b.id) in pol.expr) > 0) as policies,
             coalesce((
               select array_agg(distinct pol.command) from pol
                where position(quote_literal(b.id) in pol.expr) > 0
                  and pol.roles && array['anon', 'public']
             ), array[]::text[]) as anon_commands
        from storage.buckets b
       order by b.id
       limit {MAX_BUCKETS}
    ) q
  ), '[]'::jsonb),
  'unscoped_policies', coalesce((
    select jsonb_agg(to_jsonb(q)) from (
      select pol.policy, pol.command, pol.roles
        from pol
       where not exists (
               select 1 from storage.buckets b where position(quote_literal(b.id) in pol.expr) > 0
             )
       order by pol.policy
       limit {MAX_BUCKETS}
    ) q
  ), '[]'::jsonb)
) as storage"""


def why_not(probe: dict) -> str:
    if not probe.get("installed"):
        return "this database has no storage.buckets table, so there are no buckets to check"
    role = probe.get("role", "the connected role")
    if not probe.get("readable"):
        return f"role {role} may not read storage.buckets"
    if probe.get("row_security") and not probe.get("sees_every_row"):
        return (
            f"storage.buckets is protected by row-level security and role {role} is shown no "
            "bucket; an empty answer would not mean that no bucket is public. Use the "
            "Management API route (--via-api)."
        )
    return ""


def judge(result: CheckResult, report: dict, target: Target) -> CheckResult:
    buckets = [bucket for bucket in report.get("buckets", []) if isinstance(bucket, dict)]
    expected = set(target.expected_public_buckets)

    def add(rule: str, severity: str, location: str, message: str) -> None:
        result.findings.append(Finding(SOURCE, rule, severity, location, message))

    seen_public = set()
    for bucket in buckets:
        name = str(bucket.get("bucket"))
        place = f"bucket {name!r}"
        public = bool(bucket.get("public"))
        anon = {str(command) for command in bucket.get("anon_commands") or []}
        if public:
            seen_public.add(name)
            if name not in expected:
                add(
                    "storage_bucket_public", "medium", place,
                    "the bucket is public: anyone who has or guesses a file's URL can download "
                    "it, and no policy applies to downloads. If that is intended, list the "
                    "bucket in expected_public_buckets.",
                )
        if anon & _WRITES:
            add(
                "storage_anon_write", "medium", place,
                "a policy lets visitors who are not signed in "
                f"{', '.join(sorted(anon & _WRITES))} files in this bucket",
            )
        elif "SELECT" in anon and not public:
            add(
                "storage_anon_read", "low", place,
                "the bucket is private, yet a policy lets visitors who are not signed in read "
                "and list its files",
            )
        writable = public or int(bucket.get("policies") or 0) > 0
        if writable and not bucket.get("has_size_limit") and not bucket.get("has_type_list"):
            add(
                "storage_no_upload_limits", "low", place,
                "the bucket has no file size limit and no list of allowed file types",
            )
    for name in sorted(expected - seen_public):
        add(
            "expected_public_bucket_missing", "low", f"bucket {name!r}",
            "listed in expected_public_buckets, but no public bucket has this id; remove the "
            "entry so that it cannot excuse a future bucket",
        )
    for policy in report.get("unscoped_policies", []):
        if not isinstance(policy, dict):
            continue
        roles = {str(role) for role in policy.get("roles") or []}
        open_to_all = bool(roles & {"anon", "public"})
        add(
            "storage_policy_every_bucket", "medium" if open_to_all else "low",
            f"storage.objects policy {policy.get('policy')!r}",
            f"this {policy.get('command')} policy for {', '.join(sorted(roles)) or 'no role'} "
            "quotes no bucket id, so it appears to apply to every bucket, including ones "
            "created later; read the policy to confirm",
        )
    result.notes.append(
        f"{len(buckets)} buckets examined ({len(seen_public)} public), as of "
        f"{report.get('taken_at', 'an unknown time')}; no file name or file content was read"
    )
    if len(buckets) >= MAX_BUCKETS:
        result.notes.append(f"only the first {MAX_BUCKETS} buckets were examined")
    return result.finish()


def run(ask: Callable[[str], object], target: Target, evidence: str) -> CheckResult:
    result = CheckResult(id="storage_buckets", title=TITLE, evidence=evidence)
    for sql in (PROBE_SQL, SQL):
        live.assert_single_select(sql)
    probe = health.unwrap(ask(PROBE_SQL), "probe", health.PROBE_FORMAT)
    if probe is None:
        result.status, result.reason = ERROR, "the answer to the Storage probe was not understood"
        return result
    reason = why_not(probe)
    if reason:
        result.status, result.reason = NOT_RUN, reason
        return result
    report = health.unwrap(ask(SQL), "storage", FORMAT)
    if report is None or not isinstance(report.get("buckets"), list):
        result.status, result.reason = ERROR, "the answer to the Storage query was not understood"
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
        failed = CheckResult(id="storage_buckets", title=TITLE, evidence=evidence, status=ERROR)
        failed.reason = f"the Storage query failed ({type(error).__name__})"
        return failed
