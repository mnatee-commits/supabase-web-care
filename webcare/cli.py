"""Command line entry point: python -m webcare <command>.

    check         run every check that the given inputs allow and write a report
    secrets       scan a source tree for credentials
    probe         ask the Data API what an anonymous visitor can read (HEAD only)
    preflight     show what the connecting database role is able to do
    snapshot-sql  print the read-only statement that takes a catalog snapshot
    inventory     save what one database is made of (names, grants, hashes) to a file
    compare       report what differs between two inventory files (offline)

Offline checks need no configuration. Live checks need a target declared in
webcare.toml; credentials come from environment variables, never from flags.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import (
    __version__, advisors, anon_probe, api_snapshot, auth_config, backups, baseline, changes, data_api, setup_init, db_health, functions_static, health, inventory, live, logs, pgrls_runner, secret_scan,
    focus, parity, platform, sarif, snapshot, storage_buckets, table_writes,
)
from .model import ERROR, NOT_RUN, CheckResult, Refusal, severity_at_least
from .report import DEFAULT_LANGUAGE, LANGUAGE_ENV, LANGUAGES, Report
from .targets import APPROVAL_FLAG, DEFAULT_CONFIG_NAME, Target, get_target

DEFAULT_DB_ENV = "WEBCARE_DATABASE_URL"
DEFAULT_OUT_DIR = "webcare-output"
EXIT_REFUSED = 2

TITLES = {
    "rls_static": "RLS policies from SQL files (pgrls, offline)",
    "functions_static": functions_static.TITLE,
    "rls_live": "RLS policies from the live catalog (pgrls)",
    "storage_live": "Storage policies from the live catalog (pgrls)",
    "extra_live": "Catalog checks beyond pgrls",
    "functions_live": "SECURITY DEFINER functions callable without signing in",
    "storage_buckets": storage_buckets.TITLE,
    "table_writes": table_writes.TITLE,
    "advisors": advisors.TITLE,
    "auth_config": auth_config.TITLE,
    "health_cron": health.TITLE,
    "health_backups": backups.TITLE,
    "health_logs": logs.TITLE,
    "db_health": db_health.TITLE,
    "data_api": data_api.TITLE,
    "parity": parity.TITLE,
    "platform": platform.TITLE,
    "advisors_performance": advisors.PERFORMANCE_TITLE,
    "anon_probe": "What an anonymous visitor can read",
}


def _not_run(check_id: str, reason: str) -> CheckResult:
    return CheckResult(id=check_id, title=TITLES[check_id], status=NOT_RUN, reason=reason)


def _git_revision(path: Path) -> str:
    """Short revision of the tree at `path`, marked when it has local changes."""
    try:
        revision = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--short=12", "HEAD"],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain"],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "revision unknown"
    return f"revision {revision}" + (" with uncommitted changes" if dirty else "")


def _add_target_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", default=DEFAULT_CONFIG_NAME, help="target file (default: ./webcare.toml)")
    parser.add_argument(
        APPROVAL_FLAG, dest="owner_approved", action="store_true",
        help="the owner has approved, in their own words, live checks against a target "
        "that is production or holds real data",
    )


def _add_database_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db-env", default=DEFAULT_DB_ENV,
        help=f"environment variable holding the connection string (default: {DEFAULT_DB_ENV})",
    )
    parser.add_argument(
        live.OVERRIDE_FLAG, dest="allow_privileged_role", action="store_true",
        help="accept a superuser, BYPASSRLS or writing role; only for a throwaway "
        "local database with synthetic data",
    )


def _add_probe_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rest-url", help="API base URL (default: the target's `rest`)")
    parser.add_argument(
        "--key-env", default=anon_probe.DEFAULT_KEY_ENV,
        help=f"environment variable holding the public key (default: {anon_probe.DEFAULT_KEY_ENV})",
    )
    parser.add_argument("--table", action="append", default=[], help="table or view to probe; repeatable")
    parser.add_argument("--probe-schema", default="public", help="exposed schema to probe (default: public)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="webcare", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"supabase-web-care {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check", help="run every check the inputs allow and write a report")
    check.add_argument("--repo", action="append", default=[], help="source tree for the credential scan; repeatable (default: .)")
    check.add_argument("--exclude", action="append", default=[], help="glob of paths the credential scan skips; repeatable")
    check.add_argument("--max-bytes", type=int, default=secret_scan.DEFAULT_MAX_BYTES, help="largest file the credential scan reads")
    check.add_argument("--include-build", action="store_true", help="also scan build output (dist, build, .next, .nuxt, .svelte-kit), where a key baked into the front end lives")
    check.add_argument("--migrations", help="directory of .sql migrations, linted in file-name order")
    check.add_argument("--sql-file", action="append", default=[], help="SQL file to lint, in the order given; repeatable")
    check.add_argument("--exclude-sql", action="append", default=[], help="glob of migration file names to leave out; repeatable")
    check.add_argument("--target", help="declared target for live checks")
    check.add_argument(
        "--snapshot",
        help="catalog snapshot file to judge instead of connecting to the database "
        "(see `snapshot-sql`); needs no database credentials",
    )
    check.add_argument(
        "--via-api", action="store_true",
        help="fetch the catalog snapshot through the Supabase Management API read-only "
        "endpoint of the target's project_ref, for machines that cannot reach Postgres",
    )
    check.add_argument(
        "--token-env", default=api_snapshot.DEFAULT_TOKEN_ENV,
        help="environment variable holding the account access token for --via-api "
        f"(default: {api_snapshot.DEFAULT_TOKEN_ENV})",
    )
    check.add_argument(
        "--baseline",
        help="file of findings from SQL files that are already known; they are counted in "
        "the report but do not fail the run (see --write-baseline)",
    )
    check.add_argument(
        "--write-baseline",
        help="record the current findings from SQL files into this file, to start from",
    )
    check.add_argument(
        "--with-advisors", action="store_true",
        help="with --via-api, also read Supabase's own security lints (one GET; the token then "
        "also needs advisors_read)",
    )
    check.add_argument(
        "--parity", metavar="INVENTORY",
        help="compare the database with an inventory saved earlier from the same target "
        "(webcare inventory) and report what changed since",
    )
    check.add_argument(
        "--changed-since", metavar="REF",
        help="file checks only look at what changed since this git revision (e.g. HEAD~1, main); "
        "database checks still run in full",
    )
    check.add_argument(
        "--with-platform", action="store_true",
        help="with --via-api, also read SSL enforcement and network restrictions (two GETs; "
        "beta endpoints on Supabase's side)",
    )
    check.add_argument(
        "--with-data-api", action="store_true",
        help="with --via-api, also read which schemas the Data API serves (one GET of the "
        "PostgREST settings; only allowlisted settings are kept)",
    )
    check.add_argument(
        "--with-performance", action="store_true",
        help="with --via-api, also read Supabase's Performance Advisor (one GET; experimental on "
        "Supabase's side; the token then also needs advisors_read)",
    )
    check.add_argument(
        "--with-auth-config", action="store_true",
        help="with --via-api, also read the project's sign-in settings (one GET; the token "
        "then also needs auth_config_read; the answer includes secrets, which are discarded)",
    )
    check.add_argument(
        "--with-backups", action="store_true",
        help="with --via-api, also read the project's backup list (one GET; the token "
        "then also needs the backups_read permission)",
    )
    check.add_argument(
        "--with-logs", action="store_true",
        help="with --via-api, also count the last 24 hours of API gateway requests by "
        "status (one GET, counts only; the token then also needs analytics_logs_read)",
    )
    check.add_argument(
        "--cron-days", type=int, default=health.DEFAULT_WINDOW_DAYS, choices=range(1, health.MAX_WINDOW_DAYS + 1),
        metavar="DAYS", help=f"how far back to look at scheduled-job runs (default: {health.DEFAULT_WINDOW_DAYS})",
    )
    check.add_argument("--skip", action="append", default=[], choices=["secrets", "static", "live", "probe"], help="leave a group of checks out; repeatable")
    check.add_argument(
        "--focus", action="append", default=[], metavar="AREA",
        help="check only these areas, comma-separated or repeated: " + ", ".join(focus.AREAS)
        + "; the rest is reported as NOT_RUN",
    )
    check.add_argument(
        "--group", action="append", default=[], metavar="GROUP",
        help="check only a group of areas: " + ", ".join(focus.GROUPS),
    )
    check.add_argument(
        "--only", action="append", default=[], metavar="CHECK",
        help="check only these, comma-separated or repeated: report rows such as table_writes, "
        "or single catalog checks such as extension_net_callable",
    )
    check.add_argument(
        "--fail-groups", default=None, metavar="GROUPS",
        help="comma-separated groups whose results decide the exit code (default: all); "
        "for example security, so health findings warn without failing CI",
    )
    check.add_argument(
        "--profile", choices=focus.PROFILES, default=None,
        help="quick: files only, nothing live; full: every optional --via-api check on",
    )
    check.add_argument("--pgrls-config", help="pgrls.toml with rule allowlists or severities")
    check.add_argument("--allow-pgrls-version-mismatch", action="store_true", help="run a pgrls release other than the reviewed one")
    check.add_argument("--out-dir", default=DEFAULT_OUT_DIR, help=f"where report.md and report.json go (default: {DEFAULT_OUT_DIR})")
    check.add_argument("--fail-on", default="high", choices=["high", "medium", "low", "never"], help="lowest severity that makes the exit code 1 (default: high)")
    check.add_argument(
        "--lang", choices=LANGUAGES, default=None,
        help=f"language of report.md (default: the target's `lang`, then the {LANGUAGE_ENV} "
        f"environment variable, then {DEFAULT_LANGUAGE})",
    )
    check.add_argument("--json", action="store_true", help="print the JSON report instead of the summary")
    check.add_argument("--sarif", action="store_true", help="also write report.sarif, for code scanning on pull requests")
    _add_target_options(check)
    _add_database_options(check)
    _add_probe_options(check)
    check.set_defaults(handler=cmd_check)

    init = commands.add_parser(
        "init", help="write a target into webcare.toml from a few answers (asks when run in a terminal)",
    )
    init.add_argument("--config", default=DEFAULT_CONFIG_NAME, help="target file to write (default: ./webcare.toml)")
    init.add_argument("--name", help="a short name for the target, e.g. staging")
    init.add_argument("--env", choices=["local", "staging", "production"], help="what kind of environment it is")
    init.add_argument("--real-data", dest="real", choices=["yes", "no"],
                      help="does it hold real people's data? (default when not asked: yes)")
    init.add_argument("--project-ref", help="the 20-letter project reference, for --via-api")
    init.add_argument("--schema", action="append", default=[], help="schema to check; repeatable (default: public)")
    init.add_argument("--lang", choices=LANGUAGES, default="en", help="language of reports for this target")
    init.set_defaults(handler=cmd_init)

    secrets = commands.add_parser("secrets", help="scan a source tree for credentials")
    secrets.add_argument("paths", nargs="*", default=["."], help="files or directories (default: .)")
    secrets.add_argument("--exclude", action="append", default=[], help="glob of paths to skip; repeatable")
    secrets.add_argument("--max-bytes", type=int, default=secret_scan.DEFAULT_MAX_BYTES)
    secrets.add_argument("--include-build", action="store_true", help="also scan build output (dist, build, .next, .nuxt, .svelte-kit)")
    secrets.add_argument("--fail-on", default="high", choices=["high", "medium", "low", "never"])
    secrets.add_argument("--show-info", action="store_true", help="also list public keys found (inventory)")
    secrets.set_defaults(handler=cmd_secrets)

    probe = commands.add_parser("probe", help="HEAD-only check of what an anonymous visitor can read")
    probe.add_argument("--target", required=True, help="declared target")
    _add_target_options(probe)
    _add_probe_options(probe)
    probe.set_defaults(handler=cmd_probe)

    preflight = commands.add_parser("preflight", help="show what the connecting database role can do")
    preflight.add_argument("--target", required=True, help="declared target")
    _add_target_options(preflight)
    _add_database_options(preflight)
    preflight.set_defaults(handler=cmd_preflight)

    snapshot_sql = commands.add_parser(
        "snapshot-sql",
        help="print the read-only statement that takes a catalog snapshot",
        description="Print one read-only SELECT. An administrator runs it where they already "
        "have access (the SQL editor, for example) and saves the JSON result to a file for "
        "`check --snapshot`. Nothing is contacted by this command.",
    )
    snapshot_sql.add_argument("--target", help="take the label and schemas from this declared target")
    snapshot_sql.add_argument("--config", default=DEFAULT_CONFIG_NAME, help="target file (default: ./webcare.toml)")
    snapshot_sql.add_argument("--label", help="label written into the snapshot; must equal the target name used later")
    snapshot_sql.add_argument("--schema", action="append", default=[], help="schema to cover; repeatable (default: public)")
    snapshot_sql.set_defaults(handler=cmd_snapshot_sql)

    inv = commands.add_parser(
        "inventory",
        help="save what one database is made of to a file, for `compare`",
        description="Reads names, RLS state, grants, default privileges, migration history, "
        "scheduled jobs, buckets, and md5 hashes of function bodies and policy expressions. "
        "No row of an application table, no function body and no policy expression is read.",
    )
    inv.add_argument("--target", required=True, help="declared target")
    inv.add_argument("--out", required=True, help="file to write the inventory to")
    inv.add_argument("--via-api", action="store_true", help="read through the Management API read-only endpoint")
    inv.add_argument("--token-env", default=api_snapshot.DEFAULT_TOKEN_ENV,
                     help=f"environment variable holding the access token (default: {api_snapshot.DEFAULT_TOKEN_ENV})")
    _add_target_options(inv)
    _add_database_options(inv)
    inv.set_defaults(handler=cmd_inventory)

    cmp = commands.add_parser("compare", help="report what differs between two inventory files; contacts nothing")
    cmp.add_argument("first", help="inventory file, e.g. of staging")
    cmp.add_argument("second", help="inventory file, e.g. of production")
    cmp.add_argument("--out-dir", default=DEFAULT_OUT_DIR, help=f"where compare.md and compare.json go (default: {DEFAULT_OUT_DIR})")
    cmp.add_argument("--lang", choices=LANGUAGES, default=None, help="language of compare.md headings")
    cmp.set_defaults(handler=cmd_compare)
    return parser


def _print_findings(result: CheckResult, show_info: bool = False) -> None:
    for finding in result.findings:
        if finding.severity == "info" and not show_info:
            continue
        print(f"{finding.severity:<6} {finding.rule:<32} {finding.location}  {finding.message}")
    for note in result.notes:
        print(f"note: {note}")
    if result.reason:
        print(f"{result.status}: {result.reason}")


def _exit_code(result: CheckResult, fail_on: str) -> int:
    if result.status in ("ERROR", NOT_RUN):
        return EXIT_REFUSED
    if fail_on != "never" and any(severity_at_least(f.severity, fail_on) for f in result.findings):
        return 1
    return 0


def cmd_secrets(args: argparse.Namespace) -> int:
    result = secret_scan.run([Path(p) for p in args.paths], args.exclude, args.max_bytes, args.include_build)
    _print_findings(result, args.show_info)
    print(f"{result.status}: {result.evidence}")
    return _exit_code(result, args.fail_on)


def cmd_probe(args: argparse.Namespace) -> int:
    try:
        target = get_target(Path(args.config), args.target)
    except Refusal as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return EXIT_REFUSED
    result = anon_probe.run(
        target,
        args.rest_url or target.rest or "",
        args.table,
        owner_approved=args.owner_approved,
        key_env=args.key_env,
        schema=args.probe_schema,
    )
    _print_findings(result)
    print(f"{result.status}: {result.evidence}")
    return _exit_code(result, "high")


def cmd_preflight(args: argparse.Namespace) -> int:
    try:
        target = get_target(Path(args.config), args.target)
        dsn = os.environ.get(args.db_env, "")
        if not dsn:
            raise Refusal(f"environment variable {args.db_env} is not set")
        connection, endpoint, facts = live.open_checked(
            target, dsn, args.owner_approved, args.allow_privileged_role
        )
    except Refusal as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return EXIT_REFUSED
    connection.close()
    print(f"target:     {target.describe()}")
    print(f"connection: {endpoint.describe()}")
    print(f"role:       {facts.summary()}")
    if facts.member_of:
        print(f"member of:  {', '.join(facts.member_of)}")
    problems = facts.problems()
    if problems:
        print(f"warning:    this role {' and '.join(problems)} (accepted by {live.OVERRIDE_FLAG})")
    else:
        print("ok:         this role cannot write to application tables")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    interactive = sys.stdin.isatty()
    try:
        message = setup_init.run(
            Path(args.config), args.name, args.env, args.real, args.project_ref, args.schema or None,
            args.lang, interactive,
        )
    except Refusal as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return EXIT_REFUSED
    except (EOFError, KeyboardInterrupt):
        print("stopped; nothing was written", file=sys.stderr)
        return EXIT_REFUSED
    print(message)
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    connection = None
    try:
        target = get_target(Path(args.config), args.target)
        if args.via_api:
            ask = api_snapshot.asker(target, args.owner_approved, args.token_env)
            route = f"Management API read-only endpoint of project {target.project_ref}"
        else:
            dsn = os.environ.get(args.db_env, "")
            if not dsn:
                raise Refusal(f"environment variable {args.db_env} is not set (or use --via-api)")
            connection, endpoint, _facts = live.open_checked(
                target, dsn, args.owner_approved, args.allow_privileged_role
            )
            ask = inventory.connection_asker(connection)
            route = endpoint.describe()
        data = inventory.collect(ask, target)
    except Refusal as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return EXIT_REFUSED
    finally:
        if connection is not None:
            connection.close()
    out = Path(args.out)
    try:
        inventory.write(out, data)
    except OSError as error:
        print(f"could not write {out} ({type(error).__name__})", file=sys.stderr)
        return EXIT_REFUSED
    for name, part in data["parts"].items():
        state = f"{len(part['rows'])} entries" if "rows" in part else f"not read: {part['not_read']}"
        print(f"  {name:<14} {state}")
    print(f"inventory of {target.describe()} through {route}: {out}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    try:
        first, second = inventory.load(Path(args.first)), inventory.load(Path(args.second))
    except Refusal as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return EXIT_REFUSED
    lang = args.lang or (os.environ.get(LANGUAGE_ENV) if os.environ.get(LANGUAGE_ENV) in LANGUAGES else DEFAULT_LANGUAGE)
    result = inventory.compare(first, second)
    markdown = inventory.to_markdown(first, second, result, lang)
    out = Path(args.out_dir)
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "compare.md").write_text(markdown, encoding="utf-8")
        (out / "compare.json").write_text(
            json.dumps({"first": first["label"], "second": second["label"], "parts": result},
                       ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    except OSError as error:
        print(f"could not write to {out} ({type(error).__name__})", file=sys.stderr)
        return EXIT_REFUSED
    for name in inventory.PART_ORDER:
        part = result[name]
        if "not_compared" in part:
            print(f"  {name:<14} not compared ({part['not_compared']})")
        else:
            print(f"  {name:<14} only {first['label']}={len(part['only_first'])} "
                  f"only {second['label']}={len(part['only_second'])} different={len(part['changed'])}")
    total = inventory.differences(result)
    print(f"{total} differences: {out / 'compare.md'}")
    return 1 if total else 0


def cmd_snapshot_sql(args: argparse.Namespace) -> int:
    try:
        if args.target:
            target = get_target(Path(args.config), args.target)
            label, schemas = target.name, list(target.schemas)
        elif args.label:
            label, schemas = args.label, args.schema or ["public"]
        else:
            raise Refusal("give --target, or --label (and --schema when not public)")
        sys.stdout.write(snapshot.build_sql(schemas, label))
    except Refusal as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return EXIT_REFUSED
    return 0


def _snapshot_checks(
    args: argparse.Namespace, skip: set[str], requested: set[str]
) -> tuple[list[CheckResult], str]:
    """Catalog checks judged from a snapshot file. No database is contacted."""
    requested.update({"extra_live", "functions_live"})
    no_pgrls = _not_run(
        "rls_live", "a snapshot was used instead of a connection; pgrls needs a database to lint"
    )
    via_api = bool(args.via_api)
    thai = args.lang == "th"
    label = "Management API" if via_api else (
        f"ไฟล์ snapshot {Path(args.snapshot).name}" if thai else f"snapshot file {Path(args.snapshot).name}"
    )
    try:
        if via_api and args.snapshot:
            raise Refusal("give either --snapshot or --via-api, not both")
        target: Optional[Target] = get_target(Path(args.config), args.target) if args.target else None
        if via_api:
            if target is None:
                raise Refusal("--via-api needs --target, which names the project to ask")
            data, source = api_snapshot.fetch(target, args.owner_approved, args.token_env)
        else:
            source = Path(args.snapshot)
            data = snapshot.load(source)
        if target is not None:
            snapshot.ensure_matches(data, target)
    except Refusal as refusal:
        refused_ids = ["extra_live", "functions_live", "health_cron", "anon_probe"]
        if via_api:
            refused_ids += ["storage_buckets", "table_writes", "db_health"]
            refused_ids += [
                check_id
                for check_id, asked in (
                    ("advisors", args.with_advisors),
                    ("auth_config", args.with_auth_config),
                    ("health_backups", args.with_backups),
                    ("health_logs", args.with_logs),
                    ("advisors_performance", args.with_performance),
                    ("data_api", args.with_data_api),
                    ("parity", bool(args.parity)),
                    ("platform", args.with_platform),
                )
                if asked
            ]
        refused = [_not_run(check_id, str(refusal)) for check_id in refused_ids]
        return [no_pgrls] + refused, f"{label} (ถูกปฏิเสธ)" if thai else f"{label} (refused)"

    results = [no_pgrls] + snapshot.run_checks(data, source, target)
    if via_api:
        try:
            results.append(
                storage_buckets.run(
                    api_snapshot.asker(target, args.owner_approved, args.token_env), target,
                    f"storage.buckets and the policies of storage.objects in project "
                    f"{target.project_ref}, read through the Management API read-only query endpoint",
                )
            )
        except Refusal as refusal:
            failed = CheckResult(id="storage_buckets", title=storage_buckets.TITLE, status=ERROR)
            failed.reason = str(refusal)
            results.append(failed)
        try:
            results.append(
                table_writes.run(
                    api_snapshot.asker(target, args.owner_approved, args.token_env), target,
                    f"table privileges of anon and authenticated in project {target.project_ref}, "
                    "read through the Management API read-only query endpoint",
                )
            )
        except Refusal as refusal:
            failed = CheckResult(id="table_writes", title=table_writes.TITLE, status=ERROR)
            failed.reason = str(refusal)
            results.append(failed)
        try:
            results.append(
                db_health.run(
                    api_snapshot.asker(target, args.owner_approved, args.token_env),
                    f"statistics and catalog of project {target.project_ref}, read through the "
                    "Management API read-only query endpoint",
                )
            )
        except Refusal as refusal:
            failed = CheckResult(id="db_health", title=db_health.TITLE, status=ERROR)
            failed.reason = str(refusal)
            results.append(failed)
        try:
            results.append(
                health.run(
                    api_snapshot.asker(target, args.owner_approved, args.token_env),
                    f"pg_cron job list of project {target.project_ref}, read through the "
                    "Management API read-only query endpoint",
                    args.cron_days, target.expected_cron_jobs,
                )
            )
        except Refusal as refusal:
            failed = CheckResult(id="health_cron", title=health.TITLE, status=ERROR)
            failed.reason = str(refusal)
            results.append(failed)
        if args.with_advisors:
            try:
                results.append(
                    advisors.run(
                        target,
                        lambda: api_snapshot.advisors_security(target, args.owner_approved, args.token_env),
                        f"security advisors of project {target.project_ref}, read through the Management API",
                    )
                )
            except Refusal as refusal:
                failed = CheckResult(id="advisors", title=advisors.TITLE, status=ERROR)
                failed.reason = str(refusal)
                results.append(failed)
        if args.parity:
            try:
                results.append(
                    parity.run(
                        api_snapshot.asker(target, args.owner_approved, args.token_env), target,
                        Path(args.parity),
                        f"a new inventory of project {target.project_ref}, through the Management API "
                        f"read-only query endpoint, against {Path(args.parity).name}",
                    )
                )
            except Refusal as refusal:
                failed = CheckResult(id="parity", title=parity.TITLE, status=ERROR)
                failed.reason = str(refusal)
                results.append(failed)
        if args.with_platform:
            try:
                results.append(
                    platform.run(
                        target,
                        lambda: api_snapshot.platform_setting("ssl-enforcement", target, args.owner_approved, args.token_env),
                        lambda: api_snapshot.platform_setting("network-restrictions", target, args.owner_approved, args.token_env),
                        f"SSL enforcement and network restrictions of project {target.project_ref}, read "
                        "through the Management API",
                    )
                )
            except Refusal as refusal:
                failed = CheckResult(id="platform", title=platform.TITLE, status=ERROR)
                failed.reason = str(refusal)
                results.append(failed)
        if args.with_data_api:
            try:
                results.append(
                    data_api.run(
                        target,
                        lambda: api_snapshot.postgrest_settings(target, args.owner_approved, args.token_env),
                        f"PostgREST settings of project {target.project_ref}, read through the Management "
                        "API and reduced to an allowlist",
                    )
                )
            except Refusal as refusal:
                failed = CheckResult(id="data_api", title=data_api.TITLE, status=ERROR)
                failed.reason = str(refusal)
                results.append(failed)
        if args.with_performance:
            try:
                results.append(
                    advisors.run_performance(
                        target,
                        lambda: api_snapshot.advisors_performance(target, args.owner_approved, args.token_env),
                        f"performance advisors of project {target.project_ref}, read through the Management API",
                    )
                )
            except Refusal as refusal:
                failed = CheckResult(id="advisors_performance", title=advisors.PERFORMANCE_TITLE, status=ERROR)
                failed.reason = str(refusal)
                results.append(failed)
        if args.with_auth_config:
            try:
                results.append(
                    auth_config.run(
                        target,
                        # already reduced to the allowlist inside api_snapshot
                        lambda: api_snapshot.auth_settings(target, args.owner_approved, args.token_env),
                        f"Auth configuration of project {target.project_ref}, read through the "
                        "Management API and reduced to an allowlist of settings",
                    )
                )
            except Refusal as refusal:
                failed = CheckResult(id="auth_config", title=auth_config.TITLE, status=ERROR)
                failed.reason = str(refusal)
                results.append(failed)
        if args.with_backups:
            try:
                results.append(
                    backups.run(
                        target,
                        lambda: api_snapshot.backup_list(target, args.owner_approved, args.token_env),
                        f"backup list of project {target.project_ref}, read through the Management API",
                    )
                )
            except Refusal as refusal:
                failed = CheckResult(id="health_backups", title=backups.TITLE, status=ERROR)
                failed.reason = str(refusal)
                results.append(failed)
        if args.with_logs:
            try:
                results.append(
                    logs.run(
                        target,
                        lambda sql, start, end: api_snapshot.log_summary(
                            target, args.owner_approved, sql, start, end, args.token_env
                        ),
                        f"API gateway log of project {target.project_ref}, counted through the "
                        "Management API log query endpoint",
                    )
                )
            except Refusal as refusal:
                failed = CheckResult(id="health_logs", title=logs.TITLE, status=ERROR)
                failed.reason = str(refusal)
                results.append(failed)
    else:
        results.append(
            _not_run(
                "health_cron",
                "a snapshot file carries no scheduled-job history; use --via-api or a connection",
            )
        )
    if "probe" in skip:
        results.append(_not_run("anon_probe", "left out with --skip probe"))
    elif target is None or target.rest is None:
        results.append(_not_run("anon_probe", "no target with an API URL was given"))
    else:
        tables = list(args.table) or snapshot.anon_readable(data, args.probe_schema)
        if not tables:
            results.append(
                _not_run(
                    "anon_probe",
                    f"the snapshot shows no relation in schema {args.probe_schema} "
                    "that anon may SELECT, so there is nothing to probe",
                )
            )
        else:
            requested.add("anon_probe")
            probe = anon_probe.run(
                target,
                args.rest_url or target.rest,
                tables[: anon_probe.MAX_TABLES],
                owner_approved=args.owner_approved,
                key_env=args.key_env,
                schema=args.probe_schema,
            )
            if len(tables) > anon_probe.MAX_TABLES:
                probe.notes.append(
                    f"{len(tables)} relations are readable by anon; only the first "
                    f"{anon_probe.MAX_TABLES} were probed"
                )
            results.append(probe)
    if via_api:
        if thai:
            return results, (
                f"{target.describe()} ผ่าน Management API แบบอ่านอย่างเดียวของโปรเจกต์ "
                f"{target.project_ref} ไม่ได้เชื่อมต่อ Postgres โดยตรง"
            )
        return results, (
            f"{target.describe()} through the read-only Management API of project "
            f"{target.project_ref}; Postgres was not contacted directly"
        )
    if target is not None:
        if thai:
            return results, f"{target.describe()} จาก{label} ไม่ได้เชื่อมต่อฐานข้อมูล"
        return results, f"{target.describe()} from {label}; no database was contacted"
    if thai:
        return results, f"{label} ป้าย {data['label']} ไม่ได้ระบุเป้าหมายและไม่ได้เชื่อมต่อฐานข้อมูล"
    return results, f"{label} labelled {data['label']}; no target was named and no database was contacted"


def _live_checks(
    args: argparse.Namespace, target: Target, skip: set[str], requested: set[str]
) -> list[CheckResult]:
    """Database and API checks against one declared target."""
    results: list[CheckResult] = []
    connection = None
    database_reason = ""
    dsn = os.environ.get(args.db_env, "")

    if "live" in skip:
        database_reason = "left out with --skip live"
    elif target.db is None:
        database_reason = f"target {target.name!r} declares no database"
    else:
        requested.update({"rls_live", "extra_live", "functions_live"})
        if not dsn:
            database_reason = f"environment variable {args.db_env} is not set"
        else:
            try:
                connection, endpoint, facts = live.open_checked(
                    target, dsn, args.owner_approved, args.allow_privileged_role
                )
            except Refusal as refusal:
                database_reason = str(refusal)

    try:
        if connection is None:
            results.append(_not_run("rls_live", database_reason))
            results.append(_not_run("extra_live", database_reason))
            results.append(_not_run("functions_live", database_reason))
            results.append(_not_run("health_cron", database_reason))
        else:
            evidence = (
                f"system catalog of {endpoint.describe()}, target {target.describe()}; "
                f"{facts.summary()}"
            )
            config = Path(args.pgrls_config) if args.pgrls_config else None
            rls_live = CheckResult(id="rls_live", title=TITLES["rls_live"], evidence=evidence)
            pgrls_runner.run_lint(
                rls_live,
                schemas=target.schemas,
                database_url=dsn,
                config=config,
                allow_version_mismatch=args.allow_pgrls_version_mismatch,
                force_read_only=facts.privileged,
            )
            if facts.problems():
                rls_live.notes.append(
                    f"connected with a privileged role ({' and '.join(facts.problems())}); "
                    f"accepted by {live.OVERRIDE_FLAG}"
                )
            if facts.relations_readable:
                rls_live.notes.append(
                    f"the connecting role can read {facts.relations_readable} of "
                    f"{facts.relations_total} relations in the checked schemas; none were read"
                )
            results.append(rls_live)

            if live.schema_exists(connection, "storage") and "storage" not in target.schemas:
                storage = CheckResult(id="storage_live", title=TITLES["storage_live"], evidence=evidence)
                pgrls_runner.run_lint(
                    storage,
                    schemas=["storage"],
                    database_url=dsn,
                    rules=pgrls_runner.STORAGE_RULES,
                    allow_version_mismatch=args.allow_pgrls_version_mismatch,
                    force_read_only=facts.privileged,
                )
                results.append(storage)

            results.append(live.run_extra_checks(connection, target.schemas, evidence))
            results.append(live.run_function_exposure(connection, target, evidence))
            results.append(storage_buckets.run_on_connection(connection, target, evidence))
            results.append(table_writes.run_on_connection(connection, target, evidence))
            results.append(db_health.run_on_connection(connection, evidence))
            if args.parity:
                results.append(parity.run(inventory.connection_asker(connection), target, Path(args.parity),
                                          f"{evidence}, against {Path(args.parity).name}"))
            results.append(health.run_on_connection(connection, evidence, args.cron_days, target.expected_cron_jobs))

        if "probe" in skip:
            results.append(_not_run("anon_probe", "left out with --skip probe"))
        elif target.rest is None:
            results.append(_not_run("anon_probe", f"target {target.name!r} declares no API URL"))
        else:
            requested.add("anon_probe")
            tables = list(args.table)
            if not tables and connection is None:
                results.append(
                    _not_run(
                        "anon_probe",
                        "no table to probe: without a database connection the tool cannot list "
                        "what anon may read; name tables with --table",
                    )
                )
                requested.discard("anon_probe")
                return results
            if not tables:
                tables = live.anon_readable_relations(connection, args.probe_schema)
                if not tables:
                    results.append(
                        _not_run(
                            "anon_probe",
                            f"the catalog shows no relation in schema {args.probe_schema} "
                            "that anon may SELECT, so there is nothing to probe",
                        )
                    )
                    requested.discard("anon_probe")
                    return results
            probe = anon_probe.run(
                target,
                args.rest_url or target.rest,
                tables[: anon_probe.MAX_TABLES],
                owner_approved=args.owner_approved,
                key_env=args.key_env,
                schema=args.probe_schema,
            )
            if len(tables) > anon_probe.MAX_TABLES:
                probe.notes.append(
                    f"{len(tables)} relations are readable by anon; only the first "
                    f"{anon_probe.MAX_TABLES} were probed"
                )
            results.append(probe)
    finally:
        if connection is not None:
            connection.close()
    return results


def _apply_target_settings(args: argparse.Namespace) -> list[str]:
    """Switch on what the target file asks for; flags given on the command line still win.

    Returns the optional checks the file switched on, so the report can say so.
    """
    switched: list[str] = []
    target = None
    if args.target:
        try:
            target = get_target(Path(args.config), args.target)
        except Refusal:
            target = None  # reported, with its reason, by the live checks
    if target is not None:
        for name in target.optional_checks:
            if not getattr(args, f"with_{name}"):
                setattr(args, f"with_{name}", True)
                switched.append(name)
        if args.lang is None:
            args.lang = target.lang
    if args.lang is None:
        from_env = os.environ.get(LANGUAGE_ENV)
        args.lang = from_env if from_env in LANGUAGES else DEFAULT_LANGUAGE
    return switched


def cmd_check(args: argparse.Namespace) -> int:
    switched = _apply_target_settings(args)
    skip = set(args.skip)
    try:
        if args.only and (args.focus or args.group):
            raise ValueError("--only names exact checks; use it without --focus or --group")
        areas = tuple(dict.fromkeys(focus.parse(args.focus) + focus.parse_groups(args.group)))
        areas = tuple(name for name in focus.AREAS if name in areas)
        only = focus.parse_only(args.only, ["secrets", *TITLES])
        fail_groups = None
        if args.fail_groups is not None:
            fail_groups = [name.strip() for name in args.fail_groups.split(",") if name.strip()]
            unknown = sorted(set(fail_groups) - set(focus.GROUPS))
            if unknown or not fail_groups:
                raise ValueError(f"--fail-groups takes {', '.join(focus.GROUPS)}; got {args.fail_groups!r}")
        plan = focus.Plan(areas, args.profile, only)
    except ValueError as error:
        print(f"refused: {error}", file=sys.stderr)
        return EXIT_REFUSED
    plan.prepare(args, skip)
    requested: set[str] = set()
    checks: list[CheckResult] = []
    repos = [Path(p) for p in (args.repo or ["."])]

    changed: Optional[set[Path]] = None
    if args.changed_since:
        try:
            changed = set()
            for repo in repos:
                changed |= changes.changed_files(repo, args.changed_since)
            for extra in ([Path(args.migrations)] if args.migrations else []) + [Path(p) for p in args.sql_file]:
                if extra.exists():
                    changed |= changes.changed_files(extra, args.changed_since)
        except Refusal as refusal:
            print(f"refused: {refusal}", file=sys.stderr)
            return EXIT_REFUSED

    if "secrets" not in skip:
        requested.add("secrets")
        scan = secret_scan.run(repos, args.exclude, args.max_bytes, args.include_build, changed)
        if changed is not None:
            scan.notes.append(f"only files changed since {args.changed_since} were read ({len(changed)} changed)")
        checks.append(scan)

    sql_files: list[Path] = []
    if "static" not in skip:
        sql_files = [Path(p) for p in args.sql_file]
        if args.migrations:
            excludes = tuple(args.exclude_sql) or pgrls_runner.DEFAULT_SQL_EXCLUDES
            sql_files += pgrls_runner.collect_sql_files(Path(args.migrations), excludes)
        static = CheckResult(id="rls_static", title=TITLES["rls_static"])
        functions = CheckResult(id="functions_static", title=TITLES["functions_static"])
        missing = [str(path) for path in sql_files if not path.is_file()]
        if missing:
            static.status = functions.status = "ERROR"
            static.reason = functions.reason = "SQL file not found: " + ", ".join(missing)
        elif not sql_files:
            static.reason = functions.reason = "no SQL files given (--migrations or --sql-file)"
        elif changed is not None and not any(path.resolve() in changed for path in sql_files):
            static.reason = functions.reason = f"no SQL file changed since {args.changed_since}"
        else:
            requested.add("rls_static")
            static.evidence = (
                f"{len(sql_files)} SQL files read from disk, in this order: "
                + ", ".join(path.name for path in sql_files)
            )
            pgrls_runner.run_lint(
                static,
                sql_files=sql_files,
                config=Path(args.pgrls_config) if args.pgrls_config else None,
                allow_version_mismatch=args.allow_pgrls_version_mismatch,
            )
            requested.add("functions_static")
            functions_static.run(sql_files, functions)
            if changed is not None:
                for result in (static, functions):
                    result.notes.append(
                        f"a SQL file changed since {args.changed_since}, so every given file was read: "
                        "privileges depend on the files before the change"
                    )
        checks.append(static)
        checks.append(functions)

    target_text = "ไม่มี (ตรวจจากไฟล์เท่านั้น)" if args.lang == "th" else "none (files only)"
    if args.snapshot or args.via_api:
        snapshot_results, target_text = _snapshot_checks(args, skip, requested)
        checks += snapshot_results
    elif args.target is None:
        reason = "no --target given, so nothing live was contacted"
        checks += [_not_run(check_id, reason) for check_id in ("rls_live", "extra_live", "functions_live", "health_cron", "anon_probe")]
    else:
        try:
            target: Optional[Target] = get_target(Path(args.config), args.target)
        except Refusal as refusal:
            target = None
            requested.update({"rls_live", "extra_live", "functions_live"})
            checks += [_not_run(check_id, str(refusal)) for check_id in ("rls_live", "extra_live", "functions_live", "health_cron", "anon_probe")]
        if target is not None:
            target_text = target.describe()
            checks += _live_checks(args, target, skip, requested)

    if not any(check.id == "storage_buckets" for check in checks):
        checks.append(_not_run("storage_buckets", "buckets are read through --via-api or a database connection"))
    if not any(check.id == "table_writes" for check in checks):
        checks.append(_not_run("table_writes", "table privileges are read through --via-api or a database connection"))
    if not any(check.id == "platform" for check in checks):
        reason = platform.NOT_ASKED if args.via_api else "platform settings are only read with --via-api --with-platform"
        checks.append(_not_run("platform", reason))
    if not any(check.id == "parity" for check in checks):
        reason = (parity.NOT_ASKED if not args.parity
                  else "a parity check needs a database connection or --via-api")
        checks.append(_not_run("parity", reason))
    if not any(check.id == "data_api" for check in checks):
        reason = data_api.NOT_ASKED if args.via_api else "the Data API settings are only read with --via-api --with-data-api"
        checks.append(_not_run("data_api", reason))
    if not any(check.id == "db_health" for check in checks):
        checks.append(_not_run("db_health", "statistics are read through --via-api or a database connection"))
    if not any(check.id == "advisors_performance" for check in checks):
        reason = (advisors.PERFORMANCE_NOT_ASKED if args.via_api
                  else "the performance advisors are only read with --via-api --with-performance")
        checks.append(_not_run("advisors_performance", reason))
    if not any(check.id == "advisors" for check in checks):
        reason = advisors.NOT_ASKED if args.via_api else "the advisors are only read with --via-api --with-advisors"
        checks.append(_not_run("advisors", reason))
    if not any(check.id == "auth_config" for check in checks):
        reason = auth_config.NOT_ASKED if args.via_api else "sign-in settings are only read with --via-api --with-auth-config"
        checks.append(_not_run("auth_config", reason))
    if not any(check.id == "health_backups" for check in checks):
        reason = backups.NOT_ASKED if args.via_api else "the backup list is only read with --via-api --with-backups"
        checks.append(_not_run("health_backups", reason))
    if not any(check.id == "health_logs" for check in checks):
        reason = logs.NOT_ASKED if args.via_api else "the log summary is only read with --via-api --with-logs"
        checks.append(_not_run("health_logs", reason))

    checks = plan.apply(checks, requested, args.lang, {"secrets": secret_scan.TITLE, **TITLES})

    if args.write_baseline:
        try:
            count = baseline.write(Path(args.write_baseline), checks)
        except OSError as error:
            print(f"could not write the baseline ({type(error).__name__})", file=sys.stderr)
            return EXIT_REFUSED
        print(f"baseline: {count} findings recorded in {args.write_baseline}", file=sys.stderr)
    if args.baseline:
        try:
            baseline.apply(checks, baseline.load(Path(args.baseline)), Path(args.baseline).name)
        except Refusal as refusal:
            print(f"refused: {refusal}", file=sys.stderr)
            return EXIT_REFUSED

    source = "; ".join(f"{repo.resolve()} ({_git_revision(repo)})" for repo in repos)
    if switched:
        for check in checks:
            if check.id in switched and check.status != NOT_RUN:
                check.notes.append("switched on by the target's `checks` in the target file")
    scope = plan.describe(args.lang)
    if args.changed_since:
        since = (f"ไฟล์ที่เปลี่ยนตั้งแต่ {args.changed_since} (ตรวจฐานเต็ม)" if args.lang == "th"
                 else f"files changed since {args.changed_since} (database checks in full)")
        scope = "; ".join(part for part in (scope, since) if part)
    real_data = False
    if args.target:
        try:
            real_data = get_target(Path(args.config), args.target).data == "real"
        except Refusal:
            real_data = False
    report = Report(checks=checks, source=source, target=target_text, requested=requested, lang=args.lang,
                    real_data=real_data,
                    scope=scope)
    try:
        written = report.write(Path(args.out_dir))
    except OSError as error:
        written = None
        print(
            f"could not write the report to {args.out_dir} ({type(error).__name__}). "
            "Pass --out-dir with a writable folder, or --json to print the full report.",
            file=sys.stderr,
        )
    if args.sarif and written:
        try:
            located = sarif.write(Path(args.out_dir) / "report.sarif", checks, repos, sql_files)
            print(f"report.sarif: {located} findings placed on file lines", file=sys.stderr if args.json else sys.stdout)
        except OSError as error:
            print(f"could not write report.sarif ({type(error).__name__})", file=sys.stderr)
    if args.json:
        sys.stdout.write(report.to_json())
    else:
        print(report.console_summary())
        if written:
            print(f"report: {written[1]}")
            print(f"        {written[0]}")
    return report.exit_code(args.fail_on, fail_groups)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)
