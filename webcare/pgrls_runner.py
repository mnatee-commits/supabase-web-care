"""Run the pinned pgrls release and translate its report.

pgrls is used as published: this module starts it as a separate process with
a fixed argument list and reads its JSON output. A database connection string
is handed over through the process environment so it never shows up in the
process list or in a log line.
"""

from __future__ import annotations

import fnmatch
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional, Sequence

from . import PINNED_PGRLS_VERSION
from .model import CheckResult, Finding

# pgrls "info" findings are nudges, not defects; they are listed without
# turning a check into FINDINGS.
SEVERITY_MAP = {"error": "high", "warning": "medium", "info": "info"}
DEFAULT_SQL_EXCLUDES = ("ROLLBACK_*.sql", "*.down.sql", "*rollback*.sql")
# Supabase owns the storage schema, so only the rules about what the project's
# own policies let through are useful there.
STORAGE_RULES = ("SEC008", "SEC028", "SEC039", "SEC050")
TIMEOUT_SECONDS = 600

# Supabase creates and owns the tables in these schemas, so migration files
# hold policies for them but never their CREATE TABLE. A lint of SQL files
# alone cannot know whether RLS is enabled there and would report it as off.
MANAGED_SCHEMAS = frozenset(
    {
        "auth", "storage", "realtime", "vault", "extensions", "graphql",
        "graphql_public", "supabase_functions", "pgsodium", "cron", "net",
    }
)
TABLE_STATE_RULES = frozenset({"SEC001", "SEC002", "SEC009", "SEC032"})
# Offline, these fire on a table whose CREATE TABLE is in the files while the
# migration that enabled RLS is not, which happens whenever the set is partial.
HISTORY_DEPENDENT_RULES = frozenset({"SEC001", "SEC032"})


def find_pgrls() -> Optional[str]:
    """Prefer the pgrls installed next to the running interpreter."""
    beside = Path(sys.executable).parent / "pgrls"
    if beside.is_file():
        return str(beside)
    return shutil.which("pgrls")


def installed_version(executable: str) -> Optional[str]:
    try:
        completed = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    words = completed.stdout.strip().split()
    return words[-1] if completed.returncode == 0 and words else None


def collect_sql_files(directory: Path, excludes: Sequence[str] = DEFAULT_SQL_EXCLUDES) -> list[Path]:
    """Forward migrations in a directory, ordered by file name."""
    return [
        path
        for path in sorted(directory.glob("*.sql"), key=lambda p: p.name)
        if not any(fnmatch.fnmatch(path.name, pattern) for pattern in excludes)
    ]


def _scrub(text: str, database_url: Optional[str]) -> str:
    """Remove the connection string and its password from text bound for a report."""
    if not database_url:
        return text
    secrets = [database_url]
    try:
        from psycopg.conninfo import conninfo_to_dict

        password = conninfo_to_dict(database_url).get("password")
        if password:
            secrets.append(str(password))
    except Exception:
        pass
    for secret in secrets:
        text = text.replace(secret, "***")
    return text


def _translate(violations: list[dict]) -> list[Finding]:
    findings = []
    for item in violations:
        title = str(item.get("title", "")).strip()
        message = str(item.get("message", "")).strip()
        findings.append(
            Finding(
                source="pgrls",
                rule=str(item.get("rule_id", "UNKNOWN")),
                severity=SEVERITY_MAP.get(str(item.get("severity")), "medium"),
                location=str(item.get("location", "")),
                message=f"{title}. {message}" if title else message,
            )
        )
    return findings


def run_lint(
    result: CheckResult,
    *,
    schemas: Iterable[str] = (),
    sql_files: Sequence[Path] = (),
    database_url: Optional[str] = None,
    rules: Sequence[str] = (),
    baseline: Optional[Path] = None,
    config: Optional[Path] = None,
    allow_version_mismatch: bool = False,
    force_read_only: bool = False,
) -> CheckResult:
    """Fill `result` from one `pgrls lint` run (offline SQL or live database).

    `force_read_only` asks the server for read-only transactions through
    PGOPTIONS. It is meant for the one case where the connecting role could
    write (a privileged role accepted on a throwaway database); some poolers
    reject startup options, so it stays off for the audit role, whose lack of
    grants already rules writing out.
    """
    executable = find_pgrls()
    if executable is None:
        result.status = "NOT_RUN"
        result.reason = (
            f"pgrls is not installed. Install the pinned release: pip install "
            f"pgrls=={PINNED_PGRLS_VERSION} (see scripts/install_offline.sh for a machine "
            "without internet)."
        )
        return result
    version = installed_version(executable)
    if version != PINNED_PGRLS_VERSION:
        if not allow_version_mismatch:
            result.status = "NOT_RUN"
            result.reason = (
                f"pgrls {version or 'of unknown version'} is installed, but this toolkit was "
                f"reviewed against {PINNED_PGRLS_VERSION}. Install the pinned release, or pass "
                "--allow-pgrls-version-mismatch after reviewing the newer release."
            )
            return result
        result.notes.append(
            f"pgrls {version} differs from the reviewed release {PINNED_PGRLS_VERSION}"
        )

    offline = database_url is None
    schemas = list(schemas)
    argv = [executable, "lint", "--format", "json"]
    if not offline:
        # pgrls reads every schema present in SQL files, so the option only
        # means something against a live database.
        argv += ["--schemas", ",".join(schemas)]
    for rule in rules:
        argv += ["--rule", rule]
    if baseline is not None:
        argv += ["--baseline", str(baseline)]
    if config is not None:
        argv += ["--config", str(config)]

    environment = {
        key: value
        for key, value in os.environ.items()
        if key != "DATABASE_URL" and not key.startswith("WEBCARE_")
    }
    if not offline:
        environment["DATABASE_URL"] = database_url
        if force_read_only:
            environment["PGOPTIONS"] = "-c default_transaction_read_only=on"
    else:
        for path in sql_files:
            argv += ["--sql-file", str(path)]

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        result.status = "ERROR"
        result.reason = f"pgrls did not finish within {TIMEOUT_SECONDS} seconds"
        return result
    except OSError as error:
        result.status = "ERROR"
        result.reason = f"pgrls could not be started ({type(error).__name__})"
        return result

    try:
        report = json.loads(completed.stdout)
        violations = report["violations"]
    except (ValueError, KeyError, TypeError):
        result.status = "ERROR"
        # pgrls prints its own error on the last line. The connection string went
        # through the environment, and is scrubbed here in case a driver echoed it.
        last_line = (completed.stderr.strip().splitlines() or ["no output"])[-1]
        last_line = _scrub(last_line, database_url)[:300]
        result.reason = f"pgrls exited with code {completed.returncode}: {last_line}"
        return result

    findings = _translate(violations)
    if offline:
        unknowable = [
            f for f in findings
            if f.rule in TABLE_STATE_RULES and f.location.split(".")[0] in MANAGED_SCHEMAS
        ]
        if unknowable:
            findings = [f for f in findings if f not in unknowable]
            result.notes.append(
                f"{len(unknowable)} findings about RLS being off on Supabase-managed tables "
                "(auth, storage, ...) were left out: the SQL files do not define those "
                "tables, so their state is unknown here. A live check covers them."
            )
        if any(f.rule in HISTORY_DEPENDENT_RULES for f in findings):
            result.notes.append(
                "\"RLS not enabled\" findings (SEC001, SEC032) are only as complete as the SQL "
                "files. If the migration that enables RLS on a table is not among them, the "
                "finding is false. Confirm against the live catalog before acting on one."
            )
    result.findings.extend(findings)
    skipped = report.get("skipped_rules") or []
    if skipped:
        result.notes.append(
            f"{len(skipped)} rules need a live database and did not run on SQL files alone: "
            + ", ".join(str(rule) for rule in skipped)
        )
    scope = "every schema defined in the SQL files" if offline else ", ".join(schemas)
    result.notes.append(f"pgrls {version}, schemas: {scope}")
    if baseline is not None:
        result.notes.append(f"baseline {baseline.name} applied: only findings not in it are listed")
    return result.finish()
