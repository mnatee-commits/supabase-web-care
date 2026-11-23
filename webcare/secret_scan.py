"""Find credentials left in a source tree.

A finding says where a credential is and what kind it is. It never contains
the credential: no finding, note, or error message carries a matched value.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

from .model import CheckResult, Finding

SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "dist",
        "build",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        "coverage",
        "wheelhouse",
        "webcare-output",
        ".webcare-output",  # the pre-commit hook writes its report here
    }
)
TITLE = "Credentials left in the source tree"
BUILD_DIRS = frozenset({"dist", "build", ".next", ".nuxt", ".svelte-kit"})
DEFAULT_MAX_BYTES = 2_000_000

# Put this text on a line to silence findings on that line, for a fixture or a
# documented placeholder that only looks like a credential.
ALLOW_MARKER = "webcare:allow-secret"

# Values that stand in for a credential in examples and templates.
_PLACEHOLDER = re.compile(
    r"^(?:<.*>|\[.*\]|\$\{?\w+\}?|\{\{.*\}\}|\{\w+\}|%\w+%|x{3,}|\*{3,}|\.{3,}|"
    r"password|passwd|pass|secret|changeme|change[-_]me.*|your[-_ ]?\w+|example)$",
    re.IGNORECASE,
)
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "db", "host.docker.internal"})

# Credentials every `supabase start` hands out. Public, so not worth an alarm.
_LOCAL_JWT_SECRET = "super-secret-jwt-token-with-at-least-32-characters-long"
_LOCAL_JWT_ISSUER = "supabase-demo"

# A match handler returns (rule, severity, message), or None to drop the match.
Verdict = Optional[tuple[str, str, str]]


@dataclass(frozen=True)
class Rule:
    pattern: re.Pattern
    handle: Callable[[re.Match], Verdict]


def _fixed(rule: str, severity: str, message: str) -> Callable[[re.Match], Verdict]:
    def handle(match: re.Match) -> Verdict:
        return rule, severity, f"{message} ({len(match.group(0))} characters)"

    return handle


def _jwt_payload(token: str) -> Optional[dict]:
    try:
        segment = token.split(".")[1]
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        payload = json.loads(raw)
    except (IndexError, ValueError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _handle_jwt(match: re.Match) -> Verdict:
    payload = _jwt_payload(match.group(0))
    if payload is None:
        return None
    role = payload.get("role")
    local = payload.get("iss") == _LOCAL_JWT_ISSUER
    if role == "service_role":
        if local:
            return (
                "supabase_local_service_role_jwt",
                "low",
                "service_role JWT issued by a local Supabase stack (public default key)",
            )
        return (
            "supabase_service_role_jwt",
            "high",
            "service_role JWT: this key bypasses row level security",
        )
    if role == "anon":
        return (
            "supabase_anon_jwt",
            "info",
            "anon JWT (public by design; listed so you know where it lives)",
        )
    if "sub" in payload or "exp" in payload:
        return "jwt_token", "medium", "a signed JWT, possibly a user session token"
    return None


def _handle_postgres_url(match: re.Match) -> Verdict:
    password = match.group("password")
    host = match.group("host").lower()
    if _PLACEHOLDER.match(password):
        return None
    if host in _LOOPBACK_HOSTS:
        if password == "postgres":
            return None  # the local development default
        return (
            "postgres_url_password_local",
            "low",
            "Postgres connection string with a password, pointing at a local host",
        )
    return (
        "postgres_url_password",
        "high",
        "Postgres connection string with an embedded password",
    )


def _handle_dsn_keyword(match: re.Match) -> Verdict:
    if _PLACEHOLDER.match(match.group("password")):
        return None
    return (
        "postgres_dsn_password",
        "medium",
        "libpq connection string with an embedded password",
    )


def _handle_jwt_secret(match: re.Match) -> Verdict:
    value = match.group("value")
    if value == _LOCAL_JWT_SECRET or _PLACEHOLDER.match(value):
        return None
    return (
        "jwt_secret_assignment",
        "high",
        "JWT signing secret assigned in a file: anyone holding it can mint any role",
    )


_WELL_KNOWN_LOCAL_PASSWORDS = frozenset({"postgres", "supabase"})


# Code that reads a password rather than holding one: process.env.X, os.getenv("X"),
# settings.db.password, z.string().min(8), and the like.
_CODE_REFERENCE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[\w$]+)+|^[A-Za-z_$][\w$.]*\(")
_PLACEHOLDER_WORDS = re.compile(r"your|example|sample|placeholder|changeme|change[-_]me|dummy|redacted|xxx", re.I)


def _handle_password_variable(match: re.Match) -> Verdict:
    single = match.group("single")
    value = single if single is not None else (match.group("double") if match.group("double") is not None
                                               else match.group("bare"))
    if single is None and value.startswith("$"):
        return None  # a shell or compose variable; single quotes would make it literal
    if match.group("bare") is not None and _CODE_REFERENCE.match(value):
        return None
    if (len(value) < 6 or _PLACEHOLDER.match(value) or _PLACEHOLDER_WORDS.search(value)
            or value.lower() in _WELL_KNOWN_LOCAL_PASSWORDS or " " in value.strip()):
        return None
    return (
        "database_password_variable",
        "high",
        f"database password assigned to {match.group('name')} in a file",
    )


def _handle_public_env_name(match: re.Match) -> Verdict:
    return (
        "secret_in_public_env_name",
        "high",
        f"variable {match.group(0)} is shipped to the browser by its prefix, "
        "yet is named like a server-side secret",
    )


RULES: tuple[Rule, ...] = (
    Rule(
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        _handle_jwt,
    ),
    Rule(
        re.compile(r"\bsb_secret_[A-Za-z0-9_-]{16,}"),
        _fixed("supabase_secret_key", "high", "Supabase secret API key"),
    ),
    Rule(
        re.compile(r"\bsb_publishable_[A-Za-z0-9_-]{16,}"),
        _fixed(
            "supabase_publishable_key",
            "info",
            "Supabase publishable key (public by design; listed so you know where it lives)",
        ),
    ),
    Rule(
        re.compile(r"\bsbp_[A-Za-z0-9_]{32,}"),
        _fixed(
            "supabase_access_token",
            "high",
            "Supabase personal access token: account-level access",
        ),
    ),
    Rule(
        re.compile(
            r"\b(?:NEXT_PUBLIC|NUXT_PUBLIC|EXPO_PUBLIC|REACT_APP|VITE|GATSBY|PUBLIC)_"
            r"[A-Z0-9_]*(?:SERVICE_ROLE|SECRET)[A-Z0-9_]*"
        ),
        _handle_public_env_name,
    ),
    Rule(
        re.compile(
            r"\b[A-Za-z0-9_]*JWT_SECRET[A-Za-z0-9_]*\s*[:=]\s*[\"']?"
            r"(?P<value>[A-Za-z0-9+/=_-]{24,})"
        ),
        _handle_jwt_secret,
    ),
    Rule(
        re.compile(
            r"\bpostgres(?:ql)?://[^\s:/@'\"`]+:(?P<password>[^\s@'\"`]+)@"
            r"(?P<host>\[[0-9a-fA-F:]+\]|[^\s:/'\"`?]+)"
        ),
        _handle_postgres_url,
    ),
    Rule(
        re.compile(
            r"\b(?:host|hostaddr|dbname|user)=[^\s,]+[^,\n]{0,200}?\bpassword=(?P<password>[^\s'\"&;,)]{6,})"
        ),
        _handle_dsn_keyword,
    ),
    Rule(
        re.compile(
            r"(?<![A-Za-z0-9])(?:[A-Z0-9]+_)*(?P<name>PGPASSWORD|POSTGRES_PASSWORD|SUPABASE_DB_PASSWORD|"
            r"DB_PASSWORD|DATABASE_PASSWORD)[\"']?\s*[:=]\s*"
            r"(?:'(?P<single>[^'\n]*)'|\"(?P<double>[^\"\n]*)\"|(?P<bare>[^\s\"'#,;]+))",
        ),
        _handle_password_variable,
    ),
    Rule(
        re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
        lambda match: ("private_key_block", "high", "private key block"),
    ),
    Rule(
        re.compile(r"\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b"),
        _fixed("brevo_api_key", "high", "Brevo API key"),
    ),
    Rule(
        re.compile(r"\bre_[A-Za-z0-9]{6,}_[A-Za-z0-9]{20,}\b"),
        _fixed("resend_api_key", "high", "Resend API key"),
    ),
    Rule(
        re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"),
        _fixed("stripe_live_key", "high", "Stripe live secret key"),
    ),
    # Keys of services a Supabase app often calls. Formats as the providers publish them.
    Rule(
        re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{24,}"),
        _fixed("anthropic_api_key", "high", "Anthropic API key"),
    ),
    Rule(
        re.compile(r"(?<![A-Za-z0-9_-])sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{24,}"
                   r"|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"),
        _fixed("openai_api_key", "high", "OpenAI API key"),
    ),
    Rule(
        re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Za-z])"),
        _fixed("aws_access_key_id", "medium", "AWS access key id (the secret key that goes with it is not checked for)"),
    ),
    Rule(
        re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})"),
        _fixed("github_token", "high", "GitHub token"),
    ),
    Rule(
        re.compile(r"(?<![A-Za-z0-9_.-])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
        _fixed("sendgrid_api_key", "high", "SendGrid API key"),
    ),
    Rule(
        re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
        _fixed("google_api_key", "low",
               "Google API key: public for Firebase or Maps when restricted, secret for Gemini and paid APIs"),
    ),
)


@dataclass
class ScanStats:
    files_scanned: int = 0
    skipped_large: int = 0
    skipped_binary: int = 0
    unreadable: int = 0


def scan_text(text: str, display_path: str) -> list[Finding]:
    """Scan one file's text. `display_path` is used only to label findings."""
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                verdict = rule.handle(match)
                if verdict is None:
                    continue
                rule_id, severity, message = verdict
                if (rule_id, line_number) in seen:
                    continue
                seen.add((rule_id, line_number))
                findings.append(
                    Finding(
                        source="secret_scan",
                        rule=rule_id,
                        severity=severity,
                        location=f"{display_path}:{line_number}",
                        message=message,
                    )
                )
    return findings


def _excluded(relative: str, excludes: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(relative, pattern) for pattern in excludes)


def _iter_files(root: Path, excludes: tuple[str, ...], skip_dirs: frozenset = SKIP_DIRS,
                only: Optional[set] = None):
    """Yield (path, relative posix path) for regular files under root; only those in `only`
    (absolute paths) when it is given."""
    if root.is_file():
        yield root, root.name
        return
    for directory, subdirs, files in os.walk(root, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if d not in skip_dirs)
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if _excluded(relative, excludes):
                continue
            if only is not None and path.resolve() not in only:
                continue
            yield path, relative


def scan_tree(
    root: Path,
    excludes: Iterable[str] = (),
    max_bytes: int = DEFAULT_MAX_BYTES,
    include_build: bool = False,
    only: Optional[set] = None,
) -> tuple[list[Finding], ScanStats]:
    findings: list[Finding] = []
    stats = ScanStats()
    skip_dirs = SKIP_DIRS - BUILD_DIRS if include_build else SKIP_DIRS
    for path, relative in _iter_files(root, tuple(excludes), skip_dirs, only):
        try:
            if path.stat().st_size > max_bytes:
                stats.skipped_large += 1
                continue
            data = path.read_bytes()
        except OSError:
            stats.unreadable += 1
            continue
        if b"\x00" in data[:8192]:
            stats.skipped_binary += 1
            continue
        stats.files_scanned += 1
        findings.extend(scan_text(data.decode("utf-8", errors="replace"), relative))
    return findings, stats


def root_labels(roots: list[Path]) -> list[str]:
    """The prefix each root's findings carry when several roots are scanned.

    A root is named by its folder; two roots with the same folder name are named by
    their path instead, so `apps/api` and `services/api` stay apart.
    """
    if len(roots) == 1:
        return [""]
    names = [root.resolve().name for root in roots]
    labels = []
    for root, name in zip(roots, names):
        if names.count(name) > 1:
            try:
                name = root.resolve().relative_to(Path.cwd().resolve()).as_posix()
            except ValueError:
                name = root.resolve().as_posix().lstrip("/")
        labels.append(f"{name}/")
    return labels


def run(
    roots: Iterable[Path],
    excludes: Iterable[str] = (),
    max_bytes: int = DEFAULT_MAX_BYTES,
    include_build: bool = False,
    only: Optional[set] = None,
) -> CheckResult:
    result = CheckResult(id="secrets", title=TITLE)
    roots = [Path(root) for root in roots]
    missing = [str(root) for root in roots if not root.exists()]
    if missing:
        result.status = "ERROR"
        result.reason = "path not found: " + ", ".join(missing)
        return result

    total = ScanStats()
    for root, prefix in zip(roots, root_labels(roots)):
        findings, stats = scan_tree(root, excludes, max_bytes, include_build, only)
        for finding in findings:
            result.findings.append(
                Finding(
                    source=finding.source,
                    rule=finding.rule,
                    severity=finding.severity,
                    location=prefix + finding.location,
                    message=finding.message,
                )
            )
        total.files_scanned += stats.files_scanned
        total.skipped_large += stats.skipped_large
        total.skipped_binary += stats.skipped_binary
        total.unreadable += stats.unreadable

    result.evidence = (
        f"working tree of {', '.join(str(root) for root in roots)}: "
        f"{total.files_scanned} text files scanned"
    )
    if total.skipped_large:
        result.notes.append(
            f"{total.skipped_large} files over {max_bytes} bytes were not scanned"
        )
    if total.unreadable:
        result.notes.append(f"{total.unreadable} files could not be read")
    result.notes.append(
        "Scans files on disk only. Credentials removed in an earlier commit are "
        "still in git history and are not covered."
    )
    return result.finish()
