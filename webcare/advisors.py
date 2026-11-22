"""Supabase's own security lints (the Security Advisor), read through the Management API.

One GET of the project's security advisors, and only when the operator asks
with `--with-advisors`. The access token needs the `advisors_read` permission.

Supabase runs about thirty security lints. Several are RLS checks that pgrls
would make on a direct connection and that the other `--via-api` checks do not
make: RLS off on an exposed table, an always-true policy, a policy that trusts
`user_metadata`, a view that bypasses RLS. Reading the platform's own verdict
fills that gap without this toolkit reimplementing it. It is not pgrls's
policy analysis, and it only covers what the platform's lints cover.

The answer is names and counts: which lint fired and which objects it names.
One lint can name hundreds of objects, so a finding carries the count and the
first few names, and a lint the owner has reviewed can be listed in the
target's `advisors_ignore`. Ignored lints are counted in a note, never hidden.
"""

from __future__ import annotations

import re
from typing import Optional

from .model import ERROR, CheckResult, Finding
from .targets import Target

TITLE = "Supabase Security Advisor lints (the platform's own checks)"
SOURCE = "advisor"
NOT_ASKED = "not asked for; add --with-advisors to --via-api (the token then also needs advisors_read)"
MAX_NAMES = 5
MAX_NAME_CHARS = 80
MAX_TEXT_CHARS = 240
LINT_NAME = re.compile(r"^[a-z0-9_]{3,80}$")
_SEVERITY = {"ERROR": "high", "WARN": "medium", "INFO": "info"}
_LINK_PREFIX = "https://supabase.com/"


def _text(value, limit: int = MAX_TEXT_CHARS) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def lints_of(answer) -> Optional[list]:
    """The list of lints, whichever wrapper the answer came in."""
    for _ in range(3):
        if isinstance(answer, dict) and "lints" not in answer and "result" in answer:
            answer = answer["result"]
    if isinstance(answer, dict):
        answer = answer.get("lints")
    return answer if isinstance(answer, list) else None


def _count(lint: dict) -> int:
    count = lint.get("count")
    if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
        return count
    findings = lint.get("findings")
    return len(findings) if isinstance(findings, list) else 1


def _object_names(lint: dict) -> list[str]:
    names: list[str] = []
    findings = lint.get("findings")
    for item in findings if isinstance(findings, list) else []:
        metadata = item.get("metadata") if isinstance(item, dict) else None
        if not isinstance(metadata, dict):
            continue
        schema, name = metadata.get("schema"), metadata.get("name") or metadata.get("entity")
        if not isinstance(name, str) or not name:
            continue
        label = f"{schema}.{name}" if isinstance(schema, str) and schema else name
        label = _text(label, MAX_NAME_CHARS)
        if label not in names:
            names.append(label)
        if len(names) >= MAX_NAMES:
            break
    return names


def judge(result: CheckResult, answer, target: Target) -> CheckResult:
    lints = lints_of(answer)
    if lints is None:
        result.status, result.reason = ERROR, "the advisor answer was not in the documented shape"
        return result
    ignore = set(target.advisors_ignore)
    seen: set[str] = set()
    ignored: dict[str, int] = {}
    total = 0
    for lint in lints:
        if not isinstance(lint, dict):
            continue
        name = _text(lint.get("name") or "unknown", MAX_NAME_CHARS)
        seen.add(name)
        count = _count(lint)
        total += count
        if name in ignore:
            ignored[name] = count
            continue
        severity = _SEVERITY.get(str(lint.get("level")).upper(), "medium")
        names = _object_names(lint)
        shown = ""
        if names:
            more = f" and {count - len(names)} more" if count > len(names) else ""
            shown = f" (for example {', '.join(names)}{more})"
        remediation = lint.get("remediation")
        link = f" See {remediation}" if isinstance(remediation, str) and remediation.startswith(_LINK_PREFIX) else ""
        result.findings.append(
            Finding(
                SOURCE, name, severity, f"advisor {name}",
                f"{_text(lint.get('title') or name, 120)}: {count} object{'s' if count != 1 else ''}{shown}. "
                f"{_text(lint.get('description'))}{link}",
            )
        )
    result.notes.append(
        f"{len(lints)} kinds of lint returned, {total} objects in all. Security lints only: the "
        "performance and health advisors were not read. These are the platform's checks, not "
        "pgrls's analysis of what each policy lets a caller do."
    )
    if ignored:
        result.notes.append(
            "not counted because advisors_ignore lists them: "
            + ", ".join(f"{name} ({count})" for name, count in sorted(ignored.items()))
        )
    stale = sorted(ignore - seen)
    if stale:
        result.notes.append(
            "advisors_ignore lists lints the advisor did not return, so the entries can be "
            "removed: " + ", ".join(stale)
        )
    return result.finish()


def run(target: Target, fetch, evidence: str) -> CheckResult:
    """`fetch` returns the decoded answer of the security advisors endpoint."""
    result = CheckResult(id="advisors", title=TITLE, evidence=evidence)
    return judge(result, fetch(), target)
