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


def _label(metadata) -> Optional[str]:
    """`schema.name` from the metadata of one flagged object, when it has them."""
    if not isinstance(metadata, dict):
        return None
    schema, name = metadata.get("schema"), metadata.get("name") or metadata.get("entity")
    if not isinstance(name, str) or not name:
        return None
    label = f"{schema}.{name}" if isinstance(schema, str) and schema else name
    return _text(label, MAX_NAME_CHARS)


def _group(lints: list) -> dict[str, dict]:
    """Lint entries grouped by lint name, in the order first seen.

    The platform's endpoint answers with one entry per flagged object, each
    carrying its own `metadata`. The Supabase MCP tool answers with one entry per
    lint holding a `findings` list and a `count`. Both are read here, so a count
    never depends on which of the two a caller was given.
    """
    groups: dict[str, dict] = {}
    for lint in lints:
        if not isinstance(lint, dict):
            continue
        name = _text(lint.get("name") or "unknown", MAX_NAME_CHARS)
        group = groups.setdefault(name, {"lint": lint, "count": 0, "names": []})
        found: list[Optional[str]]
        if isinstance(lint.get("findings"), list) or isinstance(lint.get("count"), int):
            group["count"] += _count(lint)
            found = [
                _label(item.get("metadata")) for item in lint.get("findings") or [] if isinstance(item, dict)
            ]
        else:
            group["count"] += 1
            found = [_label(lint.get("metadata"))]
        for label in found:
            if label and label not in group["names"] and len(group["names"]) < MAX_NAMES:
                group["names"].append(label)
    return groups


def judge(result: CheckResult, answer, target: Target) -> CheckResult:
    lints = lints_of(answer)
    if lints is None:
        result.status, result.reason = ERROR, "the advisor answer was not in the documented shape"
        return result
    groups = _group(lints)
    ignore = set(target.advisors_ignore)
    ignored: dict[str, int] = {}
    total = sum(group["count"] for group in groups.values())
    for name, group in groups.items():
        lint, count, names = group["lint"], group["count"], group["names"]
        if name in ignore:
            ignored[name] = count
            continue
        severity = _SEVERITY.get(str(lint.get("level")).upper(), "medium")
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
        f"{len(groups)} kinds of lint returned, {total} objects in all. Security lints only: the "
        "performance and health advisors were not read. These are the platform's checks, not "
        "pgrls's analysis of what each policy lets a caller do."
    )
    if ignored:
        result.notes.append(
            "not counted because advisors_ignore lists them: "
            + ", ".join(f"{name} ({count})" for name, count in sorted(ignored.items()))
        )
    stale = sorted(ignore - set(groups))
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
