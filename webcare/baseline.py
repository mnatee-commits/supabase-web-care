"""Baseline: let a repository adopt the file checks without fixing its history first.

A project that starts linting old migrations gets findings for decisions made
long ago, often already corrected in the database by a later migration. A
baseline records those findings once, so that the check fails only for what a
change adds.

Limits, on purpose:
- Only the two checks that read SQL files can be baselined. A credential found
  in the tree and anything found in a live system are never accepted this way.
- An entry names a check, a rule and a place. Line numbers are left out, so
  editing a file does not unmatch its entries, and a new finding of the same
  rule on the same object in the same file is covered by the old entry.
- Accepted findings are counted in the report, never hidden.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .model import FINDINGS, PASS, CheckResult, Refusal

FORMAT = "webcare-baseline/1"
BASELINED_CHECKS = ("rls_static", "functions_static", "edge_functions")
_LINE = re.compile(r":\d+(?=\)|$)")  # "(a.sql:10)" and "functions/x/index.ts:10"


def key(check_id: str, rule: str, location: str) -> tuple[str, str, str]:
    return (check_id, rule, _LINE.sub("", location))


def collect(checks: list[CheckResult]) -> list[dict]:
    entries = {
        key(check.id, finding.rule, finding.location)
        for check in checks if check.id in BASELINED_CHECKS
        for finding in check.findings if finding.severity != "info"
    }
    return [{"check": c, "rule": r, "location": l} for c, r, l in sorted(entries)]


def write(path: Path, checks: list[CheckResult]) -> int:
    entries = collect(checks)
    path.write_text(
        json.dumps({"format": FORMAT, "findings": entries}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return len(entries)


def load(path: Path) -> set[tuple[str, str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise Refusal(f"could not read baseline file {path} ({type(error).__name__})") from None
    except ValueError:
        raise Refusal(f"baseline file {path.name} is not valid JSON") from None
    if not isinstance(data, dict) or data.get("format") != FORMAT or not isinstance(data.get("findings"), list):
        raise Refusal(f"{path.name} is not a baseline in format {FORMAT}")
    keys = set()
    for entry in data["findings"]:
        if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) for k in ("check", "rule", "location")):
            raise Refusal(f"baseline file {path.name} has a malformed entry")
        if entry["check"] not in BASELINED_CHECKS:
            raise Refusal(
                f"baseline file {path.name} lists check {entry['check']!r}; only "
                f"{' and '.join(BASELINED_CHECKS)} can be baselined"
            )
        keys.add(key(entry["check"], entry["rule"], entry["location"]))
    return keys


def apply(checks: list[CheckResult], keys: set[tuple[str, str, str]], name: str) -> None:
    """Drop findings the baseline already holds, and say how many were dropped."""
    used: set[tuple[str, str, str]] = set()
    for check in checks:
        if check.id not in BASELINED_CHECKS or check.status not in (PASS, FINDINGS):
            continue
        kept, accepted = [], 0
        for finding in check.findings:
            k = key(check.id, finding.rule, finding.location)
            if finding.severity != "info" and k in keys:
                accepted += 1
                used.add(k)
            else:
                kept.append(finding)
        check.findings = kept
        check.finish()
        stale = sum(1 for k in keys if k[0] == check.id and k not in used)
        check.notes.append(
            f"baseline {name}: {accepted} findings already recorded there are not counted"
            + (f"; {stale} of its entries no longer match anything and can be removed" if stale else "")
        )
