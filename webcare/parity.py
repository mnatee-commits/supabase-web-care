"""Parity: what changed in a database since a saved inventory.

`check --parity <file>` takes a new inventory through the same route as the
other live checks (a connection or `--via-api`) and compares it with the file,
which was saved earlier with `webcare inventory` from the same target. Every
difference is reported: a grant, policy, function or default privilege that
appeared, went away or changed since the file was saved. Read it as "was this
change intended?", not as a fault in itself.

The file must carry the target's own name, so one database is never judged
against another's inventory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from . import inventory
from .model import ERROR, CheckResult, Finding, Refusal
from .targets import Target

TITLE = "Parity with a saved inventory: what changed since then"
SOURCE = "parity"
NOT_ASKED = "not asked for; pass --parity with an inventory file saved earlier from this target"
# Parts that decide who may reach what; a change there is worth a look first.
ACCESS_PARTS = {"tables", "column_grants", "policies", "functions", "default_acl"}
SHOWN = 6


def _list(names: list[str]) -> str:
    shown = ", ".join(names[:SHOWN])
    return shown + (f" and {len(names) - SHOWN} more" if len(names) > SHOWN else "")


def judge(result: CheckResult, saved: dict, current: dict) -> CheckResult:
    compared = inventory.compare(saved, current)
    since = saved.get("taken_at", "the saved inventory")
    for name in inventory.PART_ORDER:
        part = compared.get(name, {})
        if "not_compared" in part:
            result.notes.append(f"{name} not compared: {part['not_compared']}")
            continue
        added, removed, changed = part["only_second"], part["only_first"], sorted(part["changed"])
        if not (added or removed or changed):
            continue
        pieces = []
        if added:
            pieces.append(f"{len(added)} added ({_list(added)})")
        if removed:
            pieces.append(f"{len(removed)} gone ({_list(removed)})")
        if changed:
            fields = sorted({str(field).split(":")[0] for key in changed for field in part["changed"][key]})
            pieces.append(f"{len(changed)} changed in {', '.join(fields)} ({_list(changed)})")
        result.findings.append(Finding(
            SOURCE, f"parity_{name}", "medium" if name in ACCESS_PARTS else "low", name,
            f"since {since}: " + "; ".join(pieces) + ". If intended, save a new inventory.",
        ))
    if set(saved.get("schemas", [])) != set(current.get("schemas", [])):
        result.notes.append(
            f"the saved inventory covers schemas {', '.join(saved.get('schemas', []))}, this run "
            f"{', '.join(current.get('schemas', []))}; differences may come from that"
        )
    result.notes.append(f"compared with the inventory taken at {since} by version {saved.get('tool_version', '?')}")
    return result.finish()


def run(ask: Callable[[str], object], target: Target, saved_path: Path, evidence: str) -> CheckResult:
    result = CheckResult(id="parity", title=TITLE, evidence=evidence)
    try:
        saved = inventory.load(saved_path)
    except Refusal as refusal:
        result.status, result.reason = ERROR, str(refusal)
        return result
    if saved.get("label") != target.name:
        result.status = ERROR
        result.reason = (f"{saved_path.name} was saved from target {saved.get('label')!r}, not "
                         f"{target.name!r}; compare like with like")
        return result
    try:
        current = inventory.collect(ask, target)
    except Refusal as refusal:
        result.status, result.reason = ERROR, str(refusal)
        return result
    except Exception as error:  # a failed query must not take the other checks down
        result.status, result.reason = ERROR, f"the inventory could not be taken ({type(error).__name__})"
        return result
    return judge(result, saved, current)
