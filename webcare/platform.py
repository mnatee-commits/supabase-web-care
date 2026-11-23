"""Platform settings: SSL enforcement and network restrictions of the database.

Two GETs of the Management API, only when asked with `--with-platform`. Both
endpoints are marked beta and experimental by Supabase, so their answers are
read defensively: anything not understood is reported as such, never as safe.

- SSL enforcement off means Postgres accepts unencrypted connections; a client
  that does not insist on TLS can leak the password and every row on the way.
- No network restriction (every address allowed) is Supabase's default: the
  database password is then the only gate in front of direct connections.
"""

from __future__ import annotations

from typing import Callable

from .model import ERROR, CheckResult, Finding
from .targets import Target

TITLE = "Platform settings: SSL enforcement and network restrictions"
SOURCE = "platform"
NOT_ASKED = "not asked for; add --with-platform to --via-api (two GETs of beta endpoints)"
_OPEN = {"0.0.0.0/0", "::/0"}


def ssl_enforced(answer):
    """True, False, or None when the answer is not in a known shape."""
    if not isinstance(answer, dict):
        return None
    current = answer.get("currentConfig", answer.get("current_config"))
    if isinstance(current, dict) and isinstance(current.get("database"), bool):
        return current["database"]
    return None


def allowed_ranges(answer):
    """(entitlement, list of allowed CIDR ranges) or None when not understood."""
    if not isinstance(answer, dict):
        return None
    config = answer.get("config")
    if not isinstance(config, dict):
        return None
    ranges = []
    for key in ("dbAllowedCidrs", "dbAllowedCidrsV6", "db_allowed_cidrs", "db_allowed_cidrs_v6"):
        value = config.get(key)
        if isinstance(value, list):
            ranges += [str(item) for item in value]
    return str(answer.get("entitlement", "")), ranges


def judge(result: CheckResult, ssl_answer, network_answer, target: Target) -> CheckResult:
    def add(rule: str, severity: str, location: str, message: str) -> None:
        result.findings.append(Finding(SOURCE, rule, severity, location, message))

    enforced = ssl_enforced(ssl_answer)
    if enforced is None:
        result.notes.append("the SSL enforcement answer was not in a known shape, so SSL was not judged")
    elif not enforced:
        add("ssl_not_enforced", "high" if target.data == "real" else "medium", "database",
            "the database accepts connections without TLS; a client that does not insist on it can "
            "send the password and rows in the clear. Turn on SSL enforcement in the database settings.")
    if isinstance(ssl_answer, dict) and ssl_answer.get("appliedSuccessfully") is False:
        result.notes.append("Supabase reports the stored SSL setting was not applied successfully")

    network = allowed_ranges(network_answer)
    if network is None:
        result.notes.append("the network restrictions answer was not in a known shape, so it was not judged")
    else:
        entitlement, ranges = network
        if entitlement == "disallowed":
            result.notes.append("network restrictions are not available on this project's plan")
        elif not ranges or set(ranges) & _OPEN:
            add("database_open_to_every_address", "low", "database",
                "direct database connections are allowed from every address, so the database "
                "password is the only gate; restrict them to the addresses that need them")
        else:
            result.notes.append(f"direct connections allowed from {len(ranges)} address ranges")
        status = network_answer.get("status") if isinstance(network_answer, dict) else None
        if status and status != "applied":
            result.notes.append(f"network restrictions status: {status}")
    if enforced is None and network is None:
        result.status, result.reason = ERROR, "neither answer was in a known shape"
        return result
    return result.finish()


def run(target: Target, fetch_ssl: Callable[[], object], fetch_network: Callable[[], object],
        evidence: str) -> CheckResult:
    result = CheckResult(id="platform", title=TITLE, evidence=evidence)
    return judge(result, fetch_ssl(), fetch_network(), target)

