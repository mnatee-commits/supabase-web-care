"""Site health: a 24-hour summary of the API gateway log, counts only.

One GET of the project's log query endpoint through the Management API, and
only when the operator asks with `--with-logs`. The access token needs one
more permission for it, `analytics_logs_read`.

The query is fixed and asks for counts grouped by service, table or function
name, method, status, kind of API key and whether the caller was signed in.
It never asks for an IP address, a user id, a query string, a header value or
a request body, and for services other than the Data API it drops everything
after the service name, because Storage paths contain file names.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from .model import ERROR, CheckResult, Finding
from .targets import Target

TITLE = "API gateway log, last 24 hours (counts only)"
SOURCE = "health"
WINDOW = timedelta(hours=24)
MAX_GROUPS = 300
NOT_ASKED = "not asked for; add --with-logs to --via-api (the token then also needs analytics_logs_read)"
SERVER_ERRORS_LOW, SERVER_ERRORS_MEDIUM = 5, 50
DENIED_LOW, DENIED_MEDIUM = 50, 500

_PATH = "splitByChar('/', log_attributes['request.path'])"
_KEY = "log_attributes['request.sb.apikey.apikey.prefix']"
_KEY_ROLE = "log_attributes['request.sb.jwt.apikey.payload.role']"
SQL = (
    f"select {_PATH}[2] as service, "
    f"if({_PATH}[2] = 'rest', if({_PATH}[4] = 'rpc', concat('rpc/', {_PATH}[5]), {_PATH}[4]), '') as target, "
    "log_attributes['request.method'] as method, "
    "log_attributes['response.status_code'] as status, "
    f"multiIf(startsWith({_KEY}, 'sb_secret'), 'secret', "
    f"{_KEY} = '' and {_KEY_ROLE} = 'service_role', 'secret', "
    f"{_KEY} = '' and {_KEY_ROLE} = '', 'none', 'public') as key_kind, "
    "if(log_attributes['request.sb.jwt.authorization.payload.subject'] = '', 0, 1) as signed_in, "
    "count() as requests "
    "from logs where source = 'edge_logs' and log_attributes['request.method'] != 'OPTIONS' "
    "group by service, target, method, status, key_kind, signed_in "
    f"order by requests desc limit {MAX_GROUPS}"
)


def window(now: Optional[datetime] = None) -> tuple[str, str]:
    end = (now or datetime.now(timezone.utc)).replace(second=0, microsecond=0)
    return (end - WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")


def _expected_names(target: Target) -> set[str]:
    """Function names from the allowlist, without schema or argument list."""
    return {re.sub(r"\(.*$", "", entry).split(".")[-1].strip() for entry in target.expected_anon_functions}


def _number(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def judge(result: CheckResult, answer, target: Target, start: str, end: str) -> CheckResult:
    if not isinstance(answer, dict) or not isinstance(answer.get("result"), list) or answer.get("error"):
        result.status, result.reason = ERROR, "the log endpoint did not return a result in the documented shape"
        return result
    rows = [row for row in answer["result"] if isinstance(row, dict)]
    total = sum(_number(row.get("requests")) for row in rows)
    server_errors: dict[str, int] = defaultdict(int)
    denied: dict[str, int] = defaultdict(int)
    anon_calls: dict[str, int] = defaultdict(int)
    secret_requests = 0

    for row in rows:
        count, status = _number(row.get("requests")), _number(row.get("status"))
        place = "/".join(part for part in (str(row.get("service") or "?"), str(row.get("target") or "")) if part)
        if status >= 500:
            server_errors[place] += count
        elif status in (401, 403):
            denied[place] += count
        if row.get("key_kind") == "secret":
            secret_requests += count
        function = str(row.get("target") or "")
        if (
            function.startswith("rpc/") and 200 <= status < 300
            and not _number(row.get("signed_in")) and row.get("key_kind") != "secret"
        ):
            anon_calls[function[4:]] += count

    def add(rule: str, severity: str, location: str, message: str) -> None:
        result.findings.append(Finding(SOURCE, rule, severity, location, message))

    for place, count in sorted(server_errors.items(), key=lambda item: -item[1]):
        if count >= SERVER_ERRORS_LOW:
            add(
                "log_server_errors", "medium" if count >= SERVER_ERRORS_MEDIUM else "low", place,
                f"{count} requests ended in a server error (5xx) in the last 24 hours",
            )
    for place, count in sorted(denied.items(), key=lambda item: -item[1]):
        if count >= DENIED_LOW:
            add(
                "log_denied_burst", "medium" if count >= DENIED_MEDIUM else "low", place,
                f"{count} requests were refused (401 or 403) in the last 24 hours; a broken "
                "client, an expired key, or someone probing",
            )
    if anon_calls:
        if target.expected_anon_functions:
            expected = _expected_names(target)
            for name, count in sorted(anon_calls.items(), key=lambda item: -item[1]):
                if name not in expected:
                    add(
                        "log_anon_rpc_unexpected", "medium", f"rpc/{name}",
                        f"called successfully {count} times without signing in, and it is not "
                        "in expected_anon_functions",
                    )
        else:
            result.notes.append(
                f"{len(anon_calls)} functions were called successfully without signing in; declare "
                "expected_anon_functions on the target to have them judged"
            )
    result.notes.append(
        f"{total} requests from {start} to {end}: {sum(server_errors.values())} server errors, "
        f"{sum(denied.values())} refused, {secret_requests} made with a secret key"
    )
    result.notes.append(
        "counts only: no IP address, user id, query string, header value or request body was asked for"
    )
    if len(rows) >= MAX_GROUPS:
        result.notes.append(f"only the {MAX_GROUPS} largest groups were returned; small counts may be missing")
    return result.finish()


def run(target: Target, fetch, evidence: str, now: Optional[datetime] = None) -> CheckResult:
    """`fetch(sql, start, end)` returns the decoded answer of the log endpoint."""
    start, end = window(now)
    result = CheckResult(id="health_logs", title=TITLE, evidence=evidence)
    return judge(result, fetch(SQL, start, end), target, start, end)
