"""Site health: a 24-hour summary of the API gateway log, counts only.

Three GETs of the project's log query endpoint through the Management API, and
only when the operator asks with `--with-logs`: the grouped summary below, and
one count per source (API gateway and Auth) for the last 24 hours and for the
24 hours before, so that a rise in server errors or refusals is compared with
the day before, as Supabase's detection checks do. The access token needs one
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


# Supabase's detection checks (docs: observability/detecting): one count per source, the API
# gateway and Auth judged separately because their events are different observations.
TREND_SQL = (
    "select source, count() as events, "
    "countIf(status between 100 and 599) as responses, "
    "countIf(status between 500 and 599) as server_errors, "
    "countIf(status in (401, 403)) as access_failures, "
    "countIf(status is null or status < 100 or status > 599) as unknown_status "
    "from (select source, toInt32OrNull(if(source = 'edge_logs', "
    "log_attributes['response.status_code'], log_attributes['status'])) as status "
    "from logs where source in ('edge_logs', 'auth_logs')) "
    "group by source order by source limit 2"
)
TREND_MIN_RESPONSES = 100
TREND_MIN_COUNT = 20
TREND_MIN_RATE = 0.01
TREND_RISE = 2.0
TREND_SOURCES = {"edge_logs": "API gateway", "auth_logs": "Auth"}


def previous_window(start: str) -> tuple[str, str]:
    begin = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (begin - WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ"), start


def _by_source(answer) -> Optional[dict[str, dict]]:
    if not isinstance(answer, dict) or not isinstance(answer.get("result"), list) or answer.get("error"):
        return None
    return {str(row.get("source")): row for row in answer["result"] if isinstance(row, dict)}


def judge_trend(result: CheckResult, current, previous) -> None:
    """Compare server errors and refusals per source with the 24 hours before."""
    now_rows, before_rows = _by_source(current), _by_source(previous)
    if now_rows is None or before_rows is None:
        result.notes.append("comparison with the previous 24 hours: unable to assess (the log endpoint "
                            "did not return a result in the documented shape)")
        return
    for source, label in TREND_SOURCES.items():
        now_row, before_row = now_rows.get(source), before_rows.get(source)
        if now_row is None or before_row is None:
            result.notes.append(
                f"{label}: unable to assess the change since the previous 24 hours, because one window "
                "has no events from this source. On the free plan logs are kept for a short time, so "
                "the earlier window may already be gone; a missing source is not a zero error rate")
            continue
        now_total, before_total = _number(now_row.get("responses")), _number(before_row.get("responses"))
        unknown = _number(now_row.get("unknown_status"))
        if unknown:
            result.notes.append(f"{label}: {unknown} events in the last 24 hours had no valid status")
        if now_total < TREND_MIN_RESPONSES or before_total < TREND_MIN_RESPONSES:
            result.notes.append(
                f"{label}: unable to assess the change since the previous 24 hours ({now_total} and "
                f"{before_total} responses; both windows need at least {TREND_MIN_RESPONSES})")
            continue
        for field, rule, what in (("server_errors", "log_error_rate_rising", "server errors (5xx)"),
                                  ("access_failures", "log_denied_rate_rising", "refusals (401 or 403)")):
            count, before = _number(now_row.get(field)), _number(before_row.get(field))
            rate, before_rate = count / now_total, before / before_total
            rising = rate >= TREND_RISE * before_rate if before_rate else True
            if count >= TREND_MIN_COUNT and rate >= TREND_MIN_RATE and rising:
                compared = (f"against {before_rate:.1%} in the 24 hours before" if before_rate
                            else "with none in the 24 hours before")
                result.findings.append(Finding(
                    SOURCE, rule, "medium", f"{label} log",
                    f"{count} {what} out of {now_total} responses ({rate:.1%}) in the last 24 hours, "
                    f"{compared}. A rise is a reason to look, not proof of an attack: group them by "
                    "status and path, not by user or address"))
            else:
                result.notes.append(
                    f"{label}: {what} {count} of {now_total} ({rate:.1%}), the 24 hours before "
                    f"{before} of {before_total} ({before_rate:.1%}); no rise above the thresholds")


def window(now: Optional[datetime] = None) -> tuple[str, str]:
    end = (now or datetime.now(timezone.utc)).replace(second=0, microsecond=0)
    return (end - WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")


def _expected_names(target: Target) -> set[str]:
    """Function names from the allowlist, without schema or argument list."""
    return {re.sub(r"\(.*$", "", entry).split(".")[-1].strip().lower() for entry in target.expected_anon_functions}


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
                if name.lower() not in expected:
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
    judge(result, fetch(SQL, start, end), target, start, end)
    if result.status != ERROR:
        before_start, before_end = previous_window(start)
        judge_trend(result, fetch(TREND_SQL, start, end), fetch(TREND_SQL, before_start, before_end))
        result.finish()
    return result
