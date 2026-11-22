"""Ask the Data API what an anonymous visitor can see.

For each table the probe sends one HEAD request with the public (anon or
publishable) key and reads the status line and Content-Range header. HEAD
responses have no body, so no row ever reaches this process. The probe never
sends a write, never calls a function, and never signs anyone up.
"""

from __future__ import annotations

import os
import re
import time
import urllib.error
import urllib.request
from typing import Iterable, Optional
from urllib.parse import quote, urlsplit

from . import __version__
from .model import CheckResult, Finding, Refusal
from .secret_scan import _jwt_payload
from .targets import Target, _is_private_host

DEFAULT_KEY_ENV = "WEBCARE_ANON_KEY"
MAX_TABLES = 200
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,62}$")
_RANGE_WITH_ROWS = re.compile(r"^\d+-\d+/(?:\*|\d+)$")
_RANGE_EMPTY = re.compile(r"^\*/(?:\*|\d+)$")

VISIBLE = "visible"
NO_ROWS = "reachable_no_rows"
REACHABLE_UNKNOWN = "reachable_unknown"
DENIED = "denied"
NOT_EXPOSED = "not_exposed"
UNKNOWN = "unknown"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Report a redirect instead of following it to a host nobody declared."""

    def redirect_request(self, *args, **kwargs):
        return None


def check_public_key(key: str) -> str:
    """Return the key kind, or refuse anything that is not a public key."""
    if not key:
        raise Refusal("no API key supplied for the anon probe")
    if key.startswith("sb_secret_"):
        raise Refusal("this is a secret key. The anon probe only accepts the public key.")
    if key.startswith("sb_publishable_"):
        return "publishable"
    payload = _jwt_payload(key)
    if payload is None:
        raise Refusal("the supplied key is neither a publishable key nor a readable JWT")
    role = payload.get("role")
    if role != "anon":
        raise Refusal(
            f"the supplied JWT carries role {role!r}. The anon probe only accepts role 'anon'."
        )
    return "anon_jwt"


def classify(status: int, content_range: Optional[str]) -> str:
    if status in (200, 206):
        if content_range and _RANGE_WITH_ROWS.match(content_range):
            return VISIBLE
        if content_range and _RANGE_EMPTY.match(content_range):
            return NO_ROWS
        return REACHABLE_UNKNOWN
    if status == 416:  # requested range past the end: reachable, nothing there
        return NO_ROWS
    if status in (401, 403):
        return DENIED
    if status == 404:
        return NOT_EXPOSED
    return UNKNOWN


def _opener(host: str) -> urllib.request.OpenerDirector:
    handlers: list = [_NoRedirect()]
    if _is_private_host(host):
        handlers.append(urllib.request.ProxyHandler({}))  # never route local traffic out
    return urllib.request.build_opener(*handlers)


def probe_table(
    origin: str,
    key: str,
    key_kind: str,
    table: str,
    schema: str = "public",
    timeout: float = 10.0,
) -> tuple[Optional[int], Optional[str], str]:
    """Return (status, content_range, error_text) for one HEAD request."""
    url = f"{origin}/rest/v1/{quote(table, safe='')}?select=*&limit=1"
    headers = {
        "apikey": key,
        "Accept": "application/json",
        "User-Agent": f"supabase-web-care/{__version__}",
    }
    if key_kind == "anon_jwt":
        headers["Authorization"] = f"Bearer {key}"
    if schema != "public":
        headers["Accept-Profile"] = schema
    request = urllib.request.Request(url, method="HEAD", headers=headers)
    opener = _opener(urlsplit(origin).hostname or "")
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.headers.get("Content-Range"), ""
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("Content-Range"), ""
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return None, None, type(error).__name__


def run(
    target: Target,
    rest_url: str,
    tables: Iterable[str],
    owner_approved: bool = False,
    key_env: str = DEFAULT_KEY_ENV,
    schema: str = "public",
    delay: float = 0.2,
) -> CheckResult:
    result = CheckResult(id="anon_probe", title="What an anonymous visitor can read")
    try:
        target.ensure_allowed(owner_approved)
        origin = target.ensure_rest_matches(rest_url)
        key = os.environ.get(key_env, "")
        key_kind = check_public_key(key)
        names = list(dict.fromkeys(tables))
        bad = [name for name in names if not _IDENTIFIER.match(name)]
        if bad:
            raise Refusal(
                f"{len(bad)} table name(s) are not plain identifiers; pass bare names such as 'orders'"
            )
        if not names:
            raise Refusal("no tables to probe")
        if len(names) > MAX_TABLES:
            raise Refusal(f"{len(names)} tables requested; the probe stops at {MAX_TABLES}")
    except Refusal as refusal:
        result.status = "NOT_RUN"
        result.reason = str(refusal)
        return result

    result.evidence = (
        f"HEAD requests to {origin} (target {target.describe()}) with the {key_kind} key, "
        f"schema {schema}, {len(names)} tables"
    )
    counts: dict[str, int] = {}
    for index, table in enumerate(names):
        if index:
            time.sleep(delay)
        status, content_range, error = probe_table(origin, key, key_kind, table, schema)
        outcome = classify(status, content_range) if status is not None else UNKNOWN
        counts[outcome] = counts.get(outcome, 0) + 1
        location = f"{schema}.{table}"
        if outcome == VISIBLE:
            if table in target.expected_public:
                result.notes.append(f"{location}: rows visible to anon, declared as expected")
            else:
                result.findings.append(
                    Finding(
                        source="anon_probe",
                        rule="anon_can_read_rows",
                        severity="high",
                        location=location,
                        message=(
                            "an anonymous request received rows. If this table is meant "
                            "to be public, list it under expected_public for this target."
                        ),
                    )
                )
        elif outcome == REACHABLE_UNKNOWN:
            result.findings.append(
                Finding(
                    source="anon_probe",
                    rule="anon_reachable_unclear",
                    severity="medium",
                    location=location,
                    message=(
                        f"HTTP {status} without a readable Content-Range; could not tell "
                        "whether rows are visible"
                    ),
                )
            )
        elif outcome == UNKNOWN:
            detail = f"HTTP {status}" if status is not None else f"no response ({error})"
            result.notes.append(f"{location}: {detail}; result unknown")
    summary = ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
    result.notes.append(f"outcomes: {summary}")
    result.notes.append(
        "'reachable_no_rows' means the request was accepted and returned nothing: "
        "either RLS filtered every row or the table is empty."
    )
    if counts.get(UNKNOWN, 0) == len(names):
        result.status = "ERROR"
        result.reason = "no table gave a usable answer; check the URL and the key"
        return result
    return result.finish()
