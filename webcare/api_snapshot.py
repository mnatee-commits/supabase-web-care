"""Fetch a catalog snapshot through the Supabase Management API.

For a machine that can reach the web but not Postgres. The tool sends the
snapshot statement from `snapshot.build_sql` to the project's read-only query
endpoint, and afterwards the two scheduled-job statements from `health`. That
endpoint runs each statement as `supabase_read_only_user`, so the platform
refuses writes whatever this code sends. Nothing here accepts SQL from outside:
every statement is built by this package and checked to be a single SELECT
before it leaves.

Two other endpoints exist, each only when the operator asks for it. With
`--with-backups`: a GET of the project's backup list (`backups.py`), which
carries no SQL and returns no data from the database. With `--with-logs`: a
GET of the log query endpoint carrying one fixed counting query (`logs.py`).
With `--with-auth-config`: a GET of the Auth configuration, whose answer is
reduced to an allowlist before anything reads it (`auth_config.py`). With
`--with-advisors`: a GET of the security advisors (`advisors.py`), which holds
lint names and the names of the objects they flag. No other endpoint is ever
called.

What this route costs: it needs an account access token, which is a stronger
credential than the audit role. Through the same endpoint that token can read
rows of application tables, although this tool never asks for any. Use a
fine-grained token limited to the one project with the `database_read`
permission only, give it a short life, and revoke it afterwards.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlsplit

from . import __version__, live, snapshot
from .model import Refusal
from .targets import Target, _is_private_host

API_BASE = "https://api.supabase.com"
# Not SUPABASE_ACCESS_TOKEN on purpose: that name is what the Supabase CLI reads, and on a
# developer machine it usually holds an account-wide token that can write. The audit must
# be handed its own narrow token, never pick up a broad one that happens to be set.
DEFAULT_TOKEN_ENV = "WEBCARE_ACCESS_TOKEN"
TIMEOUT_SECONDS = 60
MAX_RESPONSE_BYTES = snapshot.MAX_BYTES

_HINTS = {
    401: "the access token was rejected (expired, revoked, or not an account access token)",
    403: "the access token may not read this project's database; a fine-grained token "
    "needs the database_read permission for this project",
    404: "no project with this reference is visible to the access token",
    429: "the Management API rate limit was reached; wait a minute and run again",
}


def _api_message(error: urllib.error.HTTPError, token: str) -> str:
    """A short, scrubbed excerpt of the API's own error text, for debugging."""
    try:
        payload = json.loads(error.read(4000).decode("utf-8", "replace"))
    except (ValueError, OSError):
        return ""
    text = payload.get("message") or payload.get("error") if isinstance(payload, dict) else ""
    if not isinstance(text, str):
        return ""
    text = text.replace(token, "[token]")
    text = re.sub(r"(?i)bearer\s+\S+", "[redacted]", text)
    text = " ".join(text.split())
    return text if len(text) <= 240 else text[:239] + "…"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the token to a host nobody declared. Refuse it."""

    def redirect_request(self, *args, **kwargs):
        return None


def check_token(token: str, token_env: str) -> None:
    """Refuse values that are plainly not an account access token."""
    if not token:
        raise Refusal(f"environment variable {token_env} is not set")
    if token.startswith(("sb_secret_", "sb_publishable_")) or token.startswith("eyJ"):
        raise Refusal(
            f"{token_env} holds a project API key. This route needs an account access "
            "token; never give an audit a secret or service_role key."
        )
    if any(character.isspace() for character in token):
        raise Refusal(f"{token_env} contains whitespace and cannot be an access token")


def endpoint(project_ref: str, api_base: str = "") -> str:
    base = (api_base or API_BASE).rstrip("/")
    parts = urlsplit(base)
    if parts.scheme != "https" and not (parts.scheme == "http" and _is_private_host(parts.hostname or "")):
        raise Refusal("the Management API is only contacted over https")
    return f"{base}/v1/projects/{project_ref}/database/query/read-only"


def fetch(
    target: Target,
    owner_approved: bool,
    token_env: str = DEFAULT_TOKEN_ENV,
    api_base: str = "",
) -> tuple[dict, str]:
    """Return (snapshot, origin text). Raises Refusal without contacting anything
    when a guard rail fails, and Refusal with a short reason when the API does."""
    statement = snapshot.build_sql(target.schemas, target.name)
    data = _select(target, owner_approved, token_env, api_base, snapshot.statement_body(statement))

    taken = snapshot.parse(data, "the Management API answer")
    if taken["label"] != target.name:
        raise Refusal("the Management API answer does not carry the label that was sent")
    origin = (
        f"fetched by this run from project {target.project_ref} through the Management API "
        "read-only query endpoint (one SELECT over the system catalog, run as "
        f"supabase_read_only_user), target {target.describe()}"
    )
    return taken, origin


def asker(target: Target, owner_approved: bool, token_env: str = DEFAULT_TOKEN_ENV, api_base: str = ""):
    """A function that sends one of this package's own SELECTs and returns the answer."""

    def ask(body: str):
        return _select(target, owner_approved, token_env, api_base, body)

    return ask


def _select(target: Target, owner_approved: bool, token_env: str, api_base: str, body: str):
    """POST one SELECT to the read-only endpoint and return the decoded JSON answer."""
    target.ensure_allowed(owner_approved)
    if not target.project_ref:
        raise Refusal(
            f"target {target.name!r} declares no project_ref, so there is no project to ask"
        )
    token = os.environ.get(token_env, "")
    check_token(token, token_env)
    live.assert_single_select(body)  # nothing but a single SELECT leaves this module

    url = endpoint(target.project_ref, api_base)
    request = urllib.request.Request(
        url,
        method="POST",
        data=json.dumps({"query": body}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"supabase-web-care/{__version__}",
        },
    )
    return _send(request, token, "the read-only query endpoint", _HINTS[403])


def backup_list(target: Target, owner_approved: bool, token_env: str = DEFAULT_TOKEN_ENV, api_base: str = ""):
    """GET the project's backup list. The only request here that is not a SELECT."""
    target.ensure_allowed(owner_approved)
    if not target.project_ref:
        raise Refusal(
            f"target {target.name!r} declares no project_ref, so there is no project to ask"
        )
    token = os.environ.get(token_env, "")
    check_token(token, token_env)
    url = endpoint(target.project_ref, api_base).removesuffix("/query/read-only") + "/backups"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": f"supabase-web-care/{__version__}",
        },
    )
    return _send(
        request, token, "the backup list endpoint",
        "the access token may not list this project's backups; a fine-grained token "
        "needs the backups_read permission for this project",
    )


def advisors_security(target: Target, owner_approved: bool, token_env: str = DEFAULT_TOKEN_ENV, api_base: str = ""):
    """GET the project's security advisors (Supabase's own lints)."""
    target.ensure_allowed(owner_approved)
    if not target.project_ref:
        raise Refusal(
            f"target {target.name!r} declares no project_ref, so there is no project to ask"
        )
    token = os.environ.get(token_env, "")
    check_token(token, token_env)
    base = endpoint(target.project_ref, api_base).removesuffix("/database/query/read-only")
    request = urllib.request.Request(
        f"{base}/advisors/security",
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": f"supabase-web-care/{__version__}",
        },
    )
    return _send(
        request, token, "the security advisors endpoint",
        "the access token may not read this project's advisors; a fine-grained token "
        "needs the advisors_read permission for this project",
    )


def auth_settings(target: Target, owner_approved: bool, token_env: str = DEFAULT_TOKEN_ENV, api_base: str = ""):
    """GET the Auth configuration and return only the allowlisted settings."""
    from . import auth_config

    target.ensure_allowed(owner_approved)
    if not target.project_ref:
        raise Refusal(
            f"target {target.name!r} declares no project_ref, so there is no project to ask"
        )
    token = os.environ.get(token_env, "")
    check_token(token, token_env)
    base = endpoint(target.project_ref, api_base).removesuffix("/database/query/read-only")
    request = urllib.request.Request(
        f"{base}/config/auth",
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": f"supabase-web-care/{__version__}",
        },
    )
    # The full answer holds secrets. It is reduced here and never leaves this function.
    return auth_config.keep(
        _send(
            request, token, "the Auth configuration endpoint",
            "the access token may not read this project's Auth configuration; a fine-grained "
            "token needs the auth_config_read permission for this project",
        )
    )


def log_summary(
    target: Target, owner_approved: bool, sql: str, start: str, end: str,
    token_env: str = DEFAULT_TOKEN_ENV, api_base: str = "",
):
    """GET the log query endpoint with this package's one fixed counting query."""
    from . import logs

    if sql != logs.SQL:
        raise Refusal("only the toolkit's own log summary query may be sent")
    target.ensure_allowed(owner_approved)
    if not target.project_ref:
        raise Refusal(
            f"target {target.name!r} declares no project_ref, so there is no project to ask"
        )
    token = os.environ.get(token_env, "")
    check_token(token, token_env)
    base = endpoint(target.project_ref, api_base).removesuffix("/database/query/read-only")
    query = urlencode({"sql": sql, "iso_timestamp_start": start, "iso_timestamp_end": end})
    request = urllib.request.Request(
        f"{base}/analytics/endpoints/logs?{query}",
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": f"supabase-web-care/{__version__}",
        },
    )
    return _send(
        request, token, "the log query endpoint",
        "the access token may not read this project's logs; a fine-grained token "
        "needs the analytics_logs_read permission for this project",
    )


def _send(request: urllib.request.Request, token: str, what: str, forbidden_hint: str):
    url = request.full_url
    handlers: list = [_NoRedirect()]
    if _is_private_host(urlsplit(url).hostname or ""):
        handlers.append(urllib.request.ProxyHandler({}))  # never route local traffic out
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        hint = forbidden_hint if error.code == 403 else _HINTS.get(
            error.code, "the Management API refused the request"
        )
        detail = _api_message(error, token)
        raise Refusal(
            f"{what} answered HTTP {error.code}: {hint}"
            + (f" (API message: {detail})" if detail else "")
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise Refusal(
            f"could not reach the Management API ({type(error).__name__})"
        ) from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise Refusal("the Management API answer is larger than a snapshot can be")
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        raise Refusal("the Management API answer is not JSON") from None
