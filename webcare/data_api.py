"""Which schemas the Data API serves, read from the project's PostgREST settings.

One GET of the Management API's PostgREST configuration, only when asked with
`--with-data-api`. Supabase's API reference lists a JWT secret in that answer,
so, as with the sign-in settings, a fixed allowlist is copied and the rest is
dropped before anything else reads it.

It reports schemas the Data API serves that the target's `schemas` leave out:
every check here that reads the catalog looks only at the declared schemas, so
an undeclared served schema is a blind spot.
"""

from __future__ import annotations

from typing import Callable

from .model import ERROR, CheckResult, Finding
from .targets import Target

TITLE = "Data API settings: which schemas are served"
SOURCE = "data_api"
NOT_ASKED = "not asked for; add --with-data-api to --via-api (one GET of the PostgREST settings)"
KEPT = ("db_schema", "db_extra_search_path", "max_rows")


def keep(answer) -> dict:
    """The allowlisted settings only. Everything else, secrets included, is dropped."""
    if not isinstance(answer, dict):
        return {}
    return {key: answer[key] for key in KEPT if key in answer}


def _schemas(value) -> list[str]:
    return [part.strip().strip('"').lower() for part in str(value or "").split(",") if part.strip()]


def judge(result: CheckResult, settings: dict, target: Target) -> CheckResult:
    if "db_schema" not in settings:
        result.status, result.reason = ERROR, "the PostgREST settings carried no db_schema"
        return result
    served = _schemas(settings.get("db_schema"))
    declared = set(target.schemas)
    for schema in served:
        if schema not in declared and schema != "graphql_public":
            result.findings.append(Finding(
                SOURCE, "served_schema_unchecked", "medium", f"schema {schema}",
                "the Data API serves this schema, but the target's schemas leave it out, so "
                "no catalog check here looks at it; add it to schemas",
            ))
    not_served = sorted(declared - set(served))
    result.notes.append(
        f"served: {', '.join(served) or 'none'}; extra search path: "
        f"{settings.get('db_extra_search_path') or 'none'}; row cap per request: "
        f"{settings.get('max_rows') if settings.get('max_rows') is not None else 'none'}"
    )
    if not_served:
        result.notes.append(f"declared but not served by the Data API: {', '.join(not_served)}")
    return result.finish()


def run(target: Target, fetch: Callable[[], object], evidence: str) -> CheckResult:
    result = CheckResult(id="data_api", title=TITLE, evidence=evidence)
    return judge(result, keep(fetch()), target)
