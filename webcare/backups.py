"""Site health: does the platform hold a recent backup of this database?

One GET of the project's backup list through the Management API, and only
when the operator asks with `--with-backups`. The answer holds dates and
statuses, nothing from the database itself. The access token needs one more
permission for it, `backups_read`.

A listed backup is not a tested restore. This check can say that no recent
backup exists; it cannot say that one would restore.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from .model import ERROR, CheckResult, Finding
from .targets import Target

TITLE = "Database backups held by the platform"
SOURCE = "health"
MAX_AGE = timedelta(hours=48)
NOT_ASKED = "not asked for; add --with-backups to --via-api (the token then also needs backups_read)"


def _when(value) -> Optional[datetime]:
    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def judge(result: CheckResult, answer, target: Target, now: Optional[datetime] = None) -> CheckResult:
    if not isinstance(answer, dict) or not isinstance(answer.get("backups"), list):
        result.status, result.reason = ERROR, "the backup list was not in the documented shape"
        return result
    now = now or datetime.now(timezone.utc)
    real = target.data == "real" or target.env == "production"
    location = f"project {target.project_ref}"

    def add(rule: str, severity: str, message: str) -> None:
        result.findings.append(Finding(SOURCE, rule, severity, location, message))

    listed = [entry for entry in answer["backups"] if isinstance(entry, dict)]
    done = [when for entry in listed if entry.get("status") == "COMPLETED" and (when := _when(entry.get("inserted_at")))]
    physical = answer.get("physical_backup_data") if isinstance(answer.get("physical_backup_data"), dict) else {}
    latest_physical = _when(physical.get("latest_physical_backup_date_unix"))
    if latest_physical:
        done.append(latest_physical)
    latest = max(done) if done else None
    pitr = bool(answer.get("pitr_enabled"))

    if latest is None:
        add(
            "backup_none", "high" if real else "low",
            "the platform lists no completed backup of this database"
            + ("" if real else "; acceptable only while the data is synthetic and can be rebuilt"),
        )
    else:
        age = now - latest
        if age > MAX_AGE and not pitr:
            add(
                "backup_stale", "medium" if real else "low",
                f"the newest completed backup is from {latest:%Y-%m-%d %H:%M} UTC, "
                f"{age.days} days ago; daily backups appear to have stopped",
            )
        result.notes.append(f"newest completed backup: {latest:%Y-%m-%d %H:%M} UTC")
    newest_entry = max(
        (entry for entry in listed if _when(entry.get("inserted_at"))),
        key=lambda entry: _when(entry.get("inserted_at")), default=None,
    )
    if newest_entry is not None and newest_entry.get("status") == "FAILED":
        add("backup_last_failed", "medium" if real else "low", "the most recent backup attempt failed")
    result.notes.append(
        f"{len(listed)} backups listed; point-in-time recovery is {'on' if pitr else 'off'}"
    )
    result.notes.append("a listed backup is not a tested restore; restoring into a scratch project is a manual check")
    return result.finish()


def run(target: Target, fetch, evidence: str) -> CheckResult:
    """`fetch` returns the decoded answer of the backup list endpoint."""
    result = CheckResult(id="health_backups", title=TITLE, evidence=evidence)
    return judge(result, fetch(), target)
