"""Focused runs: check one area, or use a named set, instead of everything.

A focused run still lists every check. The ones left out are NOT_RUN with the
reason, so a focused report is never read as a whole one, and they do not make
the exit code 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .model import NOT_RUN, CheckResult


@dataclass(frozen=True)
class Area:
    checks: frozenset[str]  # report rows that belong to the area
    catalog: frozenset[str] = field(default_factory=frozenset)  # catalog checks inside extra_live
    optional: tuple[str, ...] = ()  # --with-* flags the area switches on for --via-api


AREAS: dict[str, Area] = {
    "secrets": Area(frozenset({"secrets"})),
    "functions": Area(
        frozenset({"functions_static", "functions_live", "extra_live"}),
        frozenset({"secdef_trusts_current_user", "default_function_privileges",
                   "default_function_privileges_platform"}),
    ),
    "tables": Area(
        frozenset({"rls_static", "rls_live", "table_writes", "extra_live", "anon_probe", "data_api"}),
        frozenset({"update_without_select", "auth_role_deprecated", "default_table_privileges",
                   "view_runs_as_owner", "schema_usable_but_unchecked", "matview_readable_by_api_roles"}),
        optional=("with_data_api",),
    ),
    "storage": Area(
        frozenset({"storage_live", "storage_buckets", "extra_live"}),
        frozenset({"storage_upsert_incomplete"}),
    ),
    "extensions": Area(
        frozenset({"extra_live"}),
        frozenset({"extension_net_callable", "extension_vault_reachable", "extension_cron_reachable"}),
    ),
    "realtime": Area(
        frozenset({"extra_live"}),
        frozenset({"realtime_table_without_rls", "realtime_messages_open",
                   "realtime_messages_open_to_signed_in"}),
    ),
    "edge": Area(frozenset({"edge_functions"})),
    "parity": Area(frozenset({"parity"})),
    "platform": Area(frozenset({"platform"}), optional=("with_platform",)),
    "auth": Area(frozenset({"auth_config"}), optional=("with_auth_config",)),
    "advisors": Area(frozenset({"advisors"}), optional=("with_advisors",)),
    "health": Area(
        frozenset({"health_cron", "health_backups", "health_logs", "db_health", "advisors_performance"}),
        optional=("with_backups", "with_logs", "with_performance"),
    ),
}
PROFILES = ("quick", "full")
# Wider names for sets of areas. Health findings say how the database is running;
# everything else is about who may reach what.
GROUPS: dict[str, tuple[str, ...]] = {
    "security": tuple(name for name in AREAS if name not in ("health", "parity")),
    "health": ("health",),
    # Changes since a saved inventory ask "was this intended?"; they are not faults by
    # themselves, so they neither fail a security gate nor ride along with it.
    "parity": ("parity",),
}
# Optional --via-api checks, by report row, for --only.
OPTIONAL_BY_CHECK = {
    "advisors": "with_advisors", "auth_config": "with_auth_config",
    "health_backups": "with_backups", "health_logs": "with_logs",
    "advisors_performance": "with_performance", "data_api": "with_data_api", "platform": "with_platform",
}


def group_of(check_id: str) -> str:
    """The group a report row belongs to, for --fail-groups."""
    if check_id in AREAS["health"].checks:
        return "health"
    if check_id in AREAS["parity"].checks:
        return "parity"
    return "security"


def catalog_ids() -> set[str]:
    return set().union(*(area.catalog for area in AREAS.values()))
ALL_OPTIONAL = ("with_advisors", "with_auth_config", "with_backups", "with_logs", "with_performance",
                "with_data_api", "with_platform")
STATIC = ("rls_static", "functions_static", "edge_functions")
LIVE = ("rls_live", "storage_live", "extra_live", "functions_live", "storage_buckets",
        "table_writes", "health_cron", "advisors", "auth_config", "health_backups", "health_logs",
        "db_health", "advisors_performance", "data_api", "parity", "platform")


def _split(values: Iterable[str]) -> list[str]:
    names = []
    for value in values:
        names += [part.strip() for part in value.split(",") if part.strip()]
    return names


def parse_groups(values: Iterable[str]) -> tuple[str, ...]:
    """Areas named by --group values."""
    names = _split(values)
    unknown = sorted(set(names) - set(GROUPS))
    if unknown:
        raise ValueError(f"unknown --group {', '.join(unknown)}; the groups are {', '.join(GROUPS)}")
    return tuple(area for area in AREAS if any(area in GROUPS[name] for name in names))


def parse_only(values: Iterable[str], report_ids: Iterable[str]) -> frozenset[str]:
    """Check names for --only: report rows, or single catalog checks."""
    names = set(_split(values))
    known = set(report_ids) | catalog_ids()
    unknown = sorted(names - known)
    if unknown:
        raise ValueError(
            f"unknown --only check {', '.join(unknown)}; use a report row such as table_writes "
            "or a catalog check such as extension_net_callable"
        )
    return frozenset(names)


def parse(values: Iterable[str]) -> tuple[str, ...]:
    """Areas from repeated or comma-separated --focus values, in a stable order."""
    names = _split(values)
    unknown = sorted(set(names) - set(AREAS))
    if unknown:
        raise ValueError(f"unknown --focus area {', '.join(unknown)}; the areas are {', '.join(AREAS)}")
    return tuple(name for name in AREAS if name in names)


@dataclass
class Plan:
    areas: tuple[str, ...] = ()
    profile: Optional[str] = None
    only: frozenset[str] = frozenset()

    @property
    def active(self) -> bool:
        return bool(self.areas) or self.profile is not None or bool(self.only)

    def allowed(self) -> Optional[set[str]]:
        if self.only:
            rows = set(self.only) - catalog_ids()
            return rows | ({"extra_live"} if self.only & catalog_ids() else set())
        if not self.areas:
            return None
        return set().union(*(AREAS[name].checks for name in self.areas))

    def catalog(self) -> Optional[set[str]]:
        """Catalog checks to keep inside extra_live, or None for all of them."""
        if self.only:
            return None if "extra_live" in self.only else set(self.only) & catalog_ids()
        if not self.areas:
            return None
        return set().union(*(AREAS[name].catalog for name in self.areas))

    def describe(self, lang: str = "en") -> str:
        parts = []
        if self.profile == "quick":
            parts.append("ชุด quick: ตรวจจากไฟล์เท่านั้น" if lang == "th" else "profile quick: files only")
        elif self.profile == "full":
            parts.append("ชุด full: เปิดการตรวจเสริมทั้งหมด" if lang == "th" else "profile full: every optional check on")
        if self.areas:
            parts.append(("เฉพาะด้าน " if lang == "th" else "focus: ") + ", ".join(self.areas))
        if self.only:
            parts.append(("เฉพาะการตรวจ " if lang == "th" else "only: ") + ", ".join(sorted(self.only)))
        return "; ".join(parts)

    def prepare(self, args, skip: set[str]) -> None:
        """Turn the plan into skips and --with-* switches before anything runs."""
        if self.profile == "quick":
            skip.update({"live", "probe"})
        if self.profile == "full":
            for flag in ALL_OPTIONAL:
                setattr(args, flag, True)
        allowed = self.allowed()
        if allowed is None:
            return
        if "secrets" not in allowed:
            skip.add("secrets")
        if not allowed & set(STATIC):
            skip.add("static")
        if "anon_probe" not in allowed:
            skip.add("probe")
        if not allowed & set(LIVE):
            skip.add("live")
        wanted = {flag for name in self.areas for flag in AREAS[name].optional}
        wanted |= {flag for check_id, flag in OPTIONAL_BY_CHECK.items() if check_id in self.only}
        for flag in ALL_OPTIONAL:
            # An optional check outside the focus is not asked for, even if the target file or
            # a flag switched it on; one inside it is switched on.
            setattr(args, flag, flag in wanted)

    def apply(self, checks: list[CheckResult], requested: set[str], lang: str = "en",
              titles: Optional[dict[str, str]] = None) -> list[CheckResult]:
        """Mark what the plan leaves out, and keep only the catalog checks it covers.

        Every check in `titles` gets a row, so a focused report shows what it did not do.
        """
        allowed, catalog = self.allowed(), self.catalog()
        if allowed is None:
            return checks
        out = []
        reason = ("ไม่อยู่ในขอบเขตที่เลือก" if lang == "th" else "left out by") + f" {self.describe(lang)}"
        present = {check.id for check in checks}
        checks = checks + [CheckResult(id=check_id, title=title, status=NOT_RUN, reason=reason)
                           for check_id, title in (titles or {}).items()
                           if check_id not in present and check_id not in allowed]
        for check in checks:
            if check.id not in allowed:
                requested.discard(check.id)
                out.append(CheckResult(id=check.id, title=check.title, status=NOT_RUN, reason=reason))
                continue
            if check.id == "extra_live" and catalog is not None:
                kept = [finding for finding in check.findings if finding.rule in catalog]
                left = len(check.findings) - len(kept)
                check.findings = kept
                check.notes.append(
                    "only these catalog checks were judged: " + ", ".join(sorted(catalog))
                    + (f" ({left} findings of other catalog checks left out)" if left else "")
                )
                if check.status not in ("ERROR", NOT_RUN):
                    check.finish()
            out.append(check)
        if titles:
            order = {check_id: index for index, check_id in enumerate(titles)}
            out.sort(key=lambda check: -1 if check.id == "secrets" else order.get(check.id, len(order)))
        return out
