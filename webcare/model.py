"""Shared result types.

Every check returns a CheckResult. A check that could not run says so with
NOT_RUN and a reason, so a missing check is never mistaken for a clean one.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

PASS = "PASS"
FINDINGS = "FINDINGS"
NOT_RUN = "NOT_RUN"
ERROR = "ERROR"

SEVERITIES = ("high", "medium", "low", "info")
_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def severity_at_least(severity: str, threshold: str) -> bool:
    """True when `severity` is as serious as `threshold`, or more."""
    return _RANK[severity] <= _RANK[threshold]


@dataclass(frozen=True)
class Finding:
    source: str  # which tool produced it: "secret_scan", "pgrls", ...
    rule: str
    severity: str  # one of SEVERITIES
    location: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CheckResult:
    id: str
    title: str
    status: str = NOT_RUN
    evidence: str = ""  # what was examined, and where
    reason: str = ""  # why the check did not run, or failed
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def finish(self) -> "CheckResult":
        """Set PASS or FINDINGS from the findings collected so far.

        Informational findings (an inventory of where public keys live, for
        example) do not turn a check into FINDINGS.
        """
        actionable = [f for f in self.findings if f.severity != "info"]
        self.status = FINDINGS if actionable else PASS
        return self

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "evidence": self.evidence,
            "reason": self.reason,
            "findings": [f.to_dict() for f in self.findings],
            "notes": list(self.notes),
        }


class Refusal(Exception):
    """Raised when a guard rail stops a live action before it starts."""
