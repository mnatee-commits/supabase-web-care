"""Turn check results into a JSON record and a Markdown report, in English or Thai.

The report states, for every check, what was examined and where. A check that
did not run stays visible as NOT_RUN with its reason.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from . import __version__
from .explain_th import explain
from .manual import MANUAL_ITEMS
from .model import ERROR, FINDINGS, NOT_RUN, PASS, SEVERITIES, CheckResult, severity_at_least

TITLES_TH = {
    "secrets": "key และรหัสผ่านที่ค้างอยู่ในไฟล์",
    "rls_static": "นโยบาย RLS จากไฟล์ SQL (pgrls แบบออฟไลน์)",
    "functions_static": "ฟังก์ชัน SECURITY DEFINER จากไฟล์ SQL (ใครเรียกได้, search_path)",
    "rls_live": "นโยบาย RLS จากฐานข้อมูล (pgrls)",
    "storage_live": "นโยบายของ Storage (pgrls)",
    "extra_live": "การตรวจเพิ่มจาก catalog",
    "functions_live": "ฟังก์ชัน SECURITY DEFINER ที่ผู้ไม่ล็อกอินเรียกได้",
    "storage_buckets": "bucket ของ Storage: เปิดสาธารณะหรือไม่ และใครอัปโหลดได้",
    "table_writes": "ตารางที่ role ของ API เขียนได้",
    "advisors": "ผลตรวจความปลอดภัยของ Supabase เอง (Security Advisor)",
    "advisors_performance": "ผลตรวจประสิทธิภาพของ Supabase เอง (Performance Advisor)",
    "data_api": "การตั้งค่า Data API: schema ที่เปิดให้เรียก",
    "platform": "การตั้งค่าแพลตฟอร์ม: บังคับ SSL และจำกัด IP ที่ต่อฐานได้",
    "parity": "เทียบกับรายการที่บันทึกไว้: อะไรเปลี่ยนไปตั้งแต่ครั้งก่อน",
    "db_health": "สุขภาพฐาน: index เสีย ตารางบวม อายุธุรกรรม เซสชันค้าง sequence ใกล้เต็ม",
    "auth_config": "การตั้งค่าการล็อกอิน (Supabase Auth)",
    "health_cron": "งานตั้งเวลา (pg_cron) ที่ล้มหรือหยุดรัน",
    "health_backups": "backup ของฐานข้อมูลที่ Supabase เก็บไว้",
    "health_logs": "สรุป log ของ API ย้อนหลัง 24 ชั่วโมง (เฉพาะยอดรวม)",
    "anon_probe": "สิ่งที่ผู้ใช้ที่ไม่ล็อกอินอ่านได้",
}
STATUS_TH = {
    PASS: "PASS (ตรวจแล้วไม่พบ)",
    FINDINGS: "FINDINGS (พบปัญหา)",
    NOT_RUN: "NOT_RUN (ยังไม่ได้ตรวจ)",
    ERROR: "ERROR (ตรวจไม่สำเร็จ)",
}
SEVERITY_TH = {"high": "สูง", "medium": "กลาง", "low": "ต่ำ", "info": "ข้อมูล"}
LANGUAGES = ("en", "th")
DEFAULT_LANGUAGE = "en"
LANGUAGE_ENV = "WEBCARE_LANG"
STATUS_EN = {
    PASS: "PASS (checked, nothing found)",
    FINDINGS: "FINDINGS (problems found)",
    NOT_RUN: "NOT_RUN (not checked yet)",
    ERROR: "ERROR (the check did not complete)",
}
SEVERITY_EN = {"high": "high", "medium": "medium", "low": "low", "info": "info"}
TEXT = {
    "th": {
        "heading": "# รายงาน Supabase Web Care",
        "generated": "สร้างเมื่อ", "tool": "เครื่องมือ", "source": "ซอร์สที่ตรวจ", "target": "เป้าหมายที่เชื่อมต่อ",
        "scope": "ขอบเขต (ตรวจเพียงบางส่วน)",
        "summary": "## สรุป",
        "summary_head": "| การตรวจ | สถานะ | สูง | กลาง | ต่ำ | ข้อมูล |",
        "legend": "PASS = ตรวจแล้วไม่พบ, FINDINGS = พบปัญหา, NOT_RUN = ยังไม่ได้ตรวจ, "
        "ERROR = ตรวจไม่สำเร็จ การตรวจที่เป็น NOT_RUN หรือ ERROR ยังสรุปไม่ได้ว่าปลอดภัย "
        "คอลัมน์ \"ข้อมูล\" คือข้อสังเกตที่ไม่นับเป็นปัญหา",
        "each": "## ผลแต่ละการตรวจ",
        "status": "สถานะ", "evidence": "หลักฐาน", "reason": "เหตุผล", "note": "หมายเหตุ",
        "findings_head": "| ระดับ | กฎ | ตำแหน่ง | ความหมายและวิธีแก้ | รายละเอียด (อังกฤษ) |",
        "truncated": "แสดง {shown} จาก {total} รายการ รายการทั้งหมดอยู่ในไฟล์ report.json",
        "manual": "## รายการที่ต้องตรวจด้วยมือ (NOT_RUN ทุกข้อ)",
        "manual_intro": "สคริปต์ตรวจข้อเหล่านี้ไม่ได้ ต้องให้คนหรือ agent ที่มีสิทธิ์เข้าถึงตรวจแยก",
    },
    "en": {
        "heading": "# Supabase Web Care report",
        "generated": "Generated", "tool": "Tool", "source": "Source examined", "target": "Live target",
        "scope": "Scope (only part of the checks ran)",
        "summary": "## Summary",
        "summary_head": "| Check | Status | High | Medium | Low | Info |",
        "legend": "PASS = checked, nothing found. FINDINGS = problems found. NOT_RUN = not checked "
        "yet. ERROR = the check did not complete. A check that is NOT_RUN or ERROR says nothing "
        "about safety. The Info column counts observations that are not problems.",
        "each": "## Each check",
        "status": "Status", "evidence": "Evidence", "reason": "Reason", "note": "Note",
        "findings_head": "| Severity | Rule | Location | Detail |",
        "truncated": "Showing {shown} of {total}. The full list is in report.json.",
        "manual": "## Items that need a manual check (all NOT_RUN)",
        "manual_intro": "No script here can settle these. A person, or an agent with the right "
        "access, has to check them separately.",
    },
}
MAX_ROWS_PER_CHECK = 100
MAX_MESSAGE_CHARS = 280


@dataclass
class Report:
    checks: list[CheckResult]
    source: str  # what was read from disk, with revision when known
    target: str  # the declared live target, or a statement that there is none
    requested: set[str] = field(default_factory=set)  # checks the caller asked for
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    lang: str = DEFAULT_LANGUAGE  # language of report.md and of the manual items
    scope: str = ""  # a focused run's areas or profile; empty for a whole run

    def counts(self, check: CheckResult) -> dict[str, int]:
        totals = {severity: 0 for severity in SEVERITIES}
        for finding in check.findings:
            totals[finding.severity] += 1
        return totals

    def exit_code(self, fail_on: str, groups: Optional[Iterable[str]] = None) -> int:
        """0 clean, 1 findings at or above the threshold, 2 a requested check failed.

        With `groups`, only checks in those groups count (`--fail-groups`); the others
        are still in the report.
        """
        from .focus import group_of

        counted = [check for check in self.checks if groups is None or group_of(check.id) in set(groups)]
        incomplete = any(
            check.status == ERROR or (check.status == NOT_RUN and check.id in self.requested)
            for check in counted
        )
        if incomplete:
            return 2
        if fail_on != "never" and any(
            severity_at_least(finding.severity, fail_on)
            for check in counted
            for finding in check.findings
        ):
            return 1
        return 0

    def to_dict(self) -> dict:
        return {
            "tool": "supabase-web-care",
            "version": __version__,
            "generated_at": self.generated_at,
            "language": self.lang,
            "source": self.source,
            "target": self.target,
            "scope": self.scope or None,
            "checks": [check.to_dict() for check in self.checks],
            "manual": [
                {"id": item.id, "status": NOT_RUN, "title": item.title(self.lang), "how": item.how(self.lang)}
                for item in MANUAL_ITEMS
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n"

    def to_markdown(self) -> str:
        text = TEXT[self.lang]
        status_names = STATUS_TH if self.lang == "th" else STATUS_EN
        severity_names = SEVERITY_TH if self.lang == "th" else SEVERITY_EN
        lines = [
            text["heading"],
            "",
            f"- {text['generated']}: {self.generated_at}",
            f"- {text['tool']}: supabase-web-care {__version__}",
            f"- {text['source']}: {self.source}",
            f"- {text['target']}: {self.target}",
            *([f"- {text['scope']}: {self.scope}"] if self.scope else []),
            "",
            text["summary"],
            "",
            text["summary_head"],
            "|---|---|---|---|---|---|",
        ]
        for check in self.checks:
            totals = self.counts(check)
            lines.append(
                f"| {_title(check, self.lang)} | {check.status} | {totals['high']} | "
                f"{totals['medium']} | {totals['low']} | {totals['info']} |"
            )
        lines += ["", text["legend"], "", text["each"]]
        for check in self.checks:
            lines += [
                "", f"### {_title(check, self.lang)}", "",
                f"- {text['status']}: {status_names[check.status]}",
            ]
            if check.evidence:
                lines.append(f"- {text['evidence']}: {check.evidence}")
            if check.reason:
                lines.append(f"- {text['reason']}: {check.reason}")
            for note in check.notes:
                lines.append(f"- {text['note']}: {note}")
            if check.findings:
                ordered = sorted(
                    check.findings, key=lambda f: (SEVERITIES.index(f.severity), f.rule, f.location)
                )
                thai = self.lang == "th"
                lines += ["", text["findings_head"], "|---|---|---|---|---|" if thai else "|---|---|---|---|"]
                for finding in ordered[:MAX_ROWS_PER_CHECK]:
                    meaning = f" {_cell(explain(finding) or '-')} |" if thai else ""
                    lines.append(
                        f"| {severity_names[finding.severity]} | {_cell(finding.rule)} | "
                        f"{_cell(finding.location)} |{meaning} {_cell(_shorten(finding.message))} |"
                    )
                if len(ordered) > MAX_ROWS_PER_CHECK:
                    lines += ["", text["truncated"].format(shown=MAX_ROWS_PER_CHECK, total=len(ordered))]
        lines += ["", text["manual"], "", text["manual_intro"], ""]
        for item in MANUAL_ITEMS:
            lines.append(f"- [ ] **{item.title(self.lang)}**: {item.how(self.lang)}")
        return "\n".join(lines) + "\n"

    def write(self, directory: Path) -> tuple[Path, Path]:
        directory.mkdir(parents=True, exist_ok=True)
        json_path = directory / "report.json"
        markdown_path = directory / "report.md"
        json_path.write_text(self.to_json(), encoding="utf-8")
        markdown_path.write_text(self.to_markdown(), encoding="utf-8")
        return json_path, markdown_path

    def console_summary(self) -> str:
        rows = []
        for check in self.checks:
            totals = self.counts(check)
            rows.append(
                f"  {check.status:<9} {check.id:<17} high={totals['high']} "
                f"medium={totals['medium']} low={totals['low']} info={totals['info']}"
                + (f"  ({check.reason})" if check.reason else "")
            )
        rows.append(f"  {NOT_RUN:<9} manual            {len(MANUAL_ITEMS)} items need a human or an agent")
        return "\n".join(rows)


def _title(check: CheckResult, lang: str = DEFAULT_LANGUAGE) -> str:
    return TITLES_TH.get(check.id, check.title) if lang == "th" else check.title


def _shorten(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_MESSAGE_CHARS else text[: MAX_MESSAGE_CHARS - 1] + "…"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")
