"""SARIF 2.1.0 output, so code-scanning tools can show findings on file lines.

Only findings that can be tied to a file are written: credentials (file and
line), function privileges replayed from SQL files (file and line), and pgrls
findings from SQL files, which name a table, view, function or policy and are
placed on the first statement in the given files that creates it. That last placement is
a text search, not a parse; a finding whose object no file creates is left out.
Findings from a live database have no file and stay in report.md only. The run
records how many findings were left out, so a clean SARIF file is never read as
a clean report.

Paths are written relative to the current directory; run from the repository
root, as CI does. A finding in a file outside the current directory, or in one of
two given SQL files that share a name, is left out rather than placed on the wrong
file.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Iterable, Optional, Sequence

from . import __version__
from .model import CheckResult

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/mnatee-commits/supabase-web-care"
LEVELS = {"high": "error", "medium": "warning", "low": "note"}
FILE_CHECKS = ("secrets", "rls_static", "functions_static")

_IN_BRACKETS = re.compile(r"\((.+):(\d+)\)\s*$")  # "public.f (dir/(group)/0001.sql:12)"
_PLAIN = re.compile(r"^(.+):(\d+)$")  # "src/app/(dashboard)/actions.ts:15"
_OBJECT = re.compile(r"^([a-z_][a-z0-9_$]*)\.([a-z_][a-z0-9_$]*)$", re.IGNORECASE)
_POLICY = re.compile(r"^([a-z_][a-z0-9_$]*)\.([a-z_][a-z0-9_$]*)\.(.+)$", re.IGNORECASE)
# Strings are kept so that a comment marker inside one is not taken for a comment.
_STRING_OR_COMMENT = re.compile(r"'(?:[^']|'')*'|--[^\n]*|/\*.*?\*/", re.DOTALL)


def _relative(path: Path) -> Optional[str]:
    """Path from the current directory in POSIX form, or None when it lies outside it."""
    try:
        text = os.path.relpath(path.resolve(), Path.cwd().resolve())
    except ValueError:  # another drive on Windows
        return None
    text = Path(text).as_posix()
    return None if text == ".." or text.startswith("../") else text


def _without_comments(text: str) -> str:
    """The text with comments blanked out, keeping every offset and line break."""
    def blank(match: re.Match) -> str:
        found = match.group(0)
        if found.startswith("'"):
            return found
        return "".join(ch if ch == "\n" else " " for ch in found)

    return _STRING_OR_COMMENT.sub(blank, text)


class Locator:
    """Turns a finding's location text into (file, line), or None."""

    def __init__(self, roots: Sequence[Path], sql_files: Sequence[Path]):
        from .secret_scan import root_labels

        self.roots = list(roots)
        self.labels = root_labels(self.roots) if self.roots else []
        self.sql_files = list(sql_files)
        self._by_name: dict[str, list[Path]] = {}
        for path in self.sql_files:
            self._by_name.setdefault(path.name, []).append(path)
        self._texts: Optional[list[tuple[Path, str]]] = None

    def _file(self, name: str, check_id: str) -> Optional[Path]:
        if check_id == "secrets":
            for root, label in zip(self.roots, self.labels):
                if name.startswith(label) and (root / name[len(label):]).is_file():
                    return root / name[len(label):]
            return None
        paths = self._by_name.get(Path(name).name, [])
        # Two given files with the same name: the finding cannot say which, so leave it out.
        return paths[0] if len(paths) == 1 else None

    def _first_match(self, pattern: "re.Pattern[str]") -> Optional[tuple[Path, int]]:
        if self._texts is None:
            self._texts = []
            for path in self.sql_files:
                try:
                    raw = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                self._texts.append((path, _without_comments(raw)))
        for path, text in self._texts:
            match = pattern.search(text)
            if match:
                return path, text.count("\n", 0, match.start()) + 1
        return None

    @staticmethod
    def _qualified(schema: str, name: str) -> str:
        return rf'(?:"?{re.escape(schema)}"?\s*\.\s*)?"?{re.escape(name)}"?(?![\w$])'

    def _created_at(self, schema: str, name: str) -> Optional[tuple[Path, int]]:
        return self._first_match(re.compile(
            r"\bcreate\s+(?:or\s+replace\s+)?(?:(?:unlogged|materialized|foreign|recursive|temp|temporary)\s+)*"
            r"(?:table|view|function|procedure)\s+(?:if\s+not\s+exists\s+)?" + self._qualified(schema, name),
            re.IGNORECASE,
        ))

    def _policy_at(self, schema: str, table: str, policy: str) -> Optional[tuple[Path, int]]:
        return self._first_match(re.compile(
            r'\bcreate\s+policy\s+"?' + re.escape(policy) + r'"?\s+on\s+' + self._qualified(schema, table),
            re.IGNORECASE,
        ))

    def locate(self, check_id: str, location: str) -> Optional[tuple[str, int]]:
        text = location.strip()
        if check_id == "secrets":
            match = _PLAIN.match(text)
        elif check_id == "functions_static":
            match = _IN_BRACKETS.search(text)
        else:
            match = None
        if match:
            path = self._file(match.group(1), check_id)
            relative = _relative(path) if path else None
            return (relative, int(match.group(2))) if relative else None
        if check_id == "rls_static":
            obj, pol = _OBJECT.match(text), _POLICY.match(text)
            found = None
            if obj:
                found = self._created_at(obj.group(1), obj.group(2))
            elif pol:
                found = self._policy_at(pol.group(1), pol.group(2), pol.group(3))
            if found:
                relative = _relative(found[0])
                return (relative, found[1]) if relative else None
        return None


def build(checks: Iterable[CheckResult], roots: Sequence[Path], sql_files: Sequence[Path]) -> dict:
    locator = Locator(roots, sql_files)
    rules: dict[str, dict] = {}
    results = []
    left_out = 0
    for check in checks:
        for finding in check.findings:
            level = LEVELS.get(finding.severity)
            if level is None:  # info is an observation, not a problem
                continue
            place = locator.locate(check.id, finding.location) if check.id in FILE_CHECKS else None
            if place is None:
                left_out += 1
                continue
            rule_id = f"{finding.source}/{finding.rule}"
            rules.setdefault(rule_id, {
                "id": rule_id,
                "name": finding.rule,
                "shortDescription": {"text": f"{finding.rule} ({finding.source})"},
                "defaultConfiguration": {"level": level},
                "helpUri": INFORMATION_URI,
            })
            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{finding.message} [{finding.location}]"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": place[0], "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": max(1, place[1])},
                    }
                }],
                # Stable across edits that move the line, so code scanning does not open a new alert.
                "partialFingerprints": {"webcareFinding/v1": hashlib.sha256(
                    f"{check.id}|{finding.rule}|{finding.location}".encode("utf-8")).hexdigest()[:32]},
                "properties": {"severity": finding.severity, "check": check.id},
            })
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "supabase-web-care",
                "version": __version__,
                "informationUri": INFORMATION_URI,
                "rules": sorted(rules.values(), key=lambda rule: rule["id"]),
            }},
            "results": results,
            "properties": {
                "findings_without_a_file_line": left_out,
                "note": "findings with no file line, and every check that did not run, are in "
                        "report.md and report.json only",
            },
        }],
    }


def write(path: Path, checks: Iterable[CheckResult], roots: Sequence[Path], sql_files: Sequence[Path]) -> int:
    data = build(checks, roots, sql_files)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return len(data["runs"][0]["results"])
