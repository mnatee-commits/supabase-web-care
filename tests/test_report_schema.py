"""report.json against schema/report.schema.json, with a small validator for the subset
of JSON Schema the file uses, so no extra dependency is needed."""

import json
import re

from conftest import FIXTURES, ROOT
from webcare.cli import main

SCHEMA = json.loads((ROOT / "schema" / "report.schema.json").read_text())
TYPES = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "null": type(None)}


def problems(value, schema, path="$"):
    found = []
    if "const" in schema and value != schema["const"]:
        found.append(f"{path}: {value!r} is not {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        found.append(f"{path}: {value!r} not in {schema['enum']}")
    kinds = schema.get("type")
    if kinds:
        kinds = kinds if isinstance(kinds, list) else [kinds]
        if not any(isinstance(value, TYPES[k]) and not (k == "integer" and isinstance(value, bool)) for k in kinds):
            return found + [f"{path}: {type(value).__name__} is not {kinds}"]
    if "pattern" in schema and isinstance(value, str) and not re.search(schema["pattern"], value):
        found.append(f"{path}: {value!r} does not match {schema['pattern']}")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                found.append(f"{path}: missing {key}")
        for key, sub in schema.get("properties", {}).items():
            if key in value:
                found += problems(value[key], sub, f"{path}.{key}")
    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            found += problems(item, schema["items"], f"{path}[{index}]")
    return found


def test_reports_match_the_published_schema(tmp_path):
    for lang in ("en", "th"):
        out = tmp_path / lang
        main(["check", "--repo", str(FIXTURES), "--sql-file", str(FIXTURES / "vulnerable.sql"),
              "--lang", lang, "--out-dir", str(out)])
        report = json.loads((out / "report.json").read_text())
        assert problems(report, SCHEMA) == []
        assert report["schema_version"].startswith("1.")


def test_the_validator_catches_a_broken_report():
    broken = {"tool": "supabase-web-care", "checks": [{"id": "x", "status": "MAYBE"}]}
    found = problems(broken, SCHEMA)
    assert any("missing schema_version" in p for p in found)
    assert any("'MAYBE' not in" in p for p in found)
