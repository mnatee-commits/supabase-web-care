"""`webcare init`: write a target into webcare.toml from a few answers.

Every answer can be given as a flag, so an AI assistant can run it after asking
the owner; a person at a terminal is asked for whatever is missing. Nothing is
contacted and no key is asked for or stored.

The safe answer wins when in doubt: a target is taken to hold real data unless
the owner says it does not, so the owner-approval guard applies to it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Callable, Optional

from .model import Refusal
from .targets import DATA_KINDS, ENVIRONMENTS, load_targets

_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")
_REF = re.compile(r"^[a-z]{20}$")
_SCHEMA = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_YES = {"y", "yes", "ใช่", "มี", "จริง"}
_NO = {"n", "no", "ไม่", "ไม่มี", "ไม่ใช่"}


def _ask(prompt: str, ask: Callable[[str], str], check, default: Optional[str] = None) -> str:
    for _ in range(3):
        suffix = f" [{default}]" if default is not None else ""
        answer = ask(f"{prompt}{suffix}: ").strip() or (default or "")
        error = check(answer)
        if error is None:
            return answer
        print(f"  {error}", file=sys.stderr)
    raise Refusal(f"no usable answer for: {prompt}")


def _name_error(value: str):
    return None if _NAME.match(value) else "lower-case letters, digits, - and _ only, starting with a letter"


def _ref_error(value: str):
    return None if not value or _REF.match(value) else "20 lower-case letters (from the project's URL), or empty"


def _env_error(value: str):
    return None if value.lower() in ENVIRONMENTS else f"one of {', '.join(ENVIRONMENTS)}"


def _real_error(value: str):
    return None if value.lower() in _YES | _NO else "yes or no"


def build_entry(name: str, env: str, real: bool, project_ref: str = "", schemas=("public",),
                lang: str = "en") -> str:
    """The TOML text of one target, with comments that say what each line means."""
    if _name_error(name) or _env_error(env) or _ref_error(project_ref):
        raise Refusal("the answers do not make a valid target; see `webcare init --help`")
    for schema in schemas:
        if not _SCHEMA.match(schema):
            raise Refusal(f"schema {schema!r} is not a plain lower-case identifier")
    data = "real" if real else "synthetic"
    lines = [
        "",
        "[[target]]",
        f'name = "{name}"',
        f'env = "{env}"            # local, staging or production',
        f'data = "{data}"' + ("          # real data: live checks need --owner-approved"
                              if real else "     # no real person's data in this database"),
    ]
    if project_ref:
        lines.append(f'project_ref = "{project_ref}"   # for --via-api')
    if list(schemas) != ["public"]:
        lines.append("schemas = [" + ", ".join(f'"{s}"' for s in schemas) + "]")
    lines.append(f'lang = "{lang}"')
    lines += [
        "# After the first run, declare what is meant to be open, so the next runs report only surprises:",
        "# expected_anon_functions = []",
        "# expected_table_writes = { anon = [], authenticated = [] }",
        "# expected_cron_jobs = []",
    ]
    return "\n".join(lines) + "\n"


def next_steps(name: str, project_ref: str, real: bool, lang: str = "en", env: str = "") -> str:
    approval = " --owner-approved" if real else ""
    local = env == "local" and not project_ref
    if lang == "th":
        text = [
            "ขั้นต่อไป",
            "1. ตรวจจากไฟล์ก่อน (ไม่ต้องใช้ key): python -m webcare check --migrations supabase/migrations",
        ]
        if project_ref:
            text += [
                "2. ตรวจฐานผ่าน API: สร้าง access token ที่หน้า Supabase > Account > Access Tokens",
                "   เลือกเฉพาะโปรเจกต์นี้ สิทธิ์ Database Read อย่างเดียว อายุสั้นที่สุด แล้วใส่ในตัวแปร WEBCARE_ACCESS_TOKEN",
                f"   python -m webcare check --target {name} --via-api --profile full{approval}",
                "   เพิกถอน token ทันทีเมื่อตรวจเสร็จ",
            ]
        if local:
            text += [
                "2. ตรวจฐานในเครื่อง: ใส่ connection string ของ role ตรวจแบบอ่านอย่างเดียวในตัวแปร WEBCARE_DATABASE_URL",
                "   (ดูวิธีสร้าง role ใน sql/auditor-role.sql)",
                f"   python -m webcare check --target {name}{approval}",
            ]
        if real:
            text.append("เป้าหมายนี้เก็บข้อมูลจริง ใส่ --owner-approved ได้ก็ต่อเมื่อเจ้าของอนุญาตด้วยคำพูดของตัวเองแล้วเท่านั้น")
        return "\n".join(text)
    text = [
        "Next steps",
        "1. Check files first (no key needed): python -m webcare check --migrations supabase/migrations",
    ]
    if project_ref:
        text += [
            "2. Check the database through the API: create an access token in Supabase > Account > Access Tokens,",
            "   limited to this project, with Database Read only and the shortest expiry; put it in WEBCARE_ACCESS_TOKEN.",
            f"   python -m webcare check --target {name} --via-api --profile full{approval}",
            "   Delete the token as soon as the check is done.",
        ]
    if local:
        text += [
            "2. Check the local database: put the connection string of a read-only audit role in",
            "   WEBCARE_DATABASE_URL (sql/auditor-role.sql shows how to make one).",
            f"   python -m webcare check --target {name}{approval}",
        ]
    if real:
        text.append("This target holds real data: pass --owner-approved only after the owner has said yes in their own words.")
    return "\n".join(text)


def run(path: Path, name: Optional[str], env: Optional[str], real: Optional[str], project_ref: Optional[str],
        schemas: Optional[list[str]], lang: str, interactive: bool,
        ask: Callable[[str], str] = input) -> str:
    """Append a target to `path` and return what to tell the user."""
    def need(value, prompt, check, default=None):
        if value is not None:
            error = check(value)
            if error:
                raise Refusal(f"{prompt}: {error}")
            return value
        if not interactive:
            if default is not None:
                return default
            raise Refusal(f"{prompt} is needed; give it as a flag (see `webcare init --help`)")
        return _ask(prompt, ask, check, default)

    name = need(name, "Target name (e.g. staging)", _name_error, None)
    env = need(env, "Environment: local, staging or production", _env_error, "production").lower()
    # Real data unless the owner says otherwise: the guard applies when in doubt.
    real_answer = need(real, "Does this database hold real people's data? (yes/no)", _real_error, "yes")
    holds_real = real_answer.lower() not in _NO
    if env == "local" and project_ref is None:
        project_ref = ""  # a local stack (supabase start) has no project reference
    project_ref = need(project_ref, "Project reference (20 letters in the project's URL; empty to skip)", _ref_error, "")
    schemas = schemas or ["public"]

    before = ""
    if path.exists():
        if name in load_targets(path):
            raise Refusal(f"{path} already declares a target named {name!r}; choose another name")
        before = path.read_text(encoding="utf-8")
    else:
        before = "# Targets for supabase-web-care. Holds no key or password.\n"
    entry = build_entry(name, env, holds_real, project_ref, schemas, lang)
    # Check that the whole file still loads before replacing it: a broken file is worse than none.
    trial = path.with_name(f".{path.name}.new")
    trial.write_text(before + entry, encoding="utf-8")
    try:
        load_targets(trial)
    except BaseException:  # a refusal, Ctrl-C or a disk error: leave no half-made file behind
        trial.unlink(missing_ok=True)
        raise
    trial.replace(path)
    return f"wrote target {name!r} to {path}\n\n" + next_steps(name, project_ref, holds_real, lang, env)
