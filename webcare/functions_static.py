"""SECURITY DEFINER functions in migration files: who may call them.

pgrls cannot judge function privileges from SQL files, so this check replays
the CREATE FUNCTION, GRANT, REVOKE, ALTER FUNCTION and DROP FUNCTION statements
in the order the files are given and reports what a new function is left with.

Two mistakes it looks for are easy to make and hard to see in review:

* `REVOKE ... FROM anon` on its own. Every new function is executable by
  PUBLIC, and every role is a member of PUBLIC, so the function stays callable.
* `REVOKE ... FROM PUBLIC` followed by a GRANT to one role. On Supabase the
  schema's default privileges also grant EXECUTE to anon and authenticated
  directly, and that grant survives.

The check reads files only. It does not connect to anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

from .model import ERROR, CheckResult, Finding

SOURCE = "functions_static"
TITLE = "SECURITY DEFINER functions in SQL files (who may call them, search_path)"
PUBLIC = "PUBLIC"
DEFAULT_SCHEMA = "public"
# Schemas the Data API serves unless the project says otherwise. A function
# elsewhere cannot be reached by a visitor without USAGE on its schema, so the
# same mistake there is reported at low severity.
EXPOSED_SCHEMAS = ("public", "graphql_public")

_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)
_STRING = re.compile(r"'(?:[^']|'')*'")
_OWNER_IDENTITY = re.compile(r"\bcurrent_(user|role)\b", re.IGNORECASE)


def reads_owner_identity(body: str) -> bool:
    """True when code, not a comment or a string, reads current_user or current_role."""
    return bool(_OWNER_IDENTITY.search(_STRING.sub("''", _COMMENT.sub(" ", body))))


@dataclass
class FunctionState:
    schema: str
    name: str
    file: str
    line: int
    definer: bool = False
    pins_search_path: bool = False
    reads_owner_identity: bool = False
    public_may_execute: bool = True
    revoked_from: set[str] = field(default_factory=set)
    granted_to: set[str] = field(default_factory=set)

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"

    @property
    def location(self) -> str:
        return f"{self.qualified} ({self.file}:{self.line})"


def _split_name(parts: Sequence[str]) -> tuple[str, str]:
    if len(parts) >= 2:
        return parts[-2].lower(), parts[-1].lower()
    return DEFAULT_SCHEMA, parts[-1].lower()


def _string_values(nodes) -> list[str]:
    return [node.sval for node in nodes or () if hasattr(node, "sval")]


def _grantee_names(grantees, role_public) -> set[str]:
    names = set()
    for grantee in grantees or ():
        if grantee.roletype == role_public:
            names.add(PUBLIC)
        elif grantee.rolename:
            names.add(grantee.rolename.lower())
    return names


def _covers_execute(privileges) -> bool:
    """True for ALL (no list) or a list naming EXECUTE."""
    if not privileges:
        return True
    return any((privilege.priv_name or "all").lower() in ("execute", "all") for privilege in privileges)


class _Replay:
    """State of every function after the statements seen so far."""

    def __init__(self) -> None:
        self.functions: dict[tuple[str, str], FunctionState] = {}
        self.public_revoked_by_default = False
        self.notes: list[str] = []

    def in_schema(self, schema: str) -> Iterable[FunctionState]:
        return [state for state in self.functions.values() if state.schema == schema]

    def create(self, key: tuple[str, str], file: str, line: int, replace: bool) -> FunctionState:
        existing = self.functions.get(key)
        if existing is not None and replace:
            # CREATE OR REPLACE keeps the privileges of the function it replaces.
            existing.file, existing.line = file, line
            return existing
        state = FunctionState(schema=key[0], name=key[1], file=file, line=line)
        state.public_may_execute = not self.public_revoked_by_default
        self.functions[key] = state
        return state

    def apply_acl(self, state: FunctionState, grantees: set[str], is_grant: bool) -> None:
        if is_grant:
            state.granted_to |= grantees
            state.revoked_from -= grantees
            if PUBLIC in grantees:
                state.public_may_execute = True
        else:
            state.revoked_from |= grantees
            state.granted_to -= grantees
            if PUBLIC in grantees:
                state.public_may_execute = False


def _line_of(text: str, offset: int) -> int:
    """Line of a statement's first keyword.

    The parser reports where a statement starts, which is usually the blank
    space and comments that follow the previous statement.
    """
    position = offset
    while position < len(text):
        if text[position].isspace():
            position += 1
        elif text.startswith("--", position):
            end = text.find("\n", position)
            position = len(text) if end == -1 else end + 1
        elif text.startswith("/*", position):
            end = text.find("*/", position + 2)
            position = len(text) if end == -1 else end + 2
        else:
            break
    return text.count("\n", 0, position) + 1


def _apply_file(replay: _Replay, path: Path, text: str) -> None:
    from pglast import ast, enums, parse_sql

    function_kinds = {
        enums.ObjectType.OBJECT_FUNCTION,
        enums.ObjectType.OBJECT_PROCEDURE,
        enums.ObjectType.OBJECT_ROUTINE,
    }
    role_public = enums.RoleSpecType.ROLESPEC_PUBLIC
    for raw in parse_sql(text):
        statement = raw.stmt
        line = _line_of(text, raw.stmt_location or 0)

        if isinstance(statement, ast.CreateFunctionStmt):
            key = _split_name(_string_values(statement.funcname))
            state = replay.create(key, path.name, line, bool(statement.replace))
            state.definer = False
            state.pins_search_path = False
            state.reads_owner_identity = False
            for option in statement.options or ():
                if option.defname == "security":
                    state.definer = bool(getattr(option.arg, "boolval", False))
                elif option.defname == "set" and getattr(option.arg, "name", "") == "search_path":
                    state.pins_search_path = True
                elif option.defname == "as" and isinstance(option.arg, tuple):
                    state.reads_owner_identity = reads_owner_identity(
                        "\n".join(_string_values(option.arg))
                    )

        elif isinstance(statement, ast.AlterFunctionStmt):
            key = _split_name(_string_values(statement.func.objname))
            state = replay.functions.get(key)
            if state is None:
                continue
            for action in statement.actions or ():
                if action.defname == "security":
                    state.definer = bool(getattr(action.arg, "boolval", False))
                elif action.defname == "set":
                    kind = getattr(action.arg, "kind", None)
                    name = getattr(action.arg, "name", "") or ""
                    if kind == enums.VariableSetKind.VAR_RESET_ALL:
                        state.pins_search_path = False
                    elif name == "search_path":
                        state.pins_search_path = kind != enums.VariableSetKind.VAR_RESET

        elif isinstance(statement, ast.GrantStmt) and statement.objtype in function_kinds:
            if not _covers_execute(statement.privileges):
                continue
            grantees = _grantee_names(statement.grantees, role_public)
            if statement.targtype == enums.GrantTargetType.ACL_TARGET_ALL_IN_SCHEMA:
                for schema in _string_values(statement.objects):
                    for state in replay.in_schema(schema.lower()):
                        replay.apply_acl(state, grantees, bool(statement.is_grant))
            elif statement.targtype == enums.GrantTargetType.ACL_TARGET_OBJECT:
                for target in statement.objects or ():
                    key = _split_name(_string_values(getattr(target, "objname", ())))
                    state = replay.functions.get(key)
                    if state is not None:
                        replay.apply_acl(state, grantees, bool(statement.is_grant))

        elif isinstance(statement, ast.AlterDefaultPrivilegesStmt):
            action = statement.action
            if action.objtype not in function_kinds or not _covers_execute(action.privileges):
                continue
            scoped_to_schema = any(option.defname == "schemas" for option in statement.options or ())
            if PUBLIC in _grantee_names(action.grantees, role_public) and not scoped_to_schema:
                # Only the global default can remove PUBLIC; a per-schema
                # default adds privileges and cannot take the built-in one away.
                replay.public_revoked_by_default = not action.is_grant
                replay.notes.append(
                    f"{path.name}:{line} changes the default privileges for new functions; "
                    "functions created after it are treated accordingly, which holds only "
                    "when the migrations run as the role that statement names"
                )

        elif isinstance(statement, ast.DropStmt) and statement.removeType in function_kinds:
            for target in statement.objects or ():
                replay.functions.pop(_split_name(_string_values(getattr(target, "objname", ()))), None)

        elif isinstance(statement, ast.DoStmt):
            replay.notes.append(
                f"{path.name}:{line} runs a DO block; functions or grants made inside it are not seen"
            )


def _findings(replay: _Replay) -> list[Finding]:
    findings: list[Finding] = []
    for state in sorted(replay.functions.values(), key=lambda s: (s.schema, s.name)):
        if not state.definer:
            continue
        exposed = state.schema in EXPOSED_SCHEMAS
        if state.public_may_execute:
            hint = (
                " A REVOKE from "
                + ", ".join(sorted(state.revoked_from))
                + " does not close it, because every role is a member of PUBLIC."
                if state.revoked_from
                else ""
            )
            findings.append(
                Finding(
                    source=SOURCE,
                    rule="secdef_public_execute",
                    severity="high" if exposed else "low",
                    location=state.location,
                    message=(
                        "SECURITY DEFINER function is left executable by PUBLIC"
                        + (
                            ", so anyone who can reach the API can call it."
                            if exposed
                            else f". Schema {state.schema} is assumed not to be served by the "
                            "API, which is all that keeps visitors out."
                        )
                        + hint
                        + " Add REVOKE ALL ON FUNCTION ... FROM PUBLIC, anon and grant only "
                        "the roles that need it."
                    ),
                )
            )
        elif "anon" in state.granted_to:
            findings.append(
                Finding(
                    source=SOURCE,
                    rule="secdef_anon_granted",
                    severity="info",
                    location=state.location,
                    message=(
                        "SECURITY DEFINER function is granted to anon on purpose. Its body is "
                        "the only access control; confirm it checks the caller or returns "
                        "nothing private."
                    ),
                )
            )
        elif exposed and "anon" not in state.revoked_from:
            findings.append(
                Finding(
                    source=SOURCE,
                    rule="secdef_anon_not_revoked",
                    severity="medium",
                    location=state.location,
                    message=(
                        "PUBLIC is revoked but anon is not. On Supabase the schema's default "
                        "privileges grant EXECUTE to anon and authenticated directly, and that "
                        "grant survives a REVOKE from PUBLIC. Revoke from anon as well, or "
                        "grant to anon explicitly if the function is meant to be public."
                    ),
                )
            )
        if state.reads_owner_identity:
            findings.append(
                Finding(
                    source=SOURCE,
                    rule="secdef_trusts_current_user",
                    severity="medium",
                    location=state.location,
                    message=(
                        "The body reads current_user or current_role. Inside a SECURITY "
                        "DEFINER function these name the function owner, whoever calls it, so "
                        "a guard built on them lets every caller through. Use session_user, "
                        "auth.uid() or the request claims to identify the caller."
                    ),
                )
            )
        if not state.pins_search_path:
            findings.append(
                Finding(
                    source=SOURCE,
                    rule="secdef_no_search_path",
                    severity="medium",
                    location=state.location,
                    message=(
                        "SECURITY DEFINER function does not set search_path, so a caller can "
                        "make it resolve unqualified names in a schema they control. Add "
                        "SET search_path = '' and qualify every name."
                    ),
                )
            )
    return findings


def run(sql_files: Sequence[Path], result: Optional[CheckResult] = None) -> CheckResult:
    """Replay the given SQL files in order and report on SECURITY DEFINER functions."""
    result = result or CheckResult(id=SOURCE, title=TITLE)
    try:
        import pglast  # noqa: F401  (installed together with pgrls)
    except ImportError:
        result.reason = "needs pglast, which is installed together with pgrls"
        return result

    replay = _Replay()
    unreadable: list[str] = []
    for path in sql_files:
        try:
            _apply_file(replay, path, path.read_text(encoding="utf-8"))
        except OSError as error:
            unreadable.append(f"{path.name} ({type(error).__name__})")
        except Exception as error:  # pglast raises its own parse error type
            unreadable.append(f"{path.name} (could not be parsed: {type(error).__name__})")

    if unreadable and len(unreadable) == len(sql_files):
        result.status = ERROR
        result.reason = "no SQL file could be read: " + ", ".join(unreadable)
        return result

    definers = [state for state in replay.functions.values() if state.definer]
    result.evidence = (
        f"{len(sql_files)} SQL files replayed in order; {len(replay.functions)} functions "
        f"defined, {len(definers)} of them SECURITY DEFINER"
    )
    result.findings.extend(_findings(replay))
    for name in unreadable:
        result.notes.append(
            f"skipped {name}; statements in it are missing from the replay, so results "
            "for functions it touches can be wrong"
        )
    result.notes.extend(dict.fromkeys(replay.notes))
    result.notes.append(
        "This replays only the files given. If they are part of the migration history, a "
        "function can look open although a later file outside the set closes it, or the "
        "other way round. Confirm against the live catalog before acting."
    )
    result.notes.append(
        "Overloads are tracked by name: a GRANT or REVOKE on one overload is applied to "
        "every function of that name."
    )
    return result.finish()
