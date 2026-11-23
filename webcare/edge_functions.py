"""Edge Functions, read from files: who may call each one, and with what rights.

Reads `supabase/config.toml` and the code under `supabase/functions/<name>/`.
Nothing is contacted and no function is run.

What files cannot show: a function deployed with `--no-verify-jwt`, or switched
in the dashboard, looks the same on disk as one that checks the JWT. The check
says so in its notes, and a function with no entry in config.toml is judged as
if the platform checks the JWT, which is the default.

The findings are signs, not proof. "No caller check found" means none of the
usual calls was seen in the function's own files; a check hidden in an imported
package would be missed, so read the function before changing it.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .model import ERROR, NOT_RUN, CheckResult, Finding

TITLE = "Edge Functions from files (who may call them, and with what rights)"
SOURCE = "edge_functions"
CODE_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".jsx")
MAX_FILE_BYTES = 1_000_000

# A string is kept as it is, so that "https://..." is not taken for a comment.
_STRING_OR_COMMENT = re.compile(
    r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|`(?:\\.|[^`\\])*`|//[^\n]*|/\*.*?\*/', re.DOTALL
)
_SERVICE_ROLE = re.compile(r"SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY|\bsb_secret_", re.IGNORECASE)
# Calls that settle who the caller is, or that a shared secret or signature is right.
_VERIFIES_CALLER = re.compile(
    r"\.auth\s*\.\s*getUser\s*\(|\.auth\s*\.\s*getClaims\s*\(|/auth/v1/user\b|\bjwtVerify\s*\(|"
    r"\bverify\s*\(|\btimingSafeEqual\s*\(|\bconstructEvent(?:Async)?\s*\(|\bverifyWebhook\w*\s*\(|"
    r"\bcrypto\s*\.\s*subtle\s*\.\s*verify\s*\(",
)
_READS_CREDENTIAL = re.compile(
    r"headers\s*\.\s*get\s*\(\s*[\"'`](?:authorization|apikey|x-[a-z0-9-]*(?:secret|signature|token|key))[\"'`]",
    re.IGNORECASE,
)
_CORS_ANY = re.compile(r"Access-Control-Allow-Origin[\"'`]?\s*[:,]\s*[\"'`]\*[\"'`]", re.IGNORECASE)
_SHARED_IMPORT = re.compile(r"[\"'`](\.\.?/[^\"'`\n]*)[\"'`]")


def _without_comments(text: str) -> str:
    """The text with comments blanked out, keeping every offset and line break."""
    def blank(match: re.Match) -> str:
        found = match.group(0)
        if found[0] in "\"'`":
            return found
        return "".join(ch if ch == "\n" else " " for ch in found)

    return _STRING_OR_COMMENT.sub(blank, text)


def _display(path: Path) -> str:
    """Path from the current directory when it lies under it, so reports and SARIF can point at it."""
    try:
        text = Path(os.path.relpath(path.resolve(), Path.cwd().resolve())).as_posix()
    except ValueError:
        return path.as_posix()
    return path.as_posix() if text.startswith("../") or text == ".." else text


@dataclass
class EdgeFunction:
    name: str
    directory: Path
    files: list[Path] = field(default_factory=list)  # its own code, then local files it imports
    verify_jwt: Optional[bool] = None  # None: not stated in config.toml


def _config_settings(config: Path) -> dict[str, bool]:
    """verify_jwt per function from a supabase/config.toml."""
    data = tomllib.loads(config.read_text(encoding="utf-8"))
    functions = data.get("functions", {})
    settings = {}
    if isinstance(functions, dict):
        for name, entry in functions.items():
            if isinstance(entry, dict) and isinstance(entry.get("verify_jwt"), bool):
                settings[name] = entry["verify_jwt"]
    return settings


def _code_files(directory: Path) -> list[Path]:
    found = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.suffix in CODE_SUFFIXES and "node_modules" not in path.parts:
            found.append(path)
    return found


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _with_local_imports(files: list[Path], root: Path) -> list[Path]:
    """The files, plus files they import by a relative path (such as ../_shared/cors.ts)."""
    seen = list(files)
    queue = list(files)
    while queue:
        current = queue.pop()
        for target in _SHARED_IMPORT.findall(_without_comments(_read(current))):
            candidate = (current.parent / target).resolve()
            options = [candidate] + [candidate.with_suffix(suffix) for suffix in CODE_SUFFIXES if not candidate.suffix]
            for option in options:
                inside = root.resolve() in option.parents
                if inside and option.is_file() and option.suffix in CODE_SUFFIXES and option not in seen:
                    seen.append(option)
                    queue.append(option)
    return seen


def discover(repos: Iterable[Path], extra_dirs: Iterable[Path] = ()) -> tuple[list[EdgeFunction], list[Path], list[str]]:
    """Functions found, the config files read, and notes about what could not be read."""
    functions: list[EdgeFunction] = []
    configs: list[Path] = []
    notes: list[str] = []
    roots: list[tuple[Path, dict[str, bool]]] = []
    for repo in repos:
        config = repo / "supabase" / "config.toml"
        settings: dict[str, bool] = {}
        if config.is_file():
            try:
                settings = _config_settings(config)
                configs.append(config)
            except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as error:
                notes.append(f"{_display(config)} could not be read ({type(error).__name__}); verify_jwt is not known")
        folder = repo / "supabase" / "functions"
        if folder.is_dir():
            roots.append((folder, settings))
    known = {root.resolve() for root, _ in roots}
    merged: dict[str, bool] = {}
    for _, settings in roots:
        merged.update(settings)
    for folder in extra_dirs:
        if folder.resolve() not in known:
            roots.append((folder, merged))
    for folder, settings in roots:
        for directory in sorted(p for p in folder.iterdir() if p.is_dir()):
            # Names that start with "_" (such as _shared) hold helpers, not functions.
            if directory.name.startswith(("_", ".")) or directory.name == "node_modules":
                continue
            own = _code_files(directory)
            if not own:
                continue
            functions.append(EdgeFunction(
                name=directory.name, directory=directory,
                files=_with_local_imports(own, folder), verify_jwt=settings.get(directory.name),
            ))
    return functions, configs, notes


def _first(pattern: "re.Pattern[str]", texts: list[tuple[Path, str]]) -> Optional[tuple[Path, int]]:
    for path, text in texts:
        match = pattern.search(text)
        if match:
            return path, text.count("\n", 0, match.start()) + 1
    return None


def judge(function: EdgeFunction) -> list[Finding]:
    texts = [(path, _without_comments(_read(path))) for path in function.files]
    entry = function.files[0] if function.files else function.directory
    service = _first(_SERVICE_ROLE, texts)
    verifies = _first(_VERIFIES_CALLER, texts)
    reads = _first(_READS_CREDENTIAL, texts)
    cors = _first(_CORS_ANY, texts)
    findings: list[Finding] = []

    def at(spot: Optional[tuple[Path, int]]) -> str:
        return f"{_display(spot[0])}:{spot[1]}" if spot else f"{_display(entry)}:1"

    rights = "with the service role key, which passes row-level security" if service else "with its own rights"
    if function.verify_jwt is False:
        if verifies is None and reads is None:
            findings.append(Finding(
                SOURCE, "edge_open_to_anyone", "high" if service else "medium", at(service),
                f"function {function.name}: verify_jwt is off in config.toml and no caller check was found in its "
                f"files, so anyone who knows the address can run it {rights}. Check a JWT, a shared secret or "
                "a webhook signature inside the function, or switch verify_jwt back on",
            ))
        else:
            findings.append(Finding(
                SOURCE, "edge_verify_jwt_off", "info", at(verifies or reads),
                f"function {function.name}: verify_jwt is off in config.toml, and the function appears to check "
                "callers itself. That is the usual shape of a webhook; confirm that every path through it does",
            ))
    elif service and verifies is None:
        seen = ("it reads a credential from the request, but no call that settles who the caller is was found"
                if reads else "no caller check was found in its files")
        findings.append(Finding(
            SOURCE, "edge_service_role_no_caller_check", "low" if reads else "medium", at(service),
            f"function {function.name} uses the service role key and {seen}. The platform's JWT check lets in "
            "every signed-in user, and the legacy anon key is a valid JWT too, so each of them could run it with "
            "full rights. Find out who is calling (auth.getUser or getClaims) and check what they may do",
        ))
    if cors:
        findings.append(Finding(
            SOURCE, "edge_cors_any_origin", "low" if service else "info", at(cors),
            f"function {function.name} answers browsers on any website (Access-Control-Allow-Origin: *). "
            "Name the site's own origins instead, unless every website is meant to call it",
        ))
    return findings


def run(repos: Iterable[Path], extra_dirs: Iterable[Path] = (), changed: Optional[set] = None,
        changed_since: str = "") -> CheckResult:
    result = CheckResult(id="edge_functions", title=TITLE)
    extra = [Path(p) for p in extra_dirs]
    missing = [str(path) for path in extra if not path.is_dir()]
    if missing:
        result.status = ERROR
        result.reason = "functions folder not found: " + ", ".join(missing)
        return result
    functions, configs, notes = discover(list(repos), extra)
    if not functions:
        result.status = NOT_RUN
        result.reason = "no Edge Function found under supabase/functions (or name the folder with --functions-dir)"
        return result
    if changed is not None:
        touched = {path.resolve() for function in functions for path in function.files}
        touched |= {config.resolve() for config in configs}
        folders = {function.directory.parent.resolve() for function in functions}
        # A deleted file under a functions folder is a change too (a removed check, say).
        gone = any(path.suffix in CODE_SUFFIXES and not path.exists() and folders & set(path.parents)
                   for path in changed)
        if not (touched & changed) and not gone:
            result.status = NOT_RUN
            result.reason = f"no Edge Function file changed since {changed_since}"
            return result
    for function in functions:
        result.findings += judge(function)
    result.evidence = (
        f"{len(functions)} Edge Functions read from disk: " + ", ".join(function.name for function in functions)
    )
    unstated = [function.name for function in functions if function.verify_jwt is None]
    if not configs:
        result.notes.append(
            "no supabase/config.toml was found, so every function was judged as if the platform checks the JWT"
        )
    elif unstated:
        result.notes.append(
            "not named in config.toml, so judged as if the platform checks the JWT (the default): "
            + ", ".join(unstated)
        )
    result.notes += notes
    result.notes.append(
        "Files cannot show a function deployed with --no-verify-jwt or switched in the dashboard; "
        "compare with Edge Functions > (function) > Details in the dashboard"
    )
    result.notes.append(
        "Signs, not proof: a caller check inside an imported package is not seen, and a check that is "
        "present may still not cover every path"
    )
    return result.finish()
