"""Files changed since a git revision, for `check --changed-since <ref>`.

Only the file checks use this: the credential scan reads just the changed
files, and the SQL checks run only when a SQL file changed (and then over every
given file, since a function's privileges depend on the files before it).
Checks of a live database are never narrowed: a database can change without a
commit.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .model import Refusal

_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/~^@{}-]{0,200}$")
TIMEOUT_SECONDS = 20


def _git(directory: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise Refusal("--changed-since needs git, which is not installed")
    try:
        done = subprocess.run(
            [executable, "-C", str(directory), *arguments],
            capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refusal(f"git could not run ({type(error).__name__})") from None
    if done.returncode != 0:
        raise Refusal(f"git refused: {' '.join(arguments[:2])} in {directory} (exit {done.returncode})")
    return done.stdout


def check_ref(ref: str) -> str:
    """Refuse anything that is not a plain revision name, so it cannot act as an option."""
    if not _REF.match(ref or ""):
        raise Refusal(f"--changed-since {ref!r} is not a revision name such as HEAD~1, main or a commit hash")
    return ref


def changed_files(path: Path, ref: str) -> set[Path]:
    """Absolute paths of files added, changed or renamed since `ref`, plus untracked files,
    in the git repository that holds `path`."""
    ref = check_ref(ref)
    directory = path if path.is_dir() else path.parent
    top = Path(_git(directory, "rev-parse", "--show-toplevel").strip())
    _git(top, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}")
    names = _git(top, "diff", "--name-only", "--diff-filter=ACMR", "--end-of-options", ref, "--").splitlines()
    names += _git(top, "ls-files", "--others", "--exclude-standard").splitlines()
    return {(top / name).resolve() for name in names if name.strip()}
