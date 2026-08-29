"""
Install/uninstall a Git pre-commit hook that scans staged files with
SecretShield, and helpers for reading what's actually staged (as opposed
to what's on disk, which can differ from a partially-staged working
tree).

The hook itself is a thin shell script that just invokes
``secretshield scan-staged`` -- all real logic lives in Python, in
:mod:`secretshield.cli`, so it's testable without spawning a shell.
"""

from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

HOOK_MARKER = "# --- secretshield managed pre-commit hook ---"
BACKUP_SUFFIX = ".secretshield-backup"

HOOK_SCRIPT = f"""\
#!/bin/sh
{HOOK_MARKER}
secretshield scan-staged
exit $?
"""


def _wrapped_hook_script(backup_relname: str) -> str:
    """
    A pre-commit hook that preserves an existing (foreign) hook by
    invoking its backed-up copy first, then running SecretShield's own
    staged-file scan. Both must succeed for the commit to proceed.
    """
    return f"""\
#!/bin/sh
{HOOK_MARKER}
# This hook wraps a pre-existing pre-commit hook that was backed up to
# "{backup_relname}" when SecretShield was installed.
HOOKDIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$HOOKDIR/{backup_relname}" ]; then
    sh "$HOOKDIR/{backup_relname}"
    status=$?
    if [ "$status" -ne 0 ]; then
        exit $status
    fi
fi
secretshield scan-staged
exit $?
"""


def find_git_dir(start: Path | None = None) -> Path | None:
    """
    Walk upward from `start` (default: current directory) looking for a
    `.git` entry. Handles both a normal `.git` directory and the
    `.git` *file* used by Git worktrees/submodules (which contains a
    `gitdir: <path>` pointer).
    """
    current = (start or Path.cwd()).resolve()
    for directory in [current, *current.parents]:
        candidate = directory / ".git"
        if candidate.is_dir():
            return candidate
        if candidate.is_file():
            try:
                text = candidate.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return None
            for line in text.splitlines():
                if line.startswith("gitdir:"):
                    pointed = line.split(":", 1)[1].strip()
                    pointed_path = Path(pointed)
                    if not pointed_path.is_absolute():
                        pointed_path = (directory / pointed_path).resolve()
                    return pointed_path
            return None
    return None


def is_git_repo(start: Path | None = None) -> bool:
    return find_git_dir(start) is not None


def hooks_dir(git_dir: Path) -> Path:
    return git_dir / "hooks"


def get_staged_files() -> list[str]:
    """
    Return the relative paths of staged files that will actually be
    part of the commit (added/copied/modified) -- deleted files are
    excluded since there's nothing to scan.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def get_staged_content(relpath: str) -> str | None:
    """
    Return the *staged* (index) content of a file -- not what's
    currently on disk, which can differ under partial staging. Returns
    None if the blob can't be read as text (binary, missing, etc.).
    """
    try:
        result = subprocess.run(
            ["git", "show", f":{relpath}"],
            capture_output=True,
            check=True,
        )
    except Exception:
        return None
    raw = result.stdout
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _make_executable(path: Path) -> None:
    try:
        current = os.stat(path).st_mode
        os.chmod(path, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        # Not fatal -- some platforms/filesystems don't support this,
        # and Git for Windows runs hooks via its bundled sh regardless.
        pass


@dataclass
class HookResult:
    status: str  # "installed" | "reinstalled" | "wrapped_existing" |
    #                "already_installed" | "error"
    message: str
    backup_path: str | None = None


def install_hook(force: bool = False) -> HookResult:
    git_dir = find_git_dir()
    if git_dir is None:
        return HookResult("error", "Not inside a Git repository.")

    hdir = hooks_dir(git_dir)
    hdir.mkdir(parents=True, exist_ok=True)
    hook_path = hdir / "pre-commit"
    backup_path = hdir / f"pre-commit{BACKUP_SUFFIX}"

    if hook_path.exists():
        try:
            existing = hook_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            existing = ""

        if HOOK_MARKER in existing:
            if not force:
                return HookResult(
                    "already_installed",
                    "SecretShield's pre-commit hook is already installed.",
                )
            hook_path.write_text(HOOK_SCRIPT, encoding="utf-8")
            _make_executable(hook_path)
            return HookResult("reinstalled", "SecretShield pre-commit hook reinstalled.")

        # A foreign hook is present -- never destroy it.
        if backup_path.exists() and not force:
            return HookResult(
                "error",
                f"A pre-commit hook already exists and a backup at "
                f"{backup_path} is also present. Refusing to proceed "
                f"without --force.",
            )
        backup_path.write_text(existing, encoding="utf-8")
        _make_executable(backup_path)
        hook_path.write_text(
            _wrapped_hook_script(backup_path.name), encoding="utf-8"
        )
        _make_executable(hook_path)
        return HookResult(
            "wrapped_existing",
            f"Existing pre-commit hook preserved and backed up to "
            f"{backup_path}. SecretShield now runs alongside it.",
            backup_path=str(backup_path),
        )

    hook_path.write_text(HOOK_SCRIPT, encoding="utf-8")
    _make_executable(hook_path)
    return HookResult("installed", "SecretShield pre-commit hook installed.")


def uninstall_hook() -> HookResult:
    git_dir = find_git_dir()
    if git_dir is None:
        return HookResult("error", "Not inside a Git repository.")

    hdir = hooks_dir(git_dir)
    hook_path = hdir / "pre-commit"
    backup_path = hdir / f"pre-commit{BACKUP_SUFFIX}"

    if not hook_path.exists():
        return HookResult("not_installed", "No pre-commit hook is installed.")

    try:
        content = hook_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        content = ""

    if HOOK_MARKER not in content:
        return HookResult(
            "error",
            "The existing pre-commit hook wasn't installed by "
            "SecretShield. Refusing to remove it.",
        )

    if backup_path.exists():
        hook_path.write_text(backup_path.read_text(encoding="utf-8"), encoding="utf-8")
        _make_executable(hook_path)
        backup_path.unlink()
        return HookResult(
            "restored_backup",
            "SecretShield hook removed; the original pre-commit hook was restored.",
        )

    hook_path.unlink()
    return HookResult("removed", "SecretShield pre-commit hook removed.")
