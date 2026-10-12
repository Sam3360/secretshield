"""Ensure `.env` is excluded from Git, without disturbing other rules."""

from __future__ import annotations

from pathlib import Path

_ENTRY = ".env"


def ensure_env_ignored(gitignore_path: Path) -> bool:
    """
    Make sure `.env` is listed in `.gitignore`. Creates the file if it
    doesn't exist. Returns True if a change was made, False if `.env`
    was already covered.
    """
    if not gitignore_path.exists():
        gitignore_path.write_text(_ENTRY + "\n", encoding="utf-8")
        return True

    try:
        content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        content = ""

    existing_lines = {line.strip() for line in content.splitlines()}
    if _ENTRY in existing_lines:
        return False

    prefix = "" if (not content or content.endswith("\n")) else "\n"
    with open(gitignore_path, "a", encoding="utf-8", newline="") as f:
        f.write(f"{prefix}{_ENTRY}\n")
    return True
