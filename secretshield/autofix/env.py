"""
Safe `.env` (and `.env.example`) file handling for Auto-Fix.

Existing files are never overwritten -- new variables are only ever
appended, and only after checking they aren't already present.
"""

from __future__ import annotations

from pathlib import Path


def load_env_keys(env_path: Path) -> set[str]:
    """Return the set of variable names already defined in an env file."""
    if not env_path.exists():
        return set()
    try:
        text = env_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return set()

    keys = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            keys.add(stripped.split("=", 1)[0].strip())
    return keys


def _append(path: Path, line: str) -> None:
    prefix = ""
    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            existing = ""
        if existing and not existing.endswith("\n"):
            prefix = "\n"
    with open(path, "a", encoding="utf-8", newline="") as f:
        f.write(f"{prefix}{line}\n")


def append_env_var(env_path: Path, key: str, value: str) -> None:
    """Append `KEY=value` to `.env`, creating the file if needed."""
    _append(env_path, f"{key}={value}")


def append_env_example_var(example_path: Path, key: str) -> None:
    """
    Append `KEY=` (no value) to `.env.example`, creating it if needed.
    Never writes a real secret. Skips silently if the key is already
    present, so this is safe to call repeatedly.
    """
    if key in load_env_keys(example_path):
        return
    _append(example_path, f"{key}=")


def unique_env_key(env_path: Path, desired: str, also_avoid: set[str] | None = None) -> str:
    """
    Return `desired` if it isn't already used in `.env` (or in
    `also_avoid`, e.g. names already claimed earlier in this same
    Auto-Fix run); otherwise append a numeric suffix until it's unique.
    """
    taken = load_env_keys(env_path) | (also_avoid or set())
    if desired not in taken:
        return desired
    n = 2
    while f"{desired}_{n}" in taken:
        n += 1
    return f"{desired}_{n}"
