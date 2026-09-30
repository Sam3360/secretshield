"""
`.secretshieldignore` -- a familiar, `.gitignore`-style companion to
`secretshield.toml`'s `[scan.ignore]` section, for anyone who'd rather
drop in a plain ignore file than edit TOML.
"""

from __future__ import annotations

from pathlib import Path

IGNORE_FILENAME = ".secretshieldignore"


def ignore_file_path(root: Path) -> Path:
    return root / IGNORE_FILENAME


def load_ignore_patterns(root: Path | None = None) -> list[str]:
    """
    Read `.secretshieldignore` from `root` (default: current directory)
    if present. One glob pattern per line; blank lines and lines
    starting with `#` are skipped, same as `.gitignore`. A trailing
    `/` means "this directory and everything under it," matching
    `secretshield.toml`'s `[scan.ignore].paths` convention -- both
    ultimately feed the same exclude-pattern matching used by
    `--exclude`.
    """
    path = ignore_file_path(root or Path.cwd())
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []

    patterns: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line if not line.endswith("/") else line + "*")
    return patterns
