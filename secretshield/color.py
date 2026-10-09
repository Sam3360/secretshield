"""
Minimal, dependency-free ANSI color support for CLI output.

Colors are only applied when the target stream is a real interactive
terminal -- never when output is piped, redirected, going into CI logs,
or serialized as `--json`. Respects the informal-but-widely-followed
`NO_COLOR` (disable) and `FORCE_COLOR` (force on) environment variable
conventions.
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

_RED = "\033[31m"
_GREEN = "\033[32m"
_RESET = "\033[0m"


def supports_color(stream: TextIO | None = None) -> bool:
    """Whether ANSI colors should be used when writing to `stream`
    (default: sys.stdout)."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True

    target = stream if stream is not None else sys.stdout
    try:
        return bool(target.isatty())
    except Exception:
        return False


def red(text: str, enabled: bool) -> str:
    return f"{_RED}{text}{_RESET}" if enabled else text


def green(text: str, enabled: bool) -> str:
    return f"{_GREEN}{text}{_RESET}" if enabled else text


def hyperlink(text: str, url: str, enabled: bool) -> str:
    """
    Wrap `text` in a standard OSC 8 terminal hyperlink escape sequence
    pointing at `url`, so supported terminals can Ctrl+Click it --
    while the *visible* text stays exactly `text`. Falls back to plain
    `text` (no escape codes at all) when `enabled` is False, so
    terminals that don't understand OSC 8 never see raw escape junk.
    """
    if not enabled:
        return text
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"
