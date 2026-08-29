"""Interactive Auto-Fix: move detected secrets into `.env` safely."""

from __future__ import annotations

from .fixer import FixSummary, is_interactive, run_autofix

__all__ = ["run_autofix", "FixSummary", "is_interactive"]
