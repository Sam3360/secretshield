"""
secretshield: detect and redact likely secrets before they reach
Python's terminal output or logging system.

Importing this package automatically enables protection for
``sys.stdout``, ``sys.stderr``, and the standard ``logging`` module::

    import secretshield

    api_key = "example-secret-value"
    print("API key:", api_key)
    # API key: ********
    # \u26a0 secretshield: Potential secret detected and redacted.

Protection can be toggled manually with :func:`enable` / :func:`disable`,
and behavior can be tuned with :func:`configure`.
"""

from __future__ import annotations

from .config import Config, configure, get_config, reset_config
from .detector import Match, detect
from .guardian import disable, enable, is_enabled
from .redactor import redact

__version__ = "0.2.1"

__all__ = [
    "__version__",
    "enable",
    "disable",
    "is_enabled",
    "configure",
    "get_config",
    "reset_config",
    "Config",
    "detect",
    "redact",
    "Match",
]

# Automatically protect stdout/stderr/logging as soon as secretshield is
# imported, per the tool's core promise: "import it and you're protected."
enable()
