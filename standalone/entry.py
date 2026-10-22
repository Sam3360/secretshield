"""
Entry point for the standalone (PyInstaller) executables.

The executable runs exactly the same ``secretshield.cli.main`` as the ``ss`` /
``secretshield`` console scripts that pip installs, so there is only one
implementation of the CLI. The one thing done here, and only in the frozen
build, is :func:`prepare_streams`.

Why it exists: a PyInstaller executable ignores the ``PYTHON*`` environment
variables (``PYTHONIOENCODING``, ``PYTHONUTF8``) that a normal Python honors,
and on Windows a redirected or piped stdout then falls back to the legacy ANSI
code page. That turned file names like ``ключ.py`` and the check/cross marks
into ``?`` even when the caller asked for UTF-8.
"""

import codecs
import os
import sys


def _same_encoding(current, wanted):
    try:
        return codecs.lookup(current).name == codecs.lookup(wanted).name
    except (LookupError, TypeError):
        return False


def _apply(stream, encoding, errors):
    reconfigure = getattr(stream, "reconfigure", None)
    if not callable(reconfigure):
        return
    if _same_encoding(getattr(stream, "encoding", None), encoding) and not errors:
        return  # e.g. an interactive Windows console, which is left exactly as it is
    try:
        reconfigure(encoding=encoding, errors=errors or None)
    except (LookupError, ValueError, OSError):
        pass  # an unknown encoding name or an unusable stream keeps its current setup


def prepare_streams(environ=None, stdout=None, stderr=None):
    """Give the standalone build's stdout/stderr sensible encodings.

    * ``PYTHONIOENCODING=encoding[:errors]`` is honored, exactly as Python would.
    * ``PYTHONUTF8=0`` means "leave the platform default alone".
    * Otherwise redirected/piped output is UTF-8, the encoding scripts, CI logs
      and other tools expect (and what Python itself is moving to by default).

    Does nothing outside a frozen executable, so the pip package is unchanged.
    """
    if not getattr(sys, "frozen", False):
        return
    environ = os.environ if environ is None else environ
    requested = (environ.get("PYTHONIOENCODING") or "").strip()
    if requested:
        encoding, _, errors = requested.partition(":")
        encoding = encoding.strip() or "utf-8"
        errors = errors.strip()
    elif environ.get("PYTHONUTF8") == "0":
        return
    else:
        encoding, errors = "utf-8", ""
    for stream in (sys.stdout if stdout is None else stdout, sys.stderr if stderr is None else stderr):
        if stream is not None:
            _apply(stream, encoding, errors)


if __name__ == "__main__":
    prepare_streams()
    from secretshield.cli import main

    sys.exit(main())
