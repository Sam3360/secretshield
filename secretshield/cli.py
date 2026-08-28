"""
Command-line interface for secretshield.

Provides:

* ``secretshield run <script.py> [args...]`` -- run a Python script with
  secretshield protection enabled for stdout/stderr/logging.
* ``secretshield scan <path>`` -- statically scan a file or a directory
  of text-based project files (Python, HTML, JS/TS, CSS, JSON, YAML,
  shell scripts, and more) for likely secrets, without executing
  anything. This is a static scan, distinct from runtime protection.

Static scanning is intentionally kept as a thin layer on top of the same
``detect()`` engine used for runtime protection -- there is no separate
per-language detection logic. Files are treated as plain text; the
regex/entropy patterns are what do the real work, regardless of whether
the file happens to be ``.py``, ``.js``, or ``.env``.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import runpy
import sys
from pathlib import Path

from . import __version__
from .detector import detect

# --- File type support -----------------------------------------------------

# Extensions treated as text/source files worth scanning by default.
_SCAN_EXTENSIONS = {
    ".py",
    ".js", ".jsx", ".ts", ".tsx",
    ".html", ".htm",
    ".css", ".scss",
    ".vue", ".svelte",
    ".json", ".jsonc",
    ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf",
    ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd",
    ".xml",
    ".md", ".txt",
    ".sql",
    ".graphql", ".gql",
}

# Directories skipped by default during a recursive scan: version control,
# dependency caches, virtual environments, and build/coverage output.
# None of these normally contain source secrets worth flagging, and they
# can be enormous, so skipping them keeps scans fast and low-noise.
_SKIP_DIR_NAMES = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "dist", "build", "coverage", ".pytest_cache", ".mypy_cache",
    ".tox", "egg-info",
}

# Bytes read from the start of a file to decide whether it looks binary.
_BINARY_SNIFF_SIZE = 1024


def _is_env_filename(name: str) -> bool:
    """True for `.env`, `.env.local`, `.env.production`, etc."""
    return name == ".env" or name.startswith(".env.")


def _looks_binary(path: Path) -> bool:
    """
    Best-effort check for whether a file is binary rather than text, so
    scanning never blindly reads/decodes arbitrary binary content. A
    file is treated as binary if it contains a NUL byte in its opening
    bytes, or if it can't be decoded as UTF-8 at all. Errors are treated
    as "binary" (skip it) rather than raised.
    """
    try:
        with open(path, "rb") as f:
            chunk = f.read(_BINARY_SNIFF_SIZE)
    except Exception:
        return True
    if b"\x00" in chunk:
        return True
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _should_scan_file(
    path: Path,
    include_patterns: list[str],
    exclude_patterns: list[str],
) -> bool:
    rel = path.as_posix()
    name = path.name

    # Explicit --exclude always wins, regardless of anything else.
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern):
            return False

    if include_patterns:
        for pattern in include_patterns:
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern):
                return True
        # An explicit --include list was given and nothing matched.
        return False

    if path.suffix.lower() in _SCAN_EXTENSIONS:
        return True
    if _is_env_filename(name):
        return True
    if path.suffix == "":
        # Extensionless files (Dockerfile, Makefile, etc.) are only
        # scanned if they turn out to actually be text, checked lazily
        # by the caller via _looks_binary() -- accepting here just means
        # "don't reject on the basis of extension alone".
        return True

    return False


def _iter_scan_files(
    root: Path,
    include_patterns: list[str],
    exclude_patterns: list[str],
    no_ignore: bool,
):
    if root.is_file():
        yield root
        return

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if not no_ignore and any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        if not _should_scan_file(path, include_patterns, exclude_patterns):
            continue
        if _looks_binary(path):
            continue
        yield path


# --- Detection kind display -------------------------------------------------

# Human-friendly (label, category) shown in CLI output for each detector
# `kind`. Keeps output readable without inventing a second detection
# engine -- this is purely presentational, layered on top of detect().
_KIND_DISPLAY: dict[str, tuple[str, str]] = {
    "aws_access_key_id": ("AWS access key", "cloud credential"),
    "aws_secret_access_key": ("AWS secret access key", "cloud credential"),
    "github_token": ("GitHub token", "token"),
    "openai_api_key": ("OpenAI API key", "API key"),
    "slack_token": ("Slack token", "token"),
    "stripe_key": ("Stripe key", "API key"),
    "google_api_key": ("Google API key", "API key"),
    "jwt": ("JWT", "token"),
    "bearer_token": ("Bearer token", "token"),
    "private_key_block": ("Private key block", "private key"),
    "generic_labeled_secret": ("Generic credential", "credential"),
    "high_entropy": ("High-entropy string", "possible secret"),
}


def _kind_display(kind: str) -> tuple[str, str]:
    return _KIND_DISPLAY.get(kind, (kind, "possible secret"))


# --- Placeholder filtering ---------------------------------------------------

# Values that are almost always documentation/tutorial placeholders
# rather than real secrets. Filtering is intentionally narrow (exact or
# near-exact match only) so real secrets are never suppressed just
# because they happen to share a substring with a placeholder.
_PLACEHOLDER_VALUES = {
    "your_api_key", "your-api-key", "youapikey", "your_api_key_here",
    "your-api-key-here", "your_token", "your-token", "your_secret",
    "your-secret", "example-key", "example_key", "fake-key", "fake_key",
    "test-token", "test_token", "changeme", "change_me", "change-me",
    "placeholder", "dummy-secret", "dummy_secret", "sample-key",
    "sample_key", "xxxxxxxx", "todo",
}


def _is_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("'\"").lower()
    if cleaned in _PLACEHOLDER_VALUES:
        return True
    if cleaned.startswith("your") and any(
        word in cleaned for word in ("key", "token", "secret", "password")
    ):
        return True
    if cleaned and set(cleaned) == {"x"}:
        return True
    return False


# --- `run` command -----------------------------------------------------------


def _cmd_run(args: argparse.Namespace) -> int:
    script_path = Path(args.script)
    if not script_path.is_file():
        print(f"secretshield: error: no such file: {script_path}", file=sys.stderr)
        return 1

    # Enable protection for the duration of the script's execution.
    from . import enable

    enable()

    sys.argv = [str(script_path), *args.script_args]
    script_dir = str(script_path.resolve().parent)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    try:
        runpy.run_path(str(script_path), run_name="__main__")
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1
    except Exception as exc:  # noqa: BLE001 - surface script errors to the user
        print(f"secretshield: script raised an exception: {exc}", file=sys.stderr)
        return 1
    return 0


# --- `scan` command -----------------------------------------------------------


def _line_number_for_offset(text: str, offset: int) -> int:
    """1-indexed line number containing `offset` within `text`."""
    return text.count("\n", 0, offset) + 1


def _scan_file(file_path: Path, entropy_threshold: float) -> list[dict]:
    """
    Scan a single file and return a list of finding dicts:
    {"line": int, "kind": str}. Never includes the secret value, the
    matched text, or the surrounding line content.
    """
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    try:
        matches = detect(text, entropy_threshold=entropy_threshold)
    except Exception:
        return []

    findings = []
    for match in matches:
        if _is_placeholder(match.value):
            continue
        findings.append(
            {"line": _line_number_for_offset(text, match.start), "kind": match.kind}
        )
    return findings


def _cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"secretshield: error: no such path: {target}", file=sys.stderr)
        return 1

    include_patterns = args.include or []
    exclude_patterns = args.exclude or []

    files_scanned = 0
    all_findings: list[dict] = []  # each: {"file": str, "line": int, "kind": str}

    for file_path in _iter_scan_files(
        target, include_patterns, exclude_patterns, args.no_ignore
    ):
        files_scanned += 1
        try:
            display_path = str(file_path.relative_to(Path.cwd()))
        except ValueError:
            display_path = str(file_path)

        for finding in _scan_file(file_path, entropy_threshold=args.entropy_threshold):
            all_findings.append(
                {"file": display_path, "line": finding["line"], "kind": finding["kind"]}
            )

    if args.json:
        payload = {
            "files_scanned": files_scanned,
            "matches": all_findings,
            "secrets_found": len(all_findings),
        }
        print(json.dumps(payload, indent=2))
        return 1 if all_findings else 0

    print("SecretShield scan\n")

    for finding in all_findings:
        label, category = _kind_display(finding["kind"])
        print(f"\u2717 {finding['file']}:{finding['line']}")
        print(f"  Potential secret: {label}")
        print(f"  Type: {category}\n")

    if all_findings:
        print(f"\u2713 {files_scanned} files scanned")
        print(f"\u2717 {len(all_findings)} potential secret(s) found")
    else:
        print(f"\u2713 {files_scanned} files scanned")
        print("\u2713 No potential secrets found")

    exit_code = 1 if all_findings else 0
    print(f"\nExit code: {exit_code}")
    return exit_code


# --- argparse wiring -----------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretshield",
        description=(
            "secretshield: detect and redact likely secrets before they "
            "reach Python's terminal output or logging system."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"secretshield {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser(
        "run", help="Run a Python script with secretshield protection enabled."
    )
    run_parser.add_argument("script", help="Path to the Python script to run.")
    run_parser.add_argument(
        "script_args",
        nargs=argparse.REMAINDER,
        help="Arguments to pass through to the script.",
    )
    run_parser.set_defaults(func=_cmd_run)

    scan_parser = subparsers.add_parser(
        "scan",
        help=(
            "Statically scan a file or directory of text-based project "
            "files (Python, HTML, JS/TS, CSS, JSON, YAML, shell scripts, "
            "and more) for potential secrets. Does not execute anything."
        ),
    )
    scan_parser.add_argument("path", help="File or directory to scan.")
    scan_parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.2,
        help="Shannon entropy threshold for generic secret detection (default: 4.2).",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON instead of human-readable text.",
    )
    scan_parser.add_argument(
        "--include",
        action="append",
        default=None,
        metavar="PATTERN",
        help=(
            "Glob pattern (matched against filename or relative path) to "
            "additionally scan, e.g. --include '*.rb'. Repeatable. When "
            "given, only files matching an --include pattern are scanned."
        ),
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="PATTERN",
        help=(
            "Glob pattern to skip, e.g. --exclude '*.min.js'. Repeatable. "
            "Always takes precedence over --include and default matching."
        ),
    )
    scan_parser.add_argument(
        "--no-ignore",
        action="store_true",
        help=(
            "Don't skip default-ignored directories (.git, node_modules, "
            "__pycache__, .venv, venv, dist, build, coverage, etc.)."
        ),
    )
    scan_parser.set_defaults(func=_cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
