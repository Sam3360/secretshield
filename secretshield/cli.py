"""
Command-line interface for secretshield.

Provides two commands:

* ``secretshield run <script.py> [args...]`` -- run a Python script with
  secretshield protection enabled for stdout/stderr/logging.
* ``secretshield scan <path>`` -- scan a text file (or directory of text
  files) for likely secrets without executing anything. This is a static
  scan, distinct from runtime protection.
"""

from __future__ import annotations

import argparse
import runpy
import sys
from pathlib import Path

from . import __version__
from .detector import detect

# Reasonable default set of extensions to consider "text" when scanning a
# directory. Binary files and common non-source directories are skipped.
_SCAN_EXTENSIONS = {
    ".py", ".txt", ".md", ".env", ".yml", ".yaml", ".json",
    ".ini", ".cfg", ".toml", ".sh", ".js", ".ts",
}
_SKIP_DIR_NAMES = {".git", "__pycache__", "node_modules", ".venv", "venv"}


def _cmd_run(args: argparse.Namespace) -> int:
    script_path = Path(args.script)
    if not script_path.is_file():
        print(f"secretshield: error: no such file: {script_path}", file=sys.stderr)
        return 1

    # Enable protection for the duration of the script's execution.
    from . import enable

    enable()

    # Make the script's own arguments available to it via sys.argv, and
    # ensure its directory is importable the way `python script.py` would.
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


def _scan_text(text: str, entropy_threshold: float) -> list[str]:
    findings = []
    try:
        matches = detect(text, entropy_threshold=entropy_threshold)
    except Exception:
        return findings
    for match in matches:
        findings.append(f"  - {match.kind} at offset {match.start}-{match.end}")
    return findings


def _iter_scan_files(root: Path):
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in _SCAN_EXTENSIONS:
            yield path


def _cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"secretshield: error: no such path: {target}", file=sys.stderr)
        return 1

    total_findings = 0
    for file_path in _iter_scan_files(target):
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        findings = _scan_text(text, entropy_threshold=args.entropy_threshold)
        if findings:
            total_findings += len(findings)
            print(f"{file_path}")
            for line in findings:
                print(line)

    if total_findings == 0:
        print("secretshield: scan complete, no potential secrets found.")
    else:
        print(
            f"\nsecretshield: scan complete, {total_findings} potential "
            "secret(s) found."
        )
    return 1 if total_findings else 0


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
            "Statically scan a file or directory of text files for "
            "potential secrets (does not execute anything)."
        ),
    )
    scan_parser.add_argument("path", help="File or directory to scan.")
    scan_parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.2,
        help="Shannon entropy threshold for generic secret detection (default: 4.2).",
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
