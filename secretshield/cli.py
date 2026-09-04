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

from . import __version__, disable, enable, is_enabled
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
    matches = _scan_file_matches(file_path, entropy_threshold)
    return [
        {"line": _line_number_for_offset(_read_text_safe(file_path), m.start), "kind": m.kind}
        for m in matches
    ]


def _read_text_safe(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _scan_text_matches(text: str, entropy_threshold: float) -> list:
    """
    Run detect() against already-loaded text and filter placeholders.
    Shared by disk-based scanning and Git-staged-content scanning so
    both go through identical detection logic.
    """
    if not text:
        return []
    try:
        matches = detect(text, entropy_threshold=entropy_threshold)
    except Exception:
        return []
    return [m for m in matches if not _is_placeholder(m.value)]


def _scan_file_matches(file_path: Path, entropy_threshold: float) -> list:
    """
    Like `_scan_file`, but returns the raw (placeholder-filtered) Match
    objects, including their real values. Used internally by Auto-Fix,
    which needs the actual secret value in memory to decide how to
    rewrite the source -- never printed, never serialized to JSON.
    """
    return _scan_text_matches(_read_text_safe(file_path), entropy_threshold)


def _temporarily_unwrap_streams() -> tuple:
    """
    Temporarily replace sys.stdout/sys.stderr with their underlying,
    unwrapped stream if currently guarded, so a CLI command's own
    diagnostic text isn't subject to live redaction (see the
    self-redaction note on `_cmd_scan` below). Returns the *original*
    references so they can be restored exactly afterward.

    Deliberately does NOT use guardian.disable()/enable(): those toggle
    a single global "is protection active" flag and, once already
    active (the normal state from the moment `secretshield` is
    imported), enable() becomes a no-op. That means disable() would
    restore whatever stream was captured at the very first enable()
    call -- not whatever sys.stdout/sys.stderr actually are right now.
    Under something like pytest's capsys fixture (which replaces
    sys.stdout per-test), that mismatch would silently redirect output
    away from the current capture target. Working directly off the
    live stream objects sidesteps that entirely.
    """
    from .guardian import _WRAPPED_MARKER

    orig_stdout, orig_stderr = sys.stdout, sys.stderr
    if getattr(sys.stdout, _WRAPPED_MARKER, False):
        sys.stdout = sys.stdout._wrapped  # noqa: SLF001
    if getattr(sys.stderr, _WRAPPED_MARKER, False):
        sys.stderr = sys.stderr._wrapped  # noqa: SLF001
    return orig_stdout, orig_stderr


def _cmd_scan(args: argparse.Namespace) -> int:
    # `scan`'s own status/report output is, by design, never supposed to
    # contain a secret value -- but if runtime protection is active (as
    # it is by default the moment `secretshield` is imported), that same
    # live redaction filter also inspects this command's own diagnostic
    # text. That can misfire: a kind label like "High-entropy string",
    # printed right after the word "secret:", happens to match the
    # generic-label detection pattern on itself and gets mangled into
    # "secret: ******** string" -- even though nothing sensitive was
    # ever printed. Since scan() never emits real secret values in the
    # first place, its own reporting doesn't need (and shouldn't be
    # subject to) that filter.
    orig_stdout, orig_stderr = _temporarily_unwrap_streams()
    try:
        return _run_scan(args)
    finally:
        sys.stdout, sys.stderr = orig_stdout, orig_stderr


def _progress_supported() -> bool:
    try:
        return sys.stderr.isatty()
    except Exception:
        return False


def _progress_update(show: bool, count: int) -> None:
    if not show:
        return
    try:
        sys.stderr.write(f"\rScanning... {count} files scanned")
        sys.stderr.flush()
    except Exception:
        pass


def _progress_clear(show: bool) -> None:
    if not show:
        return
    try:
        sys.stderr.write("\r" + " " * 40 + "\r")
        sys.stderr.flush()
    except Exception:
        pass


def _iter_scan_sources(args: argparse.Namespace, target: Path, include_patterns: list, exclude_patterns: list):
    """
    Yield (display_path, text) pairs for whichever scan source mode is
    active. --staged reads actual Git *index* content (correct even
    under partial staging); --diff and the normal directory walk read
    current on-disk content. Yields nothing (after printing an error)
    if --staged/--diff is used outside a Git repository.
    """
    if getattr(args, "staged", False):
        from .git import get_staged_content, get_staged_files, is_git_repo

        if not is_git_repo():
            print("secretshield: error: not inside a Git repository", file=sys.stderr)
            return
        for relpath in get_staged_files():
            path = Path(relpath)
            if not _should_scan_file(path, include_patterns, exclude_patterns):
                continue
            content = get_staged_content(relpath)
            if content is None:
                continue
            yield relpath, content
        return

    diff_ref = getattr(args, "diff", None)
    if diff_ref:
        from .git import get_diff_files, is_git_repo

        if not is_git_repo():
            print("secretshield: error: not inside a Git repository", file=sys.stderr)
            return
        for relpath in get_diff_files(diff_ref):
            path = Path(relpath)
            if not _should_scan_file(path, include_patterns, exclude_patterns):
                continue
            if not path.exists() or _looks_binary(path):
                continue
            yield relpath, _read_text_safe(path)
        return

    for file_path in _iter_scan_files(target, include_patterns, exclude_patterns, args.no_ignore):
        try:
            display_path = str(file_path.relative_to(Path.cwd()))
        except ValueError:
            display_path = str(file_path)
        yield display_path, _read_text_safe(file_path)


def _run_scan(args: argparse.Namespace) -> int:
    from .baseline import baseline_exists, compute_finding_id, load_baseline_ids, write_baseline
    from .project_config import load_project_config

    project_cfg = load_project_config()

    entropy_threshold = args.entropy_threshold
    if entropy_threshold is None:
        entropy_threshold = project_cfg.entropy_threshold
    if entropy_threshold is None:
        entropy_threshold = 4.2

    include_patterns = args.include or project_cfg.include_patterns or []
    exclude_patterns = list(args.exclude or [])
    for raw in project_cfg.ignore_paths:
        # A trailing "/" means "this directory and everything in it" --
        # translate that into a glob so it matches nested files too.
        exclude_patterns.append(raw if not raw.endswith("/") else raw + "*")

    json_output = bool(args.json) or (project_cfg.output_format == "json")

    target = Path(args.path)
    using_explicit_source = bool(getattr(args, "staged", False) or getattr(args, "diff", None))

    if using_explicit_source:
        from .git import is_git_repo

        if not is_git_repo():
            print("secretshield: error: not inside a Git repository", file=sys.stderr)
            return 2

    if not using_explicit_source and not target.exists():
        print(f"secretshield: error: no such path: {target}", file=sys.stderr)
        return 1

    files_scanned = 0
    all_findings: list[dict] = []  # each: {"file": str, "line": int, "kind": str}
    matches_by_file: dict[str, list] = {}
    matches_with_context: list[tuple[str, int, object]] = []  # (file, line, Match)
    show_progress = _progress_supported() and not json_output

    for display_path, text in _iter_scan_sources(args, target, include_patterns, exclude_patterns):
        files_scanned += 1
        _progress_update(show_progress, files_scanned)

        file_matches = _scan_text_matches(text, entropy_threshold=entropy_threshold)
        if file_matches:
            matches_by_file[display_path] = file_matches
        for match in file_matches:
            line_no = _line_number_for_offset(text, match.start)
            all_findings.append({"file": display_path, "line": line_no, "kind": match.kind})
            matches_with_context.append((display_path, line_no, match))

    _progress_clear(show_progress)

    project_root = Path.cwd()

    # --baseline: write a fresh baseline capturing every current finding,
    # then stop -- this run itself never fails on those findings.
    if getattr(args, "baseline", False):
        baseline_findings = [
            {
                "id": compute_finding_id(file, m.kind, m.value),
                "file": file,
                "kind": m.kind,
                "line": line,
            }
            for file, line, m in matches_with_context
        ]
        path = write_baseline(project_root, baseline_findings)
        print(f"\u2713 Baseline written to {path} ({len(baseline_findings)} finding(s))")
        return 0

    ignored_by_baseline = 0
    if baseline_exists(project_root) and not getattr(args, "fix", False):
        known_ids = load_baseline_ids(project_root)
        kept_context = []
        new_matches_by_file: dict[str, list] = {}
        for file, line, m in matches_with_context:
            finding_id = compute_finding_id(file, m.kind, m.value)
            if finding_id in known_ids:
                ignored_by_baseline += 1
                continue
            kept_context.append((file, line, m))
            new_matches_by_file.setdefault(file, []).append(m)
        matches_by_file = new_matches_by_file
        matches_with_context = kept_context
        all_findings = [
            {"file": file, "line": line, "kind": m.kind} for file, line, m in matches_with_context
        ]

    if getattr(args, "fix", False):
        from .autofix import run_autofix

        summary = run_autofix(project_root, matches_by_file, entropy_threshold=entropy_threshold)
        return 1 if summary.fixed < summary.detected else 0

    if json_output:
        payload = {
            "files_scanned": files_scanned,
            "matches": all_findings,
            "secrets_found": len(all_findings),
        }
        if ignored_by_baseline:
            payload["ignored_by_baseline"] = ignored_by_baseline
        print(json.dumps(payload, indent=2))
        return 1 if all_findings else 0

    print("SecretShield scan\n")

    for finding in all_findings:
        label, category = _kind_display(finding["kind"])
        print(f"\u2717 {finding['file']}:{finding['line']}")
        print(f"  Potential secret: {label}")
        print(f"  Type: {category}\n")

    if ignored_by_baseline:
        print(f"\u2713 {ignored_by_baseline} existing finding(s) ignored by baseline")

    if all_findings:
        print(f"\u2713 {files_scanned} files scanned")
        print(f"\u2717 {len(all_findings)} potential secret(s) found")
    else:
        print(f"\u2713 {files_scanned} files scanned")
        print("\u2713 No potential secrets found")

    exit_code = 1 if all_findings else 0
    print(f"\nExit code: {exit_code}")
    return exit_code


# --- `scan-staged` command (used by the pre-commit hook) ---------------------


def _cmd_scan_staged(args: argparse.Namespace) -> int:
    orig_stdout, orig_stderr = _temporarily_unwrap_streams()
    try:
        return _run_scan_staged(args)
    finally:
        sys.stdout, sys.stderr = orig_stdout, orig_stderr


def _run_scan_staged(args: argparse.Namespace) -> int:
    from .git import get_staged_content, get_staged_files, is_git_repo

    if not is_git_repo():
        print("secretshield: error: not inside a Git repository", file=sys.stderr)
        return 2

    print("SecretShield: scanning staged files...\n")

    findings: list[dict] = []
    for relpath in get_staged_files():
        path = Path(relpath)
        if not _should_scan_file(path, [], []):
            continue
        content = get_staged_content(relpath)
        if content is None:
            continue
        try:
            matches = detect(content, entropy_threshold=args.entropy_threshold)
        except Exception:
            continue
        for match in matches:
            if _is_placeholder(match.value):
                continue
            label, _category = _kind_display(match.kind)
            findings.append(
                {
                    "file": relpath,
                    "line": _line_number_for_offset(content, match.start),
                    "label": label,
                }
            )

    if not findings:
        print("\u2713 No secrets detected.")
        return 0

    for finding in findings:
        print("\u2717 Potential secret detected\n")
        print(f"File: {finding['file']}")
        print(f"Line: {finding['line']}")
        print(f"Type: {finding['label']}\n")

    print("Commit blocked.\n")
    print("Remove the secret from the staged changes and try again.")
    return 1


# --- `install-hook` / `uninstall-hook` commands -------------------------------


def _cmd_install_hook(args: argparse.Namespace) -> int:
    from .git import install_hook

    result = install_hook(force=args.force)
    if result.status == "error":
        print(f"secretshield: error: {result.message}", file=sys.stderr)
        return 1
    print(f"\u2713 {result.message}")
    return 0


def _cmd_uninstall_hook(args: argparse.Namespace) -> int:
    from .git import uninstall_hook

    result = uninstall_hook()
    if result.status == "error":
        print(f"secretshield: error: {result.message}", file=sys.stderr)
        return 1
    print(f"\u2713 {result.message}")
    return 0


# --- `github-action` command --------------------------------------------------


def _cmd_github_action(args: argparse.Namespace) -> int:
    from .github import generate_workflow

    written, path = generate_workflow(Path.cwd(), force=args.force)
    if not written:
        print(
            f"secretshield: {path} already exists. Use --force to overwrite.",
            file=sys.stderr,
        )
        return 1
    print(f"\u2713 Created {path}")
    return 0


# --- `init` command ------------------------------------------------------


def _prompt_yes_no(prompt: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input(f"{prompt} {suffix}: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def _cmd_init(args: argparse.Namespace) -> int:
    from .git import install_hook, is_git_repo
    from .github import generate_workflow
    from .project_config import find_config_file, render_default_toml

    try:
        interactive = sys.stdin.isatty()
    except Exception:
        interactive = False

    if not interactive:
        print("secretshield init requires an interactive terminal.")
        print("No setup was performed.")
        return 1

    project_root = Path.cwd()
    is_python_project = any(
        (project_root / marker).exists()
        for marker in ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt")
    )
    in_git_repo = is_git_repo()

    print("SecretShield project setup\n")
    print(f"{'\u2713' if is_python_project else '\u2717'} "
          f"{'Detected Python project' if is_python_project else 'No Python project markers found'}")
    print(f"{'\u2713' if in_git_repo else '\u2717'} "
          f"{'Detected Git repository' if in_git_repo else 'Not a Git repository'}")
    print()

    want_config = _prompt_yes_no("Create a secretshield.toml configuration file?", default=True)
    want_hook = False
    if in_git_repo:
        want_hook = _prompt_yes_no("Install Git pre-commit hook?", default=True)
    else:
        print("(Skipping pre-commit hook -- not a Git repository)")
    want_actions = _prompt_yes_no("Generate GitHub Actions workflow?", default=True)

    print()
    if not _prompt_yes_no("Apply this setup?", default=True):
        print("No changes were made.")
        return 0

    print()
    created: list[str] = []

    if want_config:
        existing = find_config_file(project_root)
        if existing is not None:
            print(f"\u2713 secretshield.toml already exists, leaving it unchanged")
        else:
            config_path = project_root / "secretshield.toml"
            config_path.write_text(render_default_toml(), encoding="utf-8")
            print(f"\u2713 Created {config_path.name}")
            created.append(config_path.name)

    if want_hook:
        result = install_hook()
        if result.status == "error":
            print(f"\u2717 {result.message}")
        else:
            print(f"\u2713 {result.message}")
            created.append("Git pre-commit hook")

    if want_actions:
        written, path = generate_workflow(project_root)
        if written:
            print(f"\u2713 Created {path.relative_to(project_root)}")
            created.append(str(path.relative_to(project_root)))
        else:
            print(f"\u2713 {path.relative_to(project_root)} already exists, leaving it unchanged")

    print("\nSecretShield is ready.")
    return 0


# --- argparse wiring -----------------------------------------------------


CREATOR_MESSAGE = "SecretShield\nCreated by Samarth Chugh (Sam3360)\ngithub.com/Sam3360"


class _CreatorAction(argparse.Action):
    """Prints creator info and exits -- mirrors argparse's built-in
    `action="version"` behavior so `--creator` works the same way
    `--version` does, with no subcommand required."""

    def __init__(self, option_strings, dest, nargs=0, **kwargs):
        super().__init__(option_strings, dest, nargs=nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print(CREATOR_MESSAGE)
        parser.exit()


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
    parser.add_argument(
        "--creator", action=_CreatorAction, help="Show who made this and exit."
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
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory).",
    )
    scan_parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=None,
        help="Shannon entropy threshold for generic secret detection (default: 4.2, "
        "or the value from secretshield.toml if present).",
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
    scan_parser.add_argument(
        "--fix",
        action="store_true",
        help=(
            "Interactively offer to move safely-transformable Python "
            "secrets into a local .env file. Requires an interactive "
            "terminal; never modifies files in a non-interactive "
            "environment such as CI."
        ),
    )
    scan_parser.add_argument(
        "--staged",
        action="store_true",
        help=(
            "Scan only Git-staged file contents (the actual index blob, "
            "correct even under partial staging) instead of a path. "
            "Answers: \"would this commit introduce a secret?\""
        ),
    )
    scan_parser.add_argument(
        "--diff",
        metavar="REF",
        default=None,
        help=(
            "Scan only files changed relative to REF (e.g. HEAD~1, "
            "origin/main...HEAD), reading their current on-disk content. "
            "Answers: \"did my changes introduce a secret?\""
        ),
    )
    scan_parser.add_argument(
        "--baseline",
        action="store_true",
        help=(
            "Write (or overwrite) .secretshield-baseline.json capturing "
            "every current finding. Future scans ignore anything already "
            "in the baseline and only fail on genuinely new findings."
        ),
    )
    scan_parser.set_defaults(func=_cmd_scan)

    scan_staged_parser = subparsers.add_parser(
        "scan-staged",
        help=(
            "Scan only Git-staged file contents (used internally by the "
            "pre-commit hook installed via `install-hook`)."
        ),
    )
    scan_staged_parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.2,
        help="Shannon entropy threshold for generic secret detection (default: 4.2).",
    )
    scan_staged_parser.set_defaults(func=_cmd_scan_staged)

    install_hook_parser = subparsers.add_parser(
        "install-hook",
        help="Install a Git pre-commit hook that blocks commits containing potential secrets.",
    )
    install_hook_parser.add_argument(
        "--force",
        action="store_true",
        help="Reinstall even if SecretShield's hook is already present.",
    )
    install_hook_parser.set_defaults(func=_cmd_install_hook)

    uninstall_hook_parser = subparsers.add_parser(
        "uninstall-hook",
        help="Remove the SecretShield Git pre-commit hook, restoring any hook it wrapped.",
    )
    uninstall_hook_parser.set_defaults(func=_cmd_uninstall_hook)

    github_action_parser = subparsers.add_parser(
        "github-action",
        help="Generate a GitHub Actions workflow that runs SecretShield on push/PR.",
    )
    github_action_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing workflow file if one is already present.",
    )
    github_action_parser.set_defaults(func=_cmd_github_action)

    init_parser = subparsers.add_parser(
        "init",
        help="Interactive setup: scanning config, Git hook, and GitHub Actions in one step.",
    )
    init_parser.set_defaults(func=_cmd_init)

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
