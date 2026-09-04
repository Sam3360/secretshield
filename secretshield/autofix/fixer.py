"""
Auto-Fix orchestration: the interactive `secretshield scan . --fix` flow.

Core principle: detect aggressively, modify conservatively. Every write
is validated after the fact, and any failure rolls the affected file
back to its original content rather than leaving a half-modified file.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..detector import detect
from . import python as pyfix
from .env import append_env_example_var, append_env_var, unique_env_key
from .gitignore import ensure_env_ignored

MASK = "********"


@dataclass
class FixSummary:
    detected: int = 0
    fixed: int = 0
    skipped: int = 0
    modified_files: list[str] = field(default_factory=list)
    touched_support_files: list[str] = field(default_factory=list)

    def add_modified_file(self, path: str) -> None:
        if path not in self.modified_files:
            self.modified_files.append(path)

    def add_touched_support_file(self, path: str) -> None:
        if path not in self.touched_support_files:
            self.touched_support_files.append(path)


def is_interactive() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


def mask(_value: str) -> str:
    # Always fully masked -- consistent with the rest of SecretShield's
    # "never partially reveal a secret" policy.
    return MASK


def _default_print(text: str = "") -> None:
    print(text)


def _default_input(prompt: str) -> str:
    return input(prompt)


def run_autofix(
    project_root: Path,
    findings_by_file: dict[str, list],
    entropy_threshold: float = 4.2,
    print_func: Callable[[str], None] = _default_print,
    input_func: Callable[[str], str] = _default_input,
) -> FixSummary:
    """
    Run the interactive Auto-Fix flow.

    `findings_by_file` maps a relative file path to a list of
    `secretshield.detector.Match` objects found in that file (already
    filtered for placeholders by the caller). Files are processed in
    sorted order for deterministic output.
    """
    summary = FixSummary()
    env_path = project_root / ".env"
    env_example_path = project_root / ".env.example"
    gitignore_path = project_root / ".gitignore"
    claimed_this_run: set[str] = set()

    if not is_interactive():
        print_func("Auto-fix requires an interactive terminal.")
        print_func("No automatic modifications were made.")
        for matches in findings_by_file.values():
            summary.detected += len(matches)
        summary.skipped = summary.detected
        return summary

    total = sum(len(m) for m in findings_by_file.values())
    index = 0

    for relpath in sorted(findings_by_file.keys()):
        matches = findings_by_file[relpath]
        summary.detected += len(matches)
        file_path = project_root / relpath
        suffix = file_path.suffix.lower()

        if suffix not in pyfix.SUPPORTED_FIX_EXTENSIONS:
            lang = pyfix.language_name_for(suffix, file_path.name)
            for _ in matches:
                index += 1
                print_func(f"\nSecret {index}/{total} detected")
                print_func(f"File: {relpath}")
                print_func(f"Type: possible secret\n")
                print_func(f"Automatic fixing is not currently supported for {lang}.")
                print_func("No changes were made.")
                summary.skipped += 1
            continue

        try:
            source = file_path.read_text(encoding="utf-8")
        except Exception:
            for _ in matches:
                index += 1
                summary.skipped += 1
                print_func(f"\nSecret {index}/{total} detected")
                print_func(f"File: {relpath}")
                print_func("Could not read this file for Auto-Fix. Skipped.")
            continue

        original_source = source

        lines = source.splitlines(keepends=True)

        def _line_at(text: str, offset: int) -> int:
            return text.count("\n", 0, offset) + 1

        # Determine up front whether any match on this file is a safe
        # assignment; if so (and import os is missing) insert it first.
        any_safe = False
        for m in matches:
            line_no = _line_at(source, m.start)
            if 1 <= line_no <= len(lines):
                if pyfix.find_safe_assignment(lines[line_no - 1], m.value):
                    any_safe = True
                    break

        if any_safe and not pyfix.has_import_os(source):
            source = pyfix.insert_import_os(source)

        # Re-scan the (possibly import-adjusted) source fresh, so line
        # numbers reflect the current content exactly.
        try:
            current_matches = detect(source, entropy_threshold=entropy_threshold)
        except Exception:
            current_matches = []

        file_modified = False
        rollback_needed = False

        for m in matches:
            index += 1
            # Find the corresponding current match by value (safest
            # correlation available -- values are stable across the
            # import-os insertion since that only affects earlier
            # lines' *numbers*, not the matched text itself).
            current = next((cm for cm in current_matches if cm.value == m.value), None)

            print_func(f"\nSecret {index}/{total} detected")
            print_func(f"File: {relpath}")
            if current is not None:
                line_no = _line_at(source, current.start)
                print_func(f"Line: {line_no}")
            print_func(f"Detected value: {mask(m.value)}")

            if current is None:
                print_func("This secret could no longer be located precisely. Skipped.")
                summary.skipped += 1
                continue

            lines = source.splitlines(keepends=True)
            line_no = _line_at(source, current.start)
            if not (1 <= line_no <= len(lines)):
                print_func("Could not safely locate this line. Skipped.")
                summary.skipped += 1
                continue

            safe = pyfix.find_safe_assignment(lines[line_no - 1], current.value)
            if safe is None:
                print_func(
                    "Secret detected, but SecretShield could not safely "
                    "determine how to replace it automatically."
                )
                print_func("No changes were made.")
                summary.skipped += 1
                continue

            answer = input_func(
                "Would you like me to move this secret to a local .env "
                "file automatically? [y/N] "
            ).strip().lower()
            if answer not in ("y", "yes"):
                print_func("Skipped.")
                summary.skipped += 1
                continue

            default_key = pyfix.suggest_env_var_name(safe.var_name)
            key = input_func(f"What environment variable name should be used? [{default_key}]: ").strip()
            if not key:
                key = default_key
            key = pyfix.suggest_env_var_name(key)
            key = unique_env_key(env_path, key, also_avoid=claimed_this_run)
            claimed_this_run.add(key)

            new_line = pyfix.build_getenv_line(safe.indent, safe.var_name, key, safe.quote)
            # Replace the *entire matched line*, not just the matched
            # span, so the whole assignment statement is cleanly
            # swapped out for the os.getenv() call.
            line_start = source.rfind("\n", 0, current.start) + 1
            line_end = source.find("\n", current.start)
            if line_end == -1:
                line_end = len(source)
            else:
                line_end += 1  # include the newline
            candidate_source = source[:line_start] + new_line + source[line_end:]

            try:
                append_env_var(env_path, key, safe.value)
                ensure_env_ignored(gitignore_path)
                append_env_example_var(env_example_path, key)
                file_path.write_text(candidate_source, encoding="utf-8")

                # Validation pass: the secret must be gone from the
                # source, and present in .env.
                revalidated = detect(candidate_source, entropy_threshold=entropy_threshold)
                still_present = any(rv.value == safe.value for rv in revalidated)
                env_contains_secret = safe.value in env_path.read_text(encoding="utf-8")

                if still_present or not env_contains_secret:
                    raise RuntimeError("validation failed")

            except Exception:
                # Roll the source file back; .env/.gitignore additions
                # are append-only and harmless to leave (they contain
                # no partial state), but the source must not be left
                # half-modified.
                try:
                    file_path.write_text(original_source, encoding="utf-8")
                except Exception:
                    pass
                print_func("\u2717 Auto-fix failed.")
                print_func("No partial changes were kept.")
                summary.skipped += 1
                continue

            source = candidate_source
            file_modified = True
            summary.fixed += 1
            summary.add_touched_support_file(str(env_path))
            summary.add_touched_support_file(str(gitignore_path))
            summary.add_touched_support_file(str(env_example_path))
            print_func(f"\u2713 Fixed (moved to .env as {key})")

        if file_modified:
            summary.add_modified_file(relpath)

    print_func("\nSecretShield Auto-Fix Summary")
    print_func("\u2500" * 30)
    print_func(f"\nDetected: {summary.detected}")
    print_func(f"Fixed: {summary.fixed}")
    print_func(f"Skipped: {summary.skipped}")
    if summary.modified_files:
        print_func("\nModified:")
        for f in summary.modified_files:
            print_func(f"  {f}")
    if summary.touched_support_files:
        print_func("\nCreated/updated:")
        for f in summary.touched_support_files:
            print_func(f"  {f}")

    return summary
