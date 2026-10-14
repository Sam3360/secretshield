"""
`.secretshield-rules.toml` -- simple, project-local regex rules that
become additional detectors alongside SecretShield's built-in
patterns, automatically, for any project that has the file.

Deliberately minimal by design: a rule has a `name` and a `pattern`,
nothing else. No severity, no IDs, no capture-group logic, no path
filters -- see the project's USAGE.md for the reasoning. This module
only loads and compiles rules and runs them against already-loaded
text; everything else (scanning, ignoring, reporting, redaction,
Auto-Fix) is the existing SecretShield pipeline, unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover -- exercised only on 3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

from .detector import Match

RULES_FILENAME = ".secretshield-rules.toml"


@dataclass
class CustomRule:
    name: str
    pattern: str
    regex: re.Pattern


@dataclass
class RuleError:
    """A problem found while loading the rules file. `rule_index` and
    `name` are None for file-level errors (bad TOML, wrong shape)."""

    rule_index: int | None
    name: str | None
    message: str


def rules_file_path(root: Path) -> Path:
    return root / RULES_FILENAME


def load_custom_rules(root: Path | None = None) -> tuple[list[CustomRule], list[RuleError]]:
    """
    Load and compile custom rules from `.secretshield-rules.toml` in
    `root` (default: current directory).

    Returns `(rules, errors)`. A rule with a problem is skipped and
    recorded as an error rather than silently dropped or aborting the
    whole file -- one bad rule doesn't disable the rest. No file, an
    empty file, or an empty `rules` list all return `([], [])`, which
    is a valid, non-error state.
    """
    path = rules_file_path(root or Path.cwd())
    rules: list[CustomRule] = []
    errors: list[RuleError] = []

    if not path.exists():
        return rules, errors

    if tomllib is None:
        errors.append(
            RuleError(None, None, "No TOML parser available to read this file.")
        )
        return rules, errors

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception as exc:
        errors.append(RuleError(None, None, f"Invalid TOML: {exc}"))
        return rules, errors

    if not data:
        return rules, errors

    raw_rules = data.get("rules")
    if raw_rules is None:
        return rules, errors
    if not isinstance(raw_rules, list):
        errors.append(RuleError(None, None, '"rules" must be a list of [[rules]] tables.'))
        return rules, errors

    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            errors.append(RuleError(index, None, "Each rule must be a [[rules]] table."))
            continue

        name = raw.get("name")
        if not name or not isinstance(name, str):
            errors.append(RuleError(index, None, 'Missing or invalid "name".'))
            continue

        pattern = raw.get("pattern")
        if not pattern or not isinstance(pattern, str):
            errors.append(RuleError(index, name, 'Missing or invalid "pattern".'))
            continue

        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            errors.append(RuleError(index, name, f"Invalid regular expression: {exc}"))
            continue

        rules.append(CustomRule(name=name, pattern=pattern, regex=compiled))

    return rules, errors


def scan_text_with_rules(text: str, rules: list[CustomRule]) -> list[Match]:
    """
    Run custom rules against already-loaded text, returning
    `secretshield.detector.Match` objects -- the same shape built-in
    detection produces. `kind` is set to the rule's own name, so a
    custom-rule finding flows through the existing finding/report/
    JSON/--fix pipeline with no separate output system: it's
    identified simply by its name, e.g. "My API Key".
    """
    if not text or not rules:
        return []
    matches: list[Match] = []
    for rule in rules:
        for m in rule.regex.finditer(text):
            value = m.group(0)
            if not value:
                continue
            matches.append(Match(start=m.start(), end=m.end(), value=value, kind=rule.name))
    return matches


def append_rule(path: Path, name: str, pattern: str) -> None:
    """
    Append a new `[[rules]]` block to `path`, creating it if it
    doesn't exist. Never rewrites or reformats whatever's already
    there -- existing rules (and any manual edits) are preserved
    byte-for-byte, the same append-only convention used elsewhere in
    SecretShield (.env, .gitignore, .secretshieldignore).
    """

    def _toml_string(s: str) -> str:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    block = f"[[rules]]\nname = {_toml_string(name)}\npattern = {_toml_string(pattern)}\n"

    prefix = ""
    if path.exists():
        existing = path.read_text(encoding="utf-8", errors="ignore")
        if existing and not existing.endswith("\n"):
            prefix = "\n"

    with open(path, "a", encoding="utf-8", newline="") as f:
        f.write(f"{prefix}{block}")
