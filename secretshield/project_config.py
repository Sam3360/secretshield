"""
Project-level configuration via a `secretshield.toml` file in the
current directory, read automatically by `secretshield scan`.

CLI flags always take precedence over the config file, which in turn
takes precedence over built-in defaults. Uses the standard-library
`tomllib` on Python 3.11+; on 3.10 it falls back to the small `tomli`
backport (declared as a conditional dependency in pyproject.toml, only
installed on 3.10) -- if neither is available, the config file is
silently skipped rather than crashing the scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover -- exercised only on 3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

CONFIG_FILENAME = "secretshield.toml"


@dataclass
class ProjectConfig:
    entropy_threshold: float | None = None
    ignore_paths: list[str] = field(default_factory=list)
    include_patterns: list[str] = field(default_factory=list)
    output_format: str | None = None  # "text" | "json"
    source_path: Path | None = None


def find_config_file(start: Path | None = None) -> Path | None:
    candidate = (start or Path.cwd()) / CONFIG_FILENAME
    return candidate if candidate.exists() else None


def load_project_config(start: Path | None = None) -> ProjectConfig:
    """
    Load `secretshield.toml` from `start` (default: current directory).
    Returns an all-None/empty ProjectConfig if the file doesn't exist,
    can't be parsed, or no TOML parser is available -- config-file
    support degrades gracefully rather than breaking the scan.
    """
    path = find_config_file(start)
    if path is None or tomllib is None:
        return ProjectConfig()

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return ProjectConfig()

    scan = data.get("scan", {}) if isinstance(data, dict) else {}
    ignore = scan.get("ignore", {}) if isinstance(scan, dict) else {}
    include = scan.get("include", {}) if isinstance(scan, dict) else {}
    output = data.get("output", {}) if isinstance(data, dict) else {}

    entropy = scan.get("entropy_threshold") if isinstance(scan, dict) else None
    try:
        entropy = float(entropy) if entropy is not None else None
    except (TypeError, ValueError):
        entropy = None

    return ProjectConfig(
        entropy_threshold=entropy,
        ignore_paths=[str(p) for p in ignore.get("paths", [])] if isinstance(ignore, dict) else [],
        include_patterns=[str(p) for p in include.get("patterns", [])]
        if isinstance(include, dict)
        else [],
        output_format=output.get("format") if isinstance(output, dict) else None,
        source_path=path,
    )


DEFAULT_TOML_TEMPLATE = """\
# SecretShield project configuration.
# CLI flags (--entropy-threshold, --include, --exclude, --json) always
# override these values. See:
# https://github.com/Sam3360/secretshield#configuration-file

[scan]
entropy_threshold = {entropy_threshold}

[scan.ignore]
paths = [
{ignore_paths}
]

[scan.include]
patterns = [
{include_patterns}
]

[output]
format = "text"
"""


def _toml_string_list(items: list[str]) -> str:
    if not items:
        return ""
    return ",\n".join(f'    "{item}"' for item in items) + ","


def render_default_toml(
    entropy_threshold: float = 4.2,
    ignore_paths: list[str] | None = None,
    include_patterns: list[str] | None = None,
) -> str:
    return DEFAULT_TOML_TEMPLATE.format(
        entropy_threshold=entropy_threshold,
        ignore_paths=_toml_string_list(ignore_paths or []),
        include_patterns=_toml_string_list(include_patterns or []),
    )
