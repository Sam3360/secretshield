"""
Single source of truth for the release version, used by every standalone
build step (PyInstaller version resource, installer metadata, CI checks).

The version is *read* from ``secretshield/__init__.py`` without importing the
package (importing it would switch on runtime protection) and cross-checked
against ``pyproject.toml``, so the two can never drift unnoticed.

    python standalone/version.py              # print the version
    python standalone/version.py --check      # fail if sources disagree
    python standalone/version.py --tag v0.13.2   # fail if a tag doesn't match
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_PACKAGE_INIT = REPO_ROOT / "secretshield" / "__init__.py"
_PYPROJECT = REPO_ROOT / "pyproject.toml"
_LICENSE = REPO_ROOT / "LICENSE"


def read_package_version(init_file: Path = _PACKAGE_INIT) -> str:
    """``__version__`` from the package, parsed statically."""
    tree = ast.parse(init_file.read_text(encoding="utf-8"), filename=str(init_file))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__version__":
                    value = ast.literal_eval(node.value)
                    if isinstance(value, str):
                        return value
    raise ValueError(f"no literal __version__ found in {init_file}")


def read_pyproject_version(pyproject: Path = _PYPROJECT) -> str:
    """``[project] version`` from pyproject.toml (no TOML parser needed)."""
    in_project = False
    for line in pyproject.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_project = stripped == "[project]"
            continue
        if in_project:
            match = re.fullmatch(r'version\s*=\s*"([^"]+)"', stripped)
            if match:
                return match.group(1)
    raise ValueError(f"no [project] version found in {pyproject}")


def read_copyright(license_file: Path = _LICENSE) -> str:
    """The copyright line from the project's own LICENSE file."""
    for line in license_file.read_text(encoding="utf-8").splitlines():
        if line.lower().startswith("copyright"):
            return line.strip()
    raise ValueError(f"no copyright line found in {license_file}")


def numeric_tuple(version: str) -> tuple[int, int, int, int]:
    """``0.13.2`` -> ``(0, 13, 2, 0)`` for Windows version resources."""
    parts = [int(m) for m in re.findall(r"\d+", version.split("+")[0])][:4]
    parts += [0] * (4 - len(parts))
    return (parts[0], parts[1], parts[2], parts[3])


def problems(tag: str | None = None) -> list[str]:
    """Every version inconsistency found (empty list means all agree)."""
    found: list[str] = []
    package = read_package_version()
    pyproject = read_pyproject_version()
    if package != pyproject:
        found.append(
            f"secretshield/__init__.py says {package!r} but pyproject.toml says {pyproject!r}"
        )
    if tag:  # None or an empty string (an unset CI input) means "no tag to check"
        expected = tag[1:] if tag.startswith("v") else tag
        if expected != package:
            found.append(f"tag {tag!r} does not match package version {package!r}")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--check", action="store_true", help="fail if sources disagree")
    parser.add_argument("--tag", help="also fail if this git tag doesn't match the version")
    args = parser.parse_args(argv)
    if args.check or args.tag:
        issues = problems(args.tag)
        for issue in issues:
            print(f"version check failed: {issue}", file=sys.stderr)
        if issues:
            return 1
    print(read_package_version())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
