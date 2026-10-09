"""
Generate a GitHub Actions workflow that runs SecretShield's static
scanner on every push and pull request.
"""

from __future__ import annotations

from pathlib import Path

WORKFLOW_FILENAME = "secretshield.yml"

WORKFLOW_TEMPLATE = """\
name: SecretShield

on:
  push:
  pull_request:

jobs:
  secretshield:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.x"

      - name: Install SecretShield
        run: python -m pip install secretshield

      - name: Scan repository
        run: secretshield scan .
"""


def workflow_path(project_root: Path) -> Path:
    return project_root / ".github" / "workflows" / WORKFLOW_FILENAME


def generate_workflow(project_root: Path, force: bool = False) -> tuple[bool, Path]:
    """
    Write the SecretShield GitHub Actions workflow file.

    Returns (written, path). `written` is False (and nothing is touched)
    if the file already exists and `force` was not set.
    """
    path = workflow_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists() and not force:
        return False, path

    path.write_text(WORKFLOW_TEMPLATE, encoding="utf-8")
    return True, path
