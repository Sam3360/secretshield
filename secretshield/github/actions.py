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

# Opt-in variant (`secretshield github-action --sarif`): same scan, but the
# findings are also uploaded to GitHub Code Scanning as SARIF. Kept separate
# so the default workflow above is unchanged -- Code Scanning needs the
# `security-events: write` permission, and on private repositories GitHub
# Code Security (Advanced Security), so it must be a deliberate choice.
#
# The scan step exits 1 when it finds something, which fails the job as it
# always has; `if: always()` makes the upload run anyway so the alerts still
# reach GitHub. The hashFiles() guard skips the upload when the scan never
# produced a report (e.g. a scanner error), instead of failing on a missing
# file. Fork pull requests get a read-only token, so the upload step can't
# succeed there.
SARIF_WORKFLOW_TEMPLATE = """\
name: SecretShield

on:
  push:
  pull_request:

jobs:
  secretshield:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      security-events: write

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
        run: secretshield scan . --format sarif --output secretshield.sarif

      - name: Upload SARIF to GitHub Code Scanning
        if: ${{ always() && hashFiles('secretshield.sarif') != '' }}
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: secretshield.sarif
          category: secretshield
"""


def workflow_path(project_root: Path) -> Path:
    return project_root / ".github" / "workflows" / WORKFLOW_FILENAME


def generate_workflow(
    project_root: Path, force: bool = False, sarif: bool = False
) -> tuple[bool, Path]:
    """
    Write the SecretShield GitHub Actions workflow file.

    Returns (written, path). `written` is False (and nothing is touched)
    if the file already exists and `force` was not set. With `sarif=True`
    the workflow also uploads a SARIF report to GitHub Code Scanning (see
    SARIF_WORKFLOW_TEMPLATE); the default workflow is unchanged.
    """
    path = workflow_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists() and not force:
        return False, path

    path.write_text(
        SARIF_WORKFLOW_TEMPLATE if sarif else WORKFLOW_TEMPLATE, encoding="utf-8"
    )
    return True, path
