"""Tests for secretshield.github.actions -- GitHub Actions workflow generation."""

from __future__ import annotations

from pathlib import Path

from secretshield.github.actions import generate_workflow, workflow_path


def test_workflow_generated(tmp_path):
    written, path = generate_workflow(tmp_path)
    assert written is True
    assert path.exists()


def test_directory_automatically_created(tmp_path):
    assert not (tmp_path / ".github").exists()
    generate_workflow(tmp_path)
    assert (tmp_path / ".github" / "workflows").is_dir()


def test_existing_workflow_not_silently_overwritten(tmp_path):
    generate_workflow(tmp_path)
    path = workflow_path(tmp_path)
    path.write_text("# custom user content\n", encoding="utf-8")

    written, _ = generate_workflow(tmp_path)
    assert written is False
    assert path.read_text(encoding="utf-8") == "# custom user content\n"


def test_force_overwrites_existing_workflow(tmp_path):
    generate_workflow(tmp_path)
    path = workflow_path(tmp_path)
    path.write_text("# custom user content\n", encoding="utf-8")

    written, _ = generate_workflow(tmp_path, force=True)
    assert written is True
    assert "SecretShield" in path.read_text(encoding="utf-8")


def test_generated_workflow_installs_secretshield(tmp_path):
    generate_workflow(tmp_path)
    content = workflow_path(tmp_path).read_text(encoding="utf-8")
    assert "pip install secretshield" in content


def test_generated_workflow_runs_scan(tmp_path):
    generate_workflow(tmp_path)
    content = workflow_path(tmp_path).read_text(encoding="utf-8")
    assert "secretshield scan ." in content


def test_generated_workflow_runs_on_push_and_pr(tmp_path):
    generate_workflow(tmp_path)
    content = workflow_path(tmp_path).read_text(encoding="utf-8")
    assert "push:" in content
    assert "pull_request:" in content


# --- opt-in SARIF / Code Scanning workflow -------------------------------------


def test_default_workflow_does_not_upload_sarif(tmp_path):
    generate_workflow(tmp_path)
    content = workflow_path(tmp_path).read_text(encoding="utf-8")
    assert "sarif" not in content.lower()
    assert "security-events" not in content


def test_sarif_workflow_generated_on_request(tmp_path):
    written, path = generate_workflow(tmp_path, sarif=True)
    assert written is True
    content = path.read_text(encoding="utf-8")
    assert "secretshield scan . --format sarif --output secretshield.sarif" in content
    assert "github/codeql-action/upload-sarif@v4" in content
    assert "sarif_file: secretshield.sarif" in content


def test_sarif_workflow_requests_required_permissions(tmp_path):
    generate_workflow(tmp_path, sarif=True)
    content = workflow_path(tmp_path).read_text(encoding="utf-8")
    assert "security-events: write" in content
    assert "contents: read" in content


def test_sarif_workflow_uploads_even_when_scan_finds_secrets(tmp_path):
    generate_workflow(tmp_path, sarif=True)
    content = workflow_path(tmp_path).read_text(encoding="utf-8")
    assert "always()" in content
    assert "hashFiles('secretshield.sarif')" in content


def test_sarif_workflow_keeps_push_pr_triggers_and_install(tmp_path):
    generate_workflow(tmp_path, sarif=True)
    content = workflow_path(tmp_path).read_text(encoding="utf-8")
    assert "push:" in content and "pull_request:" in content
    assert "pip install secretshield" in content


def test_sarif_workflow_respects_existing_file_and_force(tmp_path):
    generate_workflow(tmp_path)
    original = workflow_path(tmp_path).read_text(encoding="utf-8")
    written, _ = generate_workflow(tmp_path, sarif=True)
    assert written is False
    assert workflow_path(tmp_path).read_text(encoding="utf-8") == original
    written, _ = generate_workflow(tmp_path, force=True, sarif=True)
    assert written is True
    assert "upload-sarif" in workflow_path(tmp_path).read_text(encoding="utf-8")


def test_github_action_cli_sarif_flag(tmp_path, monkeypatch):
    from secretshield.cli import main

    monkeypatch.chdir(tmp_path)
    assert main(["github-action", "--sarif"]) == 0
    assert "upload-sarif" in workflow_path(tmp_path).read_text(encoding="utf-8")


def test_github_action_cli_default_unchanged(tmp_path, monkeypatch):
    from secretshield.cli import main

    monkeypatch.chdir(tmp_path)
    assert main(["github-action"]) == 0
    assert "upload-sarif" not in workflow_path(tmp_path).read_text(encoding="utf-8")
