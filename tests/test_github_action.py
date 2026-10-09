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
