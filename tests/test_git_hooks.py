"""Tests for secretshield.git.hooks -- pre-commit hook install/uninstall."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from secretshield.git.hooks import (
    HOOK_MARKER,
    find_git_dir,
    get_staged_content,
    get_staged_files,
    install_hook,
    is_git_repo,
    uninstall_hook,
)


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_hook_installed_in_fresh_repo(repo):
    result = install_hook()
    assert result.status == "installed"
    hook_path = repo / ".git" / "hooks" / "pre-commit"
    assert hook_path.exists()
    assert HOOK_MARKER in hook_path.read_text()


def test_non_git_directory_handled_correctly(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # not a git repo
    assert is_git_repo() is False
    result = install_hook()
    assert result.status == "error"


def test_reinstall_without_force_reports_already_installed(repo):
    install_hook()
    result = install_hook()
    assert result.status == "already_installed"


def test_reinstall_with_force_succeeds(repo):
    install_hook()
    result = install_hook(force=True)
    assert result.status == "reinstalled"


def test_existing_foreign_hook_is_preserved_as_backup(repo):
    hook_path = repo / ".git" / "hooks" / "pre-commit"
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text("#!/bin/sh\necho custom-hook\n")

    result = install_hook()
    assert result.status == "wrapped_existing"

    backup = repo / ".git" / "hooks" / "pre-commit.secretshield-backup"
    assert backup.exists()
    assert "custom-hook" in backup.read_text()

    new_hook = hook_path.read_text()
    assert HOOK_MARKER in new_hook
    assert "pre-commit.secretshield-backup" in new_hook


def test_uninstall_restores_original_foreign_hook(repo):
    hook_path = repo / ".git" / "hooks" / "pre-commit"
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text("#!/bin/sh\necho custom-hook\n")

    install_hook()
    result = uninstall_hook()
    assert result.status == "restored_backup"
    assert "custom-hook" in hook_path.read_text()

    backup = repo / ".git" / "hooks" / "pre-commit.secretshield-backup"
    assert not backup.exists()


def test_uninstall_removes_hook_when_no_foreign_hook_existed(repo):
    install_hook()
    result = uninstall_hook()
    assert result.status == "removed"
    hook_path = repo / ".git" / "hooks" / "pre-commit"
    assert not hook_path.exists()


def test_uninstall_refuses_to_remove_unmanaged_hook(repo):
    hook_path = repo / ".git" / "hooks" / "pre-commit"
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text("#!/bin/sh\necho totally unmanaged\n")

    result = uninstall_hook()
    assert result.status == "error"
    assert "custom" not in hook_path.read_text() or "totally unmanaged" in hook_path.read_text()


def test_uninstall_on_missing_hook_reports_not_installed(repo):
    result = uninstall_hook()
    assert result.status == "not_installed"


def test_hook_file_is_executable(repo):
    install_hook()
    hook_path = repo / ".git" / "hooks" / "pre-commit"
    import os

    assert os.access(hook_path, os.X_OK)


def test_get_staged_files_lists_only_staged(repo):
    (repo / "a.txt").write_text("hello\n")
    (repo / "b.txt").write_text("world\n")
    subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)

    staged = get_staged_files()
    assert "a.txt" in staged
    assert "b.txt" not in staged


def test_get_staged_content_reads_index_not_working_tree(repo):
    (repo / "a.txt").write_text("staged-version\n")
    subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)
    # Modify working tree AFTER staging -- staged content should still
    # reflect what was actually added to the index.
    (repo / "a.txt").write_text("modified-after-staging\n")

    content = get_staged_content("a.txt")
    assert content == "staged-version\n"


def test_get_staged_content_returns_none_for_untracked_file(repo):
    content = get_staged_content("does-not-exist.txt")
    assert content is None
