"""
CLI-level integration tests for the v0.3.0 subcommands: `github-action`,
`install-hook` / `uninstall-hook`, `scan-staged`, and `scan --fix`.

These exercise the commands through `main()` / `build_parser()` the way
a real user invocation would, on top of the lower-level unit tests in
test_github_action.py, test_git_hooks.py, and test_autofix.py.
"""

from __future__ import annotations

import subprocess

import pytest

from secretshield.cli import main

FAKE_SECRET = "cliIntegrationFakeSecretABC123456"


def _init_repo(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True)


def test_github_action_cli(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["github-action"])
    assert exit_code == 0
    assert (tmp_path / ".github" / "workflows" / "secretshield.yml").exists()


def test_github_action_cli_refuses_overwrite_without_force(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    main(["github-action"])
    exit_code = main(["github-action"])
    assert exit_code == 1


def test_github_action_cli_force_overwrites(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    main(["github-action"])
    exit_code = main(["github-action", "--force"])
    assert exit_code == 0


def test_install_hook_cli(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    exit_code = main(["install-hook"])
    assert exit_code == 0
    assert (tmp_path / ".git" / "hooks" / "pre-commit").exists()


def test_install_hook_cli_outside_git_repo_fails(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["install-hook"])
    assert exit_code == 1


def test_uninstall_hook_cli(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    main(["install-hook"])
    exit_code = main(["uninstall-hook"])
    assert exit_code == 0
    assert not (tmp_path / ".git" / "hooks" / "pre-commit").exists()


def test_scan_staged_cli_clean(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    (tmp_path / "clean.py").write_text("print('hello')\n")
    subprocess.run(["git", "add", "clean.py"], cwd=tmp_path, check=True)

    exit_code = main(["scan-staged"])
    assert exit_code == 0


def test_scan_staged_cli_blocks_secret(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    (tmp_path / "secret.py").write_text(f'api_key = "{FAKE_SECRET}"\n')
    subprocess.run(["git", "add", "secret.py"], cwd=tmp_path, check=True)

    exit_code = main(["scan-staged"])
    assert exit_code == 1


def test_scan_staged_cli_outside_git_repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["scan-staged"])
    assert exit_code == 2


def test_scan_staged_never_prints_secret_value(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    (tmp_path / "secret.py").write_text(f'api_key = "{FAKE_SECRET}"\n')
    subprocess.run(["git", "add", "secret.py"], cwd=tmp_path, check=True)

    main(["scan-staged"])
    out = capsys.readouterr().out
    assert FAKE_SECRET not in out


def test_real_git_commit_blocked_by_installed_hook(tmp_path, monkeypatch):
    """The strongest possible test: install the hook for real, then run
    an actual `git commit` and confirm it's genuinely blocked."""
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    main(["install-hook"])

    (tmp_path / "secret.py").write_text(f'api_key = "{FAKE_SECRET}"\n')
    subprocess.run(["git", "add", "secret.py"], cwd=tmp_path, check=True)

    result = subprocess.run(
        ["git", "commit", "-m", "adding secret"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0

    log = subprocess.run(
        ["git", "log", "--oneline"], cwd=tmp_path, capture_output=True, text=True
    )
    assert log.stdout.strip() == ""


def test_real_git_commit_succeeds_when_clean(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    main(["install-hook"])

    (tmp_path / "clean.py").write_text("print('hello')\n")
    subprocess.run(["git", "add", "clean.py"], cwd=tmp_path, check=True)

    result = subprocess.run(
        ["git", "commit", "-m", "clean commit"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0

    log = subprocess.run(
        ["git", "log", "--oneline"], cwd=tmp_path, capture_output=True, text=True
    )
    assert "clean commit" in log.stdout


def test_scan_fix_non_interactive_makes_no_changes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    original = (tmp_path / "app.py").read_text()

    # Under pytest/subprocess, stdin is never a real TTY -- this
    # exercises the same non-interactive safety path a CI run would hit.
    exit_code = main(["scan", str(tmp_path), "--fix"])
    assert (tmp_path / "app.py").read_text() == original
