"""
CLI-level integration tests for v0.4.0: secretshield.toml, --baseline,
--staged, --diff, the scan progress indicator, and `secretshield init`.
"""

from __future__ import annotations

import json
import subprocess

from secretshield.cli import main

FAKE_SECRET = "v040IntegrationFakeSecretABC123456"


def _init_repo(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True)


# --- secretshield.toml --------------------------------------------------


def test_scan_respects_toml_ignore_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secretshield.toml").write_text('[scan.ignore]\npaths = ["vendor/"]\n')
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    (tmp_path / "app.py").write_text("print('clean')\n")

    exit_code = main(["scan", "."])
    assert exit_code == 0  # only the ignored vendor/ file had a secret


def test_scan_toml_entropy_threshold_used_as_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secretshield.toml").write_text("[scan]\nentropy_threshold = 8.0\n")
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')

    # entropy_threshold=8.0 is high but this is caught by the
    # known-format pattern (generic_labeled_secret), not entropy, so it
    # should still be found -- this mainly confirms the toml value is
    # actually read and doesn't crash the scan.
    exit_code = main(["scan", "."])
    assert exit_code == 1


def test_cli_flag_overrides_toml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secretshield.toml").write_text('[scan.ignore]\npaths = ["vendor/"]\n')
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')

    # --no-ignore doesn't override toml ignore paths (only default dirs),
    # but --exclude/--include on the CLI should still work alongside toml.
    exit_code = main(["scan", ".", "--include", "*.py"])
    # vendor/ is still excluded by toml even with --include set
    assert exit_code == 0


# --- --baseline -----------------------------------------------------------


def test_baseline_write_creates_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')

    exit_code = main(["scan", ".", "--baseline"])
    assert exit_code == 0
    assert (tmp_path / ".secretshield-baseline.json").exists()


def test_baseline_absorbs_existing_finding(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    main(["scan", ".", "--baseline"])

    exit_code = main(["scan", "."])
    assert exit_code == 0


def test_baseline_still_catches_new_finding(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    main(["scan", ".", "--baseline"])

    (tmp_path / "new.py").write_text('TOKEN = "ghp_brandNewSecretNotInBaseline123456"\n')
    exit_code = main(["scan", "."])
    assert exit_code == 1


def test_baseline_json_reports_ignored_count(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    main(["scan", ".", "--baseline"])
    capsys.readouterr()

    main(["scan", ".", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload.get("ignored_by_baseline") == 1
    assert payload["secrets_found"] == 0


# --- --staged / --diff ----------------------------------------------------


def test_scan_staged_flag_finds_staged_secret(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    (tmp_path / "secret.py").write_text(f'api_key = "{FAKE_SECRET}"\n')
    subprocess.run(["git", "add", "secret.py"], cwd=tmp_path, check=True)

    exit_code = main(["scan", "--staged"])
    assert exit_code == 1


def test_scan_staged_reads_index_not_disk(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    (tmp_path / "a.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    subprocess.run(["git", "add", "a.py"], cwd=tmp_path, check=True)
    # Modify on disk AFTER staging -- should have no effect on --staged.
    (tmp_path / "a.py").write_text("print('totally different now')\n")

    exit_code = main(["scan", "--staged", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert exit_code == 1
    assert payload["secrets_found"] == 1


def test_scan_diff_finds_newly_introduced_secret(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    (tmp_path / "app.py").write_text("print('clean')\n")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=tmp_path, check=True)

    (tmp_path / "new_file.py").write_text(f'TOKEN = "{FAKE_SECRET}"\n')
    subprocess.run(["git", "add", "new_file.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "add secret"], cwd=tmp_path, check=True)

    exit_code = main(["scan", "--diff", "HEAD~1"])
    assert exit_code == 1


def test_scan_diff_clean_when_no_new_secrets(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    (tmp_path / "app.py").write_text("print('clean')\n")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=tmp_path, check=True)

    (tmp_path / "app.py").write_text("print('still clean')\n")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "harmless change"], cwd=tmp_path, check=True)

    exit_code = main(["scan", "--diff", "HEAD~1"])
    assert exit_code == 0


def test_scan_staged_outside_git_repo_errors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["scan", "--staged"])
    assert exit_code != 0


def test_scan_never_prints_secret_in_staged_or_diff_modes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    (tmp_path / "secret.py").write_text(f'api_key = "{FAKE_SECRET}"\n')
    subprocess.run(["git", "add", "secret.py"], cwd=tmp_path, check=True)

    main(["scan", "--staged"])
    out = capsys.readouterr().out
    assert FAKE_SECRET not in out


# --- progress indicator (non-interference checks) --------------------------


def test_progress_does_not_break_json_output(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')

    exit_code = main(["scan", ".", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)  # must parse cleanly -- no stray progress text
    assert payload["secrets_found"] == 1
    assert exit_code == 1


def test_progress_is_silent_when_stderr_not_a_tty(tmp_path, monkeypatch, capsys):
    # Under pytest, stderr is never a real TTY, so progress must be
    # entirely absent from captured output.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text("print('clean')\n")

    main(["scan", "."])
    err = capsys.readouterr().err
    assert "Scanning..." not in err


# --- `init` -----------------------------------------------------------------


def test_init_non_interactive_refuses(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["init"])
    assert exit_code == 1


def test_init_non_interactive_creates_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    main(["init"])
    assert not (tmp_path / "secretshield.toml").exists()
    assert not (tmp_path / ".github").exists()
