"""CLI-level integration tests for .secretshieldignore."""

from __future__ import annotations

from secretshield.cli import main

FAKE_SECRET = "ignoreFileIntegrationFakeSecret123456"


def test_scan_respects_secretshieldignore(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshieldignore").write_text("vendor/\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    (tmp_path / "app.py").write_text("print('clean')\n")

    exit_code = main(["scan", "."])
    assert exit_code == 0


def test_scan_still_catches_non_ignored_secret(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshieldignore").write_text("vendor/\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text('API_KEY = "not-caught-anyway"\n')
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')

    exit_code = main(["scan", "."])
    assert exit_code == 1


def test_no_ignore_file_behaves_as_before(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')

    exit_code = main(["scan", "."])
    assert exit_code == 1


def test_secretshieldignore_and_toml_ignore_paths_combine(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshieldignore").write_text("vendor/\n")
    (tmp_path / "secretshield.toml").write_text('[scan.ignore]\npaths = ["docs/"]\n')
    (tmp_path / "vendor").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "vendor" / "a.py").write_text(f'A = "{FAKE_SECRET}"\n')
    (tmp_path / "docs" / "b.py").write_text(f'B = "{FAKE_SECRET}"\n')
    (tmp_path / "app.py").write_text("print('clean')\n")

    exit_code = main(["scan", "."])
    assert exit_code == 0


def test_explicit_exclude_flag_still_works_alongside_ignorefile(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshieldignore").write_text("vendor/\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "a.py").write_text(f'A = "{FAKE_SECRET}"\n')
    (tmp_path / "other.py").write_text(f'B = "{FAKE_SECRET}"\n')

    exit_code = main(["scan", ".", "--exclude", "other.py"])
    assert exit_code == 0
