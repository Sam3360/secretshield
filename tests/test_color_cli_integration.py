"""
CLI-level integration tests confirming colored output actually applies
(or doesn't) in `scan`'s real report, based on TTY status.
"""

from __future__ import annotations

import io

from secretshield.cli import main

FAKE_SECRET = "colorIntegrationFakeSecret123456789"


class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


def test_scan_output_has_no_ansi_codes_by_default_under_pytest(tmp_path, monkeypatch, capsys):
    # Under pytest, stdout is never a real TTY -- output must be plain.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')

    main(["scan", "."])
    out = capsys.readouterr().out
    assert "\033[" not in out


def test_scan_json_output_never_contains_ansi_codes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORCE_COLOR", "1")  # even if forced on, --json must stay clean
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')

    main(["scan", ".", "--json"])
    out = capsys.readouterr().out
    assert "\033[" not in out


def test_scan_with_force_color_env_produces_ansi_codes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORCE_COLOR", "1")
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')

    main(["scan", "."])
    out = capsys.readouterr().out
    assert "\033[31m" in out  # red for the finding


def test_scan_clean_with_force_color_produces_green(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORCE_COLOR", "1")
    (tmp_path / "app.py").write_text("print('clean')\n")

    main(["scan", "."])
    out = capsys.readouterr().out
    assert "\033[32m" in out  # green for "No potential secrets found"


def test_no_color_env_suppresses_even_with_force_color_tty(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')

    main(["scan", "."])
    out = capsys.readouterr().out
    assert "\033[" not in out
