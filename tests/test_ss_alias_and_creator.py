"""
Tests for v0.4.2: the `ss` short CLI alias and the `--creator` easter
egg. Both `ss` and `secretshield` are registered as separate console
scripts pointing to the exact same `secretshield.cli:main` function, so
most equivalence is tested by exercising `main()` directly; a couple of
tests also verify the actual installed executables behave identically.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

import pytest

from secretshield.cli import CREATOR_MESSAGE, build_parser, main

FAKE_SECRET = "ssAliasFakeSecretForTests123456789"


# --- --creator, via main() (fast, no subprocess) -----------------------------


def test_creator_flag_exits_zero():
    with pytest.raises(SystemExit) as exc_info:
        main(["--creator"])
    assert exc_info.value.code in (0, None)


def test_creator_flag_prints_expected_content(capsys):
    with pytest.raises(SystemExit):
        main(["--creator"])
    out = capsys.readouterr().out
    assert "Samarth Chugh (Sam3360)" in out
    assert "github.com/Sam3360" in out


def test_creator_message_constant_matches_requirements():
    assert "Samarth Chugh (Sam3360)" in CREATOR_MESSAGE
    assert "github.com/Sam3360" in CREATOR_MESSAGE


def test_creator_flag_is_not_overly_verbose():
    # Polished, not a wall of text.
    assert CREATOR_MESSAGE.count("\n") <= 3


def test_creator_works_regardless_of_subcommand_position():
    # --creator, like --version, should short-circuit before any
    # subcommand dispatch is required.
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--creator"])


# --- console scripts: both entry points exist and are wired identically ----


def test_pyproject_declares_both_console_scripts():
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:
        import tomli as tomllib  # Python 3.10 fallback

    with open("pyproject.toml", "rb") as f:
        data = tomllib.load(f)
    scripts = data["project"]["scripts"]
    assert scripts.get("secretshield") == "secretshield.cli:main"
    assert scripts.get("ss") == "secretshield.cli:main"


def _find_executable(name: str) -> str | None:
    return shutil.which(name)


@pytest.mark.skipif(
    _find_executable("ss") is None or _find_executable("secretshield") is None,
    reason="ss/secretshield not installed as real executables in this environment",
)
def test_installed_ss_and_secretshield_creator_output_match():
    result_full = subprocess.run(
        ["secretshield", "--creator"], capture_output=True, text=True
    )
    result_short = subprocess.run(["ss", "--creator"], capture_output=True, text=True)
    assert result_full.returncode == 0
    assert result_short.returncode == 0
    assert result_full.stdout == result_short.stdout


@pytest.mark.skipif(
    _find_executable("ss") is None or _find_executable("secretshield") is None,
    reason="ss/secretshield not installed as real executables in this environment",
)
def test_installed_ss_and_secretshield_version_match():
    result_full = subprocess.run(
        ["secretshield", "--version"], capture_output=True, text=True
    )
    result_short = subprocess.run(["ss", "--version"], capture_output=True, text=True)
    assert result_full.stdout == result_short.stdout


@pytest.mark.skipif(
    _find_executable("ss") is None or _find_executable("secretshield") is None,
    reason="ss/secretshield not installed as real executables in this environment",
)
def test_installed_ss_and_secretshield_help_match():
    result_full = subprocess.run(
        ["secretshield", "--help"], capture_output=True, text=True
    )
    result_short = subprocess.run(["ss", "--help"], capture_output=True, text=True)
    assert result_full.stdout == result_short.stdout


@pytest.mark.skipif(
    _find_executable("ss") is None or _find_executable("secretshield") is None,
    reason="ss/secretshield not installed as real executables in this environment",
)
def test_installed_ss_scan_behaves_like_secretshield_scan(tmp_path):
    (tmp_path / "app.py").write_text(f'API_KEY = "{FAKE_SECRET}"\n')

    result_full = subprocess.run(
        ["secretshield", "scan", str(tmp_path)], capture_output=True, text=True
    )
    result_short = subprocess.run(
        ["ss", "scan", str(tmp_path)], capture_output=True, text=True
    )
    assert result_full.returncode == result_short.returncode == 1
    assert result_full.stdout == result_short.stdout
    assert FAKE_SECRET not in result_full.stdout
    assert FAKE_SECRET not in result_short.stdout


# --- existing commands unaffected -------------------------------------------


def test_existing_scan_command_still_works_after_creator_addition(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    exit_code = main(["scan", str(app)])
    assert exit_code == 1


def test_version_flag_still_works():
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code in (0, None)
