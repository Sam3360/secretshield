"""
Executes standalone/windows/installer-test-helpers.ps1 under real PowerShell.

The Windows lifecycle test (test-installer.ps1) simulates "a freshly opened
terminal" and asserts that `ss` and `secretshield` resolve to the INSTALLED copy.
It once failed on a CI runner because an unrelated SecretShield (pip's, from the
job's own `pip install -e .`) sat earlier on the PATH and legitimately won. The
helpers fix that by leaving other SecretShield folders out of the simulated PATH,
loudly, and by comparing canonical paths.

These tests need PowerShell 7 (`pwsh`), which GitHub's Ubuntu runners have, and
are skipped where it is missing. They run on any OS: tool files are created with
both the bare name (what PowerShell resolves on Linux/macOS) and a `.exe` name
(what Windows resolves and what the helper looks for).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WINDOWS = ROOT / "standalone" / "windows"
HELPERS = WINDOWS / "installer-test-helpers.ps1"
PWSH = shutil.which("pwsh")

pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell 7 (pwsh) is not installed")

SEP = os.pathsep


def q(value) -> str:
    """A PowerShell single-quoted string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def run_ps(body: str, env_extra: dict | None = None) -> str:
    script = (
        "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        f". {q(HELPERS)}\n{body}\n"
    )
    env = dict(os.environ, DOTNET_SYSTEM_GLOBALIZATION_INVARIANT="1", **(env_extra or {}))
    result = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=120, env=env,
    )  # fmt: skip
    assert result.returncode == 0, f"PowerShell failed:\n{result.stdout}\n{result.stderr}"
    return result.stdout


def run_json(body: str, env_extra: dict | None = None):
    out = run_ps(body, env_extra)
    return json.loads(out.strip().splitlines()[-1])


def make_tool(directory: Path, name: str) -> None:
    """Both spellings: the bare executable (Linux/macOS lookup) and name.exe (Windows lookup)."""
    directory.mkdir(parents=True, exist_ok=True)
    bare = directory / name
    bare.write_text("#!/bin/sh\nexit 0\n")
    bare.chmod(0o755)
    (directory / f"{name}.exe").write_text("MZ")


def exe(directory: Path, name: str) -> str:
    return str(directory / (f"{name}.exe" if os.name == "nt" else name))


@pytest.fixture
def dirs(tmp_path):
    ours, foreign, other = tmp_path / "ours", tmp_path / "pip Scripts", tmp_path / "other"
    for name in ("ss", "secretshield"):
        make_tool(ours, name)
        make_tool(foreign, name)
    other.mkdir()
    (other / "notss.exe").write_text("x")
    (other / "ss.txt").write_text("x")
    return {"ours": ours, "foreign": foreign, "other": other, "tmp": tmp_path}


def new_path(machine, user, own):
    body = (
        f"$r = Get-NewTerminalPath -MachinePath {q(machine)} -UserPath {q(user)} -OwnDir {q(own)}\n"
        "[pscustomobject]@{ Path = $r.Path; Foreign = @($r.Foreign); Entries = @($r.Entries) } | ConvertTo-Json -Compress"
    )
    return run_json(body)


# --- Which folders are "foreign" -----------------------------------------------------------------


def test_a_pip_style_copy_ahead_of_the_installed_one_is_left_out(dirs):
    machine = SEP.join([str(dirs["foreign"]), str(dirs["other"])])
    result = new_path(machine, str(dirs["ours"]), dirs["ours"])
    assert result["Foreign"] == [str(dirs["foreign"])]
    assert result["Path"] == SEP.join([str(dirs["other"]), str(dirs["ours"])]), "unrelated entries stay, in order"


def test_the_installed_folder_is_never_foreign_even_though_it_contains_the_commands(dirs):
    result = new_path(str(dirs["other"]), str(dirs["ours"]), dirs["ours"])
    assert result["Foreign"] == []
    assert str(dirs["ours"]) in result["Path"].split(SEP)


@pytest.mark.parametrize("spelling", ["{p}{sep}", "{p}/../ours", '"{p}"', "{p}{sep}{sep}"])
def test_the_installed_folder_is_recognised_in_any_spelling(dirs, spelling):
    own = str(dirs["ours"])
    entry = spelling.format(p=own, sep=os.sep)
    result = new_path(SEP.join([str(dirs["other"]), entry]), "", dirs["ours"])
    assert result["Foreign"] == [], f"{entry!r} is the installed folder"


def test_the_installed_folder_can_be_given_in_a_different_spelling_too(dirs):
    result = new_path(str(dirs["foreign"]), str(dirs["ours"]), f"{dirs['ours']}{os.sep}")
    assert result["Foreign"] == [str(dirs["foreign"])]
    result = new_path(str(dirs["foreign"]), str(dirs["ours"]).upper(), dirs["ours"])
    assert str(dirs["foreign"]) in result["Foreign"]


def test_detection_covers_both_names_and_every_pathext_extension(dirs):
    cmd_only, bat_only, secretshield_only = (dirs["tmp"] / n for n in ("cmd_only", "bat_only", "ss_only"))
    for d, fname in ((cmd_only, "ss.cmd"), (bat_only, "secretshield.bat"), (secretshield_only, "secretshield.exe")):
        d.mkdir()
        (d / fname).write_text("x")
    machine = SEP.join(str(d) for d in (cmd_only, bat_only, secretshield_only, dirs["other"]))
    result = new_path(machine, str(dirs["ours"]), dirs["ours"])
    assert sorted(result["Foreign"]) == sorted(str(d) for d in (cmd_only, bat_only, secretshield_only))
    assert str(dirs["other"]) in result["Path"].split(SEP)


def test_lookalike_files_and_directories_are_not_foreign(dirs):
    lookalike = dirs["tmp"] / "lookalike"
    (lookalike / "ss.exe").mkdir(parents=True)  # a DIRECTORY named like the program
    (lookalike / "ss.txt").write_text("x")
    (lookalike / "xss.exe").write_text("x")
    (lookalike / "secretshield-helper.exe").write_text("x")
    result = new_path(SEP.join([str(lookalike), str(dirs["other"])]), str(dirs["ours"]), dirs["ours"])
    assert result["Foreign"] == []


def test_nothing_foreign_keeps_the_path_exactly_as_it_was(dirs):
    machine = SEP.join([str(dirs["other"]), "/no/such/dir"])
    result = new_path(machine, str(dirs["ours"]), dirs["ours"])
    assert result["Foreign"] == []
    assert result["Path"] == SEP.join([str(dirs["other"]), "/no/such/dir", str(dirs["ours"])])


def test_blank_segments_are_dropped_and_unusable_entries_are_tolerated(dirs):
    machine = SEP.join(["", "   ", "<>|?*", str(dirs["other"]), "", "/no/such/dir"])
    result = new_path(machine, "", dirs["ours"])
    assert result["Foreign"] == []
    assert result["Entries"] == ["<>|?*", str(dirs["other"]), "/no/such/dir"]


def test_environment_variables_in_entries_are_expanded_for_detection_but_kept_verbatim(dirs):
    machine = SEP.join(["%SS_TEST_PIP_DIR%", str(dirs["other"])])
    body = (
        f"$r = Get-NewTerminalPath -MachinePath {q(machine)} -UserPath {q(dirs['ours'])} -OwnDir {q(dirs['ours'])}\n"
        "[pscustomobject]@{ Path = $r.Path; Foreign = @($r.Foreign) } | ConvertTo-Json -Compress"
    )
    result = run_json(body, {"SS_TEST_PIP_DIR": str(dirs["foreign"])})
    assert result["Foreign"] == ["%SS_TEST_PIP_DIR%"]
    assert "%SS_TEST_PIP_DIR%" not in result["Path"]


def test_a_quoted_entry_is_detected_and_removed_by_its_original_text(dirs):
    quoted = f'"{dirs["foreign"]}"'
    result = new_path(SEP.join([quoted, str(dirs["other"])]), str(dirs["ours"]), dirs["ours"])
    assert result["Foreign"] == [quoted]
    assert quoted not in result["Path"]


# --- Does the name resolve to the installed copy? ---------------------------------------------------


def resolve(path_entries, name, expected):
    body = (
        f"$env:PATH = {q(SEP.join(str(p) for p in path_entries))}\n"
        f"$r = Test-CommandResolvesTo {q(name)} {q(expected)}\n"
        "[pscustomobject]@{ Ok = [bool]$r.Ok; Found = @($r.Found); Detail = $r.Detail } | ConvertTo-Json -Compress"
    )
    return run_json(body)


def test_resolution_passes_when_the_installed_copy_is_first(dirs):
    result = resolve([dirs["ours"], dirs["foreign"]], "ss", exe(dirs["ours"], "ss"))
    assert result["Ok"] is True and result["Detail"] == ""


def test_resolution_fails_with_a_message_naming_what_won_when_another_copy_is_first(dirs):
    """This is the CI failure: the assertion was false and said nothing about why."""
    expected = exe(dirs["ours"], "ss")
    result = resolve([dirs["foreign"], dirs["other"], dirs["ours"]], "ss", expected)
    assert result["Ok"] is False
    assert result["Found"][0] == exe(dirs["foreign"], "ss")
    assert expected in result["Detail"] and exe(dirs["foreign"], "ss") in result["Detail"]
    after_resolves = result["Detail"].index("resolves")
    assert result["Detail"].index(exe(dirs["foreign"], "ss"), after_resolves) < result["Detail"].index(
        exe(dirs["ours"], "ss"), after_resolves
    ), "listed in PATH order"


def test_resolution_reports_a_missing_command_instead_of_throwing(dirs):
    result = resolve([dirs["other"]], "ss", exe(dirs["ours"], "ss"))
    assert result["Ok"] is False and result["Found"] == []
    assert "was not found on the PATH" in result["Detail"]


def test_resolution_compares_canonical_paths_not_spellings(dirs):
    odd = f"{dirs['other']}{os.sep}..{os.sep}ours"  # the same folder, spelled with ..
    result = resolve([odd], "ss", exe(dirs["ours"], "ss"))
    assert result["Ok"] is True, result


# --- The scenario that failed in CI, end to end ------------------------------------------------------


def test_the_ci_failure_before_and_after(dirs):
    expected = exe(dirs["ours"], "ss")
    machine = SEP.join([str(dirs["foreign"]), str(dirs["other"])])
    body = f"""
$env:PATH = {q(machine + SEP + str(dirs['ours']))}
$old = ((Get-Command ss -CommandType Application | Select-Object -First 1).Source) -ieq {q(expected)}
$null = Set-NewTerminalPath -OwnDir {q(dirs['ours'])} -MachinePath {q(machine)} -UserPath {q(dirs['ours'])}
$new = Test-CommandResolvesTo 'ss' {q(expected)}
$newSecret = Test-CommandResolvesTo 'secretshield' {q(exe(dirs['ours'], 'secretshield'))}
[pscustomobject]@{{ OldAssertion = [bool]$old; Ss = [bool]$new.Ok; Secretshield = [bool]$newSecret.Ok; Path = $env:PATH }} | ConvertTo-Json -Compress
"""
    result = run_json(body)
    assert result["OldAssertion"] is False, "premise: the old check really fails with a pip-style copy ahead"
    assert result["Ss"] is True and result["Secretshield"] is True
    assert str(dirs["foreign"]) not in result["Path"].split(SEP)


def test_set_new_terminal_path_applies_the_path_and_says_what_it_left_out(dirs):
    machine = SEP.join([str(dirs["foreign"]), str(dirs["other"])])
    out = run_ps(
        f"$r = Set-NewTerminalPath -OwnDir {q(dirs['ours'])} -MachinePath {q(machine)} -UserPath {q(dirs['ours'])}\n"
        "Write-Output ('RESULT=' + $env:PATH)\n"
    )
    assert f"RESULT={dirs['other']}{SEP}{dirs['ours']}" in out
    assert "ignoring another SecretShield" in out and str(dirs["foreign"]) in out
    assert "::warning::" in out


def test_set_new_terminal_path_is_silent_when_nothing_is_in_the_way(dirs):
    out = run_ps(
        f"$null = Set-NewTerminalPath -OwnDir {q(dirs['ours'])} -MachinePath {q(dirs['other'])} -UserPath {q(dirs['ours'])}\n"
    )
    assert "ignoring" not in out and "::warning::" not in out


# --- The scripts themselves ------------------------------------------------------------------------------


@pytest.mark.parametrize("script", ["test-installer.ps1", "installer-test-helpers.ps1", "build-installer.ps1"])
def test_every_installer_script_parses_with_the_real_powershell_parser(script):
    code = (
        "$tokens = $null; $errors = $null\n"
        f"[void][System.Management.Automation.Language.Parser]::ParseFile({q(WINDOWS / script)}, [ref]$tokens, [ref]$errors)\n"
        "$errors | ForEach-Object { 'line ' + $_.Extent.StartLineNumber + ': ' + $_.Message }\n"
        "exit $errors.Count"
    )
    env = dict(os.environ, DOTNET_SYSTEM_GLOBALIZATION_INVARIANT="1")
    result = subprocess.run([PWSH, "-NoProfile", "-Command", code], capture_output=True, text=True, env=env, timeout=60)
    assert result.returncode == 0, result.stdout


def test_the_lifecycle_script_keeps_its_assertion_and_uses_the_helpers():
    text = (WINDOWS / "test-installer.ps1").read_text(encoding="utf-8")
    assert "\"'$cmd' resolves to the installed copy$($resolution.Detail)\"" in text
    assert ". (Join-Path $PSScriptRoot 'installer-test-helpers.ps1')" in text
    assert "function Set-NewTerminalPath" not in text, "defined once, in the helper file"
    assert "Set-NewTerminalPath -OwnDir $installDir" in text
    assert "Test-CommandResolvesTo $cmd" in text
    helpers = HELPERS.read_text(encoding="utf-8")
    for fn in ("ConvertTo-CanonicalPath", "Get-ForeignCommandDirs", "Get-NewTerminalPath", "Set-NewTerminalPath", "Test-CommandResolvesTo"):
        assert f"function {fn}" in helpers, fn
