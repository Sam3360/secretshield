"""
CLI-level tests for `secretshield scan --format sarif [--output FILE]`:
report content, exit codes, error handling, secret redaction, and
compatibility with ignore rules, baselines, configuration, custom rules,
`--staged`/`--diff`, JSON/text output, and the `ss` entry point.

All secrets used here are fake / non-functional.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys

import pytest

from secretshield.cli import main

FAKE_OPENAI_KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz1234567890"
FAKE_GITHUB_TOKEN = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLQ"
FAKE_PASSWORD = "MyDogFluffy99"
FAKE_CUSTOM = "MYAPP_12345678901234567890123456789012"
FAKE_PRIVATE_KEY_BODY = "MIIEowIBAAKCAQEAxyz123abcDEF456ghi789jkl"
FAKE_PRIVATE_KEY = (
    "-----BEGIN " + "RSA PRIVATE KEY-----\n"
    + FAKE_PRIVATE_KEY_BODY + "\n"
    + "QWERTYuiopASDFGhjklZXCVbnm0123456789abcd\n"
    + "-----END " + "RSA PRIVATE KEY-----"
)

ALL_FAKE_VALUES = [
    FAKE_OPENAI_KEY, FAKE_GITHUB_TOKEN, FAKE_AWS_KEY, FAKE_PASSWORD,
    FAKE_CUSTOM, FAKE_PRIVATE_KEY_BODY,
]


def _init_repo(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True)


def _scan(args, capsys):
    exit_code = main(["scan", *args])
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def _results(log):
    return log["runs"][0]["results"]


def _uris(log):
    return [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in _results(log)]


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        f'import os\n\n    api_key = "{FAKE_OPENAI_KEY}"\n'
    )
    (tmp_path / "deploy.sh").write_text(f'export TOKEN="{FAKE_GITHUB_TOKEN}"\n')
    (tmp_path / "creds.txt").write_text(f"intro\n  {FAKE_PRIVATE_KEY}\nend\n")
    (tmp_path / "config.yaml").write_text(f'password: "{FAKE_PASSWORD}"\nid: {FAKE_AWS_KEY}\n')
    (tmp_path / "clean.py").write_text("print('nothing secret here')\n")
    return tmp_path


# --- basic generation ---------------------------------------------------------------


def test_sarif_to_stdout_is_valid_json_with_findings(project, capsys):
    exit_code, out, _ = _scan([".", "--format", "sarif"], capsys)
    log = json.loads(out)
    assert exit_code == 1
    assert log["version"] == "2.1.0"
    assert len(_results(log)) >= 4


def test_sarif_to_file_writes_report_and_confirms_on_stdout(project, capsys):
    exit_code, out, err = _scan([".", "--format", "sarif", "--output", "secretshield.sarif"], capsys)
    assert exit_code == 1
    assert err == ""
    assert "SARIF report written to secretshield.sarif" in out
    log = json.loads((project / "secretshield.sarif").read_text(encoding="utf-8"))
    assert log["version"] == "2.1.0"
    assert _results(log)


def test_documented_command_via_main_matches_stdout_mode(project, capsys):
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    _scan([".", "--format", "sarif", "--output", "secretshield.sarif"], capsys)
    assert (project / "secretshield.sarif").read_text(encoding="utf-8") == out


def test_output_creates_missing_parent_directories(project, capsys):
    exit_code, _, _ = _scan([".", "--format", "sarif", "--output", "reports/nested/ss.sarif"], capsys)
    assert exit_code == 1
    assert (project / "reports" / "nested" / "ss.sarif").is_file()


def test_output_overwrites_existing_file(project, capsys):
    (project / "ss.sarif").write_text("stale")
    _scan([".", "--format", "sarif", "--output", "ss.sarif"], capsys)
    assert json.loads((project / "ss.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_file_locations_rule_ids_and_levels(project, capsys):
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    log = json.loads(out)
    by_uri = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: r for r in _results(log)}

    app = by_uri["src/app.py"]
    assert app["ruleId"] == "secretshield.openai_api_key"
    assert app["level"] == "error"
    # `    api_key = "<key>"` -> key starts at column 16, spans 39 chars.
    assert app["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 3, "startColumn": 16, "endLine": 3, "endColumn": 55,
    }
    assert by_uri["deploy.sh"]["ruleId"] == "secretshield.github_token"
    assert by_uri["deploy.sh"]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_multiline_private_key_region(project, capsys):
    _, out, _ = _scan(["creds.txt", "--format", "sarif"], capsys)
    (result,) = _results(json.loads(out))
    assert result["ruleId"] == "secretshield.private_key_block"
    assert result["level"] == "error"
    region = result["locations"][0]["physicalLocation"]["region"]
    # Starts on line 2 (after two leading spaces), ends after the END line (line 5).
    assert (region["startLine"], region["startColumn"]) == (2, 3)
    assert region["endLine"] == 5
    assert region["endColumn"] == len("-----END RSA PRIVATE KEY-----") + 1


def test_utf16_column_after_astral_character(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "u.py").write_text(f'x = "\U0001F600" + "{FAKE_OPENAI_KEY}"\n', encoding="utf-8")
    _, out, _ = _scan(["u.py", "--format", "sarif"], capsys)
    region = _results(json.loads(out))[0]["locations"][0]["physicalLocation"]["region"]
    # `x = "` (5) + emoji (2 UTF-16 units) + `" + "` (5) -> key starts at column 13.
    assert region["startColumn"] == 13


def test_uris_are_repo_relative_and_percent_encoded(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "my dir" / "d\u00e9p"
    folder.mkdir(parents=True)
    (folder / "a#b.py").write_text(f'k = "{FAKE_OPENAI_KEY}"\n')
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    assert _uris(json.loads(out)) == ["my%20dir/d%C3%A9p/a%23b.py"]


def test_absolute_scan_target_outside_cwd_uses_file_uri(tmp_path, monkeypatch, capsys):
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text(f'k = "{FAKE_OPENAI_KEY}"\n')
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    _, out, _ = _scan([str(target), "--format", "sarif"], capsys)
    (uri,) = _uris(json.loads(out))
    assert uri.startswith("file:///") and uri.endswith("/target/a.py")


def test_output_is_deterministic_across_runs(project, capsys):
    _, first, _ = _scan([".", "--format", "sarif"], capsys)
    _, second, _ = _scan([".", "--format", "sarif"], capsys)
    assert first == second
    uris = _uris(json.loads(first))
    assert uris == sorted(uris)


def test_report_scan_counts_recorded(project, capsys):
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    props = json.loads(out)["runs"][0]["invocations"][0]["properties"]
    assert props["filesScanned"] == 5


# --- empty results ------------------------------------------------------------------------


def test_no_findings_exits_zero_with_valid_empty_report(project, capsys):
    exit_code, out, _ = _scan(["clean.py", "--format", "sarif"], capsys)
    log = json.loads(out)
    assert exit_code == 0
    assert _results(log) == []
    assert log["runs"][0]["tool"]["driver"]["rules"]


def test_empty_directory_with_output_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "empty").mkdir()
    exit_code, out, _ = _scan(["empty", "--format", "sarif", "--output", "e.sarif"], capsys)
    assert exit_code == 0
    assert "0 finding(s)" in out
    assert _results(json.loads((tmp_path / "e.sarif").read_text(encoding="utf-8"))) == []


# --- redaction ---------------------------------------------------------------------------------


def _assert_no_secret_material(text):
    for value in ALL_FAKE_VALUES:
        assert value not in text
        # Not even a meaningful fragment of the value.
        assert value[:10] not in text
        assert value[-10:] not in text
    assert "BEGIN RSA PRIVATE KEY" not in text


def test_no_secret_values_in_stdout_report(project, capsys):
    _, out, err = _scan([".", "--format", "sarif"], capsys)
    _assert_no_secret_material(out)
    _assert_no_secret_material(err)


def test_no_secret_values_in_output_file_or_console(project, capsys):
    _, out, err = _scan([".", "--format", "sarif", "--output", "r.sarif"], capsys)
    _assert_no_secret_material((project / "r.sarif").read_text(encoding="utf-8"))
    _assert_no_secret_material(out)
    _assert_no_secret_material(err)


def test_no_secret_values_with_custom_rules(project, capsys):
    (project / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    (project / "c.py").write_text(f'v = "{FAKE_CUSTOM}"\n')
    _, out, err = _scan([".", "--format", "sarif"], capsys)
    assert "secretshield.custom.my-api-key" in out
    _assert_no_secret_material(out)
    _assert_no_secret_material(err)


def test_no_secret_values_in_error_output(project, capsys):
    blocker = project / "blocker"
    blocker.mkdir()
    exit_code, out, err = _scan([".", "--format", "sarif", "--output", "blocker"], capsys)
    assert exit_code == 2
    _assert_no_secret_material(out)
    _assert_no_secret_material(err)


def test_report_contains_no_source_line_content(project, capsys):
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    for line_fragment in ('api_key = ', "export TOKEN", "password: ", "import os", "intro"):
        assert line_fragment not in out
    assert "snippet" not in out


def test_no_value_derived_hashes_in_report(project, capsys):
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    assert not re.search(r"\b[0-9a-f]{64}\b", out)


def test_real_process_stdout_not_mangled_by_live_redaction(project):
    # In a real process secretshield's runtime protection wraps stdout; the
    # report must still come through intact (no "********" substitutions).
    proc = subprocess.run(
        [sys.executable, "-m", "secretshield.cli", "scan", ".", "--format", "sarif"],
        cwd=project, capture_output=True, text=True,
    )
    assert proc.returncode == 1
    assert "********" not in proc.stdout
    log = json.loads(proc.stdout)
    assert len(_results(log)) >= 4
    _assert_no_secret_material(proc.stdout)
    _assert_no_secret_material(proc.stderr)


# --- error handling -------------------------------------------------------------------------------


def test_output_without_format_is_an_error(project, capsys):
    exit_code, out, err = _scan([".", "--output", "r.sarif"], capsys)
    assert exit_code == 2
    assert "--output requires --format" in err
    assert not (project / "r.sarif").exists()


def test_output_with_explicit_text_format_is_an_error(project, capsys):
    exit_code, _, err = _scan([".", "--format", "text", "--output", "r.txt"], capsys)
    assert exit_code == 2
    assert "--output requires" in err


def test_unwritable_output_path_reports_error_and_exits_2(project, capsys):
    (project / "adir").mkdir()
    exit_code, out, err = _scan([".", "--format", "sarif", "--output", "adir"], capsys)
    assert exit_code == 2
    assert "could not write SARIF report to adir" in err
    assert "written" not in out


def test_output_parent_is_a_file_reports_error(project, capsys):
    (project / "afile").write_text("x")
    exit_code, _, err = _scan([".", "--format", "sarif", "--output", "afile/r.sarif"], capsys)
    assert exit_code == 2
    assert "could not write SARIF report" in err


def test_json_flag_conflicting_with_sarif_format_is_an_error(project, capsys):
    exit_code, _, err = _scan([".", "--json", "--format", "sarif"], capsys)
    assert exit_code == 2
    assert "--json conflicts with --format sarif" in err


def test_json_flag_with_matching_format_is_fine(project, capsys):
    exit_code, out, _ = _scan([".", "--json", "--format", "json"], capsys)
    assert exit_code == 1
    assert "secrets_found" in json.loads(out)


def test_unknown_format_rejected_by_argparse(project, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", ".", "--format", "xml"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--fix", "--baseline"])
def test_fix_and_baseline_cannot_combine_with_sarif(project, capsys, flag):
    exit_code, _, err = _scan([".", "--format", "sarif", flag], capsys)
    assert exit_code == 2
    assert f"{flag} cannot be combined" in err
    assert not (project / ".secretshield-baseline.json").exists()


def test_missing_scan_path_still_errors_and_writes_no_report(project, capsys):
    exit_code, out, err = _scan(["nope", "--format", "sarif", "--output", "r.sarif"], capsys)
    assert exit_code == 1
    assert "no such path" in err
    assert not (project / "r.sarif").exists()


def test_staged_outside_git_repo_errors_without_report(project, capsys):
    exit_code, _, err = _scan(["--staged", "--format", "sarif", "--output", "r.sarif"], capsys)
    assert exit_code == 2
    assert "not inside a Git repository" in err
    assert not (project / "r.sarif").exists()


# --- existing behavior preserved ------------------------------------------------------------------------


def test_default_text_output_unchanged(project, capsys):
    exit_code, out, _ = _scan(["."], capsys)
    assert exit_code == 1
    assert out.startswith("SecretShield scan")
    assert "Potential secret:" in out
    assert "$schema" not in out


def test_json_output_unchanged_and_has_no_sarif_fields(project, capsys):
    exit_code, out, _ = _scan([".", "--json"], capsys)
    payload = json.loads(out)
    assert exit_code == 1
    assert set(payload) == {"files_scanned", "matches", "secrets_found"}
    assert set(payload["matches"][0]) == {"file", "line", "kind"}


def test_json_output_to_file(project, capsys):
    exit_code, out, _ = _scan([".", "--format", "json", "--output", "r.json"], capsys)
    assert exit_code == 1
    assert "JSON report written to r.json" in out
    assert json.loads((project / "r.json").read_text(encoding="utf-8"))["secrets_found"] >= 4


def test_sarif_and_json_report_the_same_findings(project, capsys):
    _, json_out, _ = _scan([".", "--json"], capsys)
    _, sarif_out, _ = _scan([".", "--format", "sarif"], capsys)
    json_set = sorted((m["file"], m["line"]) for m in json.loads(json_out)["matches"])
    sarif_set = sorted(
        (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in _results(json.loads(sarif_out))
    )
    assert json_set == sarif_set


def test_text_scan_exit_codes_unchanged(project, capsys):
    assert main(["scan", "clean.py"]) == 0
    assert main(["scan", "."]) == 1


def test_scan_help_documents_new_flags(capsys):
    with pytest.raises(SystemExit):
        main(["scan", "--help"])
    out = capsys.readouterr().out
    assert "--format" in out and "sarif" in out and "--output" in out


# --- compatibility: ignore rules, include/exclude, defaults --------------------------------------------------------


def test_secretshieldignore_respected(project, capsys):
    (project / ".secretshieldignore").write_text("deploy.sh\nsrc/\n")
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    uris = _uris(json.loads(out))
    assert "deploy.sh" not in uris
    assert "src/app.py" not in uris
    assert "creds.txt" in uris


def test_toml_ignore_paths_respected(project, capsys):
    (project / "secretshield.toml").write_text('[scan.ignore]\npaths = ["src/"]\n')
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    assert "src/app.py" not in _uris(json.loads(out))


def test_exclude_and_include_flags_respected(project, capsys):
    _, out, _ = _scan([".", "--format", "sarif", "--exclude", "*.sh"], capsys)
    assert "deploy.sh" not in _uris(json.loads(out))
    _, out, _ = _scan([".", "--format", "sarif", "--include", "*.sh"], capsys)
    assert _uris(json.loads(out)) == ["deploy.sh"]


def test_default_ignored_directories_skipped_and_no_ignore_restores(project, capsys):
    (project / "node_modules").mkdir()
    (project / "node_modules" / "lib.js").write_text(f'const t = "{FAKE_GITHUB_TOKEN}";\n')
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    assert not any(u.startswith("node_modules") for u in _uris(json.loads(out)))
    _, out, _ = _scan([".", "--format", "sarif", "--no-ignore"], capsys)
    assert any(u.startswith("node_modules") for u in _uris(json.loads(out)))


def test_placeholder_values_not_reported(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.py").write_text('api_key = "your_api_key_here"\n')
    exit_code, out, _ = _scan([".", "--format", "sarif"], capsys)
    assert exit_code == 0
    assert _results(json.loads(out)) == []


def test_entropy_threshold_flag_applies(project, capsys):
    (project / "e.py").write_text('v = "aX9pQ2zM7vL0rT4wK8yB1nD6fH3jC5sE"\n')
    _, default_out, _ = _scan(["e.py", "--format", "sarif"], capsys)
    _, strict_out, _ = _scan(["e.py", "--format", "sarif", "--entropy-threshold", "6.5"], capsys)
    assert len(_results(json.loads(default_out))) == 1
    assert _results(json.loads(strict_out)) == []


def test_report_file_is_not_rescanned_on_next_scan(project, capsys):
    _scan([".", "--format", "sarif", "--output", "secretshield.sarif"], capsys)
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    assert "secretshield.sarif" not in _uris(json.loads(out))


# --- compatibility: baseline ---------------------------------------------------------------------------------------


def test_baselined_findings_excluded_and_counted(project, capsys):
    assert main(["scan", ".", "--baseline"]) == 0
    capsys.readouterr()
    exit_code, out, _ = _scan([".", "--format", "sarif"], capsys)
    log = json.loads(out)
    assert exit_code == 0
    assert _results(log) == []
    assert log["runs"][0]["invocations"][0]["properties"]["ignoredByBaseline"] >= 4


def test_new_finding_after_baseline_is_reported(project, capsys):
    main(["scan", ".", "--baseline"])
    capsys.readouterr()
    (project / "new.py").write_text(f'k = "{FAKE_GITHUB_TOKEN}"\n')
    exit_code, out, _ = _scan([".", "--format", "sarif"], capsys)
    assert exit_code == 1
    assert _uris(json.loads(out)) == ["new.py"]


def test_baseline_file_itself_is_not_in_report(project, capsys):
    main(["scan", ".", "--baseline"])
    capsys.readouterr()
    _, out, _ = _scan([".", "--format", "sarif", "--no-ignore"], capsys)
    assert not any("baseline" in u for u in _uris(json.loads(out)))


# --- compatibility: configuration ---------------------------------------------------------------------------------------


def test_config_output_format_sarif_is_honored(project, capsys):
    (project / "secretshield.toml").write_text('[output]\nformat = "sarif"\n')
    _, out, _ = _scan([".", "--entropy-threshold", "4.2"], capsys)
    assert json.loads(out)["version"] == "2.1.0"


def test_cli_format_overrides_config_format(project, capsys):
    (project / "secretshield.toml").write_text('[output]\nformat = "json"\n')
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    assert json.loads(out)["version"] == "2.1.0"
    _, out, _ = _scan([".", "--format", "text"], capsys)
    assert out.startswith("SecretShield scan")


def test_config_json_still_works_without_flags(project, capsys):
    (project / "secretshield.toml").write_text('[output]\nformat = "json"\n')
    _, out, _ = _scan(["."], capsys)
    assert "secrets_found" in json.loads(out)


def test_unknown_config_format_falls_back_to_text(project, capsys):
    (project / "secretshield.toml").write_text('[output]\nformat = "xml"\n')
    _, out, _ = _scan(["."], capsys)
    assert out.startswith("SecretShield scan")


def test_config_sarif_with_fix_keeps_existing_fix_precedence(project, monkeypatch):
    # A config-level format never blocks --fix (same as config-level json);
    # only an explicit --format sarif / --output conflicts with it.
    (project / "secretshield.toml").write_text('[output]\nformat = "sarif"\n')
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["scan", ".", "--fix"]) in (0, 1)


# --- compatibility: custom rules ---------------------------------------------------------------------------------------------


def test_custom_rule_findings_and_rule_metadata(project, capsys):
    (project / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
        '[[rules]]\nname = "Never Matches"\npattern = "ZZZNOPE"\n'
    )
    (project / "c.py").write_text(f'v = "{FAKE_CUSTOM}"\n')
    _, out, _ = _scan(["c.py", "--format", "sarif"], capsys)
    log = json.loads(out)
    (result,) = _results(log)
    assert result["ruleId"] == "secretshield.custom.my-api-key"
    assert result["level"] == "error"
    rule_ids = {r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]}
    assert {"secretshield.custom.my-api-key", "secretshield.custom.never-matches"} <= rule_ids


def test_custom_rule_name_with_special_characters_stays_valid_json(project, capsys):
    (project / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Q \\"x\\" \\\\ <b> \\u00e9"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    (project / "c.py").write_text(f'v = "{FAKE_CUSTOM}"\n')
    _, out, _ = _scan(["c.py", "--format", "sarif"], capsys)
    log = json.loads(out)
    assert 'Q "x" \\ <b> \u00e9' in log["runs"][0]["tool"]["driver"]["rules"][-1]["name"]
    assert out.isascii()


def test_broken_custom_rule_warning_goes_to_stderr_not_report(project, capsys):
    (project / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Bad"\npattern = "("\n'
    )
    _, out, err = _scan(["clean.py", "--format", "sarif"], capsys)
    assert "invalid custom rule" in err
    json.loads(out)  # stdout is still pure SARIF


def test_rules_file_itself_not_reported(project, capsys):
    (project / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "R"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    _, out, _ = _scan([".", "--format", "sarif"], capsys)
    assert ".secretshield-rules.toml" not in _uris(json.loads(out))


# --- compatibility: --staged / --diff ---------------------------------------------------------------------------------------------


def test_staged_scan_as_sarif(tmp_path, monkeypatch, capsys):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.py").write_text(f'k = "{FAKE_GITHUB_TOKEN}"\n')
    subprocess.run(["git", "add", "a.py"], cwd=tmp_path, check=True)
    exit_code, out, _ = _scan(["--staged", "--format", "sarif"], capsys)
    log = json.loads(out)
    assert exit_code == 1
    assert _uris(log) == ["a.py"]
    assert _results(log)[0]["ruleId"] == "secretshield.github_token"
    _assert_no_secret_material(out)


def test_staged_scan_uses_index_content_columns(tmp_path, monkeypatch, capsys):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.py").write_text(f'\n\nk = "{FAKE_GITHUB_TOKEN}"\n')
    subprocess.run(["git", "add", "a.py"], cwd=tmp_path, check=True)
    (tmp_path / "a.py").write_text("clean now\n")  # unstaged edit must not matter
    _, out, _ = _scan(["--staged", "--format", "sarif"], capsys)
    region = _results(json.loads(out))[0]["locations"][0]["physicalLocation"]["region"]
    assert (region["startLine"], region["startColumn"]) == (3, 6)


def test_diff_scan_as_sarif(tmp_path, monkeypatch, capsys):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "old.py").write_text(f'k = "{FAKE_OPENAI_KEY}"\n')
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)
    (tmp_path / "new.py").write_text(f'k = "{FAKE_GITHUB_TOKEN}"\n')
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "second"], cwd=tmp_path, check=True)
    exit_code, out, _ = _scan(["--diff", "HEAD~1", "--format", "sarif"], capsys)
    assert exit_code == 1
    assert _uris(json.loads(out)) == ["new.py"]


# --- the `ss` entry point -------------------------------------------------------------------------------------------------------------


def test_ss_and_secretshield_share_the_entry_point():
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib

    with open("pyproject.toml", "rb") as f:
        scripts = tomllib.load(f)["project"]["scripts"]
    assert scripts["ss"] == scripts["secretshield"] == "secretshield.cli:main"


def _real_ss() -> str | None:
    """`ss` on PATH, but only if it is SecretShield's (Linux ships an
    unrelated `ss` socket tool)."""
    path = shutil.which("ss")
    if path is None:
        return None
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=20)
    except Exception:
        return None
    return path if "secretshield" in proc.stdout.lower() else None


@pytest.mark.skipif(_real_ss() is None, reason="SecretShield's `ss` executable is not installed here")
def test_installed_ss_exports_sarif_to_file(project):
    proc = subprocess.run(
        [_real_ss(), "scan", ".", "--format", "sarif", "--output", "secretshield.sarif"],
        cwd=project, capture_output=True, text=True,
    )
    assert proc.returncode == 1
    log = json.loads((project / "secretshield.sarif").read_text(encoding="utf-8"))
    assert log["version"] == "2.1.0" and _results(log)
    _assert_no_secret_material(proc.stdout + proc.stderr)
    _assert_no_secret_material((project / "secretshield.sarif").read_text(encoding="utf-8"))


@pytest.mark.skipif(
    _real_ss() is None or shutil.which("secretshield") is None,
    reason="ss/secretshield not installed as real executables in this environment",
)
def test_installed_ss_and_secretshield_produce_identical_sarif(project):
    outs = [
        subprocess.run([exe, "scan", ".", "--format", "sarif"], cwd=project, capture_output=True, text=True)
        for exe in (_real_ss(), shutil.which("secretshield"))
    ]
    assert outs[0].returncode == outs[1].returncode == 1
    assert outs[0].stdout == outs[1].stdout
