"""
v0.8.0: regression tests for the custom-rule self-detection bug fix,
plus tests for the new `secretshield rule test` command.

Root cause (confirmed by direct reproduction before the fix): a custom
rule's `pattern` field, by design, resembles the very secret shape
it's meant to catch. `.secretshield-rules.toml` is an ordinary `.toml`
file, so a plain directory scan swept it in as regular project
content -- meaning a rule whose pattern looked enough like a real
secret (or whose example value happened to trip built-in entropy
detection) caused the rules file to report itself as a finding.

The fix: SecretShield's own meta-files (.secretshield-rules.toml,
secretshield.toml, .secretshieldignore, .secretshield-baseline.json)
are now skipped by name during a default directory scan, the same way
_SKIP_DIR_NAMES already skips well-known directories -- not a broad
"skip all .toml files" exclusion. --no-ignore re-includes them;
explicitly scanning one by path is unaffected.
"""

from __future__ import annotations

import subprocess

from secretshield.cli import main

SELF_RESEMBLING_PATTERN = "MYAPP_abc123def456ghi789jkl012mno345"


def _init_repo(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True)


# --- 1 & 2: reproduce, then confirm fixed -----------------------------------


def test_custom_rule_pattern_in_source_file_is_still_detected(tmp_path, monkeypatch):
    """A custom rule must still catch its intended pattern in real
    project files -- the fix must not weaken detection."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        f'[[rules]]\nname = "My Test Rule"\npattern = "{SELF_RESEMBLING_PATTERN}"\n'
    )
    (tmp_path / "app.py").write_text(f'API_KEY = "{SELF_RESEMBLING_PATTERN}"\n')

    exit_code = main(["scan", "."])
    assert exit_code == 1


def test_rules_file_does_not_self_detect(tmp_path, monkeypatch, capsys):
    """The core bug: a rule whose pattern resembles a real secret must
    not cause .secretshield-rules.toml to report itself."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        f'[[rules]]\nname = "My Test Rule"\npattern = "{SELF_RESEMBLING_PATTERN}"\n'
    )
    # No other files -- if anything is reported, it can only be the
    # rules file self-matching.
    exit_code = main(["scan", ".", "--json"])
    assert exit_code == 0

    import json

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["secrets_found"] == 0
    assert payload["files_scanned"] == 0


def test_rules_file_excluded_even_from_files_scanned_count(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "X"\npattern = "AAA_[0-9]{6}"\n'
    )
    (tmp_path / "clean.py").write_text("print('hello')\n")
    main(["scan", ".", "--json"])

    import json

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["files_scanned"] == 1  # only clean.py, not the rules file


# --- 4 & 5: multiple custom rules + real detection ---------------------------


def test_multiple_custom_rules_no_self_detection_any_of_them(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Rule A"\npattern = "AAA_bbbbbbbbbbbbbbbbbbbbbbbb"\n'
        '[[rules]]\nname = "Rule B"\npattern = "BBB_cccccccccccccccccccccc"\n'
    )
    main(["scan", ".", "--json"])

    import json

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["secrets_found"] == 0


def test_multiple_custom_rules_still_detect_real_matches(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Rule A"\npattern = "AAA_[0-9]{6}"\n'
        '[[rules]]\nname = "Rule B"\npattern = "BBB_[0-9]{6}"\n'
    )
    (tmp_path / "app.py").write_text('a = "AAA_123456"\nb = "BBB_654321"\n')
    main(["scan", ".", "--json"])

    import json

    out = capsys.readouterr().out
    payload = json.loads(out)
    kinds = {m["kind"] for m in payload["matches"]}
    assert {"Rule A", "Rule B"}.issubset(kinds)


# --- 6: built-in rules unaffected --------------------------------------------


def test_built_in_detection_still_works(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    aws_key = "AKIAABCDEFGHIJKLMNOP"
    (tmp_path / "app.py").write_text(f'x = "{aws_key}"\n')
    main(["scan", ".", "--json"])

    import json

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["matches"][0]["kind"] == "aws_access_key_id"


# --- 7: broken custom rules behave as before ---------------------------------


def test_broken_custom_rule_still_reported_via_rules_check(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text('[[rules]]\nname = "Bad"\npattern = "["\n')
    exit_code = main(["rules", "check"])
    assert exit_code == 1


def test_broken_custom_rule_does_not_block_scan(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text('[[rules]]\nname = "Bad"\npattern = "["\n')
    (tmp_path / "clean.py").write_text("print('hello')\n")
    assert main(["scan", "."]) == 0


# --- --no-ignore re-includes meta-files --------------------------------------


def test_no_ignore_flag_allows_scanning_meta_files_again(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        f'[[rules]]\nname = "X"\npattern = "{SELF_RESEMBLING_PATTERN}"\n'
    )
    main(["scan", ".", "--no-ignore", "--json"])

    import json

    out = capsys.readouterr().out
    payload = json.loads(out)
    # With --no-ignore, the rules file IS scanned again, and since its
    # own pattern text resembles a real secret it's expected to
    # self-match -- this proves --no-ignore genuinely re-includes it,
    # rather than the exclusion being silently unconditional.
    assert payload["files_scanned"] == 1


def test_explicit_direct_scan_of_rules_file_still_works(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rules_file = tmp_path / ".secretshield-rules.toml"
    rules_file.write_text(f'[[rules]]\nname = "X"\npattern = "{SELF_RESEMBLING_PATTERN}"\n')
    # Explicitly naming the file as the scan target still works --
    # only the default directory *walk* excludes it.
    exit_code = main(["scan", str(rules_file)])
    assert exit_code == 1


# --- secretshield.toml / .secretshieldignore / baseline also excluded -------


def test_secretshield_toml_not_scanned_by_default(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secretshield.toml").write_text("[scan]\nentropy_threshold = 4.2\n")
    main(["scan", ".", "--json"])

    import json

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["files_scanned"] == 0


def test_secretshieldignore_not_scanned_by_default(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshieldignore").write_text("vendor/\n")
    main(["scan", ".", "--json"])

    import json

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["files_scanned"] == 0


def test_baseline_file_not_scanned_by_default(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    from secretshield.baseline import write_baseline

    write_baseline(tmp_path, [{"id": "a" * 64, "file": "app.py", "kind": "x", "line": 1}])
    main(["scan", ".", "--json"])

    import json

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["files_scanned"] == 0


# --- --staged / scan-staged (the pre-commit hook path) -----------------------


def test_staged_rules_file_does_not_self_block(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        f'[[rules]]\nname = "X"\npattern = "{SELF_RESEMBLING_PATTERN}"\n'
    )
    subprocess.run(["git", "add", ".secretshield-rules.toml"], cwd=tmp_path, check=True)

    exit_code = main(["scan", "--staged"])
    assert exit_code == 0


def test_scan_staged_command_does_not_self_block(tmp_path, monkeypatch):
    # This is the exact path the installed pre-commit hook invokes.
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        f'[[rules]]\nname = "X"\npattern = "{SELF_RESEMBLING_PATTERN}"\n'
    )
    subprocess.run(["git", "add", ".secretshield-rules.toml"], cwd=tmp_path, check=True)

    exit_code = main(["scan-staged"])
    assert exit_code == 0


def test_real_commit_of_rules_file_succeeds(tmp_path, monkeypatch):
    """The exact real-world scenario reported: committing an update to
    your own custom-rules file must not get blocked by itself."""
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    main(["install-hook"])

    (tmp_path / ".secretshield-rules.toml").write_text(
        f'[[rules]]\nname = "X"\npattern = "{SELF_RESEMBLING_PATTERN}"\n'
    )
    subprocess.run(["git", "add", ".secretshield-rules.toml"], cwd=tmp_path, check=True)

    result = subprocess.run(
        ["git", "commit", "-m", "add custom rule"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


# --- `secretshield rule test` ------------------------------------------------


def test_rule_test_non_interactive_refuses(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["rule", "test"])
    assert exit_code == 1


def test_rule_test_no_rules_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    exit_code = main(["rule", "test"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "No .secretshield-rules.toml found" in out


def test_rule_test_reports_match(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        f'[[rules]]\nname = "My Rule"\npattern = "{SELF_RESEMBLING_PATTERN}"\n'
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": SELF_RESEMBLING_PATTERN)

    exit_code = main(["rule", "test"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Matched: My Rule" in out


def test_rule_test_reports_no_match(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My Rule"\npattern = "AAA_[0-9]{6}"\n'
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "totally unrelated text")

    exit_code = main(["rule", "test"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "No match: My Rule" in out


def test_rule_test_never_prints_raw_matched_value(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        f'[[rules]]\nname = "My Rule"\npattern = "{SELF_RESEMBLING_PATTERN}"\n'
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": SELF_RESEMBLING_PATTERN)

    main(["rule", "test"])
    out = capsys.readouterr().out
    assert "value masked" in out


# --- 8: existing suite remains green (spot-checked here too) ---------------


def test_scan_with_no_config_files_at_all_still_works(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "clean.py").write_text("print('nothing here')\n")
    assert main(["scan", "."]) == 0
