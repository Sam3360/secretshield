"""
CLI-level integration tests for custom rules: `secretshield scan`
automatically picking up `.secretshield-rules.toml`, `secretshield
rules check`, `secretshield rules`, `secretshield rule create`, and
their interaction with .secretshieldignore, --fix, --json, and
redaction safety.
"""

from __future__ import annotations

import json

from secretshield.cli import main

FAKE_MATCH = "MYAPP_12345678901234567890123456789012"


# --- Automatic inclusion in scans --------------------------------------------


def test_scan_automatically_picks_up_custom_rules(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    (tmp_path / "test.py").write_text(f'value = "{FAKE_MATCH}"\n')

    exit_code = main(["scan", "."])
    assert exit_code == 1


def test_scan_behaves_normally_without_rules_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "test.py").write_text("print('nothing secret here')\n")
    exit_code = main(["scan", "."])
    assert exit_code == 0


def test_scan_json_includes_custom_rule_name_as_kind(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    (tmp_path / "test.py").write_text(f'value = "{FAKE_MATCH}"\n')

    main(["scan", ".", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    kinds = [m["kind"] for m in payload["matches"]]
    assert "My API Key" in kinds


def test_scan_no_custom_rules_flag_needed(tmp_path, monkeypatch):
    # The core requirement: no --custom-rules / --rules-file / etc.
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    (tmp_path / "test.py").write_text(f'value = "{FAKE_MATCH}"\n')
    # Plain `scan .` with nothing extra must find it.
    assert main(["scan", "."]) == 1


def test_built_in_rules_still_work_alongside_custom(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    aws_key = "AKIAABCDEFGHIJKLMNOP"
    (tmp_path / "test.py").write_text(f'aws = "{aws_key}"\nother = "{FAKE_MATCH}"\n')

    main(["scan", ".", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    kinds = {m["kind"] for m in payload["matches"]}
    assert "aws_access_key_id" in kinds
    assert "My API Key" in kinds


def test_multiple_custom_rules_all_scanned(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Acme API Key"\npattern = "ACME_[0-9]{6}"\n'
        '[[rules]]\nname = "Internal Token"\npattern = "internal_[a-f0-9]{8}"\n'
        '[[rules]]\nname = "Company Credential"\npattern = "company_[A-Za-z0-9_-]+"\n'
    )
    (tmp_path / "test.py").write_text(
        'a = "ACME_123456"\nb = "internal_deadbeef"\nc = "company_secretvalue"\n'
    )
    main(["scan", ".", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    kinds = {m["kind"] for m in payload["matches"]}
    assert {"Acme API Key", "Internal Token", "Company Credential"}.issubset(kinds)


# --- Broken rules file doesn't block a scan ---------------------------------


def test_broken_custom_rules_does_not_block_scan(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Bad Rule"\npattern = "["\n'
    )
    (tmp_path / "clean.py").write_text("print('hello')\n")
    exit_code = main(["scan", "."])
    assert exit_code == 0  # scan still runs
    err = capsys.readouterr().err
    assert "rules check" in err  # points the user at how to see details


# --- `secretshield rules check` ---------------------------------------------


def test_rules_check_no_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["rules", "check"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "No .secretshield-rules.toml found" in out


def test_rules_check_success(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "A"\npattern = "AAA_[0-9]{4}"\n'
        '[[rules]]\nname = "B"\npattern = "BBB_[0-9]{4}"\n'
    )
    exit_code = main(["rules", "check"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "2 rule(s) loaded" in out
    assert "All patterns are valid" in out


def test_rules_check_reports_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Internal Token"\npattern = "["\n'
    )
    exit_code = main(["rules", "check"])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Internal Token" in out
    assert "regular expression" in out.lower()


def test_rules_check_never_dumps_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text("not [ valid toml {{{")
    exit_code = main(["rules", "check"])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Traceback" not in out


# --- `secretshield rules` (list) --------------------------------------------


def test_rules_list_shows_rules(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    main(["rules"])
    out = capsys.readouterr().out
    assert "My API Key" in out
    assert "MYAPP_[A-Za-z0-9]{32}" in out


def test_rules_list_no_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["rules"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "No .secretshield-rules.toml found" in out


# --- `secretshield rule create` ---------------------------------------------


def test_rule_create_non_interactive_refuses(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["rule", "create"])
    assert exit_code == 1
    assert not (tmp_path / ".secretshield-rules.toml").exists()


def test_rule_no_subcommand_shows_message(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["rule"])
    assert exit_code == 1


# --- .secretshieldignore interaction ----------------------------------------


def test_ignored_files_not_scanned_by_custom_rules(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    (tmp_path / ".secretshieldignore").write_text("ignored/\n")
    (tmp_path / "ignored").mkdir()
    (tmp_path / "ignored" / "secret.py").write_text(f'x = "{FAKE_MATCH}"\n')
    (tmp_path / "clean.py").write_text("print('clean')\n")

    exit_code = main(["scan", "."])
    assert exit_code == 0


def test_non_ignored_file_still_caught_by_custom_rule(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    (tmp_path / ".secretshieldignore").write_text("ignored/\n")
    (tmp_path / "ignored").mkdir()
    (tmp_path / "ignored" / "secret.py").write_text(f'x = "{FAKE_MATCH}"\n')
    (tmp_path / "not_ignored.py").write_text(f'x = "{FAKE_MATCH}"\n')

    exit_code = main(["scan", "."])
    assert exit_code == 1


# --- Redaction / no-leak safety ----------------------------------------------


def test_custom_rule_value_never_printed_in_scan_output(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    (tmp_path / "test.py").write_text(f'x = "{FAKE_MATCH}"\n')

    main(["scan", "."])
    out = capsys.readouterr().out
    assert FAKE_MATCH not in out


def test_custom_rule_value_never_in_json_output(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    (tmp_path / "test.py").write_text(f'x = "{FAKE_MATCH}"\n')

    main(["scan", ".", "--json"])
    out = capsys.readouterr().out
    assert FAKE_MATCH not in out


# --- --fix integration -------------------------------------------------------


def test_fix_moves_safe_custom_rule_match_to_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    app = tmp_path / "app.py"
    app.write_text(f'CUSTOM_KEY = "{FAKE_MATCH}"\n')

    import secretshield.autofix.fixer as fixer_mod

    monkeypatch.setattr(fixer_mod, "is_interactive", lambda: True)
    answers = iter(["y", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    exit_code = main(["scan", ".", "--fix"])
    assert exit_code == 0
    assert FAKE_MATCH not in app.read_text()
    assert FAKE_MATCH in (tmp_path / ".env").read_text()


def test_fix_leaves_ambiguous_custom_rule_match_untouched(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    app = tmp_path / "app.py"
    original = f'headers = {{"X-Key": "{FAKE_MATCH}"}}\n'
    app.write_text(original)

    import secretshield.autofix.fixer as fixer_mod

    monkeypatch.setattr(fixer_mod, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": (_ for _ in ()).throw(AssertionError))

    main(["scan", ".", "--fix"])
    assert app.read_text() == original


# --- Compatibility ------------------------------------------------------------


def test_built_in_only_scan_unaffected_by_absent_rules_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    aws_key = "AKIAABCDEFGHIJKLMNOP"
    (tmp_path / "test.py").write_text(f'x = "{aws_key}"\n')
    main(["scan", ".", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["secrets_found"] == 1
    assert payload["matches"][0]["kind"] == "aws_access_key_id"
