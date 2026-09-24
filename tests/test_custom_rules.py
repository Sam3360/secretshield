"""
Tests for secretshield.custom_rules -- .secretshield-rules.toml loading,
compiling, and running custom detection rules.

All secrets used are fake / non-functional.
"""

from __future__ import annotations

from secretshield.custom_rules import (
    append_rule,
    load_custom_rules,
    rules_file_path,
    scan_text_with_rules,
)

FAKE_MATCH = "MYAPP_12345678901234567890123456789012"


# --- Loading -----------------------------------------------------------------


def test_no_rules_file_returns_empty(tmp_path):
    rules, errors = load_custom_rules(tmp_path)
    assert rules == []
    assert errors == []


def test_one_rule_loads(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    rules, errors = load_custom_rules(tmp_path)
    assert errors == []
    assert len(rules) == 1
    assert rules[0].name == "My API Key"
    assert rules[0].pattern == "MYAPP_[A-Za-z0-9]{32}"


def test_multiple_rules_load(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Acme API Key"\npattern = "ACME_[A-Za-z0-9]{32}"\n'
        '[[rules]]\nname = "Internal Token"\npattern = "internal_[a-f0-9]{40}"\n'
        '[[rules]]\nname = "Company Credential"\npattern = "company_[A-Za-z0-9_-]+"\n'
    )
    rules, errors = load_custom_rules(tmp_path)
    assert errors == []
    assert [r.name for r in rules] == ["Acme API Key", "Internal Token", "Company Credential"]


def test_empty_file_is_valid_no_rules(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text("")
    rules, errors = load_custom_rules(tmp_path)
    assert rules == []
    assert errors == []


def test_empty_rules_list_is_valid(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text("rules = []\n")
    rules, errors = load_custom_rules(tmp_path)
    assert rules == []
    assert errors == []


def test_rules_file_path_helper(tmp_path):
    path = rules_file_path(tmp_path)
    assert path.name == ".secretshield-rules.toml"
    assert path.parent == tmp_path


# --- Detection -----------------------------------------------------------------


def test_matching_regex_is_detected(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    rules, _ = load_custom_rules(tmp_path)
    text = f'API_KEY = "{FAKE_MATCH}"'
    matches = scan_text_with_rules(text, rules)
    assert len(matches) == 1
    assert matches[0].kind == "My API Key"
    assert matches[0].value == FAKE_MATCH


def test_non_matching_content_is_ignored(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    rules, _ = load_custom_rules(tmp_path)
    matches = scan_text_with_rules("nothing interesting here", rules)
    assert matches == []


def test_multiple_rules_detect_multiple_findings(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Rule A"\npattern = "AAA_[0-9]{6}"\n'
        '[[rules]]\nname = "Rule B"\npattern = "BBB_[0-9]{6}"\n'
    )
    rules, _ = load_custom_rules(tmp_path)
    text = "x = AAA_123456\ny = BBB_654321"
    matches = scan_text_with_rules(text, rules)
    kinds = sorted(m.kind for m in matches)
    assert kinds == ["Rule A", "Rule B"]


def test_custom_rule_name_appears_as_kind(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Stripe Test Key"\npattern = "sk_test_[A-Za-z0-9]+"\n'
    )
    rules, _ = load_custom_rules(tmp_path)
    matches = scan_text_with_rules("key = sk_test_abcdef123456", rules)
    assert matches[0].kind == "Stripe Test Key"


def test_no_rules_scans_nothing(tmp_path):
    assert scan_text_with_rules("MYAPP_12345678901234567890123456789012", []) == []


def test_empty_text_scans_nothing(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "X"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    rules, _ = load_custom_rules(tmp_path)
    assert scan_text_with_rules("", rules) == []


# --- Validation -----------------------------------------------------------------


def test_malformed_toml_reports_error(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text("this is [ not valid toml {{{")
    rules, errors = load_custom_rules(tmp_path)
    assert rules == []
    assert len(errors) == 1
    assert "toml" in errors[0].message.lower() or "expected" in errors[0].message.lower()


def test_missing_name_reports_error(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )
    rules, errors = load_custom_rules(tmp_path)
    assert rules == []
    assert len(errors) == 1
    assert "name" in errors[0].message.lower()


def test_missing_pattern_reports_error(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text('[[rules]]\nname = "Broken Rule"\n')
    rules, errors = load_custom_rules(tmp_path)
    assert rules == []
    assert len(errors) == 1
    assert errors[0].name == "Broken Rule"
    assert "pattern" in errors[0].message.lower()


def test_invalid_regex_reports_error(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Bad Regex"\npattern = "["\n'
    )
    rules, errors = load_custom_rules(tmp_path)
    assert rules == []
    assert len(errors) == 1
    assert errors[0].name == "Bad Regex"
    assert "regular expression" in errors[0].message.lower()


def test_invalid_rule_structure_reports_error(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text("rules = [1, 2, 3]\n")
    rules, errors = load_custom_rules(tmp_path)
    assert rules == []
    assert len(errors) == 3


def test_one_bad_rule_does_not_block_others(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "Good Rule"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
        '[[rules]]\nname = "Bad Rule"\npattern = "["\n'
    )
    rules, errors = load_custom_rules(tmp_path)
    assert [r.name for r in rules] == ["Good Rule"]
    assert len(errors) == 1
    assert errors[0].name == "Bad Rule"


# --- Rule creation -----------------------------------------------------------------


def test_append_rule_creates_file_when_missing(tmp_path):
    path = rules_file_path(tmp_path)
    assert not path.exists()
    append_rule(path, "My API Key", "MYAPP_[A-Za-z0-9]{32}")
    assert path.exists()


def test_append_rule_creates_valid_toml(tmp_path):
    path = rules_file_path(tmp_path)
    append_rule(path, "My API Key", "MYAPP_[A-Za-z0-9]{32}")
    rules, errors = load_custom_rules(tmp_path)
    assert errors == []
    assert len(rules) == 1
    assert rules[0].name == "My API Key"


def test_append_rule_preserves_existing_rules(tmp_path):
    path = rules_file_path(tmp_path)
    append_rule(path, "First Rule", "FIRST_[0-9]{6}")
    append_rule(path, "Second Rule", "SECOND_[0-9]{6}")
    rules, errors = load_custom_rules(tmp_path)
    assert errors == []
    assert [r.name for r in rules] == ["First Rule", "Second Rule"]


def test_append_rule_does_not_overwrite_existing_content(tmp_path):
    path = rules_file_path(tmp_path)
    append_rule(path, "First Rule", "FIRST_[0-9]{6}")
    original = path.read_text()
    append_rule(path, "Second Rule", "SECOND_[0-9]{6}")
    updated = path.read_text()
    assert updated.startswith(original)


def test_append_rule_escapes_special_characters(tmp_path):
    path = rules_file_path(tmp_path)
    append_rule(path, 'Rule "with" quotes', r'a\b"c')
    rules, errors = load_custom_rules(tmp_path)
    assert errors == []
    assert rules[0].name == 'Rule "with" quotes'
    assert rules[0].pattern == r'a\b"c'


def test_append_rule_never_creates_broken_config(tmp_path):
    path = rules_file_path(tmp_path)
    append_rule(path, "Rule One", "ONE_[0-9]{4}")
    append_rule(path, "Rule Two", "TWO_[0-9]{4}")
    append_rule(path, "Rule Three", "THREE_[0-9]{4}")
    rules, errors = load_custom_rules(tmp_path)
    assert errors == []
    assert len(rules) == 3
