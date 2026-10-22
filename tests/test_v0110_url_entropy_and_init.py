"""
Tests for v0.11.0: URLs are no longer reported as generic high-entropy
strings, and `secretshield init` creates `secretshield.toml` and
`.secretshieldignore` together (leaving either one alone if it exists).

All secrets used here are fake / clearly non-functional test values.
"""

from __future__ import annotations

import subprocess

import pytest

from secretshield import patterns
from secretshield.cli import main
from secretshield.detector import _mask_url_identifiers, detect
from secretshield.ignorefile import (
    DEFAULT_IGNORE_CONTENT,
    load_ignore_patterns,
)
from secretshield.project_config import (
    DEFAULT_TOML_TEMPLATE,
    load_project_config,
    render_default_toml,
)

NEW_DOC_URL = "https://github.com/Sam3360/secretshield/blob/main/USAGE.md#configuration"
OLD_DOC_URL = "https://github.com/Sam3360/secretshield#configuration-file"

# Fake, clearly non-functional values.
FAKE_HIGH_ENTROPY = "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1"
FAKE_AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
FAKE_GITHUB_TOKEN = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
FAKE_MATCH = "MYAPP_12345678901234567890123456789012"


# --- 1. URLs are not high-entropy findings -----------------------------------


@pytest.mark.parametrize(
    "text",
    [
        NEW_DOC_URL,
        f"# {NEW_DOC_URL}",
        "https://github.com/Sam3360/secretshield/blob/main/USAGE.md",
        "See https://github.com/Sam3360/secretshield/blob/main/USAGE.md for docs",
        "[docs](https://github.com/Sam3360/secretshield/blob/main/USAGE.md)",
        '<a href="https://github.com/Sam3360/secretshield/blob/main/USAGE.md">docs</a>',
        "https://pypi.org/project/secretshield/0.11.0/",
        "https://github.com/Sam3360/secretshield/actions/workflows/secretshield.yml",
        "https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit",
        "http://example.org/a/b/c/some-long-article-slug-about-things",
        "www.github.com/Sam3360/secretshield/blob/main/USAGE.md",
    ],
)
def test_urls_are_not_flagged_as_high_entropy(text):
    assert detect(text) == []


def test_github_url_in_generated_toml_comment_is_not_flagged():
    assert detect(f"# {NEW_DOC_URL}\n") == []


def test_url_masking_preserves_length_and_offsets():
    text = f"before {NEW_DOC_URL} after {FAKE_HIGH_ENTROPY}"
    assert len(_mask_url_identifiers(text)) == len(text)
    matches = detect(text)
    assert len(matches) == 1
    assert text[matches[0].start : matches[0].end] == FAKE_HIGH_ENTROPY


def test_text_without_urls_is_not_modified_by_masking():
    text = f"token {FAKE_HIGH_ENTROPY}"
    assert _mask_url_identifiers(text) == text


# --- Genuine high-entropy strings are still detected -------------------------


def test_genuine_high_entropy_string_still_detected():
    matches = detect(FAKE_HIGH_ENTROPY)
    assert [m.kind for m in matches] == ["high_entropy"]
    assert matches[0].value == FAKE_HIGH_ENTROPY


def test_high_entropy_string_assigned_to_unlabeled_name_still_detected():
    assert any(m.kind == "high_entropy" for m in detect(f"x = '{FAKE_HIGH_ENTROPY}'"))


def test_high_entropy_string_next_to_a_url_still_detected():
    text = f"see https://github.com/Sam3360/secretshield and {FAKE_HIGH_ENTROPY}"
    matches = detect(text)
    assert [m.kind for m in matches] == ["high_entropy"]
    assert text[matches[0].start : matches[0].end] == FAKE_HIGH_ENTROPY


@pytest.mark.parametrize(
    "text",
    [
        f"https://user:{FAKE_HIGH_ENTROPY}@host.example.com/repo",
        f"postgres://admin:{FAKE_HIGH_ENTROPY}@db.internal/app",
        f"https://example.com/path?k={FAKE_HIGH_ENTROPY}",
        f"https://example.com/path#{FAKE_HIGH_ENTROPY}",
    ],
)
def test_credentials_and_query_values_inside_urls_still_detected(text):
    matches = detect(text)
    assert any(
        m.kind == "high_entropy" and text[m.start : m.end] == FAKE_HIGH_ENTROPY
        for m in matches
    )


# --- Built-in detectors are unaffected ---------------------------------------


def test_builtin_patterns_still_detected():
    assert "aws_access_key_id" in [m.kind for m in detect(f"key = '{FAKE_AWS_KEY}'")]
    assert any(m.kind == "github_token" or "github" in m.kind for m in detect(f"t: {FAKE_GITHUB_TOKEN}"))


def test_builtin_patterns_still_detected_inside_urls():
    kinds = [m.kind for m in detect(f"https://example.com/download/{FAKE_AWS_KEY}/file")]
    assert "aws_access_key_id" in kinds
    kinds = [m.kind for m in detect(f"https://example.com/?api_key=abcd1234efgh5678")]
    assert "generic_labeled_secret" in kinds


def test_url_pattern_is_not_used_by_known_format_detectors():
    # The URL regex only feeds the entropy check; known-format patterns
    # must not have been given a URL exemption.
    assert "url" not in [name for name, _ in patterns.PATTERNS]


# --- Custom rules are unaffected ---------------------------------------------


def _write_rule(tmp_path):
    (tmp_path / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n'
    )


def test_custom_rule_still_detected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_rule(tmp_path)
    (tmp_path / "app.py").write_text(f'value = "{FAKE_MATCH}"\n')
    assert main(["scan", "."]) == 1


def test_custom_rule_still_detected_inside_a_url(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_rule(tmp_path)
    (tmp_path / "notes.md").write_text(f"https://example.com/dl/{FAKE_MATCH}/x\n")
    assert main(["scan", "."]) == 1


# --- CLI-level behaviour -----------------------------------------------------


def test_scan_does_not_flag_docs_link_in_readme(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "README.md").write_text(
        "Docs: https://github.com/Sam3360/secretshield/blob/main/USAGE.md\n"
    )
    assert main(["scan", "."]) == 0


def test_generated_toml_scans_clean_even_when_not_skipped(tmp_path, monkeypatch, capsys):
    """--no-ignore re-includes secretshield.toml, so this really scans it."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secretshield.toml").write_text(render_default_toml(), encoding="utf-8")
    exit_code = main(["scan", ".", "--no-ignore"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "1 files scanned" in out
    assert "High-entropy" not in out


def test_generated_toml_scans_clean_when_scanned_by_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secretshield.toml").write_text(render_default_toml(), encoding="utf-8")
    assert main(["scan", "secretshield.toml"]) == 0


def test_real_secret_in_secretshield_toml_still_detected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secretshield.toml").write_text(
        render_default_toml() + f"\n# token {FAKE_HIGH_ENTROPY}\n", encoding="utf-8"
    )
    assert main(["scan", ".", "--no-ignore"]) == 1


def test_builtin_secret_in_secretshield_toml_still_detected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secretshield.toml").write_text(
        render_default_toml() + f"\n# {FAKE_AWS_KEY}\n", encoding="utf-8"
    )
    assert main(["scan", ".", "--no-ignore"]) == 1


def test_staged_scan_passes_for_docs_link(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "README.md").write_text(
        "Docs: https://github.com/Sam3360/secretshield/blob/main/USAGE.md\n"
    )
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    assert main(["scan", "--staged"]) == 0


def test_findings_never_print_the_secret(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.txt").write_text(f"https://example.com/p?k={FAKE_HIGH_ENTROPY}\n")
    assert main(["scan", "."]) == 1
    captured = capsys.readouterr()
    assert FAKE_HIGH_ENTROPY not in captured.out + captured.err


# --- 3/4. Generated secretshield.toml ----------------------------------------


def test_generated_toml_contains_new_documentation_url():
    toml_text = render_default_toml()
    assert f"# {NEW_DOC_URL}" in toml_text


def test_old_documentation_url_is_not_generated_anywhere():
    assert OLD_DOC_URL not in render_default_toml()
    assert OLD_DOC_URL not in DEFAULT_TOML_TEMPLATE
    assert "configuration-file" not in DEFAULT_TOML_TEMPLATE


def test_generated_toml_structure_and_defaults_unchanged(tmp_path):
    toml_text = render_default_toml()
    for expected in ("[scan]", "entropy_threshold = 4.2", "[scan.ignore]", "[scan.include]", "[output]", 'format = "text"'):
        assert expected in toml_text
    path = tmp_path / "secretshield.toml"
    path.write_text(toml_text, encoding="utf-8")
    cfg = load_project_config(tmp_path)
    assert cfg.entropy_threshold == 4.2
    assert cfg.ignore_paths == []
    assert cfg.include_patterns == []
    assert cfg.output_format == "text"


# --- 2. `secretshield init` ---------------------------------------------------


def _run_init(monkeypatch, answers):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(it))
    return main(["init"])


# Not a git repo, so the hook prompt is skipped: config, actions, apply.
YES_CONFIG_ONLY = ["y", "n", "y"]
NO_CONFIG = ["n", "n", "y"]


def test_init_creates_both_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert _run_init(monkeypatch, YES_CONFIG_ONLY) == 0
    out = capsys.readouterr().out
    assert (tmp_path / "secretshield.toml").exists()
    assert (tmp_path / ".secretshieldignore").exists()
    assert "Created secretshield.toml" in out
    assert "Created .secretshieldignore" in out


def test_init_written_toml_has_new_url(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _run_init(monkeypatch, YES_CONFIG_ONLY)
    content = (tmp_path / "secretshield.toml").read_text(encoding="utf-8")
    assert f"# {NEW_DOC_URL}" in content
    assert OLD_DOC_URL not in content


def test_init_written_ignore_file_is_minimal_and_valid(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _run_init(monkeypatch, YES_CONFIG_ONLY)
    content = (tmp_path / ".secretshieldignore").read_text(encoding="utf-8")
    assert content == DEFAULT_IGNORE_CONTENT
    assert len(content.splitlines()) <= 12
    # Comments only: nothing is excluded until the user opts in.
    assert load_ignore_patterns(tmp_path) == []


def test_init_existing_toml_left_unchanged_and_ignore_created(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secretshield.toml").write_text("# mine\n", encoding="utf-8")
    _run_init(monkeypatch, YES_CONFIG_ONLY)
    out = capsys.readouterr().out
    assert (tmp_path / "secretshield.toml").read_text(encoding="utf-8") == "# mine\n"
    assert (tmp_path / ".secretshieldignore").exists()
    assert "secretshield.toml already exists, leaving it unchanged" in out
    assert "Created .secretshieldignore" in out


def test_init_existing_ignore_left_unchanged_and_toml_created(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshieldignore").write_text("vendor/\n", encoding="utf-8")
    _run_init(monkeypatch, YES_CONFIG_ONLY)
    out = capsys.readouterr().out
    assert (tmp_path / ".secretshieldignore").read_text(encoding="utf-8") == "vendor/\n"
    assert (tmp_path / "secretshield.toml").exists()
    assert "Created secretshield.toml" in out
    assert ".secretshieldignore already exists, leaving it unchanged" in out


def test_init_both_existing_left_unchanged(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secretshield.toml").write_text("# mine\n", encoding="utf-8")
    (tmp_path / ".secretshieldignore").write_text("vendor/\n", encoding="utf-8")
    _run_init(monkeypatch, YES_CONFIG_ONLY)
    out = capsys.readouterr().out
    assert (tmp_path / "secretshield.toml").read_text(encoding="utf-8") == "# mine\n"
    assert (tmp_path / ".secretshieldignore").read_text(encoding="utf-8") == "vendor/\n"
    assert "Created secretshield.toml" not in out
    assert "Created .secretshieldignore" not in out
    assert out.count("already exists, leaving it unchanged") == 2


def test_init_declining_project_config_creates_neither_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _run_init(monkeypatch, NO_CONFIG) == 0
    assert not (tmp_path / "secretshield.toml").exists()
    assert not (tmp_path / ".secretshieldignore").exists()


def test_init_declining_apply_creates_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _run_init(monkeypatch, ["y", "y", "n"]) == 0
    assert not (tmp_path / "secretshield.toml").exists()
    assert not (tmp_path / ".secretshieldignore").exists()


def test_init_generated_files_scan_clean_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _run_init(monkeypatch, YES_CONFIG_ONLY)
    assert main(["scan", ".", "--no-ignore"]) == 0
