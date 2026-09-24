"""Tests for secretshield.ignorefile -- .secretshieldignore support."""

from __future__ import annotations

from secretshield.ignorefile import ignore_file_path, load_ignore_patterns


def test_no_ignore_file_returns_empty_list(tmp_path):
    assert load_ignore_patterns(tmp_path) == []


def test_loads_simple_patterns(tmp_path):
    (tmp_path / ".secretshieldignore").write_text("*.min.js\nvendor/\n")
    patterns = load_ignore_patterns(tmp_path)
    assert "*.min.js" in patterns


def test_trailing_slash_becomes_glob(tmp_path):
    (tmp_path / ".secretshieldignore").write_text("vendor/\n")
    patterns = load_ignore_patterns(tmp_path)
    assert "vendor/*" in patterns
    assert "vendor/" not in patterns


def test_comments_and_blank_lines_skipped(tmp_path):
    (tmp_path / ".secretshieldignore").write_text(
        "# this is a comment\n\nvendor/\n\n# another comment\n*.log\n"
    )
    patterns = load_ignore_patterns(tmp_path)
    assert patterns == ["vendor/*", "*.log"]


def test_ignore_file_path_helper(tmp_path):
    path = ignore_file_path(tmp_path)
    assert path.name == ".secretshieldignore"
    assert path.parent == tmp_path


def test_malformed_file_does_not_crash(tmp_path):
    # Write invalid UTF-8 bytes directly.
    (tmp_path / ".secretshieldignore").write_bytes(b"\xff\xfe\x00garbage")
    # Should not raise -- errors="ignore" handles invalid bytes.
    patterns = load_ignore_patterns(tmp_path)
    assert isinstance(patterns, list)
