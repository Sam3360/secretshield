"""
Tests for secretshield.redactor: redact() must replace detected secrets
and must never leak the original secret value in its output.
"""

from __future__ import annotations

from secretshield.redactor import redact

FAKE_AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
FAKE_GITHUB_TOKEN = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
FAKE_OPENAI_KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz1234567890"


def test_redact_replaces_known_secret():
    text = f"api key is {FAKE_AWS_KEY}"
    redacted, was_redacted = redact(text)
    assert was_redacted is True
    assert FAKE_AWS_KEY not in redacted
    assert "********" in redacted


def test_redact_no_secret_present():
    text = "hello world, nothing to see here"
    redacted, was_redacted = redact(text)
    assert was_redacted is False
    assert redacted == text


def test_redact_multiple_secrets_same_line():
    text = f"{FAKE_AWS_KEY} then {FAKE_GITHUB_TOKEN}"
    redacted, was_redacted = redact(text)
    assert was_redacted is True
    assert FAKE_AWS_KEY not in redacted
    assert FAKE_GITHUB_TOKEN not in redacted


def test_redact_repeated_occurrences_of_same_secret():
    text = f"first: {FAKE_OPENAI_KEY} second: {FAKE_OPENAI_KEY}"
    redacted, was_redacted = redact(text)
    assert was_redacted is True
    assert FAKE_OPENAI_KEY not in redacted
    assert redacted.count("********") == 2


def test_redact_multiline_text():
    text = f"line1\nsecret={FAKE_AWS_KEY}\nline3\ntoken={FAKE_GITHUB_TOKEN}\nline5"
    redacted, was_redacted = redact(text)
    assert was_redacted is True
    assert FAKE_AWS_KEY not in redacted
    assert FAKE_GITHUB_TOKEN not in redacted
    assert "line1" in redacted
    assert "line3" in redacted
    assert "line5" in redacted


def test_redact_custom_placeholder():
    text = f"key: {FAKE_AWS_KEY}"
    redacted, was_redacted = redact(text, redact_with="[REDACTED]")
    assert was_redacted is True
    assert FAKE_AWS_KEY not in redacted
    assert "[REDACTED]" in redacted


def test_redact_empty_string():
    redacted, was_redacted = redact("")
    assert redacted == ""
    assert was_redacted is False


def test_redact_preserves_surrounding_text():
    text = f"prefix-before {FAKE_AWS_KEY} suffix-after"
    redacted, _ = redact(text)
    assert "prefix-before" in redacted
    assert "suffix-after" in redacted


def test_redact_never_raises_on_malformed_input():
    redacted, was_redacted = redact("\x00" * 5)
    assert isinstance(redacted, str)
    assert isinstance(was_redacted, bool)
