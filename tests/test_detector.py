"""
Tests for secretshield.detector: known-pattern detection, entropy
detection, and false-positive avoidance.

All secrets used here are fake / clearly non-functional test values.
"""

from __future__ import annotations

from secretshield.detector import detect

# --- Fake credentials for testing purposes only. Not real. ---
FAKE_AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
FAKE_GITHUB_TOKEN = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
FAKE_OPENAI_KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz1234567890"
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYE"
)
FAKE_SLACK_TOKEN = "xoxb-1234567890-abcdefghijklmnop"
FAKE_STRIPE_KEY = "sk_test_" + "abcdefghijklmnopqrstuvwx"
FAKE_GOOGLE_KEY = "AIza" + "S" * 35
FAKE_PRIVATE_KEY_BLOCK = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD91loAd0zSMDT6bwWEsMLE1v9wYS4z9V93gGdKvC\n"
    "-----END RSA PRIVATE KEY-----"
)


def test_detects_aws_access_key():
    text = f"aws_key = '{FAKE_AWS_KEY}'"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "aws_access_key_id" in kinds


def test_detects_github_token():
    text = f"token: {FAKE_GITHUB_TOKEN}"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "github_token" in kinds


def test_detects_openai_key():
    text = f"OPENAI_API_KEY={FAKE_OPENAI_KEY}"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "openai_api_key" in kinds


def test_detects_jwt():
    text = f"Authorization: {FAKE_JWT}"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "jwt" in kinds


def test_detects_bearer_token():
    text = "Authorization: Bearer abcdef123456ABCDEF7890xyz"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "bearer_token" in kinds


def test_detects_slack_token():
    text = f"slack token {FAKE_SLACK_TOKEN}"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "slack_token" in kinds


def test_detects_stripe_key():
    text = f"stripe: {FAKE_STRIPE_KEY}"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "stripe_key" in kinds


def test_detects_google_api_key():
    text = f"key={FAKE_GOOGLE_KEY}"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "google_api_key" in kinds


def test_detects_private_key_block():
    matches = detect(FAKE_PRIVATE_KEY_BLOCK)
    kinds = [m.kind for m in matches]
    assert "private_key_block" in kinds


def test_detects_contextual_password_label():
    text = "password = 'Sup3rSecretPassw0rd!'"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "generic_labeled_secret" in kinds


def test_detects_high_entropy_generic_secret():
    # A random-looking token with no contextual label at all.
    random_token = "aX9pQ2zM7vL0rT4wK8yB1nD6fH3jC5sE"
    matches = detect(random_token, entropy_threshold=3.5)
    kinds = [m.kind for m in matches]
    assert "high_entropy" in kinds


def test_low_entropy_text_not_flagged():
    text = "this is just a normal sentence about the weather today"
    matches = detect(text)
    assert matches == []


def test_common_words_not_flagged_as_secrets():
    text = "The quick brown fox jumps over the lazy dog repeatedly"
    matches = detect(text)
    assert matches == []


def test_repeated_digits_not_flagged():
    text = "order_id = 000000000000000000000000"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "high_entropy" not in kinds


def test_multiline_text_detects_all_secrets():
    text = f"line one\naws_key={FAKE_AWS_KEY}\nline three\ntoken={FAKE_GITHUB_TOKEN}\n"
    matches = detect(text)
    kinds = {m.kind for m in matches}
    assert "aws_access_key_id" in kinds
    assert "github_token" in kinds


def test_multiple_secrets_same_line():
    text = f"{FAKE_AWS_KEY} and also {FAKE_GITHUB_TOKEN}"
    matches = detect(text)
    assert len(matches) >= 2


def test_detect_never_raises_on_empty_string():
    assert detect("") == []


def test_detect_never_raises_on_weird_input():
    # Should not raise even with unusual/edge-case input.
    assert detect("\x00\x01\x02" * 10) == []


# --- Regression tests for real bugs found during manual testing ---

def test_labeled_secret_with_special_characters():
    # Regression: the value character class used to exclude common
    # password symbols ($, !, etc.), silently failing to match anything
    # once a special character appeared before the 8-char minimum length.
    text = 'password = "MyDog$Fluffy99!"'
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "generic_labeled_secret" in kinds


def test_labeled_secret_with_underscore_prefixed_label():
    # Regression: `\bpassword\b` never matched inside `db_password`
    # because `_` counts as a word character, so there was no boundary
    # between "db_" and "password".
    text = 'db_password = "MyDogFluffy99"'
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "generic_labeled_secret" in kinds


def test_labeled_secret_uppercase_underscore_prefixed_label():
    text = "DB_PASSWORD=SuperSecret123!"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "generic_labeled_secret" in kinds


def test_labeled_secret_still_requires_actual_label_word():
    # Sanity check: the relaxed boundary must not turn into "match
    # anything" -- plain prose containing "password" as part of a longer
    # word, or with no separator, should still not match.
    text = "this passwordless login flow has no separator"
    matches = detect(text)
    kinds = [m.kind for m in matches]
    assert "generic_labeled_secret" not in kinds
