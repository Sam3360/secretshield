"""
Tests for logging protection: secrets passed via record.msg (f-strings)
or record.args (%-style lazy formatting) must be redacted before any
handler emits them.
"""

from __future__ import annotations

import io
import logging

import secretshield

FAKE_AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
FAKE_GITHUB_TOKEN = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"


def _make_logger_with_buffer(name: str):
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers = [handler]
    logger.propagate = False
    return logger, buffer


def setup_function(_func):
    secretshield.disable()
    secretshield.enable()


def teardown_function(_func):
    secretshield.disable()


def test_logging_redacts_percent_style_args():
    logger, buffer = _make_logger_with_buffer("secretshield_test_percent")
    logger.warning("Token: %s", FAKE_AWS_KEY)
    output = buffer.getvalue()
    assert FAKE_AWS_KEY not in output
    assert "********" in output


def test_logging_redacts_fstring_message():
    logger, buffer = _make_logger_with_buffer("secretshield_test_fstring")
    logger.warning(f"Token: {FAKE_GITHUB_TOKEN}")
    output = buffer.getvalue()
    assert FAKE_GITHUB_TOKEN not in output
    assert "********" in output


def test_logging_redacts_multiple_args():
    logger, buffer = _make_logger_with_buffer("secretshield_test_multi_args")
    logger.warning("Creds: %s and %s", FAKE_AWS_KEY, FAKE_GITHUB_TOKEN)
    output = buffer.getvalue()
    assert FAKE_AWS_KEY not in output
    assert FAKE_GITHUB_TOKEN not in output


def test_logging_passes_through_safe_messages():
    logger, buffer = _make_logger_with_buffer("secretshield_test_safe")
    logger.warning("This is a perfectly safe log message")
    output = buffer.getvalue()
    assert output.strip() == "This is a perfectly safe log message"


def test_logging_works_on_child_loggers_not_just_root():
    # Regression test: protection must not depend on attaching a Filter
    # to the root logger only, since child-logger records don't pass
    # through the root logger's own `.filter()` check.
    logger, buffer = _make_logger_with_buffer("secretshield.child.module")
    logger.error("Secret leaking: %s", FAKE_AWS_KEY)
    output = buffer.getvalue()
    assert FAKE_AWS_KEY not in output


def test_logging_does_not_recurse_or_crash():
    # Sanity check: repeated logging with secrets should not raise or
    # hang due to recursive notification/logging loops.
    logger, buffer = _make_logger_with_buffer("secretshield_test_recursion")
    for _ in range(5):
        logger.warning("Token: %s", FAKE_AWS_KEY)
    output = buffer.getvalue()
    assert FAKE_AWS_KEY not in output
    assert output.count("********") == 5


def test_disable_removes_logging_protection():
    logger, buffer = _make_logger_with_buffer("secretshield_test_disable")
    secretshield.disable()
    try:
        logger.warning("Token: %s", FAKE_AWS_KEY)
        output = buffer.getvalue()
        # With protection disabled, the raw secret passes through.
        assert FAKE_AWS_KEY in output
    finally:
        secretshield.enable()
