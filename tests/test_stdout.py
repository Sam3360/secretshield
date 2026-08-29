"""
Tests for stdout/stderr protection: writes containing secrets must be
redacted, normal writes must pass through unchanged, enable()/disable()
must be idempotent and must correctly restore the original streams.
"""

from __future__ import annotations

import io
import sys

import secretshield

FAKE_AWS_KEY = "AKIAABCDEFGHIJKLMNOP"


def _run_with_captured_stdout(action):
    """Helper: temporarily swap sys.stdout for a StringIO, wrap it with
    secretshield, run `action`, then always restore the real stdout."""
    original_stdout = sys.stdout
    secretshield.disable()
    buffer = io.StringIO()
    sys.stdout = buffer
    secretshield.enable()
    try:
        action()
    finally:
        secretshield.disable()
        sys.stdout = original_stdout
    return buffer.getvalue()


def _run_with_captured_stderr(action):
    original_stderr = sys.stderr
    secretshield.disable()
    buffer = io.StringIO()
    sys.stderr = buffer
    secretshield.enable()
    try:
        action()
    finally:
        secretshield.disable()
        sys.stderr = original_stderr
    return buffer.getvalue()


def test_stdout_redacts_secret():
    output = _run_with_captured_stdout(
        lambda: print(f"API key: {FAKE_AWS_KEY}")
    )
    assert FAKE_AWS_KEY not in output
    assert "********" in output


def test_stdout_passes_through_normal_text():
    output = _run_with_captured_stdout(lambda: print("hello, world"))
    assert output.strip() == "hello, world"


def test_stderr_redacts_secret():
    output = _run_with_captured_stderr(
        lambda: print(f"leaked: {FAKE_AWS_KEY}", file=sys.stderr)
    )
    assert FAKE_AWS_KEY not in output
    assert "********" in output


def test_enable_is_idempotent_no_double_wrapping():
    original_stdout = sys.stdout
    secretshield.disable()
    buffer = io.StringIO()
    sys.stdout = buffer
    try:
        secretshield.enable()
        first_wrapped = sys.stdout
        secretshield.enable()
        second_wrapped = sys.stdout
        # Calling enable() twice should not stack a second wrapper.
        assert first_wrapped is second_wrapped
    finally:
        secretshield.disable()
        sys.stdout = original_stdout


def test_disable_restores_original_stream():
    original_stdout = sys.stdout
    secretshield.disable()
    buffer = io.StringIO()
    sys.stdout = buffer
    secretshield.enable()
    assert sys.stdout is not buffer  # it should now be wrapped
    secretshield.disable()
    assert sys.stdout is buffer  # restored to the pre-enable object
    sys.stdout = original_stdout


def test_write_and_flush_still_work_after_wrapping():
    original_stdout = sys.stdout
    secretshield.disable()
    buffer = io.StringIO()
    sys.stdout = buffer
    secretshield.enable()
    try:
        sys.stdout.write("plain text\n")
        sys.stdout.flush()
    finally:
        secretshield.disable()
        sys.stdout = original_stdout
    assert buffer.getvalue() == "plain text\n"


def test_is_enabled_reflects_state():
    secretshield.disable()
    assert secretshield.is_enabled() is False
    secretshield.enable()
    assert secretshield.is_enabled() is True
    secretshield.disable()
    assert secretshield.is_enabled() is False


# --- Regression test for a real bug found during manual testing ---

def test_labeled_secret_split_across_multiple_write_calls():
    # Regression: print("label:", value) issues *separate* write() calls
    # for the label, the separator, the value, and the trailing newline.
    # Redacting each write() call in isolation meant a label and its
    # value never appeared together in the same call, so the
    # label-based generic secret pattern silently never matched. The
    # fix buffers output per logical line before redacting, so this
    # must now be caught once the line is complete.
    output = _run_with_captured_stdout(
        lambda: print("Using password:", "MyDogFluffy99")
    )
    assert "MyDogFluffy99" not in output
    assert "********" in output


def test_partial_line_without_newline_flushed_on_flush_call():
    # A write() with no trailing newline should stay buffered until an
    # explicit flush() (e.g. a progress indicator using \r), at which
    # point it must still be redacted and released.
    original_stdout = sys.stdout
    secretshield.disable()
    buffer = io.StringIO()
    sys.stdout = buffer
    secretshield.enable()
    try:
        sys.stdout.write(f"password={'MyDogFluffy99'}")  # no newline
        assert buffer.getvalue() == ""  # still buffered, nothing emitted yet
        sys.stdout.flush()
    finally:
        secretshield.disable()
        sys.stdout = original_stdout
    output = buffer.getvalue()
    assert "MyDogFluffy99" not in output
    assert "********" in output
