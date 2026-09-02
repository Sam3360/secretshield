"""
Core guardian logic: wraps sys.stdout/sys.stderr and the logging module so
that secrets are redacted before they are ever written out.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, TextIO

from . import notifications
from .config import get_config
from .redactor import redact

# Sentinel attribute used to mark a stream as already wrapped, so repeated
# enable() calls don't stack wrappers on top of each other.
_WRAPPED_MARKER = "_secretshield_wrapped"

# Module-level state tracking whether protection is currently active and
# what the original (unwrapped) streams / logging factory were, so
# disable() can cleanly restore them.
_state: dict[str, Any] = {
    "active": False,
    "orig_stdout": None,
    "orig_stderr": None,
}

# Guard against re-entrant redaction triggered by secretshield's own
# console warnings being written through a wrapped stream.
_in_write = False

# A single logical "line" of output (e.g. everything print() sends before
# its trailing newline) can arrive across several separate write() calls
# -- print("label:", value) alone issues four write() calls: the label,
# the separator, the value, and the newline. Redacting each write() call
# in isolation would let a label and its value slip past detection simply
# because they never appear together within a single call. To catch that,
# each guarded stream buffers text until a newline is seen (or the buffer
# grows past a safety cap, or flush() is called), then redacts the whole
# assembled line at once before handing it to the real stream.
_MAX_BUFFER_CHARS = 65536


class _GuardedStream:
    """A drop-in replacement for a text stream that redacts secrets.

    Buffers output per logical line so that a secret split across
    multiple write() calls (as print() naturally does) is still detected
    as a whole, rather than being checked one fragment at a time.
    """

    def __init__(self, wrapped: TextIO) -> None:
        self._wrapped = wrapped
        self._buffer = ""
        setattr(self, _WRAPPED_MARKER, True)

    def _redact_and_emit(self, text: str) -> int:
        """Redact a complete chunk of text and write it to the real stream."""
        global _in_write
        config = get_config()

        if not config.enabled or _in_write:
            return self._wrapped.write(text)

        _in_write = True
        try:
            safe_text, was_redacted = redact(
                text,
                entropy_threshold=config.entropy_threshold,
                redact_with=config.redact_with,
            )
        except Exception:
            # Never let a detection failure prevent output entirely.
            safe_text, was_redacted = text, False
        finally:
            _in_write = False

        result = self._wrapped.write(safe_text)

        if was_redacted and config.notify:
            notifications.notify_console()

        return result

    def write(self, s: str) -> int:
        config = get_config()

        if not config.enabled or _in_write or not isinstance(s, str):
            # Protection disabled, re-entrant call, or non-str payload:
            # pass straight through without buffering.
            return self._wrapped.write(s)

        self._buffer += s

        while True:
            newline_index = self._buffer.find("\n")
            if newline_index == -1:
                break
            line = self._buffer[: newline_index + 1]
            self._buffer = self._buffer[newline_index + 1 :]
            self._redact_and_emit(line)

        # Safety valve: don't let unterminated output (no trailing
        # newline, e.g. a progress indicator) grow the buffer forever.
        if len(self._buffer) > _MAX_BUFFER_CHARS:
            self._redact_and_emit(self._buffer)
            self._buffer = ""

        # Text streams report the number of characters accepted, which is
        # always the full input here -- nothing is dropped, only delayed
        # until a newline (or flush) triggers the actual write.
        return len(s)

    def flush(self) -> None:
        # Release any buffered partial line (no trailing newline yet) so
        # explicit flush() calls -- e.g. from progress bars using \r --
        # still surface output promptly.
        if self._buffer:
            self._redact_and_emit(self._buffer)
            self._buffer = ""
        self._wrapped.flush()

    def isatty(self) -> bool:
        try:
            return self._wrapped.isatty()
        except Exception:
            return False

    def __getattr__(self, name: str) -> Any:
        # Delegate any other attribute access (encoding, buffer, etc.) to
        # the wrapped stream so behavior stays consistent with a normal
        # file-like object.
        return getattr(self._wrapped, name)


def _wrap_stream(stream: TextIO) -> TextIO:
    if getattr(stream, _WRAPPED_MARKER, False):
        return stream
    return _GuardedStream(stream)


def _redact_record(record: logging.LogRecord) -> None:
    """Redact secrets from a LogRecord's msg and args, in place."""
    config = get_config()
    if not config.enabled:
        return

    try:
        redacted_any = False

        if isinstance(record.msg, str):
            new_msg, changed = redact(
                record.msg,
                entropy_threshold=config.entropy_threshold,
                redact_with=config.redact_with,
            )
            record.msg = new_msg
            redacted_any = redacted_any or changed

        if record.args:
            if isinstance(record.args, dict):
                new_args = {}
                for key, value in record.args.items():
                    if isinstance(value, str):
                        new_value, changed = redact(
                            value,
                            entropy_threshold=config.entropy_threshold,
                            redact_with=config.redact_with,
                        )
                        new_args[key] = new_value
                        redacted_any = redacted_any or changed
                    else:
                        new_args[key] = value
                record.args = new_args
            else:
                new_args = []
                for value in record.args:
                    if isinstance(value, str):
                        new_value, changed = redact(
                            value,
                            entropy_threshold=config.entropy_threshold,
                            redact_with=config.redact_with,
                        )
                        new_args.append(new_value)
                        redacted_any = redacted_any or changed
                    else:
                        new_args.append(value)
                record.args = tuple(new_args)

        if redacted_any and config.notify:
            notifications.notify_console()

    except Exception:
        # Logging must never break because of a detection failure.
        pass


# We protect logging by wrapping the global LogRecord factory rather than
# using a Filter. Filters attached to a specific Logger (e.g. the root
# logger) are only consulted by the logger that originated the call, so a
# filter on the root logger would NOT see records from child loggers
# (logging.getLogger(__name__).warning(...)). The record factory, on the
# other hand, is invoked for every LogRecord created anywhere in the
# process, which gives us reliable, hierarchy-independent coverage.
_log_filter_installed = False
_orig_log_record_factory = None


def _guarded_log_record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
    record = _orig_log_record_factory(*args, **kwargs)  # type: ignore[misc]
    _redact_record(record)
    return record


def _install_logging_protection() -> None:
    global _log_filter_installed, _orig_log_record_factory
    if _log_filter_installed:
        return
    _orig_log_record_factory = logging.getLogRecordFactory()
    logging.setLogRecordFactory(_guarded_log_record_factory)
    _log_filter_installed = True


def _remove_logging_protection() -> None:
    global _log_filter_installed, _orig_log_record_factory
    if _log_filter_installed and _orig_log_record_factory is not None:
        logging.setLogRecordFactory(_orig_log_record_factory)
    _orig_log_record_factory = None
    _log_filter_installed = False


def enable() -> None:
    """
    Enable secretshield protection for ``sys.stdout``, ``sys.stderr``, and
    the standard ``logging`` module. Safe to call multiple times; repeated
    calls do not create duplicate wrappers.
    """
    if _state["active"]:
        return

    _state["orig_stdout"] = sys.stdout
    _state["orig_stderr"] = sys.stderr

    sys.stdout = _wrap_stream(sys.stdout)
    sys.stderr = _wrap_stream(sys.stderr)

    _install_logging_protection()

    _state["active"] = True


def disable() -> None:
    """
    Disable secretshield protection, restoring the original ``sys.stdout``
    and ``sys.stderr`` streams and removing the logging filter.
    """
    if not _state["active"]:
        return

    # Flush any buffered partial-line content (e.g. output with no
    # trailing newline yet) before swapping the streams out, so it isn't
    # silently lost.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, _GuardedStream):
            try:
                stream.flush()
            except Exception:
                pass

    if _state["orig_stdout"] is not None:
        sys.stdout = _state["orig_stdout"]
    if _state["orig_stderr"] is not None:
        sys.stderr = _state["orig_stderr"]

    _remove_logging_protection()

    _state["orig_stdout"] = None
    _state["orig_stderr"] = None
    _state["active"] = False


def is_enabled() -> bool:
    """Return True if secretshield protection is currently active."""
    return bool(_state["active"])
