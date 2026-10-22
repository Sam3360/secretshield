"""
Tests for ``standalone/entry.py``: the stream-encoding setup that only the
frozen (PyInstaller) build performs.

A frozen executable ignores PYTHONIOENCODING / PYTHONUTF8, and on Windows a
redirected stdout then uses the legacy ANSI code page, which turned file names
such as ключ.py and the check/cross marks into "?". These tests drive
``prepare_streams`` through every combination without needing a real
executable (tests/test_frozen_binary.py covers the built artifact itself).
"""

from __future__ import annotations

import ast
import importlib.util
import io
import sys
from pathlib import Path

import pytest

ENTRY = Path(__file__).resolve().parent.parent / "standalone" / "entry.py"
SPEC = importlib.util.spec_from_file_location("ss_standalone_entry", ENTRY)
entry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(entry)

TEXT = "\u2713 \u043a\u043b\u044e\u0447.py \u5bc6\u94a5"  # check mark, Cyrillic, CJK


@pytest.fixture
def frozen(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)


def stream(encoding="cp1252", errors="strict"):
    raw = io.BytesIO()
    return io.TextIOWrapper(raw, encoding=encoding, errors=errors, write_through=True), raw


def prepare(env, out, err):
    entry.prepare_streams(environ=env, stdout=out, stderr=err)


class Recorder:
    """A stream that records reconfigure() calls."""

    def __init__(self, encoding):
        self.encoding = encoding
        self.calls = []

    def reconfigure(self, **kwargs):
        self.calls.append(kwargs)
        if "encoding" in kwargs:
            self.encoding = kwargs["encoding"]


# --- Default: redirected output becomes UTF-8 ---------------------------------------------


def test_a_legacy_codepage_stdout_and_stderr_become_utf8_by_default(frozen):
    out, raw_out = stream("cp1252")
    err, raw_err = stream("cp1252")
    prepare({}, out, err)
    out.write(TEXT)
    err.write(TEXT)
    assert raw_out.getvalue() == TEXT.encode("utf-8")
    assert raw_err.getvalue() == TEXT.encode("utf-8")


@pytest.mark.parametrize("legacy", ["cp1252", "cp437", "cp850", "latin-1", "ascii", "mbcs" if sys.platform == "win32" else "cp1250"])
def test_every_legacy_encoding_ends_up_as_utf8(frozen, legacy):
    out, raw = stream(legacy)
    prepare({}, out, stream()[0])
    out.write("\u2713")
    assert raw.getvalue() == "\u2713".encode("utf-8")


def test_an_already_utf8_stream_is_left_completely_alone(frozen):
    for name in ("utf-8", "UTF8", "utf_8"):
        rec = Recorder(name)
        prepare({}, rec, Recorder("utf-8"))
        assert rec.calls == [], f"{name}: an interactive console must not be touched"


def test_the_error_handler_of_a_utf8_stream_is_not_changed(frozen):
    out, _ = stream("utf-8", "backslashreplace")
    prepare({}, out, stream("utf-8")[0])
    assert out.errors == "backslashreplace"


def test_output_is_not_double_encoded(frozen):
    out, raw = stream("cp1252")
    prepare({}, out, stream()[0])
    out.write("abc")
    assert raw.getvalue() == b"abc"


# --- PYTHONIOENCODING is honored, as in a normal Python ---------------------------------------


def test_pythonioencoding_utf8_is_honored(frozen):
    out, raw = stream("cp1252")
    prepare({"PYTHONIOENCODING": "utf-8"}, out, stream()[0])
    out.write(TEXT)
    assert raw.getvalue() == TEXT.encode("utf-8")


def test_a_requested_legacy_encoding_is_honored_not_overridden(frozen):
    out, raw = stream("utf-8")
    prepare({"PYTHONIOENCODING": "cp1252"}, out, stream()[0])
    assert out.encoding == "cp1252"
    out.write("caf\u00e9")
    assert raw.getvalue() == b"caf\xe9"


def test_an_error_handler_after_the_colon_is_applied(frozen):
    out, raw = stream("cp1252")
    prepare({"PYTHONIOENCODING": "ascii:backslashreplace"}, out, stream()[0])
    out.write("a\u2713")
    assert raw.getvalue() == b"a\\u2713"


def test_pythonioencoding_with_only_an_error_handler_means_utf8(frozen):
    out, raw = stream("cp1252")
    prepare({"PYTHONIOENCODING": ":replace"}, out, stream()[0])
    out.write("\u2713")
    assert raw.getvalue() == "\u2713".encode("utf-8")


def test_surrounding_whitespace_is_tolerated(frozen):
    out, _ = stream("cp1252")
    prepare({"PYTHONIOENCODING": "  utf-8  "}, out, stream()[0])
    assert out.encoding == "utf-8"


def test_pythonioencoding_wins_over_pythonutf8(frozen):
    out, _ = stream("utf-8")
    prepare({"PYTHONIOENCODING": "latin-1", "PYTHONUTF8": "1"}, out, stream()[0])
    assert out.encoding == "latin-1"
    out, _ = stream("cp1252")
    prepare({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "0"}, out, stream()[0])
    assert out.encoding == "utf-8"


# --- PYTHONUTF8 ------------------------------------------------------------------------------------


def test_pythonutf8_zero_keeps_the_platform_default(frozen):
    out, raw = stream("cp1252")
    prepare({"PYTHONUTF8": "0"}, out, stream()[0])
    assert out.encoding == "cp1252"
    out.write("caf\u00e9")
    assert raw.getvalue() == b"caf\xe9"


def test_pythonutf8_one_means_utf8(frozen):
    out, _ = stream("cp1252")
    prepare({"PYTHONUTF8": "1"}, out, stream()[0])
    assert out.encoding == "utf-8"


# --- Robustness --------------------------------------------------------------------------------------


def test_an_unknown_encoding_name_is_ignored_not_fatal(frozen):
    out, _ = stream("cp1252")
    prepare({"PYTHONIOENCODING": "definitely-not-an-encoding"}, out, stream()[0])
    assert out.encoding == "cp1252"


def test_missing_or_unconfigurable_streams_are_tolerated(frozen):
    class Plain:
        encoding = "cp1252"

    class Refuses:
        encoding = "cp1252"

        def reconfigure(self, **kwargs):
            raise ValueError("cannot")

    prepare({}, None, None)
    prepare({}, Plain(), Refuses())  # must not raise


def test_only_the_frozen_build_is_affected(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    out, _ = stream("cp1252")
    prepare({}, out, stream()[0])
    assert out.encoding == "cp1252", "the pip package must behave exactly as before"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    prepare({}, out, stream()[0])
    assert out.encoding == "utf-8"


def test_the_real_process_streams_are_used_when_none_are_passed(frozen, monkeypatch):
    out, raw = stream("cp1252")
    err, _ = stream("cp1252")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    entry.prepare_streams(environ={})
    assert out.encoding == "utf-8" and err.encoding == "utf-8"


def test_importing_the_entry_module_has_no_side_effects():
    tree = ast.parse(ENTRY.read_text(encoding="utf-8"))
    top_level_imports = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert top_level_imports == {"codecs", "os", "sys"}, "secretshield is imported only inside __main__"
    main_block = [n for n in tree.body if isinstance(n, ast.If)][-1]
    assert "prepare_streams()" in ast.unparse(main_block) and "from secretshield.cli import main" in ast.unparse(main_block)


def test_prepare_streams_runs_before_secretshield_is_imported():
    source = ENTRY.read_text(encoding="utf-8")
    assert source.index("prepare_streams()\n    from secretshield.cli import main") > 0
