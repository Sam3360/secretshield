"""
Tests for two v0.13.2 fixes:

* Output never crashes just because the stream's encoding can't represent the
  check/cross marks (redirected or piped output in a legacy Windows code page
  used to raise UnicodeEncodeError, even for a clean scan).
* `run` explains, in the standalone build only, why an import failed.

All secrets are fake.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from secretshield.cli import _tolerate_unencodable_output, main

REPO_ROOT = Path(__file__).resolve().parent.parent
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
_CODE = "import sys; from secretshield.cli import main; sys.exit(main())"


def run_cli(args, cwd, encoding):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONUTF8", "PYTHONIOENCODING")}
    env.update(PYTHONPATH=str(REPO_ROOT), PYTHONIOENCODING=encoding, NO_COLOR="1")
    return subprocess.run(
        [sys.executable, "-c", _CODE, *args],
        cwd=str(cwd), env=env, capture_output=True, timeout=120,
    )  # fmt: skip


def test_the_unfixed_behavior_really_was_a_crash():
    """Documents the bug: strict cp1252 cannot encode the marks the CLI prints."""
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    with pytest.raises(UnicodeEncodeError):
        stream.write("\u2713 ok")


@pytest.mark.parametrize("encoding", ["cp1252", "cp437", "ascii", "latin-1"])
def test_clean_scan_in_a_legacy_codepage_succeeds(tmp_path, encoding):
    (tmp_path / "ok.py").write_text("print(1)\n", encoding="utf-8")
    result = run_cli(["scan", "."], tmp_path, encoding)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert b"Traceback" not in result.stderr
    assert b"No potential secrets found" in result.stdout


@pytest.mark.parametrize("encoding", ["cp1252", "ascii"])
def test_scan_with_findings_in_a_legacy_codepage_keeps_the_exit_code(tmp_path, encoding):
    (tmp_path / "\u043a\u043b\u044e\u0447 \u5bc6\u94a5.py").write_text(f'k = "{AWS}"\n', encoding="utf-8")
    result = run_cli(["scan", "."], tmp_path, encoding)
    assert result.returncode == 1, result.stderr.decode("utf-8", "replace")
    assert b"Traceback" not in result.stderr
    assert b"1 potential secret(s) found" in result.stdout
    assert AWS.encode() not in result.stdout + result.stderr


def test_json_output_is_still_valid_in_a_legacy_codepage(tmp_path):
    import json

    (tmp_path / "\u043a\u043b\u044e\u0447.py").write_text(f'k = "{AWS}"\n', encoding="utf-8")
    result = run_cli(["scan", ".", "--json"], tmp_path, "cp1252")
    assert result.returncode == 1
    assert json.loads(result.stdout.decode("ascii"))["secrets_found"] == 1


def test_the_pre_commit_hook_output_survives_a_legacy_codepage(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "ok.py").write_text("print(1)\n", encoding="utf-8")
    subprocess.run(["git", "add", "ok.py"], cwd=tmp_path, check=True)
    clean = run_cli(["scan-staged"], tmp_path, "cp1252")
    assert clean.returncode == 0 and b"Traceback" not in clean.stderr
    (tmp_path / "leak.py").write_text(f'k = "{AWS}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "leak.py"], cwd=tmp_path, check=True)
    blocked = run_cli(["scan-staged"], tmp_path, "cp1252")
    assert blocked.returncode == 1 and b"Traceback" not in blocked.stderr
    assert b"Commit blocked" in blocked.stdout


def test_utf8_output_is_unchanged(tmp_path):
    (tmp_path / "ok.py").write_text("print(1)\n", encoding="utf-8")
    result = run_cli(["scan", "."], tmp_path, "utf-8")
    assert "\u2713 1 files scanned".encode("utf-8") in result.stdout


def test_helper_switches_only_the_error_handler(monkeypatch):
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", write_through=True)
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(io.BytesIO(), encoding="ascii"))
    _tolerate_unencodable_output()
    print("\u2713 caf\u00e9")  # the check mark is unencodable, the e-acute is fine in cp1252
    assert raw.getvalue() == b"? caf\xe9\n"
    assert stream.encoding == "cp1252"


def test_helper_respects_an_explicit_error_handler(monkeypatch):
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii", errors="backslashreplace", write_through=True)
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="ignore"))
    _tolerate_unencodable_output()
    assert stream.errors == "backslashreplace" and sys.stderr.errors == "ignore"
    print("\u2713")
    assert raw.getvalue() == b"\\u2713\n"


def _patch_streams(monkeypatch, out, err=None):
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err or io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="backslashreplace"))


def _wrapper(encoding, errors):
    raw = io.BytesIO()
    return io.TextIOWrapper(raw, encoding=encoding, errors=errors, write_through=True), raw


CRASHY_HANDLERS = ["strict", "surrogateescape", "surrogatepass"]
TOLERANT_HANDLERS = ["replace", "ignore", "backslashreplace", "xmlcharrefreplace", "namereplace"]
LEGACY = ["ascii", "cp1252", "cp437", "latin-1", "cp850"]


@pytest.mark.parametrize("handler", CRASHY_HANDLERS)
@pytest.mark.parametrize("encoding", LEGACY)
def test_a_stream_that_would_crash_gets_the_replace_handler(monkeypatch, encoding, handler):
    """surrogateescape is the default in many embedded/frozen interpreters and still raises."""
    monkeypatch.delenv("PYTHONIOENCODING", raising=False)
    out, raw = _wrapper(encoding, handler)
    with pytest.raises(UnicodeEncodeError):
        out.write("\u2713")  # proves this really is a crashing stream before the fix
    out, raw = _wrapper(encoding, handler)
    _patch_streams(monkeypatch, out)
    _tolerate_unencodable_output()
    assert out.errors == "replace"
    out.write("\u2713 ok")
    assert raw.getvalue() == b"? ok"


@pytest.mark.parametrize("handler", TOLERANT_HANDLERS)
@pytest.mark.parametrize("encoding", LEGACY)
def test_a_stream_that_cannot_crash_is_left_alone(monkeypatch, encoding, handler):
    monkeypatch.delenv("PYTHONIOENCODING", raising=False)
    out, _ = _wrapper(encoding, handler)
    _patch_streams(monkeypatch, out)
    _tolerate_unencodable_output()
    assert out.errors == handler


@pytest.mark.parametrize("handler", CRASHY_HANDLERS[:2] + TOLERANT_HANDLERS)
def test_an_already_utf8_stream_is_never_modified(monkeypatch, handler):
    monkeypatch.delenv("PYTHONIOENCODING", raising=False)
    out, _ = _wrapper("utf-8", handler)
    _patch_streams(monkeypatch, out)
    _tolerate_unencodable_output()
    assert out.errors == handler, "UTF-8 can encode everything: nothing to fix, so nothing is touched"


@pytest.mark.parametrize("handler", ["strict", "surrogateescape", "replace", "ignore", "backslashreplace"])
def test_an_explicit_handler_in_pythonioencoding_is_always_honored(monkeypatch, handler):
    monkeypatch.setenv("PYTHONIOENCODING", f"ascii:{handler}")
    out, _ = _wrapper("ascii", handler)
    _patch_streams(monkeypatch, out)
    _tolerate_unencodable_output()
    assert out.errors == handler


@pytest.mark.parametrize("value", ["ascii", "cp1252", "ascii:", "ascii: ", ":"])
def test_pythonioencoding_without_a_handler_is_not_an_explicit_choice(monkeypatch, value):
    monkeypatch.setenv("PYTHONIOENCODING", value)
    out, _ = _wrapper("ascii", "strict")
    _patch_streams(monkeypatch, out)
    _tolerate_unencodable_output()
    assert out.errors == "replace"


def test_stderr_with_its_default_handler_is_not_touched(monkeypatch):
    monkeypatch.delenv("PYTHONIOENCODING", raising=False)
    out, _ = _wrapper("cp1252", "strict")
    err, _ = _wrapper("cp1252", "backslashreplace")
    _patch_streams(monkeypatch, out, err)
    _tolerate_unencodable_output()
    assert out.errors == "replace" and err.errors == "backslashreplace"


@pytest.mark.parametrize("handler", CRASHY_HANDLERS + TOLERANT_HANDLERS)
@pytest.mark.parametrize("encoding", LEGACY + ["utf-8", "utf-16", "gb18030"])
def test_the_crash_probe_agrees_with_what_a_real_write_does(encoding, handler):
    """The decision is made by encoding a sample, so it must match reality exactly."""
    from secretshield.cli import _OUTPUT_PROBE, _stream_would_crash_on_unicode

    out, _ = _wrapper(encoding, handler)
    try:
        out.write(_OUTPUT_PROBE)
        really_crashes = False
    except UnicodeEncodeError:
        really_crashes = True
    out2, _ = _wrapper(encoding, handler)
    assert _stream_would_crash_on_unicode(out2) is really_crashes


def test_streams_without_an_encoding_are_treated_as_unsafe(monkeypatch):
    class Odd:
        encoding = None
        errors = None
        calls = []

        def reconfigure(self, **kwargs):
            self.calls.append(kwargs)

    odd = Odd()
    monkeypatch.delenv("PYTHONIOENCODING", raising=False)
    _patch_streams(monkeypatch, odd)
    _tolerate_unencodable_output()
    assert Odd.calls == [{"errors": "replace"}]


@pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX locale to get a non-UTF-8 stdout")
def test_pip_package_survives_an_ascii_stdout_with_the_default_surrogateescape_handler(tmp_path):
    """The case my first 'respect explicit handlers' change broke: ASCII + surrogateescape."""
    (tmp_path / "ok.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "\u043a\u043b\u044e\u0447.py").write_text(f'k = "{AWS}"\n', encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHONIO", "PYTHONUTF8", "LC_", "LANG"))}
    env.update(PYTHONPATH=str(REPO_ROOT), LC_ALL="C", PYTHONCOERCECLOCALE="0", PYTHONUTF8="0", NO_COLOR="1")
    probe = subprocess.run([sys.executable, "-c", "import sys; print(sys.stdout.encoding, sys.stdout.errors)"],
                           cwd=tmp_path, env=env, capture_output=True, text=True)  # fmt: skip
    assert probe.stdout.split() == ["ascii", "surrogateescape"], f"test premise not met: {probe.stdout!r}"
    clean = subprocess.run([sys.executable, "-c", _CODE, "scan", "ok.py"], cwd=tmp_path, env=env, capture_output=True)
    assert clean.returncode == 0, clean.stderr.decode("utf-8", "replace")
    assert b"Traceback" not in clean.stderr and b"No potential secrets found" in clean.stdout
    found = subprocess.run([sys.executable, "-c", _CODE, "scan", "."], cwd=tmp_path, env=env, capture_output=True)
    assert found.returncode == 1 and b"Traceback" not in found.stderr
    assert b"1 potential secret(s) found" in found.stdout


def test_pip_package_honors_an_explicit_strict_handler_like_python(tmp_path):
    (tmp_path / "ok.py").write_text("print(1)\n", encoding="utf-8")
    result = run_cli(["scan", "ok.py"], tmp_path, "ascii:strict")
    assert result.returncode != 0 and b"UnicodeEncodeError" in result.stderr


@pytest.mark.parametrize(
    "handler, expected",
    [("replace", b"? 1 files scanned"), ("ignore", b" 1 files scanned"),
     ("backslashreplace", b"\\u2713 1 files scanned"), ("xmlcharrefreplace", b"&#10003; 1 files scanned")],
)  # fmt: skip
def test_pip_package_applies_each_explicit_handler(tmp_path, handler, expected):
    (tmp_path / "ok.py").write_text("print(1)\n", encoding="utf-8")
    result = run_cli(["scan", "ok.py"], tmp_path, f"ascii:{handler}")
    assert result.returncode == 0 and expected in result.stdout, result.stdout


def test_helper_tolerates_streams_that_cannot_be_reconfigured(monkeypatch):
    class Plain:
        pass

    class Refuses:
        def reconfigure(self, **kwargs):
            raise ValueError("can't")

    monkeypatch.setattr(sys, "stdout", Plain())
    monkeypatch.setattr(sys, "stderr", Refuses())
    _tolerate_unencodable_output()  # must not raise


# --- `run` hint (standalone build only) ----------------------------------------------------------


def _script(tmp_path, body):
    path = tmp_path / "s.py"
    path.write_text(body, encoding="utf-8")
    return str(path)


def test_import_failure_gets_a_hint_in_the_standalone_build(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    code = main(["run", _script(tmp_path, "import definitely_not_a_module_xyz\n")])
    err = capsys.readouterr().err
    assert code == 1
    assert "script raised an exception" in err
    assert "standalone SecretShield build" in err and "pip install secretshield" in err


def test_no_hint_in_the_normal_python_package(tmp_path, monkeypatch, capsys):
    monkeypatch.delattr(sys, "frozen", raising=False)
    code = main(["run", _script(tmp_path, "import definitely_not_a_module_xyz\n")])
    err = capsys.readouterr().err
    assert code == 1 and "script raised an exception" in err
    assert "standalone" not in err


def test_other_errors_get_no_hint_even_when_frozen(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    code = main(["run", _script(tmp_path, "raise ValueError('boom')\n")])
    err = capsys.readouterr().err
    assert code == 1 and "boom" in err and "standalone" not in err
