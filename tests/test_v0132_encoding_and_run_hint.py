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
