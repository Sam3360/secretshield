"""
Tests of the BUILT standalone executable (not the Python sources).

They are skipped unless ``SECRETSHIELD_FROZEN_BIN`` points at an executable
built by ``standalone/build.py``, so a normal ``pytest`` run is unaffected:

    SECRETSHIELD_FROZEN_BIN=dist/release/secretshield-linux-x64 pytest tests/test_frozen_binary.py
    set SECRETSHIELD_FROZEN_BIN=dist\\standalone\\secretshield\\secretshield.exe   (Windows)

Optionally ``SECRETSHIELD_FROZEN_ALIAS`` names the ``ss`` launcher (Windows
onedir builds ship ``ss.exe`` next to ``secretshield.exe``).

Everything runs with a scrubbed environment (no PYTHON* variables, a minimal
PATH) from directories that contain spaces and non-ASCII characters. All
secrets are fake.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import secretshield

FROZEN_ENV = os.environ.get("SECRETSHIELD_FROZEN_BIN")
ALIAS_ENV = os.environ.get("SECRETSHIELD_FROZEN_ALIAS")
REPO_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    not FROZEN_ENV,
    reason="set SECRETSHIELD_FROZEN_BIN to a built standalone executable to run these tests",
)

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
IS_WINDOWS = sys.platform == "win32"


@pytest.fixture(scope="module")
def frozen() -> Path:
    path = Path(FROZEN_ENV).resolve()
    assert path.is_file(), f"SECRETSHIELD_FROZEN_BIN does not exist: {path}"
    return path


def clean_env(tmp: Path, extra: dict[str, str] | None = None, path_dirs: list[Path] | None = None):
    """A minimal environment: no PYTHONPATH/PYTHONHOME, no user Python on PATH."""
    dirs = [str(p) for p in (path_dirs or [])]
    if IS_WINDOWS:
        root = os.environ.get("SystemRoot", r"C:\Windows")
        env = {
            "SystemRoot": root,
            "windir": root,
            "PATH": os.pathsep.join(dirs + [rf"{root}\System32", root]),
            "TEMP": str(tmp),
            "TMP": str(tmp),
            "USERPROFILE": str(tmp),
        }
    else:
        env = {
            "PATH": os.pathsep.join(dirs + ["/usr/bin", "/bin"]),
            "HOME": str(tmp),
            "TMPDIR": str(tmp),
            "LANG": "C.UTF-8",
        }
    env.update({"NO_COLOR": "1", "COLUMNS": "100", "PYTHONIOENCODING": "utf-8"})
    env.update(extra or {})
    return {k: v for k, v in env.items() if v is not None}  # None in `extra` removes a variable


def run(cmd, cwd: Path, env: dict, input_text: str | None = None, timeout: int = 180):
    return subprocess.run(
        [str(c) for c in cmd],
        cwd=str(cwd),
        env=env,
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def run_bytes(cmd, cwd: Path, env: dict, timeout: int = 180):
    return subprocess.run([str(c) for c in cmd], cwd=str(cwd), env=env, capture_output=True, timeout=timeout)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "pr\u00f6jekt \u5bc6\u94a5 dir"  # spaces and non-ASCII
    root.mkdir()
    (root / "\u043a\u043b\u044e\u0447.py").write_text(f'k = "{AWS}"\n', encoding="utf-8")
    (root / "ok.py").write_text("print('hello')\n", encoding="utf-8")
    return root


@pytest.fixture
def exe(frozen, tmp_path):
    def call(*args, cwd=None, env_extra=None, input_text=None, path_dirs=None):
        return run(
            [frozen, *args],
            cwd or tmp_path,
            clean_env(tmp_path, env_extra, path_dirs),
            input_text,
        )

    return call


# --- Basics ---------------------------------------------------------------------------


def test_reports_the_package_version(exe):
    result = exe("--version")
    assert result.returncode == 0
    assert result.stdout.strip() == f"secretshield {secretshield.__version__}"


def test_help_lists_the_commands(exe):
    result = exe("--help")
    assert result.returncode == 0
    for command in ("scan", "init", "install-hook", "rules", "github-action"):
        assert command in result.stdout


def test_creator_flag_works(exe):
    result = exe("--creator")
    assert result.returncode == 0 and "Samarth Chugh" in result.stdout


@pytest.mark.skipif(not ALIAS_ENV, reason="no ss launcher supplied (SECRETSHIELD_FROZEN_ALIAS)")
def test_ss_launcher_is_the_same_application(tmp_path):
    result = run([ALIAS_ENV, "--version"], tmp_path, clean_env(tmp_path))
    assert result.returncode == 0
    assert result.stdout.strip() == f"secretshield {secretshield.__version__}"


# --- Scanning ------------------------------------------------------------------------------


def test_scan_finds_secret_in_unicode_path_and_never_prints_it(exe, project):
    result = exe("scan", ".", cwd=project)
    assert result.returncode == 1
    assert "\u043a\u043b\u044e\u0447.py" in result.stdout
    assert "AWS access key" in result.stdout
    assert AWS not in result.stdout + result.stderr


def test_scan_clean_file_exits_zero(exe, project):
    result = exe("scan", "ok.py", cwd=project)
    assert result.returncode == 0
    assert "No potential secrets found" in result.stdout


def test_scan_json_is_valid_and_has_no_secret(exe, project):
    result = exe("scan", ".", "--json", cwd=project)
    data = json.loads(result.stdout)
    assert result.returncode == 1 and data["secrets_found"] == 1
    assert AWS not in result.stdout


def test_sarif_written_to_an_output_file(exe, project):
    result = exe("scan", ".", "--format", "sarif", "--output", "out.sarif", cwd=project)
    assert result.returncode == 1
    sarif = json.loads((project / "out.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert AWS not in json.dumps(sarif)


def test_errors_go_to_stderr_not_stdout(exe, project):
    # The exact exit code for a missing path is covered by the parity test below
    # (it must equal the pip-installed package's); here we check stream handling.
    result = exe("scan", "no-such-path", cwd=project)
    assert result.returncode != 0
    assert "no such path" in result.stderr
    assert result.stdout.strip() == ""


def test_not_a_git_repository_exits_two(exe, project):
    """The documented 'scanner/environment error' exit code."""
    result = exe("scan", "--staged", cwd=project)
    assert result.returncode == 2
    assert "not inside a Git repository" in result.stderr


def test_reads_config_custom_rules_ignore_file_and_inline_ignore(exe, project):
    custom = "MYAPP_" + "12345678901234567890123456789012"
    (project / "app.py").write_text(f'v = "{custom}"\n', encoding="utf-8")
    (project / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n', encoding="utf-8"
    )
    result = exe("scan", "app.py", "--json", cwd=project)
    assert [m["kind"] for m in json.loads(result.stdout)["matches"]] == ["My API Key"]

    (project / ".secretshieldignore").write_text("app.py\n", encoding="utf-8")
    assert exe("scan", ".", "--json", cwd=project).returncode == 1  # the unicode file still reports
    (project / "\u043a\u043b\u044e\u0447.py").write_text(
        f'k = "{AWS}"  # secretshield:ignore\n', encoding="utf-8"
    )
    clean = exe("scan", ".", cwd=project)
    assert clean.returncode == 0 and "suppressed by inline ignore" in clean.stdout


def test_baseline_roundtrip(exe, project):
    assert exe("scan", ".", "--baseline", cwd=project).returncode == 0
    assert (project / ".secretshield-baseline.json").is_file()
    again = exe("scan", ".", cwd=project)
    assert again.returncode == 0 and "ignored by baseline" in again.stdout


def test_history_scan_finds_a_secret_that_was_removed(exe, project):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t"}  # fmt: skip
    git_dirs = [Path(shutil.which("git")).parent]
    base = clean_env(project, env, git_dirs)
    for cmd in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "commit", "-q", "-m", "add"]):
        assert run(cmd, project, base).returncode == 0
    (project / "\u043a\u043b\u044e\u0447.py").write_text("k = None\n", encoding="utf-8")
    for cmd in (["git", "add", "-A"], ["git", "commit", "-q", "-m", "remove"]):
        assert run(cmd, project, base).returncode == 0
    assert exe("scan", ".", cwd=project).returncode == 0  # gone from the working tree
    result = exe("scan", ".", "--history", cwd=project, path_dirs=git_dirs)
    assert result.returncode == 1 and "AWS access key" in result.stdout
    assert AWS not in result.stdout


# --- Output encoding ---------------------------------------------------------------------


def test_redirected_unicode_output_is_utf8_even_without_pythonioencoding(frozen, project, tmp_path):
    """The standalone build ignores PYTHONIOENCODING natively; without an explicit
    request, redirected output must still be UTF-8 (on Windows it used to be the ANSI
    code page, printing ? for the marks and for non-ASCII file names)."""
    env = clean_env(tmp_path, {"PYTHONIOENCODING": None, "PYTHONUTF8": None})
    result = run_bytes([frozen, "scan", "."], project, env)
    assert result.returncode == 1
    text = result.stdout.decode("utf-8")  # strict: it must be valid UTF-8
    assert "\u2717 \u043a\u043b\u044e\u0447.py:1" in text
    assert "\u2713 2 files scanned" in text and "\u2717 1 potential secret(s) found" in text
    assert "?" not in text.replace("secret(s)", "")


def test_stderr_is_utf8_too(frozen, project, tmp_path):
    env = clean_env(tmp_path, {"PYTHONIOENCODING": None, "PYTHONUTF8": None})
    result = run_bytes([frozen, "scan", "no-such-\u0444\u0430\u0439\u043b"], project, env)
    assert result.returncode != 0
    assert "no-such-\u0444\u0430\u0439\u043b" in result.stderr.decode("utf-8")


def test_pythonioencoding_is_honored_like_in_a_normal_python(frozen, project, tmp_path):
    """Before this fix the frozen build ignored the variable entirely."""
    (project / "caf\u00e9.py").write_text(f'k = "{AWS}"\n', encoding="utf-8")
    env = clean_env(tmp_path, {"PYTHONIOENCODING": "latin-1"})
    result = run_bytes([frozen, "scan", "."], project, env)
    assert result.returncode == 1
    assert b"caf\xe9.py:1" in result.stdout, result.stdout  # latin-1, not UTF-8
    assert "caf\u00e9".encode("utf-8") not in result.stdout
    assert b"Traceback" not in result.stderr


def test_a_requested_legacy_codepage_does_not_crash_and_is_honored(frozen, project, tmp_path):
    for encoding in ("cp1252", "ascii", "cp437"):
        env = clean_env(tmp_path, {"PYTHONIOENCODING": encoding})
        clean = run_bytes([frozen, "scan", "ok.py"], project, env)
        assert clean.returncode == 0 and b"Traceback" not in clean.stderr, encoding
        assert b"No potential secrets found" in clean.stdout
        assert "\u2713".encode("utf-8") not in clean.stdout, f"{encoding} was ignored"
        found = run_bytes([frozen, "scan", "."], project, env)
        assert found.returncode == 1 and b"Traceback" not in found.stderr, encoding


def test_an_explicit_error_handler_is_respected(frozen, project, tmp_path):
    env = clean_env(tmp_path, {"PYTHONIOENCODING": "ascii:backslashreplace"})
    result = run_bytes([frozen, "scan", "."], project, env)
    assert result.returncode == 1
    assert b"\\u2717" in result.stdout and b"\\u043a" in result.stdout  # escaped, not "?"


def test_pythonutf8_zero_opts_out_without_crashing(frozen, project, tmp_path):
    env = clean_env(tmp_path, {"PYTHONIOENCODING": None, "PYTHONUTF8": "0"})
    result = run_bytes([frozen, "scan", "."], project, env)
    assert result.returncode == 1 and b"Traceback" not in result.stderr


# --- The `run` command -------------------------------------------------------------------


def test_run_passes_arguments_and_the_exit_code(exe, tmp_path):
    script = tmp_path / "s.py"
    script.write_text("import sys\nprint('args:', sys.argv[1:])\nsys.exit(3)\n", encoding="utf-8")
    result = exe("run", str(script), "a", "b c")
    assert result.returncode == 3
    assert "args: ['a', 'b c']" in result.stdout


def test_run_explains_the_standalone_limit_for_unbundled_imports(exe, tmp_path):
    script = tmp_path / "m.py"
    script.write_text("import xml.dom.minidom\n", encoding="utf-8")
    result = exe("run", str(script))
    assert result.returncode == 1
    assert "standalone SecretShield build" in result.stderr
    assert "pip install secretshield" in result.stderr


# --- Git hook driven by the standalone build ------------------------------------------------


def test_pre_commit_hook_uses_the_standalone_build(frozen, tmp_path):
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    name = "secretshield.exe" if IS_WINDOWS else "secretshield"
    if frozen.name == name:
        bindir = frozen.parent  # onedir launcher: needs its _internal folder next to it
    else:
        shutil.copy2(frozen, bindir / name)
    repo = tmp_path / "hook repo \u00fc"
    repo.mkdir()
    env = clean_env(tmp_path, {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"},
                    [bindir, Path(git).parent])  # fmt: skip
    for cmd in (["git", "init", "-q"], ["secretshield", "install-hook"]):
        result = run(cmd, repo, env)
        assert result.returncode == 0, result.stdout + result.stderr

    (repo / "fixture.py").write_text(f'k = "{AWS}"  # secretshield:ignore\n', encoding="utf-8")
    run(["git", "add", "fixture.py"], repo, env)
    ok = run(["git", "commit", "-q", "-m", "fixture"], repo, env)
    assert ok.returncode == 0, ok.stdout + ok.stderr

    (repo / "leak.py").write_text(f'k = "{AWS}"\n', encoding="utf-8")
    run(["git", "add", "leak.py"], repo, env)
    blocked = run(["git", "commit", "-q", "-m", "leak"], repo, env)
    assert blocked.returncode != 0
    assert "Potential secret detected" in blocked.stdout + blocked.stderr
    log = run(["git", "log", "--oneline"], repo, env).stdout
    assert "fixture" in log and "leak" not in log


# --- Parity with the pip-installed code path -------------------------------------------------


def _python_reference(tmp_path: Path):
    code = "import sys; from secretshield.cli import main; sys.exit(main())"
    env_extra = {"PYTHONPATH": str(REPO_ROOT)}
    return [sys.executable, "-c", code], env_extra


@pytest.mark.parametrize(
    "args",
    [
        ["--version"],
        ["--help"],
        ["scan", "."],
        ["scan", ".", "--json"],
        ["scan", ".", "--format", "sarif"],
        ["scan", "ok.py"],
        ["scan", "no-such-path"],
        ["rules"],
        ["scan", ".", "--no-inline-ignore", "--json"],
    ],
)
def test_output_and_exit_code_match_the_python_package(frozen, project, tmp_path, args):
    ref_cmd, ref_extra = _python_reference(tmp_path)
    reference = run([*ref_cmd, *args], project, clean_env(tmp_path, ref_extra))
    built = run([frozen, *args], project, clean_env(tmp_path))
    assert built.returncode == reference.returncode, (built.stderr, reference.stderr)

    def normal(text: str) -> str:
        return text.replace("\r\n", "\n").replace(str(project), "<project>")

    assert normal(built.stdout) == normal(reference.stdout)
    assert normal(built.stderr) == normal(reference.stderr)


# --- Temp files, isolation and network (Linux, with strace) -----------------------------------


def test_leaves_no_temp_files_behind(exe, project, tmp_path):
    scratch = tmp_path / "scratch tmp"
    scratch.mkdir()
    extra = {"TMPDIR": str(scratch), "TEMP": str(scratch), "TMP": str(scratch)}
    exe("--version", cwd=project, env_extra=extra)
    exe("scan", ".", cwd=project, env_extra=extra)
    exe("scan", "no-such-path", cwd=project, env_extra=extra)
    leftovers = [p.name for p in scratch.iterdir() if p.name.startswith("_MEI")]
    assert leftovers == []


@pytest.mark.skipif(not sys.platform.startswith("linux") or shutil.which("strace") is None,
                    reason="needs Linux and strace")  # fmt: skip
def test_does_not_touch_the_host_python_or_the_network(frozen, project, tmp_path):
    trace = tmp_path / "trace.txt"
    env = clean_env(tmp_path)
    result = subprocess.run(
        ["strace", "-f", "-qq", "-e", "trace=openat,execve,socket,connect", "-o", str(trace),
         str(frozen), "scan", "."],
        cwd=str(project), env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )  # fmt: skip
    assert result.returncode == 1, result.stderr
    lines = trace.read_text(encoding="utf-8", errors="replace").splitlines()
    opened = [ln for ln in lines if "ENOENT" not in ln]
    host_python = re.compile(r"/usr/lib/python3|site-packages|dist-packages|\.local/lib/python")
    assert not [ln for ln in opened if host_python.search(ln)]
    assert not [ln for ln in opened if str(REPO_ROOT / "secretshield") in ln]
    execs = [ln for ln in opened if "execve(" in ln]
    assert all(re.search(r"python", ln) is None for ln in execs), execs
    network = [ln for ln in lines if re.search(r"socket\(AF_INET6?,|connect\(\d+, \{sa_family=AF_INET6?", ln)]
    assert network == [], "a local scan must not open network sockets"
