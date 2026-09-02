"""
Tests for the expanded `secretshield scan` CLI: multi-language file
support, ignored directories, binary-file handling, --json output, exit
codes, and the guarantee that secret values never appear in any scan
output.

These tests exercise the CLI's internal functions directly (rather than
spawning a subprocess) for speed, plus a couple of end-to-end
subprocess-free calls through `main()` to check exit codes.

All secrets used here are fake / non-functional.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from secretshield.cli import _cmd_scan, build_parser, main

FAKE_OPENAI_KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz1234567890"
FAKE_GITHUB_TOKEN = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
FAKE_BEARER = "Bearer 8fK3ndL92aWpQzX7mYtR4vB1cJ6sHo"
FAKE_PASSWORD = "MyDogFluffy99"


@pytest.fixture
def project_dir(tmp_path: Path) -> Path:
    """Build a small multi-language fake project under a temp directory."""
    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules" / "somelib").mkdir(parents=True)
    (tmp_path / ".git").mkdir()

    (tmp_path / "app.py").write_text(
        f'api_key = "{FAKE_OPENAI_KEY}"\nprint("started")\n'
    )
    (tmp_path / "src" / "app.js").write_text(
        f'const config = {{\n  apiKey: "{FAKE_OPENAI_KEY}"\n}};\n'
        f'const header = "{FAKE_BEARER}";\n'
    )
    (tmp_path / "component.tsx").write_text(
        f'const config = {{\n  apiKey: "{FAKE_OPENAI_KEY}"\n}};\n'
    )
    (tmp_path / "component.jsx").write_text(
        f'const token = "{FAKE_GITHUB_TOKEN}";\n'
    )
    (tmp_path / "index.html").write_text(
        f"<html><script>\nconst API_KEY = \"{FAKE_OPENAI_KEY}\";\n</script></html>\n"
    )
    (tmp_path / "styles.css").write_text(
        "/* no secrets here, just styling */\nbody { color: red; }\n"
    )
    (tmp_path / "App.vue").write_text(
        f'<script>\nconst apiKey = "{FAKE_OPENAI_KEY}";\n</script>\n'
    )
    (tmp_path / "App.svelte").write_text(
        f'<script>\nconst apiKey = "{FAKE_OPENAI_KEY}";\n</script>\n'
    )
    (tmp_path / "data.json").write_text(f'{{"api_key": "{FAKE_OPENAI_KEY}"}}\n')
    (tmp_path / "config.yaml").write_text(f'password: "{FAKE_PASSWORD}"\n')
    (tmp_path / ".env").write_text(f"DB_PASSWORD={FAKE_PASSWORD}\n")
    (tmp_path / "deploy.sh").write_text(f'export TOKEN="{FAKE_GITHUB_TOKEN}"\n')
    (tmp_path / "README.md").write_text("Just documentation, nothing secret.\n")

    # Should be skipped by default (ignored directory).
    (tmp_path / "node_modules" / "somelib" / "index.js").write_text(
        f'const leaked = "{FAKE_GITHUB_TOKEN}";\n'
    )

    # Fake binary file that must not be read as text.
    (tmp_path / "logo.png").write_bytes(bytes([0, 1, 2, 255, 254, 253]) * 20)

    return tmp_path


def _run_scan(args_list):
    parser = build_parser()
    args = parser.parse_args(["scan", *args_list])
    return _cmd_scan(args)


def _collect_all_secret_strings():
    return [FAKE_OPENAI_KEY, FAKE_GITHUB_TOKEN, FAKE_BEARER, FAKE_PASSWORD]


# --- Per-file-type detection -------------------------------------------------


def test_scans_python_file(project_dir, capsys):
    exit_code = _run_scan([str(project_dir / "app.py")])
    out = capsys.readouterr().out
    assert exit_code == 1
    assert "openai_api_key" not in out or "Potential secret" in out


def test_scans_html_file(project_dir, capsys):
    exit_code = _run_scan([str(project_dir / "index.html")])
    assert exit_code == 1


def test_scans_js_file(project_dir, capsys):
    exit_code = _run_scan([str(project_dir / "src" / "app.js")])
    assert exit_code == 1


def test_scans_jsx_file(project_dir):
    exit_code = _run_scan([str(project_dir / "component.jsx")])
    assert exit_code == 1


def test_scans_tsx_file(project_dir):
    exit_code = _run_scan([str(project_dir / "component.tsx")])
    assert exit_code == 1


def test_scans_css_file_no_false_positive(project_dir):
    exit_code = _run_scan([str(project_dir / "styles.css")])
    assert exit_code == 0


def test_scans_vue_file(project_dir):
    exit_code = _run_scan([str(project_dir / "App.vue")])
    assert exit_code == 1


def test_scans_svelte_file(project_dir):
    exit_code = _run_scan([str(project_dir / "App.svelte")])
    assert exit_code == 1


def test_scans_json_file(project_dir):
    exit_code = _run_scan([str(project_dir / "data.json")])
    assert exit_code == 1


def test_scans_yaml_file(project_dir):
    exit_code = _run_scan([str(project_dir / "config.yaml")])
    assert exit_code == 1


def test_scans_env_file(project_dir):
    exit_code = _run_scan([str(project_dir / ".env")])
    assert exit_code == 1


def test_scans_shell_script(project_dir):
    exit_code = _run_scan([str(project_dir / "deploy.sh")])
    assert exit_code == 1


def test_clean_markdown_file_no_false_positive(project_dir):
    exit_code = _run_scan([str(project_dir / "README.md")])
    assert exit_code == 0


# --- Recursive directory scanning & ignored directories ---------------------


def test_recursive_directory_scan_finds_multiple_files(project_dir, capsys):
    exit_code = _run_scan([str(project_dir)])
    out = capsys.readouterr().out
    assert exit_code == 1
    assert "app.py" in out
    assert "app.js" in out


def test_ignored_directories_skipped_by_default(project_dir, capsys):
    _run_scan([str(project_dir)])
    out = capsys.readouterr().out
    assert "node_modules" not in out


def test_no_ignore_flag_includes_ignored_directories(project_dir, capsys):
    _run_scan([str(project_dir), "--no-ignore"])
    out = capsys.readouterr().out
    assert "node_modules" in out


def test_binary_file_is_skipped_without_error(project_dir, capsys):
    # Should not raise, and the binary file's garbage bytes must never
    # appear in output.
    exit_code = _run_scan([str(project_dir)])
    out = capsys.readouterr().out
    assert "logo.png" not in out
    assert exit_code in (0, 1)


# --- --json output ------------------------------------------------------------


def test_json_output_is_valid_json(project_dir, capsys):
    _run_scan([str(project_dir), "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert "files_scanned" in payload
    assert "matches" in payload
    assert "secrets_found" in payload


def test_json_output_matches_have_no_secret_value(project_dir, capsys):
    _run_scan([str(project_dir), "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    for match in payload["matches"]:
        assert set(match.keys()) == {"file", "line", "kind"}
        assert isinstance(match["line"], int)


def test_json_secrets_found_matches_matches_length(project_dir, capsys):
    _run_scan([str(project_dir), "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["secrets_found"] == len(payload["matches"])


# --- Exit codes -----------------------------------------------------------


def test_exit_code_zero_when_clean(tmp_path, capsys):
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("nothing secret in this file at all\n")
    exit_code = _run_scan([str(clean_file)])
    assert exit_code == 0


def test_exit_code_one_when_secrets_found(project_dir):
    exit_code = _run_scan([str(project_dir / "app.py")])
    assert exit_code == 1


def test_main_entrypoint_scan_exit_code(project_dir):
    exit_code = main(["scan", str(project_dir / "app.py")])
    assert exit_code == 1


# --- Secret values must never appear in any scan output ---------------------


def test_no_secret_value_ever_appears_in_human_output(project_dir, capsys):
    _run_scan([str(project_dir)])
    out = capsys.readouterr().out
    for secret in _collect_all_secret_strings():
        assert secret not in out


def test_no_secret_value_ever_appears_in_json_output(project_dir, capsys):
    _run_scan([str(project_dir), "--json"])
    out = capsys.readouterr().out
    for secret in _collect_all_secret_strings():
        assert secret not in out


# --- --include / --exclude ---------------------------------------------------


def test_exclude_pattern_removes_matching_files(project_dir, capsys):
    _run_scan([str(project_dir), "--exclude", "*.js"])
    out = capsys.readouterr().out
    assert "app.js" not in out


def test_include_pattern_restricts_to_matching_files(project_dir, capsys):
    _run_scan([str(project_dir), "--include", "*.py"])
    out = capsys.readouterr().out
    assert "app.py" in out
    assert "app.js" not in out


# --- Placeholder filtering ---------------------------------------------------


def test_obvious_placeholder_not_flagged(tmp_path, capsys):
    f = tmp_path / "config.env"
    f.write_text("API_KEY=your_api_key_here\n")
    exit_code = _run_scan([str(f)])
    assert exit_code == 0


def test_changeme_placeholder_not_flagged(tmp_path):
    f = tmp_path / "config.env"
    f.write_text("password=changeme\n")
    exit_code = _run_scan([str(f)])
    assert exit_code == 0


def test_real_looking_secret_still_flagged_alongside_placeholder(tmp_path):
    f = tmp_path / "config.env"
    f.write_text(f"API_KEY=your_api_key_here\nPASSWORD={FAKE_PASSWORD}\n")
    exit_code = _run_scan([str(f)])
    assert exit_code == 1


# --- Regression test for a real bug found during manual testing ---


def test_scan_own_report_text_is_never_self_redacted(tmp_path):
    # Regression: scan's own CLI output was passing through the live
    # runtime redaction filter (since importing secretshield enables it
    # by default). The kind label "High-entropy string", printed right
    # after the word "secret:", happened to match the generic-label
    # detection pattern on itself -- turning the *display text* into
    # "secret: ******** string" even though nothing sensitive was
    # actually printed. `scan`'s own reporting must never be mangled
    # like this, regardless of whether runtime protection is enabled.
    import io
    import secrets
    import string
    import sys

    import secretshield

    random_value = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
    )
    f = tmp_path / "data.txt"
    f.write_text(f"random_blob = {random_value}\n")

    original_stdout = sys.stdout
    secretshield.disable()
    buffer = io.StringIO()
    sys.stdout = buffer
    secretshield.enable()
    try:
        exit_code = _run_scan([str(f)])
    finally:
        secretshield.disable()
        sys.stdout = original_stdout

    out = buffer.getvalue()
    assert exit_code == 1
    assert "High-entropy string" in out
    assert "********" not in out
