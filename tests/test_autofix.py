"""
Tests for the Auto-Fix system: secretshield.autofix.python (safe
assignment detection), secretshield.autofix.env / gitignore (safe file
handling), and secretshield.autofix.fixer (the interactive orchestrator).

All secrets used are fake / non-functional.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secretshield.autofix.env import append_env_var, load_env_keys, unique_env_key
from secretshield.autofix.fixer import run_autofix
from secretshield.autofix.gitignore import ensure_env_ignored
from secretshield.autofix.python import (
    build_getenv_line,
    find_safe_assignment,
    has_import_os,
    insert_import_os,
    language_name_for,
    suggest_env_var_name,
)
from secretshield.detector import detect

FAKE_SECRET = "fakeSecretValue1234567890ABCDEF"


# --- python.py: safe assignment detection -----------------------------------


def test_simple_double_quoted_assignment_is_safe():
    result = find_safe_assignment(f'API_KEY = "{FAKE_SECRET}"', FAKE_SECRET)
    assert result is not None
    assert result.var_name == "API_KEY"
    assert result.quote == '"'


def test_single_quoted_assignment_is_safe():
    result = find_safe_assignment(f"api_key = '{FAKE_SECRET}'", FAKE_SECRET)
    assert result is not None
    assert result.quote == "'"


def test_existing_import_os_is_detected():
    assert has_import_os("import os\nAPI_KEY = os.getenv('x')\n") is True


def test_missing_import_os_gets_added():
    source = f'API_KEY = "{FAKE_SECRET}"\n'
    result = insert_import_os(source)
    assert "import os" in result
    assert result.count("import os") == 1


def test_import_os_not_duplicated():
    source = f'import os\n\nAPI_KEY = "{FAKE_SECRET}"\n'
    result = insert_import_os(source)
    assert result == source


def test_ambiguous_source_not_modified_dict_header():
    line = f'headers={{"Authorization": "Bearer {FAKE_SECRET}"}}'
    assert find_safe_assignment(line, FAKE_SECRET) is None


def test_ambiguous_source_not_modified_function_call():
    line = f'requests.get(url, headers={{"Authorization": "Bearer {FAKE_SECRET}"}})'
    assert find_safe_assignment(line, FAKE_SECRET) is None


def test_unsupported_language_reported(tmp_path):
    assert language_name_for(".js") == "JavaScript"
    assert language_name_for(".rb") == "rb"


def test_env_var_name_suggestion():
    assert suggest_env_var_name("api_key") == "API_KEY"
    assert suggest_env_var_name("OPENAI_API_KEY") == "OPENAI_API_KEY"
    assert suggest_env_var_name("token") == "TOKEN"


def test_build_getenv_line_format():
    line = build_getenv_line("    ", "API_KEY", "API_KEY", '"')
    assert line == '    API_KEY = os.getenv("API_KEY")\n'


# --- env.py / gitignore.py ---------------------------------------------------


def test_new_env_created_when_missing(tmp_path):
    env_path = tmp_path / ".env"
    append_env_var(env_path, "API_KEY", FAKE_SECRET)
    assert env_path.exists()
    assert f"API_KEY={FAKE_SECRET}" in env_path.read_text()


def test_existing_env_preserved_and_appended(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("DATABASE_URL=postgres://x\nDEBUG=true\n")
    append_env_var(env_path, "API_KEY", FAKE_SECRET)
    content = env_path.read_text()
    assert "DATABASE_URL=postgres://x" in content
    assert "DEBUG=true" in content
    assert f"API_KEY={FAKE_SECRET}" in content


def test_env_appended_rather_than_overwritten(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("EXISTING=1\n")
    append_env_var(env_path, "NEW_KEY", "value")
    lines = env_path.read_text().splitlines()
    assert lines[0] == "EXISTING=1"
    assert lines[1] == "NEW_KEY=value"


def test_unique_env_key_avoids_collision(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("API_KEY=already-here\n")
    key = unique_env_key(env_path, "API_KEY")
    assert key == "API_KEY_2"


def test_unique_env_key_avoids_same_run_collision(tmp_path):
    env_path = tmp_path / ".env"
    key = unique_env_key(env_path, "TOKEN", also_avoid={"TOKEN"})
    assert key == "TOKEN_2"


def test_gitignore_created_when_missing(tmp_path):
    gi_path = tmp_path / ".gitignore"
    changed = ensure_env_ignored(gi_path)
    assert changed is True
    assert ".env" in gi_path.read_text().splitlines()


def test_env_added_to_existing_gitignore(tmp_path):
    gi_path = tmp_path / ".gitignore"
    gi_path.write_text("node_modules/\n__pycache__/\n")
    changed = ensure_env_ignored(gi_path)
    assert changed is True
    lines = gi_path.read_text().splitlines()
    assert "node_modules/" in lines
    assert "__pycache__/" in lines
    assert ".env" in lines


def test_gitignore_not_duplicated_if_already_present(tmp_path):
    gi_path = tmp_path / ".gitignore"
    gi_path.write_text(".env\nnode_modules/\n")
    changed = ensure_env_ignored(gi_path)
    assert changed is False
    assert gi_path.read_text().count(".env") == 1


# --- fixer.py: full interactive flow -----------------------------------------


def _scripted_input(answers):
    it = iter(answers)
    return lambda prompt: next(it)


@pytest.fixture(autouse=True)
def _force_interactive(monkeypatch):
    """
    Under pytest, sys.stdin is never a real TTY, so is_interactive()
    correctly returns False by default. Most tests in this file want to
    exercise the *interactive* fix flow, so force it True here; the one
    test that specifically checks non-interactive behavior overrides
    this back to False itself via its own monkeypatch.
    """
    import secretshield.autofix.fixer as fixer_mod

    monkeypatch.setattr(fixer_mod, "is_interactive", lambda: True)


def test_full_fix_moves_simple_secret_to_env(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    matches = detect(app.read_text())

    summary = run_autofix(
        tmp_path,
        {"app.py": matches},
        input_func=_scripted_input(["y", ""]),
    )
    assert summary.fixed == 1
    assert FAKE_SECRET not in app.read_text()
    assert "os.getenv" in app.read_text()
    assert FAKE_SECRET in (tmp_path / ".env").read_text()


def test_secret_removed_from_source_after_fix(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(f'TOKEN = "{FAKE_SECRET}"\n')
    matches = detect(app.read_text())
    run_autofix(tmp_path, {"app.py": matches}, input_func=_scripted_input(["y", ""]))
    assert FAKE_SECRET not in app.read_text()


def test_secret_remains_in_env_after_fix(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(f'TOKEN = "{FAKE_SECRET}"\n')
    matches = detect(app.read_text())
    run_autofix(tmp_path, {"app.py": matches}, input_func=_scripted_input(["y", ""]))
    assert FAKE_SECRET in (tmp_path / ".env").read_text()


def test_ambiguous_source_left_untouched_by_fixer(tmp_path):
    app = tmp_path / "app.py"
    original = f'headers = {{"Authorization": "Bearer {FAKE_SECRET}"}}\n'
    app.write_text(original)
    matches = detect(app.read_text())
    summary = run_autofix(tmp_path, {"app.py": matches}, input_func=_scripted_input([]))
    assert summary.fixed == 0
    assert app.read_text() == original


def test_unsupported_language_not_modified(tmp_path):
    # Ruby remains genuinely unsupported for --fix (scan-only) -- unlike
    # JS/TS, which v0.6.0 added real Auto-Fix support for.
    rb_file = tmp_path / "app.rb"
    rb_file.write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    matches = detect(rb_file.read_text())
    original = rb_file.read_text()
    summary = run_autofix(tmp_path, {"app.rb": matches}, input_func=_scripted_input([]))
    assert summary.fixed == 0
    assert rb_file.read_text() == original


def test_js_file_with_ambiguous_construct_not_modified(tmp_path):
    # JS/TS *is* supported now, but an ambiguous construct on a JS file
    # must still be left untouched, same as Python's ambiguous cases.
    js_file = tmp_path / "app.js"
    original = f'const headers = {{Authorization: "Bearer {FAKE_SECRET}"}};\n'
    js_file.write_text(original)
    matches = detect(js_file.read_text())
    summary = run_autofix(tmp_path, {"app.js": matches}, input_func=_scripted_input([]))
    assert summary.fixed == 0
    assert js_file.read_text() == original


def test_user_declining_fix_makes_no_modification(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    original = app.read_text()
    matches = detect(app.read_text())
    summary = run_autofix(tmp_path, {"app.py": matches}, input_func=_scripted_input(["n"]))
    assert summary.fixed == 0
    assert app.read_text() == original
    assert not (tmp_path / ".env").exists()


def test_non_interactive_fix_does_not_prompt(tmp_path, monkeypatch):
    import secretshield.autofix.fixer as fixer_mod

    monkeypatch.setattr(fixer_mod, "is_interactive", lambda: False)

    app = tmp_path / "app.py"
    app.write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    original = app.read_text()
    matches = detect(app.read_text())

    def _fail(prompt):
        raise AssertionError("input() must never be called non-interactively")

    summary = run_autofix(tmp_path, {"app.py": matches}, input_func=_fail)
    assert summary.fixed == 0
    assert app.read_text() == original


def test_multiple_secrets_all_processed(tmp_path):
    app = tmp_path / "app.py"
    secret2 = "anotherFakeSecretValueZZZ999888"
    app.write_text(f'API_KEY = "{FAKE_SECRET}"\nTOKEN = "{secret2}"\n')
    matches = detect(app.read_text())
    assert len(matches) == 2

    summary = run_autofix(
        tmp_path,
        {"app.py": matches},
        input_func=_scripted_input(["y", "", "y", ""]),
    )
    assert summary.fixed == 2
    assert summary.detected == 2
    content = app.read_text()
    assert FAKE_SECRET not in content
    assert secret2 not in content


def test_original_secret_never_printed_in_output(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    matches = detect(app.read_text())

    printed = []
    run_autofix(
        tmp_path,
        {"app.py": matches},
        print_func=printed.append,
        input_func=_scripted_input(["y", ""]),
    )
    joined = "\n".join(printed)
    assert FAKE_SECRET not in joined


def test_declined_fix_never_creates_env(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    matches = detect(app.read_text())
    run_autofix(tmp_path, {"app.py": matches}, input_func=_scripted_input(["n"]))
    assert not (tmp_path / ".env").exists()


def test_env_example_never_contains_real_secret(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    matches = detect(app.read_text())
    run_autofix(tmp_path, {"app.py": matches}, input_func=_scripted_input(["y", ""]))
    example = tmp_path / ".env.example"
    assert example.exists()
    assert FAKE_SECRET not in example.read_text()
    assert "API_KEY=" in example.read_text()


def test_gitignore_updated_by_fixer(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(f'API_KEY = "{FAKE_SECRET}"\n')
    matches = detect(app.read_text())
    run_autofix(tmp_path, {"app.py": matches}, input_func=_scripted_input(["y", ""]))
    gi = tmp_path / ".gitignore"
    assert gi.exists()
    assert ".env" in gi.read_text()


def test_custom_env_var_name_honored(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(f'x = "{FAKE_SECRET}"\n')
    matches = detect(app.read_text())
    run_autofix(
        tmp_path,
        {"app.py": matches},
        input_func=_scripted_input(["y", "MY_CUSTOM_NAME"]),
    )
    assert "MY_CUSTOM_NAME" in (tmp_path / ".env").read_text()
    assert "MY_CUSTOM_NAME" in app.read_text()


# --- v0.6.0: JavaScript/TypeScript Auto-Fix, full end-to-end flow -----------


def test_js_full_fix_moves_secret_to_env(tmp_path):
    app = tmp_path / "app.js"
    app.write_text(f'const API_KEY = "{FAKE_SECRET}";\n')
    matches = detect(app.read_text())

    summary = run_autofix(tmp_path, {"app.js": matches}, input_func=_scripted_input(["y", ""]))
    assert summary.fixed == 1
    content = app.read_text()
    assert FAKE_SECRET not in content
    assert 'process.env["API_KEY"]' in content
    assert FAKE_SECRET in (tmp_path / ".env").read_text()


def test_ts_full_fix_adds_non_null_assertion(tmp_path):
    app = tmp_path / "config.ts"
    app.write_text(f'export const apiKey: string = "{FAKE_SECRET}";\n')
    matches = detect(app.read_text())

    run_autofix(tmp_path, {"config.ts": matches}, input_func=_scripted_input(["y", ""]))
    content = app.read_text()
    assert FAKE_SECRET not in content
    assert content.startswith("export const apiKey: string = process.env[")
    assert content.rstrip().endswith("!;")


def test_jsx_and_tsx_extensions_also_supported(tmp_path):
    for filename, secret in [
        ("Component.jsx", "jsxFakeSecretAAA111222333444555"),
        ("Component.tsx", "tsxFakeSecretBBB111222333444555"),
    ]:
        f = tmp_path / filename
        f.write_text(f'const API_KEY = "{secret}";\n')
        matches = detect(f.read_text())
        summary = run_autofix(tmp_path, {filename: matches}, input_func=_scripted_input(["y", ""]))
        assert summary.fixed == 1
        assert secret not in f.read_text()


def test_js_no_import_insertion_needed(tmp_path):
    # Unlike Python, JS/TS Auto-Fix must never insert an import line --
    # `process` is a Node.js global, nothing to import.
    app = tmp_path / "app.js"
    original_first_line = "// existing top comment"
    app.write_text(f'{original_first_line}\nconst API_KEY = "{FAKE_SECRET}";\n')
    matches = detect(app.read_text())

    run_autofix(tmp_path, {"app.js": matches}, input_func=_scripted_input(["y", ""]))
    content = app.read_text()
    assert content.startswith(original_first_line)
    assert "require(" not in content
    assert "import " not in content


def test_js_multiple_secrets_all_processed(tmp_path):
    app = tmp_path / "app.js"
    secret2 = "jsSecondFakeSecretZZZ999888777666"
    app.write_text(f'const API_KEY = "{FAKE_SECRET}";\nconst TOKEN = "{secret2}";\n')
    matches = detect(app.read_text())
    assert len(matches) == 2

    summary = run_autofix(
        tmp_path, {"app.js": matches}, input_func=_scripted_input(["y", "", "y", ""])
    )
    assert summary.fixed == 2
    content = app.read_text()
    assert FAKE_SECRET not in content
    assert secret2 not in content


def test_js_original_secret_never_printed(tmp_path):
    app = tmp_path / "app.js"
    app.write_text(f'const API_KEY = "{FAKE_SECRET}";\n')
    matches = detect(app.read_text())

    printed = []
    run_autofix(
        tmp_path,
        {"app.js": matches},
        print_func=printed.append,
        input_func=_scripted_input(["y", ""]),
    )
    assert FAKE_SECRET not in "\n".join(printed)


def test_js_and_python_secrets_in_same_run(tmp_path):
    # A realistic full-stack repo: both languages fixed in one pass.
    py_file = tmp_path / "app.py"
    js_file = tmp_path / "app.js"
    py_secret = "pyMixedRunFakeSecret111222333444"
    js_secret = "jsMixedRunFakeSecret555666777888"
    py_file.write_text(f'API_KEY = "{py_secret}"\n')
    js_file.write_text(f'const API_KEY = "{js_secret}";\n')

    findings = {
        "app.py": detect(py_file.read_text()),
        "app.js": detect(js_file.read_text()),
    }
    summary = run_autofix(
        tmp_path, findings, input_func=_scripted_input(["y", "", "y", ""])
    )
    assert summary.fixed == 2
    assert py_secret not in py_file.read_text()
    assert js_secret not in js_file.read_text()
    env_content = (tmp_path / ".env").read_text()
    assert py_secret in env_content
    assert js_secret in env_content
