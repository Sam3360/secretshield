"""
Tests for secretshield.autofix.javascript -- the JS/TS Auto-Fix safe-
assignment detector and line builder added in v0.6.0.

All secrets used here are fake / non-functional.
"""

from __future__ import annotations

from secretshield.autofix.javascript import build_getenv_line, find_safe_assignment

FAKE_SECRET = "jsFakeSecretValue1234567890ABCDEF"


# --- find_safe_assignment: safe cases ---------------------------------------


def test_simple_const_double_quoted_is_safe():
    result = find_safe_assignment(f'const API_KEY = "{FAKE_SECRET}";', FAKE_SECRET)
    assert result is not None
    assert result.var_name == "API_KEY"
    assert result.keyword == "const"


def test_let_single_quoted_is_safe():
    result = find_safe_assignment(f"let apiKey = '{FAKE_SECRET}';", FAKE_SECRET)
    assert result is not None
    assert result.keyword == "let"


def test_var_without_semicolon_is_safe():
    result = find_safe_assignment(f'var API_KEY = "{FAKE_SECRET}"', FAKE_SECRET)
    assert result is not None
    assert result.has_semicolon is False


def test_indented_is_safe():
    result = find_safe_assignment(f'    const API_KEY = "{FAKE_SECRET}";', FAKE_SECRET)
    assert result is not None
    assert result.indent == "    "


def test_exported_is_safe():
    result = find_safe_assignment(f'export const API_KEY = "{FAKE_SECRET}";', FAKE_SECRET)
    assert result is not None
    assert result.export_prefix == "export "


def test_typescript_typed_is_safe():
    result = find_safe_assignment(f'const apiKey: string = "{FAKE_SECRET}";', FAKE_SECRET)
    assert result is not None
    assert "string" in result.type_annotation


def test_trailing_comment_is_safe():
    result = find_safe_assignment(f'const API_KEY = "{FAKE_SECRET}"; // secret', FAKE_SECRET)
    assert result is not None


def test_template_literal_without_interpolation_is_safe():
    result = find_safe_assignment(f"const API_KEY = `{FAKE_SECRET}`;", FAKE_SECRET)
    assert result is not None


# --- find_safe_assignment: ambiguous cases ----------------------------------


def test_object_literal_is_ambiguous():
    line = f'const headers = {{Authorization: "Bearer {FAKE_SECRET}"}};'
    assert find_safe_assignment(line, FAKE_SECRET) is None


def test_template_literal_with_interpolation_is_ambiguous():
    line = f"const token = `Bearer ${{{FAKE_SECRET}}}`;"
    assert find_safe_assignment(line, FAKE_SECRET) is None


def test_string_concatenation_is_ambiguous():
    line = 'const API_KEY = "wrong" + "value";'
    assert find_safe_assignment(line, FAKE_SECRET) is None


def test_multi_declarator_is_ambiguous():
    line = f'const a = "{FAKE_SECRET}", b = "other";'
    assert find_safe_assignment(line, FAKE_SECRET) is None


def test_function_call_is_ambiguous():
    line = f'axios.get(url, {{headers: {{Authorization: "Bearer {FAKE_SECRET}"}}}});'
    assert find_safe_assignment(line, FAKE_SECRET) is None


def test_value_mismatch_is_ambiguous():
    line = 'const API_KEY = "some-other-value";'
    assert find_safe_assignment(line, FAKE_SECRET) is None


def test_empty_line_is_ambiguous():
    assert find_safe_assignment("", FAKE_SECRET) is None


def test_comment_line_is_ambiguous():
    assert find_safe_assignment(f'// const API_KEY = "{FAKE_SECRET}";', FAKE_SECRET) is None


# --- build_getenv_line -------------------------------------------------------


def test_build_line_js_no_assertion():
    safe = find_safe_assignment(f'const API_KEY = "{FAKE_SECRET}";', FAKE_SECRET)
    line = build_getenv_line(safe, "API_KEY", is_typescript=False)
    assert line == 'const API_KEY = process.env["API_KEY"];\n'


def test_build_line_ts_has_non_null_assertion():
    safe = find_safe_assignment(f'const API_KEY = "{FAKE_SECRET}";', FAKE_SECRET)
    line = build_getenv_line(safe, "API_KEY", is_typescript=True)
    assert line == 'const API_KEY = process.env["API_KEY"]!;\n'


def test_build_line_preserves_export_and_type():
    safe = find_safe_assignment(f'export const apiKey: string = "{FAKE_SECRET}";', FAKE_SECRET)
    line = build_getenv_line(safe, "API_KEY", is_typescript=True)
    assert line.startswith("export const apiKey: string = ")
    assert line.endswith('process.env["API_KEY"]!;\n')


def test_build_line_preserves_indent_and_no_semicolon():
    safe = find_safe_assignment(f'    let token = "{FAKE_SECRET}"', FAKE_SECRET)
    line = build_getenv_line(safe, "TOKEN", is_typescript=False)
    assert line == '    let token = process.env["TOKEN"]\n'
