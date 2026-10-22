"""
Tests for v0.13.1: inline ignore comments (`secretshield:ignore`).

All secrets are fake and built by concatenation. The hook tests run a real
`git commit` through the installed hook, so (as with the other hook tests)
the venv's bin directory must be on PATH.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from secretshield import detect, redact
from secretshield.cli import _line_number_for_offset, main
from secretshield.inline_ignore import collect_suppressions, filter_inline_ignored

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GH = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
GH2 = "ghp_" + "z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2"
CUSTOM = "MYAPP_" + "12345678901234567890123456789012"
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEs\n"
    "-----END RSA PRIVATE KEY-----\n"
)


class _M:
    """Minimal stand-in for a Match (the filter only needs start and kind)."""

    def __init__(self, start, kind="github_token"):
        self.start, self.kind = start, kind


def _project(tmp_path, monkeypatch, files):
    monkeypatch.chdir(tmp_path)
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8", newline="")


def _scan_json(capsys, *extra):
    code = main(["scan", ".", "--json", *extra])
    return code, json.loads(capsys.readouterr().out)


# --- Marker grammar -----------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "x = 1  # secretshield:ignore",
        "x = 1  // secretshield:ignore",
        "x = 1  /* secretshield:ignore */",
        "select 1 -- secretshield:ignore",
        "<p>x</p> <!-- secretshield:ignore -->",
        "key = value ; secretshield:ignore",
        "# secretshield: ignore",  # spaces after the colon are tolerated
        "#secretshield:ignore",
        "x = 1  # secretshield:ignore  because it is a test fixture",
        "x = 1  # secretshield:ignore[]".replace("[]", "[github_token]"),
    ],
)
def test_marker_is_recognized_in_any_comment_style(line):
    assert collect_suppressions(line) == {
        1: None if "[" not in line else {"github_token"}
    }


def test_next_line_marker_targets_the_following_line():
    assert collect_suppressions("a\n# secretshield:ignore-next-line\nb\n") == {3: None}


def test_marker_kind_list_is_parsed_and_trimmed():
    got = collect_suppressions("# secretshield:ignore[ github_token ,high_entropy,, My Rule ]")
    assert got == {1: {"github_token", "high_entropy", "My Rule"}}


def test_empty_kind_list_suppresses_nothing():
    assert collect_suppressions("# secretshield:ignore[]") == {1: set()}
    assert filter_inline_ignored("# secretshield:ignore[]\n", [_M(0)])[1] == 0


@pytest.mark.parametrize(
    "line",
    [
        "# secretshield:ignored",  # a longer word
        "# secretshield:ignore-nextline",  # misspelled variant
        "# secretshield:ignore-next-line-please",
        "# secretshield:ignore_all",
        "# SECRETSHIELD:IGNORE",  # case-sensitive on purpose
        "# SecretShield:ignore",
        "# secretshield ignore",
        "# secretshield:",
        "# secretshield:skip",
        "# secret-shield:ignore",
    ],
)
def test_near_misses_are_not_honored(line):
    assert collect_suppressions(line) == {}


def test_case_is_enforced_by_the_pattern_not_just_the_fast_path():
    # The fast path only looks for the lowercase prefix. A line that has it
    # AND an uppercase marker gets past the fast path, so the pattern itself
    # must refuse the uppercase one.
    assert collect_suppressions("# secretshield: note  SECRETSHIELD:IGNORE") == {}
    assert collect_suppressions("# secretshield: note  Secretshield:Ignore-Next-Line") == {}
    assert collect_suppressions("# secretshield: note  secretshield:IGNORE") == {}
    assert collect_suppressions("# secretshield: note  secretshield:ignore") == {1: None}


def test_a_same_line_and_a_next_line_marker_combine_on_one_target_line():
    text = "# secretshield:ignore-next-line[aws_access_key_id]\nx  # secretshield:ignore[github_token]\n"
    assert collect_suppressions(text) == {2: {"aws_access_key_id", "github_token"}}


def test_an_unqualified_marker_wins_over_a_qualified_one_on_the_same_line():
    text = "# secretshield:ignore-next-line[github_token]\nx  # secretshield:ignore\n"
    assert collect_suppressions(text) == {2: None}
    text = "x  # secretshield:ignore\n"  # and the order does not matter
    text2 = "# secretshield:ignore-next-line\nx  # secretshield:ignore[github_token]\n"
    assert collect_suppressions(text2) == {2: None}


def test_text_without_the_prefix_is_a_no_op():
    assert collect_suppressions("just code\nmore code\n") == {}
    matches = [_M(3)]
    kept, n = filter_inline_ignored("just code", matches)
    assert (kept, n) == (matches, 0)


# --- Line numbering matches the scanner's ---------------------------------------------


def test_line_numbers_agree_with_the_scanners_even_with_odd_line_separators():
    # str.splitlines() would also split on \x0c and \u2028, shifting every
    # later line. The marker's idea of "line" must equal the scanner's.
    text = f"a\x0cb\u2028c\n# secretshield:ignore-next-line\nkey = {GH}\nkey2 = {GH2}\n"
    matches = detect(text)
    assert len(matches) == 2
    kept, n = filter_inline_ignored(text, matches)
    assert n == 1
    assert [_line_number_for_offset(text, m.start) for m in kept] == [4]


def test_crlf_files_work(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "a.py": f'k = "{GH}"  # secretshield:ignore\r\n# secretshield:ignore-next-line\r\nk2 = "{GH2}"\r\nok = 1\r\n',
    })  # fmt: skip
    code, report = _scan_json(capsys)
    assert code == 0 and report["inline_ignored"] == 2 and report["matches"] == []


def test_filter_uses_the_line_where_a_match_starts():
    text = f"x\ny = '{GH}'\n"
    start = text.index(GH)
    assert filter_inline_ignored(text + "# secretshield:ignore\n", [_M(start)])[1] == 0
    assert filter_inline_ignored(f"x\ny = '{GH}'  # secretshield:ignore\n", [_M(start)])[1] == 1


def test_a_multiline_private_key_is_suppressed_by_a_marker_before_it():
    text = "# secretshield:ignore-next-line\n" + PRIVATE_KEY
    matches = detect(text)
    assert [m.kind for m in matches] == ["private_key_block"]
    assert filter_inline_ignored(text, matches)[1] == 1


def test_a_marker_inside_the_key_body_does_not_suppress_it():
    text = PRIVATE_KEY.replace("KUpRKf", "# secretshield:ignore\nKUpRKf", 1)
    matches = detect(text)
    assert [m.kind for m in matches] == ["private_key_block"]
    assert filter_inline_ignored(text, matches)[1] == 0


# --- Scan behavior ---------------------------------------------------------------------


def test_same_line_marker_suppresses_only_that_line(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "a.py": f'a = "{GH}"  # secretshield:ignore\nb = "{GH}"\n',
    })  # fmt: skip
    code, report = _scan_json(capsys)
    assert code == 1
    assert [m["line"] for m in report["matches"]] == [2]
    assert report["inline_ignored"] == 1


def test_next_line_marker_covers_exactly_one_line(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "a.py": f'# secretshield:ignore-next-line\na = "{GH}"\nb = "{GH}"\n',
    })  # fmt: skip
    code, report = _scan_json(capsys)
    assert [m["line"] for m in report["matches"]] == [3]
    assert report["inline_ignored"] == 1


def test_a_next_line_marker_does_not_suppress_a_secret_on_its_own_line(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "a.py": f'a = "{GH}"  # secretshield:ignore-next-line\nok = 1\n',
    })  # fmt: skip
    code, report = _scan_json(capsys)
    assert code == 1 and [m["line"] for m in report["matches"]] == [1]
    assert "inline_ignored" not in report


def test_kind_qualified_marker_only_hides_the_named_kind(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "a.py": f'both = ("{AWS}", "{GH}")  # secretshield:ignore[aws_access_key_id]\n',
    })  # fmt: skip
    code, report = _scan_json(capsys)
    assert code == 1
    assert [m["kind"] for m in report["matches"]] == ["github_token"]
    assert report["inline_ignored"] == 1


def test_a_wrong_or_misspelled_kind_leaves_the_finding_visible(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "a.py": f'a = "{GH}"  # secretshield:ignore[github_tokn]\n',
        "b.py": f'b = "{GH}"  # secretshield:ignore[aws_access_key_id]\n',
    })  # fmt: skip
    code, report = _scan_json(capsys)
    assert code == 1 and len(report["matches"]) == 2 and "inline_ignored" not in report


def test_custom_rules_can_be_suppressed_by_rule_name(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "a.py": f'a = "{CUSTOM}"  # secretshield:ignore[My API Key]\nb = "{CUSTOM}"\n',
        ".secretshield-rules.toml": '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n',
    })  # fmt: skip
    code, report = _scan_json(capsys)
    assert [(m["line"], m["kind"]) for m in report["matches"]] == [(2, "My API Key")]
    assert report["inline_ignored"] == 1


@pytest.mark.parametrize(
    "name, line",
    [
        ("a.py", "# secretshield:ignore"),
        ("a.js", "// secretshield:ignore"),
        ("a.sql", "-- secretshield:ignore"),
        ("a.md", "<!-- secretshield:ignore -->"),
        ("a.yaml", "# secretshield:ignore"),
        ("a.ini", "; secretshield:ignore"),
    ],
)
def test_works_across_file_types(tmp_path, monkeypatch, capsys, name, line):
    _project(tmp_path, monkeypatch, {name: f"token {GH} {line}\n"})
    code, report = _scan_json(capsys)
    assert code == 0 and report["inline_ignored"] == 1


def test_a_whole_file_is_never_silenced_by_one_marker(tmp_path, monkeypatch, capsys):
    text = "# secretshield:ignore\n" + "".join(f'k{i} = "{GH}"\n' for i in range(5))
    _project(tmp_path, monkeypatch, {"a.py": text})
    code, report = _scan_json(capsys)
    assert code == 1 and len(report["matches"]) == 5 and "inline_ignored" not in report


# --- Reporting -----------------------------------------------------------------------------


def test_text_report_shows_the_suppressed_count_and_never_the_secret(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"a.py": f'a = "{GH}"  # secretshield:ignore\n'})
    assert main(["scan", "."]) == 0
    out = capsys.readouterr().out
    assert "1 finding(s) suppressed by inline ignore comments" in out
    assert "No potential secrets found" in out
    assert GH not in out


def test_text_report_is_unchanged_when_nothing_was_suppressed(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"a.py": f'a = "{GH}"\n'})
    assert main(["scan", "."]) == 1
    assert "suppressed" not in capsys.readouterr().out


def test_json_schema_is_unchanged_when_nothing_was_suppressed(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"a.py": f'a = "{GH}"\n'})
    code, report = _scan_json(capsys)
    assert set(report) == {"files_scanned", "matches", "secrets_found"}


def test_no_inline_ignore_shows_everything_again(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"a.py": f'a = "{GH}"  # secretshield:ignore\n'})
    code, report = _scan_json(capsys, "--no-inline-ignore")
    assert code == 1 and len(report["matches"]) == 1 and "inline_ignored" not in report
    assert main(["scan", ".", "--no-inline-ignore"]) == 1
    assert "suppressed" not in capsys.readouterr().out


def test_sarif_output_omits_suppressed_findings(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "a.py": f'a = "{GH}"  # secretshield:ignore\nb = "{AWS}"\n',
    })  # fmt: skip
    assert main(["scan", ".", "--format", "sarif"]) == 1
    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["secretshield.aws_access_key_id"]


# --- Interactions with other mechanisms ------------------------------------------------------


def test_suppressed_findings_are_not_written_to_the_baseline(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "a.py": f'a = "{GH}"  # secretshield:ignore\nb = "{AWS}"\n',
    })  # fmt: skip
    assert main(["scan", ".", "--baseline"]) == 0
    out = capsys.readouterr().out
    assert "(1 finding(s))" in out
    assert "1 finding(s) suppressed by inline ignore comments (not added to the baseline)" in out
    data = json.loads((tmp_path / ".secretshield-baseline.json").read_text())
    assert [f["kind"] for f in data["findings"]] == ["aws_access_key_id"]
    assert GH not in json.dumps(data) and AWS not in json.dumps(data)
    # ...so auditing without inline ignores still surfaces the suppressed one.
    assert main(["scan", ".", "--no-inline-ignore"]) == 1


def test_baseline_behaviour_is_otherwise_unchanged(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"a.py": f'a = "{AWS}"\n'})
    assert main(["scan", ".", "--baseline"]) == 0
    capsys.readouterr()
    assert main(["scan", "."]) == 0
    assert "ignored by baseline" in capsys.readouterr().out


def test_a_baselined_and_an_inline_ignored_finding_are_counted_separately(
    tmp_path, monkeypatch, capsys
):
    _project(tmp_path, monkeypatch, {"a.py": f'a = "{AWS}"\n'})
    assert main(["scan", ".", "--baseline"]) == 0
    (tmp_path / "b.py").write_text(f'b = "{GH}"  # secretshield:ignore\n')
    capsys.readouterr()
    code, report = _scan_json(capsys)
    assert code == 0 and report["ignored_by_baseline"] == 1 and report["inline_ignored"] == 1


def test_ignore_file_and_inline_ignore_work_together(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "a.py": f'a = "{GH}"  # secretshield:ignore\n',
        "skipme.py": f'b = "{GH}"\n',
        ".secretshieldignore": "skipme.py\n",
    })  # fmt: skip
    code, report = _scan_json(capsys)
    assert code == 0 and report["files_scanned"] == 1 and report["inline_ignored"] == 1


def test_rotate_does_not_offer_suppressed_findings(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"a.py": f'a = "{GH}"  # secretshield:ignore\n'})
    assert main(["scan", ".", "--rotate"]) == 0
    assert "nothing to rotate" in capsys.readouterr().out
    # With inline ignores disabled the credential is offered again.
    assert main(["scan", ".", "--rotate", "--no-inline-ignore"]) == 1
    assert "requires an interactive terminal" in capsys.readouterr().out


def test_fix_does_not_touch_suppressed_findings(tmp_path, monkeypatch):
    source = f'import os\nA = "{GH}"  # secretshield:ignore\n'
    _project(tmp_path, monkeypatch, {"a.py": source})
    assert main(["scan", ".", "--fix"]) == 0
    assert (tmp_path / "a.py").read_text() == source
    assert not (tmp_path / ".env").exists()


# --- Runtime protection never honors markers --------------------------------------------------


def test_runtime_detection_and_redaction_ignore_the_marker():
    line = f"print('{GH}')  # secretshield:ignore"
    assert [m.kind for m in detect(line)] == ["github_token"]
    redacted, was_redacted = redact(line)
    assert was_redacted and GH not in redacted


def _captured_with_protection(action):
    """Same approach as test_stdout.py: wrap a buffer with live protection."""
    import io
    import sys

    import secretshield

    original = sys.stdout
    secretshield.disable()
    buffer = io.StringIO()
    sys.stdout = buffer
    secretshield.enable()
    try:
        action()
    finally:
        secretshield.disable()
        sys.stdout = original
    return buffer.getvalue()


def test_printing_a_secret_is_still_redacted_with_a_marker_in_the_text():
    out = _captured_with_protection(lambda: print(f"leak {GH}  # secretshield:ignore"))
    assert GH not in out
    assert "********" in out


def test_logging_a_secret_is_still_redacted_with_a_marker_in_the_text():
    import logging

    def action():
        import sys

        handler = logging.StreamHandler(sys.stdout)
        log = logging.getLogger("v0131-marker-test")
        log.handlers = [handler]
        log.propagate = False
        log.warning("token=%s  # secretshield:ignore", GH)

    out = _captured_with_protection(action)
    assert GH not in out


# --- The pre-commit hook path (a separate scanner: `scan-staged`) --------------------------------


def _init_repo(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True)


def _stage(path, name, text):
    (path / name).write_text(text, encoding="utf-8", newline="")
    subprocess.run(["git", "add", name], cwd=path, check=True)


def test_scan_staged_honors_the_marker(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    _stage(tmp_path, "a.py", f'a = "{GH}"  # secretshield:ignore\n')
    assert main(["scan-staged"]) == 0
    out = capsys.readouterr().out
    assert "1 finding(s) suppressed by inline ignore comments" in out
    assert "No secrets detected" in out and GH not in out


def test_scan_staged_still_blocks_unmarked_and_wrongly_qualified_secrets(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    _stage(tmp_path, "a.py", f'a = "{GH}"\nb = "{GH}"  # secretshield:ignore[aws_access_key_id]\n')
    assert main(["scan-staged"]) == 1
    out = capsys.readouterr().out
    assert "Commit blocked" in out and out.count("Potential secret detected") == 2


def test_scan_staged_next_line_marker_and_the_opt_out_flag(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    _stage(tmp_path, "a.py", f'# secretshield:ignore-next-line\na = "{GH}"\n')
    assert main(["scan-staged"]) == 0
    capsys.readouterr()
    assert main(["scan-staged", "--no-inline-ignore"]) == 1


def test_scan_dash_dash_staged_honors_the_marker(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    _stage(tmp_path, "a.py", f'a = "{GH}"  # secretshield:ignore\n')
    assert main(["scan", "--staged"]) == 0
    assert "suppressed by inline ignore comments" in capsys.readouterr().out


def test_staged_content_not_the_working_tree_decides(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    _stage(tmp_path, "a.py", f'a = "{GH}"\n')  # staged WITHOUT a marker
    (tmp_path / "a.py").write_text(f'a = "{GH}"  # secretshield:ignore\n')  # unstaged edit
    assert main(["scan-staged"]) == 1


def test_real_commit_succeeds_with_a_marker_and_is_blocked_without_one(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    assert main(["install-hook"]) == 0

    _stage(tmp_path, "fixture.py", f'TOKEN = "{GH}"  # secretshield:ignore\n')
    ok = subprocess.run(["git", "commit", "-m", "with marker"], cwd=tmp_path, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr

    _stage(tmp_path, "leak.py", f'TOKEN = "{GH}"\n')
    blocked = subprocess.run(["git", "commit", "-m", "no marker"], cwd=tmp_path, capture_output=True, text=True)
    assert blocked.returncode != 0
    log = subprocess.run(["git", "log", "--oneline"], cwd=tmp_path, capture_output=True, text=True)
    assert "with marker" in log.stdout and "no marker" not in log.stdout


# --- Documentation -----------------------------------------------------------------------------


USAGE = (Path(__file__).resolve().parent.parent / "USAGE.md").read_text(encoding="utf-8")


def test_usage_documents_the_feature():
    assert "## Inline ignore comments" in USAGE
    for needle in ("secretshield:ignore-next-line", "--no-inline-ignore", "inline_ignored",
                   "scan-staged", "secretshield:ignore[github_token]"):  # fmt: skip
        assert needle in USAGE, needle
