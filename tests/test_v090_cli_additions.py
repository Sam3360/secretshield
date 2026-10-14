"""
Tests for v0.9.0: `--usage`, the OSC 8 hyperlink in `--creator`,
`--ignore-file`, and `init` now creating `.secretshieldignore`
(as of 0.11.0, alongside `secretshield.toml` when project configuration is chosen).
"""

from __future__ import annotations

import subprocess

import pytest

from secretshield.cli import CREATOR_GITHUB_URL, USAGE_URL, build_parser, main
from secretshield.color import hyperlink
from secretshield.ignorefile import DEFAULT_IGNORE_CONTENT, create_default_ignore_file


def _init_repo(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True)


# --- --usage ------------------------------------------------------------


def test_usage_option_exists_in_parser():
    parser = build_parser()
    # Should not raise / should be recognized (will exit via the action
    # once input() is reached -- exercised properly in the tests below).
    assert any("--usage" in opt.option_strings for opt in parser._actions)


def test_usage_enter_opens_browser_with_correct_url(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda: "")
    opened = {}

    def fake_open(url):
        opened["url"] = url

    monkeypatch.setattr("webbrowser.open", fake_open)

    with pytest.raises(SystemExit):
        main(["--usage"])

    assert opened.get("url") == USAGE_URL
    assert USAGE_URL == "https://github.com/Sam3360/secretshield/blob/main/USAGE.md"


def test_usage_ctrl_c_does_not_open_browser(monkeypatch, capsys):
    def raise_interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", lambda: raise_interrupt())
    opened = {"called": False}
    monkeypatch.setattr("webbrowser.open", lambda url: opened.update(called=True))

    with pytest.raises(SystemExit) as exc_info:
        main(["--usage"])

    assert opened["called"] is False
    assert exc_info.value.code in (0, None)


def test_usage_eof_does_not_open_browser(monkeypatch, capsys):
    def raise_eof():
        raise EOFError

    monkeypatch.setattr("builtins.input", lambda: raise_eof())
    opened = {"called": False}
    monkeypatch.setattr("webbrowser.open", lambda url: opened.update(called=True))

    with pytest.raises(SystemExit) as exc_info:
        main(["--usage"])

    assert opened["called"] is False
    assert exc_info.value.code in (0, None)


def test_usage_prompt_text_shown(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda: "")
    monkeypatch.setattr("webbrowser.open", lambda url: None)

    with pytest.raises(SystemExit):
        main(["--usage"])

    out = capsys.readouterr().out
    assert "Press Enter to open the USAGE documentation." in out
    assert "Ctrl+C to cancel." in out


# --- --creator hyperlink -----------------------------------------------


def test_creator_visible_text_still_correct(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)  # plain output
    with pytest.raises(SystemExit):
        main(["--creator"])
    out = capsys.readouterr().out
    assert "Samarth Chugh (Sam3360)" in out
    assert "github.com/Sam3360" in out


def test_creator_github_url_constant_correct():
    assert CREATOR_GITHUB_URL == "https://github.com/Sam3360"


def test_hyperlink_osc8_format_correct():
    link = hyperlink("github.com/Sam3360", CREATOR_GITHUB_URL, True)
    assert link == "\033]8;;https://github.com/Sam3360\033\\github.com/Sam3360\033]8;;\033\\"


def test_hyperlink_visible_text_unchanged():
    import re

    link = hyperlink("github.com/Sam3360", CREATOR_GITHUB_URL, True)
    # Parse the OSC 8 structure properly: \x1b]8;;URL\x1b\TEXT\x1b]8;;\x1b\
    match = re.match(r"\x1b\]8;;(?P<url>[^\x1b]*)\x1b\\(?P<text>.*)\x1b\]8;;\x1b\\$", link)
    assert match is not None
    assert match.group("text") == "github.com/Sam3360"
    assert match.group("url") == CREATOR_GITHUB_URL


def test_hyperlink_falls_back_to_plain_text_when_disabled():
    link = hyperlink("github.com/Sam3360", CREATOR_GITHUB_URL, False)
    assert link == "github.com/Sam3360"
    assert "\033" not in link


def test_creator_output_has_no_escape_codes_when_not_a_tty(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    with pytest.raises(SystemExit):
        main(["--creator"])
    out = capsys.readouterr().out
    assert "\033" not in out


def test_creator_output_has_hyperlink_when_tty(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    with pytest.raises(SystemExit):
        main(["--creator"])
    out = capsys.readouterr().out
    assert "\033]8;;https://github.com/Sam3360\033\\" in out


# --- --ignore-file --------------------------------------------------------


def test_ignore_file_creates_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        main(["--ignore-file"])
    assert (tmp_path / ".secretshieldignore").exists()


def test_ignore_file_contains_starter_comment(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        main(["--ignore-file"])
    content = (tmp_path / ".secretshieldignore").read_text()
    assert content == DEFAULT_IGNORE_CONTENT
    assert content.strip().startswith("#")


def test_ignore_file_does_not_overwrite_existing(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshieldignore").write_text("my custom rules\n")
    with pytest.raises(SystemExit):
        main(["--ignore-file"])
    assert (tmp_path / ".secretshieldignore").read_text() == "my custom rules\n"
    out = capsys.readouterr().out
    assert "already exists" in out


def test_ignore_file_exits_successfully(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc_info:
        main(["--ignore-file"])
    assert exc_info.value.code in (0, None)


def test_ignore_file_works_through_normal_cli(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        main(["--ignore-file"])
    assert (tmp_path / ".secretshieldignore").exists()


def test_create_default_ignore_file_helper_directly(tmp_path):
    created, path = create_default_ignore_file(tmp_path)
    assert created is True
    assert path.exists()
    created2, path2 = create_default_ignore_file(tmp_path)
    assert created2 is False
    assert path2 == path


# --- init creates .secretshieldignore ---------------------------------------


def test_init_creates_secretshieldignore(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    # Not a git repo, so the hook question is skipped entirely (no
    # prompt consumed for it) -- only config, actions, and apply remain.
    answers = iter(["y", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    main(["init"])
    assert (tmp_path / ".secretshieldignore").exists()


def test_init_preserves_existing_secretshieldignore(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secretshieldignore").write_text("existing content\n")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    answers = iter(["y", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    main(["init"])
    assert (tmp_path / ".secretshieldignore").read_text() == "existing content\n"


def test_init_twice_does_not_duplicate_or_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    answers1 = iter(["y", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers1))
    main(["init"])
    first_content = (tmp_path / ".secretshieldignore").read_text()

    answers2 = iter(["y", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers2))
    main(["init"])
    second_content = (tmp_path / ".secretshieldignore").read_text()

    assert first_content == second_content == DEFAULT_IGNORE_CONTENT


def test_init_still_creates_everything_else(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _init_repo(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    answers = iter(["y", "y", "y", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    main(["init"])
    assert (tmp_path / "secretshield.toml").exists()
    assert (tmp_path / ".git" / "hooks" / "pre-commit").exists()
    assert (tmp_path / ".github" / "workflows" / "secretshield.yml").exists()
    assert (tmp_path / ".secretshieldignore").exists()


def test_init_non_interactive_still_refuses_cleanly(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["init"])
    assert exit_code == 1
    assert not (tmp_path / ".secretshieldignore").exists()


# --- ss alias covers all new flags too --------------------------------------


def test_ss_entry_point_supports_new_flags():
    import tomllib

    with open("pyproject.toml", "rb") as f:
        data = tomllib.load(f)
    scripts = data["project"]["scripts"]
    # Both commands point at the same entry point, so any flag added to
    # the shared parser automatically works for both -- confirm the
    # wiring is still single-entry-point, not duplicated.
    assert scripts["secretshield"] == scripts["ss"] == "secretshield.cli:main"
