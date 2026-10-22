"""
Tests for v0.13.2: ``secretshield scan --history``.

Real Git repositories are created in tmp_path; all secrets are fake.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from secretshield.cli import _history_sources, main
from secretshield.history import HistoryError, HistoryScan, dedupe_oldest

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GH = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
GH2 = "ghp_" + "z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2"
CUSTOM = "MYAPP_" + "12345678901234567890123456789012"


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t.test", *args],
        cwd=root, check=True, capture_output=True, text=True, encoding="utf-8",
    )  # fmt: skip
    return result.stdout.strip()


def commit(root: Path, message: str, files: dict[str, str | None]) -> str:
    """Write (or delete, with None) files, commit them, return the full hash."""
    for name, text in files.items():
        path = root / name
        if text is None:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    git(tmp_path, "init", "-q")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def scan_history(capsys, *extra):
    code = main(["scan", ".", "--history", "--json", *extra])
    return code, json.loads(capsys.readouterr().out)


# --- Core behavior ---------------------------------------------------------------------


def test_finds_a_secret_that_was_deleted_and_names_the_commit(repo, capsys):
    added = commit(repo, "add", {"app.py": f'x = 1\nk = "{AWS}"\n'})
    commit(repo, "remove", {"app.py": "x = 1\n"})
    assert main(["scan", "."]) == 0  # the working tree is clean...
    capsys.readouterr()
    code, report = scan_history(capsys)  # ...but history is not
    assert code == 1
    assert [(m["file"], m["line"], m["kind"], m["commit"]) for m in report["matches"]] == [
        ("app.py", 2, "aws_access_key_id", added[:8])
    ]
    assert report["commits_scanned"] == 2 and "files_scanned" not in report


def test_text_report_shows_commit_and_a_revoke_reminder_but_never_the_secret(repo, capsys):
    added = commit(repo, "add", {"app.py": f'k = "{AWS}"\n'})
    assert main(["scan", ".", "--history"]) == 1
    out = capsys.readouterr().out
    assert f"Commit: {added[:8]}" in out
    assert "2 commits scanned" not in out and "1 commit scanned" in out
    assert "does not make it safe" in out and "--history --rotate" in out
    assert AWS not in out


def test_clean_history_exits_zero(repo, capsys):
    commit(repo, "one", {"a.py": "x = 1\n"})
    commit(repo, "two", {"a.py": "x = 2\n"})
    assert main(["scan", ".", "--history"]) == 0
    out = capsys.readouterr().out
    assert "2 commits scanned" in out and "No potential secrets found" in out


def test_a_repository_with_no_commits_is_fine(repo, capsys):
    code, report = scan_history(capsys)
    assert code == 0 and report["commits_scanned"] == 0 and report["matches"] == []


def test_line_numbers_are_real_new_file_line_numbers(repo, capsys):
    commit(repo, "base", {"f.py": "".join(f"line{i}\n" for i in range(1, 11))})
    lines = [f"line{i}\n" for i in range(1, 11)]
    lines.insert(6, f'k = "{AWS}"\n')  # becomes line 7
    commit(repo, "insert", {"f.py": "".join(lines)})
    _, report = scan_history(capsys)
    assert [m["line"] for m in report["matches"]] == [7]


def test_two_secrets_in_separate_hunks_of_one_commit(repo, capsys):
    body = [f"line{i}\n" for i in range(1, 31)]
    commit(repo, "base", {"f.py": "".join(body)})
    body[2] = f'a = "{AWS}"\n'  # line 3
    body[24] = f'b = "{GH}"\n'  # line 25
    commit(repo, "two hunks", {"f.py": "".join(body)})
    _, report = scan_history(capsys)
    assert sorted((m["line"], m["kind"]) for m in report["matches"]) == [
        (3, "aws_access_key_id"), (25, "github_token"),
    ]  # fmt: skip


def test_a_modified_line_is_scanned_on_its_new_side_only(repo, capsys):
    commit(repo, "old", {"f.py": f'k = "{AWS}"\n'})  # introduces
    commit(repo, "edit", {"f.py": f'k = "{AWS}"  # now with a comment\n'})  # same secret, new line
    _, report = scan_history(capsys)
    assert len(report["matches"]) == 1


# --- De-duplication (the same secret in many commits) -------------------------------------


def test_the_same_secret_in_several_commits_is_reported_once_at_its_oldest_commit(repo, capsys):
    first = commit(repo, "add", {"a.py": f'k = "{AWS}"\n'})
    commit(repo, "remove", {"a.py": "x = 1\n"})
    commit(repo, "re-add", {"a.py": f'k = "{AWS}"\n'})
    _, report = scan_history(capsys)
    assert len(report["matches"]) == 1
    match = report["matches"][0]
    assert match["commit"] == first[:8]  # where it ENTERED the history
    assert match["also_in_commits"] == 1


def test_text_report_mentions_the_other_commits(repo, capsys):
    commit(repo, "add", {"a.py": f'k = "{AWS}"\n'})
    commit(repo, "remove", {"a.py": "x = 1\n"})
    commit(repo, "re-add", {"a.py": f'k = "{AWS}"\n'})
    main(["scan", ".", "--history"])
    assert "(also in 1 other commit(s))" in capsys.readouterr().out


def test_different_secrets_or_files_are_not_collapsed(repo, capsys):
    commit(repo, "one", {"a.py": f'k = "{GH}"\n', "b.py": f'k = "{GH}"\n'})
    commit(repo, "two", {"c.py": f'k = "{GH2}"\n'})
    _, report = scan_history(capsys)
    assert sorted((m["file"], m["kind"]) for m in report["matches"]) == [
        ("a.py", "github_token"), ("b.py", "github_token"), ("c.py", "github_token"),
    ]  # fmt: skip


def test_dedupe_picks_the_oldest_by_rank():
    class M:
        def __init__(self, kind="k", value="v"):
            self.kind, self.value = kind, value

    new, old = M(), M()
    contexts = [("a.py", 1, new), ("a.py", 9, old)]
    commit_of = {id(new): "newest", id(old): "oldest"}
    rank = {"newest": 0, "oldest": 5}
    kept, also = dedupe_oldest(contexts, commit_of, rank)
    assert kept == [("a.py", 9, old)] and also == {id(old): 1}


# --- Which commits are covered ---------------------------------------------------------------


def test_secrets_on_other_branches_are_found(repo, capsys):
    commit(repo, "base", {"a.py": "x = 1\n"})
    git(repo, "checkout", "-q", "-b", "feature")
    side = commit(repo, "side", {"b.py": f'k = "{AWS}"\n'})
    git(repo, "checkout", "-q", "-")
    _, report = scan_history(capsys)
    assert [m["commit"] for m in report["matches"]] == [side[:8]]


def test_a_merged_secret_is_reported_once_at_the_commit_that_added_it(repo, capsys):
    commit(repo, "base", {"a.py": "x = 1\n"})
    git(repo, "checkout", "-q", "-b", "feature")
    side = commit(repo, "side", {"b.py": f'k = "{AWS}"\n'})
    git(repo, "checkout", "-q", "-")
    commit(repo, "main work", {"c.py": "y = 2\n"})
    git(repo, "merge", "-q", "--no-ff", "-m", "merge", "feature")
    _, report = scan_history(capsys)
    assert [m["commit"] for m in report["matches"]] == [side[:8]]


def test_deleting_a_file_or_renaming_it_creates_no_extra_findings(repo, capsys):
    # Git detects renames by default, which would hide a missing -M. Turn that default
    # off so the scan only gets rename detection if it asks for it itself.
    git(repo, "config", "diff.renames", "false")
    commit(repo, "add", {"old.py": f'k = "{AWS}"\n'})
    git(repo, "mv", "old.py", "new.py")
    git(repo, "commit", "-q", "-m", "rename")
    commit(repo, "delete", {"new.py": None})
    _, report = scan_history(capsys)
    assert len(report["matches"]) == 1 and report["matches"][0]["file"] == "old.py"


def test_unicode_and_spaced_file_names(repo, capsys):
    commit(repo, "add", {"my dir/\u043a\u043b\u044e\u0447 \u5bc6\u94a5.py": f'k = "{AWS}"\n'})
    _, report = scan_history(capsys)
    assert report["matches"][0]["file"].replace("\\", "/") == "my dir/\u043a\u043b\u044e\u0447 \u5bc6\u94a5.py"


def test_a_removed_line_that_looks_like_a_file_header_is_not_misparsed(repo, capsys):
    # "-- comment" removed shows up as "--- comment" inside a hunk.
    commit(repo, "sql", {"q.sql": "-- old comment\nselect 1;\n"})
    commit(repo, "edit", {"q.sql": f"select 1;\n-- k = {AWS}\n"})
    _, report = scan_history(capsys)
    assert len(report["matches"]) == 1


def test_an_added_line_that_looks_like_a_file_header_cannot_redirect_findings(repo, capsys):
    # The added line "++ b/evil.txt" appears in the diff as "+++ b/evil.txt", exactly
    # like a file header. It must not change which file later findings belong to.
    commit(repo, "tricky", {"a.py": f"++ b/evil.txt\nk = \"{AWS}\"\n"})
    _, report = scan_history(capsys)
    assert [m["file"] for m in report["matches"]] == ["a.py"]


def test_the_git_process_is_stopped_when_the_commit_limit_is_reached(tmp_path):
    import io

    lines = []
    for i in range(3):
        lines += [f"@@commit {i:040d}\n", "diff --git a/f.py b/f.py\n", "+++ b/f.py\n", "@@ -0,0 +1 @@\n", f"+x{i}\n"]

    class Proc:
        returncode = None
        killed = False

        def __init__(self):
            self.stdout = io.StringIO("".join(lines))

        def poll(self):
            return None if not self.killed else -9

        def kill(self):
            self.killed = True
            self.returncode = -9

        def wait(self):
            pass

    proc = Proc()
    scan = HistoryScan(tmp_path, max_commits=1, popen=lambda cmd, **kw: proc)
    got = list(scan.iter_sources(lambda p: True))
    assert [g[1] for g in got] == ["x0\n"] and scan.max_commits_reached and scan.commits_scanned == 1
    assert proc.killed, "git must not be left running after the limit"


def test_binary_files_do_not_break_the_scan(repo, capsys):
    (repo / "blob.bin").write_bytes(bytes(range(256)) * 50)
    commit(repo, "binary", {"a.py": f'k = "{AWS}"\n'})
    code, report = scan_history(capsys)
    assert code == 1 and len(report["matches"]) == 1


def test_path_argument_limits_history_to_that_path(repo, capsys):
    commit(repo, "add", {"src/a.py": f'k = "{AWS}"\n', "docs/b.py": f'k = "{GH}"\n'})
    code = main(["scan", "src", "--history", "--json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 1 and [m["kind"] for m in report["matches"]] == ["aws_access_key_id"]


def test_max_commits_scans_only_the_most_recent(repo, capsys):
    commit(repo, "old", {"old.py": f'k = "{AWS}"\n'})
    commit(repo, "mid", {"mid.py": "x = 1\n"})
    commit(repo, "new", {"new.py": f'k = "{GH}"\n'})
    code, report = scan_history(capsys, "--max-commits", "2")
    assert code == 1 and report["commits_scanned"] == 2 and report["max_commits_reached"] is True
    assert [m["kind"] for m in report["matches"]] == ["github_token"]  # the AWS key is older
    assert main(["scan", ".", "--history", "--max-commits", "2"]) == 1
    assert "Stopped after 2 commit(s)" in capsys.readouterr().out


def test_max_commits_not_reached_is_not_flagged(repo, capsys):
    commit(repo, "one", {"a.py": "x = 1\n"})
    _, report = scan_history(capsys, "--max-commits", "5")
    assert "max_commits_reached" not in report and report["commits_scanned"] == 1


# --- Detection and filtering behave as in a normal scan ----------------------------------------


def test_custom_rules_apply_to_history(repo, capsys):
    (repo / ".secretshield-rules.toml").write_text(
        '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n', encoding="utf-8"
    )
    commit(repo, "add", {"a.py": f'v = "{CUSTOM}"\n'})
    _, report = scan_history(capsys)
    assert [m["kind"] for m in report["matches"]] == ["My API Key"]


def test_ignore_file_and_exclude_apply_to_history(repo, capsys):
    commit(repo, "add", {"keep/a.py": f'k = "{AWS}"\n', "vendor/b.py": f'k = "{GH}"\n'})
    (repo / ".secretshieldignore").write_text("vendor/\n", encoding="utf-8")
    _, report = scan_history(capsys)
    assert [m["file"].replace("\\", "/") for m in report["matches"]] == ["keep/a.py"]
    _, report = scan_history(capsys, "--exclude", "keep/*")
    assert [m["file"].replace("\\", "/") for m in report["matches"]] == []


def test_default_skipped_directories_and_meta_files_are_skipped(repo, capsys):
    commit(repo, "add", {"node_modules/x/a.py": f'k = "{AWS}"\n', ".secretshield-rules.toml": f"# {AWS}\n"})
    code, report = scan_history(capsys)
    assert code == 0 and report["matches"] == []


def test_placeholders_are_not_reported(repo, capsys):
    commit(repo, "docs", {"README.md": "use sk-ant-api03-" + "x" * 40 + " here\n"})
    code, report = scan_history(capsys)
    assert code == 0


def test_inline_ignore_in_the_same_commit_suppresses_a_historical_finding(repo, capsys):
    commit(repo, "fixture", {"a.py": f'k = "{AWS}"  # secretshield:ignore\n'})
    code, report = scan_history(capsys)
    assert code == 0 and report["inline_ignored"] == 1
    code, report = scan_history(capsys, "--no-inline-ignore")
    assert code == 1 and len(report["matches"]) == 1


def test_a_marker_added_later_does_not_rewrite_history(repo, capsys):
    first = commit(repo, "leak", {"a.py": f'k = "{AWS}"\n'})
    commit(repo, "mark it", {"a.py": f'k = "{AWS}"  # secretshield:ignore\n'})
    code, report = scan_history(capsys)
    assert code == 1  # the commit that introduced it had no marker
    assert report["matches"][0]["commit"] == first[:8]


def test_next_line_marker_in_the_same_hunk(repo, capsys):
    commit(repo, "fixture", {"a.py": f'# secretshield:ignore-next-line\nk = "{AWS}"\n'})
    code, report = scan_history(capsys)
    assert code == 0 and report["inline_ignored"] == 1


def test_baseline_from_the_working_tree_covers_the_same_secret_in_history(repo, capsys):
    commit(repo, "add", {"a.py": f'k = "{AWS}"\n'})
    assert main(["scan", ".", "--baseline"]) == 0
    capsys.readouterr()
    commit(repo, "remove", {"a.py": "x = 1\n"})
    commit(repo, "other leak", {"b.py": f'k = "{GH}"\n'})
    code, report = scan_history(capsys)
    assert code == 1
    assert [m["kind"] for m in report["matches"]] == ["github_token"]  # the baselined AWS key is hidden
    assert report["ignored_by_baseline"] == 1


def test_secret_values_never_appear_in_any_output(repo, capsys):
    commit(repo, "add", {"a.py": f'k = "{AWS}"\nt = "{GH}"\n'})
    main(["scan", ".", "--history"])
    text = capsys.readouterr()
    main(["scan", ".", "--history", "--json"])
    js = capsys.readouterr()
    for out in (text.out + text.err, js.out + js.err):
        assert AWS not in out and GH not in out


# --- Flags and errors -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra, fragment",
    [
        (["--staged"], "--staged"),
        (["--diff", "HEAD"], "--diff"),
        (["--fix"], "--fix"),
        (["--baseline"], "--baseline"),
        (["--format", "sarif"], "--format sarif"),
    ],
)
def test_incompatible_flags_are_rejected(repo, capsys, extra, fragment):
    commit(repo, "one", {"a.py": "x = 1\n"})
    assert main(["scan", ".", "--history", *extra]) == 2
    err = capsys.readouterr().err
    assert "--history cannot be combined with" in err and fragment in err


def test_max_commits_requires_history(repo, capsys):
    assert main(["scan", ".", "--max-commits", "3"]) == 2
    assert "--max-commits requires --history" in capsys.readouterr().err


@pytest.mark.parametrize("bad", ["0", "-1", "abc"])
def test_max_commits_must_be_a_positive_whole_number(repo, capsys, bad):
    with pytest.raises(SystemExit) as exc:
        main(["scan", ".", "--history", "--max-commits", bad])
    assert exc.value.code == 2


def test_not_a_git_repository_is_an_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["scan", ".", "--history"]) == 2
    assert "not inside a Git repository" in capsys.readouterr().err


def test_a_sarif_default_in_the_config_does_not_break_history(repo, capsys):
    commit(repo, "add", {"a.py": f'k = "{AWS}"\n', "secretshield.toml": '[output]\nformat = "sarif"\n'})
    assert main(["scan", ".", "--history"]) == 1  # falls back to the text report
    out = capsys.readouterr().out
    assert out.startswith("SecretShield scan"), out[:80]
    assert "Commit: " in out and "1 commit scanned" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)  # a SARIF/JSON document would parse


def test_plain_scans_are_unchanged_by_the_new_flags(repo, capsys):
    commit(repo, "add", {"a.py": f'k = "{AWS}"\n'})
    assert main(["scan", ".", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert set(report) == {"files_scanned", "matches", "secrets_found"}
    assert "commit" not in report["matches"][0]


# --- Parser error handling ---------------------------------------------------------------------


def test_history_scan_maps_git_failures_to_a_clear_error(tmp_path):
    def no_git(cmd, **kwargs):
        raise FileNotFoundError("git")

    with pytest.raises(HistoryError, match="could not be run"):
        list(HistoryScan(tmp_path, popen=no_git).iter_sources(lambda p: True))


def test_history_scan_reports_a_failing_git(tmp_path):
    class Proc:
        returncode = 128

        def __init__(self):
            import io

            self.stdout = io.StringIO("")
            self.stderr = None

        def poll(self):
            return self.returncode

        def wait(self):
            pass

        def kill(self):
            pass

    with pytest.raises(HistoryError, match="could not read"):
        list(HistoryScan(tmp_path, popen=lambda cmd, **kw: Proc()).iter_sources(lambda p: True))


def test_the_cli_adapter_turns_a_history_error_into_exit_two(capsys):
    class Broken:
        failed = False

        def iter_sources(self, accept):
            raise HistoryError("git could not be run (is it installed and on your PATH?)")
            yield  # pragma: no cover

    broken = Broken()
    assert list(_history_sources(broken, [], [], False)) == []
    assert broken.failed is True
    assert "could not be run" in capsys.readouterr().err


def test_git_command_is_read_only_and_secret_free():
    cmd = HistoryScan(Path("."), pathspec="src").command()
    assert cmd[:2] == ["git", "-c"] and "log" in cmd and "-p" in cmd and "-U0" in cmd
    assert not set(cmd) & {"commit", "push", "reset", "checkout", "gc", "-D", "--force"}
    assert cmd[-2:] == ["--", "src"]


# --- --history --rotate ---------------------------------------------------------------------------


def test_rotate_without_a_terminal_changes_nothing(repo, capsys):
    commit(repo, "add", {"a.py": f'k = "{AWS}"\n'})
    commit(repo, "remove", {"a.py": "x = 1\n"})
    assert main(["scan", ".", "--history", "--rotate"]) == 1
    out = capsys.readouterr().out
    assert "requires an interactive terminal" in out and AWS not in out


def test_rotate_over_history_findings_offers_no_auto_fix(repo, monkeypatch, capsys):
    added = commit(repo, "add", {"app.py": f'k = "{AWS}"\n'})
    commit(repo, "remove", {"app.py": "x = 1\n"})
    monkeypatch.setattr("secretshield.rotation.workflow.is_interactive", lambda: True)
    prompts: list[str] = []

    def answer(prompt: str = "") -> str:
        prompts.append(prompt)
        if "Work on this credential" in prompt:
            return "y"
        if "Have you revoked" in prompt:
            return "y"
        return "n"

    monkeypatch.setattr("builtins.input", answer)
    code = main(["scan", ".", "--history", "--rotate"])
    out = capsys.readouterr().out
    assert not any("Auto-Fix" in p for p in prompts)
    assert f"app.py @ {added[:8]}:1" in out
    assert "found in Git history, so there is no current file for Auto-Fix to rewrite" in out
    assert AWS not in out and AWS not in "".join(prompts)
    assert code == 0  # revoked as reported, and no copy remains in the working tree
    assert not (repo / ".env").exists()


def test_rotate_still_offers_auto_fix_for_normal_scans(repo, monkeypatch, capsys):
    commit(repo, "add", {"app.py": f'import os\nk = "{AWS}"\n'})
    monkeypatch.setattr("secretshield.rotation.workflow.is_interactive", lambda: True)
    prompts: list[str] = []

    def answer(prompt: str = "") -> str:
        prompts.append(prompt)
        return "y" if "Work on this credential" in prompt else "n"

    monkeypatch.setattr("builtins.input", answer)
    main(["scan", ".", "--rotate"])
    assert any("Run Auto-Fix" in p for p in prompts)


# --- Documentation ----------------------------------------------------------------------------------


USAGE = (Path(__file__).resolve().parent.parent / "USAGE.md").read_text(encoding="utf-8")


def test_usage_documents_history_scanning():
    assert "## Scanning Git history" in USAGE
    for needle in ("--history", "--max-commits", "commits_scanned", "also_in_commits",
                   "git log --all", "Merge commits"):  # fmt: skip
        assert needle in USAGE, needle
