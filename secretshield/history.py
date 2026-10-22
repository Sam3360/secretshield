"""
Scan the whole Git history: ``secretshield scan --history``.

Streams ``git log --all -p -U0`` and yields, for every commit and file, the
text of each hunk's *added* lines together with the line number where the
hunk starts in the new version of the file. The normal scan loop then runs
the usual detectors (built-in patterns, custom rules, entropy, placeholder
and inline-ignore filtering) over that text, so history findings are exactly
what a scan of that content would have reported.

What it does and does not cover (also documented in USAGE.md):

* Every commit reachable from any ref (``--all``: branches, tags, remotes,
  stash). Not unreachable objects, other people's clones, or CI logs.
* The lines a commit *added*. Merge commits show no diff of their own, so a
  secret introduced only while resolving a merge conflict is not seen.
* An inline ``secretshield:ignore`` marker only suppresses a historical
  finding when it was added in the same hunk as the secret.

Secret values are never printed or put on a command line; they exist only in
the in-memory text handed to the detectors.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Callable, Iterator

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_COMMIT_PREFIX = "@@commit "


class HistoryError(RuntimeError):
    """git could not be run, or could not read this repository's history."""


class HistoryScan:
    """One pass over the history. Create, iterate ``iter_sources``, then read the counters."""

    def __init__(
        self,
        cwd: Path,
        *,
        pathspec: str | None = None,
        max_commits: int | None = None,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
    ) -> None:
        self.cwd = cwd
        self.pathspec = pathspec
        self.max_commits = max_commits
        self._popen = popen
        self.commits_scanned = 0
        self.max_commits_reached = False
        self.failed = False  # set by the CLI adapter if git could not be run/read
        self.rank: dict[str, int] = {}  # commit -> position; 0 is the newest

    def command(self) -> list[str]:
        # -M forces rename detection (regardless of the user's diff.renames
        # setting), so a pure rename shows no hunks instead of re-adding the file.
        cmd = [
            "git", "-c", "core.quotepath=false", "log", "--all", "--no-color",
            "--no-ext-diff", "--no-textconv", "-M", "-p", "-U0",
            f"--format={_COMMIT_PREFIX}%H",
        ]  # fmt: skip
        if self.pathspec:
            cmd += ["--", self.pathspec]
        return cmd

    def iter_sources(self, accept: Callable[[str], bool]) -> Iterator[tuple[str, str, int, str]]:
        """Yield ``(path, added_text, first_line_number, commit)`` per hunk.

        `accept(path)` says whether a path should be scanned at all (the same
        file-type, ignore-file and --include/--exclude rules as a normal scan).
        """
        try:
            proc = self._popen(
                self.command(),
                cwd=str(self.cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,  # never let an unread stderr pipe block git
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise HistoryError("git could not be run (is it installed and on your PATH?)") from exc

        commit = ""
        path: str | None = None  # None: skip this file's hunks
        in_hunk = False
        start = 0
        added: list[str] = []

        def pending() -> tuple[str, str, int, str] | None:
            if path is not None and added:
                return (path, "\n".join(added) + "\n", start, commit)
            return None

        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                line = raw.rstrip("\n")
                if line.startswith(_COMMIT_PREFIX):
                    ready = pending()
                    if ready:
                        yield ready
                    added, path, in_hunk = [], None, False
                    if self.max_commits is not None and self.commits_scanned >= self.max_commits:
                        self.max_commits_reached = True  # a further commit exists beyond the limit
                        break
                    commit = line[len(_COMMIT_PREFIX):].strip()
                    self.commits_scanned += 1
                    self.rank[commit] = len(self.rank)
                    continue

                if line.startswith("diff --git "):
                    ready = pending()
                    if ready:
                        yield ready
                    added, path, in_hunk = [], None, False
                    continue

                if not in_hunk:
                    # File headers only exist before a file's first hunk. Inside a hunk a
                    # removed "-- comment" line would otherwise look like a "---" header.
                    if line.startswith("+++ "):
                        target = line[4:].split("\t")[0]
                        if target.startswith("b/"):
                            candidate = target[2:]
                            path = candidate if accept(candidate) else None
                        else:  # /dev/null (deleted file) or a C-quoted unusual name
                            path = None
                        continue

                # Content lines always start with "+", "-", " " or "\\", so a line
                # starting "@@ " can only be a hunk header.
                hunk = _HUNK_RE.match(line) if line.startswith("@@ ") else None
                if hunk:
                    ready = pending()
                    if ready:
                        yield ready
                    in_hunk = True
                    start = int(hunk.group(1))
                    added = []
                    continue

                if in_hunk and line.startswith("+"):
                    added.append(line[1:])

            ready = pending()
            if ready:
                yield ready
        finally:
            if proc.poll() is None:  # stopped early (limit reached or consumer gave up)
                proc.kill()
            if proc.stdout is not None:
                proc.stdout.close()
            proc.wait()
        if proc.returncode not in (0, None) and not self.max_commits_reached:
            raise HistoryError("git could not read this repository's history")


def short(commit: str) -> str:
    return commit[:8]


def dedupe_oldest(contexts: list, commit_of: dict[int, str], rank: dict[str, int]):
    """Collapse the same secret seen in several commits into its first appearance.

    `contexts` is the scan's ``[(file, line, match), ...]``; `commit_of` maps
    ``id(match)`` to its commit. The same ``(file, kind, value)`` often shows up
    in many commits (rebased branches, re-added lines). The OLDEST one is kept,
    since that is where the secret entered the history, together with how many
    other commits contain it. Returns ``(kept_contexts, also_in)`` where
    ``also_in`` maps ``id(match)`` to that count.
    """
    groups: dict[tuple, list] = {}
    order: list[tuple] = []
    for item in contexts:
        file, _line, match = item
        key = (file, match.kind, match.value)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(item)

    kept: list = []
    also_in: dict[int, int] = {}
    for key in order:
        items = groups[key]
        oldest = max(items, key=lambda it: rank.get(commit_of.get(id(it[2]), ""), -1))
        kept.append(oldest)
        distinct = {commit_of.get(id(it[2]), "") for it in items}
        if len(distinct) > 1:
            also_in[id(oldest[2])] = len(distinct) - 1
    return kept, also_in
