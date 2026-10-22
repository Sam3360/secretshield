"""
The interactive Secret Rotation Assistant: ``secretshield scan . --rotate``.

Deleting a secret from source code does not make it safe. The credential
keeps working until its provider revokes it. This module walks the user
through that, and keeps three different things clearly apart:

1. **Revoking** the credential with its provider. Only the user can do
   this; SecretShield never does it and never sends the value anywhere.
2. **Replacing** references in code. This reuses Auto-Fix (it asks before
   every change).
3. **Checking** for leftover copies of the old value in the working tree
   and, optionally, in Git history. Both searches are local and read-only.

SecretShield never claims a credential is revoked or secured. What the
user tells it is recorded as "reported by you" and labelled as not
verified.

Privacy: no network calls are made here. Every line printed or used as a
prompt passes through a scrubber that masks any detected value, so even a
bug in a message cannot print one.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from ..autofix import is_interactive, run_autofix
from .providers import (
    HISTORY_GUIDE,
    Guide,
    Link,
    core_value,
    history_needle,
    identify,
)

MASK = "********"

_MAX_LOCATIONS_SHOWN = 5
_MAX_COMMITS_SHOWN = 5
# Stop reading Git history after this much output rather than hang on a
# huge repository; the result is then reported as incomplete.
_HISTORY_MAX_BYTES = 256 * 1024 * 1024

_WHY = (
    "Removing a secret from your code does not make it safe. Anyone who has already seen "
    "it, through Git history, a fork or clone, CI logs or a pushed branch, can keep using "
    "it until the provider revokes it. Only the provider can do that."
)

SourceIter = Callable[[], Iterable[tuple[str, str]]]


# --- Data ------------------------------------------------------------------------


@dataclass
class Credential:
    """One distinct detected value and everywhere it was found."""

    value: str  # raw match text; never printed
    core: str  # the credential itself; never printed
    kind: str
    guide: Guide
    locations: list[tuple[str, int]] = field(default_factory=list)
    matches: list[tuple[str, object]] = field(default_factory=list)  # (file, Match)

    skipped: bool = False
    revoked_reported: bool | None = None  # None: never asked
    replaced: int = 0
    refs_remaining: int | None = None  # None: not checked
    history_commits: int | None = None  # None: not checked or incomplete


@dataclass
class RotationSummary:
    credentials: list[Credential] = field(default_factory=list)
    cancelled: bool = False
    errored: bool = False
    exit_code: int = 0


@dataclass
class HistoryResult:
    commits: list[str] = field(default_factory=list)
    truncated: bool = False
    error: str | None = None


# --- Small helpers -----------------------------------------------------------------


def _default_print(text: str = "") -> None:
    print(text)


def _default_input(prompt: str) -> str:
    return input(prompt)


def _yes(answer: str) -> bool:
    return answer.strip().lower() in ("y", "yes")


def _yes_default(answer: str) -> bool:
    """For [Y/n] prompts: an empty answer means yes."""
    return answer.strip().lower() in ("", "y", "yes")


class _Scrubber:
    """Masks every known secret value in any text that is about to leave."""

    def __init__(self) -> None:
        self._values: set[str] = set()

    # Values shorter than this are not masked: this scrubber is a backstop
    # (nothing here prints a value to begin with), and replacing a 3-letter
    # custom-rule match everywhere would only mangle unrelated output.
    _MIN_LENGTH = 6

    def add(self, *values: str) -> None:
        for value in values:
            if len(value) >= self._MIN_LENGTH:
                self._values.add(value)
            # A multi-line value (a private key) is also masked line by line.
            if "\n" in value:
                for line in value.splitlines():
                    if len(line.strip()) >= 12:
                        self._values.add(line.strip())

    def __call__(self, text: str) -> str:
        for value in sorted(self._values, key=len, reverse=True):
            text = text.replace(value, MASK)
        return text


def _group(findings: Iterable[tuple[str, int, object]]) -> list[Credential]:
    """Group findings by credential value, so one rotation covers every copy."""
    by_core: dict[str, Credential] = {}
    for file, line, match in findings:
        kind = match.kind  # type: ignore[attr-defined]
        value = match.value  # type: ignore[attr-defined]
        core = core_value(kind, value)
        cred = by_core.get(core)
        guide = identify(kind, value)
        if cred is None:
            cred = Credential(value=value, core=core, kind=kind, guide=guide)
            by_core[core] = cred
        elif guide.identified and not cred.guide.identified:
            # The same value matched a provider detector somewhere: prefer it.
            cred.kind, cred.value, cred.guide = kind, value, guide
        if (file, line) not in cred.locations:
            cred.locations.append((file, line))
        cred.matches.append((file, match))
    return sorted(by_core.values(), key=lambda c: c.locations[0])


def _format_locations(locations: list[tuple[str, int]]) -> str:
    shown = [f"{f}:{ln}" for f, ln in locations[:_MAX_LOCATIONS_SHOWN]]
    extra = len(locations) - _MAX_LOCATIONS_SHOWN
    text = ", ".join(shown)
    return text + (f", and {extra} more" if extra > 0 else "")


def find_references(core: str, iter_sources: SourceIter) -> list[tuple[str, int]]:
    """Locations (file, line) in the scanned files that contain `core`.

    Read-only and local. Returns locations only, never the matched text.
    """
    hits: set[tuple[str, int]] = set()
    for path, text in iter_sources():
        start = text.find(core)
        while start != -1:
            hits.add((path, text.count("\n", 0, start) + 1))
            start = text.find(core, start + len(core))
    return sorted(hits)


def search_history(
    core: str,
    project_root: Path,
    popen: Callable[..., subprocess.Popen] = subprocess.Popen,
) -> HistoryResult:
    """Find commits whose diff contains `core`, without putting it on a command line.

    Streams ``git log --all -p`` and searches in this process, so the value
    never appears in an argument list (visible to other users via `ps`).
    Only commits reachable from a ref are covered.
    """
    needle = history_needle(core)
    cmd = [
        "git", "log", "--all", "-p", "--no-color", "--no-ext-diff", "--no-textconv",
        "--format=@@commit %H",
    ]  # fmt: skip
    try:
        proc = popen(
            cmd,
            cwd=str(project_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return HistoryResult(error="git could not be run")

    result = HistoryResult()
    current: str | None = None
    read = 0
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            read += len(line)
            if line.startswith("@@commit "):
                current = line[len("@@commit "):].strip()
                continue
            if current and needle in line and (not result.commits or result.commits[-1] != current):
                result.commits.append(current)
            if read > _HISTORY_MAX_BYTES:
                result.truncated = True
                break
    finally:
        if result.truncated:
            proc.kill()
        if proc.stdout is not None:
            proc.stdout.close()
        proc.wait()
    if not result.truncated and proc.returncode not in (0, None):
        result.error = "git could not read this repository's history"
    return result


# --- Workflow ----------------------------------------------------------------------


def run_rotation(
    project_root: Path,
    findings: Iterable[tuple[str, int, object]],
    *,
    entropy_threshold: float = 4.2,
    custom_rules: list | None = None,
    iter_sources: SourceIter | None = None,
    print_func: Callable[[str], None] = _default_print,
    input_func: Callable[[str], str] = _default_input,
    open_url: Callable[[str], object] | None = None,
    history_search: Callable[[str, Path], HistoryResult] = search_history,
    allow_autofix: bool = True,
) -> RotationSummary:
    """Run the interactive rotation assistant over `findings`.

    `findings` is a list of ``(display_path, line_number, Match)`` as
    produced by the scan engine. `iter_sources` yields ``(path, text)`` for
    the files to check for leftover copies; without it that step is
    skipped. `allow_autofix=False` is for findings that come from Git history
    (``scan --history --rotate``): there is no current file to rewrite, so
    Step 2 explains that instead of offering Auto-Fix. `open_url` defaults to the system browser and is only ever
    called with a URL from the provider table, after confirmation.
    """
    summary = RotationSummary()
    scrub = _Scrubber()

    def out(text: str = "") -> None:
        print_func(scrub(text))

    def ask(prompt: str) -> str:
        return input_func(scrub(prompt))

    credentials = _group(findings)
    summary.credentials = credentials
    for cred in credentials:
        scrub.add(cred.value, cred.core)

    if not credentials:
        out("No potential secrets found, so there is nothing to rotate.")
        return summary

    if not is_interactive():
        out("The rotation assistant requires an interactive terminal.")
        out("No changes were made.")
        summary.exit_code = 1
        return summary

    if open_url is None:
        import webbrowser

        open_url = webbrowser.open

    try:
        total_locations = sum(len(c.locations) for c in credentials)
        out("SecretShield Rotation Assistant")
        out(
            f"Found {len(credentials)} potential credential(s) in {total_locations} "
            f"location(s)."
        )
        out(
            "SecretShield makes no network requests here, never revokes anything itself, "
            "and asks before it changes any file. Press Ctrl+C at any time to stop."
        )
        for index, cred in enumerate(credentials, 1):
            _walk(
                index, len(credentials), cred, project_root, entropy_threshold,
                custom_rules, iter_sources, out, ask, open_url, history_search,
                allow_autofix,
            )  # fmt: skip
        _print_summary(out, credentials, partial=False)
    except (KeyboardInterrupt, EOFError):
        out("")
        out("Rotation assistant cancelled. Nothing further was changed.")
        summary.cancelled = True
        _print_summary(out, credentials, partial=True)
    except Exception as exc:  # noqa: BLE001 - never leak details; report the type only
        out(
            "secretshield: error: the rotation assistant stopped unexpectedly "
            f"({type(exc).__name__}). Nothing further was changed."
        )
        summary.errored = True

    if summary.errored:
        summary.exit_code = 2
    elif summary.cancelled or not all(_resolved(c) for c in credentials):
        summary.exit_code = 1
    return summary


def _resolved(cred: Credential) -> bool:
    """True when the user reported revoking it AND no copy remains in the tree.

    This is a statement about what the user said and what was found
    locally. It is not verification that the provider revoked anything.
    """
    if not cred.guide.needs_rotation:
        return True
    return cred.revoked_reported is True and cred.refs_remaining == 0


def _show_links(out: Callable[[str], None], guide: Guide) -> None:
    if guide.manage:
        out(f"  Credential management: {guide.manage.url}")
    for link in guide.docs:
        out(f"  {link.label}: {link.url}")


def _browser_target(guide: Guide) -> Link | None:
    return guide.manage or (guide.docs[0] if guide.docs else None)


def _walk(
    index, total, cred, project_root, entropy_threshold, custom_rules,
    iter_sources, out, ask, open_url, history_search, allow_autofix=True,
):  # fmt: skip
    guide = cred.guide
    out(f"\nCredential {index}/{total}")
    if guide.identified:
        out(f"Likely provider: {guide.provider} ({guide.credential}), matched by its format")
    else:
        out(f"Provider: not identified ({guide.credential}). SecretShield will not guess.")
    out(f"Detected value: {MASK}")
    out(f"Found in: {_format_locations(cred.locations)}")

    if not guide.needs_rotation:
        for note in guide.notes:
            out(f"\n{note}")
        _show_links(out, guide)
        out("\nNothing to revoke for this one.")
        return

    out("")
    out(_WHY)
    if not _yes_default(ask("\nWork on this credential now? [Y/n] ")):
        cred.skipped = True
        out("Skipped. It stays usable by anyone who has seen it until it is revoked.")
        return

    # --- Step 1: revoke or rotate with the provider -------------------------------
    out("\nStep 1 of 3: revoke or rotate it with the provider")
    out(
        "  This is the only step that makes the old credential unusable. SecretShield "
        "cannot do it for you."
    )
    for number, step in enumerate(guide.steps, 1):
        out(f"  {number}. {step}")
    for note in guide.notes:
        out(f"  Note: {note}")
    _show_links(out, guide)

    target = _browser_target(guide)
    if target is not None and _yes(ask(f"Open \"{target.label}\" in your browser? [y/N] ")):
        _open(out, open_url, target)

    cred.revoked_reported = _yes(
        ask("Have you revoked or rotated the old credential with the provider? [y/N] ")
    )
    if cred.revoked_reported:
        out("  Recorded as reported by you. SecretShield cannot verify it with the provider.")
    else:
        out("  Not marked as revoked. Until you do this, the old credential still works.")

    # --- Step 2: replace references in code ---------------------------------------
    out("\nStep 2 of 3: replace the old credential in your code")
    out(
        "  Replacing references is separate from revoking: it only stops your code from "
        "carrying the old value. Keep the NEW credential in an environment variable or a "
        "secrets manager, never in source code."
    )
    if not allow_autofix:
        out(
            "  This credential was found in Git history, so there is no current file for "
            "Auto-Fix to rewrite. If anything still uses the old value (your code, "
            "deployments, CI settings), switch it to the NEW credential."
        )
    else:
        out(
            "  Auto-Fix can rewrite supported Python and JS/TS assignments to read an "
            "environment variable and move the value into a local, git-ignored .env. It asks "
            "before every change."
        )
        out(
            "  Note: Auto-Fix puts the OLD value in .env. Afterwards, replace it there with "
            "the new credential; the old one must not be reused."
        )
    if not allow_autofix:
        pass
    elif _yes(ask("Run Auto-Fix for this credential now? [y/N] ")):
        by_file: dict[str, list] = {}
        for file, match in cred.matches:
            by_file.setdefault(file, []).append(match)
        fix = run_autofix(
            project_root, by_file, entropy_threshold=entropy_threshold,
            print_func=out, input_func=ask, custom_rules=custom_rules,
        )  # fmt: skip
        cred.replaced = fix.fixed
        if fix.fixed:
            out(
                "\n  Now put the NEW credential in .env (or your secrets manager) in place "
                "of the old value."
            )
    else:
        out("  Skipped. Replace the references yourself, or run `secretshield scan . --fix` later.")

    # --- Step 3: check for leftovers ---------------------------------------------
    out("\nStep 3 of 3: check for leftover copies of the old credential")
    _check_working_tree(cred, iter_sources, out, ask)
    _check_history(cred, project_root, out, ask, history_search)


def _open(out, open_url, target: Link) -> None:
    try:
        opened = open_url(target.url)
    except Exception:  # noqa: BLE001
        opened = False
    if opened is False:
        out("  Could not open a browser. Open the link above yourself.")


def _check_working_tree(cred: Credential, iter_sources: SourceIter | None, out, ask) -> None:
    if iter_sources is None:
        out("  Working tree: not checked.")
        return
    while True:
        refs = find_references(cred.core, iter_sources)
        cred.refs_remaining = len(refs)
        if not refs:
            out("  Working tree: the old value was not found in the scanned files.")
            return
        out(f"  Working tree: the old value is still present in {_format_locations(refs)}")
        if any(Path(path).name == ".env" or Path(path).name.startswith(".env.") for path, _ in refs):
            out("  A .env file still holds it. Replace that value with the new credential.")
        if not _yes(ask("  Check again after you have updated those files? [y/N] ")):
            return


def _check_history(cred: Credential, project_root: Path, out, ask, history_search) -> None:
    from ..git import is_git_repo

    if not is_git_repo(project_root):
        out("  Git history: not a Git repository, nothing to check.")
        return
    if not _yes(
        ask("  Search Git history for it? (local and read-only; can be slow on big repos) [y/N] ")
    ):
        out("  Git history: not checked.")
        return
    result = history_search(cred.core, project_root)
    if result.error:
        out(f"  Git history: could not be checked ({result.error}).")
        return
    if result.truncated:
        out("  Git history: the search was cut short on a very large history. Results are partial.")
    if not result.commits:
        out(
            "  Git history: not found in the commits reachable from your refs"
            + (" (partial search)." if result.truncated else ".")
        )
        if not result.truncated:
            cred.history_commits = 0
        return
    cred.history_commits = len(result.commits)
    shown = ", ".join(c[:8] for c in result.commits[:_MAX_COMMITS_SHOWN])
    extra = len(result.commits) - _MAX_COMMITS_SHOWN
    out(
        f"  Git history: found in {len(result.commits)} commit(s): {shown}"
        + (f", and {extra} more" if extra > 0 else "")
    )
    out(
        "  Old commits still contain it, which is why revoking (step 1) is what matters. "
        "Rewriting history is optional, affects everyone who has a clone, and cannot reach "
        "forks or copies others already have."
    )
    out(f"  {HISTORY_GUIDE.label}: {HISTORY_GUIDE.url}")


def _revocation_text(cred: Credential) -> str:
    if not cred.guide.needs_rotation:
        return "not needed (the provider documents this key as safe to expose)"
    if cred.skipped:
        return "skipped, so the credential is still usable"
    if cred.revoked_reported is True:
        return "reported by you (not verified by SecretShield)"
    if cred.revoked_reported is False:
        return "NOT done"
    return "not reached"


def _print_summary(out, credentials: list[Credential], partial: bool) -> None:
    out("\nSecretShield Rotation Summary" + (" (stopped early)" if partial else ""))
    out("\u2500" * 30)
    for number, cred in enumerate(credentials, 1):
        label = (
            f"{cred.guide.provider} {cred.guide.credential}"
            if cred.guide.identified
            else f"{cred.guide.credential} (provider unknown)"
        )
        out(f"\n{number}. {label} ({_format_locations(cred.locations[:1])})")
        out(f"   Revocation: {_revocation_text(cred)}")
        if cred.guide.needs_rotation and not cred.skipped:
            if cred.replaced:
                out(f"   Code references replaced by Auto-Fix: {cred.replaced}")
            if cred.refs_remaining is None:
                out("   Working tree: not checked")
            elif cred.refs_remaining == 0:
                out("   Working tree: no copy of the old value found")
            else:
                out(f"   Working tree: old value still present in {cred.refs_remaining} location(s)")
            if cred.history_commits is None:
                out("   Git history: not checked")
            elif cred.history_commits == 0:
                out("   Git history: not found")
            else:
                out(f"   Git history: found in {cred.history_commits} commit(s)")

    unresolved = [c for c in credentials if not _resolved(c)]
    out("")
    if unresolved:
        out(f"{len(unresolved)} of {len(credentials)} credential(s) still need attention.")
    else:
        out("Every credential was handled as far as SecretShield can tell.")
    out(
        "SecretShield cannot verify revocation with the provider. Confirm it yourself, for "
        "example by checking that the old credential is now rejected."
    )
