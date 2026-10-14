"""
Inline ignore comments: mark a single line as an accepted finding.

Syntax (put it in a comment in whatever language the file uses)::

    token = "..."   # secretshield:ignore
    token = "..."   # secretshield:ignore[github_token, high_entropy]

    # secretshield:ignore-next-line
    token = "..."

* ``secretshield:ignore`` suppresses findings that *start* on the same line.
* ``secretshield:ignore-next-line`` suppresses findings that start on the
  following line (useful where a trailing comment is impossible, such as
  JSON, or before a multi-line private key block).
* An optional ``[kind, kind]`` list narrows the suppression to those
  finding kinds, so a marker cannot silently hide a *different* secret
  that happens to be on the same line. ``[]`` suppresses nothing.

Deliberately strict, because a missed marker only leaves a finding
visible while a too-eager one hides a real secret: the marker is
lowercase and exact, a misspelling (``ignored``, ``ignore-nextline``) is
not honored, and only a finding's *first* line counts.

This only applies to the scan engine. Runtime protection (the redaction of
``print()``/logging output) never honors it.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from typing import Iterable

MARKER_PREFIX = "secretshield:"

_MARKER_RE = re.compile(
    r"secretshield:[ \t]*ignore(?P<next>-next-line)?(?![\w-])(?:\[(?P<kinds>[^\]\r\n]*)\])?"
)

# line number -> None (every kind) or the set of kinds to suppress
Suppressions = dict[int, "set[str] | None"]


def collect_suppressions(text: str) -> Suppressions:
    """Map each line that has an active marker to what it suppresses.

    Lines are separated by ``\\n`` only, exactly like the scanner's own
    line numbering (``str.splitlines`` would also split on form feeds and
    Unicode separators and shift every later line number).
    """
    result: Suppressions = {}
    if MARKER_PREFIX not in text:  # fast path: nearly every file
        return result
    for line_no, line in enumerate(text.split("\n"), start=1):
        if MARKER_PREFIX not in line:
            continue
        for marker in _MARKER_RE.finditer(line):
            target = line_no + 1 if marker.group("next") else line_no
            kinds = marker.group("kinds")
            if kinds is None:
                result[target] = None  # unqualified: every kind
                continue
            wanted = {k.strip() for k in kinds.split(",") if k.strip()}
            if target in result and result[target] is None:
                continue  # already suppressing everything
            result.setdefault(target, set()).update(wanted)  # type: ignore[union-attr]
    return result


def filter_inline_ignored(text: str, matches: Iterable) -> tuple[list, int]:
    """Drop matches covered by an inline marker; return (kept, suppressed_count).

    `matches` need ``.start`` and ``.kind`` (detector and custom-rule
    matches both qualify). Never inspects or returns a secret value.
    """
    matches = list(matches)
    if not matches:
        return matches, 0
    suppressions = collect_suppressions(text)
    if not suppressions:
        return matches, 0

    line_starts = [0] + [m.end() for m in re.finditer("\n", text)]
    kept: list = []
    suppressed = 0
    for match in matches:
        line_no = bisect_right(line_starts, match.start)  # 1-indexed
        if line_no in suppressions:
            kinds = suppressions[line_no]
            if kinds is None or match.kind in kinds:
                suppressed += 1
                continue
        kept.append(match)
    return kept, suppressed
