"""
Secret detection logic.

Combines pattern-based matching (for well-known secret formats) with a
generic high-entropy scan (for random-looking tokens that don't match a
known shape). Entropy detection is intentionally conservative and is used
as a supplement, never as the sole detection strategy, to avoid excessive
false positives.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from . import patterns


@dataclass(frozen=True)
class Match:
    """A single detected secret span within a piece of text."""

    start: int
    end: int
    value: str
    kind: str

    def __len__(self) -> int:
        return self.end - self.start


def _shannon_entropy(s: str) -> float:
    """Return the Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _looks_like_real_candidate(token: str) -> bool:
    """Filter out obvious non-secrets before running entropy checks."""
    lowered = token.lower()
    if any(word in lowered for word in patterns.ENTROPY_ALLOWLIST_SUBSTRINGS):
        return False
    # Skip strings composed of a single repeated character or simple runs.
    if len(set(token)) <= 2:
        return False
    # Skip pure digit sequences (phone numbers, IDs, timestamps, etc.)
    if token.isdigit():
        return False
    return True


def _pattern_matches(text: str) -> list[Match]:
    matches: list[Match] = []
    for name, regex in patterns.PATTERNS:
        for m in regex.finditer(text):
            if name == "generic_labeled_secret":
                # Only redact the captured value, not the label/key name.
                start, end = m.span(patterns.GENERIC_VALUE_GROUP)
                value = m.group(patterns.GENERIC_VALUE_GROUP)
            else:
                start, end = m.span()
                value = m.group()
            if not value:
                continue
            matches.append(Match(start=start, end=end, value=value, kind=name))
    return matches


def _entropy_matches(text: str, threshold: float) -> list[Match]:
    matches: list[Match] = []
    for m in patterns.ENTROPY_CANDIDATE_RE.finditer(text):
        token = m.group()
        if not _looks_like_real_candidate(token):
            continue
        entropy = _shannon_entropy(token)
        if entropy >= threshold:
            matches.append(
                Match(start=m.start(), end=m.end(), value=token, kind="high_entropy")
            )
    return matches


def _merge_overlapping(matches: list[Match]) -> list[Match]:
    """Merge/deduplicate overlapping spans, keeping the widest match."""
    if not matches:
        return []
    ordered = sorted(matches, key=lambda m: (m.start, -(m.end - m.start)))
    merged: list[Match] = [ordered[0]]
    for current in ordered[1:]:
        last = merged[-1]
        if current.start < last.end:
            # Overlaps with previous match; keep whichever is wider.
            if (current.end - current.start) > (last.end - last.start):
                merged[-1] = current
            continue
        merged.append(current)
    return merged


def detect(text: str, entropy_threshold: float = 4.2) -> list[Match]:
    """
    Detect likely secrets within ``text``.

    Returns a list of :class:`Match` objects sorted by position. This
    combines known-pattern detection with generic high-entropy detection.
    Overlapping matches are merged so a single secret isn't reported twice.
    """
    if not text:
        return []
    try:
        found = _pattern_matches(text)
        found.extend(_entropy_matches(text, entropy_threshold))
    except Exception:
        # Detection must never crash the host application.
        return []
    return _merge_overlapping(found)
