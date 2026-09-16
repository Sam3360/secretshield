"""
Redaction logic: turns detected secrets into safe placeholder text.
"""

from __future__ import annotations

from .detector import Match, detect


def redact(
    text: str,
    entropy_threshold: float = 4.2,
    redact_with: str = "********",
) -> tuple[str, bool]:
    """
    Redact any detected secrets in ``text``.

    Returns a tuple of ``(redacted_text, was_redacted)``. ``was_redacted``
    is ``True`` if at least one secret was found and replaced. The
    original secret value is never present in the returned string.
    """
    if not text:
        return text, False

    try:
        matches: list[Match] = detect(text, entropy_threshold=entropy_threshold)
    except Exception:
        # Detection failures must never break output; fail open (no redaction)
        # rather than raise, but never leak partial state.
        return text, False

    if not matches:
        return text, False

    # Rebuild the string, replacing each match span with the placeholder.
    # Process in order, tracking an offset since replacement length may
    # differ from the original match length.
    result_parts: list[str] = []
    cursor = 0
    for match in sorted(matches, key=lambda m: m.start):
        if match.start < cursor:
            # Overlap already consumed by a previous replacement; skip.
            continue
        result_parts.append(text[cursor:match.start])
        result_parts.append(redact_with)
        cursor = match.end

    result_parts.append(text[cursor:])
    return "".join(result_parts), True
