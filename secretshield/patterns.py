"""
Regex patterns used to detect well-known secret formats.

Each entry in ``PATTERNS`` is a tuple of ``(name, compiled_regex)``. These
patterns intentionally target *shapes* of known credential formats (AWS
keys, GitHub tokens, JWTs, etc.) rather than relying purely on entropy,
which keeps the false-positive rate low.

None of the values in this module are real credentials. They are regular
expressions only.
"""

from __future__ import annotations

import re

# Each pattern is (name, compiled regex). Order matters only in that more
# specific patterns are listed before more generic ones.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "aws_access_key_id",
        re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b"),
    ),
    (
        "aws_secret_access_key",
        re.compile(
            r"(?i)\baws(.{0,20})?(secret|access)?(.{0,20})?key(.{0,20})?"
            r"['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"
        ),
    ),
    (
        "github_token",
        re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255}\b"),
    ),
    (
        "openai_api_key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}(?:T3BlbkFJ[A-Za-z0-9]{20,})?\b"),
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b"),
    ),
    (
        "stripe_key",
        re.compile(r"\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{16,}\b"),
    ),
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ),
    (
        "jwt",
        re.compile(
            r"\bey[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
        ),
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{10,}=*"),
    ),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
    ),
    (
        "generic_labeled_secret",
        re.compile(
            r"""(?ix)
            (?<![A-Za-z])
            (api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|
               client[_-]?secret|auth[_-]?token|private[_-]?key)
            \b
            \s*
            [:=]
            \s*
            ['\"]?
            (?P<value>[A-Za-z0-9!@#$%^&*_+\-./~=]{8,})
            ['\"]?
            """
        ),
    ),
]

# Group name used by the generic labeled-secret pattern to isolate the
# value portion (so we don't redact the label itself, only the secret).
GENERIC_VALUE_GROUP = "value"

# Characters considered when computing Shannon entropy for generic
# high-entropy token detection. Long runs of base64/hex-like strings are
# candidates; short common words are filtered out by min length checks.
ENTROPY_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/_\-]{20,}={0,2}\b")

# Words that commonly appear as long identifiers but are NOT secrets.
# Used to reduce false positives in entropy-based detection.
ENTROPY_ALLOWLIST_SUBSTRINGS = (
    "lorem",
    "ipsum",
    "example",
    "placeholder",
)
