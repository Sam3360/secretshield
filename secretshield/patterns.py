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
        # Legacy keys are `sk-` + alphanumerics. Current project, service
        # account, admin and user keys carry a sub-prefix and also use `-`
        # and `_` in the body, so they need their own branch (anything
        # looser would flag ordinary kebab-case identifiers starting `sk-`).
        re.compile(
            r"\bsk-(?:"
            r"(?:proj|svcacct|admin|None)-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"
            r"|[A-Za-z0-9]{20,}(?:T3BlbkFJ[A-Za-z0-9]{20,})?\b"
            r")"
        ),
    ),
    (
        "anthropic_api_key",
        # Documented families: Claude API keys (sk-ant-api03-...), Admin API
        # keys (sk-ant-admin01-...) and compliance access keys (sk-ant-api01-...).
        re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
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
        "gitlab_token",
        # glpat (personal/project/group access tokens), gldt (deploy),
        # glrt (runner authentication), gloas (OAuth application secret).
        re.compile(r"\b(?:glpat|gldt|glrt|gloas)-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    ),
    (
        "npm_token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    ),
    (
        "pypi_token",
        # `pypi-` followed by a base64url macaroon, which always starts `Ag`
        # (pypi.org: `AgEIcHlwaS5vcmc...`). Requiring it keeps names like
        # `pypi-some-long-package-name` from matching.
        re.compile(r"\bpypi-AgE[A-Za-z0-9_-]{50,}(?![A-Za-z0-9_-])"),
    ),
    (
        "sendgrid_api_key",
        # SendGrid documents keys as exactly 69 characters: SG. + 22 + . + 43.
        re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"),
    ),
    (
        "huggingface_token",
        re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
    ),
    (
        "slack_webhook_url",
        # The URL itself is the secret. The generic entropy check skips URL
        # paths (see URL_RE), so webhook URLs need their own detector.
        re.compile(
            r"https://hooks\.slack(?:-gov)?\.com/services/"
            r"T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}(?![A-Za-z0-9])"
        ),
    ),
    (
        "discord_webhook_url",
        re.compile(
            r"https://(?:discord|discordapp)\.com/api(?:/v\d+)?/webhooks/"
            r"\d{15,20}/[A-Za-z0-9_-]{50,}(?![A-Za-z0-9_-])"
        ),
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

# Kinds whose documentation examples are usually a real-looking prefix
# followed by filler (`glpat-xxxxxxxxxxxxxxxxxxxx`, `.../XXXXXXXXXXXXXXXXXXXXXXXX`).
# A match whose longest alphanumeric run uses three or fewer distinct
# characters is treated as that kind of filler and skipped.
TRIVIAL_BODY_KINDS = frozenset(
    {
        "anthropic_api_key", "gitlab_token", "npm_token", "pypi_token",
        "sendgrid_api_key", "huggingface_token", "slack_webhook_url",
        "discord_webhook_url",
    }
)  # fmt: skip

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

# URLs (scheme://... or www....). Used only by the generic entropy check:
# the scheme, host and path of a URL are identifiers, not secrets, so they
# are skipped there. Credentials (``user:password@``) and query/fragment
# values are still examined, and every known-format pattern above still
# runs against the full, unmodified text.
URL_RE = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.\-]*://|www\.)[^\s'\"<>`)\]}]+")
