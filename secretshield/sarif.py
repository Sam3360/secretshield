"""
SARIF 2.1.0 export for `secretshield scan --format sarif`.

This module is a pure *reporting* layer. It takes findings the existing
scan pipeline has already produced (file, rule kind, location) and turns
them into a SARIF log; it never runs detection itself, reads files,
touches the network, or imports anything outside the standard library.

Secret values never reach this module. The builder's input type
(:class:`SarifFinding`) has no field that could carry one -- only the
file path, the rule ``kind`` (e.g. ``"github_token"``), and a source
region -- so a leak through a message, snippet, or property is not
possible by construction rather than by careful filtering. For the
same reason no value-derived fingerprint (such as the baseline hash,
which is a SHA-256 of the secret) is emitted; GitHub's ``upload-sarif``
action computes ``partialFingerprints`` itself at upload time.

Output follows the subset of SARIF 2.1.0 that GitHub Code Scanning
consumes: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import quote_from_bytes

from . import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "SecretShield"
TOOL_INFORMATION_URI = "https://github.com/Sam3360/secretshield"
HELP_URI = TOOL_INFORMATION_URI + "/blob/main/USAGE.md#sarif-export"

RULE_ID_PREFIX = "secretshield."
CUSTOM_RULE_ID_PREFIX = "secretshield.custom."

# Region columns are computed in UTF-16 code units (the SARIF default),
# and declared explicitly on the run so consumers don't have to guess.
COLUMN_KIND = "utf16CodeUnits"


@dataclass(frozen=True)
class SarifFinding:
    """One finding, as the report needs it. Deliberately has no value field."""

    file: str
    kind: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int


# --- Rule catalog -------------------------------------------------------------

_GENERIC_STEPS = (
    "Treat the credential as compromised: revoke or rotate it with the issuing "
    "service, remove it from the source file, and load it at runtime from an "
    "environment variable or a secret manager instead. If it was ever committed, "
    "deleting it from the latest commit does not undo the exposure; rotate it and "
    "consider purging it from Git history."
)
_FALSE_POSITIVE_STEPS = (
    "If this is a false positive, exclude the path with .secretshieldignore or "
    "secretshield.toml, or accept it with `secretshield scan . --baseline`."
)


@dataclass(frozen=True)
class _RuleSpec:
    name: str  # SARIF rule "name" (PascalCase identifier)
    label: str  # human label, mirrors the CLI's text output
    short: str
    full: str
    level: str  # error | warning | note
    severity: str  # GitHub security-severity, as a string
    precision: str  # very-high | high | medium | low
    remediation: str
    extra_tags: tuple[str, ...] = ()


# Keyed by detector `kind`. Every pattern in patterns.PATTERNS plus
# "high_entropy" must have an entry here (enforced by tests).
#
# security-severity buckets used by GitHub: >9.0 critical, 7.0-8.9 high,
# 4.0-6.9 medium, 0.1-3.9 low. `level` is kept consistent with them:
# critical/high -> error, medium -> warning, low -> note.
_BUILTIN_RULES: dict[str, _RuleSpec] = {
    "aws_access_key_id": _RuleSpec(
        name="AwsAccessKeyId",
        label="AWS access key",
        short="Hardcoded AWS access key ID",
        full="An AWS access key ID is present in source. Paired with its secret key it grants API access to an AWS account.",
        level="error",
        severity="7.5",
        precision="very-high",
        remediation="Deactivate and delete the access key in AWS IAM, create a replacement, and review CloudTrail for use of the old key. " + _GENERIC_STEPS,
        extra_tags=("aws",),
    ),
    "aws_secret_access_key": _RuleSpec(
        name="AwsSecretAccessKey",
        label="AWS secret access key",
        short="Hardcoded AWS secret access key",
        full="An AWS secret access key is present in source. It grants API access to an AWS account with the permissions of its IAM identity.",
        level="error",
        severity="9.5",
        precision="high",
        remediation="Deactivate and delete the access key in AWS IAM, create a replacement, and review CloudTrail for use of the old key. " + _GENERIC_STEPS,
        extra_tags=("aws",),
    ),
    "github_token": _RuleSpec(
        name="GithubToken",
        label="GitHub token",
        short="Hardcoded GitHub token",
        full="A GitHub personal access token or app token is present in source. It can act with the permissions of its owner or app.",
        level="error",
        severity="8.5",
        precision="very-high",
        remediation="Revoke the token in GitHub (Settings > Developer settings, or the owning app's settings) and issue a new one with the minimum scopes needed. " + _GENERIC_STEPS,
        extra_tags=("github",),
    ),
    "openai_api_key": _RuleSpec(
        name="OpenAiApiKey",
        label="OpenAI API key",
        short="Hardcoded OpenAI-style API key",
        full="An API key in the OpenAI key format is present in source. It allows billable API use under the owning account.",
        level="error",
        severity="8.0",
        precision="high",
        remediation="Revoke the key in the provider's dashboard and create a new one. " + _GENERIC_STEPS,
        extra_tags=("api-key",),
    ),
    "slack_token": _RuleSpec(
        name="SlackToken",
        label="Slack token",
        short="Hardcoded Slack token",
        full="A Slack bot, app, or user token is present in source. It can read and post in the workspace according to its scopes.",
        level="error",
        severity="8.0",
        precision="very-high",
        remediation="Revoke or regenerate the token in your Slack app settings. " + _GENERIC_STEPS,
        extra_tags=("slack",),
    ),
    "stripe_key": _RuleSpec(
        name="StripeKey",
        label="Stripe key",
        short="Hardcoded Stripe API key",
        full="A Stripe API key is present in source. Secret and restricted live keys can move money and read customer data; publishable and test keys are lower risk.",
        level="error",
        severity="8.0",
        precision="high",
        remediation="Roll the key in the Stripe Dashboard (Developers > API keys). Publishable (pk_) and test-mode keys are lower risk but should still not be committed. " + _GENERIC_STEPS,
        extra_tags=("stripe", "api-key"),
    ),
    "google_api_key": _RuleSpec(
        name="GoogleApiKey",
        label="Google API key",
        short="Hardcoded Google API key",
        full="A Google API key is present in source. Depending on its restrictions it may allow billable use of Google Cloud APIs.",
        level="error",
        severity="7.0",
        precision="high",
        remediation="Regenerate the key in the Google Cloud console (APIs & Services > Credentials) and restrict the new key by API and by application or IP. " + _GENERIC_STEPS,
        extra_tags=("google", "api-key"),
    ),
    "jwt": _RuleSpec(
        name="JsonWebToken",
        label="JWT",
        short="Hardcoded JSON Web Token",
        full="A JSON Web Token is present in source. Until it expires it may be accepted as proof of identity.",
        level="warning",
        severity="6.5",
        precision="medium",
        remediation="Invalidate the token with the service that issued it (or rotate the signing secret if it is long-lived) and remove it from the source. " + _FALSE_POSITIVE_STEPS,
        extra_tags=("token",),
    ),
    "bearer_token": _RuleSpec(
        name="BearerToken",
        label="Bearer token",
        short="Hardcoded bearer token",
        full="An HTTP bearer token is present in source and may authenticate requests to an API.",
        level="error",
        severity="7.5",
        precision="high",
        remediation="Revoke the token with the service that issued it and load the replacement at runtime instead of hardcoding it. " + _GENERIC_STEPS,
        extra_tags=("token",),
    ),
    "private_key_block": _RuleSpec(
        name="PrivateKeyBlock",
        label="Private key block",
        short="Private key committed to source",
        full="A PEM-encoded private key block is present in source. Anyone with the key can impersonate its owner or decrypt data protected by it.",
        level="error",
        severity="9.5",
        precision="very-high",
        remediation="Generate a new key pair, replace the public key everywhere the old one was trusted (servers, certificates, deploy keys), and retire the old key. " + _GENERIC_STEPS,
        extra_tags=("private-key", "external/cwe/cwe-321"),
    ),
    "generic_labeled_secret": _RuleSpec(
        name="GenericLabeledSecret",
        label="Generic credential",
        short="Hardcoded credential assigned to a secret-like name",
        full="A value is assigned to a name such as password, secret, token, or api_key. This is a heuristic match and may be a placeholder or test value.",
        level="warning",
        severity="6.0",
        precision="medium",
        remediation="If the value is a real credential, rotate it and load it from the environment or a secret manager. " + _FALSE_POSITIVE_STEPS,
    ),
    "high_entropy": _RuleSpec(
        name="HighEntropyString",
        label="High-entropy string",
        short="High-entropy string that may be a secret",
        full="A long random-looking string was found. Entropy matching is a heuristic and also flags hashes, identifiers, and encoded data that are not secrets.",
        level="note",
        severity="3.5",
        precision="low",
        remediation="Check whether the string is a credential. If it is, rotate it and load it from the environment or a secret manager; if not, exclude the path or accept it with `secretshield scan . --baseline`.",
    ),
    "anthropic_api_key": _RuleSpec(
        name="AnthropicApiKey",
        label="Anthropic API key",
        short="Hardcoded Anthropic API key",
        full="An Anthropic API key (Claude API, Admin API or compliance access key) is present in source. It allows billable API use and, for admin keys, organization management.",
        level="error",
        severity="8.0",
        precision="very-high",
        remediation="Revoke the key in the Claude Console (Settings > API keys, or Settings > Admin keys for an admin key), create a replacement, and update your applications. " + _GENERIC_STEPS,
        extra_tags=("anthropic", "api-key"),
    ),
    "gitlab_token": _RuleSpec(
        name="GitlabToken",
        label="GitLab token",
        short="Hardcoded GitLab token",
        full="A GitLab personal, project or group access token, deploy token, runner authentication token or OAuth application secret is present in source. It can act with the permissions of its owner.",
        level="error",
        severity="8.5",
        precision="very-high",
        remediation="Revoke or rotate the token in GitLab (for a personal access token: Edit profile > Access tokens) and issue a replacement with the minimum scopes needed. " + _GENERIC_STEPS,
        extra_tags=("gitlab", "token"),
    ),
    "npm_token": _RuleSpec(
        name="NpmToken",
        label="npm token",
        short="Hardcoded npm access token",
        full="An npm access token is present in source. Depending on its permissions it can publish new versions of the packages its owner maintains.",
        level="error",
        severity="8.5",
        precision="very-high",
        remediation="Revoke the token from your npm account (profile picture > Access Tokens, or `npm token delete <id>`) and create a granular replacement. npm notes revocation can take up to an hour to take effect. " + _GENERIC_STEPS,
        extra_tags=("npm", "token"),
    ),
    "pypi_token": _RuleSpec(
        name="PypiToken",
        label="PyPI token",
        short="Hardcoded PyPI API token",
        full="A PyPI API token is present in source. It can upload releases to the projects it is scoped to, or to every project of its owner account.",
        level="error",
        severity="8.5",
        precision="very-high",
        remediation="Revoke the token in your PyPI account settings (API tokens) and create a replacement scoped to a single project, or use Trusted Publishing from a CI provider that supports it. " + _GENERIC_STEPS,
        extra_tags=("pypi", "token"),
    ),
    "sendgrid_api_key": _RuleSpec(
        name="SendgridApiKey",
        label="SendGrid API key",
        short="Hardcoded SendGrid API key",
        full="A Twilio SendGrid API key is present in source. It can send email from the account and, depending on its access level, manage account settings.",
        level="error",
        severity="8.0",
        precision="very-high",
        remediation="Delete the key in the Twilio SendGrid app (Settings > API Keys) and create a replacement with the least access needed. SendGrid notes a revoked key stops working after a short propagation delay. " + _GENERIC_STEPS,
        extra_tags=("sendgrid", "api-key"),
    ),
    "huggingface_token": _RuleSpec(
        name="HuggingfaceToken",
        label="Hugging Face token",
        short="Hardcoded Hugging Face token",
        full="A Hugging Face user access token is present in source. It can read, and with write access modify, the repositories its owner can reach.",
        level="error",
        severity="7.5",
        precision="high",
        remediation="Delete or refresh the token from the Access Tokens tab of your Hugging Face settings and issue a replacement with the minimum role needed. " + _GENERIC_STEPS,
        extra_tags=("huggingface", "token"),
    ),
    "slack_webhook_url": _RuleSpec(
        name="SlackWebhookUrl",
        label="Slack webhook URL",
        short="Hardcoded Slack incoming webhook URL",
        full="A Slack incoming webhook URL is present in source. The URL is the secret: anyone holding it can post messages to the channel it is bound to.",
        level="warning",
        severity="6.0",
        precision="very-high",
        remediation="Treat the URL as compromised. Slack's documentation does not describe revoking a webhook URL, so remove the webhook (or its app) in your Slack app settings and create a replacement. " + _GENERIC_STEPS,
        extra_tags=("slack", "webhook"),
    ),
    "discord_webhook_url": _RuleSpec(
        name="DiscordWebhookUrl",
        label="Discord webhook URL",
        short="Hardcoded Discord webhook URL",
        full="A Discord webhook URL is present in source. The URL carries its own token: anyone holding it can post messages to the channel it is bound to.",
        level="warning",
        severity="6.0",
        precision="very-high",
        remediation="Delete the webhook in your server's Server Settings > Integrations > Webhooks and create a replacement. " + _GENERIC_STEPS,
        extra_tags=("discord", "webhook"),
    ),
}

# Custom rules (.secretshield-rules.toml) carry only a name and a pattern,
# so they get one fixed, conservative mapping: a scan that matches one
# already exits 1 like any other finding, so it is reported as an error.
_CUSTOM_LEVEL = "error"
_CUSTOM_SEVERITY = "7.5"
_CUSTOM_PRECISION = "medium"
_CUSTOM_REMEDIATION = (
    "A custom SecretShield rule matched here. " + _GENERIC_STEPS + " " + _FALSE_POSITIVE_STEPS
)

BUILTIN_RULE_KINDS: tuple[str, ...] = tuple(_BUILTIN_RULES)


def builtin_label(kind: str) -> str | None:
    spec = _BUILTIN_RULES.get(kind)
    return spec.label if spec else None


# --- Rule identity --------------------------------------------------------------


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "rule"


class _RuleTable:
    """Assigns every rule kind a stable SARIF id and index."""

    def __init__(self) -> None:
        self.rules: list[dict] = []
        self._index: dict[str, int] = {}
        self._used_ids: set[str] = set()
        for kind, spec in _BUILTIN_RULES.items():
            self._used_ids.add(RULE_ID_PREFIX + kind)
            self._add(kind, self._builtin_descriptor(kind, spec))

    def _add(self, kind: str, descriptor: dict) -> None:
        self._index[kind] = len(self.rules)
        self.rules.append(descriptor)

    def ensure_custom(self, name: str) -> None:
        if name in self._index:
            return
        base = CUSTOM_RULE_ID_PREFIX + _slug(name)
        rule_id, n = base, 2
        while rule_id in self._used_ids:
            rule_id = f"{base}-{n}"
            n += 1
        self._used_ids.add(rule_id)
        self._add(name, self._custom_descriptor(rule_id, name))

    def index_of(self, kind: str) -> int:
        return self._index[kind]

    def id_of(self, kind: str) -> str:
        return self.rules[self._index[kind]]["id"]

    def level_of(self, kind: str) -> str:
        return self.rules[self._index[kind]]["defaultConfiguration"]["level"]

    @staticmethod
    def _builtin_descriptor(kind: str, spec: _RuleSpec) -> dict:
        return {
            "id": RULE_ID_PREFIX + kind,
            "name": spec.name,
            "shortDescription": {"text": spec.short},
            "fullDescription": {"text": spec.full},
            "helpUri": HELP_URI,
            "help": {
                "text": spec.remediation,
                "markdown": f"**{spec.label}**\n\n{spec.remediation}",
            },
            "defaultConfiguration": {"level": spec.level},
            "properties": {
                "tags": ["security", "secret", "external/cwe/cwe-798", *spec.extra_tags],
                "precision": spec.precision,
                "security-severity": spec.severity,
            },
        }

    @staticmethod
    def _custom_descriptor(rule_id: str, name: str) -> dict:
        # The user's rule name goes only into plain-text fields; markdown
        # help is static so a name can't inject formatting.
        return {
            "id": rule_id,
            "name": name[:255],
            "shortDescription": {"text": f"Custom rule: {name}"[:1024]},
            "fullDescription": {
                "text": "A custom rule from .secretshield-rules.toml matched."
            },
            "helpUri": HELP_URI,
            "help": {
                "text": _CUSTOM_REMEDIATION,
                "markdown": f"**Custom rule**\n\n{_CUSTOM_REMEDIATION}",
            },
            "defaultConfiguration": {"level": _CUSTOM_LEVEL},
            "properties": {
                "tags": ["security", "secret", "custom"],
                "precision": _CUSTOM_PRECISION,
                "security-severity": _CUSTOM_SEVERITY,
            },
        }


# --- Locations ----------------------------------------------------------------


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _position(text: str, offset: int) -> tuple[int, int]:
    """1-based (line, UTF-16 column) of `offset`, lines split on "\\n" exactly
    like the scanner's own line numbering."""
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset) + 1
    return line, _utf16_len(text[line_start:offset]) + 1


def compute_region(text: str, start: int, end: int) -> tuple[int, int, int, int]:
    """(startLine, startColumn, endLine, endColumn) for the span [start, end).

    `endColumn` is exclusive, as SARIF defines it. Only offsets are used;
    the matched text itself is never read.
    """
    start_line, start_col = _position(text, start)
    end_line, end_col = _position(text, max(start, end))
    return start_line, start_col, end_line, end_col


def artifact_uri(path: str) -> str:
    """Convert a scan display path into a SARIF artifact URI.

    Relative paths become repo-relative, forward-slash, percent-encoded
    URI references (what GitHub expects). Absolute paths -- a scan target
    outside the working directory -- become ``file:`` URIs. Encoding goes
    through the raw filesystem bytes so odd file names (spaces, ``#``,
    ``%``, non-UTF-8 bytes) always yield a valid URI.
    """
    p = Path(path)
    if p.is_absolute():
        try:
            return p.as_uri()
        except ValueError:
            pass
    posix = path.replace("\\", "/")
    while posix.startswith("./"):
        posix = posix[2:]
    return quote_from_bytes(os.fsencode(posix), safe="/")


# --- Report -------------------------------------------------------------------


def _message(kind: str) -> str:
    spec = _BUILTIN_RULES.get(kind)
    if spec is not None:
        subject = f"Potential secret detected: {spec.label}."
    else:
        subject = f'Potential secret detected by custom rule "{kind}".'
    # First sentence stands alone: GitHub shows only it when space is tight.
    return f"{subject} Rotate the credential and remove it from source code."


def build_sarif(
    findings: Iterable[SarifFinding],
    *,
    custom_rule_names: Sequence[str] = (),
    files_scanned: int | None = None,
    ignored_by_baseline: int = 0,
) -> dict:
    """Build a SARIF 2.1.0 log (as a plain dict) for the given findings.

    Results are sorted by (file, line, column, rule) so repeated scans of
    the same tree produce identical output regardless of filesystem order.
    """
    table = _RuleTable()
    for name in custom_rule_names:
        if name not in _BUILTIN_RULES:
            table.ensure_custom(name)

    ordered = sorted(
        findings,
        key=lambda f: (f.file, f.start_line, f.start_column, f.end_line, f.end_column, f.kind),
    )

    results = []
    for f in ordered:
        if f.kind not in _BUILTIN_RULES:
            table.ensure_custom(f.kind)
        results.append(
            {
                "ruleId": table.id_of(f.kind),
                "ruleIndex": table.index_of(f.kind),
                "level": table.level_of(f.kind),
                "message": {"text": _message(f.kind)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri(f.file)},
                            "region": {
                                "startLine": f.start_line,
                                "startColumn": f.start_column,
                                "endLine": f.end_line,
                                "endColumn": f.end_column,
                            },
                        }
                    }
                ],
            }
        )

    invocation: dict = {"executionSuccessful": True}
    props: dict = {}
    if files_scanned is not None:
        props["filesScanned"] = files_scanned
    if ignored_by_baseline:
        props["ignoredByBaseline"] = ignored_by_baseline
    if props:
        invocation["properties"] = props

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": table.rules,
                    }
                },
                "columnKind": COLUMN_KIND,
                "invocations": [invocation],
                "results": results,
            }
        ],
    }


def dumps(log: dict) -> str:
    """Serialize a SARIF log. ASCII-only output (non-ASCII is \\u-escaped), so
    it is safe to print to any terminal encoding and write as UTF-8."""
    return json.dumps(log, indent=2, ensure_ascii=True) + "\n"
