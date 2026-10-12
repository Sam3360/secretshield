"""
Provider guidance for the Secret Rotation Assistant.

Everything in this module is static data. SecretShield never contacts any
of these URLs itself: it prints them and, only if you confirm, opens one
in your own browser. No secret value is ever part of a URL or a message
built here.

Every URL below was checked against the provider's own documentation
(see USAGE.md, "Secret rotation assistant"). Where a provider does not
publish a stable link to a particular settings page, the steps describe
the menu path from the provider's documentation instead of guessing a
URL.

A credential is only attributed to a provider when its *format* matches
that provider's documented format -- never because of a variable name or
a hunch. Everything else gets the generic workflow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .. import patterns


@dataclass(frozen=True)
class Link:
    label: str
    url: str


@dataclass(frozen=True)
class Guide:
    """What to tell the user about one detected credential."""

    provider: str  # "GitHub", or "Unknown provider"
    credential: str  # "personal access token (classic)"
    identified: bool  # True only when matched by a known provider format
    manage: Link | None  # the provider's credential-management page
    docs: tuple[Link, ...]
    steps: tuple[str, ...]
    notes: tuple[str, ...] = ()
    # False only where the provider itself documents the credential as
    # safe to expose (Stripe publishable keys).
    needs_rotation: bool = True


# --- Official links ------------------------------------------------------------

AWS_CONSOLE = Link("AWS IAM console", "https://console.aws.amazon.com/iam/")
AWS_UPDATE_KEYS = Link(
    "AWS: Update access keys",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id-credentials-access-keys-update.html",
)
AWS_EXPOSED_KEY = Link(
    "AWS Security Blog: What to do if you inadvertently expose an AWS access key",
    "https://aws.amazon.com/blogs/security/what-to-do-if-you-inadvertently-expose-an-aws-access-key/",
)

GITHUB_CREDENTIAL_TYPES = Link(
    "GitHub: Credential types reference",
    "https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types",
)
GITHUB_DELETE_PAT = Link(
    "GitHub: Deleting a personal access token",
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#deleting-a-personal-access-token",
)
GITHUB_OAUTH_APPS = Link(
    "GitHub: Reviewing your authorized OAuth apps",
    "https://docs.github.com/en/apps/oauth-apps/using-oauth-apps/reviewing-your-authorized-oauth-apps",
)
GITHUB_APP_AUTH = Link(
    "GitHub: Reviewing and revoking authorization of GitHub Apps",
    "https://docs.github.com/en/apps/using-github-apps/reviewing-and-revoking-authorization-of-github-apps",
)
GITHUB_TOKEN_EXPIRATION = Link(
    "GitHub: Token expiration and revocation",
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation",
)

OPENAI_KEYS = Link("OpenAI API keys page", "https://platform.openai.com/api-keys")
OPENAI_FIND_KEY = Link(
    "OpenAI Help: Where do I find my OpenAI API key?",
    "https://help.openai.com/en/articles/4936850-where-do-i-find-my-openai-api-key",
)
OPENAI_KEY_SAFETY = Link(
    "OpenAI Help: Best practices for API key safety",
    "https://help.openai.com/en/articles/5112595",
)

SLACK_APPS = Link("Slack app management", "https://api.slack.com/apps")
SLACK_AUTH_REVOKE = Link(
    "Slack: auth.revoke method", "https://docs.slack.dev/reference/methods/auth.revoke"
)
SLACK_ROTATION = Link(
    "Slack: Using token rotation", "https://docs.slack.dev/authentication/using-token-rotation"
)

STRIPE_KEYS_PAGE = Link("Stripe Dashboard: API keys", "https://dashboard.stripe.com/apikeys")
STRIPE_KEYS_DOC = Link("Stripe: API keys", "https://docs.stripe.com/keys")
STRIPE_BEST_PRACTICES = Link(
    "Stripe: Best practices for managing secret API keys",
    "https://docs.stripe.com/keys-best-practices",
)
STRIPE_COMPROMISED = Link(
    "Stripe Support: Protecting against compromised API keys",
    "https://support.stripe.com/questions/protecting-against-compromised-api-keys",
)

GOOGLE_CREDENTIALS = Link(
    "Google Cloud console: Credentials", "https://console.cloud.google.com/apis/credentials"
)
GOOGLE_API_KEYS = Link(
    "Google Cloud: Manage API keys",
    "https://docs.cloud.google.com/docs/authentication/api-keys",
)
FIREBASE_API_KEYS = Link(
    "Firebase: Learn about and manage API keys",
    "https://firebase.google.com/docs/projects/api-keys",
)

# Only relevant when a copy of the credential is found in Git history.
HISTORY_GUIDE = Link(
    "GitHub: Removing sensitive data from a repository (applies if your repo is on GitHub)",
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
)

ALL_LINKS: tuple[Link, ...] = (
    AWS_CONSOLE, AWS_UPDATE_KEYS, AWS_EXPOSED_KEY,
    GITHUB_CREDENTIAL_TYPES, GITHUB_DELETE_PAT, GITHUB_OAUTH_APPS,
    GITHUB_APP_AUTH, GITHUB_TOKEN_EXPIRATION,
    OPENAI_KEYS, OPENAI_FIND_KEY, OPENAI_KEY_SAFETY,
    SLACK_APPS, SLACK_AUTH_REVOKE, SLACK_ROTATION,
    STRIPE_KEYS_PAGE, STRIPE_KEYS_DOC, STRIPE_BEST_PRACTICES, STRIPE_COMPROMISED,
    GOOGLE_CREDENTIALS, GOOGLE_API_KEYS, FIREBASE_API_KEYS,
    HISTORY_GUIDE,
)  # fmt: skip


# --- Format checks and value helpers ---------------------------------------------

_BUILTIN_REGEX = {name: regex for name, regex in patterns.PATTERNS}


def _matches_builtin_format(kind: str, value: str) -> bool:
    """True if `value` really has the documented shape for built-in `kind`.

    Guards against a custom rule that happens to be named like a built-in
    kind: such a match is treated as an unknown provider rather than
    being attributed to one.
    """
    regex = _BUILTIN_REGEX.get(kind)
    return bool(regex and regex.search(value))


def core_value(kind: str, value: str) -> str:
    """The part of a match that is the credential itself.

    A few detectors match surrounding text too (``aws_secret_key = "..."``
    or ``Bearer ...``). Searching for leftover copies needs the credential
    alone.
    """
    if kind == "aws_secret_access_key":
        runs = re.findall(r"[A-Za-z0-9/+=]{40}", value)
        return runs[-1] if runs else value
    if kind == "bearer_token":
        return re.sub(r"(?is)^bearer\s+", "", value)
    return value


def history_needle(core: str) -> str:
    """A single line to look for when scanning Git history line by line.

    Multi-line values (private keys) can't be matched line by line, so the
    longest body line stands in for the whole block.
    """
    if "\n" not in core:
        return core
    body = [ln.strip() for ln in core.splitlines() if ln.strip() and not ln.startswith("-----")]
    return max(body, key=len) if body else core.strip()


# --- Identification ------------------------------------------------------------

_GITHUB_PREFIXES = (
    ("github_pat_", "fine-grained personal access token"),
    ("ghp_", "personal access token (classic)"),
    ("gho_", "OAuth app access token"),
    ("ghu_", "GitHub App user access token"),
    ("ghr_", "GitHub App refresh token"),
    ("ghs_", "GitHub App installation access token"),
)

_PAT_NOTE = (
    "GitHub documents that personal access tokens and OAuth app tokens pushed to a "
    "public repository or gist are revoked automatically. Check your token list "
    "rather than assuming that happened."
)


def _aws(kind: str) -> Guide:
    notes = ()
    if kind == "aws_secret_access_key":
        notes = (
            "The access key ID that belongs with this secret may appear elsewhere in "
            "your code. Rotating the key pair replaces both.",
        )
    return Guide(
        provider="AWS",
        credential=(
            "secret access key (part of an IAM access key pair)"
            if kind == "aws_secret_access_key"
            else "IAM access key"
        ),
        identified=True,
        manage=AWS_CONSOLE,
        docs=(AWS_UPDATE_KEYS, AWS_EXPOSED_KEY),
        steps=(
            "In the IAM console choose Users, open the user that owns the key, and go to "
            "the Security credentials tab.",
            "Create a replacement access key and store it outside your source code.",
            "Deactivate the exposed access key, confirm nothing legitimate still depends "
            "on it, then delete it. AWS recommends deactivating before deleting.",
            "Review your AWS account for activity you do not recognize. The AWS guide "
            "below explains how.",
        ),
        notes=notes,
    )


def _github(value: str) -> Guide:
    label = "token"
    for prefix, name in _GITHUB_PREFIXES:
        if value.startswith(prefix):
            label = name
            break

    common_replace = (
        "Create a replacement with the minimum scopes or permissions it needs, ideally "
        "with an expiration, and store it outside your source code."
    )

    if label.startswith(("personal access token", "fine-grained")):
        tab = "Fine-grained tokens" if label.startswith("fine-grained") else "Tokens (classic)"
        return Guide(
            provider="GitHub",
            credential=label,
            identified=True,
            manage=None,
            docs=(GITHUB_DELETE_PAT, GITHUB_TOKEN_EXPIRATION),
            steps=(
                "On GitHub click your profile picture, then Settings, then Developer settings.",
                f"Under Personal access tokens open {tab} and click Delete next to the "
                "exposed token.",
                common_replace,
            ),
            notes=(_PAT_NOTE,),
        )
    if label == "OAuth app access token":
        return Guide(
            provider="GitHub",
            credential=label,
            identified=True,
            manage=None,
            docs=(GITHUB_OAUTH_APPS, GITHUB_CREDENTIAL_TYPES),
            steps=(
                "In your personal account settings, revoke your authorization of the OAuth "
                "app that issued this token. Revoking the authorization revokes every token "
                "tied to that app.",
                "Re-authorize the app to get a new token if you still need it, and store it "
                "outside your source code.",
            ),
            notes=(_PAT_NOTE,),
        )
    if label in ("GitHub App user access token", "GitHub App refresh token"):
        life = "8 hours" if label.endswith("user access token") else "6 months"
        return Guide(
            provider="GitHub",
            credential=label,
            identified=True,
            manage=None,
            docs=(GITHUB_APP_AUTH, GITHUB_CREDENTIAL_TYPES),
            steps=(
                "In your personal account settings, revoke your authorization of the "
                "GitHub App. GitHub notes that this revokes the authorization for all "
                "organizations, not just one.",
                "Authorize the app again to get new tokens and store them outside your "
                "source code.",
            ),
            notes=(f"By default this kind of token expires on its own after {life}.",),
        )
    if label == "GitHub App installation access token":
        return Guide(
            provider="GitHub",
            credential=label,
            identified=True,
            manage=None,
            docs=(GITHUB_CREDENTIAL_TYPES,),
            steps=(
                "Installation access tokens expire automatically after one hour. The app's "
                "owner can revoke one sooner through the REST API, or an organization owner "
                "can uninstall the app.",
                "Make sure your code requests fresh installation tokens instead of "
                "hardcoding one.",
            ),
        )
    return Guide(
        provider="GitHub",
        credential="token",
        identified=True,
        manage=None,
        docs=(GITHUB_CREDENTIAL_TYPES,),
        steps=(
            "The GitHub credential types reference below lists how each kind of GitHub "
            "token is revoked. Find the entry that matches this token's prefix.",
            common_replace,
        ),
    )


def _openai() -> Guide:
    return Guide(
        provider="OpenAI",
        credential="API key",
        identified=True,
        manage=OPENAI_KEYS,
        docs=(OPENAI_FIND_KEY, OPENAI_KEY_SAFETY),
        steps=(
            "On the API keys page, create a replacement key and store it outside your "
            "source code.",
            "Update your applications to use the replacement.",
            "Delete the exposed key with the trash can icon next to it. OpenAI states "
            "that deleted keys cannot be used.",
        ),
        notes=(
            "This was matched by the sk- key format. If the key is not from OpenAI, treat "
            "it as an unknown provider and use that provider's own process.",
        ),
    )


def _slack() -> Guide:
    return Guide(
        provider="Slack",
        credential="token",
        identified=True,
        manage=SLACK_APPS,
        docs=(SLACK_AUTH_REVOKE, SLACK_ROTATION),
        steps=(
            "Open Slack's app management page and find the app this token belongs to.",
            "Invalidate the token. Slack documents the auth.revoke method for revoking a "
            "single token (a bot token's revocation does not uninstall the app), and "
            "apps.uninstall, which usually revokes the installation's authorization so the "
            "app must be reinstalled. Use the Slack docs below; SecretShield will not "
            "send the token to Slack for you.",
            "Reinstall or re-authorize to obtain a new token, and store it outside your "
            "source code. Slack also offers token rotation for apps that support it.",
        ),
    )


def _stripe(value: str) -> Guide:
    if value.startswith("pk_"):
        return Guide(
            provider="Stripe",
            credential="publishable key",
            identified=True,
            manage=STRIPE_KEYS_PAGE,
            docs=(STRIPE_KEYS_DOC,),
            steps=(),
            notes=(
                "Stripe documents publishable keys as safe to expose: you can include one "
                "in front-end code or distributed apps, and Stripe does not allow "
                "publishable keys to be expired. No revocation is needed.",
                "If you were looking for a secret key, check whether an sk_ or rk_ key "
                "is stored nearby.",
            ),
            needs_rotation=False,
        )
    test_mode = "_test_" in value
    notes = (
        "A test-mode key only reaches sandbox data (Stripe keeps live and test objects "
        "separate), so the impact is lower. Rotate it anyway if it was exposed publicly.",
    ) if test_mode else ()
    return Guide(
        provider="Stripe",
        credential=(
            ("restricted" if value.startswith("rk_") else "secret")
            + " API key"
            + (" (test mode)" if test_mode else "")
        ),
        identified=True,
        manage=STRIPE_KEYS_PAGE,
        docs=(STRIPE_KEYS_DOC, STRIPE_BEST_PRACTICES, STRIPE_COMPROMISED),
        steps=(
            "Open the API keys page in the Stripe Dashboard.",
            "Open the overflow menu for the exposed key and choose Rotate key. Set the "
            "expiration to Now: Stripe deletes the old key immediately, whereas a later "
            "expiration keeps the exposed key working until then (up to 7 days).",
            "Copy the replacement key and store it outside your source code, in a secrets "
            "vault or an environment variable.",
            "Review the key's request logs in the Dashboard for activity you do not "
            "recognize.",
        ),
        notes=notes,
    )


def _google() -> Guide:
    return Guide(
        provider="Google",
        credential="API key",
        identified=True,
        manage=GOOGLE_CREDENTIALS,
        docs=(GOOGLE_API_KEYS, FIREBASE_API_KEYS),
        steps=(
            "In the Google Cloud console open APIs & Services, then Credentials, and "
            "find the exposed key in the API keys list.",
            "Create a replacement key with API restrictions and application restrictions "
            "(Google recommends both) and store it outside your source code.",
            "Delete the exposed key. A deleted key can no longer be used, so anything "
            "still using it will fail until you update it.",
        ),
        notes=(
            "Firebase web API keys follow different rules. If this is a Firebase API key, "
            "the Firebase guide below explains when it is safe to include in code.",
        ),
    )


_GENERIC_STEPS = (
    "Work out who issued this credential. The variable name, the file it was in and the "
    "services your project talks to are the best clues; SecretShield cannot tell.",
    "Open that provider's credential-management page (API keys, tokens or access "
    "settings) and revoke, delete or regenerate it there. Deleting it from your code "
    "does not do this.",
    "Create a replacement with the least privilege it needs and keep it outside your "
    "source code, in an environment variable or a secrets manager.",
    "Review the provider's access or audit logs for use of the old credential since it "
    "was exposed.",
)

_PRIVATE_KEY_STEPS = (
    "Generate a new key pair. Do not reuse the exposed one.",
    "Replace the public key everywhere the old one was trusted: authorized_keys on "
    "servers, SSH and deploy keys on code hosts, and certificates (reissue them).",
    "Retire the exposed private key so nothing trusts it any more.",
    "Review access logs on the systems that trusted the old key.",
)


def _generic(kind: str) -> Guide:
    notes: tuple[str, ...] = ()
    steps = _GENERIC_STEPS
    credential = "credential"
    if kind == "jwt":
        credential = "JWT"
        notes = (
            "A JWT is a signed token. Revoking it, or ending the session, with the service "
            "that issued it is the fix; if it is long-lived, the signing secret may need "
            "rotating too.",
        )
    elif kind == "bearer_token":
        credential = "bearer token"
        notes = ("A bearer token is whatever the service issued you. Revoke it with that service.",)
    elif kind == "private_key_block":
        credential = "private key"
        steps = _PRIVATE_KEY_STEPS
    elif kind == "generic_labeled_secret":
        credential = "labeled credential"
        notes = (
            "If this is a password, change it at the service it belongs to, and anywhere "
            "else you reused it.",
        )
    elif kind == "high_entropy":
        credential = "high-entropy string"
        notes = (
            "SecretShield could not tell what this is. It may not be a credential at all; "
            "if it is not, there is nothing to revoke (exclude the path, or accept it "
            "with `secretshield scan . --baseline`).",
        )
    else:
        notes = ("This was matched by a custom rule, so SecretShield does not know the provider.",)
    return Guide(
        provider="Unknown provider",
        credential=credential,
        identified=False,
        manage=None,
        docs=(),
        steps=steps,
        notes=notes,
    )


def identify(kind: str, value: str) -> Guide:
    """Return the guidance for a detected credential.

    Provider-specific guidance is returned only when `kind` is a built-in
    provider detector AND `value` actually has that provider's format.
    Anything else gets the generic workflow.
    """
    if kind in ("aws_access_key_id", "aws_secret_access_key") and _matches_builtin_format(kind, value):
        return _aws(kind)
    if kind == "github_token" and _matches_builtin_format(kind, value):
        return _github(value)
    if kind == "openai_api_key" and _matches_builtin_format(kind, value):
        return _openai()
    if kind == "slack_token" and _matches_builtin_format(kind, value):
        return _slack()
    if kind == "stripe_key" and _matches_builtin_format(kind, value):
        return _stripe(value)
    if kind == "google_api_key" and _matches_builtin_format(kind, value):
        return _google()
    return _generic(kind)
