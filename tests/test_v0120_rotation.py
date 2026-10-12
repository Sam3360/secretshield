"""
Tests for v0.12.0: the Secret Rotation Assistant (`scan --rotate`).

All secrets are fake. Nothing here contacts a provider, opens a real
browser, or needs a real credential; the browser and (where useful) the
Git-history search are mocked, and one test blocks sockets outright.
"""

from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import pytest

from secretshield.cli import main
from secretshield.detector import Match
from secretshield.rotation import identify, run_rotation
from secretshield.rotation import providers, workflow
from secretshield.rotation.workflow import (
    HistoryResult,
    _Scrubber,
    find_references,
    search_history,
)

GH_CLASSIC = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
GH_FINE = "github_pat_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"
GH_OAUTH = "gho_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"
GH_USER = "ghu_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"
GH_REFRESH = "ghr_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"
GH_INSTALL = "ghs_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"
AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
AWS_SECRET_LINE = 'aws_secret_access_key = "' + "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" + '"'
OPENAI = "sk-" + "abcdefghijklmnopqrstuvwxyz1234"
SLACK = "xoxb-" + "1234567890-abcdefghij"
STRIPE_LIVE = "sk_live_" + "abcdefghijklmnop1234"
STRIPE_RK_TEST = "rk_test_" + "abcdefghijklmnop1234"
STRIPE_PUB = "pk_test_" + "abcdefghijklmnop1234"
GOOGLE = "AIza" + "abcdefghij" * 3 + "12345"
ENTROPY = "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1"
CUSTOM = "MYAPP_" + "12345678901234567890123456789012"
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEs\n"
    "-----END RSA PRIVATE KEY-----"
)

ALLOWED_HOSTS = {
    "console.aws.amazon.com", "docs.aws.amazon.com", "aws.amazon.com",
    "docs.github.com",
    "platform.openai.com", "help.openai.com",
    "api.slack.com", "docs.slack.dev",
    "dashboard.stripe.com", "docs.stripe.com", "support.stripe.com",
    "console.cloud.google.com", "docs.cloud.google.com", "firebase.google.com",
}  # fmt: skip

OLD_GOOGLE_DOCS_HOST = "cloud.google.com"  # that path 404s now; docs moved


def _match(kind: str, value: str) -> Match:
    return Match(start=0, end=len(value), value=value, kind=kind)


def _all_guides() -> list[providers.Guide]:
    samples = [
        ("aws_access_key_id", AWS_KEY), ("aws_secret_access_key", AWS_SECRET_LINE),
        ("github_token", GH_CLASSIC), ("github_token", GH_FINE), ("github_token", GH_OAUTH),
        ("github_token", GH_USER), ("github_token", GH_REFRESH), ("github_token", GH_INSTALL),
        ("openai_api_key", OPENAI), ("slack_token", SLACK),
        ("stripe_key", STRIPE_LIVE), ("stripe_key", STRIPE_RK_TEST), ("stripe_key", STRIPE_PUB),
        ("google_api_key", GOOGLE),
        ("jwt", "eyJhbGciOi.eyJzdWIiOiIx.abcdefghij"), ("bearer_token", "Bearer abcdefghijklmnop"),
        ("private_key_block", PRIVATE_KEY), ("generic_labeled_secret", "hunter2hunter2"),
        ("high_entropy", ENTROPY), ("My Custom Rule", CUSTOM),
    ]  # fmt: skip
    return [identify(k, v) for k, v in samples]


# --- Provider identification -----------------------------------------------------


@pytest.mark.parametrize(
    "kind, value, provider, credential_fragment",
    [
        ("aws_access_key_id", AWS_KEY, "AWS", "IAM access key"),
        ("aws_secret_access_key", AWS_SECRET_LINE, "AWS", "secret access key"),
        ("github_token", GH_CLASSIC, "GitHub", "personal access token (classic)"),
        ("github_token", GH_FINE, "GitHub", "fine-grained"),
        ("github_token", GH_OAUTH, "GitHub", "OAuth app"),
        ("github_token", GH_USER, "GitHub", "user access token"),
        ("github_token", GH_REFRESH, "GitHub", "refresh token"),
        ("github_token", GH_INSTALL, "GitHub", "installation"),
        ("openai_api_key", OPENAI, "OpenAI", "API key"),
        ("slack_token", SLACK, "Slack", "token"),
        ("stripe_key", STRIPE_LIVE, "Stripe", "secret API key"),
        ("stripe_key", STRIPE_RK_TEST, "Stripe", "restricted API key (test mode)"),
        ("stripe_key", STRIPE_PUB, "Stripe", "publishable"),
        ("google_api_key", GOOGLE, "Google", "API key"),
    ],
)
def test_known_providers_are_identified(kind, value, provider, credential_fragment):
    guide = identify(kind, value)
    assert guide.identified is True
    assert guide.provider == provider
    assert credential_fragment in guide.credential


@pytest.mark.parametrize(
    "kind, value",
    [
        ("jwt", "eyJhbGciOi.eyJzdWIiOiIx.abcdefghij"),
        ("bearer_token", "Bearer abcdefghijklmnop"),
        ("private_key_block", PRIVATE_KEY),
        ("generic_labeled_secret", "hunter2hunter2"),
        ("high_entropy", ENTROPY),
        ("My Custom Rule", CUSTOM),
    ],
)
def test_unknown_providers_get_the_generic_workflow(kind, value):
    guide = identify(kind, value)
    assert guide.identified is False
    assert guide.provider == "Unknown provider"
    assert guide.manage is None
    assert guide.docs == ()  # never a guessed link
    assert guide.steps
    assert guide.needs_rotation is True


def test_a_custom_rule_named_like_a_builtin_is_not_attributed_to_a_provider():
    # A custom rule called "github_token" matching something that is not a
    # GitHub token must not get GitHub's guidance.
    assert identify("github_token", "totally-not-a-github-token-1234").identified is False
    assert identify("aws_access_key_id", "nope").identified is False
    assert identify("stripe_key", ENTROPY).identified is False


def test_private_key_guidance_is_key_specific():
    guide = identify("private_key_block", PRIVATE_KEY)
    assert any("new key pair" in step for step in guide.steps)


def test_stripe_publishable_key_needs_no_revocation():
    guide = identify("stripe_key", STRIPE_PUB)
    assert guide.needs_rotation is False
    assert guide.steps == ()
    assert any("safe to expose" in n for n in guide.notes)


def test_stripe_live_secret_key_says_to_rotate_with_expiration_now():
    guide = identify("stripe_key", STRIPE_LIVE)
    assert guide.needs_rotation is True
    assert any("expiration to Now" in s for s in guide.steps)


def test_github_has_no_unverified_direct_settings_link():
    for value in (GH_CLASSIC, GH_FINE, GH_OAUTH, GH_USER, GH_REFRESH, GH_INSTALL):
        guide = identify("github_token", value)
        assert guide.manage is None
        assert all(link.url.startswith("https://docs.github.com/") for link in guide.docs)


# --- Official links ----------------------------------------------------------------


def test_every_link_is_https_on_an_expected_provider_host():
    for link in providers.ALL_LINKS:
        parsed = urlparse(link.url)
        assert parsed.scheme == "https", link
        assert parsed.hostname in ALLOWED_HOSTS, link
        assert not any(ch.isspace() for ch in link.url), link
        assert parsed.hostname != OLD_GOOGLE_DOCS_HOST, link


def test_every_link_a_guide_can_return_is_in_the_registry():
    registered = set(providers.ALL_LINKS)
    for guide in _all_guides():
        for link in ([guide.manage] if guide.manage else []) + list(guide.docs):
            assert link in registered, link


@pytest.mark.parametrize(
    "kind, value, url",
    [
        ("aws_access_key_id", AWS_KEY, "https://console.aws.amazon.com/iam/"),
        ("openai_api_key", OPENAI, "https://platform.openai.com/api-keys"),
        ("slack_token", SLACK, "https://api.slack.com/apps"),
        ("stripe_key", STRIPE_LIVE, "https://dashboard.stripe.com/apikeys"),
        ("google_api_key", GOOGLE, "https://console.cloud.google.com/apis/credentials"),
    ],
)
def test_management_links_are_the_documented_ones(kind, value, url):
    assert identify(kind, value).manage.url == url


def test_google_docs_link_uses_the_current_docs_host():
    urls = [link.url for link in identify("google_api_key", GOOGLE).docs]
    assert "https://docs.cloud.google.com/docs/authentication/api-keys" in urls


def test_no_guide_contains_a_secret_value():
    values = [AWS_KEY, GH_CLASSIC, OPENAI, SLACK, STRIPE_LIVE, GOOGLE, ENTROPY, CUSTOM]
    texts = []
    for guide in _all_guides():
        texts += [guide.provider, guide.credential, *guide.steps, *guide.notes]
        texts += [f"{l.label} {l.url}" for l in guide.docs]
    blob = "\n".join(texts)
    for value in values:
        assert value not in blob


def test_core_value_and_history_needle():
    assert providers.core_value("bearer_token", "Bearer abcdefghijklmnop") == "abcdefghijklmnop"
    secret = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
    assert providers.core_value("aws_secret_access_key", AWS_SECRET_LINE) == secret
    assert providers.core_value("github_token", GH_CLASSIC) == GH_CLASSIC
    needle = providers.history_needle(PRIVATE_KEY)
    assert "\n" not in needle and not needle.startswith("-----")
    assert needle in PRIVATE_KEY


# --- Harness for the interactive workflow ----------------------------------------

DEFAULT_ANSWERS = {
    "Work on this credential": "y",
    "Open": "n",
    "Have you revoked": "y",
    "Run Auto-Fix": "n",
    "Check again": "n",
    "Search Git history": "n",
    "Would you like me to move": "y",
    "What environment variable": "",
}


class Session:
    def __init__(self, answers=None, on_prompt=None):
        self.answers = {**DEFAULT_ANSWERS, **(answers or {})}
        self.on_prompt = on_prompt
        self.output: list[str] = []
        self.prompts: list[str] = []

    def print(self, text: str = "") -> None:
        self.output.append(text)

    def input(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if self.on_prompt:
            self.on_prompt(prompt)
        for key, answer in self.answers.items():
            if key in prompt:
                return answer
        raise AssertionError(f"unexpected prompt: {prompt!r}")

    @property
    def text(self) -> str:
        return "\n".join(self.output + self.prompts)


@pytest.fixture
def interactive(monkeypatch):
    monkeypatch.setattr(workflow, "is_interactive", lambda: True)
    monkeypatch.setattr("secretshield.autofix.fixer.is_interactive", lambda: True)


def _sources(root: Path):
    def iterate():
        for path in sorted(root.rglob("*")):
            if path.is_file() and ".git" not in path.parts:
                yield str(path.relative_to(root)), path.read_text(encoding="utf-8", errors="ignore")

    return iterate


def _run(tmp_path, findings, session, *, iter_sources=None, **kwargs):
    return run_rotation(
        tmp_path,
        findings,
        iter_sources=iter_sources if iter_sources is not None else (lambda: []),
        print_func=session.print,
        input_func=session.input,
        open_url=kwargs.pop("open_url", lambda url: True),
        history_search=kwargs.pop("history_search", lambda core, root: HistoryResult()),
        **kwargs,
    )


# --- Workflow: guidance and honesty ------------------------------------------------


def test_nothing_to_rotate(tmp_path):
    s = Session()
    summary = _run(tmp_path, [], s)
    assert summary.exit_code == 0
    assert "nothing to rotate" in s.text


def test_guidance_separates_revoking_from_replacing_from_checking(tmp_path, interactive):
    s = Session()
    _run(tmp_path, [("app.py", 1, _match("github_token", GH_CLASSIC))], s)
    text = s.text
    assert "does not make it safe" in text
    assert "Step 1 of 3: revoke or rotate it with the provider" in text
    assert "Step 2 of 3: replace the old credential in your code" in text
    assert "Step 3 of 3: check for leftover copies" in text
    assert "only step that makes the old credential unusable" in text
    assert "separate from revoking" in text
    assert "Likely provider: GitHub" in text


def test_never_claims_revocation_it_cannot_verify(tmp_path, interactive):
    s = Session()
    summary = _run(tmp_path, [("app.py", 1, _match("openai_api_key", OPENAI))], s)
    text = s.text
    assert "reported by you (not verified by SecretShield)" in text
    assert "cannot verify revocation" in text
    for forbidden in ("has been revoked", "was revoked", "is now revoked", "successfully revoked",
                      "is secure", "has been secured", "now safe"):  # fmt: skip
        assert forbidden not in text.lower()
    assert summary.credentials[0].revoked_reported is True


def test_user_who_has_not_revoked_is_told_it_still_works(tmp_path, interactive):
    s = Session({"Have you revoked": "n"})
    summary = _run(tmp_path, [("app.py", 1, _match("github_token", GH_CLASSIC))], s)
    assert "the old credential still works" in s.text
    assert "Revocation: NOT done" in s.text
    assert summary.exit_code == 1


def test_skipping_a_credential_is_reported_and_unresolved(tmp_path, interactive):
    s = Session({"Work on this credential": "n"})
    summary = _run(tmp_path, [("app.py", 1, _match("github_token", GH_CLASSIC))], s)
    assert "stays usable" in s.text
    assert summary.exit_code == 1
    assert not any("Have you revoked" in p for p in s.prompts)


def test_fully_handled_credential_exits_zero(tmp_path, interactive):
    (tmp_path / "app.py").write_text("print('clean')\n")
    s = Session()
    summary = _run(
        tmp_path,
        [("app.py", 1, _match("github_token", GH_CLASSIC))],
        s,
        iter_sources=_sources(tmp_path),
    )
    assert summary.exit_code == 0
    assert "no copy of the old value found" in s.text


def test_publishable_stripe_key_asks_nothing_and_exits_zero(tmp_path, interactive):
    s = Session()
    summary = _run(tmp_path, [("a.js", 1, _match("stripe_key", STRIPE_PUB))], s)
    assert s.prompts == []
    assert summary.exit_code == 0
    assert "Nothing to revoke" in s.text
    assert "does not make it safe" not in s.text


def test_unknown_provider_is_not_guessed_and_has_no_links(tmp_path, interactive):
    s = Session()
    _run(tmp_path, [("a.py", 1, _match("high_entropy", ENTROPY))], s)
    assert "not identified" in s.text and "will not guess" in s.text
    assert "https://" not in s.text
    assert not any("Open" in p for p in s.prompts)


def test_same_value_in_several_files_is_one_credential(tmp_path, interactive):
    findings = [
        ("a.py", 3, _match("github_token", GH_CLASSIC)),
        ("b.py", 7, _match("github_token", GH_CLASSIC)),
        ("c.py", 9, _match("high_entropy", GH_CLASSIC)),
    ]
    s = Session()
    summary = _run(tmp_path, findings, s)
    assert len(summary.credentials) == 1
    assert "a.py:3, b.py:7, c.py:9" in s.text
    assert summary.credentials[0].guide.identified is True


def test_non_interactive_terminal_does_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(workflow, "is_interactive", lambda: False)
    s = Session()
    summary = _run(tmp_path, [("a.py", 1, _match("github_token", GH_CLASSIC))], s)
    assert summary.exit_code == 1
    assert "requires an interactive terminal" in s.text
    assert s.prompts == []


# --- Workflow: browser ---------------------------------------------------------------


def test_browser_opens_only_after_confirmation_and_only_the_provider_url(tmp_path, interactive):
    opened = []
    s = Session({"Open": "y"})
    _run(tmp_path, [("a.py", 1, _match("openai_api_key", OPENAI))], s,
         open_url=lambda url: opened.append(url) or True)  # fmt: skip
    assert opened == ["https://platform.openai.com/api-keys"]


def test_browser_is_not_opened_when_declined(tmp_path, interactive):
    opened = []
    _run(tmp_path, [("a.py", 1, _match("openai_api_key", OPENAI))], Session({"Open": "n"}),
         open_url=lambda url: opened.append(url) or True)  # fmt: skip
    assert opened == []


@pytest.mark.parametrize("behaviour", ["returns_false", "raises"])
def test_browser_failure_is_handled(tmp_path, interactive, behaviour):
    def broken(url):
        if behaviour == "raises":
            raise RuntimeError(f"boom {OPENAI}")
        return False

    s = Session({"Open": "y"})
    summary = _run(tmp_path, [("a.py", 1, _match("openai_api_key", OPENAI))], s, open_url=broken)
    assert "Could not open a browser" in s.text
    assert OPENAI not in s.text
    assert summary.errored is False


def test_github_offers_its_docs_page_since_no_direct_settings_url_is_verified(tmp_path, interactive):
    opened = []
    _run(tmp_path, [("a.py", 1, _match("github_token", GH_CLASSIC))], Session({"Open": "y"}),
         open_url=lambda url: opened.append(url) or True)  # fmt: skip
    assert opened and opened[0].startswith("https://docs.github.com/")


# --- Workflow: privacy ---------------------------------------------------------------


@pytest.mark.parametrize(
    "kind, value",
    [
        ("aws_access_key_id", AWS_KEY), ("github_token", GH_CLASSIC), ("openai_api_key", OPENAI),
        ("slack_token", SLACK), ("stripe_key", STRIPE_LIVE), ("google_api_key", GOOGLE),
        ("high_entropy", ENTROPY), ("My Custom Rule", CUSTOM), ("private_key_block", PRIVATE_KEY),
    ],
)  # fmt: skip
def test_secret_values_never_appear_in_output_or_prompts(tmp_path, interactive, kind, value):
    s = Session({"Run Auto-Fix": "y", "Search Git history": "y"})
    (tmp_path / "f.txt").write_text(f"x = '{value}'\n")
    _run(
        tmp_path,
        [("f.txt", 1, _match(kind, value))],
        s,
        iter_sources=_sources(tmp_path),
        history_search=lambda core, root: HistoryResult(commits=["a" * 40]),
    )
    blob = s.text
    assert value not in blob
    for line in value.splitlines():
        if len(line) >= 12:
            assert line not in blob


def test_messages_never_contain_values_even_with_the_scrubber_disabled(
    tmp_path, interactive, monkeypatch
):
    """The scrubber is only a backstop: the messages themselves must be clean."""
    monkeypatch.setattr(_Scrubber, "__call__", lambda self, text: text)
    cases = [("github_token", GH_CLASSIC), ("aws_secret_access_key", AWS_SECRET_LINE),
             ("bearer_token", "Bearer abcdefghijklmnop"), ("private_key_block", PRIVATE_KEY),
             ("high_entropy", ENTROPY)]  # fmt: skip
    for kind, value in cases:
        s = Session({"Run Auto-Fix": "n", "Search Git history": "y"})
        (tmp_path / "f.txt").write_text(value + "\n")
        _run(tmp_path, [("f.txt", 1, _match(kind, value))], s, iter_sources=_sources(tmp_path),
             history_search=lambda core, root: HistoryResult(commits=["a" * 40]))  # fmt: skip
        core = providers.core_value(kind, value)
        assert core not in s.text, kind
        assert value not in s.text, kind


def test_scrubber_masks_values_even_inside_other_text():
    scrub = _Scrubber()
    scrub.add(GH_CLASSIC, PRIVATE_KEY)
    assert GH_CLASSIC not in scrub(f"oops {GH_CLASSIC} leaked")
    assert "********" in scrub(f"oops {GH_CLASSIC} leaked")
    assert "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu" not in scrub(
        "line: MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu"
    )


def test_scrubber_leaves_very_short_values_alone():
    scrub = _Scrubber()
    scrub.add("abc")
    assert scrub("abc def") == "abc def"


def test_unexpected_error_reports_only_the_exception_type(tmp_path, interactive):
    def explode(core, root):
        raise RuntimeError(f"history failed for {GH_CLASSIC}")

    s = Session({"Search Git history": "y"})
    (tmp_path / ".git").mkdir()
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    summary = _run(tmp_path, [("a.py", 1, _match("github_token", GH_CLASSIC))], s,
                   history_search=explode)  # fmt: skip
    assert summary.errored is True
    assert summary.exit_code == 2
    assert "RuntimeError" in s.text
    assert GH_CLASSIC not in s.text
    assert "history failed" not in s.text


def test_no_network_is_ever_used(tmp_path, interactive, monkeypatch):
    def blocked(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    (tmp_path / "app.py").write_text(f'T = "{GH_CLASSIC}"\n')
    s = Session({"Run Auto-Fix": "y", "Open": "y"})
    summary = _run(tmp_path, [("app.py", 2, _match("github_token", GH_CLASSIC))], s,
                   iter_sources=_sources(tmp_path))  # fmt: skip
    assert summary.errored is False


# --- Workflow: cancellation and interruption -------------------------------------------


@pytest.mark.parametrize("exc", [KeyboardInterrupt, EOFError])
def test_cancellation_is_graceful_and_changes_nothing(tmp_path, interactive, exc):
    source = f'T = "{GH_CLASSIC}"\n'
    (tmp_path / "app.py").write_text(source)

    def interrupt(prompt):
        if "Run Auto-Fix" in prompt:
            raise exc()

    s = Session(on_prompt=interrupt)
    summary = _run(tmp_path, [("app.py", 1, _match("github_token", GH_CLASSIC))], s,
                   iter_sources=_sources(tmp_path))  # fmt: skip
    assert summary.cancelled is True
    assert summary.exit_code == 1
    assert "cancelled. Nothing further was changed" in s.text
    assert "stopped early" in s.text
    assert (tmp_path / "app.py").read_text() == source
    assert not (tmp_path / ".env").exists()
    assert GH_CLASSIC not in s.text


def test_cancel_at_first_prompt_still_prints_a_summary(tmp_path, interactive):
    s = Session(on_prompt=lambda p: (_ for _ in ()).throw(KeyboardInterrupt()))
    summary = _run(tmp_path, [("a.py", 1, _match("github_token", GH_CLASSIC))], s)
    assert summary.cancelled and summary.exit_code == 1
    assert "Revocation: not reached" in s.text


# --- Workflow: Auto-Fix integration and leftover references ------------------------------


def test_auto_fix_is_reused_to_replace_the_reference(tmp_path, interactive):
    (tmp_path / "app.py").write_text(f'import os\nGH_TOKEN = "{GH_CLASSIC}"\n')
    s = Session({"Run Auto-Fix": "y"})
    summary = _run(tmp_path, [("app.py", 2, _match("github_token", GH_CLASSIC))], s,
                   iter_sources=_sources(tmp_path))  # fmt: skip
    new_source = (tmp_path / "app.py").read_text()
    assert GH_CLASSIC not in new_source
    assert "os.getenv" in new_source
    assert (tmp_path / ".env").read_text().startswith("GH_TOKEN=")
    assert summary.credentials[0].replaced == 1
    assert "Auto-Fix Summary" in s.text  # the existing Auto-Fix flow ran
    assert "put the NEW credential in .env" in s.text


def test_old_value_left_in_dotenv_is_flagged_and_blocks_a_clean_exit(tmp_path, interactive):
    (tmp_path / "app.py").write_text(f'import os\nGH_TOKEN = "{GH_CLASSIC}"\n')
    s = Session({"Run Auto-Fix": "y"})
    summary = _run(tmp_path, [("app.py", 2, _match("github_token", GH_CLASSIC))], s,
                   iter_sources=_sources(tmp_path))  # fmt: skip
    assert "still present in .env:1" in s.text
    assert "A .env file still holds it" in s.text
    assert summary.credentials[0].refs_remaining == 1
    assert summary.exit_code == 1


def test_recheck_after_the_user_updates_dotenv_reaches_exit_zero(tmp_path, interactive):
    (tmp_path / "app.py").write_text(f'import os\nGH_TOKEN = "{GH_CLASSIC}"\n')

    def user_edits_env(prompt):
        if "Check again" in prompt:
            (tmp_path / ".env").write_text("GH_TOKEN=a-brand-new-value-from-the-provider\n")

    s = Session({"Run Auto-Fix": "y", "Check again": "y"}, on_prompt=user_edits_env)
    summary = _run(tmp_path, [("app.py", 2, _match("github_token", GH_CLASSIC))], s,
                   iter_sources=_sources(tmp_path))  # fmt: skip
    assert summary.credentials[0].refs_remaining == 0
    assert summary.exit_code == 0
    assert "was not found in the scanned files" in s.text


def test_declining_auto_fix_modifies_nothing(tmp_path, interactive):
    source = f'import os\nGH_TOKEN = "{GH_CLASSIC}"\n'
    (tmp_path / "app.py").write_text(source)
    _run(tmp_path, [("app.py", 2, _match("github_token", GH_CLASSIC))], Session({"Run Auto-Fix": "n"}),
         iter_sources=_sources(tmp_path))  # fmt: skip
    assert (tmp_path / "app.py").read_text() == source
    assert not (tmp_path / ".env").exists()


def test_unsupported_file_type_is_left_to_the_user(tmp_path, interactive):
    (tmp_path / "config.yaml").write_text(f"token: {GH_CLASSIC}\n")
    s = Session({"Run Auto-Fix": "y"})
    summary = _run(tmp_path, [("config.yaml", 1, _match("github_token", GH_CLASSIC))], s,
                   iter_sources=_sources(tmp_path))  # fmt: skip
    assert "not currently supported" in s.text
    assert GH_CLASSIC in (tmp_path / "config.yaml").read_text()  # untouched
    assert summary.credentials[0].replaced == 0
    assert summary.exit_code == 1


def test_find_references_returns_locations_only(tmp_path):
    (tmp_path / "a.txt").write_text(f"one\ntwo {GH_CLASSIC}\nthree {GH_CLASSIC}\n")
    (tmp_path / "b.txt").write_text("nothing here\n")
    hits = find_references(GH_CLASSIC, _sources(tmp_path))
    assert hits == [("a.txt", 2), ("a.txt", 3)]


def test_find_references_handles_multiline_values(tmp_path):
    (tmp_path / "k.pem").write_text(PRIVATE_KEY + "\n")
    assert find_references(PRIVATE_KEY, _sources(tmp_path)) == [("k.pem", 1)]


# --- Git history search ----------------------------------------------------------------


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    return tmp_path


def test_history_search_finds_a_secret_that_was_removed_from_the_tree(repo):
    (repo / "app.py").write_text(f'T = "{GH_CLASSIC}"\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add")
    (repo / "app.py").write_text("T = None\n")
    _git(repo, "commit", "-q", "-am", "remove")
    result = search_history(GH_CLASSIC, repo)
    assert result.error is None and not result.truncated
    assert len(result.commits) == 2  # added in one commit, removed in the next
    assert all(len(c) == 40 for c in result.commits)


def test_history_search_reports_none_when_absent(repo):
    (repo / "app.py").write_text("x = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    assert search_history(GH_CLASSIC, repo).commits == []


def test_history_search_covers_other_branches(repo):
    (repo / "a.txt").write_text("a\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    _git(repo, "checkout", "-q", "-b", "feature")
    (repo / "b.txt").write_text(GH_CLASSIC + "\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "feature")
    _git(repo, "checkout", "-q", "-")
    assert len(search_history(GH_CLASSIC, repo).commits) == 1


def test_history_search_never_puts_the_value_on_a_command_line(tmp_path):
    seen = {}

    class FakeProc:
        stdout = iter(["@@commit " + "b" * 40 + "\n", "+" + GH_CLASSIC + "\n"])
        returncode = 0

        def __init__(self):
            self.stdout = _Closable(["@@commit " + "b" * 40 + "\n", "+" + GH_CLASSIC + "\n"])

        def wait(self):
            pass

        def kill(self):
            pass

    class _Closable:
        def __init__(self, lines):
            self._it = iter(lines)

        def __iter__(self):
            return self._it

        def close(self):
            pass

    def fake_popen(cmd, **kwargs):
        seen["cmd"] = cmd
        return FakeProc()

    result = search_history(GH_CLASSIC, tmp_path, popen=fake_popen)
    assert result.commits == ["b" * 40]
    assert all(GH_CLASSIC not in part for part in seen["cmd"])


def test_history_search_is_cut_off_on_enormous_output(tmp_path, monkeypatch):
    monkeypatch.setattr(workflow, "_HISTORY_MAX_BYTES", 50)
    killed = []

    class _Out:
        def __init__(self):
            self._it = iter(["@@commit " + "c" * 40 + "\n"] + ["x" * 40 + "\n"] * 10)

        def __iter__(self):
            return self._it

        def close(self):
            pass

    class P:
        returncode = -9

        def __init__(self):
            self.stdout = _Out()

        def wait(self):
            pass

        def kill(self):
            killed.append(True)

    result = search_history(GH_CLASSIC, tmp_path, popen=lambda cmd, **kw: P())
    assert result.truncated is True
    assert result.error is None
    assert killed


def test_history_search_handles_git_missing(tmp_path):
    def no_git(cmd, **kwargs):
        raise FileNotFoundError("git")

    assert search_history(GH_CLASSIC, tmp_path, popen=no_git).error == "git could not be run"


def test_workflow_reports_history_hits_and_the_limits_of_rewriting(repo, interactive):
    (repo / "app.py").write_text("clean = True\n")
    s = Session({"Search Git history": "y"})
    summary = _run(
        repo,
        [("app.py", 1, _match("github_token", GH_CLASSIC))],
        s,
        iter_sources=_sources(repo),
        history_search=lambda core, root: HistoryResult(commits=["1234567890abcdef" * 2] * 7),
    )
    assert "found in 7 commit(s): 12345678" in s.text and "and 2 more" in s.text
    assert "cannot reach forks" in s.text
    assert providers.HISTORY_GUIDE.url in s.text
    assert summary.credentials[0].history_commits == 7


def test_workflow_survives_a_history_search_error(repo, interactive):
    s = Session({"Search Git history": "y"})
    summary = _run(repo, [("a.py", 1, _match("github_token", GH_CLASSIC))], s,
                   history_search=lambda c, r: HistoryResult(error="git could not be run"))  # fmt: skip
    assert "could not be checked (git could not be run)" in s.text
    assert summary.errored is False


def test_workflow_skips_history_outside_a_git_repo(tmp_path, interactive):
    s = Session()
    _run(tmp_path, [("a.py", 1, _match("github_token", GH_CLASSIC))], s)
    assert "not a Git repository" in s.text
    assert not any("Search Git history" in p for p in s.prompts)


# --- CLI integration -----------------------------------------------------------------------


def _project(tmp_path, monkeypatch, files):
    monkeypatch.chdir(tmp_path)
    for name, text in files.items():
        (tmp_path / name).write_text(text)


@pytest.mark.parametrize(
    "extra",
    [["--fix"], ["--baseline"], ["--json"], ["--format", "json"], ["--format", "sarif"],
     ["--output", "out.json", "--format", "json"]],
)  # fmt: skip
def test_rotate_rejects_incompatible_flags(tmp_path, monkeypatch, capsys, extra):
    _project(tmp_path, monkeypatch, {"app.py": f'T = "{GH_CLASSIC}"\n'})
    assert main(["scan", ".", "--rotate", *extra]) == 2
    assert "--rotate cannot be combined with" in capsys.readouterr().err


def test_rotate_on_a_clean_project_exits_zero(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"app.py": "print('hello')\n"})
    assert main(["scan", ".", "--rotate"]) == 0
    assert "nothing to rotate" in capsys.readouterr().out


def test_rotate_in_a_non_interactive_shell_changes_nothing(tmp_path, monkeypatch, capsys):
    source = f'T = "{GH_CLASSIC}"\n'
    _project(tmp_path, monkeypatch, {"app.py": source})
    assert main(["scan", ".", "--rotate"]) == 1
    out = capsys.readouterr().out
    assert "requires an interactive terminal" in out
    assert GH_CLASSIC not in out
    assert (tmp_path / "app.py").read_text() == source
    assert not (tmp_path / ".env").exists()


def test_rotate_ignores_a_json_default_from_secretshield_toml(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "app.py": f'T = "{GH_CLASSIC}"\n',
        "secretshield.toml": '[output]\nformat = "json"\n',
    })  # fmt: skip
    assert main(["scan", ".", "--rotate"]) == 1
    out = capsys.readouterr().out
    assert "requires an interactive terminal" in out  # text mode, not a JSON dump
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_rotate_still_covers_findings_accepted_in_the_baseline(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"app.py": f'T = "{GH_CLASSIC}"\n'})
    assert main(["scan", ".", "--baseline"]) == 0
    capsys.readouterr()
    assert main(["scan", "."]) == 0  # baselined: a plain scan is clean
    capsys.readouterr()
    assert main(["scan", ".", "--rotate"]) == 1  # but rotation still offers to help
    assert "requires an interactive terminal" in capsys.readouterr().out


def test_rotate_end_to_end_through_the_cli(tmp_path, monkeypatch, capsys, interactive):
    _project(tmp_path, monkeypatch, {"app.py": f'import os\nGH_TOKEN = "{GH_CLASSIC}"\n'})
    answers = iter(["y", "n", "y", "y", "y", "", "n", "n"])
    prompts = []

    def fake_input(prompt=""):
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)
    code = main(["scan", ".", "--rotate"])
    out = capsys.readouterr().out
    assert code == 1  # .env still holds the OLD value
    assert GH_CLASSIC not in out
    assert GH_CLASSIC not in "".join(prompts)
    assert "Rotation Summary" in out
    assert GH_CLASSIC not in (tmp_path / "app.py").read_text()
    assert "still present in .env:1" in out


def test_rotate_works_with_custom_rules(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {
        "app.py": f'V = "{CUSTOM}"\n',
        ".secretshield-rules.toml": '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n',
    })  # fmt: skip
    assert main(["scan", ".", "--rotate"]) == 1  # found, so rotation is offered
    out = capsys.readouterr().out
    assert "requires an interactive terminal" in out
    assert CUSTOM not in out


def test_scan_without_rotate_is_unchanged(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"app.py": f'T = "{GH_CLASSIC}"\n'})
    assert main(["scan", "."]) == 1
    out = capsys.readouterr().out
    assert "Potential secret" in out and "Rotation" not in out


# --- Documentation stays consistent with the implementation ---------------------------------


USAGE = (Path(__file__).resolve().parent.parent / "USAGE.md").read_text(encoding="utf-8")


def test_usage_documents_the_flag_the_section_and_its_anchors():
    assert "## Secret rotation assistant" in USAGE
    assert "### Supported providers" in USAGE and "### Privacy and security" in USAGE
    assert "(#secret-rotation-assistant)" in USAGE
    assert "--rotate" in USAGE
    assert "(#supported-providers)" in USAGE and "(#privacy-and-security)" in USAGE


def test_every_supported_provider_is_documented_and_nothing_extra_is_claimed():
    documented = {g.provider for g in _all_guides() if g.identified}
    assert documented == {"AWS", "GitHub", "OpenAI", "Slack", "Stripe", "Google"}
    for provider in documented:
        assert provider in USAGE
    low = USAGE.lower()
    assert "no provider is revoked automatically" in low
    assert "no network requests" in low


def test_usage_links_to_the_exact_provider_urls_the_code_uses():
    for url in ("https://console.aws.amazon.com/iam/", "https://platform.openai.com/api-keys",
                "https://api.slack.com/apps", "https://dashboard.stripe.com/apikeys",
                "https://console.cloud.google.com/apis/credentials"):  # fmt: skip
        assert url in USAGE
