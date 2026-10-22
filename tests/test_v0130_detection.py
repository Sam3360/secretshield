"""
Tests for v0.13.0: detection coverage for modern provider credentials.

New: OpenAI project/service/admin keys, Anthropic, GitLab, npm, PyPI,
SendGrid, Hugging Face, and Slack/Discord webhook URLs. All secrets are
fake and built by concatenation so this file never contains a literal
token.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secretshield import patterns, redact
from secretshield.baseline import compute_finding_id, finding_ids, write_baseline
from secretshield.cli import _KIND_DISPLAY, main
from secretshield.detector import _has_trivial_body, detect
from secretshield.rotation import identify
from secretshield.sarif import BUILTIN_RULE_KINDS

BODY = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0uV1w2X3y4Z5"

OPENAI_PROJ = "sk-proj-" + BODY
OPENAI_PROJ_PUNCT = "sk-proj-" + "a1B2c3_D4e5F6-g7H8i9J0k1L2m3N4o5P6q7R8_s9T0-"
OPENAI_SVCACCT = "sk-svcacct-" + BODY
OPENAI_ADMIN = "sk-admin-" + BODY
OPENAI_NONE = "sk-None-" + BODY
OPENAI_LEGACY = "sk-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
ANTHROPIC_API = "sk-ant-api03-" + BODY + "AA"
ANTHROPIC_ADMIN = "sk-ant-admin01-" + BODY
GITLAB_PAT = "glpat-" + "a1B2c3D4e5F6g7H8i9J0"
GITLAB_DEPLOY = "gldt-" + "a1B2c3D4e5F6g7H8i9J0"
GITLAB_RUNNER = "glrt-" + "a1B2c3D4e5F6g7H8i9J0"
GITLAB_OAUTH = "gloas-" + "a1B2c3D4e5F6g7H8i9J0"
NPM = "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
PYPI = "pypi-AgEIcHlwaS5vcmc" + BODY
SENDGRID = "SG." + "a1B2c3D4e5F6g7H8i9J0kL" + "." + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0uV1"
HUGGINGFACE = "hf_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7"
SLACK_HOOK = "https://hooks.slack.com/services/T0123ABCD/B0123ABCD/" + "a1B2c3D4e5F6g7H8i9J0k1L2"
SLACK_GOV_HOOK = "https://hooks.slack-gov.com/services/T0123ABCD/B0123ABCD/" + "a1B2c3D4e5F6g7H8i9J0k1L2"
DISCORD_HOOK = "https://discord.com/api/webhooks/123456789012345678/" + BODY
DISCORD_HOOK_LEGACY_HOST = "https://discordapp.com/api/webhooks/123456789012345678/" + BODY
DISCORD_HOOK_V10 = "https://discord.com/api/v10/webhooks/123456789012345678/" + BODY

NEW_CASES = [
    (OPENAI_PROJ, "openai_api_key"),
    (OPENAI_PROJ_PUNCT, "openai_api_key"),
    (OPENAI_SVCACCT, "openai_api_key"),
    (OPENAI_ADMIN, "openai_api_key"),
    (OPENAI_NONE, "openai_api_key"),
    (ANTHROPIC_API, "anthropic_api_key"),
    (ANTHROPIC_ADMIN, "anthropic_api_key"),
    (GITLAB_PAT, "gitlab_token"),
    (GITLAB_DEPLOY, "gitlab_token"),
    (GITLAB_RUNNER, "gitlab_token"),
    (GITLAB_OAUTH, "gitlab_token"),
    (NPM, "npm_token"),
    (PYPI, "pypi_token"),
    (SENDGRID, "sendgrid_api_key"),
    (HUGGINGFACE, "huggingface_token"),
    (SLACK_HOOK, "slack_webhook_url"),
    (SLACK_GOV_HOOK, "slack_webhook_url"),
    (DISCORD_HOOK, "discord_webhook_url"),
    (DISCORD_HOOK_LEGACY_HOST, "discord_webhook_url"),
    (DISCORD_HOOK_V10, "discord_webhook_url"),
]  # fmt: skip

NEW_KINDS = {
    "anthropic_api_key", "gitlab_token", "npm_token", "pypi_token",
    "sendgrid_api_key", "huggingface_token", "slack_webhook_url", "discord_webhook_url",
}  # fmt: skip


# --- New and broadened detectors --------------------------------------------------


@pytest.mark.parametrize("token, kind", NEW_CASES)
def test_credential_is_detected_with_its_specific_kind_and_full_span(token, kind):
    text = f"value = '{token}'"
    matches = detect(text)
    assert [m.kind for m in matches] == [kind]
    assert matches[0].value == token
    assert text[matches[0].start : matches[0].end] == token


@pytest.mark.parametrize("token, kind", NEW_CASES)
def test_specific_kind_wins_even_when_the_token_is_labeled(token, kind):
    # `OPENAI_API_KEY=...` also matches the generic labeled-secret detector
    # on the same span; the specific detector must be the one reported.
    assert [m.kind for m in detect(f"SECRET_TOKEN={token}")] == [kind]


@pytest.mark.parametrize("token, kind", NEW_CASES)
def test_credential_is_redacted_at_runtime(token, kind):
    redacted, was_redacted = redact(f"leaked: {token} end")
    assert was_redacted is True
    assert token not in redacted
    assert "********" in redacted


def test_trailing_punctuation_is_not_swallowed():
    text = f"token is {GITLAB_PAT}."
    (match,) = detect(text)
    assert match.value == GITLAB_PAT
    assert text[match.end] == "."


def test_anthropic_keys_are_not_claimed_by_the_openai_detector():
    kinds = [m.kind for m in detect(ANTHROPIC_API)]
    assert kinds == ["anthropic_api_key"]


def test_existing_openai_legacy_formats_still_detected():
    assert [m.kind for m in detect(OPENAI_LEGACY)] == ["openai_api_key"]
    marker = "sk-" + "a1B2c3D4e5F6g7H8i9J0k1L2" + "T3BlbkFJ" + "a1B2c3D4e5F6g7H8i9J0k1L2"
    (match,) = detect(marker)
    assert match.kind == "openai_api_key" and match.value == marker


def test_webhook_secrets_in_url_paths_are_found_despite_the_entropy_url_exemption():
    # Since 0.11.0 the generic entropy check skips URL paths, so a webhook
    # secret living in a path is only caught by these dedicated detectors.
    for url in (SLACK_HOOK, DISCORD_HOOK):
        assert [m.kind for m in detect(f"curl -X POST {url}")] != []


# --- False-positive guards ----------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
        "glpat-" + "x" * 20,
        "sk-ant-api03-" + "x" * 40,
        "sk-ant-admin01-" + "X" * 40,
        "npm_" + "x" * 36,
        "hf_" + "x" * 34,
        "SG." + "x" * 22 + "." + "x" * 43,
        "pypi-AgE" + "A" * 60,
        "https://discord.com/api/webhooks/123456789012345678/" + "x" * 68,
    ],
)
def test_documentation_filler_is_not_flagged(text):
    assert detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "see sk-learn-based-model-for-classification-tasks",
        "risk-assessment-framework-document-for-review",
        "npm_config_cache_directory_path_value",
        "pypi-some-long-package-name-for-publishing-things-here-ok",
        "hf_tokenizer_name_for_the_model",
        "glpat-",
        "SG.short.short",
        "https://discord.com/api/webhooks/{webhook.id}/{webhook.token}",
        "https://hooks.slack.com/services/T0123ABCD/B0123ABCD",
        "sk-proj-short",
    ],
)
def test_lookalikes_are_not_flagged(text):
    assert not [m for m in detect(text) if m.kind in NEW_KINDS | {"openai_api_key"}]


def _kinds(text):
    return [m.kind for m in detect(text)]


@pytest.mark.parametrize("length, expected", [(35, []), (36, ["npm_token"]), (37, [])])
def test_npm_token_requires_exactly_36_characters(length, expected):
    body = ("a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0" * 2)[:length]
    assert [k for k in _kinds("npm_" + body) if k == "npm_token"] == expected


@pytest.mark.parametrize(
    "first, second, expected",
    [(21, 43, []), (22, 43, ["sendgrid_api_key"]), (23, 43, []), (22, 42, []), (22, 44, [])],
)
def test_sendgrid_key_requires_the_documented_69_character_shape(first, second, expected):
    a = ("a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0uV1w2X3y4Z5" * 2)[:first]
    b = ("q7R8s9T0uV1w2X3y4Z5a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6" * 2)[:second]
    assert [k for k in _kinds(f"SG.{a}.{b}") if k == "sendgrid_api_key"] == expected


@pytest.mark.parametrize("length, expected", [(29, []), (30, ["huggingface_token"]), (34, ["huggingface_token"])])
def test_huggingface_token_has_a_minimum_length(length, expected):
    body = ("a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" * 2)[:length]
    assert [k for k in _kinds("hf_" + body) if k == "huggingface_token"] == expected


@pytest.mark.parametrize("length, expected", [(23, []), (24, ["slack_webhook_url"]), (25, [])])
def test_slack_webhook_secret_is_exactly_24_characters(length, expected):
    secret = ("a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6" * 2)[:length]
    text = f"https://hooks.slack.com/services/T0123ABCD/B0123ABCD/{secret}"
    assert [k for k in _kinds(text) if k == "slack_webhook_url"] == expected


def test_trivial_body_helper():
    assert _has_trivial_body("glpat-" + "x" * 20)
    assert _has_trivial_body("https://hooks.slack.com/services/T00000000/B00000000/" + "X" * 24)
    assert not _has_trivial_body(GITLAB_PAT)
    assert not _has_trivial_body(SLACK_HOOK)
    # ends in "AA" like real Anthropic keys: the long body run is what counts
    assert not _has_trivial_body(ANTHROPIC_API)


def test_trivial_body_guard_applies_only_to_the_new_kinds():
    assert patterns.TRIVIAL_BODY_KINDS == NEW_KINDS - set()
    # Existing behavior is untouched: a filler legacy OpenAI-style key is still reported.
    assert [m.kind for m in detect("sk-" + "x" * 30)] == ["openai_api_key"]


# --- Existing detectors keep working --------------------------------------------------


@pytest.mark.parametrize(
    "text, kind",
    [
        ("AKIA" + "ABCDEFGHIJKLMNOP", "aws_access_key_id"),
        ("ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8", "github_token"),
        ("xoxb-" + "1234567890-abcdefghij", "slack_token"),
        ("sk_live_" + "abcdefghijklmnop1234", "stripe_key"),
        ("AIza" + "abcdefghij" * 3 + "12345", "google_api_key"),
        ("eyJhbGciOi.eyJzdWIiOiIx.abcdefghij", "jwt"),
        ("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----", "private_key_block"),
        ("password = 'hunter2hunter2'", "generic_labeled_secret"),
    ],
)
def test_existing_builtin_detectors_unchanged(text, kind):
    assert kind in [m.kind for m in detect(text)]


def test_every_new_kind_has_a_label_and_sarif_rule():
    for kind in NEW_KINDS:
        assert kind in _KIND_DISPLAY
        assert kind in BUILTIN_RULE_KINDS
    assert NEW_KINDS <= {name for name, _ in patterns.PATTERNS}


def test_existing_sarif_rule_indexes_did_not_move():
    assert BUILTIN_RULE_KINDS[:12] == (
        "aws_access_key_id", "aws_secret_access_key", "github_token", "openai_api_key",
        "slack_token", "stripe_key", "google_api_key", "jwt", "bearer_token",
        "private_key_block", "generic_labeled_secret", "high_entropy",
    )  # fmt: skip


# --- Scan integration -------------------------------------------------------------------


def _project(tmp_path, monkeypatch, files):
    monkeypatch.chdir(tmp_path)
    for name, text in files.items():
        (tmp_path / name).write_text(text)


@pytest.mark.parametrize("token, kind", NEW_CASES)
def test_scan_reports_the_specific_label_and_masks_the_value(
    tmp_path, monkeypatch, capsys, token, kind
):
    _project(tmp_path, monkeypatch, {"app.txt": f"x = {token}\n"})
    assert main(["scan", "."]) == 1
    out = capsys.readouterr().out
    assert _KIND_DISPLAY[kind][0] in out
    assert token not in out


def test_scan_json_uses_the_new_kinds(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"a.txt": GITLAB_PAT + "\n", "b.txt": SLACK_HOOK + "\n"})
    assert main(["scan", ".", "--json"]) == 1
    kinds = {f["kind"] for f in json.loads(capsys.readouterr().out)["matches"]}
    assert kinds == {"gitlab_token", "slack_webhook_url"}


def test_scan_sarif_reports_new_rules_with_expected_levels(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"a.txt": GITLAB_PAT + "\n", "b.txt": SLACK_HOOK + "\n"})
    assert main(["scan", ".", "--format", "sarif"]) == 1
    run = json.loads(capsys.readouterr().out)["runs"][0]
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels == {
        "secretshield.gitlab_token": "error",
        "secretshield.slack_webhook_url": "warning",
    }
    assert GITLAB_PAT not in json.dumps(run) and SLACK_HOOK not in json.dumps(run)


def test_scan_ignores_documentation_placeholders(tmp_path, monkeypatch):
    _project(tmp_path, monkeypatch, {
        "README.md": "curl https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX\n"
                     "use glpat-xxxxxxxxxxxxxxxxxxxx or sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
    })  # fmt: skip
    assert main(["scan", "."]) == 0


def test_a_labeled_placeholder_is_still_reported_only_by_the_generic_detector(
    tmp_path, monkeypatch, capsys
):
    # Pre-existing behavior, unchanged: `NAME=value` placeholders are flagged
    # by the generic labeled-secret detector. The new specific detectors must
    # not add a second, misleading finding on top of it.
    _project(tmp_path, monkeypatch, {"README.md": "export GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx\n"})
    assert main(["scan", ".", "--json"]) == 1
    kinds = [f["kind"] for f in json.loads(capsys.readouterr().out)["matches"]]
    assert kinds == ["generic_labeled_secret"]


def test_custom_rules_still_work_alongside_the_new_detectors(tmp_path, monkeypatch, capsys):
    custom = "MYAPP_" + "12345678901234567890123456789012"
    _project(tmp_path, monkeypatch, {
        "a.txt": f"{GITLAB_PAT}\n{custom}\n",
        ".secretshield-rules.toml": '[[rules]]\nname = "My API Key"\npattern = "MYAPP_[A-Za-z0-9]{32}"\n',
    })  # fmt: skip
    assert main(["scan", ".", "--json"]) == 1
    kinds = sorted(f["kind"] for f in json.loads(capsys.readouterr().out)["matches"])
    assert kinds == ["My API Key", "gitlab_token"]


# --- Baselines survive the reclassification ------------------------------------------------


@pytest.mark.parametrize("old_kind", ["high_entropy", "generic_labeled_secret"])
@pytest.mark.parametrize(
    "token, kind",
    [(OPENAI_PROJ, "openai_api_key"), (ANTHROPIC_API, "anthropic_api_key"),
     (GITLAB_PAT, "gitlab_token"), (NPM, "npm_token"), (PYPI, "pypi_token"),
     (SENDGRID, "sendgrid_api_key"), (HUGGINGFACE, "huggingface_token")],
)  # fmt: skip
def test_a_baseline_written_before_the_upgrade_still_suppresses_the_finding(
    tmp_path, monkeypatch, capsys, token, kind, old_kind
):
    _project(tmp_path, monkeypatch, {"app.py": f"x = '{token}'\n"})
    write_baseline(tmp_path, [{
        "id": compute_finding_id("app.py", old_kind, token),
        "file": "app.py", "kind": old_kind, "line": 1,
    }])  # fmt: skip
    assert main(["scan", "."]) == 0
    assert "ignored by baseline" in capsys.readouterr().out


def test_legacy_baseline_entry_for_a_different_value_or_file_does_not_suppress(
    tmp_path, monkeypatch
):
    _project(tmp_path, monkeypatch, {"app.py": f"x = '{GITLAB_PAT}'\n"})
    write_baseline(tmp_path, [
        {"id": compute_finding_id("app.py", "high_entropy", "something-else-entirely-1234"),
         "file": "app.py", "kind": "high_entropy", "line": 1},
        {"id": compute_finding_id("other.py", "high_entropy", GITLAB_PAT),
         "file": "other.py", "kind": "high_entropy", "line": 1},
    ])  # fmt: skip
    assert main(["scan", "."]) == 1


def test_legacy_fallback_does_not_apply_to_kinds_that_were_always_specific(tmp_path, monkeypatch):
    aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    _project(tmp_path, monkeypatch, {"app.py": f"x = '{aws}'\n"})
    write_baseline(tmp_path, [{
        "id": compute_finding_id("app.py", "high_entropy", aws),
        "file": "app.py", "kind": "high_entropy", "line": 1,
    }])  # fmt: skip
    assert main(["scan", "."]) == 1
    assert finding_ids("app.py", "aws_access_key_id", aws) == {
        compute_finding_id("app.py", "aws_access_key_id", aws)
    }


def test_a_fresh_baseline_uses_the_new_kind_and_suppresses(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, {"app.py": f"x = '{GITLAB_PAT}'\n"})
    assert main(["scan", ".", "--baseline"]) == 0
    data = json.loads((tmp_path / ".secretshield-baseline.json").read_text())
    assert data["findings"][0]["kind"] == "gitlab_token"
    assert GITLAB_PAT not in json.dumps(data)
    capsys.readouterr()
    assert main(["scan", "."]) == 0


def test_baseline_file_still_never_contains_the_value(tmp_path, monkeypatch):
    _project(tmp_path, monkeypatch, {"app.py": f"x = '{PYPI}'\n"})
    main(["scan", ".", "--baseline"])
    assert PYPI not in (tmp_path / ".secretshield-baseline.json").read_text()


# --- Rotation guidance for the new kinds -------------------------------------------------------


@pytest.mark.parametrize(
    "kind, value, provider, credential_fragment",
    [
        ("openai_api_key", OPENAI_PROJ, "OpenAI", "API key"),
        ("anthropic_api_key", ANTHROPIC_API, "Anthropic", "API key"),
        ("anthropic_api_key", ANTHROPIC_ADMIN, "Anthropic", "Admin API key"),
        ("gitlab_token", GITLAB_PAT, "GitLab", "access token"),
        ("gitlab_token", GITLAB_DEPLOY, "GitLab", "deploy token"),
        ("gitlab_token", GITLAB_RUNNER, "GitLab", "runner authentication token"),
        ("gitlab_token", GITLAB_OAUTH, "GitLab", "OAuth application secret"),
        ("npm_token", NPM, "npm", "access token"),
        ("pypi_token", PYPI, "PyPI", "API token"),
        ("sendgrid_api_key", SENDGRID, "Twilio SendGrid", "API key"),
        ("huggingface_token", HUGGINGFACE, "Hugging Face", "user access token"),
        ("slack_webhook_url", SLACK_HOOK, "Slack", "incoming webhook URL"),
        ("discord_webhook_url", DISCORD_HOOK, "Discord", "webhook URL"),
    ],
)  # fmt: skip
def test_new_kinds_are_identified_for_rotation(kind, value, provider, credential_fragment):
    guide = identify(kind, value)
    assert guide.identified is True
    assert guide.provider == provider
    assert credential_fragment in guide.credential
    assert guide.steps and guide.needs_rotation is True


@pytest.mark.parametrize(
    "kind, value",
    [("anthropic_api_key", "nope"), ("gitlab_token", "glpat-"), ("npm_token", "npm_x"),
     ("pypi_token", "pypi-x"), ("sendgrid_api_key", "SG.a.b"), ("huggingface_token", "hf_x"),
     ("slack_webhook_url", "https://hooks.slack.com/x"), ("discord_webhook_url", "https://x")],
)  # fmt: skip
def test_a_custom_rule_named_like_a_new_kind_is_not_attributed_to_the_provider(kind, value):
    assert identify(kind, value).identified is False


def test_slack_webhook_guidance_is_honest_that_slack_documents_no_revoke_step():
    guide = identify("slack_webhook_url", SLACK_HOOK)
    assert any("does not describe a revoke step" in n for n in guide.notes)
    assert guide.manage.url == "https://api.slack.com/apps"


def test_anthropic_api01_keys_are_not_asserted_to_be_compliance_keys():
    note = identify("anthropic_api_key", "sk-ant-api01-" + BODY).notes[0]
    assert "Older Claude API keys may also use this prefix" in note
    assert identify("anthropic_api_key", ANTHROPIC_API).notes == ()


def test_pypi_and_gitlab_do_not_invent_direct_links():
    assert identify("pypi_token", PYPI).manage is None and identify("pypi_token", PYPI).docs == ()
    assert identify("gitlab_token", GITLAB_PAT).manage is None
    assert [l.url for l in identify("gitlab_token", GITLAB_PAT).docs] == [
        "https://docs.gitlab.com/user/profile/personal_access_tokens/"
    ]


@pytest.mark.parametrize(
    "kind, value, url",
    [
        ("anthropic_api_key", ANTHROPIC_API, "https://platform.claude.com/"),
        ("sendgrid_api_key", SENDGRID, "https://app.sendgrid.com/settings/api_keys"),
        ("slack_webhook_url", SLACK_HOOK, "https://api.slack.com/apps"),
    ],
)
def test_management_links_for_new_kinds(kind, value, url):
    assert identify(kind, value).manage.url == url


def test_new_guides_never_contain_the_credential():
    for kind, value in [(k, v) for v, k in NEW_CASES]:
        guide = identify(kind, value)
        blob = "\n".join([guide.provider, guide.credential, *guide.steps, *guide.notes])
        blob += "\n".join(l.url + l.label for l in guide.docs)
        assert value not in blob


# --- Documentation ----------------------------------------------------------------------------


USAGE = (Path(__file__).resolve().parent.parent / "USAGE.md").read_text(encoding="utf-8")


def test_usage_lists_every_new_detector_kind_and_the_upgrade_note():
    for kind in NEW_KINDS:
        assert f"`{kind}`" in USAGE, kind
    assert "sk-proj-" in USAGE
    assert "Upgrading to 0.13" in USAGE
