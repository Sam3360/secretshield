"""
Unit tests for secretshield.sarif -- the SARIF 2.1.0 report builder.

Covers document structure, schema version, rule metadata, severity
mapping, file locations (including UTF-16 columns and multi-line spans),
empty results, JSON escaping, URI encoding, determinism, secret
redaction, and the GitHub Code Scanning requirements documented at
https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support

All secrets used here are fake / non-functional.
"""

from __future__ import annotations

import json
import re

import pytest

import secretshield
from secretshield import patterns, sarif
from secretshield.cli import _KIND_DISPLAY
from secretshield.sarif import (
    BUILTIN_RULE_KINDS,
    SarifFinding,
    artifact_uri,
    build_sarif,
    compute_region,
    dumps,
)

FAKE_OPENAI_KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz1234567890"


def _finding(file="app.py", kind="github_token", line=3, col=5, end_line=3, end_col=45):
    return SarifFinding(file, kind, line, col, end_line, end_col)


def _run(log):
    return log["runs"][0]


def _rules_by_id(log):
    return {r["id"]: r for r in _run(log)["tool"]["driver"]["rules"]}


# --- document structure / schema version ------------------------------------


def test_top_level_structure_and_schema_version():
    log = build_sarif([_finding()])
    assert log["version"] == "2.1.0"
    assert log["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert isinstance(log["runs"], list) and len(log["runs"]) == 1
    assert set(_run(log)) >= {"tool", "results", "columnKind", "invocations"}


def test_tool_driver_metadata():
    driver = _run(build_sarif([]))["tool"]["driver"]
    assert driver["name"] == "SecretShield"
    assert driver["version"] == secretshield.__version__
    assert driver["informationUri"] == "https://github.com/Sam3360/secretshield"
    assert isinstance(driver["rules"], list) and driver["rules"]


def test_column_kind_declared_as_utf16():
    assert _run(build_sarif([]))["columnKind"] == "utf16CodeUnits"


def test_dumps_round_trips_and_ends_with_newline():
    log = build_sarif([_finding()])
    text = dumps(log)
    assert text.endswith("\n")
    assert json.loads(text) == log


def test_dumps_is_pure_ascii():
    log = build_sarif([_finding(file="d\u00e9p/\u2603.py")], custom_rule_names=["caf\u00e9 \U0001F600"])
    text = dumps(log)
    assert text.isascii()
    assert json.loads(text) == log


# --- empty results -------------------------------------------------------------


def test_empty_results_is_valid_and_has_empty_results_list():
    log = build_sarif([])
    assert _run(log)["results"] == []
    assert _run(log)["tool"]["driver"]["rules"]  # rule catalog still present
    assert _run(log)["invocations"][0]["executionSuccessful"] is True


def test_run_properties_report_counts_only():
    log = build_sarif([], files_scanned=7, ignored_by_baseline=2)
    props = _run(log)["invocations"][0]["properties"]
    assert props == {"filesScanned": 7, "ignoredByBaseline": 2}


def test_run_properties_omitted_when_unknown():
    assert "properties" not in _run(build_sarif([]))["invocations"][0]


# --- rule metadata ---------------------------------------------------------------


def test_every_detector_kind_has_sarif_metadata():
    detector_kinds = {name for name, _ in patterns.PATTERNS} | {"high_entropy"}
    assert detector_kinds == set(BUILTIN_RULE_KINDS)


def test_sarif_labels_match_cli_display_labels():
    for kind in BUILTIN_RULE_KINDS:
        assert sarif.builtin_label(kind) == _KIND_DISPLAY[kind][0]


def test_builtin_rule_ids_are_namespaced_and_unique():
    ids = [r["id"] for r in _run(build_sarif([]))["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))
    for kind in BUILTIN_RULE_KINDS:
        assert f"secretshield.{kind}" in ids


@pytest.mark.parametrize("kind", BUILTIN_RULE_KINDS)
def test_rule_descriptor_is_complete(kind):
    rule = _rules_by_id(build_sarif([]))[f"secretshield.{kind}"]
    assert rule["name"] and len(rule["name"]) <= 255
    assert rule["shortDescription"]["text"] and len(rule["shortDescription"]["text"]) <= 1024
    assert rule["fullDescription"]["text"] and len(rule["fullDescription"]["text"]) <= 1024
    assert rule["help"]["text"]
    assert rule["help"]["markdown"]
    assert rule["helpUri"].startswith("https://")
    assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note"}
    props = rule["properties"]
    assert "security" in props["tags"]
    assert len(props["tags"]) <= 10  # GitHub shows at most 10 tags
    assert props["precision"] in {"very-high", "high", "medium", "low"}


@pytest.mark.parametrize("kind", BUILTIN_RULE_KINDS)
def test_remediation_guidance_present(kind):
    rule = _rules_by_id(build_sarif([]))[f"secretshield.{kind}"]
    assert re.search(r"rotate|revoke|deactivate|regenerate|roll|replace|invalidate|check whether", rule["help"]["text"], re.I)


def test_result_rule_index_matches_rule_id():
    log = build_sarif([_finding(kind="jwt"), _finding(kind="private_key_block", line=9, end_line=9)])
    rules = _run(log)["tool"]["driver"]["rules"]
    for result in _run(log)["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


# --- severity mapping --------------------------------------------------------------

_EXPECTED_SEVERITY = {
    "private_key_block": ("error", 9.5),
    "aws_secret_access_key": ("error", 9.5),
    "github_token": ("error", 8.5),
    "openai_api_key": ("error", 8.0),
    "slack_token": ("error", 8.0),
    "stripe_key": ("error", 8.0),
    "aws_access_key_id": ("error", 7.5),
    "bearer_token": ("error", 7.5),
    "google_api_key": ("error", 7.0),
    "jwt": ("warning", 6.5),
    "generic_labeled_secret": ("warning", 6.0),
    "high_entropy": ("note", 3.5),
    # Added in 0.13.0
    "gitlab_token": ("error", 8.5),
    "npm_token": ("error", 8.5),
    "pypi_token": ("error", 8.5),
    "anthropic_api_key": ("error", 8.0),
    "sendgrid_api_key": ("error", 8.0),
    "huggingface_token": ("error", 7.5),
    "slack_webhook_url": ("warning", 6.0),
    "discord_webhook_url": ("warning", 6.0),
}


def test_severity_table_covers_every_kind():
    assert set(_EXPECTED_SEVERITY) == set(BUILTIN_RULE_KINDS)


@pytest.mark.parametrize("kind,expected", sorted(_EXPECTED_SEVERITY.items()))
def test_severity_mapping_per_kind(kind, expected):
    level, score = expected
    log = build_sarif([_finding(kind=kind)])
    rule = _rules_by_id(log)[f"secretshield.{kind}"]
    result = _run(log)["results"][0]
    assert rule["defaultConfiguration"]["level"] == level
    assert result["level"] == level
    assert rule["properties"]["security-severity"] == f"{score:.1f}"


@pytest.mark.parametrize("kind", BUILTIN_RULE_KINDS)
def test_level_is_consistent_with_security_severity_bucket(kind):
    rule = _rules_by_id(build_sarif([]))[f"secretshield.{kind}"]
    score = float(rule["properties"]["security-severity"])
    assert 0.0 < score <= 10.0
    expected = "error" if score >= 7.0 else "warning" if score >= 4.0 else "note"
    assert rule["defaultConfiguration"]["level"] == expected


def test_security_severity_is_a_string():
    for rule in _run(build_sarif([]))["tool"]["driver"]["rules"]:
        assert isinstance(rule["properties"]["security-severity"], str)


# --- locations ------------------------------------------------------------------------


def test_result_location_fields():
    log = build_sarif([_finding(file="src/app.py", line=3, col=16, end_line=3, end_col=55)])
    loc = _run(log)["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"] == {"uri": "src/app.py"}
    assert loc["region"] == {"startLine": 3, "startColumn": 16, "endLine": 3, "endColumn": 55}


def test_exactly_one_location_per_result():
    for result in _run(build_sarif([_finding(), _finding(line=8, end_line=8)]))["results"]:
        assert len(result["locations"]) == 1


def test_compute_region_single_line_is_one_based_and_end_exclusive():
    text = 'a = 1\nkey = "SECRETVALUE"\n'
    start = text.index("SECRETVALUE")
    end = start + len("SECRETVALUE")
    assert compute_region(text, start, end) == (2, 8, 2, 19)


def test_compute_region_first_char_of_file():
    assert compute_region("abc", 0, 3) == (1, 1, 1, 4)


def test_compute_region_multiline_span():
    text = "x\n  BEGIN\nmid\nEND\ntail\n"
    start = text.index("BEGIN")
    end = text.index("END") + 3
    assert compute_region(text, start, end) == (2, 3, 4, 4)


def test_compute_region_columns_are_utf16_code_units():
    # An astral character (emoji) is 2 UTF-16 code units but 1 Python character.
    text = "\U0001F600=SECRET"
    start = text.index("SECRET")
    assert compute_region(text, start, start + 6) == (1, 4, 1, 10)


def test_compute_region_with_crlf_text():
    text = "one\r\ntwo = SECRET\r\n"
    start = text.index("SECRET")
    assert compute_region(text, start, start + 6) == (2, 7, 2, 13)


def test_compute_region_never_reads_matched_text():
    # Only offsets matter: the result is identical for different content.
    assert compute_region("aaaaaa bbbbbb", 7, 13) == compute_region("cccccc dddddd", 7, 13)


# --- artifact URIs / escaping -------------------------------------------------------------


@pytest.mark.parametrize(
    "path,expected",
    [
        ("app.py", "app.py"),
        ("src/app.py", "src/app.py"),
        ("./src/app.py", "src/app.py"),
        ("src\\win\\app.py", "src/win/app.py"),
        ("my file.py", "my%20file.py"),
        ("dir/a#b.py", "dir/a%23b.py"),
        ("dir/100%.py", "dir/100%25.py"),
        ("q?x.py", "q%3Fx.py"),
        ("d\u00e9p/\u2603.py", "d%C3%A9p/%E2%98%83.py"),
    ],
)
def test_artifact_uri_encoding(path, expected):
    assert artifact_uri(path) == expected


def test_artifact_uri_has_no_uribaseid_or_absolute_path_for_relative_files():
    log = build_sarif([_finding(file="src/app.py")])
    art = _run(log)["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert "uriBaseId" not in art
    assert not art["uri"].startswith(("/", "file:"))


def test_artifact_uri_absolute_path_becomes_file_uri(tmp_path):
    uri = artifact_uri(str(tmp_path / "a b.py"))
    assert uri.startswith("file:///")
    assert "a%20b.py" in uri


def test_artifact_uri_handles_undecodable_filename_bytes():
    import os

    name = os.fsdecode(b"bad_\xff_name.py")
    uri = artifact_uri(name)
    assert uri.isascii()
    assert "%FF" in uri


def test_special_characters_in_custom_rule_name_survive_json_round_trip():
    nasty = 'My "API" Key\\ <script>alert(1)</script> & \u00e9\n\ttab'
    log = build_sarif([_finding(kind=nasty)])
    parsed = json.loads(dumps(log))
    rule = _run(parsed)["tool"]["driver"]["rules"][-1]
    assert rule["name"] == nasty
    assert nasty in rule["shortDescription"]["text"]
    assert nasty in _run(parsed)["results"][0]["message"]["text"]


def test_custom_rule_name_never_enters_markdown_help():
    nasty = "**bold** [link](http://evil.example) <img src=x>"
    log = build_sarif([_finding(kind=nasty)])
    rule = _run(log)["tool"]["driver"]["rules"][-1]
    assert nasty not in rule["help"]["markdown"]
    assert nasty not in rule["help"]["text"]


# --- custom rules ------------------------------------------------------------------------------


def test_custom_rule_gets_namespaced_slug_id_and_error_level():
    log = build_sarif([_finding(kind="My API Key")])
    result = _run(log)["results"][0]
    assert result["ruleId"] == "secretshield.custom.my-api-key"
    assert result["level"] == "error"
    rule = _rules_by_id(log)["secretshield.custom.my-api-key"]
    assert rule["properties"]["security-severity"] == "7.5"
    assert "custom" in rule["properties"]["tags"]


def test_custom_rule_ids_do_not_collide():
    log = build_sarif([], custom_rule_names=["My Key", "my-key", "MY KEY!"])
    ids = [r["id"] for r in _run(log)["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))
    assert {"secretshield.custom.my-key", "secretshield.custom.my-key-2", "secretshield.custom.my-key-3"} <= set(ids)


def test_non_ascii_only_custom_rule_name_still_gets_valid_id():
    log = build_sarif([_finding(kind="\u5bc6\u94a5")])
    assert _run(log)["results"][0]["ruleId"] == "secretshield.custom.rule"


def test_loaded_custom_rules_listed_even_without_findings():
    log = build_sarif([], custom_rule_names=["Unused Rule"])
    assert "secretshield.custom.unused-rule" in _rules_by_id(log)


def test_custom_rule_named_like_builtin_kind_does_not_duplicate_rule():
    log = build_sarif([_finding(kind="jwt")], custom_rule_names=["jwt"])
    ids = [r["id"] for r in _run(log)["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))


# --- ordering / determinism -------------------------------------------------------------------------


def test_results_sorted_deterministically():
    findings = [
        _finding(file="b.py", line=1, end_line=1),
        _finding(file="a.py", line=9, end_line=9),
        _finding(file="a.py", line=2, end_line=2),
        _finding(file="a.py", line=2, col=1, end_line=2, end_col=3),
    ]
    log = build_sarif(findings)
    locs = [
        (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            r["locations"][0]["physicalLocation"]["region"]["startColumn"],
        )
        for r in _run(log)["results"]
    ]
    assert locs == [("a.py", 2, 1), ("a.py", 2, 5), ("a.py", 9, 5), ("b.py", 1, 5)]


def test_output_independent_of_input_order():
    findings = [_finding(file="b.py"), _finding(file="a.py"), _finding(kind="jwt")]
    assert dumps(build_sarif(findings)) == dumps(build_sarif(list(reversed(findings))))


def test_output_contains_no_timestamps_or_absolute_paths():
    text = dumps(build_sarif([_finding()]))
    assert "startTimeUtc" not in text and "endTimeUtc" not in text
    assert "workingDirectory" not in text


# --- redaction -------------------------------------------------------------------------------------------


def test_finding_type_has_no_field_that_can_carry_a_secret():
    assert {f for f in SarifFinding.__dataclass_fields__} == {
        "file", "kind", "start_line", "start_column", "end_line", "end_column",
    }


def test_report_omits_snippets_and_value_derived_data():
    text = dumps(build_sarif([_finding()]))
    for forbidden in ("snippet", "contextRegion", "partialFingerprints", "fingerprints", "sha256"):
        assert forbidden not in text
    assert not re.search(r"\b[0-9a-f]{64}\b", text)  # no baseline-style SHA-256 digests


def test_secret_in_value_shaped_kind_never_comes_from_findings():
    # The builder never receives values, so even a scan of text full of
    # secrets yields a report free of them (see CLI integration tests for
    # the end-to-end version of this check).
    log = build_sarif([_finding(kind="openai_api_key")])
    assert FAKE_OPENAI_KEY not in dumps(log)


# --- GitHub Code Scanning requirements ---------------------------------------------------------------------


def _assert_github_compatible(log):
    assert log["version"] == "2.1.0"
    run = _run(log)
    driver = run["tool"]["driver"]
    assert driver["name"]
    rules = driver["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    assert len(rules) <= 25000
    for rule in rules:
        assert rule["id"]
        assert len(rule["name"]) <= 255
        assert len(rule["shortDescription"]["text"]) <= 1024
        assert len(rule["fullDescription"]["text"]) <= 1024
        assert len(rule["properties"]["tags"]) <= 20
        score = float(rule["properties"]["security-severity"])
        assert 0.0 < score <= 10.0
        assert rule["defaultConfiguration"]["level"] in {"note", "warning", "error"}
    assert len(run["results"]) <= 5000
    for result in run["results"]:
        assert result["ruleId"] and rules[result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["level"] in {"note", "warning", "error"}
        assert result["message"]["text"].strip()
        assert 1 <= len(result["locations"]) <= 10
        phys = result["locations"][0]["physicalLocation"]
        uri = phys["artifactLocation"]["uri"]
        assert uri and uri.isascii() and " " not in uri and "\\" not in uri
        region = phys["region"]
        assert region["startLine"] >= 1 and region["startColumn"] >= 1
        assert (region["endLine"], region["endColumn"]) >= (region["startLine"], region["startColumn"])


def test_github_requirements_with_findings():
    findings = [
        _finding(kind=k, file=f"src/f{i}.py", line=i + 1, end_line=i + 1)
        for i, k in enumerate(BUILTIN_RULE_KINDS)
    ]
    findings.append(_finding(kind="My Custom Rule", file="x y.py"))
    _assert_github_compatible(json.loads(dumps(build_sarif(findings, custom_rule_names=["My Custom Rule"]))))


def test_github_requirements_with_no_findings():
    _assert_github_compatible(json.loads(dumps(build_sarif([]))))


def test_message_first_sentence_is_self_contained_title():
    # GitHub shows only the first sentence of message.text when space is tight.
    for kind in BUILTIN_RULE_KINDS:
        text = _run(build_sarif([_finding(kind=kind)]))["results"][0]["message"]["text"]
        first = text.split(". ")[0]
        assert first.startswith("Potential secret detected")
        assert sarif.builtin_label(kind) in first
