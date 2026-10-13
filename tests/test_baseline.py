"""Tests for secretshield.baseline -- --baseline support."""

from __future__ import annotations

from secretshield.baseline import (
    baseline_exists,
    baseline_path,
    compute_finding_id,
    load_baseline_ids,
    write_baseline,
)


def test_finding_id_is_deterministic():
    id1 = compute_finding_id("app.py", "openai_api_key", "sk-realvalue")
    id2 = compute_finding_id("app.py", "openai_api_key", "sk-realvalue")
    assert id1 == id2


def test_finding_id_differs_by_value():
    id1 = compute_finding_id("app.py", "openai_api_key", "value-a")
    id2 = compute_finding_id("app.py", "openai_api_key", "value-b")
    assert id1 != id2


def test_finding_id_differs_by_file():
    id1 = compute_finding_id("a.py", "openai_api_key", "same-value")
    id2 = compute_finding_id("b.py", "openai_api_key", "same-value")
    assert id1 != id2


def test_baseline_does_not_exist_initially(tmp_path):
    assert baseline_exists(tmp_path) is False


def test_write_and_load_baseline(tmp_path):
    fid = compute_finding_id("app.py", "openai_api_key", "sk-realvalue")
    write_baseline(tmp_path, [{"id": fid, "file": "app.py", "kind": "openai_api_key", "line": 3}])
    assert baseline_exists(tmp_path) is True
    ids = load_baseline_ids(tmp_path)
    assert fid in ids


def test_baseline_file_never_contains_raw_secret_value(tmp_path):
    secret = "sk-thisIsARealLookingFakeSecretValue123"
    fid = compute_finding_id("app.py", "openai_api_key", secret)
    write_baseline(tmp_path, [{"id": fid, "file": "app.py", "kind": "openai_api_key", "line": 1}])
    content = baseline_path(tmp_path).read_text()
    assert secret not in content


def test_load_baseline_ids_empty_when_missing(tmp_path):
    assert load_baseline_ids(tmp_path) == set()


def test_load_baseline_ids_handles_malformed_json(tmp_path):
    baseline_path(tmp_path).write_text("not valid json {{{")
    assert load_baseline_ids(tmp_path) == set()
