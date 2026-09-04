"""Tests for secretshield.project_config -- secretshield.toml support."""

from __future__ import annotations

from secretshield.project_config import (
    find_config_file,
    load_project_config,
    render_default_toml,
)


def test_no_config_file_returns_empty_config(tmp_path):
    cfg = load_project_config(tmp_path)
    assert cfg.entropy_threshold is None
    assert cfg.ignore_paths == []
    assert cfg.include_patterns == []
    assert cfg.output_format is None


def test_find_config_file_detects_present_file(tmp_path):
    (tmp_path / "secretshield.toml").write_text("[scan]\n")
    assert find_config_file(tmp_path) is not None


def test_find_config_file_none_when_absent(tmp_path):
    assert find_config_file(tmp_path) is None


def test_loads_entropy_threshold(tmp_path):
    (tmp_path / "secretshield.toml").write_text("[scan]\nentropy_threshold = 3.5\n")
    cfg = load_project_config(tmp_path)
    assert cfg.entropy_threshold == 3.5


def test_loads_ignore_paths(tmp_path):
    (tmp_path / "secretshield.toml").write_text(
        '[scan.ignore]\npaths = ["tests/fixtures/", "docs/examples/"]\n'
    )
    cfg = load_project_config(tmp_path)
    assert "tests/fixtures/" in cfg.ignore_paths
    assert "docs/examples/" in cfg.ignore_paths


def test_loads_include_patterns(tmp_path):
    (tmp_path / "secretshield.toml").write_text(
        '[scan.include]\npatterns = ["*.py", "*.js"]\n'
    )
    cfg = load_project_config(tmp_path)
    assert "*.py" in cfg.include_patterns
    assert "*.js" in cfg.include_patterns


def test_loads_output_format(tmp_path):
    (tmp_path / "secretshield.toml").write_text('[output]\nformat = "json"\n')
    cfg = load_project_config(tmp_path)
    assert cfg.output_format == "json"


def test_malformed_toml_does_not_crash(tmp_path):
    (tmp_path / "secretshield.toml").write_text("this is not [ valid toml {{{")
    cfg = load_project_config(tmp_path)
    assert cfg.entropy_threshold is None


def test_render_default_toml_round_trips(tmp_path):
    content = render_default_toml(
        entropy_threshold=3.9,
        ignore_paths=["build/"],
        include_patterns=["*.py"],
    )
    (tmp_path / "secretshield.toml").write_text(content)
    cfg = load_project_config(tmp_path)
    assert cfg.entropy_threshold == 3.9
    assert "build/" in cfg.ignore_paths
    assert "*.py" in cfg.include_patterns
