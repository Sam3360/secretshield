"""Tests for secretshield.color -- dependency-free ANSI color support."""

from __future__ import annotations

import io

from secretshield.color import green, red, supports_color


class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


class _FakeNonTTY(io.StringIO):
    def isatty(self):
        return False


def test_red_wraps_with_ansi_when_enabled():
    result = red("X", True)
    assert result.startswith("\033[31m")
    assert result.endswith("\033[0m")
    assert "X" in result


def test_red_plain_when_disabled():
    assert red("X", False) == "X"


def test_green_wraps_with_ansi_when_enabled():
    result = green("Y", True)
    assert result.startswith("\033[32m")
    assert result.endswith("\033[0m")


def test_green_plain_when_disabled():
    assert green("Y", False) == "Y"


def test_supports_color_true_for_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert supports_color(_FakeTTY()) is True


def test_supports_color_false_for_non_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert supports_color(_FakeNonTTY()) is False


def test_no_color_env_disables_even_for_tty(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert supports_color(_FakeTTY()) is False


def test_force_color_env_enables_even_for_non_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert supports_color(_FakeNonTTY()) is True


def test_no_color_takes_precedence_over_force_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert supports_color(_FakeTTY()) is False


def test_supports_color_handles_stream_without_isatty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)

    class _Weird:
        pass

    assert supports_color(_Weird()) is False
