"""
Configuration for secretshield.

A single module-level :class:`Config` instance holds the active settings.
Use :func:`configure` to update it; :func:`get_config` to read it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Config:
    """Runtime configuration for secretshield."""

    enabled: bool = True
    redact_with: str = "********"
    entropy_threshold: float = 4.2
    notify: bool = True


_config = Config()


def configure(
    enabled: bool | None = None,
    redact_with: str | None = None,
    entropy_threshold: float | None = None,
    notify: bool | None = None,
) -> Config:
    """
    Update the active configuration. Only provided (non-None) fields are
    changed; omitted fields keep their current value.
    """
    global _config
    if enabled is not None:
        _config.enabled = enabled
    if redact_with is not None:
        _config.redact_with = redact_with
    if entropy_threshold is not None:
        _config.entropy_threshold = entropy_threshold
    if notify is not None:
        _config.notify = notify
    return _config


def get_config() -> Config:
    """Return the current active :class:`Config` instance."""
    return _config


def reset_config() -> Config:
    """Reset configuration back to defaults. Primarily useful for tests."""
    global _config
    _config = Config()
    return _config
