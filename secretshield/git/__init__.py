"""Git pre-commit hook integration for SecretShield."""

from __future__ import annotations

from .hooks import (
    find_git_dir,
    get_staged_content,
    get_staged_files,
    install_hook,
    is_git_repo,
    uninstall_hook,
)

__all__ = [
    "find_git_dir",
    "is_git_repo",
    "get_staged_files",
    "get_staged_content",
    "install_hook",
    "uninstall_hook",
]
