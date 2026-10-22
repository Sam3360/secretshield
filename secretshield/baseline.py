"""
`--baseline` support: let a repo adopt SecretShield without being
forced to immediately fix every pre-existing finding. Findings are
identified by a hash of (file, kind, value) -- never the plaintext
value itself -- so a baseline file is safe to commit even though it's
derived from real secret content.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

BASELINE_FILENAME = ".secretshield-baseline.json"


def compute_finding_id(file: str, kind: str, value: str) -> str:
    digest_input = f"{file}:{kind}:{value}".encode("utf-8", errors="ignore")
    return hashlib.sha256(digest_input).hexdigest()


# Kinds that used to be reported as something more generic. The fingerprint
# includes the kind, so reclassifying a token (say, from `high_entropy` to
# `gitlab_token`) would otherwise make an already-accepted finding reappear
# after an upgrade. A baseline entry written under one of these older kinds
# still matches the same file and value.
_PREVIOUS_KINDS = ("high_entropy", "generic_labeled_secret")
_RECLASSIFIED_KINDS = frozenset(
    {
        "openai_api_key",  # sk-proj-, sk-svcacct-, sk-admin-, sk-None- keys
        "anthropic_api_key", "gitlab_token", "npm_token", "pypi_token",
        "sendgrid_api_key", "huggingface_token",
    }
)  # fmt: skip


def finding_ids(file: str, kind: str, value: str) -> set[str]:
    """Every fingerprint under which this finding may be stored in a baseline."""
    ids = {compute_finding_id(file, kind, value)}
    if kind in _RECLASSIFIED_KINDS:
        ids.update(compute_finding_id(file, old, value) for old in _PREVIOUS_KINDS)
    return ids


def baseline_path(root: Path) -> Path:
    return root / BASELINE_FILENAME


def write_baseline(root: Path, findings: list[dict]) -> Path:
    """
    `findings` entries: {"id": str, "file": str, "kind": str, "line": int}.
    Never include the actual secret value.
    """
    path = baseline_path(root)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "findings": findings,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load_baseline_ids(root: Path) -> set[str]:
    path = baseline_path(root)
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    if not isinstance(data, dict):
        return set()
    return {f["id"] for f in data.get("findings", []) if isinstance(f, dict) and "id" in f}


def baseline_exists(root: Path) -> bool:
    return baseline_path(root).exists()
