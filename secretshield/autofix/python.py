"""
Python-specific Auto-Fix logic: deciding whether a line containing a
detected secret is a *safely transformable* simple assignment, and
building the replacement source.

Safety is determined with the `ast` module rather than a regex, which
is what lets us correctly reject things a regex would get wrong: dict
literals, f-strings, string concatenation across a function call,
multi-target assignments, etc. If the single line doesn't parse as
exactly one `NAME = "constant string"` assignment whose string equals
the detected secret, it's treated as ambiguous and left untouched.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass


@dataclass
class SafeAssignment:
    indent: str
    var_name: str
    quote: str
    value: str


def find_safe_assignment(line_text: str, secret_value: str) -> SafeAssignment | None:
    """
    Return a SafeAssignment if `line_text` is exactly a simple
    `NAME = "secret_value"` (or `'secret_value'`) statement and nothing
    more elaborate -- otherwise None.
    """
    code = line_text.rstrip("\n\r")
    stripped = code.strip()
    if not stripped or stripped.startswith("#"):
        return None

    try:
        tree = ast.parse(stripped, mode="exec")
    except SyntaxError:
        return None

    if len(tree.body) != 1:
        return None

    node = tree.body[0]
    if not isinstance(node, ast.Assign):
        return None
    if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
        return None

    value_node = node.value
    if not (isinstance(value_node, ast.Constant) and isinstance(value_node.value, str)):
        return None
    if value_node.value != secret_value:
        return None

    var_name = node.targets[0].id
    indent = code[: len(code) - len(code.lstrip(" \t"))]

    # Figure out which quote character the original source actually
    # used, so the rewritten line stays stylistically consistent-ish
    # (not load-bearing, just tidy -- default to double quotes).
    quote = '"'
    eq_index = stripped.find("=")
    if eq_index != -1:
        rhs = stripped[eq_index + 1 :].lstrip()
        if rhs[:1] == "'":
            quote = "'"

    return SafeAssignment(indent=indent, var_name=var_name, quote=quote, value=value_node.value)


def suggest_env_var_name(var_name: str) -> str:
    """
    Turn a Python identifier into a reasonable environment variable
    name: `api_key` -> `API_KEY`, `OPENAI_API_KEY` -> unchanged, etc.
    """
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", var_name).strip("_").upper()
    return cleaned or "SECRET_KEY"


_IMPORT_OS_RE = re.compile(r"^\s*import\s+os(\s*,.*)?\s*(#.*)?$", re.MULTILINE)
_IMPORT_OS_AS_RE = re.compile(r"^\s*import\s+os\s+as\s+\w+\s*(#.*)?$", re.MULTILINE)


def has_import_os(source: str) -> bool:
    """True if `os` is already imported in a way that supports `os.getenv`."""
    return bool(_IMPORT_OS_RE.search(source)) and not bool(_IMPORT_OS_AS_RE.match(source))


def insert_import_os(source: str) -> str:
    """
    Insert `import os` near the top of the file if it isn't already
    present in a usable form. Preserves a leading shebang and/or PEP
    263 encoding declaration line, if present.
    """
    if has_import_os(source):
        return source

    lines = source.splitlines(keepends=True)
    insert_at = 0
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    if len(lines) > insert_at and re.match(r"^#.*coding[:=]", lines[insert_at]):
        insert_at += 1

    lines.insert(insert_at, "import os\n")
    return "".join(lines)


def build_getenv_line(indent: str, var_name: str, env_key: str, quote: str = '"') -> str:
    return f"{indent}{var_name} = os.getenv({quote}{env_key}{quote})\n"


# Extensions for which Auto-Fix source transformation is supported.
# Static *scanning* covers far more languages than this -- only the
# automatic rewrite is restricted, deliberately, per the "detect
# aggressively, modify conservatively" principle.
SUPPORTED_FIX_EXTENSIONS = {".py"}

_LANGUAGE_NAMES = {
    ".js": "JavaScript",
    ".jsx": "JavaScript (JSX)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (TSX)",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".json": "JSON",
    ".jsonc": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".ini": "INI",
    ".cfg": "CFG",
    ".conf": "CONF",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".ps1": "PowerShell",
    ".bat": "Batch",
    ".cmd": "Batch",
    ".xml": "XML",
    ".md": "Markdown",
    ".txt": "text",
    ".sql": "SQL",
    ".graphql": "GraphQL",
    ".gql": "GraphQL",
}


def language_name_for(suffix: str, filename: str = "") -> str:
    if filename.startswith(".env"):
        return "env files"
    return _LANGUAGE_NAMES.get(suffix.lower(), suffix.lstrip(".") or "this file type")
