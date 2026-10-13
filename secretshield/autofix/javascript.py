"""
JavaScript/TypeScript-specific Auto-Fix logic, mirroring python.py's
discipline for the same reason: detect aggressively, modify
conservatively.

There's no JS/TS parser in the standard library, and adding one as a
dependency would go against SecretShield's "no unnecessary
dependencies" policy -- so safety is determined with a deliberately
narrow regex instead of a real AST. Anything that isn't unambiguously
a single `const`/`let`/`var` declaration assigned a *plain* string
literal is treated as ambiguous and left untouched: object/array
literals, string concatenation, template-literal interpolation
(`` `Bearer ${token}` ``), function-call arguments, and multi-declarator
lines (`const a = "x", b = "y";`) are all deliberately rejected, the
same way headers-dict assignments are rejected for Python.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Naming heuristic is language-agnostic -- reuse it rather than
# duplicating it.
from .python import suggest_env_var_name  # noqa: F401  (re-exported)

__all__ = ["SafeAssignment", "find_safe_assignment", "build_getenv_line", "suggest_env_var_name"]


@dataclass
class SafeAssignment:
    indent: str
    export_prefix: str
    keyword: str
    var_name: str
    type_annotation: str
    value: str
    has_semicolon: bool


# Matches (optionally exported) `const`/`let`/`var NAME[: Type] = "value"[;]`
# on a single line, with nothing else on that line besides an optional
# trailing `//` comment. The type-annotation group is intentionally
# permissive (it's cosmetic to the fix, not load-bearing for safety) --
# what actually gates safety is that the *value* must be a complete,
# non-interpolated string literal filling the entire right-hand side.
_ASSIGNMENT_RE = re.compile(
    r"""^(?P<indent>[ \t]*)
        (?P<export>export\s+)?
        (?P<keyword>const|let|var)\s+
        (?P<name>[A-Za-z_$][A-Za-z0-9_$]*)
        (?P<type>\s*:\s*[A-Za-z_$][A-Za-z0-9_$<>\[\].,\s|&]*?)?
        \s*=\s*
        (?P<quote>['"`])
        (?P<value>(?:\\.|(?!(?P=quote)).)*)
        (?P=quote)
        (?P<semi>\s*;)?
        \s*(?://.*)?$
    """,
    re.VERBOSE,
)


def find_safe_assignment(line_text: str, secret_value: str) -> SafeAssignment | None:
    code = line_text.rstrip("\n\r")
    stripped = code.strip()
    if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
        return None

    match = _ASSIGNMENT_RE.match(code)
    if not match:
        return None

    quote = match.group("quote")
    value = match.group("value")

    # A template literal containing `${...}` is interpolated, not a
    # plain string -- e.g. `` `Bearer ${token}` `` -- so it's ambiguous.
    if quote == "`" and "${" in value:
        return None

    if value != secret_value:
        return None

    return SafeAssignment(
        indent=match.group("indent"),
        export_prefix=match.group("export") or "",
        keyword=match.group("keyword"),
        var_name=match.group("name"),
        type_annotation=match.group("type") or "",
        value=value,
        has_semicolon=bool(match.group("semi")),
    )


def build_getenv_line(safe: SafeAssignment, env_key: str, is_typescript: bool) -> str:
    """
    `process.env["KEY"]` (bracket notation, so it's valid regardless of
    whether KEY happens to be a legal bare identifier). On TypeScript,
    `process.env[...]` is typed `string | undefined`; a trailing `!`
    non-null assertion keeps the rewritten line type-compatible with
    whatever annotation (if any) the original declaration had, instead
    of silently introducing a type error.
    """
    non_null = "!" if is_typescript else ""
    semi = ";" if safe.has_semicolon else ""
    return (
        f'{safe.indent}{safe.export_prefix}{safe.keyword} {safe.var_name}'
        f'{safe.type_annotation} = process.env["{env_key}"]{non_null}{semi}\n'
    )
