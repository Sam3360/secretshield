# SecretShield — Usage Guide 

This is the detailed manual for SecretShield. For a quick overview,
see [`README.md`](README.md).

- [Installation](#installation)
- [Runtime protection](#runtime-protection)
- [CLI](#cli)
- [Scanning](#scanning)
- [Auto-Fix](#auto-fix)
- [Git hooks](#git-hooks)
- [GitHub Actions](#github-actions)
- [Configuration](#configuration)
- [Detection](#detection)
- [Limitations](#limitations)
- [Testing / development](#testing--development)

## Installation

```bash
pip install secretshield
```

Requires Python 3.10+. No required third-party runtime dependencies on
Python 3.11+. On Python 3.10, a small `tomli` backport is installed
automatically (it's only needed there because `tomllib` isn't in the
standard library until 3.11 — it's used to read `secretshield.toml`).

## Runtime protection

Importing the package protects `sys.stdout`, `sys.stderr`, and the
standard `logging` module for the rest of the process:

```python
import secretshield

api_key = "sk-example1234567890abcdefFAKEKEY"
print("API key:", api_key)
```

```text
API key: ********
⚠ secretshield: Potential secret detected and redacted.
```

This works the same way for `logging`, whether the secret is passed as
a `%s`-style argument or already interpolated into the message:

```python
import logging
logger = logging.getLogger(__name__)

logger.warning("Token: %s", token)          # redacted
logger.warning(f"Token: {token}")           # also redacted
```

### Enabling / disabling

```python
import secretshield

secretshield.disable()      # turn protection off
secretshield.enable()       # turn it back on
secretshield.is_enabled()   # -> True / False
```

`enable()`/`disable()` are safe to call repeatedly and always act on
whatever `sys.stdout`/`sys.stderr` currently are — so they behave
correctly even if something else (a test framework's output capture,
your own redirection) has swapped those streams out since the last
call.

### `configure()`

```python
secretshield.configure(
    enabled=True,             # master on/off switch
    redact_with="********",   # placeholder used in place of a secret
    entropy_threshold=4.2,    # bits/char threshold for generic detection
    notify=True,              # print the "potential secret" warning
)
```

Sensible defaults mean most projects need zero configuration.

### `detect()` / `redact()`

Use the detection engine directly, without touching any stream:

```python
from secretshield import detect, redact

detect("aws_key=AKIAABCDEFGHIJKLMNOP")
# [Match(start=8, end=28, value='AKIA...', kind='aws_access_key_id')]

redact("aws_key=AKIAABCDEFGHIJKLMNOP")
# ("aws_key=********", True)
```

`detect()` returns a list of `Match` objects (`start`, `end`, `value`,
`kind`). `redact()` returns `(new_text, was_redacted)`.

## CLI

Every command below also works via the shorter `ss` alias — `ss` and
`secretshield` are registered as separate console scripts pointing to
the exact same entry point, so `ss scan .` behaves identically to
`secretshield scan .` in every respect.

```text
secretshield --version
secretshield --creator
```

### `secretshield init`

```bash
secretshield init
```

Interactive setup wizard. Detects whether the current directory looks
like a Python project and whether it's a Git repository, then offers
to:

- create a `secretshield.toml` (if one doesn't already exist)
- install the Git pre-commit hook (skipped automatically if not in a
  Git repo)
- generate the GitHub Actions workflow

Requires a real interactive terminal. In a non-interactive environment
(CI, a piped session) it prints a message and exits without making any
changes or prompting.

### `secretshield scan`

```bash
secretshield scan .                       # scan a directory (default: ".")
secretshield scan app.py                  # scan a single file
secretshield scan . --json                # machine-readable output
secretshield scan . --fix                 # interactively move secrets to .env
secretshield scan --staged                # scan Git-staged content
secretshield scan --diff HEAD~1           # scan files changed since a ref
secretshield scan . --baseline            # write/refresh the baseline file
```

Flags:

| Flag | What it does |
|---|---|
| `--entropy-threshold FLOAT` | Shannon entropy threshold for generic detection (default `4.2`, or the value from `secretshield.toml` if present) |
| `--json` | Machine-readable JSON output |
| `--include PATTERN` | Only scan files matching this glob (filename or relative path). Repeatable. |
| `--exclude PATTERN` | Skip files matching this glob. Repeatable. Always wins over `--include`. |
| `--no-ignore` | Don't skip the default-ignored directories (see below) |
| `--fix` | Interactive Auto-Fix (see [Auto-Fix](#auto-fix)) |
| `--staged` | Scan Git *index* content instead of a path — "would this commit introduce a secret?" |
| `--diff REF` | Scan the current on-disk content of files changed relative to `REF` — "did my changes introduce a secret?" |
| `--baseline` | Write (or overwrite) `.secretshield-baseline.json` from the current findings |

Exit codes: `0` — no findings; `1` — findings present; `2` — a
scanner/environment error (e.g. `--staged`/`--diff` used outside a Git
repository).

`--staged` and `--diff` both require running inside a Git repository.

### `secretshield run`

```bash
secretshield run app.py [args...]
```

Runs a Python script with runtime protection enabled, without needing
to add `import secretshield` to the script itself.

### `secretshield install-hook` / `uninstall-hook`

```bash
secretshield install-hook [--force]
secretshield uninstall-hook
```

See [Git hooks](#git-hooks).

### `secretshield github-action`

```bash
secretshield github-action [--force]
```

See [GitHub Actions](#github-actions).

### Color output

Scan output uses red `✗` / green `✓` automatically when connected to a
real terminal. It's plain text everywhere else — piped output, CI
logs, and `--json` are never colored. Override either direction with
the standard environment variables:

```bash
NO_COLOR=1 secretshield scan .        # force color off, even in a terminal
FORCE_COLOR=1 secretshield scan .     # force color on, even when piped
```

If both are set, `NO_COLOR` wins.

## Scanning

`secretshield scan` treats every file as plain text and runs the same
detection engine regardless of language — there's no separate parser
per file type.

**Extensions scanned by default:** `.py`, `.js`/`.jsx`/`.ts`/`.tsx`,
`.html`/`.htm`, `.css`/`.scss`, `.vue`, `.svelte`, `.json`/`.jsonc`,
`.yaml`/`.yml`, `.toml`, `.ini`/`.cfg`/`.conf`, `.sh`/`.bash`/`.zsh`,
`.ps1`/`.bat`/`.cmd`, `.xml`, `.md`/`.txt`, `.sql`, `.graphql`/`.gql`.
`.env` and `.env.*` files are always scanned regardless of extension.
Extensionless files (`Dockerfile`, `Makefile`, etc.) are scanned as
long as they're actually text, checked by sniffing for a null byte or
invalid UTF-8 in the first 1 KB.

**Skipped by default:** `.git/`, `__pycache__/`, `node_modules/`,
`.venv/`, `venv/`, `dist/`, `build/`, `coverage/`, `.pytest_cache/`,
`.mypy_cache/`, `.tox/`, and `egg-info` directories, plus any file that
looks binary. Use `--no-ignore` to scan these directories too (binary
files are always skipped regardless).

**Placeholders are filtered out automatically** — values like
`your_api_key_here`, `changeme`, `xxxxxxxx`, `fake-key`, `test-token`
and similar are recognized and not reported, so obvious documentation
examples don't create noise.

**Example output:**

```text
SecretShield scan

✗ src/app.js:82
  Potential secret: Bearer token
  Type: token

✓ 143 files scanned
✗ 1 potential secret(s) found

Exit code: 1
```

A live `Scanning... N files scanned` line is shown on stderr while a
scan runs, but only in an interactive terminal — never in CI logs or
`--json` output.

## Auto-Fix

```bash
secretshield scan . --fix
```

For each detected secret, SecretShield asks whether to move it into a
local `.env` file:

```text
Secret 1/1 detected
File: app.py
Line: 5
Detected value: ********

Would you like me to move this secret to a local .env file automatically? [y/N]
```

If you confirm, you're asked for an environment variable name (with a
suggested default derived from the variable name), and:

```python
API_KEY = "actual-secret-value"
```

becomes:

```python
import os

API_KEY = os.getenv("API_KEY")
```

with the real value appended to `.env` (created if it doesn't exist,
and never overwritten — only ever appended to), `.gitignore` updated
to exclude `.env` if it isn't already covered, and `.env.example`
updated with a blank placeholder (`API_KEY=`, never the real value).

**Supported languages: Python, JavaScript, TypeScript, JSX, TSX.**
Nothing else is auto-rewritten (though `scan` without `--fix` still
detects secrets in every language it supports — only the automatic
rewrite is limited). For an unsupported file, SecretShield reports the
finding and explains that automatic fixing isn't supported for that
language; no changes are made.

**What counts as "safe" to auto-fix:** a line that is unambiguously a
single variable assignment to a plain string literal — nothing else.
For Python, this is checked with Python's own `ast` module (not a
regex), so what actually gets rewritten is exactly `NAME = "value"` or
`NAME = 'value'`. For JavaScript/TypeScript, a comparably narrow parser
built for this purpose accepts `const`/`let`/`var NAME = "value"`
(optionally `export`ed, optionally type-annotated). On TypeScript, the
rewritten line gets a trailing `!` non-null assertion so it stays
type-compatible with `process.env`'s `string | undefined` type.

Anything less certain is left untouched and reported as such:

```text
Secret detected, but SecretShield could not safely determine how to
replace it automatically.

No changes were made.
```

This includes: a value inside a dict/object literal
(`headers={"Authorization": "Bearer " + token}`), an f-string or
template-literal interpolation, a function-call argument, or more than
one variable assigned on the same line.

**Safety mechanics:**

- The detected value is never printed — only a full `********` mask,
  regardless of the secret's length or shape.
- Each fix is validated immediately after being written: the secret
  must be gone from the source and present in `.env`. If validation
  fails, that file is rolled back to its original content rather than
  left half-modified.
- `--fix` only prompts in a real interactive terminal. In CI or any
  other non-interactive environment, it prints a notice and makes no
  changes — it never hangs waiting for input.
- Multiple secrets (across one or more files) are handled one at a
  time, with a running `Secret N/M detected` count and a summary at
  the end listing what was fixed, skipped, and which files were
  touched.

## Git hooks

```bash
secretshield install-hook [--force]
```

Installs a `pre-commit` hook that scans **staged content** — the
actual Git index blob, not whatever happens to be on disk, so it's
still correct if a file is only partially staged. If a secret is
found, the commit is blocked:

```text
SecretShield: scanning staged files...

✗ Potential secret detected

File: config.py
Line: 14
Type: API token

Commit blocked.

Remove the secret from the staged changes and try again.
```

If a `pre-commit` hook already exists and wasn't installed by
SecretShield, it's never overwritten: the original is backed up to
`pre-commit.secretshield-backup` and a new hook is written that runs
the backup first, then SecretShield's own check — both have to pass.

```bash
secretshield uninstall-hook
```

Removes SecretShield's hook. If it had wrapped an existing hook, that
original hook is restored from the backup; if SecretShield installed a
fresh hook (nothing to wrap), it's simply removed. Uninstall refuses to
touch a hook it didn't install itself.

**PATH requirement:** the hook shells out to the `secretshield` command
by name (`secretshield scan-staged`). If you installed SecretShield
inside a virtual environment, that environment needs to be active — or
`secretshield` otherwise resolvable on `PATH` — whenever you run
`git commit`, or the hook itself will fail to run rather than silently
skip the scan.

## GitHub Actions

```bash
secretshield github-action [--force]
```

Writes `.github/workflows/secretshield.yml`. Won't overwrite an
existing workflow file unless `--force` is passed. The generated
workflow runs on every `push` and `pull_request`, installs
SecretShield via `pip install secretshield`, and runs
`secretshield scan .`, failing the check if a potential secret is
found.

## Configuration

### `secretshield.toml`

Project-wide scan settings, read automatically from the current
directory:

```toml
[scan]
entropy_threshold = 4.2

[scan.ignore]
paths = [
    "tests/fixtures/",
    "docs/examples/",
]

[scan.include]
patterns = [
    "*.py",
    "*.js",
]

[output]
format = "text"
```

`secretshield init` can generate a starting file for you.

### `.secretshieldignore`

A `.gitignore`-style alternative (or companion) to
`[scan.ignore]`, for anyone who'd rather drop in a plain ignore file:

```text
# .secretshieldignore
vendor/
*.min.js
tests/fixtures/
```

One glob pattern per line; blank lines and `#` comments are skipped. A
trailing `/` means "this path and everything under it" — the same
convention `secretshield.toml`'s `[scan.ignore].paths` uses.

### How they interact

`secretshield.toml`'s `[scan.ignore].paths` and `.secretshieldignore`
combine — both are read, and their patterns are unioned with any
`--exclude` flags. **Explicit CLI flags always take precedence** over
the config file: `--json` overrides `format = "text"`, and
`--entropy-threshold 3.0` overrides whatever `secretshield.toml` says.

## Detection

Two strategies, combined:

**1. Known-format pattern matching.** Regexes tuned to the shape of
specific credential formats: AWS access keys, GitHub tokens,
OpenAI-style keys, Slack tokens, Stripe keys, Google API keys, JWTs,
Bearer tokens, PEM-style private-key blocks, and generic
`label = value` pairs where the label looks like `api_key`, `secret`,
`token`, `password`, etc.

**2. High-entropy detection.** A Shannon-entropy check over long,
non-dictionary-like character runs, used as a *supplement* to catch
random-looking secrets that don't match a known format — not the
primary mechanism, since entropy alone produces far more false
positives (hashes, UUIDs, encoded binary data) than pattern matching
does.

```python
from secretshield import detect

detect('password = "MyDogFluffy99"')
# [Match(..., kind='generic_labeled_secret')]

detect('aX9pQ2zM7vL0rT4wK8yB1nD6fH3jC5sE')
# [Match(..., kind='high_entropy')]
```

## Limitations

- Runtime protection covers **this Python process's** `stdout`,
  `stderr`, and `logging` — not screenshots, the clipboard, arbitrary
  file writes, other applications, or network traffic.
- Auto-Fix only rewrites Python, JavaScript, TypeScript, JSX, and TSX,
  and only lines that are unambiguously a single string-literal
  assignment. Anything less certain is reported but left untouched —
  see [Auto-Fix](#auto-fix) above.
- The pre-commit hook needs `secretshield` resolvable on `PATH` at
  commit time.
- Detection is heuristic. It can produce false negatives (a real
  secret in an unusual format slips through) and, more rarely, false
  positives (something that merely looks like a secret gets flagged).

Treat SecretShield as a defense-in-depth safety net for accidental
exposure during development — not a replacement for proper secret
management (vaults, least-privilege credentials, secret scanning in
CI, `.gitignore` discipline, etc.).

## Testing / development

```bash
git clone https://github.com/Sam3360/secretshield.git
cd secretshield
pip install -e ".[dev]"
pytest
```

All secrets used in the test suite and examples are fake. Please add
tests for any new detection pattern or behavior change, and keep using
fake credentials only in tests/examples/PRs.
