<div align="center">

# 🛡️ SecretShield

**Your secrets shouldn't end up in your terminal, your logs, or your commit history.**
**SecretShield makes sure they don't — automatically.**

[![PyPI version](https://img.shields.io/pypi/v/secretshield?color=blue)](https://pypi.org/project/secretshield/)
[![Python versions](https://img.shields.io/pypi/pyversions/secretshield)](https://pypi.org/project/secretshield/)
[![PyPI downloads](https://img.shields.io/pypi/dm/secretshield)](https://pypi.org/project/secretshield/)
[![License: MIT](https://img.shields.io/pypi/l/secretshield)](LICENSE)

[Install](#installation) · [Demo](#demo) · [Quick start](#quick-start) · [Features](#what-secretshield-does) · [Docs below](#cli-reference)

</div>

---

## The problem

You've done this. Everyone has.

```python
print("API key:", api_key)          # ...now it's in your terminal history
logger.info("Token: %s", token)     # ...now it's in your log files
API_KEY = "sk-live-abc123..."       # ...now it's about to get committed
```

One `print()` left in from debugging. One log line that dumps a config
dict. One hardcoded key that slips past code review. That's usually all
it takes.

## The fix

```bash
pip install secretshield
```

```python
import secretshield

api_key = "sk-example1234567890abcdefFAKEKEY"
print("API key:", api_key)
```

```text
API key: ********
⚠ secretshield: Potential secret detected and redacted.
```

**No configuration. No code changes. Just `pip install` and `import`.**
The moment you import it, your terminal output, your logs — protected.

## Demo

See SecretShield in action:

[![SecretShield Demo](https://img.youtube.com/vi/g95lNIhWsXM/maxresdefault.jpg)](https://youtu.be/g95lNIhWsXM)

**[▶ Watch the full demo on YouTube](https://youtu.be/g95lNIhWsXM)**

## Quick start

```bash
pip install secretshield
```

Protect a running script:
```python
import secretshield   # that's it — stdout, stderr, and logging are now protected
```

Scan an entire project for hardcoded secrets:
```bash
secretshield scan .
```

Set a whole project up in one step (config file + Git hook + CI):
```bash
secretshield init
```

> Typing `secretshield` a lot? Every command also works with the short
> alias `ss` — `ss scan .`, `ss init`, `ss --fix`, all identical to
> their `secretshield` equivalents.

## What SecretShield does

SecretShield isn't just one trick — it's five layers that cover the
whole path a secret takes from your keyboard to a place you can't take
it back from:

| | |
|---|---|
| 🖥️ **Runtime protection** | Automatically redacts secrets from `stdout`, `stderr`, and `logging` the instant you `import secretshield` |
| 🔍 **Static scanning** | `secretshield scan .` finds hardcoded secrets across Python, JS/TS, HTML, YAML, `.env`, and more |
| 🔧 **Auto-Fix** | `scan . --fix` interactively moves a hardcoded secret into `.env` and rewrites your code to use it — safely, and only when it's unambiguous |
| 🪝 **Git pre-commit hook** | `install-hook` blocks a commit before a secret ever reaches your repo's history |
| ⚙️ **GitHub Actions** | `github-action` generates a workflow that scans every push and PR automatically |

All of it: **zero required dependencies, no telemetry, no network calls, nothing sent anywhere.** Everything happens locally, in your own process.

## Why star this repo

If SecretShield has ever caught something before it hit your terminal
or your Git history — that's the whole point of the project working.
Starring it costs nothing and helps the next developer who's about to
`print()` an API key by accident actually find this before it's too
late.

---

## Installation

```bash
pip install secretshield
```

Requires Python 3.10+. No required third-party runtime dependencies
(a tiny `tomli` backport is pulled in automatically, but only on Python 3.10).

## Basic usage

```python
import secretshield

password = "hunter2-example-not-real"
print("Using password:", password)
```

```text
Using password: ********
⚠ secretshield: Potential secret detected and redacted.
```

Toggle protection manually if you need to:

```python
import secretshield

secretshield.disable()
secretshield.enable()      # idempotent, safe to call repeatedly
secretshield.is_enabled()
```

Or use detection/redaction directly, without touching stdout at all:

```python
from secretshield import detect, redact

detect("aws_key=AKIAABCDEFGHIJKLMNOP")
# [Match(start=8, end=28, value='AKIA...', kind='aws_access_key_id')]

redact("aws_key=AKIAABCDEFGHIJKLMNOP")
# ("aws_key=********", True)
```

## CLI reference

*(Every command below also works via the shorter `ss` alias — `ss scan .` is identical to `secretshield scan .`.)*

### `secretshield init` — set a project up in one step

```bash
secretshield init
```

Detects your project, then interactively offers to create a config
file, install the Git hook, and generate the GitHub Actions workflow —
all in one pass instead of discovering each command separately.

### `secretshield scan` — find hardcoded secrets

```bash
secretshield scan .                       # scan a directory
secretshield scan app.py                  # scan a single file
secretshield scan . --json                # machine-readable, CI-safe
secretshield scan . --fix                 # interactively move secrets to .env
secretshield scan --staged                # would this commit introduce a secret?
secretshield scan --diff HEAD~1           # did my changes introduce a secret?
secretshield scan . --baseline            # adopt SecretShield without fixing everything today
```

Scans Python, JavaScript/TypeScript, HTML, CSS, Vue, Svelte, JSON,
YAML, TOML/INI, `.env` files, shell scripts, and more — treating each
as text and running the same detection engine regardless of language.
Automatically skips `.git/`, `node_modules/`, `.venv/`, binary files,
and obvious documentation placeholders like `your_api_key_here`.

```text
SecretShield scan

✗ src/app.js:82
  Potential secret: Bearer token
  Type: token

✓ 143 files scanned
✗ 1 potential secret(s) found

Exit code: 1
```

### `secretshield run` — protect a script without editing it

```bash
secretshield run app.py
```

### `secretshield install-hook` / `uninstall-hook` — stop secrets before they're committed

```bash
secretshield install-hook
```

Scans **staged content** (not your whole working tree) before every
commit and blocks it if something looks like a secret. Never destroys
an existing pre-commit hook — backs it up and wraps it instead.

### `secretshield github-action` — catch what slips past locally

```bash
secretshield github-action
```

Generates `.github/workflows/secretshield.yml`, scanning every push and
pull request automatically.

## Configuration file

Project-wide scan settings live in `secretshield.toml` (generate one
with `secretshield init`):

```toml
[scan]
entropy_threshold = 4.2

[scan.ignore]
paths = ["tests/fixtures/", "docs/examples/"]

[scan.include]
patterns = ["*.py", "*.js"]

[output]
format = "text"
```

CLI flags always override the file.

## Runtime configuration

```python
import secretshield

secretshield.configure(
    enabled=True,             # master on/off switch
    redact_with="********",   # placeholder used in place of a secret
    entropy_threshold=4.2,    # bits/char threshold for generic detection
    notify=True,              # print the "potential secret" warning
)
```

## Detection methods

SecretShield combines two strategies:

1. **Known-format pattern matching** — AWS keys, GitHub tokens,
   OpenAI-style keys, Slack tokens, Stripe keys, Google API keys, JWTs,
   bearer tokens, PEM private-key blocks, and labeled generic secrets
   (`password =`, `api_key:`, etc.)
2. **High-entropy detection** — catches random-looking secrets that
   don't match a known format, used as a conservative supplement (not
   the primary mechanism) to keep false positives low.

## Architecture

```text
secretshield/
├── patterns.py, detector.py, redactor.py   # detection & redaction engine
├── guardian.py                              # stdout/stderr + logging protection
├── config.py, notifications.py               # runtime settings & safe warnings
├── project_config.py, baseline.py              # secretshield.toml, --baseline
├── cli.py                                        # command-line interface
├── autofix/                                        # interactive scan --fix
├── git/                                              # pre-commit hook
└── github/                                             # Actions workflow generation
```

## Testing

```bash
pip install -e ".[dev]"
pytest
```

176+ tests covering detection, redaction, runtime protection, static
scanning across languages, Auto-Fix, Git hooks, and CI integration. All
secrets used in tests and examples are fake.

## Limitations

Be honest about what this is and isn't:

- Runtime protection covers **this Python process's** `stdout`,
  `stderr`, and `logging` — not screenshots, clipboard, arbitrary file
  writes, other applications, or network traffic.
- **Auto-Fix (`--fix`)** only rewrites Python, and only unambiguous
  simple assignments (checked via Python's own `ast` module, not a
  regex). Anything less certain is reported but left untouched.
- The pre-commit hook needs `secretshield` resolvable on `PATH` at
  commit time — keep your virtual environment active.

Treat SecretShield as a strong defense-in-depth safety net, not a
replacement for proper secret management (vaults, least-privilege
credentials, secret scanning in CI, etc.).

## Security considerations

No network calls. No telemetry. Nothing sent anywhere — detection and
redaction happen entirely locally, in-process.

## Contributing

Issues and PRs welcome. Please add tests for new detection patterns or
behavior changes, use only fake credentials in tests/examples, and run
`pytest` before opening a PR.

## [☕](https://github.com/sponsors/Sam3360/) Get me a coffee

If you find this project useful, consider [supporting its development through GitHub Sponsors](https://github.com/sponsors/Sam3360/).

## License

MIT — see [LICENSE](LICENSE).
