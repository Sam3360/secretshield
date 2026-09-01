🛡️ SecretShield

<p align="center">
  <strong>Catch secrets before they hit your terminal, logs, commits, or CI.</strong><br>
  A local, dependency-free Python security utility for detecting and redacting credential-shaped data.
</p>

<p align="center">
  <a href="https://pypi.org/project/secretshield/"><img src="https://img.shields.io/pypi/v/secretshield?style=for-the-badge&label=PyPI" alt="PyPI"></a>
  <a href="https://github.com/Sam3360/secretshield"><img src="https://img.shields.io/github/stars/Sam3360/secretshield?style=for-the-badge&logo=github" alt="GitHub stars"></a>
  <a href="https://github.com/Sam3360/secretshield/actions"><img src="https://img.shields.io/github/actions/workflow/status/Sam3360/secretshield/secretshield.yml?style=for-the-badge&label=CI" alt="GitHub Actions"></a>
  <img src="https://img.shields.io/pypi/pyversions/secretshield?style=for-the-badge" alt="Python versions">
  <img src="https://img.shields.io/github/license/Sam3360/secretshield?style=for-the-badge" alt="MIT License">
</p>

⚡ What is SecretShield?

secretshield is a local Python security utility that detects likely secrets — API keys, tokens, passwords, private keys, and other credential-shaped strings — and redacts them before they are printed through Python's stdout, stderr, or standard logging system.

It also works as a static scanner, interactive auto-fixer, Git pre-commit guard, and GitHub Actions CI check.

The idea

                         SECRET
                           │
              ┌────────────┴────────────┐
              │                         │
        Running Python              Source code
              │                         │
       stdout / stderr             secretshield scan
          / logging                      │
              │                    ┌─────┴─────┐
              ▼                    │           │
       🛡️ REDACT IT              Report      --fix
                                   │           │
                                   │      Move to .env
                                   │
                              CI / Git hook

One tool. Multiple layers of protection.

✨ Features

Feature

What it does

🛡️ Runtime protection

Redacts likely secrets from stdout, stderr, and logging while your Python app runs

🔎 Static scanning

Scans source/config files without executing or importing them

🔧 --fix auto-repair

Interactively moves safely-detectable Python assignments into .env

🪝 Git pre-commit hook

Scans the exact staged contents before every commit

🤖 GitHub Actions

Runs secret scanning automatically on pushes and pull requests

🧠 Pattern detection

Recognizes common credential formats

📈 Entropy detection

Catches random-looking secrets that do not match known formats

📄 JSON output

Machine-readable scan results for CI and automation

🎛️ Configurable

Enable/disable protection and tune redaction + entropy settings

🔌 Dependency-free

No third-party runtime dependencies

🔒 Local-only

No network calls and no telemetry

🚀 Installation

Requires Python 3.10+.

pip install secretshield

For local development:

pip install -e ".[dev]"

No third-party runtime dependencies are required.

🛡️ Runtime Protection

Protection for Python's stdout, stderr, and logging is enabled when SecretShield is imported.

import secretshield

api_key = "sk-example1234567890abcdefFAKEKEY"

print("API key:", api_key)

Instead of exposing the value:

API key: ********
⚠ secretshield: Potential secret detected and redacted.

The real secret value is not included in SecretShield's warning messages or exceptions.

Toggle protection

import secretshield

secretshield.disable()

# protection is off

secretshield.enable()

# protection is back on

secretshield.is_enabled()

enable() and disable() are safe to call repeatedly.

🔎 Detect & Redact Text Directly

You can use the detection engine without routing text through a terminal or logger.

from secretshield import detect, redact

matches = detect("aws_key=AKIAABCDEFGHIJKLMNOP")

safe_text, was_redacted = redact(
    "aws_key=AKIAABCDEFGHIJKLMNOP"
)

detect() returns match information, while redact() gives you the sanitized text and whether anything was changed.

🔍 Static Scanning

Scan a project:

secretshield scan .

Or a single file:

secretshield scan path/to/file.py

Scan a source directory and return JSON:

secretshield scan src/ --json

Important difference

scan is static analysis.

It does not execute or import the files it scans.

┌─────────────────────────────────────┐
│           secretshield scan         │
├─────────────────────────────────────┤
│ Source / config files               │
│            │                        │
│            ▼                        │
│     Detection engine                │
│            │                        │
│      ┌─────┴─────┐                  │
│      ▼           ▼                  │
│   Safe ✓      Secret ✗              │
└─────────────────────────────────────┘

By default, common non-source directories such as .git, node_modules, virtual environments, build directories, and caches are skipped. Binary files are also ignored automatically.

Supported file types

SecretShield can scan common:

Python

JavaScript / JSX

TypeScript / TSX

HTML

CSS / SCSS

Vue

Svelte

JSON / JSONC

YAML

TOML / INI / CFG / CONF

.env and .env.*

Shell scripts (.sh, .bash, .zsh)

Windows scripts (.ps1, .bat, .cmd)

XML

Markdown / plain text

SQL

GraphQL

Extensionless text files such as Dockerfile and Makefile

Example

SecretShield scan

✗ src/app.js:82
  Potential secret: Bearer token
  Type: token

✓ 143 files scanned
✗ 1 potential secret(s) found

Exit code: 1

When nothing is found:

SecretShield scan

✓ 143 files scanned
✓ No potential secrets found

Exit code: 0

🧰 Scan Options

Option

Purpose

--json

Machine-readable JSON output

--include PATTERN

Only scan files matching a glob pattern

--exclude PATTERN

Exclude matching files; overrides includes and defaults

--no-ignore

Scan directories normally skipped by default

--entropy-threshold FLOAT

Tune generic high-entropy detection; default is 4.2

--fix

Start the interactive repair flow

--include and --exclude can be repeated.

JSON output

{
  "files_scanned": 143,
  "matches": [
    {
      "file": "src/app.js",
      "line": 82,
      "kind": "bearer_token"
    }
  ],
  "secrets_found": 1
}

JSON output is safe for CI because it contains locations and secret types, not secret values or surrounding source text.

Exit codes

0 → no potential secrets found
1 → one or more potential secrets found

That makes scan suitable for automated security gates.

🔧 Auto-Fix with --fix

Found a secret in your Python source?

Instead of manually moving it, try:

secretshield scan . --fix

SecretShield adds an interactive repair step to the normal scan.

Example:

Secret 1/1 detected
File: app.py
Line: 5
Detected value: ********

Would you like me to move this secret to a local .env file automatically? [y/N]

If you confirm, a safe simple assignment such as:

API_KEY = "actual-secret-value"

can become:

import os

API_KEY = os.getenv("API_KEY")

while the real value is moved into .env.

What --fix handles

When a fix is accepted, SecretShield:

creates .env if necessary

never overwrites existing .env content

appends new variables safely

adds .env to .gitignore if needed

updates .env.example

puts only a blank placeholder in .env.example

validates the result

rolls the source file back if validation fails

Conservative by design

--fix does not blindly rewrite code.

It only automatically rewrites Python when the secret is an unambiguous simple assignment such as:

API_KEY = "..."

More complicated cases are reported but left untouched:

config = {"api_key": "..."}

print(f"key={API_KEY}")

send_request(token="...")

And non-Python files are never automatically rewritten.

If SecretShield cannot safely determine the replacement:

Secret detected, but SecretShield could not safely determine how to
replace it automatically.

No changes were made.

CI-safe

--fix only prompts in a real interactive terminal.

In CI or another non-interactive environment:

no files are modified

SecretShield does not wait for input

the process will not hang

🪝 Git Pre-Commit Hook

Catch secrets before they become a commit.

Install the hook:

secretshield install-hook

Now every commit scans the staged file contents.

That distinction matters: SecretShield scans what you are actually committing, not merely everything sitting in your working directory.

Example:

SecretShield: scanning staged files...

✗ Potential secret detected

File: config.py
Line: 14
Type: API token

Commit blocked.

Remove the secret from the staged changes and try again.

Existing hooks are protected

If you already have a pre-commit hook, SecretShield does not simply overwrite it.

It:

backs up the existing hook

wraps it with SecretShield

runs both on future commits

can restore the original when SecretShield is removed

Uninstall:

secretshield uninstall-hook

🤖 GitHub Actions

SecretShield can generate a ready-to-use GitHub Actions workflow:

secretshield github-action

This creates:

.github/
└── workflows/
    └── secretshield.yml

The workflow installs SecretShield and runs:

secretshield scan .

on:

every push

every pull request

If a potential secret is detected, the workflow fails.

Existing workflow protection

SecretShield will not overwrite an existing secretshield.yml by default.

If you intentionally want to replace it:

secretshield github-action --force

The complete protection chain

        👨‍💻 Write code
             │
             ▼
      🛡️ Runtime Shield
             │
             ▼
       🔎 Local Scan
             │
             ▼
        🔧 --fix
             │
             ▼
        🪝 Git Hook
             │
             ▼
       📦 git commit
             │
             ▼
       ☁️ GitHub Actions
             │
        ┌────┴────┐
        ▼         ▼
       ✓ Pass    ✗ Block

🧠 How Detection Works

SecretShield combines two detection strategies.

1. Known-format pattern matching

It uses patterns tuned for credential-shaped data including:

AWS access keys

GitHub tokens

OpenAI-style keys

Slack tokens

Stripe keys

Google API keys

JWTs

Bearer tokens

PEM-style private keys

generic credential assignments such as api_key, secret, token, and password

2. Generic high-entropy detection

Some secrets do not follow a recognizable format.

SecretShield therefore also checks long, random-looking character sequences using Shannon entropy.

Entropy is intentionally a supplement rather than the primary detector because hashes, UUIDs, encoded data, and other harmless strings can also look random.

⚙️ Configuration

Most projects need no configuration.

For custom behavior:

import secretshield

secretshield.configure(
    enabled=True,
    redact_with="********",
    entropy_threshold=4.2,
    notify=True,
)

Setting

Purpose

enabled

Master runtime protection switch

redact_with

Replacement text used for detected secrets

entropy_threshold

Threshold for generic entropy detection

notify

Controls the potential-secret warning

💻 CLI

secretshield --help
secretshield --version

Run an existing script with protection

secretshield run app.py [args...]

This executes app.py as __main__ while protecting its stdout, stderr, and logging output.

Useful when you want runtime protection without editing the application source.

Scan

secretshield scan .
secretshield scan src/
secretshield scan app.py
secretshield scan . --json
secretshield scan . --fix

Git hook

secretshield install-hook
secretshield uninstall-hook

GitHub Actions

secretshield github-action
secretshield github-action --force

🏗️ Architecture

secretshield/
│
├── patterns.py              # Known secret-format patterns
├── detector.py              # Pattern + entropy detection
├── redactor.py              # Match spans → redacted text
├── config.py                # Runtime configuration
├── notifications.py         # Safe warning messages
├── guardian.py              # stdout/stderr + logging protection
├── cli.py                   # CLI entry point
│
├── autofix/
│   ├── fixer.py             # Fix orchestration + rollback
│   ├── python.py            # AST-based safe assignments
│   ├── env.py               # .env / .env.example handling
│   └── gitignore.py         # Keeps .env out of Git
│
├── git/
│   └── hooks.py             # Hook installation/removal
│
└── github/
    └── actions.py           # GitHub Actions workflow generation

Design highlights

Stream wrapping

SecretShield wraps sys.stdout and sys.stderr rather than monkey-patching print().

Reliable logging coverage

Logging protection uses logging.setLogRecordFactory, allowing SecretShield to cover both:

logger.info("token=%s", token)

and:

logger.info(f"token={token}")

across logger hierarchies.

Re-entrancy protection

SecretShield's own warning messages are protected from recursively triggering the detector.

Fail-safe behavior

Detection and redaction failures are caught so a problem inside SecretShield does not crash or block the host application.

Atomic auto-fixing

--fix validates its changes and rolls a file back if a fix cannot be safely completed.

🎥 Demo

See SecretShield in action:



▶️ Watch the full demo on YouTube

🧪 Testing

Install development dependencies:

pip install -e ".[dev]"

Run the test suite:

pytest

Tests cover:

known-token detection

entropy detection

false positives

single, multiple, and repeated secrets

multiline text

stdout

stderr

logging

%s logging arguments

f-string logging

enable/disable behavior

stream restoration

All secrets used in tests and examples are fake.

📁 Examples

The repository includes:

examples/
├── basic.py
└── logging_demo.py

Run them with:

python examples/basic.py
python examples/logging_demo.py

🔐 Security & Privacy

SecretShield is designed to stay local.

🚫 No network calls

🚫 No telemetry

🚫 No secret collection

✅ Detection happens locally

✅ Redaction happens in-process

✅ Scan output avoids printing secret values

SecretShield's own warnings and exceptions are designed not to expose the detected secret value.

⚠️ Limitations

SecretShield is a defense-in-depth safety net, not a complete security boundary.

It does not protect against every possible secret leak.

Specifically, it does not automatically prevent:

secrets appearing in screenshots or screen recordings

clipboard leaks

secrets written through arbitrary file operations

leaks from other applications or processes

all output produced directly by subprocesses

network transmission of secrets

every possible obfuscated or unusual secret format

Detection is heuristic, so false positives and false negatives are possible.

Use SecretShield alongside proper secret management, environment isolation, .gitignore discipline, CI scanning, and least-privilege credentials.

⚠️ One Important Hook Note

The Git pre-commit hook invokes:

secretshield

by name.

If SecretShield was installed inside a virtual environment, make sure that environment is active — or that the command is otherwise available on PATH — when running git commit.

Otherwise the hook may fail to run instead of silently skipping the scan.

🤝 Contributing

Issues and pull requests are welcome.

When contributing:

Add tests for new detection patterns or behavior changes.

Use only fake credentials in tests, examples, and documentation.

Keep the standard-library-only runtime dependency policy unless there is a strong reason to change it.

Run pytest before opening a pull request.

📜 License

MIT — see LICENSE.

☕ Support SecretShield

If SecretShield is useful to you, consider supporting its development.

<p align="center">
  <a href="https://github.com/sponsors/Sam3360">
    <strong>☕ Get me a coffee →</strong>
  </a>
</p>

<p align="center">
  Built with Python · Designed for developers · Made to catch secrets before they escape
</p>
