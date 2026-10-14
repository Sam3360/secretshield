# SecretShield — Usage Guide

This is the detailed manual for SecretShield. For a quick overview,
see [`README.md`](README.md).

- [Installation](#installation)
- [Runtime protection](#runtime-protection)
- [CLI](#cli)
- [Scanning](#scanning)
- [Inline ignore comments](#inline-ignore-comments)
- [Auto-Fix](#auto-fix)
- [Secret rotation assistant](#secret-rotation-assistant)
- [Git hooks](#git-hooks)
- [SARIF export](#sarif-export)
- [GitHub Actions](#github-actions)
- [Configuration](#configuration)
- [Custom rules](#custom-rules)
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
secretshield --usage
secretshield --ignore-file
```

`--usage` prompts for confirmation, then opens this USAGE.md page in
your system's default browser once you press Enter — it never opens
anything on its own. Ctrl+C or Ctrl+D cancels cleanly, with no browser
launch. On a terminal that supports it, `--creator`'s GitHub line is a
clickable OSC 8 hyperlink (Ctrl+Click); the visible text stays exactly
`github.com/Sam3360` either way, and terminals that don't understand
OSC 8 just see plain text, not raw escape codes.

`--ignore-file` creates a starter `.secretshieldignore` in the current
directory (see [Configuration](#configuration)) if one doesn't already
exist; it tells you and exits cleanly if one's already there, rather
than overwriting it.

### `secretshield init`

```bash
secretshield init
```

Interactive setup wizard. Detects whether the current directory looks
like a Python project and whether it's a Git repository, then offers
to:

- create the project configuration: a `secretshield.toml` and a
  starter `.secretshieldignore` (see [Configuration](#configuration))
- install the Git pre-commit hook (skipped automatically if not in a
  Git repo)
- generate the GitHub Actions workflow

Each configuration file is only created when it doesn't already exist,
and `init` tells you which it did for each one: `Created
secretshield.toml` / `Created .secretshieldignore`, or `... already
exists, leaving it unchanged`. An existing `secretshield.toml` or
`.secretshieldignore` is never modified, so re-running `init` is safe
at any time. If you decline the project configuration prompt, neither
file is created.

The generated `secretshield.toml` starts with a comment linking to the
[Configuration](https://github.com/Sam3360/secretshield/blob/main/USAGE.md#configuration)
section of this guide. The generated `.secretshieldignore` contains
only comments and a couple of example patterns, so nothing is excluded
until you add a pattern yourself.

Requires a real interactive terminal. In a non-interactive environment
(CI, a piped session) it prints a message and exits without making any
changes or prompting.

### `secretshield scan`

```bash
secretshield scan .                       # scan a directory (default: ".")
secretshield scan app.py                  # scan a single file
secretshield scan . --json                # machine-readable output
secretshield scan . --format sarif --output secretshield.sarif   # SARIF 2.1.0 report
secretshield scan . --fix                 # interactively move secrets to .env
secretshield scan . --rotate              # guided revoke / replace / verify (see below)
secretshield scan --staged                # scan Git-staged content
secretshield scan --diff HEAD~1           # scan files changed since a ref
secretshield scan . --baseline            # write/refresh the baseline file
```

Flags:

| Flag | What it does |
|---|---|
| `--entropy-threshold FLOAT` | Shannon entropy threshold for generic detection (default `4.2`, or the value from `secretshield.toml` if present) |
| `--json` | Machine-readable JSON output (same as `--format json`) |
| `--format text\|json\|sarif` | Report format. `sarif` writes a SARIF 2.1.0 log (see [SARIF export](#sarif-export)). Overrides `[output] format` in `secretshield.toml`. |
| `--output FILE` | Write the `json`/`sarif` report to `FILE` instead of stdout. Missing parent directories are created. Not valid with the default `text` format. |
| `--include PATTERN` | Only scan files matching this glob (filename or relative path). Repeatable. |
| `--exclude PATTERN` | Skip files matching this glob. Repeatable. Always wins over `--include`. |
| `--no-ignore` | Don't skip the default-ignored directories (see below) |
| `--no-inline-ignore` | Report findings even on lines marked `secretshield:ignore` (see [Inline ignore comments](#inline-ignore-comments)). Use it to audit what those comments hide. |
| `--fix` | Interactive Auto-Fix (see [Auto-Fix](#auto-fix)) |
| `--rotate` | Interactive secret rotation assistant (see [Secret rotation assistant](#secret-rotation-assistant)). Can't be combined with `--fix`, `--baseline`, `--json`, `--format` or `--output`. |
| `--staged` | Scan Git *index* content instead of a path — "would this commit introduce a secret?" |
| `--diff REF` | Scan the current on-disk content of files changed relative to `REF` — "did my changes introduce a secret?" |
| `--baseline` | Write (or overwrite) `.secretshield-baseline.json` from the current findings |

Exit codes: `0` — no findings; `1` — findings present; `2` — a
scanner/environment error (e.g. `--staged`/`--diff` used outside a Git
repository, or a report file that can't be written). Exit codes are the
same for every report format.

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
secretshield github-action [--force] [--sarif]
```

See [GitHub Actions](#github-actions).

### `secretshield rules check` / `rules` / `rule create` / `rule test`

```bash
secretshield rules check
secretshield rules
secretshield rule create
secretshield rule test
```

See [Custom rules](#custom-rules).

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
looks binary. SecretShield's own meta-files
(`.secretshield-rules.toml`, `secretshield.toml`,
`.secretshieldignore`, `.secretshield-baseline.json`) are also skipped
by name, since they configure detection rather than holding project
content. Use `--no-ignore` to scan any of these again (binary files
are always skipped regardless).

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

## Inline ignore comments

Some findings are fine: a test fixture, a documented example, a value
that only *looks* like a secret. Rather than excluding a whole file,
mark the one line, in a comment, in whatever language the file uses:

```python
aws_key = "AKIAIOSFODNN7EXAMPLE"  # secretshield:ignore
```

```js
const fixture = "AKIAIOSFODNN7EXAMPLE"; // secretshield:ignore
```

```sql
-- secretshield:ignore-next-line
INSERT INTO keys VALUES ('AKIAIOSFODNN7EXAMPLE');
```

```html
<code>AKIAIOSFODNN7EXAMPLE</code> <!-- secretshield:ignore -->
```

### Syntax

| Marker | Suppresses |
|---|---|
| `secretshield:ignore` | Findings that **start on the same line** |
| `secretshield:ignore-next-line` | Findings that start on the **following line**. Use it where a trailing comment isn't possible: JSON, YAML block scalars, or just above a multi-line private key block. |
| `secretshield:ignore[github_token]` | Only the listed kinds (comma-separated, e.g. `[github_token, high_entropy]`). Works on both forms. Custom rules are named by their rule name, e.g. `[My API Key]`. |

The qualified form is the safer habit: an unqualified marker hides
*every* kind of finding on its line, while `[aws_access_key_id]` leaves
a second, different secret on the same line visible. The kind names are
the ones in the [Detection](#detection) table (and in `--json` output).

The marker is deliberately strict, because a missed marker only leaves a
finding visible while an over-eager one could hide a real secret:

- It is lowercase and exact. `SECRETSHIELD:IGNORE`, `secretshield:ignored`
  and `secretshield:ignore-nextline` are **not** honored. (Spaces after
  the colon are fine: `secretshield: ignore`.)
- An unknown or misspelled kind in brackets suppresses nothing, and
  `secretshield:ignore[]` suppresses nothing.
- Only the line where a finding **starts** counts. For a multi-line
  private key that is the `-----BEGIN` line, so put an
  `ignore-next-line` marker above it; a marker inside the key body does
  nothing.
- One marker never silences a whole file: each suppressed finding needs
  its own marker.

### What you see

Suppressed findings aren't reported, but they aren't invisible either:

```text
✓ 3 finding(s) suppressed by inline ignore comments
✓ 42 files scanned
✓ No potential secrets found
```

The same count appears in `--json` output as `"inline_ignored": 3`
(the key is only present when it's non-zero, so existing consumers see
no change), and in the pre-commit hook's output. To see exactly what the
comments are hiding, run a scan with `--no-inline-ignore`, or list the
markers with `git grep -n "secretshield:"`.

### Where it applies

Inline ignores are applied by the scan engine, before anything else
sees the findings, so a suppressed finding is not written to a baseline
(`--baseline` says how many it left out), not offered by `--fix` or
`--rotate`, and not included in `--format sarif` output. Use
`--no-inline-ignore` to bring them back for any of those.

They **never** affect [runtime protection](#runtime-protection):
`print()` and logging output is still redacted, and `detect()` /
`redact()` still report a secret on a line that carries the marker.

### Which ignore mechanism should I use?

| | Inline ignore | `.secretshieldignore` / `[scan.ignore]` | Baseline |
|---|---|---|---|
| Scope | One line (one kind, if qualified) | Whole files or directories | Specific findings, by file + kind + value hash |
| Lives in | The code itself, reviewed with it | A config file | `.secretshield-baseline.json` |
| Good for | A known-fine value, such as a test fixture | Vendored code, generated files | Adopting SecretShield on a codebase that already has findings |
| Honored by `scan` / `--staged` | Yes | Yes | Yes |
| Honored by the pre-commit hook (`scan-staged`) | **Yes** | No | No |

The last row is the current behavior: the pre-commit hook runs its own
simpler scan of the staged content, which applies placeholder filtering
and inline ignores but not ignore files, baselines or custom rules. If a
value keeps blocking commits and you've confirmed it's not a secret, an
inline ignore is the mechanism that works at commit time.

### Security notes

An inline ignore is a trust decision made in the same commit as the code
it hides, by whoever wrote that code. Review them like any other
suppression: the printed count, `git grep -n "secretshield:"` and
`--no-inline-ignore` make them easy to audit. Prefer the qualified form,
and never use a marker on a line you haven't confirmed is harmless.

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

## Secret rotation assistant

```bash
secretshield scan . --rotate
```

Deleting a secret from your code does **not** make it safe. The
credential keeps working until its provider revokes it, and anyone who
has already seen it (through Git history, a fork or clone, CI logs, a
pushed branch) can keep using it. `--rotate` walks you through fixing
that for every credential the scan finds.

It treats three different things as three different steps, and never
blurs them:

1. **Revoke or rotate it with the provider.** This is the only step that
   makes the old credential unusable. You do it, on the provider's own
   site. SecretShield shows the likely provider, the steps from that
   provider's documentation, and the official links.
2. **Replace the references in your code.** This reuses
   [Auto-Fix](#auto-fix), so it asks before every change and has the same
   safety checks and rollback.
3. **Check for leftover copies** of the old value in your working tree
   and, if you agree, in your Git history.

A session looks like this (secret values are always shown as `********`):

```text
Credential 1/1
Likely provider: GitHub (personal access token (classic)), matched by its format
Detected value: ********
Found in: app.py:2

Work on this credential now? [Y/n]
Step 1 of 3: revoke or rotate it with the provider
  ...steps and official links...
Open "GitHub: Deleting a personal access token" in your browser? [y/N]
Have you revoked or rotated the old credential with the provider? [y/N]
Step 2 of 3: replace the old credential in your code
Run Auto-Fix for this credential now? [y/N]
Step 3 of 3: check for leftover copies of the old credential
  Working tree: the old value is still present in .env:1
```

### What it automates, and what stays with you

| SecretShield does | You do |
|---|---|
| Groups every copy of the same value into one credential | Revoke, delete or rotate it on the provider's site |
| Identifies the likely provider *from the credential's format* | Create the replacement credential |
| Prints the provider's steps and official links; opens one in your browser only if you say yes | Put the new credential in an environment variable or secrets manager |
| Replaces code references through Auto-Fix, after asking | Check that the old credential is now rejected by the provider |
| Searches your working tree, and optionally Git history, for leftover copies (local, read-only) | Decide whether rewriting Git history is worth it |

Because Auto-Fix moves the **old** value into `.env`, the leftover check
will flag that `.env` file until you replace the value with your new
credential. That is intended: the old value must not be reused.

### Revoking is not the same as removing

- **Removing** a secret from a file changes your code. The credential
  still works.
- **Replacing** references (Step 2) makes your code read the credential
  from the environment. The old credential still works.
- **Revoking** (Step 1) is the only thing that stops the old credential
  from working.
- **Rewriting Git history** (optional) removes old commits' copies from
  your repository, but cannot reach forks, clones or CI logs, and does
  not revoke anything. GitHub's own guidance is to revoke first and
  notes that rewriting history may not then be needed.

SecretShield never says a credential "was revoked" or "is secure". It
can't know. What you tell it is recorded as *reported by you (not
verified by SecretShield)*.

### Supported providers

Provider-specific guidance is shown only when a credential's format
matches the provider's documented format. Everything else gets the
generic workflow; SecretShield does not guess from variable names.

| Provider | Recognized as | Where you revoke it |
|---|---|---|
| AWS | IAM access key IDs and secret access keys | [AWS IAM console](https://console.aws.amazon.com/iam/) |
| GitHub | `ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghr_`, `ghs_` tokens | Settings → Developer settings (personal tokens) or your authorized apps; GitHub doesn't document a direct settings URL, so the docs page is linked instead |
| OpenAI | `sk-` keys, including `sk-proj-`, `sk-svcacct-`, `sk-admin-`, `sk-None-` | [API keys page](https://platform.openai.com/api-keys) |
| Anthropic | `sk-ant-api…` API keys and `sk-ant-admin…` Admin keys | [Claude Console](https://platform.claude.com/) (Settings → API keys, or Settings → Admin keys). `sk-ant-api01-` keys may be compliance access keys, which Anthropic's docs place under claude.ai Organization settings; both are mentioned. |
| GitLab | `glpat-`, `gldt-`, `glrt-`, `gloas-` | No single URL (GitLab.com and self-managed differ). Personal access tokens: [GitLab docs](https://docs.gitlab.com/user/profile/personal_access_tokens/), Edit profile → Access tokens → Revoke or Rotate. Other kinds: the settings of the project, group, runner or application that owns them. |
| npm | `npm_` tokens | profile picture → Access Tokens, or `npm token delete`; see [npm: Revoking access tokens](https://docs.npmjs.com/revoking-access-tokens). npm notes it can take up to an hour. |
| PyPI | `pypi-AgE…` tokens | Your PyPI account settings → API tokens (no direct URL is linked; PyPI's own help text is the source) |
| Twilio SendGrid | `SG.…` keys | [SendGrid API keys](https://app.sendgrid.com/settings/api_keys) |
| Hugging Face | `hf_` tokens | Your settings → Access Tokens; see [Hugging Face: User access tokens](https://huggingface.co/docs/hub/security-tokens) |
| Slack | `xox[baprs]-` tokens; incoming webhook URLs | [Slack app management](https://api.slack.com/apps), plus Slack's `auth.revoke` and token-rotation docs. Slack's docs don't describe revoking a webhook URL; the assistant says so and gives the removal route instead of presenting it as documented. |
| Discord | Webhook URLs | Server Settings → Integrations → Webhooks (delete the webhook); see Discord's [Intro to Webhooks](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks) |
| Stripe | `sk_`, `rk_` secret/restricted keys; `pk_` publishable keys | [Dashboard API keys](https://dashboard.stripe.com/apikeys). Publishable keys are documented by Stripe as safe to expose, so no revocation is asked for. |
| Google | `AIza…` API keys (the Firebase guide is linked for Firebase keys) | [Cloud console Credentials](https://console.cloud.google.com/apis/credentials) |

JWTs, bearer tokens, private keys, labeled generic credentials,
high-entropy strings and custom-rule matches get the **generic
workflow**: find out who issued it, revoke it there, replace it, review
the provider's logs. Private keys get key-specific steps (new key pair,
replace the public key wherever it was trusted).

Limits of that support:

- **No provider is revoked automatically.** SecretShield has no
  revocation integration for any provider, by design (see
  [Privacy](#privacy-and-security)). For every provider the revocation
  step is yours.
- A few providers publish no stable direct link to their token page, or
  their location depends on where you host (GitLab, npm, PyPI, Hugging
  Face, Discord). For those SecretShield prints the menu path from the
  provider's documentation and links only documentation pages it could
  verify, rather than guessing a URL.
- Identification is by format. An `sk-` string that isn't from OpenAI is
  still labeled "likely OpenAI"; the notes say to treat it as unknown if
  so. A custom rule named like a built-in detector is not attributed to
  a provider unless the value really has that provider's format.
- Provider consoles and docs change. The links were checked against each
  provider's own documentation when this version was released; if one
  has moved, use the provider's own search.

### Leftover-copy checks

- **Working tree:** after Step 2 (or whenever you want), the old value is
  searched for across the project with the same ignore rules as the scan
  (`.secretshieldignore`, `secretshield.toml`, default skipped
  directories). It always reads the files on disk, even if you ran the
  scan with `--staged`. It reports `file:line` only, never the text, and
  you can re-check after you edit.
- **Git history:** only if you answer yes. It reads `git log --all -p`
  locally and searches in-process, so the value is never on a command
  line. It covers commits reachable from your refs; it does not cover
  other people's clones, forks, or unreachable objects. Very large histories are cut off and reported as
  partial.

### Exit codes and interactivity

Like `--fix`, `--rotate` needs an interactive terminal; otherwise it
prints a notice and changes nothing. With no findings it exits `0`.
Otherwise it exits `0` only if, for every credential, you reported
revoking it **and** no copy of the old value remains in the scanned
working tree (credentials the provider documents as safe to expose don't
count against this). That is a statement about what you reported and what
was found locally, not proof that anything was revoked. Skipping a
credential, stopping early, or leaving a copy behind exits `1`; an
unexpected internal error exits `2`. Ctrl+C or Ctrl+D stops cleanly,
prints how far you got, and leaves files exactly as they were.

`--rotate` also covers findings you've accepted in a baseline, and it
ignores a `json`/`sarif` default from `secretshield.toml`.

### Privacy and security

- **No network requests.** The assistant never contacts a provider, a
  SecretShield server or any third party, and sends nothing anywhere.
  There is no telemetry. The only thing that can leave your machine is
  your own browser, opened to a provider URL from a fixed table, and only
  after you confirm.
- **You never give SecretShield a credential.** It doesn't ask for your
  old or new key; paste the new one into your environment or secrets
  manager yourself.
- **Values are never printed.** Messages, prompts, errors and reports show
  `********`; an output scrubber masks any detected value as a second
  line of defense, and an unexpected error shows only its type.
- **Nothing is revoked or modified without you.** Every file change goes
  through Auto-Fix's own confirmation, and nothing is revoked at all.

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

The hook honors [inline ignore comments](#inline-ignore-comments) on the
staged lines (and prints how many findings they suppressed). It does not
currently read `.secretshieldignore`, `[scan.ignore]`, the baseline or
custom rules.

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

## SARIF export

[SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
2.1.0 is the standard interchange format for static-analysis results.
It's what GitHub Code Scanning ingests, and many IDEs and security
dashboards read it too.

```bash
secretshield scan . --format sarif --output secretshield.sarif
ss scan . --format sarif --output secretshield.sarif     # same thing
secretshield scan . --format sarif                       # to stdout instead
```

The report is built from the same findings a normal scan produces, so
everything that shapes a scan applies unchanged: `--include` /
`--exclude`, `.secretshieldignore`, `secretshield.toml`, the
[baseline](#secretshield-scan) (baselined findings are left out and counted in
the run's `invocations[0].properties.ignoredByBaseline`), custom rules,
`--staged`, `--diff`, and `--entropy-threshold`. Exit codes are
unchanged (`0` clean, `1` findings, `2` error), so a SARIF scan can
still gate a CI job.

`--format sarif` can't be combined with `--fix` or `--baseline` (those
commands don't produce a report) — that's an error (exit `2`) rather
than a silently ignored flag. `--json` and `--format sarif` together are
also an error. In `secretshield.toml`, `[output] format = "sarif"` works
the same as passing `--format sarif`; the command-line flag wins.

### What's in the report

- **Rules.** Every detector is a SARIF rule with a stable ID
  `secretshield.<kind>` (for example `secretshield.github_token`),
  a short and full description, remediation guidance (`help`), CWE-798
  and category tags, and a precision rating. Custom rules from
  `.secretshield-rules.toml` appear as `secretshield.custom.<name-slug>`.
- **Severity.** Each rule has a SARIF `level` and a GitHub
  `security-severity` score, which GitHub shows as Critical / High /
  Medium / Low:

  | Rule | `level` | `security-severity` | GitHub label |
  |---|---|---|---|
  | `private_key_block`, `aws_secret_access_key` | `error` | 9.5 | Critical |
  | `github_token`, `gitlab_token`, `npm_token`, `pypi_token` | `error` | 8.5 | High |
  | `openai_api_key`, `anthropic_api_key`, `slack_token`, `stripe_key`, `sendgrid_api_key` | `error` | 8.0 | High |
  | `aws_access_key_id`, `bearer_token`, `huggingface_token`, custom rules | `error` | 7.5 | High |
  | `google_api_key` | `error` | 7.0 | High |
  | `jwt` | `warning` | 6.5 | Medium |
  | `generic_labeled_secret`, `slack_webhook_url`, `discord_webhook_url` | `warning` | 6.0 | Medium |
  | `high_entropy` | `note` | 3.5 | Low |

  Heuristic rules (`generic_labeled_secret`, `high_entropy`, `jwt`) are
  scored lower because they produce more false positives. Custom rules
  have no severity of their own, so they all get the conservative
  `error` mapping.
- **Locations.** Each result has one location: the file as a
  repository-relative, forward-slash, percent-encoded URI, plus
  `startLine`, `startColumn`, `endLine`, and `endColumn` (1-based, end
  column exclusive, counted in UTF-16 code units). A multi-line private
  key spans from its `BEGIN` line to its `END` line.
- **Messages.** Short and fixed per rule, e.g. *Potential secret
  detected: GitHub token. Rotate the credential and remove it from
  source code.* — the first sentence is what GitHub shows as the alert
  title.
- **Ordering.** Results are sorted by file, line, and column, so
  scanning the same tree twice gives byte-identical output, with no
  timestamps or absolute paths.

### Secret values are never included

The report builder is only ever given a finding's file, rule, and
position — never the matched text — so there is no message, snippet,
property, or fingerprint that could contain a secret. That includes no
`region.snippet` and no `partialFingerprints`: the baseline's finding
IDs are hashes of the secret value, so they are deliberately not
reused. Errors writing the report name only the path and the operating
system's reason. (GitHub's `upload-sarif` action computes its own
`partialFingerprints` from your checked-out files at upload time; that
happens on the runner, not in the report SecretShield writes.)

### Notes

- Run the scan from the repository root with a path inside it (`.`), so
  locations are relative to the repo — GitHub matches alerts to files by
  that path. A scan target outside the current directory is reported
  with `file:` URIs, which GitHub can't map to repository files.
- `.sarif` isn't a scanned file type, so a report written into the tree
  isn't re-scanned on the next run.
- A custom rule whose name is the same as a built-in kind (for example
  `jwt`) can't be told apart from it in findings, and is reported as the
  built-in rule.

## GitHub Actions

```bash
secretshield github-action [--force] [--sarif]
```

Writes `.github/workflows/secretshield.yml`. Won't overwrite an
existing workflow file unless `--force` is passed.

**Default workflow.** Runs on every `push` and `pull_request`, installs
SecretShield via `pip install secretshield`, and runs
`secretshield scan .`, failing the check if a potential secret is
found.

**With `--sarif`.** The same scan, plus an upload of the results to
GitHub Code Scanning so findings show up as alerts in the repository's
**Security** tab and as annotations on pull requests:

```yaml
jobs:
  secretshield:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.x"
      - run: python -m pip install secretshield
      - name: Scan repository
        run: secretshield scan . --format sarif --output secretshield.sarif
      - name: Upload SARIF to GitHub Code Scanning
        if: ${{ always() && hashFiles('secretshield.sarif') != '' }}
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: secretshield.sarif
          category: secretshield
```

(`--sarif` writes the complete file, including the `name:`/`on:`
header; the above shows the part that differs.) You can also add the
two SARIF steps to a workflow you already have.

How it fits together:

- The scan step still exits `1` when it finds something, so the job
  fails exactly as before. `if: always()` makes the upload run anyway;
  without it a failing scan would skip the upload and nothing would
  reach Code Scanning. The `hashFiles` check skips the upload when the
  scan never produced a report (for instance after a scanner error)
  instead of failing on a missing file.
- `security-events: write` is required to upload. Pull requests from
  forks get a read-only token, so the upload step can't succeed for
  them.
- Code Scanning is available on public repositories, and on private
  repositories with GitHub Code Security (Advanced Security) enabled.
  The default workflow has none of these requirements, which is why
  `--sarif` is opt-in.
- `category` keeps SecretShield's alerts separate from other tools'. Use
  a different value per job if you upload more than one SecretShield
  report for the same commit (for example in a matrix).
- The workflow uses `upload-sarif@v4`. GitHub Enterprise Server 3.19
  can't run v4; on that version use `@v3`.
- GitHub accepts at most 5,000 results per upload (the highest-severity
  ones are kept) and a 10 MB gzip-compressed file. Use ignore rules or a
  [baseline](#secretshield-scan) for noisy repositories.

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

`[output] format` accepts `text`, `json`, or `sarif` (SARIF goes to
stdout; use `--output` on the command line to write a file). The
`--format` / `--json` flags override it.

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

`secretshield --ignore-file` creates a starter file for you (and
`secretshield init` does the same when you choose project
configuration), rather than needing to create it by hand.

### How they interact

`secretshield.toml`'s `[scan.ignore].paths` and `.secretshieldignore`
combine — both are read, and their patterns are unioned with any
`--exclude` flags. **Explicit CLI flags always take precedence** over
the config file: `--json` overrides `format = "text"`, and
`--entropy-threshold 3.0` overrides whatever `secretshield.toml` says.

## Custom rules

Project-specific detection rules, for credential formats SecretShield
doesn't know about out of the box. Add a `.secretshield-rules.toml` to
the project root:

```toml
[[rules]]
name = "My API Key"
pattern = "MYAPP_[A-Za-z0-9]{32}"

[[rules]]
name = "Internal Token"
pattern = "internal_[a-f0-9]{40}"
```

Each rule has exactly two fields: `name` and `pattern` (a regular
expression). No severity levels, no IDs, no capture groups, nothing
else to configure.

If this file exists, `secretshield scan .` loads and uses it
automatically — no flag, no `--custom-rules`, nothing to opt into. If
it doesn't exist, SecretShield behaves exactly as it does without this
feature at all.

**The rules file is never scanned as project content.** A rule's
`pattern` necessarily resembles the real secret it's meant to catch —
that's the whole point of writing it — so `.secretshield-rules.toml`
(along with `secretshield.toml` and `.secretshieldignore`) is excluded
by name from the default directory scan, the same way well-known
directories like `node_modules/` already are. Without this, a rule
whose pattern looked enough like a real secret would cause the rules
file to report itself as a finding the moment you wrote it. Use
`--no-ignore` if you genuinely need to include these files in a scan,
or name one directly (`secretshield scan .secretshield-rules.toml`) —
explicit targeting always works.

Custom rules become additional detectors alongside the built-in ones,
not a replacement for them, and they can't disable a built-in rule. A
match against a custom rule produces a normal finding — same filename,
line number, output formatting, redaction, and JSON representation as
any other finding, identified by the rule's own name:

```text
✗ config.py:1
  Potential secret: My API Key
  Type: possible secret
```

A custom-rule match is never printed unredacted; it goes through the
exact same masking as every other finding. It also respects
`.secretshieldignore` and `secretshield.toml`'s ignore paths the same
way built-in detection does — nothing custom rules match in an ignored
file is ever reported.

**Auto-Fix:** a custom-rule match integrates with `--fix` exactly like
a built-in one — if it sits in a line Auto-Fix can already safely
rewrite (a plain `NAME = "value"` assignment in a supported language,
see [Auto-Fix](#auto-fix) above), it's offered for fixing the same way.
There's no rule-specific fixing logic: custom rules don't get special
treatment, safe or unsafe, beyond what the existing Auto-Fix safety
check already does for any match regardless of which detector found
it. If a custom-rule match sits somewhere Auto-Fix can't safely rewrite
(or in an unsupported file type), it's still detected and reported
normally — `--fix` just leaves it untouched, the same as any other
ambiguous finding.

### `secretshield rules check`

Validates `.secretshield-rules.toml`: TOML syntax, that each rule has
both a `name` and a `pattern`, and that every pattern is a valid
regular expression.

```text
SecretShield Rules

✓ .secretshield-rules.toml
✓ 4 rules loaded
✓ All patterns are valid
```

```text
SecretShield Rules

✗ Invalid custom rule "Internal Token"
  Invalid regular expression
```

One broken rule doesn't block the others from loading — `rules check`
reports every problem it finds, not just the first. If the file
doesn't exist, `rules check` prints a plain "No .secretshield-rules.toml
found." and exits successfully; that's a valid state, not an error.

A broken rules file also never blocks `secretshield scan .` itself:
any rule that fails to load is skipped (with the rest of the file still
used), and a single warning points at `rules check` for the details.

### `secretshield rule create`

Interactive wizard for adding a rule without hand-writing TOML:

```text
SecretShield — Create custom rule

Rule name: My API Key
Pattern: MYAPP_[A-Za-z0-9]{32}
✓ Added rule to .secretshield-rules.toml
```

The pattern is validated as a regular expression before anything is
written — an invalid one is rejected with a clear message and you're
asked to try again, so a broken rule never gets written to disk. If
`.secretshield-rules.toml` already has rules in it, they're preserved
exactly as-is; the new rule is appended, not merged or reformatted.
Requires a real interactive terminal, same as `--fix` and `init`.

### `secretshield rule test`

Try a rule against sample text without scanning any file:

```text
SecretShield — Test custom rules

Loaded 2 rules: My API Key, Internal Token

Text to test: MYAPP_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

✓ Matched: My API Key
  at position 0-38 (38 character(s), value masked)
✗ No match: Internal Token
```

Useful for checking a pattern actually matches what you expect before
relying on it, without needing to paste an example into a real file
(and risk it getting picked up by a detector elsewhere). Like every
other place SecretShield reports a match, the matched text itself is
never printed — only its position and length. Requires a real
interactive terminal; if `.secretshield-rules.toml` doesn't exist, it
suggests `secretshield rule create` instead.

### `secretshield rules`

Lists the rules currently loaded from `.secretshield-rules.toml`:

```text
SecretShield Custom Rules

1. My API Key
   MYAPP_[A-Za-z0-9]{32}
2. Internal Token
   internal_[a-f0-9]{40}
```

## Detection

Two strategies, combined:

**1. Known-format pattern matching.** Regexes tuned to the shape of
specific credential formats. Each reports its own `kind` (shown in
`--json` output and as the SARIF rule `secretshield.<kind>`):

| `kind` | What it matches |
|---|---|
| `aws_access_key_id`, `aws_secret_access_key` | AWS access key IDs; a 40-character secret assigned to an AWS-labeled name |
| `github_token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` and `github_pat_` tokens |
| `gitlab_token` | `glpat-` (personal, project, group access tokens), `gldt-` (deploy), `glrt-` (runner authentication), `gloas-` (OAuth application secret) |
| `openai_api_key` | Legacy `sk-…` keys, plus `sk-proj-`, `sk-svcacct-`, `sk-admin-` and `sk-None-` keys |
| `anthropic_api_key` | `sk-ant-api…-` and `sk-ant-admin…-` keys |
| `slack_token` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` tokens |
| `slack_webhook_url` | Slack incoming webhook URLs (`hooks.slack.com` and GovSlack `hooks.slack-gov.com`) |
| `discord_webhook_url` | Discord webhook URLs (`discord.com` / `discordapp.com`) |
| `stripe_key` | `sk_`, `rk_` and `pk_` keys, live or test |
| `google_api_key` | `AIza…` keys |
| `npm_token` | `npm_` access tokens |
| `pypi_token` | `pypi-` API tokens |
| `sendgrid_api_key` | `SG.….…` keys |
| `huggingface_token` | `hf_` access tokens |
| `jwt`, `bearer_token` | JSON Web Tokens; `Bearer …` values |
| `private_key_block` | PEM-style private key blocks |
| `generic_labeled_secret` | `label = value` pairs where the label looks like `api_key`, `secret`, `token`, `password`, etc. |

Each of these formats was checked against the provider's own
documentation. Two things to know about that evidence: OpenAI does not
publish a formal key-format specification (the `sk-proj-` family comes
from what OpenAI's keys and community channels show, and OpenAI has
changed the format before), and for PyPI the `pypi-AgE…` shape is how
real tokens look rather than a documented contract. Anthropic is matched
only for the documented families (`sk-ant-api…`, `sk-ant-admin…`).

Webhook URLs are listed separately because the URL itself is the
secret. Since 0.11.0 the generic entropy check skips URL paths (below),
so these dedicated detectors are what catch a secret that lives inside
a URL.

Documentation filler is skipped for the newer detectors: a match whose
token body uses three or fewer distinct characters (for example
`glpat-xxxxxxxxxxxxxxxxxxxx`, or Slack's own
`…/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX` example) is not
reported. A *labeled* placeholder such as `GITLAB_TOKEN=glpat-xxxx…` is
still caught by the generic labeled-secret detector, as before.

**2. High-entropy detection.** A Shannon-entropy check over long,
non-dictionary-like character runs, used as a *supplement* to catch
random-looking secrets that don't match a known format — not the
primary mechanism, since entropy alone produces far more false
positives (hashes, UUIDs, encoded binary data) than pattern matching
does.

URLs are not treated as high-entropy strings: the scheme, host and
path of a `https://...` (or `www....`) link are skipped by the entropy
check, so documentation links like
`https://github.com/Sam3360/secretshield/blob/main/USAGE.md` don't
block a commit. This only affects the generic entropy check. A URL's
credentials (`https://user:password@host/`) and its query-string or
fragment values are still examined, and every known-format pattern and
custom rule still runs against the full text, including text inside
URLs.

```python
from secretshield import detect

detect('password = "MyDogFluffy99"')
# [Match(..., kind='generic_labeled_secret')]

detect('aX9pQ2zM7vL0rT4wK8yB1nD6fH3jC5sE')
# [Match(..., kind='high_entropy')]
```

### Upgrading to 0.13

Tokens that used to be reported as `high_entropy` or
`generic_labeled_secret` (for example a GitLab token, an Anthropic key
or an `sk-proj-` key) are now reported under their own `kind`. In
practice:

- **Baselines keep working.** A baseline fingerprint includes the kind,
  so a plain rename would have made accepted findings reappear. A
  finding is now treated as baselined if it matches under its current
  kind *or* under `high_entropy` / `generic_labeled_secret` for the same
  file and value (only for the kinds that were reclassified in this
  release). Re-running `secretshield scan . --baseline` writes the new
  kinds.
- **`--json` and SARIF** show the new `kind` values and rule IDs
  (`secretshield.gitlab_token`, and so on). Eight new rules are
  appended to the SARIF rule list after the existing ones, so existing
  rules keep their indexes. If you filter code-scanning alerts by rule
  ID, add the new IDs.
- **More findings are possible.** Secrets that used to slip through (a
  Slack or Discord webhook URL, or an `sk-proj-` key that wasn't
  labeled and had low entropy) are now caught.

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
- SARIF export has no `partialFingerprints` or code snippets by design
  (see [SARIF export](#sarif-export)); alert tracking across commits
  relies on GitHub's `upload-sarif` action computing fingerprints.
  Results in files reached through symlinks are reported under the
  symlink's path, which GitHub may not be able to display.
- Inline ignore markers only work in the exact syntax shown in
  [Inline ignore comments](#inline-ignore-comments), and only for the line
  where a finding starts. They are honored by the scan engine and the
  pre-commit hook, never by runtime protection.
- The rotation assistant can't revoke anything, can't verify that you
  did, and only knows the providers listed in its
  [supported providers](#supported-providers) table. Its Git-history
  search covers commits reachable from your refs only.
- The URL exemption in high-entropy detection applies to links with a
  scheme (`https://...`) or a leading `www.`. A bare `host.com/path`
  without either is still treated as ordinary text.
- Detectors match the documented credential families only. For example,
  Anthropic OAuth tokens (`sk-ant-oat…`) and Twilio credentials (whose
  secret half has no distinctive format) are not given their own
  detector, so they are caught only by the generic checks, if at all.
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
