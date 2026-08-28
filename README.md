# secretshield

`secretshield` is a local Python security utility that detects likely
secrets (API keys, tokens, passwords, private keys, and other
credential-shaped strings) and redacts them **before** they are printed
through Python's terminal output (`stdout`/`stderr`) or the standard
`logging` module.

```python
import secretshield

api_key = "sk-example1234567890abcdefFAKEKEY"
print("API key:", api_key)
```

```text
API key: ********
⚠ secretshield: Potential secret detected and redacted.
```

The real secret value never appears in the redacted output, in
secretshield's own warning messages, or in any exception it raises.

## Why it exists

Secrets end up in terminal output and logs more often than anyone
intends: a debug `print()` left in accidentally, a stack trace that
includes a config dict, a `logger.info()` call that dumps request
headers. `secretshield` is a small, dependency-free safety net for
exactly that class of mistake during local development and debugging.

It is **not** a replacement for secret management, code review, or
static-analysis security tooling — see [Limitations](#limitations) below.

## Installation

```bash
pip install secretshield
```

For local development, from a cloned copy of this repository:

```bash
pip install -e ".[dev]"
```

Requires Python 3.10 or newer. No third-party runtime dependencies.

## Basic usage

Protection for `sys.stdout`, `sys.stderr`, and `logging` is enabled the
moment you import the package:

```python
import secretshield

password = "hunter2-example-not-real"
print("Using password:", password)
```

```text
Using password: ********
⚠ secretshield: Potential secret detected and redacted.
```

You can also toggle protection manually:

```python
import secretshield

secretshield.disable()   # protection off
secretshield.enable()    # protection back on (idempotent, safe to call repeatedly)
secretshield.is_enabled()
```

### Detecting or redacting text directly

You don't need to route text through stdout/logging to use the
detection and redaction logic:

```python
from secretshield import detect, redact

matches = detect("aws_key=AKIAABCDEFGHIJKLMNOP")
# [Match(start=8, end=28, value='AKIA...', kind='aws_access_key_id')]

safe_text, was_redacted = redact("aws_key=AKIAABCDEFGHIJKLMNOP")
# ("aws_key=********", True)
```

## Examples

See the [`examples/`](examples/) directory:

* [`examples/basic.py`](examples/basic.py) — a fake secret printed to
  the terminal.
* [`examples/logging_demo.py`](examples/logging_demo.py) — a fake secret
  logged via both `%s`-style arguments and an f-string.

Run either with:

```bash
python examples/basic.py
python examples/logging_demo.py
```

## CLI

```bash
secretshield --help
secretshield --version
```

### `run` — execute a script with runtime protection

```bash
secretshield run app.py [args...]
```

Runs `app.py` as `__main__` with `sys.stdout`, `sys.stderr`, and
`logging` protected for the duration of the script's execution. This is
useful for wrapping an existing script without editing its source.

### `scan` — static file/directory scanning

```bash
secretshield scan .
secretshield scan path/to/file.py
secretshield scan src/ --json
```

`scan` recursively scans a directory (or a single file) of text-based
project files, reporting the *kind* and *location* of any likely secrets
found. It does **not** execute or import anything it scans, and it never
prints the secret values themselves — only which file, which line, and
what kind of credential it looks like.

**Supported file types** include Python, JavaScript/JSX, TypeScript/TSX,
HTML, CSS/SCSS, Vue, Svelte, JSON/JSONC, YAML, TOML/INI/CFG/CONF, `.env`
and `.env.*` variants, shell scripts (`.sh`/`.bash`/`.zsh`), Windows
scripts (`.ps1`/`.bat`/`.cmd`), XML, Markdown/plain text, SQL, and
GraphQL. Extensionless files (`Dockerfile`, `Makefile`, etc.) are also
scanned as long as they're actually text, not binary. Files are treated
purely as text — the same `detect()` engine used for runtime protection
does the work, regardless of which language the file is written in.

By default, `scan` skips common non-source directories: `.git/`,
`node_modules/`, `__pycache__/`, `.venv/`/`venv/`, `dist/`, `build/`,
`coverage/`, and a few similar cache directories. It also skips binary
files automatically (detected by sniffing for null bytes / invalid
UTF-8), so pointing it at a directory containing images, compiled
artifacts, etc. is safe.

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

If nothing is found:

```text
SecretShield scan

✓ 143 files scanned
✓ No potential secrets found

Exit code: 0
```

**Options:**

| Flag | Purpose |
|---|---|
| `--json` | Machine-readable JSON output instead of the text report (see below). Safe to pipe into CI — never contains secret values, matched text, or surrounding lines. |
| `--include PATTERN` | Only scan files matching a glob pattern (filename or relative path). Repeatable. |
| `--exclude PATTERN` | Skip files matching a glob pattern. Repeatable. Always wins over `--include` and the defaults. |
| `--no-ignore` | Don't skip the default-ignored directories (`.git`, `node_modules`, etc.). |
| `--entropy-threshold FLOAT` | Shannon entropy threshold for generic high-entropy detection (default `4.2`). |

**`--json` output shape:**

```json
{
  "files_scanned": 143,
  "matches": [
    {"file": "src/app.js", "line": 82, "kind": "bearer_token"}
  ],
  "secrets_found": 1
}
```

Exit code is `1` if `secrets_found > 0`, `0` otherwise — identical logic
to the text output, so `scan` works the same way as a CI gate either way.

Obvious documentation placeholders (`your_api_key_here`, `changeme`,
`xxxxxxxx`, and similar) are filtered out of scan results so they don't
create noise — this filtering is narrow and only applies to `scan`
output, not to runtime redaction, so it never risks hiding a real secret
just because it resembles a placeholder pattern.

---

**`scan` is static analysis; `run` (and the automatic protection on
import) is runtime redaction.** They are separate, complementary
features:

```text
Runtime protection:
Protects what a running Python application writes to stdout,
stderr, and logging, live, as it happens.

Static scanning:
Searches source/configuration files on disk -- in any of the
supported languages -- for likely exposed secrets without
executing or importing them.
```

## Configuration

```python
import secretshield

secretshield.configure(
    enabled=True,             # master on/off switch
    redact_with="********",   # placeholder used in place of a secret
    entropy_threshold=4.2,    # bits/char threshold for generic detection
    notify=True,              # print the "potential secret" warning
)
```

Sensible defaults mean most projects need zero configuration.

## Detection methods

`secretshield` combines two strategies:

1. **Known-format pattern matching** — regexes tuned to the shape of
   common credential formats: AWS access keys, GitHub tokens, OpenAI-style
   keys, Slack tokens, Stripe keys, Google API keys, JWTs, bearer tokens,
   PEM-style private-key blocks, and generic `key = value` pairs whose
   label looks like `api_key`, `secret`, `token`, `password`, etc.
2. **Generic high-entropy detection** — a Shannon-entropy check over
   long, non-dictionary-like character runs, used to catch random-looking
   secrets that don't match a known format. This is intentionally used
   as a *supplement*, not the primary mechanism, because entropy alone
   produces far too many false positives on things like hashes, UUIDs,
   and encoded binary data that aren't secrets.

## Architecture

```text
secretshield/
├── patterns.py       # regexes for known secret formats
├── detector.py        # detect(): pattern + entropy matching -> Match objects
├── redactor.py         # redact(): turns Match spans into "********"
├── config.py            # configure()/get_config(): runtime settings
├── notifications.py      # safe, secret-free console/desktop warnings
├── guardian.py             # stdout/stderr wrapping + logging record-factory hook
└── cli.py                    # `secretshield` command-line entry point
```

Key design points:

* **Stream wrapping**, not monkey-patching `print`: `sys.stdout` and
  `sys.stderr` are replaced with a thin wrapper object that redacts on
  `write()` and delegates everything else (`flush`, `isatty`, attribute
  access) to the original stream.
* **Logging protection** hooks `logging.setLogRecordFactory`, not a
  `Filter` on the root logger. Filters attached to the root logger are
  only consulted by the logger that originated a given call, so a
  root-only filter would miss records from `logging.getLogger(__name__)`
  child loggers. The record factory is invoked for every `LogRecord`
  created anywhere in the process, so both `record.msg` (f-strings /
  pre-formatted messages) and `record.args` (`%s`-style lazy arguments)
  are reliably covered regardless of logger hierarchy.
* **Re-entrancy guards** prevent secretshield's own warning output from
  being fed back into detection/logging and causing recursive loops.
* Detection and redaction failures are caught and swallowed — a bug in
  secretshield should never crash or block the host application's
  normal output.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

The test suite covers known-token detection, entropy detection, false
positives, single/multiple/repeated secrets, multiline text, stdout,
stderr, logging (`%s` args and f-strings), enable/disable idempotency,
and stream restoration. All secrets used in tests and examples are fake.

## Limitations

`secretshield` protects **Python's own `stdout`, `stderr`, and `logging`
output within the current process.** It is a helpful safety net, not a
comprehensive security boundary. Specifically, it does **not**:

* Prevent secrets from appearing in **screenshots** or screen recordings.
* Prevent **clipboard** leaks.
* Prevent secrets written via **arbitrary file writes** (e.g. `open(...).write(...)`,
  `json.dump`, writing to a database).
* Protect **other applications** or processes outside this Python
  interpreter.
* Redact output from **arbitrary subprocesses** — only output written
  through this process's own `sys.stdout`/`sys.stderr`/`logging` is
  covered, not everything a spawned subprocess itself prints to its own
  inherited file descriptors before Python sees it.
* Prevent **network leaks** (secrets sent over HTTP, sockets, etc.).
* Catch **every possible way** a secret can leave a computer. Detection
  is pattern- and entropy-based and can miss unusual or obfuscated
  formats, and can occasionally over- or under-match.

Treat `secretshield` as a defense-in-depth safety net for accidental
local exposure during development and debugging — not as a substitute
for proper secret management (vaults, environment isolation, `.gitignore`
discipline, secret scanning in CI, least-privilege credentials, etc.).

## Security considerations

* secretshield performs **no network calls** and collects **no
  telemetry**. All detection and redaction happens locally, in-process.
* Desktop notifications (if you wire up your own backend beyond the
  built-in best-effort `notify-send`/`osascript` calls) are optional and
  fail silently if unavailable — they never crash the host application.
* Because detection is heuristic, it can produce false negatives (a real
  secret slips through) or false positives (harmless text gets redacted).
  Tune `entropy_threshold` and, where needed, extend `patterns.py` for
  your own credential formats.


## License

MIT — see [LICENSE](LICENSE).
