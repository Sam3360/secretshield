<div align="center">

# 🛡️ SecretShield

**Your secrets shouldn't end up in your terminal, your logs, or your commit history.**

[![PyPI version](https://img.shields.io/pypi/v/secretshield?color=blue)](https://pypi.org/project/secretshield/)
[![Python versions](https://img.shields.io/pypi/pyversions/secretshield)](https://pypi.org/project/secretshield/)
[![PyPI Downloads](https://api.pepy.tech/badge/secretshield/month)](https://pypi.org/project/secretshield/)
[![License: MIT](https://img.shields.io/pypi/l/secretshield)](LICENSE)

[Install](#install) · [Demo](#demo) · [Try it](#try-it) · [Homepage 🌐](https://therealsecretshield.freebuff.app/) · [Full usage guide →](https://github.com/Sam3360/secretshield/blob/main/USAGE.md)

</div>

---

You've done this. Everyone has: a stray `print()` left in from
debugging, a log line that dumps a config dict, a hardcoded key that
slips past review. SecretShield catches it before it leaves your
machine — redacted from your terminal output automatically, scanned
out of your codebase on demand, and blocked from your commits if it
gets that far.

## Demo

[![SecretShield Demo](https://img.youtube.com/vi/g95lNIhWsXM/maxresdefault.jpg)](https://youtu.be/g95lNIhWsXM)

**[▶ Watch the full demo on YouTube](https://youtu.be/g95lNIhWsXM)**

## Install

```bash
pip install secretshield
```

## Try it

```python
import secretshield

api_key = "sk-example1234567890abcdefFAKEKEY"
print("API key:", api_key)
```

```text
API key: ********
⚠ secretshield: Potential secret detected and redacted.
```

No config, no code changes — the moment you import it, stdout, stderr,
and `logging` are protected.

Scan a project:

```bash
secretshield scan .
```

Set a project up in one step — config file, Git hook, CI workflow:

```bash
secretshield init
```

*(Every command also works via the shorter `ss` alias.)*

## What it does

| | |
|---|---|
| 🖥️ **Runtime protection** | `import secretshield` redacts secrets from `stdout`, `stderr`, and `logging` automatically |
| 🔍 **Static scanning** | `secretshield scan .` finds hardcoded secrets across Python, JS/TS, HTML, YAML, `.env`, and more |
| 🔧 **Auto-Fix** | `scan . --fix` moves a hardcoded Python or JS/TS secret into `.env` and rewrites the code — only when it's unambiguous |
| 🪝 **Git hook** | `install-hook` blocks a commit before a secret reaches your history |
| ⚙️ **GitHub Actions** | `github-action` generates a workflow that scans every push and PR |

No required dependencies, no telemetry, no network calls. Everything
runs locally, in your own process.

## Custom rules

Have a credential format of your own? Drop a
`.secretshield-rules.toml` in your project root:

```toml
[[rules]]
name = "My API Key"
pattern = "MYAPP_[A-Za-z0-9]{32}"
```

`secretshield scan .` picks it up automatically — no flag needed.
Validate the file with `secretshield rules check`, or create a rule
interactively with `secretshield rule create`.

For the full command reference, configuration options, and exactly how
Auto-Fix decides what's safe to rewrite, see the
**[usage guide](https://github.com/Sam3360/secretshield/blob/main/USAGE.md)**.

## Limitations

Runtime protection covers this Python process's `stdout`/`stderr`/
`logging` — not screenshots, the clipboard, or other applications.
Auto-Fix only rewrites Python and JS/TS, and only unambiguous
assignments; anything less certain is reported, not modified. Treat
SecretShield as a strong safety net, not a replacement for proper
secret management. Details in the [usage guide](https://github.com/Sam3360/secretshield/blob/main/USAGE.md#limitations).

## Contributing

Issues and PRs welcome. Add tests for new detection patterns or
behavior changes, use only fake credentials in tests/examples, and run
`pytest` before opening a PR.

## [☕](https://github.com/sponsors/Sam3360/) Get me a coffee

If you find this project useful, consider [supporting its development through GitHub Sponsors](https://github.com/sponsors/Sam3360/).

## License

MIT — see [LICENSE](LICENSE).



## Homepage

Visit the official SecretShield homepage for an overview of the project, features, releases, and more:

**🌐 [therealsecretshield.freebuff.app](https://therealsecretshield.freebuff.app/)**
