# Standalone builds and the Windows installer

Everything that turns SecretShield into downloadable executables lives here.
The scanning engine is untouched: the executables run the same
`secretshield.cli.main` as the `ss` / `secretshield` commands pip installs
(`entry.py` is three lines).

| File | Purpose |
|---|---|
| `version.py` | Single source of truth for the version. Reads `secretshield/__init__.py` without importing it and fails if `pyproject.toml` disagrees. `--tag vX.Y.Z` also checks a git tag. |
| `entry.py` | PyInstaller entry point. |
| `secretshield.spec` | PyInstaller spec. Windows: *onedir*, with `secretshield.exe` and `ss.exe` as two small launchers around one shared runtime. Linux/macOS: one file. |
| `build.py` | Builds, smoke-tests, packages, and writes/verifies `SHA256SUMS.txt`. Also holds `ASSET_NAMES`, the one definition of every release file name. |
| `requirements-build.txt` | Pinned build tooling (build-time only; SecretShield still has no runtime dependencies). |
| `windows/secretshield.iss` | The Inno Setup installer. |
| `windows/build-installer.ps1` | Compiles the installer with the version from `version.py`. |
| `windows/test-installer.ps1` | Install / upgrade / downgrade / uninstall lifecycle test (run in CI on a disposable machine). |
| `windows/assets/` | Icon and wizard images. `make_assets.py` regenerates them (needs Pillow, which is not a dependency of anything else). They are deliberately plain; replace them with real branding whenever you like. |

## Build locally

```bash
python -m pip install -r standalone/requirements-build.txt
python -m pip install -e .
python standalone/build.py            # -> dist/standalone (raw) and dist/release (assets)
```

On Windows, then:

```powershell
powershell -File standalone\windows\build-installer.ps1     # needs Inno Setup 6
```

`dist/` and `build/` are git-ignored. The asset names have no version in them
on purpose, so `https://github.com/Sam3360/secretshield/releases/latest/download/<name>`
is a stable link. The version is inside every binary (`--version`) and in the
installer's metadata.

## Releasing

`.github/workflows/release-build.yml` builds and tests everything. It runs for
a pushed `v*` tag or by hand, and **never publishes anything**: it uploads
workflow artifacts. To attach them to a release you created yourself, run the
workflow on that tag with *attach_to_release* ticked; it refuses to overwrite
an existing asset and never creates a release. It never touches PyPI.

`python standalone/version.py --tag vX.Y.Z` (also run by CI) refuses a tag
that doesn't match the version in the code.

## What is tested, and where

| Check | Where it runs |
|---|---|
| Full test suite, `python -m build`, `twine check` | CI `checks` job (Ubuntu) |
| Installer PATH/version logic *executed* under Free Pascal; installer, spec and workflow static checks; docs/asset-name consistency | `tests/test_packaging.py` (Ubuntu in CI; any machine with `fpc` locally) |
| The built binary: version, `--help`, scans, JSON/SARIF, config/rules/baseline/inline ignore, `--history`, Unicode and spaced paths, a legacy-code-page pipe, `run`, a real `git commit` through the hook, parity with the pip code path, temp-file cleanup | `tests/test_frozen_binary.py`, against the real artifact on each OS |
| No access to the host's Python and no network sockets during a scan | same file, Linux with `strace` |
| Installer lifecycle (per-user and all-users, PATH exactly once, new-terminal simulation, upgrade removes stale files and leaves exactly one set of executables, a user's own file in the install folder survives upgrade and uninstall, install into a second folder refused, downgrade refused, uninstall restores PATH, project config files untouched, portable zip) | `windows/test-installer.ps1`, CI Windows job |

The CI Windows runner has Python installed, so "works without Python" there is
shown by running the executables with a scrubbed environment (no Python on
PATH, no `PYTHON*` variables). A truly clean machine is still a manual step:

### Manual verification on a clean Windows machine (not automated)

On a fresh Windows 10/11 VM with no Python or Git installed:

1. Download the installer from the release; check its SHA-256 against `SHA256SUMS.txt`.
2. Run it with the defaults (expect a SmartScreen "unknown publisher" warning).
3. In a *new* terminal: `ss --version`, then `ss scan .` in a folder with spaces in its name.
4. Run the installer again (repair), then a newer one (upgrade).
5. Uninstall from Settings → Apps; confirm `ss` is gone and the PATH entry was removed.
6. Repeat 2-3 with the portable zip.

## Code signing and antivirus

Nothing here is signed, and no certificate is configured. To add Authenticode
signing later: sign `secretshield.exe` / `ss.exe` after the PyInstaller step
and sign the compiled installer (Inno's `SignTool=` setting), keeping the
certificate in a protected CI secret. Until then SmartScreen warns, and
PyInstaller output is sometimes flagged heuristically by antivirus products.
UPX compression is turned off, which avoids one common trigger.
macOS binaries would additionally need notarization.
