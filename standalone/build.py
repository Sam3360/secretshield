"""
Build, verify and package the standalone SecretShield executables.

    python standalone/build.py                  # build + smoke-test + package
    python standalone/build.py --mode onedir    # force a bundle mode
    python standalone/build.py checksums DIR    # write DIR/SHA256SUMS.txt
    python standalone/build.py verify DIR       # check DIR against SHA256SUMS.txt

Outputs go to ``dist/standalone`` (raw PyInstaller output) and
``dist/release`` (the files that are attached to a GitHub release). Both are
git-ignored. Release asset names are deliberately version-less so that
``releases/latest/download/<name>`` is a stable link; the version is inside
the binary (``--version``) and in the release itself.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import version as ss_version  # noqa: E402

REPO_ROOT = ss_version.REPO_ROOT
RAW_DIST = REPO_ROOT / "dist" / "standalone"
RAW_WORK = REPO_ROOT / "build" / "standalone"
RELEASE_DIR = REPO_ROOT / "dist" / "release"
CHECKSUM_FILE = "SHA256SUMS.txt"  # == ASSET_NAMES["checksums"]

REQUIRED_PYINSTALLER = "6.22.3"  # keep in step with standalone/requirements-build.txt

# The one definition of every release asset name. The installer script, the
# workflow and the docs are all checked against it by tests/test_packaging.py.
ASSET_NAMES = {
    "windows_installer": "secretshield-windows-x64-setup.exe",
    "windows_portable": "secretshield-windows-x64-portable.zip",
    "linux_x64": "secretshield-linux-x64",
    "macos_arm64": "secretshield-macos-arm64",
    "macos_x64": "secretshield-macos-x64",
    "checksums": "SHA256SUMS.txt",
}


class BuildError(RuntimeError):
    pass


def os_label() -> str:
    return {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")


def arch_label() -> str:
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64", "x64"):
        return "x64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    raise BuildError(f"unsupported CPU architecture: {platform.machine()!r}")


def default_mode() -> str:
    return "onedir" if sys.platform == "win32" else "onefile"


def source_date_epoch() -> int:
    """Timestamp used for archive entries, so repeated builds can match."""
    if os.environ.get("SOURCE_DATE_EPOCH"):
        return int(os.environ["SOURCE_DATE_EPOCH"])
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%ct"], cwd=REPO_ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()  # fmt: skip
        return int(out)
    except (OSError, subprocess.CalledProcessError, ValueError):
        return 315532800  # 1980-01-01, the earliest time a zip can store


def check_environment() -> None:
    issues = ss_version.problems(os.environ.get("SS_EXPECT_TAG") or None)
    if issues:
        raise BuildError("; ".join(issues))
    try:
        import PyInstaller
    except ImportError as exc:
        raise BuildError(
            "PyInstaller is not installed. Run: python -m pip install -r "
            "standalone/requirements-build.txt"
        ) from exc
    if PyInstaller.__version__ != REQUIRED_PYINSTALLER:
        raise BuildError(
            f"PyInstaller {PyInstaller.__version__} found but {REQUIRED_PYINSTALLER} is pinned; "
            "install standalone/requirements-build.txt"
        )


def run_pyinstaller(mode: str) -> None:
    for path in (RAW_DIST, RAW_WORK):
        shutil.rmtree(path, ignore_errors=True)
    env = dict(os.environ, SS_BUNDLE_MODE=mode, SOURCE_DATE_EPOCH=str(source_date_epoch()))
    env.setdefault("PYTHONHASHSEED", "0")
    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--distpath", str(RAW_DIST), "--workpath", str(RAW_WORK),
        str(HERE / "secretshield.spec"),
    ]  # fmt: skip
    print("+", " ".join(cmd), flush=True)
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env)
    if result.returncode != 0:
        raise BuildError(f"PyInstaller failed with exit code {result.returncode}")


def built_binary(mode: str, name: str = "secretshield") -> Path:
    exe = name + (".exe" if sys.platform == "win32" else "")
    path = RAW_DIST / exe if mode == "onefile" else RAW_DIST / "secretshield" / exe
    if not path.is_file():
        raise BuildError(f"expected build output is missing: {path}")
    return path


def smoke_test(binary: Path, expected_version: str) -> None:
    """Run the freshly built binary from an unrelated directory."""
    import tempfile

    with tempfile.TemporaryDirectory() as scratch:
        result = subprocess.run(
            [str(binary), "--version"], cwd=scratch, capture_output=True, text=True, timeout=120
        )
    expected = f"secretshield {expected_version}"
    if result.returncode != 0 or result.stdout.strip() != expected:
        raise BuildError(
            f"{binary.name} --version gave {result.stdout.strip()!r} "
            f"(exit {result.returncode}), expected {expected!r}. stderr: {result.stderr.strip()}"
        )
    print(f"smoke test ok: {binary.name} -> {result.stdout.strip()}")


def deterministic_zip(source_dir: Path, archive: Path, root_name: str) -> None:
    """Zip `source_dir` as `root_name/...` with sorted entries and fixed times."""
    epoch = max(source_date_epoch(), 315532800)
    import time

    stamp = time.gmtime(epoch)[:6]
    files = sorted(p for p in source_dir.rglob("*") if p.is_file())
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in files:
            rel = path.relative_to(source_dir).as_posix()
            info = zipfile.ZipInfo(f"{root_name}/{rel}", date_time=stamp)
            mode = 0o755 if os.access(path, os.X_OK) else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, path.read_bytes())


def package(mode: str) -> list[Path]:
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    base = f"secretshield-{os_label()}-{arch_label()}"
    outputs: list[Path] = []
    if mode == "onefile":
        target = RELEASE_DIR / (base + (".exe" if sys.platform == "win32" else ""))
        shutil.copy2(built_binary(mode), target)
        target.chmod(0o755)
        outputs.append(target)
    else:
        target = RELEASE_DIR / f"{base}-portable.zip"
        deterministic_zip(RAW_DIST / "secretshield", target, "secretshield")
        outputs.append(target)
    return outputs


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(directory: Path) -> Path:
    files = sorted(p for p in directory.iterdir() if p.is_file() and p.name != CHECKSUM_FILE)
    if not files:
        raise BuildError(f"no files to checksum in {directory}")
    lines = [f"{sha256_of(p)}  {p.name}\n" for p in files]  # sha256sum-compatible
    out = directory / CHECKSUM_FILE
    out.write_text("".join(lines), encoding="utf-8", newline="\n")
    print(f"wrote {out} ({len(files)} files)")
    return out


def verify_checksums(directory: Path) -> None:
    listing = directory / CHECKSUM_FILE
    if not listing.is_file():
        raise BuildError(f"{listing} not found")
    expected: dict[str, str] = {}
    for line in listing.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        expected[name] = digest
    actual = {p.name for p in directory.iterdir() if p.is_file() and p.name != CHECKSUM_FILE}
    if set(expected) != actual:
        raise BuildError(
            f"checksum list and directory differ: only in list={sorted(set(expected) - actual)}, "
            f"only in directory={sorted(actual - set(expected))}"
        )
    for name, digest in expected.items():
        if sha256_of(directory / name) != digest:
            raise BuildError(f"checksum mismatch for {name}")
    print(f"all {len(expected)} checksums match")


def cmd_build(args: argparse.Namespace) -> int:
    mode = args.mode or default_mode()
    check_environment()
    version = ss_version.read_package_version()
    print(f"building SecretShield {version} ({mode}) for {os_label()}-{arch_label()}")
    run_pyinstaller(mode)
    smoke_test(built_binary(mode), version)
    if mode == "onedir":
        smoke_test(built_binary(mode, "ss"), version)
    for output in package(mode):
        print(f"release asset: {output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = parser.add_subparsers(dest="command")
    build = sub.add_parser("build", help="build, smoke-test and package (default)")
    build.add_argument("--mode", choices=("onedir", "onefile"))
    sums = sub.add_parser("checksums", help="write SHA256SUMS.txt for a directory")
    sums.add_argument("directory", type=Path)
    check = sub.add_parser("verify", help="verify a directory against its SHA256SUMS.txt")
    check.add_argument("directory", type=Path)
    parser.add_argument("--mode", choices=("onedir", "onefile"), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.command == "checksums":
            write_checksums(args.directory)
            return 0
        if args.command == "verify":
            verify_checksums(args.directory)
            return 0
        return cmd_build(args)
    except BuildError as exc:
        print(f"build error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
