# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the standalone SecretShield build.

Build with ``python standalone/build.py`` (preferred: it also verifies the
result), or directly with ``pyinstaller standalone/secretshield.spec``.

Bundle mode (environment variable ``SS_BUNDLE_MODE``):

* ``onedir``  (default on Windows) -- a folder containing ``secretshield`` and
  ``ss`` launchers that share one copy of the Python runtime. Starts fast and
  never extracts anything to a temp directory, which is also friendlier to
  antivirus software than a self-extracting single file.
* ``onefile`` (default elsewhere) -- one self-contained binary.

Everything bundled comes from the same ``secretshield`` package that pip
installs; nothing here changes how the CLI behaves.
"""

import importlib.util
import os
import sys

from PyInstaller.utils.hooks import collect_submodules

_spec_dir = os.path.abspath(SPECPATH)  # noqa: F821  (provided by PyInstaller)
_repo_root = os.path.dirname(_spec_dir)

# standalone/version.py is the single source of truth for the version.
_loader = importlib.util.spec_from_file_location(
    "secretshield_standalone_version", os.path.join(_spec_dir, "version.py")
)
_ver = importlib.util.module_from_spec(_loader)
_loader.loader.exec_module(_ver)

VERSION = _ver.read_package_version()
COPYRIGHT = _ver.read_copyright()
AUTHOR = "Samarth Chugh (Sam3360)"  # as in LICENSE and pyproject.toml
MODE = os.environ.get("SS_BUNDLE_MODE") or ("onedir" if sys.platform == "win32" else "onefile")
if MODE not in ("onedir", "onefile"):
    raise SystemExit(f"SS_BUNDLE_MODE must be 'onedir' or 'onefile', not {MODE!r}")

_icon = os.path.join(_spec_dir, "windows", "assets", "secretshield.ico")
ICON = _icon if sys.platform == "win32" and os.path.exists(_icon) else None


def _win_version_info(original_filename):
    """Product metadata shown in the Windows file properties dialog."""
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VarFileInfo,
        VarStruct,
        VSVersionInfo,
    )

    nums = _ver.numeric_tuple(VERSION)
    return VSVersionInfo(
        ffi=FixedFileInfo(
            filevers=nums, prodvers=nums, mask=0x3F, flags=0x0,
            OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0),
        ),  # fmt: skip
        kids=[
            StringFileInfo(
                [
                    StringTable(
                        "040904B0",
                        [
                            StringStruct("CompanyName", AUTHOR),
                            StringStruct("FileDescription", "SecretShield command-line tool"),
                            StringStruct("FileVersion", VERSION),
                            StringStruct("InternalName", "secretshield"),
                            StringStruct("LegalCopyright", COPYRIGHT + " MIT License."),
                            StringStruct("OriginalFilename", original_filename),
                            StringStruct("ProductName", "SecretShield"),
                            StringStruct("ProductVersion", VERSION),
                        ],
                    )
                ]
            ),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )


# Nothing here is imported by SecretShield; keep them out of the bundle.
EXCLUDES = [
    "tkinter", "_tkinter", "pytest", "_pytest", "setuptools", "pkg_resources",
    "pip", "wheel", "IPython", "numpy", "pydoc_data",
]  # fmt: skip

a = Analysis(  # noqa: F821
    [os.path.join(_spec_dir, "entry.py")],
    pathex=[_repo_root],
    binaries=[],
    datas=[],
    # The CLI imports several subpackages lazily; collect them all so a
    # command is never missing from the bundle.
    hiddenimports=collect_submodules("secretshield"),
    hookspath=[],
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821

_common = dict(
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX-packed executables are flagged by antivirus far more often
    console=True,
    icon=ICON,
)

if MODE == "onefile":
    exe = EXE(  # noqa: F821
        pyz, a.scripts, a.binaries, a.datas, [],
        name="secretshield",
        version=_win_version_info("secretshield.exe") if sys.platform == "win32" else None,
        **_common,
    )  # fmt: skip
else:
    # Two tiny launchers (secretshield, ss) around ONE shared runtime folder.
    launchers = [
        EXE(  # noqa: F821
            pyz, a.scripts, [],
            exclude_binaries=True,
            name=name,
            version=_win_version_info(name + ".exe") if sys.platform == "win32" else None,
            **_common,
        )  # fmt: skip
        for name in ("secretshield", "ss")
    ]
    coll = COLLECT(  # noqa: F821
        *launchers, a.binaries, a.datas,
        strip=False, upx=False, name="secretshield",
    )  # fmt: skip
