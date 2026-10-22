"""
Tests for the v0.13.2 packaging work: version single-sourcing, the build
driver's helpers, the PyInstaller spec, the Windows installer script, and the
release workflow.

These need no built binary. They check what can be checked statically or by
executing pure logic, and they cross-check files that must agree with each
other (installer GUID, asset names, URLs). The Windows installer and the
PowerShell test script themselves can only be run on Windows; see
standalone/README.md.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import secretshield

ROOT = Path(__file__).resolve().parent.parent
STANDALONE = ROOT / "standalone"
WINDOWS = STANDALONE / "windows"
ISS = WINDOWS / "secretshield.iss"
WORKFLOW = ROOT / ".github" / "workflows" / "release-build.yml"
USAGE_URL = "https://github.com/Sam3360/secretshield/blob/main/USAGE.md"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(path.parent))
    return module


version_tool = load("ss_standalone_version", STANDALONE / "version.py")
build_tool = load("ss_standalone_build", STANDALONE / "build.py")
ISS_TEXT = ISS.read_text(encoding="utf-8")
WORKFLOW_TEXT = WORKFLOW.read_text(encoding="utf-8")


# --- Version: one source of truth -------------------------------------------------------------


def test_the_package_pyproject_and_tool_agree():
    assert version_tool.read_package_version() == secretshield.__version__
    assert version_tool.read_pyproject_version() == secretshield.__version__
    assert version_tool.problems() == []


def test_a_disagreement_between_sources_is_reported(monkeypatch):
    monkeypatch.setattr(version_tool, "read_package_version", lambda: "1.2.3")
    monkeypatch.setattr(version_tool, "read_pyproject_version", lambda: "1.2.4")
    problems = version_tool.problems()
    assert len(problems) == 1 and "1.2.3" in problems[0] and "1.2.4" in problems[0]


def test_tag_must_match_the_version():
    current = version_tool.read_package_version()
    assert version_tool.problems(f"v{current}") == []
    assert version_tool.problems(current) == []
    wrong = version_tool.problems("v9.9.9")
    assert wrong and "9.9.9" in wrong[0]


def test_an_empty_or_missing_tag_means_no_tag_check():
    # In CI an unset input becomes an empty string (SS_EXPECT_TAG=""), not None.
    assert version_tool.problems("") == []
    assert version_tool.problems(None) == []
    assert version_tool.problems("   ") != [], "whitespace is not a tag; only a truly empty value is ignored"


def test_build_does_not_treat_an_empty_expected_tag_as_a_mismatch(monkeypatch):
    PyInstaller = pytest.importorskip("PyInstaller")
    monkeypatch.setattr(build_tool, "REQUIRED_PYINSTALLER", PyInstaller.__version__)
    for value in ("", None):
        if value is None:
            monkeypatch.delenv("SS_EXPECT_TAG", raising=False)
        else:
            monkeypatch.setenv("SS_EXPECT_TAG", value)
        build_tool.check_environment()  # must not raise
    monkeypatch.setenv("SS_EXPECT_TAG", "v9.9.9")
    with pytest.raises(build_tool.BuildError, match="does not match"):
        build_tool.check_environment()


def test_the_version_is_parsed_without_importing_the_package(tmp_path):
    # Importing secretshield would turn on runtime protection as a side effect.
    init = tmp_path / "__init__.py"
    init.write_text('raise SystemExit("must not be executed")\n__version__ = "4.5.6"\n', encoding="utf-8")
    assert version_tool.read_package_version(init) == "4.5.6"


def test_pyproject_version_only_comes_from_the_project_table(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.x]\nversion = "0.0.0"\n[project]\nversion = "7.8.9"\n', encoding="utf-8")
    assert version_tool.read_pyproject_version(pyproject) == "7.8.9"


@pytest.mark.parametrize(
    "version, expected",
    [("0.13.2", (0, 13, 2, 0)), ("1.2.3.4", (1, 2, 3, 4)), ("0.13.2rc1", (0, 13, 2, 1)), ("1.0", (1, 0, 0, 0))],
)
def test_numeric_version_tuple(version, expected):
    assert version_tool.numeric_tuple(version) == expected


def test_copyright_comes_from_the_license_file():
    line = version_tool.read_copyright()
    assert line == next(l for l in (ROOT / "LICENSE").read_text(encoding="utf-8").splitlines() if l.startswith("Copyright"))
    assert "Samarth Chugh" in line


def test_version_cli_exit_codes():
    ok = subprocess.run([sys.executable, str(STANDALONE / "version.py"), "--check"], capture_output=True, text=True)
    assert ok.returncode == 0 and ok.stdout.strip() == secretshield.__version__
    bad = subprocess.run([sys.executable, str(STANDALONE / "version.py"), "--tag", "v0.0.0"], capture_output=True, text=True)
    assert bad.returncode == 1 and "does not match" in bad.stderr


def test_no_new_file_hardcodes_the_current_version():
    current = re.escape(secretshield.__version__)
    for path in [ISS, WORKFLOW, STANDALONE / "build.py", STANDALONE / "secretshield.spec",
                 STANDALONE / "entry.py", WINDOWS / "build-installer.ps1", WINDOWS / "test-installer.ps1"]:  # fmt: skip
        assert not re.search(rf"(?<![\d.]){current}(?![\d.])", path.read_text(encoding="utf-8")), path.name


# --- Build driver helpers --------------------------------------------------------------------------


@pytest.mark.parametrize("machine, label", [("AMD64", "x64"), ("x86_64", "x64"), ("arm64", "arm64"), ("aarch64", "arm64")])
def test_cpu_architecture_labels(monkeypatch, machine, label):
    monkeypatch.setattr(build_tool.platform, "machine", lambda: machine)
    assert build_tool.arch_label() == label


def test_unsupported_architecture_is_an_error(monkeypatch):
    monkeypatch.setattr(build_tool.platform, "machine", lambda: "riscv64")
    with pytest.raises(build_tool.BuildError, match="unsupported CPU"):
        build_tool.arch_label()


@pytest.mark.parametrize("platform_name, label", [("win32", "windows"), ("darwin", "macos"), ("linux", "linux")])
def test_os_labels_and_default_bundle_mode(monkeypatch, platform_name, label):
    monkeypatch.setattr(build_tool.sys, "platform", platform_name)
    assert build_tool.os_label() == label
    assert build_tool.default_mode() == ("onedir" if label == "windows" else "onefile")


def test_asset_names_follow_the_naming_scheme(monkeypatch):
    names = build_tool.ASSET_NAMES
    assert names["windows_installer"] == "secretshield-windows-x64-setup.exe"
    assert names["windows_portable"] == "secretshield-windows-x64-portable.zip"
    assert names["checksums"] == build_tool.CHECKSUM_FILE
    assert not any(re.search(r"\d+\.\d+\.\d+", n) for n in names.values()), "names are version-less so /latest/download/ links are stable"
    for key, arch in (("macos_arm64", "arm64"), ("macos_x64", "x64"), ("linux_x64", "x64")):
        assert names[key].endswith(arch)


def test_checksum_roundtrip_and_tamper_detection(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"alpha")
    (tmp_path / "b.bin").write_bytes(b"beta")
    listing = build_tool.write_checksums(tmp_path)
    lines = listing.read_text(encoding="utf-8").splitlines()
    assert lines == sorted(lines, key=lambda l: l.split("  ")[1])
    assert re.fullmatch(r"[0-9a-f]{64}  a\.bin", lines[0])
    build_tool.verify_checksums(tmp_path)
    (tmp_path / "a.bin").write_bytes(b"tampered")
    with pytest.raises(build_tool.BuildError, match="mismatch for a.bin"):
        build_tool.verify_checksums(tmp_path)


def test_checksums_detect_added_and_missing_files(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"alpha")
    build_tool.write_checksums(tmp_path)
    (tmp_path / "extra.bin").write_bytes(b"x")
    with pytest.raises(build_tool.BuildError, match="differ"):
        build_tool.verify_checksums(tmp_path)
    (tmp_path / "extra.bin").unlink()
    (tmp_path / "a.bin").unlink()
    with pytest.raises(build_tool.BuildError, match="differ"):
        build_tool.verify_checksums(tmp_path)


def test_checksum_file_matches_the_sha256sum_tool_format(tmp_path):
    (tmp_path / "x.bin").write_bytes(b"data")
    build_tool.write_checksums(tmp_path)
    if shutil.which("sha256sum"):
        result = subprocess.run(["sha256sum", "-c", "SHA256SUMS.txt"], cwd=tmp_path, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr


def test_the_portable_zip_is_reproducible_and_keeps_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    src = tmp_path / "src"
    (src / "_internal").mkdir(parents=True)
    (src / "secretshield").write_bytes(b"exe")
    (src / "secretshield").chmod(0o755)
    (src / "_internal" / "lib.so").write_bytes(b"lib")
    first, second = tmp_path / "1.zip", tmp_path / "2.zip"
    build_tool.deterministic_zip(src, first, "secretshield")
    build_tool.deterministic_zip(src, second, "secretshield")
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as zf:
        assert zf.namelist() == ["secretshield/_internal/lib.so", "secretshield/secretshield"]
        assert (zf.getinfo("secretshield/secretshield").external_attr >> 16) & 0o111


def test_build_refuses_when_versions_disagree(monkeypatch):
    monkeypatch.setattr(build_tool.ss_version, "problems", lambda tag=None: ["versions differ"])
    with pytest.raises(build_tool.BuildError, match="versions differ"):
        build_tool.check_environment()


def test_pinned_pyinstaller_matches_the_requirements_file():
    pins = (STANDALONE / "requirements-build.txt").read_text(encoding="utf-8")
    assert f"pyinstaller=={build_tool.REQUIRED_PYINSTALLER}" in pins
    assert "pyinstaller-hooks-contrib==" in pins


# --- PyInstaller spec -------------------------------------------------------------------------------------

SPEC_TEXT = (STANDALONE / "secretshield.spec").read_text(encoding="utf-8")


def test_spec_is_valid_python_and_bundles_both_launchers_around_one_runtime():
    ast.parse(SPEC_TEXT)
    assert 'for name in ("secretshield", "ss")' in SPEC_TEXT
    assert SPEC_TEXT.count("COLLECT(") == 1, "one shared runtime folder, not one per launcher"
    assert 'collect_submodules("secretshield")' in SPEC_TEXT
    assert "upx=False" in SPEC_TEXT and "console=True" in SPEC_TEXT
    assert '"onedir" if sys.platform == "win32" else "onefile"' in SPEC_TEXT


def test_spec_entry_point_is_the_normal_cli():
    """One CLI implementation: the entry only prepares the output streams, then runs main()."""
    source = (STANDALONE / "entry.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert "from secretshield.cli import main" in source and "sys.exit(main())" in source
    functions = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert functions == {"_same_encoding", "_apply", "prepare_streams"}
    assert not [n for n in tree.body if isinstance(n, ast.ClassDef)]
    imports = {a.name for n in tree.body if isinstance(n, ast.Import) for a in n.names}
    assert imports == {"codecs", "os", "sys"}, "no CLI libraries, no scanning code, nothing but stream setup"
    for forbidden in ("argparse", "add_parser", "detect(", "subparsers"):
        assert forbidden not in source


def test_dev_only_packages_are_excluded_from_the_bundle():
    for name in ("tkinter", "pytest", "setuptools", "pip"):
        assert f'"{name}"' in SPEC_TEXT


def _spec_version_function(namespace_extra=None):
    tree = ast.parse(SPEC_TEXT)
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_win_version_info")
    namespace = {
        "_ver": version_tool,
        "VERSION": version_tool.read_package_version(),
        "AUTHOR": "Samarth Chugh (Sam3360)",
        "COPYRIGHT": version_tool.read_copyright(),
    }
    namespace.update(namespace_extra or {})
    exec(compile(ast.Module([func], type_ignores=[]), "spec", "exec"), namespace)
    return namespace["_win_version_info"], namespace["VERSION"]


def test_windows_version_resource_is_built_from_real_product_metadata(monkeypatch):
    """Runs on every OS: PyInstaller's Windows classes are replaced by recorders."""
    import types

    class Record:
        def __init__(self, *args, **kwargs):
            self.args, self.kwargs = args, kwargs

    class StringStruct(Record):
        pass

    fake = types.ModuleType("PyInstaller.utils.win32.versioninfo")
    for name in ("FixedFileInfo", "StringFileInfo", "StringTable", "VarFileInfo", "VarStruct", "VSVersionInfo"):
        setattr(fake, name, type(name, (Record,), {}))
    fake.StringStruct = StringStruct
    monkeypatch.setitem(sys.modules, "PyInstaller.utils.win32.versioninfo", fake)

    func, version = _spec_version_function()
    info = func("ss.exe")
    nums = version_tool.numeric_tuple(version)
    ffi = info.kwargs["ffi"]
    assert ffi.kwargs["filevers"] == nums and ffi.kwargs["prodvers"] == nums

    strings = {}

    def walk(node):
        if isinstance(node, StringStruct):
            strings[node.args[0]] = node.args[1]
        for child in list(getattr(node, "args", ())) + list(getattr(node, "kwargs", {}).values()):
            for item in child if isinstance(child, list) else [child]:
                if isinstance(item, Record):
                    walk(item)

    walk(info)
    assert strings["ProductName"] == "SecretShield"
    assert strings["ProductVersion"] == strings["FileVersion"] == version
    assert strings["OriginalFilename"] == "ss.exe"
    assert strings["CompanyName"] == "Samarth Chugh (Sam3360)"
    assert strings["LegalCopyright"].startswith("Copyright") and strings["LegalCopyright"].endswith("MIT License.")
    assert "Inc." not in str(strings) and "Ltd" not in str(strings), "no invented company"


def test_windows_version_resource_with_the_real_pyinstaller_classes():
    try:
        import PyInstaller.utils.win32.versioninfo  # noqa: F401  (importable on Windows only)
    except ImportError:
        pytest.skip("PyInstaller's Windows metadata classes are only importable on Windows")
    func, version = _spec_version_function()
    text = str(func("ss.exe"))
    assert f"filevers={version_tool.numeric_tuple(version)}" in text
    assert "ProductName', 'SecretShield'" in text and "OriginalFilename', 'ss.exe'" in text


# --- Windows installer: static properties -------------------------------------------------------------------


def iss_value(key: str) -> str:
    match = re.search(rf"^{re.escape(key)}=(.*)$", ISS_TEXT, re.MULTILINE)
    assert match, f"{key} not set in the installer script"
    return match.group(1).strip()


def section(name: str) -> str:
    match = re.search(rf"^\[{name}\]\n(.*?)(?=^\[|\Z)", ISS_TEXT, re.MULTILINE | re.DOTALL)
    return match.group(1) if match else ""


def test_installer_is_per_user_by_default_and_never_prompts_for_admin():
    assert iss_value("PrivilegesRequired") == "lowest"
    assert iss_value("PrivilegesRequiredOverridesAllowed") == "commandline"
    assert iss_value("DefaultDirName").startswith("{autopf}")


def test_installer_version_and_paths_come_from_defines_not_literals():
    assert iss_value("AppVersion") == "{#AppVersion}"
    for define in ("AppVersion", "SourceDir"):
        assert f"#ifndef {define}" in ISS_TEXT
    assert ISS_TEXT.count("#error") >= 2
    assert not re.search(r"^AppVersion=\d", ISS_TEXT, re.MULTILINE)


def test_app_id_is_a_valid_guid_that_the_powershell_test_also_uses():
    guid = re.search(r'#define AppGuid\s+"([0-9A-F-]+)"', ISS_TEXT).group(1)
    assert re.fullmatch(r"[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}", guid)
    assert f"'{guid}'" in (WINDOWS / "test-installer.ps1").read_text(encoding="utf-8")
    assert iss_value("AppId") == "{{{#AppGuid}}"  # the doubled brace escapes the literal one


def test_installer_uses_the_project_license_publisher_and_urls():
    assert iss_value("LicenseFile") == r"{#RepoRoot}\LICENSE"
    assert (WINDOWS / "install-info.txt").is_file() and iss_value("InfoBeforeFile") == "install-info.txt"
    assert '#define AppPublisher "Samarth Chugh (Sam3360)"' in ISS_TEXT
    assert f'#define DocsURL      "{USAGE_URL}"' in ISS_TEXT
    assert "https://github.com/Sam3360/secretshield" in ISS_TEXT


def test_installer_output_name_matches_the_release_asset_name():
    default = re.search(r'#define OutputName "([^"]+)"', ISS_TEXT).group(1)
    assert default + ".exe" == build_tool.ASSET_NAMES["windows_installer"]


def test_installer_artwork_exists():
    for key in ("SetupIconFile", "WizardImageFile", "WizardSmallImageFile"):
        assert (WINDOWS / iss_value(key).replace("\\", "/")).is_file(), key


def test_path_integration_is_one_default_on_task_with_a_matching_uninstall():
    tasks = section("Tasks")
    assert 'Name: "addtopath"' in tasks and "unchecked" not in tasks
    assert iss_value("ChangesEnvironment") == "yes"
    assert "AddToPath(ExpandConstant('{app}'))" in ISS_TEXT
    assert "RemoveFromPath(ExpandConstant('{app}'))" in ISS_TEXT
    assert "WizardIsTaskSelected('addtopath')" in ISS_TEXT


def test_installer_only_deletes_what_it_owns():
    delete_lines = [l.strip() for l in section("InstallDelete").splitlines() if l.strip() and not l.strip().startswith(";")]
    targets = {re.search(r'Name: "([^"]+)"', l).group(1) for l in delete_lines}
    assert targets == {r"{app}\_internal", r"{app}\secretshield.exe", r"{app}\ss.exe"}
    uninstall = [re.search(r'Name: "([^"]+)"', l).group(1) for l in section("UninstallDelete").splitlines() if l.strip() and not l.strip().startswith(";")]
    assert uninstall == [r"{app}\_internal"]
    for dangerous in ("DelTree(", "{userdocs}", "{sys}", "{win}", "{userappdata}", "{localappdata}\\*", "{app}\\*"):
        assert dangerous not in "".join(delete_lines) + ISS_TEXT.replace("{autopf}", ""), dangerous


def test_installer_makes_no_unneeded_system_changes():
    assert section("Registry").strip() == "", "no registry entries besides the PATH value written in code"
    assert section("Icons").strip() == "", "no shortcuts: it is a command-line tool"
    assert "[Services]" not in ISS_TEXT and "RunOnce" not in ISS_TEXT and "[Run]" in ISS_TEXT
    run = section("Run")
    assert "postinstall" in run and "skipifsilent" in run and "unchecked" in run, "the docs link is opt-in"
    assert re.search(r'Flags:.*\bshellexec\b', run)


def test_installer_refuses_downgrades_and_explains_how_to_go_back():
    assert "CompareVersions(OldText, '{#AppVersion}') > 0" in ISS_TEXT
    assert "uninstall SecretShield first" in ISS_TEXT
    assert "Result := False" in ISS_TEXT


def test_installer_text_makes_no_unsupported_claims():
    info = " ".join((WINDOWS / "install-info.txt").read_text(encoding="utf-8").lower().split())
    welcome = ISS_TEXT.lower()
    for claim in ("malware", "virus-free", "100% secure", "fully secure", "guarantee", "verified publisher"):
        assert claim not in info and claim not in welcome, claim
    assert "not code-signed" in info and "does not prove who published" in info


# --- Windows installer: the PATH and version logic, executed (Free Pascal) -----------------------------------


def _pure_block() -> str:
    block = ISS_TEXT.split("{ ---- BEGIN PURE PATH HELPERS", 1)[1]
    block = block.split("}", 1)[1]  # skip the rest of the opening comment
    return block.split("{ ---- END PURE PATH HELPERS", 1)[0]


HARNESS = r"""
{$mode delphi}{$H+}
program installer_logic_test;
uses SysUtils;
var Fails: Integer;
@@BLOCK@@
procedure Eq(const Name, Got, Want: string);
begin
  if Got <> Want then begin Inc(Fails); WriteLn('FAIL ', Name, ': got [', Got, '] want [', Want, ']'); end;
end;
procedure EqB(const Name: string; Got, Want: Boolean);
begin
  if Got <> Want then begin Inc(Fails); WriteLn('FAIL ', Name, ': got ', Got, ' want ', Want); end;
end;
procedure EqI(const Name: string; Got, Want: Integer);
begin
  if Got <> Want then begin Inc(Fails); WriteLn('FAIL ', Name, ': got ', Got, ' want ', Want); end;
end;
const D = 'C:\Users\Sam\AppData\Local\Programs\SecretShield';
begin
  Fails := 0;
  Eq('norm trailing', NormalizeDir('C:\Foo\\'), 'C:\Foo');
  Eq('norm root', NormalizeDir('C:\'), 'C:\');
  Eq('norm spaces', NormalizeDir('  C:\Foo  '), 'C:\Foo');
  Eq('norm empty', NormalizeDir(''), '');
  EqB('contains no', PathContains('C:\a;C:\b', D), False);
  EqB('contains yes', PathContains('C:\a;' + D + ';C:\b', D), True);
  EqB('contains case', PathContains(LowerCase(D), UpperCase(D)), True);
  EqB('contains trailing slash', PathContains(D + '\', D), True);
  EqB('contains empty path', PathContains('', D), False);
  EqB('prefix is not a match', PathContains(D + 'Extra', D), False);
  Eq('append empty', PathAppend('', D), D);
  Eq('append normal', PathAppend('C:\a;C:\b', D), 'C:\a;C:\b;' + D);
  Eq('append trailing ;', PathAppend('C:\a;', D), 'C:\a;' + D);
  Eq('append duplicate unchanged', PathAppend('C:\a;' + D, D), 'C:\a;' + D);
  Eq('append dup other case', PathAppend('C:\a;' + UpperCase(D), D), 'C:\a;' + UpperCase(D));
  Eq('append keeps %VAR% entries', PathAppend('%SystemRoot%\system32;C:\a', D), '%SystemRoot%\system32;C:\a;' + D);
  Eq('remove middle', PathRemove('C:\a;' + D + ';C:\b', D), 'C:\a;C:\b');
  Eq('remove first', PathRemove(D + ';C:\b', D), 'C:\b');
  Eq('remove last', PathRemove('C:\a;' + D, D), 'C:\a');
  Eq('remove only', PathRemove(D, D), '');
  Eq('remove absent unchanged', PathRemove('C:\a;C:\b', D), 'C:\a;C:\b');
  Eq('remove keeps trailing ;', PathRemove('C:\a;' + D + ';', D), 'C:\a;');
  Eq('remove all duplicates', PathRemove(D + ';C:\a;' + D, D), 'C:\a');
  Eq('remove keeps unrelated + %VAR%', PathRemove('%SystemRoot%;C:\a;' + D + ';%USERPROFILE%\bin', D), '%SystemRoot%;C:\a;%USERPROFILE%\bin');
  Eq('remove empty', PathRemove('', D), '');
  Eq('roundtrip no trailing ;', PathRemove(PathAppend('C:\a;C:\b', D), D), 'C:\a;C:\b');
  Eq('roundtrip empty', PathRemove(PathAppend('', D), D), '');
  Eq('roundtrip keeps every entry (a trailing empty segment may be dropped)', PathRemove(PathAppend('C:\a;C:\b;', D), D), 'C:\a;C:\b');
  EqI('seg count empty', PathSegmentCount(''), 0);
  EqI('seg count 3', PathSegmentCount('a;b;c'), 3);
  EqI('seg count trailing', PathSegmentCount('a;b;'), 3);
  Eq('seg 0', PathSegmentAt('a;b;c', 0), 'a');
  Eq('seg 2', PathSegmentAt('a;b;c', 2), 'c');
  Eq('seg out of range', PathSegmentAt('a;b;c', 5), '');
  Eq('seg empty middle', PathSegmentAt('a;;c', 1), '');
  EqB('samedir equal', SameDir(D, D), True);
  EqB('samedir case', SameDir(D, UpperCase(D)), True);
  EqB('samedir trailing slash', SameDir(D + '\', D), True);
  EqB('samedir different', SameDir(D, 'C:\Elsewhere\SecretShield'), False);
  EqB('samedir prefix is not the same', SameDir(D, D + 'Two'), False);
  EqB('samedir empty vs dir', SameDir('', D), False);
  EqI('cmp equal', CompareVersions('0.13.2', '0.13.2'), 0);
  EqI('cmp older', CompareVersions('0.13.1', '0.13.2'), -1);
  EqI('cmp newer', CompareVersions('0.14.0', '0.13.9'), 1);
  EqI('cmp numeric not lexical', CompareVersions('0.13.10', '0.13.9'), 1);
  EqI('cmp two vs three parts', CompareVersions('0.13', '0.13.0'), 0);
  EqI('cmp 4th part', CompareVersions('0.13.2.1', '0.13.2'), 1);
  EqI('cmp suffix ignored', CompareVersions('0.13.2rc1', '0.13.2'), 0);
  EqI('cmp major', CompareVersions('1.0.0', '0.99.99'), 1);
  EqI('cmp empty', CompareVersions('', '0.0.1'), -1);
  EqI('cmp test build older than real', CompareVersions('0.0.1', '0.13.2'), -1);
  if Fails = 0 then WriteLn('ALL PASS') else Halt(1);
end.
"""


@pytest.mark.skipif(shutil.which("fpc") is None, reason="Free Pascal (fpc) not installed")
def test_installer_path_and_version_logic_executes_correctly(tmp_path):
    program = tmp_path / "t.pas"
    program.write_text(HARNESS.replace("@@BLOCK@@", _pure_block()), encoding="utf-8")
    compiled = subprocess.run(["fpc", "-Mdelphi", "-Sew", str(program), f"-o{tmp_path / 't'}"],
                              capture_output=True, text=True, cwd=tmp_path)  # fmt: skip
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    ran = subprocess.run([str(tmp_path / "t")], capture_output=True, text=True)
    assert ran.returncode == 0 and ran.stdout.strip() == "ALL PASS", ran.stdout


def test_upgrade_never_leaves_a_second_copy_beside_the_first():
    assert "function PrepareToInstall(var NeedsRestart: Boolean): String;" in ISS_TEXT
    assert "not SameDir(Existing, ExpandConstant('{app}'))" in ISS_TEXT
    for phrase in ("two copies and two PATH entries", "uninstall it first", "Nothing has been changed", "keep that folder"):
        assert phrase in ISS_TEXT, phrase
    assert iss_value("UsePreviousAppDir") == "yes"
    assert not re.search(r"^DisableDirPage=yes", ISS_TEXT, re.MULTILINE), "the folder page must be shown on a first install"
    assert "RegQueryStringValue(HKEY_CURRENT_USER, UninstallKey(), 'InstallLocation'" in ISS_TEXT
    assert "RegQueryStringValue(HKEY_LOCAL_MACHINE, UninstallKey(), 'InstallLocation'" in ISS_TEXT


def test_lifecycle_script_checks_clean_upgrade_and_clean_uninstall_guarantees():
    text = (WINDOWS / "test-installer.ps1").read_text(encoding="utf-8")
    for needle in ("keep-me.txt", "survived the upgrade", "was NOT deleted", "exactly one set of executables",
                   "secretshield.exe,ss.exe,unins000.exe", "resolves to the installed copy", "installing into a second folder",
                   "no second PATH entry", "no second copy of the program", ".secretshield-rules.toml", "secretshield.toml",
                   ".secretshieldignore", "user project files are byte-for-byte unchanged", "user PATH is back to exactly its original",
                   "stale file from the older version was removed", "nothing but the user file is left"):  # fmt: skip
        assert needle in text, needle


def test_pure_pascal_block_avoids_inno_only_calls():
    block = _pure_block()
    for inno_only in ("ExpandConstant", "RegQuery", "RegWrite", "FileExists", "GetEnv", "Log(", "MsgBox", "WizardForm"):
        assert inno_only not in block, inno_only


# --- PowerShell scripts: cheap static guards (they only run on Windows) -------------------------------------------


@pytest.mark.parametrize("script", ["build-installer.ps1", "test-installer.ps1"])
def test_powershell_scripts_fail_loudly_and_use_strict_mode(script):
    text = (WINDOWS / script).read_text(encoding="utf-8")
    assert "$ErrorActionPreference = 'Stop'" in text and "Set-StrictMode -Version Latest" in text


def lex_powershell(text: str) -> list[str]:
    """A small PowerShell-aware scan for obvious syntax mistakes.

    Walks the script handling line comments, <# block comments #>, '...' strings
    ('' escapes a quote), "..." strings (backtick and "" escapes), and @'...'@ /
    @"..."@ here-strings. Returns a list of problems: unterminated strings or
    comments, and brackets that don't balance *outside* strings and comments.
    It cannot prove the script is correct (only PowerShell can), but it catches
    the typos that would stop it from parsing at all.
    """
    problems: list[str] = []
    stack: list[tuple[str, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    i, line, n = 0, 1, len(text)
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if c == "\n":
            line += 1
            i += 1
        elif two == "<#":
            end = text.find("#>", i + 2)
            if end == -1:
                problems.append(f"line {line}: unterminated block comment")
                break
            line += text.count("\n", i, end)
            i = end + 2
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif two in ("@'", '@"') and text[i + 2 : i + 3] in ("\n", "\r"):
            closer = "\n" + two[1] + "@"
            end = text.find(closer, i + 2)
            if end == -1:
                problems.append(f"line {line}: unterminated here-string")
                break
            line += text.count("\n", i, end + 1)
            i = end + len(closer)
        elif c == "'":
            start, i = line, i + 1
            while i < n:
                if text[i] == "'" and text[i + 1 : i + 2] == "'":
                    i += 2
                elif text[i] == "'":
                    break
                else:
                    line += text[i] == "\n"
                    i += 1
            else:
                problems.append(f"line {start}: unterminated single-quoted string")
                break
            i += 1
        elif c == '"':
            start, i = line, i + 1
            while i < n:
                if text[i] == "`":
                    i += 2
                elif text[i] == '"' and text[i + 1 : i + 2] == '"':
                    i += 2
                elif text[i] == '"':
                    break
                else:
                    line += text[i] == "\n"
                    i += 1
            else:
                problems.append(f"line {start}: unterminated double-quoted string")
                break
            i += 1
        elif c in "([{":
            stack.append((c, line))
            i += 1
        elif c in ")]}":
            if not stack or stack[-1][0] != pairs[c]:
                problems.append(f"line {line}: unmatched {c!r}")
            else:
                stack.pop()
            i += 1
        else:
            i += 1
    problems += [f"line {ln}: unclosed {ch!r}" for ch, ln in stack]
    return problems


def test_the_powershell_lexer_catches_real_mistakes():
    assert lex_powershell("Write-Host 'ok' # it's a comment\n$x = @(1, 2)\n") == []
    assert lex_powershell("$a = 'it''s fine'\n$b = \"say `\"hi`\"\"\n") == []
    assert lex_powershell("<# block 'quote #>\nWrite-Host 1\n") == []
    assert lex_powershell("@'\nanything ( ' here\n'@\nWrite-Host 1\n") == []
    assert any("unterminated single" in p for p in lex_powershell("Write-Host 'oops\n"))
    assert any("unterminated double" in p for p in lex_powershell('Write-Host "oops\n'))
    assert any("unmatched" in p for p in lex_powershell("if ($x) { 1 } }\n"))
    assert any("unclosed" in p for p in lex_powershell("function f {\n  Write-Host 1\n"))


@pytest.mark.parametrize("script", ["build-installer.ps1", "test-installer.ps1"])
def test_powershell_scripts_have_terminated_strings_and_balanced_brackets(script):
    problems = lex_powershell((WINDOWS / script).read_text(encoding="utf-8"))
    assert problems == [], problems


def test_scripts_read_by_windows_tools_are_pure_ascii():
    """Windows PowerShell 5.1 and Inno Setup read BOM-less files as ANSI, which would
    silently corrupt any non-ASCII character. Build such text from code points instead."""
    for path in sorted(WINDOWS.glob("*.ps1")) + [ISS, WINDOWS / "install-info.txt"]:
        data = path.read_bytes()
        assert data.isascii(), f"{path.name} has non-ASCII bytes at {[i for i, b in enumerate(data) if b > 127][:3]}"


def test_workflow_runs_the_powershell_scripts_with_pwsh_like_the_rest_of_the_job():
    code = "\n".join(l for l in WORKFLOW_TEXT.splitlines() if not l.lstrip().startswith("#"))
    assert "pwsh -NoProfile -File standalone/windows/build-installer.ps1" in code
    assert "pwsh -NoProfile -File standalone/windows/test-installer.ps1" in code
    assert re.search(r"(?<![\w-])powershell(\.exe)? -", code) is None


def test_lifecycle_script_waits_for_the_self_deleting_uninstaller():
    text = (WINDOWS / "test-installer.ps1").read_text(encoding="utf-8")
    assert "function Wait-Uninstalled" in text and text.count("Wait-Uninstalled $") >= 4
    assert "-like 'unins*'" in text
    assert "-lt 20 -and (Test-Path" not in text, "no ad-hoc waits that ignore the uninstaller's own files"


def test_powershell_test_script_avoids_the_join_eq_precedence_trap():
    text = (WINDOWS / "test-installer.ps1").read_text(encoding="utf-8")
    for line in text.splitlines():
        if "-join" in line and re.search(r"-join\s+'[^']*'\s+-[ci]?eq", line):
            pytest.fail(f"-join chained with -eq without parentheses: {line.strip()}")


def test_powershell_test_script_covers_the_whole_lifecycle():
    text = (WINDOWS / "test-installer.ps1").read_text(encoding="utf-8")
    for step in ("Fresh per-user install", "Upgrade in place", "new terminal", "Scan outside the install folder",
                 "Reinstall same version", "Downgrade is refused", "Uninstall removes only", "Reinstall after uninstall",
                 "without the PATH task", "All-users install", "Portable archive"):  # fmt: skip
        assert step in text, step


# --- Release workflow ------------------------------------------------------------------------------------------------


def test_every_action_is_pinned_to_a_full_commit_sha():
    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", WORKFLOW_TEXT, re.MULTILINE)
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), f"not pinned to a commit SHA: {ref}"


def test_workflow_triggers_only_on_version_tags_or_by_hand():
    on = WORKFLOW_TEXT.split("\npermissions:", 1)[0]
    assert "tags: [\"v*\"]" in on and "workflow_dispatch:" in on
    assert "pull_request" not in WORKFLOW_TEXT
    assert not re.search(r"^\s+branches:", on, re.MULTILINE), "a push to a branch must not start a release build"


def test_workflow_is_read_only_except_the_one_opt_in_attach_job():
    assert re.search(r"^permissions:\n  contents: read\n", WORKFLOW_TEXT, re.MULTILINE)
    assert WORKFLOW_TEXT.count("contents: write") == 1
    attach = WORKFLOW_TEXT.split("attach-to-release:", 1)[1]
    assert "contents: write" in attach and "inputs.attach_to_release" in attach
    assert "github.event_name == 'workflow_dispatch'" in attach and "github.ref_type == 'tag'" in attach


def test_workflow_never_overwrites_creates_or_publishes():
    code = "\n".join(l for l in WORKFLOW_TEXT.splitlines() if not l.lstrip().startswith("#"))
    assert "--clobber" not in code, "an existing asset must make the upload fail, never be replaced"
    assert "gh release create" not in WORKFLOW_TEXT and "gh release edit" not in WORKFLOW_TEXT
    assert "gh release upload" in WORKFLOW_TEXT and "gh release view" in WORKFLOW_TEXT
    assert "twine upload" not in code
    assert "pypi" not in code.lower().replace("twine check", ""), "nothing here may touch PyPI"


def test_workflow_uses_no_secrets_beyond_the_default_token_and_no_untrusted_input_in_scripts():
    assert "secrets." not in WORKFLOW_TEXT
    assert WORKFLOW_TEXT.count("github.token") == 1
    for run_block in re.findall(r"run: \|\n((?:\s{10,}.*\n)+)", WORKFLOW_TEXT):
        assert "${{ github.ref_name }}" not in run_block and "${{ github.head_ref }}" not in run_block


def test_workflow_checks_out_without_persisting_credentials():
    assert WORKFLOW_TEXT.count("persist-credentials: false") == WORKFLOW_TEXT.count("actions/checkout@")


def test_workflow_builds_tests_and_ships_every_asset():
    for name in build_tool.ASSET_NAMES.values():
        stem = name.replace("secretshield-macos-arm64", "secretshield-macos-${{ matrix.arch }}").replace("secretshield-macos-x64", "secretshield-macos-${{ matrix.arch }}")
        assert name in WORKFLOW_TEXT or stem in WORKFLOW_TEXT or name == "SHA256SUMS.txt", name
    assert "secretshield-macos-${{ matrix.arch }}" in WORKFLOW_TEXT
    for needle in ("test_frozen_binary.py", "test-installer.ps1", "build-installer.ps1", "standalone/version.py --tag",
                   "python -m twine check", "standalone/build.py checksums", "standalone/build.py verify",
                   "runs-on: windows-2022", "runs-on: ubuntu-22.04", "macos-15", "macos-15-intel"):  # fmt: skip
        assert needle in WORKFLOW_TEXT, needle


def test_workflow_pins_the_installer_toolchain():
    assert re.search(r'INNO_SETUP_VERSION: "\d+\.\d+\.\d+"', WORKFLOW_TEXT)
    assert "choco install innosetup --version=" in WORKFLOW_TEXT


# --- Repository hygiene ------------------------------------------------------------------------------------------------


def test_build_outputs_are_git_ignored():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "dist/" in ignore and "build/" in ignore
    result = subprocess.run(["git", "check-ignore", "dist/release/x", "build/standalone/x", "dist/installer-test/x"],
                            cwd=ROOT, capture_output=True, text=True)  # fmt: skip
    if result.returncode in (0, 1):  # in a git checkout
        assert len(result.stdout.split()) == 3


def test_no_credentials_or_binaries_were_committed_into_standalone():
    allowed_binary = {".ico", ".bmp"}
    for path in STANDALONE.rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts:
            if path.suffix.lower() in allowed_binary:
                continue
            text = path.read_text(encoding="utf-8")
            assert not re.search(r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY", text), path


# --- Documentation matches what is actually built ------------------------------------------------------------------------

USAGE_TEXT = (ROOT / "USAGE.md").read_text(encoding="utf-8")
README_TEXT = (ROOT / "README.md").read_text(encoding="utf-8")


def test_usage_documents_every_release_asset_by_its_real_name():
    for name in build_tool.ASSET_NAMES.values():
        assert f"`{name}`" in USAGE_TEXT, name


def test_readme_leads_with_the_windows_installer_and_links_the_guide():
    assert build_tool.ASSET_NAMES["windows_installer"] in README_TEXT
    assert "https://github.com/Sam3360/secretshield/blob/main/USAGE.md#installation" in README_TEXT
    assert "https://github.com/Sam3360/secretshield/releases/latest" in README_TEXT
    assert README_TEXT.index("secretshield-windows-x64-setup.exe") < README_TEXT.index("pip install secretshield")
    assert "not code-signed" in README_TEXT


def test_install_guide_covers_every_required_topic():
    for needle in ("### Windows: installer (recommended)", "### Windows: portable zip", "### Linux and macOS: single-file binary",
                   "### pip (Python developers)", "**Upgrading:**", "**Uninstalling:**", "### Check a download",
                   "### Operating-system security warnings", "### Troubleshooting", "### What the standalone build can't do",
                   "Get-FileHash", "sha256sum", "SmartScreen", "Gatekeeper", "not code-signed", "/VERYSILENT", "/ALLUSERS",
                   "does **not** prove who published", "where ss", "ss --version", "ss scan ."):  # fmt: skip
        assert needle in USAGE_TEXT, needle


def test_install_guide_makes_no_unsupported_claims():
    low = " ".join(USAGE_TEXT.lower().split())
    for claim in ("virus-free", "malware-free", "100% secure", "notarized and signed", "is signed by", "works on every linux",
                  "all linux distributions are supported", "guaranteed"):  # fmt: skip
        assert claim not in low, claim
    assert "not code-signed or notarized" in low and "not tested" in low


def test_documented_urls_are_the_real_repository_urls():
    for url in re.findall(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", USAGE_TEXT + README_TEXT):
        assert url.startswith(("https://github.com/Sam3360/secretshield", "https://github.com/sponsors/Sam3360")) or "actions/" in url, url
