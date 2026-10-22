; ============================================================================
; SecretShield -- Windows installer (Inno Setup 6.3 or newer)
;
; Build it with:  powershell -File standalone\windows\build-installer.ps1
; (that script passes the /D defines below). Do not hard-code a version here.
;
; Design:
;   * Per-user install by default: no administrator rights, no UAC prompt.
;     An all-users install is available from the command line only
;     (Setup.exe /ALLUSERS), so the normal wizard stays short.
;   * Installs ONE copy of the app (secretshield.exe + ss.exe launchers around
;     a shared runtime folder). Both commands run the same code.
;   * PATH: one optional, default-on task. Only this folder is added, only if
;     missing, and the uninstaller removes exactly that entry again.
;   * Nothing runs in the background, nothing is written outside the install
;     folder except the uninstall entry and (optionally) the PATH value.
; ============================================================================

#ifndef AppVersion
  #error Pass the version on the command line: ISCC /DAppVersion=x.y.z (see build-installer.ps1)
#endif
#ifndef NumericVersion
  #define NumericVersion AppVersion + ".0"
#endif
#ifndef SourceDir
  #error Pass the folder to package: ISCC /DSourceDir=...\dist\standalone\secretshield
#endif
#ifndef OutputName
  #define OutputName "secretshield-windows-x64-setup"
#endif
#ifndef RepoRoot
  #define RepoRoot "..\.."
#endif

; The AppId GUID identifies this product across versions. It must NEVER change:
; it is how an upgrade finds and replaces the previous installation.
#define AppGuid      "59D4E691-DE3A-45F6-B026-DAF208839A37"
#define AppName      "SecretShield"
#define AppPublisher "Samarth Chugh (Sam3360)"
#define AppURL       "https://github.com/Sam3360/secretshield"
#define ReleasesURL  "https://github.com/Sam3360/secretshield/releases"
#define DocsURL      "https://github.com/Sam3360/secretshield/blob/main/USAGE.md"

[Setup]
AppId={{{#AppGuid}}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#ReleasesURL}
VersionInfoVersion={#NumericVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} Setup
DefaultDirName={autopf}\{#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile={#RepoRoot}\LICENSE
InfoBeforeFile=install-info.txt
OutputDir={#RepoRoot}\dist\release
OutputBaseFilename={#OutputName}
SetupIconFile=assets\secretshield.ico
UninstallDisplayIcon={app}\secretshield.exe
UninstallDisplayName={#AppName}
WizardStyle=modern
WizardImageFile=assets\wizard-large.bmp
WizardSmallImageFile=assets\wizard-small.bmp
Compression=lzma2/ultra
SolidCompression=yes
ChangesEnvironment=yes
CloseApplications=yes
RestartApplications=no
UsePreviousAppDir=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nSecretShield is a command-line tool that finds leaked secrets in your code and helps you fix them. It runs on your computer and does not collect or send usage data.%n%nClick Next to continue.
ConfirmUninstall=Are you sure you want to completely remove %1?%n%nOnly SecretShield's own program files (and the PATH entry the installer added) are removed. Your projects, and any secretshield.toml, rules or baseline files inside them, are not touched.

[Tasks]
Name: "addtopath"; Description: "Add SecretShield to the PATH (recommended), so that the ss and secretshield commands work in any new terminal"; GroupDescription: "Command line:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Remove only what this installer owns, so an upgrade never leaves stale
; libraries from an older version behind.
Type: filesandordirs; Name: "{app}\_internal"
Type: files; Name: "{app}\secretshield.exe"
Type: files; Name: "{app}\ss.exe"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\_internal"

[Run]
Filename: "{#DocsURL}"; Description: "Open the getting-started guide in my browser"; Flags: shellexec postinstall skipifsilent unchecked

[Code]
{ ---- BEGIN PURE PATH HELPERS ------------------------------------------------
  Plain string logic with no Inno-only calls, so tests/test_packaging.py can
  extract this block and run it under Free Pascal. Keep it that way. }

function NormalizeDir(const S: string): string;
var
  Done: Boolean;
begin
  Result := Trim(S);
  Done := False;
  while not Done do
  begin
    Done := True;
    if Length(Result) > 0 then
      if Result[Length(Result)] = '\' then
        if not ((Length(Result) = 3) and (Copy(Result, 2, 1) = ':')) then
        begin
          Delete(Result, Length(Result), 1);
          Done := False;
        end;
  end;
end;

function PathContains(const PathValue, Dir: string): Boolean;
var
  Rest, Seg, Target: string;
  P: Integer;
begin
  Result := False;
  Target := Lowercase(NormalizeDir(Dir));
  Rest := PathValue;
  while Length(Rest) > 0 do
  begin
    P := Pos(';', Rest);
    if P = 0 then
    begin
      Seg := Rest;
      Rest := '';
    end
    else
    begin
      Seg := Copy(Rest, 1, P - 1);
      Delete(Rest, 1, P);
    end;
    if Lowercase(NormalizeDir(Seg)) = Target then
      Result := True;
  end;
end;

function PathAppend(const PathValue, Dir: string): string;
begin
  if PathContains(PathValue, Dir) then
    Result := PathValue
  else if Length(PathValue) = 0 then
    Result := NormalizeDir(Dir)
  else if PathValue[Length(PathValue)] = ';' then
    Result := PathValue + NormalizeDir(Dir)
  else
    Result := PathValue + ';' + NormalizeDir(Dir);
end;

function PathRemove(const PathValue, Dir: string): string;
var
  Rest, Seg, Target: string;
  P: Integer;
  First, HasMore: Boolean;
begin
  Result := '';
  Target := Lowercase(NormalizeDir(Dir));
  Rest := PathValue;
  First := True;
  HasMore := Length(PathValue) > 0;
  while HasMore do
  begin
    P := Pos(';', Rest);
    if P = 0 then
    begin
      Seg := Rest;
      HasMore := False;
    end
    else
    begin
      Seg := Copy(Rest, 1, P - 1);
      Delete(Rest, 1, P);
    end;
    if Lowercase(NormalizeDir(Seg)) <> Target then
    begin
      if not First then
        Result := Result + ';';
      Result := Result + Seg;
      First := False;
    end;
  end;
end;

function PathSegmentCount(const PathValue: string): Integer;
var
  I: Integer;
begin
  if Length(PathValue) = 0 then
    Result := 0
  else
  begin
    Result := 1;
    for I := 1 to Length(PathValue) do
      if PathValue[I] = ';' then
        Result := Result + 1;
  end;
end;

function PathSegmentAt(const PathValue: string; Index: Integer): string;
var
  Rest: string;
  P, N: Integer;
begin
  Result := '';
  Rest := PathValue;
  N := 0;
  while N <= Index do
  begin
    P := Pos(';', Rest);
    if P = 0 then
    begin
      if N = Index then
        Result := Rest;
      N := Index + 1;
    end
    else
    begin
      if N = Index then
        Result := Copy(Rest, 1, P - 1);
      Delete(Rest, 1, P);
      N := N + 1;
    end;
  end;
end;

{ True if two folder names are the same place (ignores case and trailing slashes). }
function SameDir(const A, B: string): Boolean;
begin
  Result := Lowercase(NormalizeDir(A)) = Lowercase(NormalizeDir(B));
end;

{ Compare dotted versions such as 1.2.3 numerically: -1, 0 or 1. Anything that
  is not a digit after a component's leading digits (like "rc1") is ignored. }
function VersionPart(const Version: string; Index: Integer): Integer;
var
  I, Dots: Integer;
  Stop: Boolean;
begin
  Result := 0;
  Dots := 0;
  Stop := False;
  for I := 1 to Length(Version) do
  begin
    if Version[I] = '.' then
    begin
      Dots := Dots + 1;
      Stop := False;
    end
    else if (Dots = Index) and (not Stop) then
    begin
      if (Version[I] >= '0') and (Version[I] <= '9') then
        Result := Result * 10 + (Ord(Version[I]) - Ord('0'))
      else
        Stop := True;
    end;
  end;
end;

function CompareVersions(const A, B: string): Integer;
var
  I, PA, PB: Integer;
begin
  Result := 0;
  for I := 0 to 3 do
    if Result = 0 then
    begin
      PA := VersionPart(A, I);
      PB := VersionPart(B, I);
      if PA < PB then
        Result := -1
      else if PA > PB then
        Result := 1;
    end;
end;

{ ---- END PURE PATH HELPERS ------------------------------------------------ }

const
  UserEnvKey   = 'Environment';
  SystemEnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function UninstallKey(): string;
begin
  Result := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{' + '{#AppGuid}' + '}_is1';
end;

function EnvRoot(): Integer;
begin
  if IsAdminInstallMode then
    Result := HKEY_LOCAL_MACHINE
  else
    Result := HKEY_CURRENT_USER;
end;

function EnvSubKey(): string;
begin
  if IsAdminInstallMode then
    Result := SystemEnvKey
  else
    Result := UserEnvKey;
end;

procedure AddToPath(const Dir: string);
var
  Current, Updated: string;
begin
  if not RegQueryStringValue(EnvRoot(), EnvSubKey(), 'Path', Current) then
    Current := '';
  Updated := PathAppend(Current, Dir);
  if Updated <> Current then
  begin
    Log('Adding to PATH: ' + Dir);
    RegWriteExpandStringValue(EnvRoot(), EnvSubKey(), 'Path', Updated);
  end
  else
    Log('PATH already contains ' + Dir);
end;

procedure RemoveFromPath(const Dir: string);
var
  Current, Updated: string;
begin
  if RegQueryStringValue(EnvRoot(), EnvSubKey(), 'Path', Current) then
  begin
    Updated := PathRemove(Current, Dir);
    if Updated <> Current then
    begin
      Log('Removing from PATH: ' + Dir);
      RegWriteExpandStringValue(EnvRoot(), EnvSubKey(), 'Path', Updated);
    end;
  end;
end;

function InstalledVersion(var Version: string): Boolean;
begin
  Result := RegQueryStringValue(HKEY_CURRENT_USER, UninstallKey(), 'DisplayVersion', Version);
  if not Result then
    Result := RegQueryStringValue(HKEY_LOCAL_MACHINE, UninstallKey(), 'DisplayVersion', Version);
end;

function InitializeSetup(): Boolean;
var
  OldText: string;
begin
  Result := True;
  if InstalledVersion(OldText) then
    if CompareVersions(OldText, '{#AppVersion}') > 0 then
    begin
      Log('Refusing to downgrade from ' + OldText + ' to {#AppVersion}');
      SuppressibleMsgBox(
        'SecretShield ' + OldText + ' is already installed. This installer contains the older version {#AppVersion}.' + #13#10#13#10 +
        'To go back to an older version, uninstall SecretShield first (Settings > Apps), then run this installer again.',
        mbError, MB_OK, IDOK);
      Result := False;
    end;
end;

function InstalledLocation(var Dir: string): Boolean;
begin
  Result := RegQueryStringValue(HKEY_CURRENT_USER, UninstallKey(), 'InstallLocation', Dir);
  if not Result then
    Result := RegQueryStringValue(HKEY_LOCAL_MACHINE, UninstallKey(), 'InstallLocation', Dir);
  if Result then
    Result := Length(Trim(Dir)) > 0;
end;

{ An upgrade must replace the existing installation, never sit beside it: a
  second copy in another folder would mean duplicate executables and two PATH
  entries. The wizard reuses the old folder automatically; this catches an
  explicit /DIR=, or a per-user install over an all-users one (or the reverse),
  before anything is changed. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Existing: string;
begin
  Result := '';
  if InstalledLocation(Existing) then
    if not SameDir(Existing, ExpandConstant('{app}')) then
    begin
      Log('Refusing to install beside an existing installation in ' + Existing);
      Result := 'SecretShield is already installed in:' + #13#10#13#10 + '    ' + NormalizeDir(Existing) + #13#10#13#10 +
        'Installing it into a different folder would leave two copies and two PATH entries behind.' + #13#10#13#10 +
        'To upgrade, run this installer again and keep that folder. To move SecretShield, uninstall it first (Settings > Apps), then run this installer again. Nothing has been changed.';
    end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = wpSelectDir then
    if Pos(';', WizardDirValue) > 0 then
    begin
      MsgBox('The folder name cannot contain a semicolon (;), because that would break the PATH list. Please choose another folder.', mbError, MB_OK);
      Result := False;
    end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    if WizardIsTaskSelected('addtopath') then
      AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;

{ Another SecretShield on PATH (for example one installed with pip) is not an
  error, but which one runs first matters, so say so on the final page. }
function FindOtherInstall(): string;
var
  PathValue, Dir, Ours: string;
  I: Integer;
begin
  Result := '';
  PathValue := GetEnv('PATH');
  Ours := Lowercase(NormalizeDir(ExpandConstant('{app}')));
  for I := 0 to PathSegmentCount(PathValue) - 1 do
  begin
    Dir := NormalizeDir(PathSegmentAt(PathValue, I));
    if (Length(Dir) > 0) and (Lowercase(Dir) <> Ours) then
      if FileExists(Dir + '\secretshield.exe') or FileExists(Dir + '\ss.exe') then
      begin
        if Length(Result) = 0 then
          Result := Dir;
      end;
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
var
  Text, Other: string;
begin
  if CurPageID = wpFinished then
  begin
    Text := 'SecretShield is installed.' + #13#10#13#10;
    if WizardIsTaskSelected('addtopath') then
      Text := Text + 'Open a NEW terminal (PowerShell or Command Prompt) so the updated PATH takes effect, then try:' + #13#10#13#10 +
        '    ss --version' + #13#10 + '    cd your-project' + #13#10 + '    ss scan .' + #13#10 + '    ss --help'
    else
      Text := Text + 'It was not added to your PATH. Run it with its full path:' + #13#10#13#10 +
        '    "' + ExpandConstant('{app}') + '\secretshield.exe" --version';
    Other := FindOtherInstall();
    if Length(Other) > 0 then
      Text := Text + #13#10#13#10 + 'Note: another SecretShield was found in ' + Other +
        ' (for example from pip). Whichever comes first in your PATH runs when you type ss; use "where ss" to check.';
    WizardForm.FinishedLabel.Caption := Text;
  end;
end;
