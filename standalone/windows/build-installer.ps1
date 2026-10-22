<#
.SYNOPSIS
  Builds the SecretShield Windows installer with Inno Setup.

.DESCRIPTION
  Expects the onedir build produced by `python standalone/build.py` (a folder
  containing secretshield.exe, ss.exe and _internal). The version always comes
  from standalone/version.py, which cross-checks pyproject.toml, unless
  -Version is given (used only to build the throw-away "older" installer for
  upgrade/downgrade tests).

.EXAMPLE
  python standalone/build.py
  powershell -File standalone\windows\build-installer.ps1
#>
[CmdletBinding()]
param(
    [string]$SourceDir,
    [string]$OutputName = 'secretshield-windows-x64-setup',
    [string]$OutputDir,
    [string]$Version,
    [string]$Iscc
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $SourceDir) { $SourceDir = Join-Path $repo 'dist\standalone\secretshield' }
if (-not $OutputDir) { $OutputDir = Join-Path $repo 'dist\release' }

# Single source of truth for the version (fails if pyproject.toml disagrees).
$packageVersion = (& python (Join-Path $repo 'standalone\version.py') --check | Select-Object -Last 1).Trim()
if ($LASTEXITCODE -ne 0) { throw 'standalone/version.py --check failed' }
if (-not $Version) { $Version = $packageVersion }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version '$Version' must look like 1.2.3" }
$numeric = "$Version.0"

foreach ($required in 'secretshield.exe', 'ss.exe', '_internal') {
    if (-not (Test-Path (Join-Path $SourceDir $required))) {
        throw "'$required' not found in $SourceDir. Run: python standalone/build.py"
    }
}

if (-not $Iscc) {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    $Iscc = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $Iscc) {
        $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        if ($cmd) { $Iscc = $cmd.Source }
    }
}
if (-not $Iscc -or -not (Test-Path $Iscc)) {
    throw 'Inno Setup compiler (ISCC.exe) not found. Install Inno Setup 6 or pass -Iscc.'
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$script = Join-Path $PSScriptRoot 'secretshield.iss'
Write-Host "Compiling $OutputName for version $Version with $Iscc"
& $Iscc "/DAppVersion=$Version" "/DNumericVersion=$numeric" "/DSourceDir=$SourceDir" `
    "/DOutputName=$OutputName" "/O$OutputDir" '/Qp' $script
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }

$installer = Join-Path $OutputDir "$OutputName.exe"
if (-not (Test-Path $installer)) { throw "Expected installer was not produced: $installer" }
if ((Get-Item $installer).Length -lt 1MB) { throw "Installer is suspiciously small: $installer" }
Write-Host "Built $installer ($([math]::Round((Get-Item $installer).Length / 1MB, 1)) MB)"
