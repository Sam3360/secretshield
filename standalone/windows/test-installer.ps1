<#
.SYNOPSIS
  End-to-end test of the SecretShield installer lifecycle, for CI.

.DESCRIPTION
  Runs real silent installs on the machine it is started on and changes the
  *user* PATH (and the machine PATH for the all-users case), so run it only on
  a disposable machine such as a CI runner or a VM. It restores PATH and
  removes everything it installed.

  Covers: per-user install without admin rights, both command aliases, PATH
  entry added exactly once, a new-terminal simulation, scanning outside the
  install folder (spaces + non-ASCII), user files untouched, reinstall,
  upgrade (stale files removed), downgrade refusal, uninstall (files and PATH
  entry removed, unrelated PATH entries preserved), reinstall after uninstall,
  all-users install (when run as administrator) and the portable archive.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Installer,
    [Parameter(Mandatory)][string]$OlderInstaller,
    [Parameter(Mandatory)][string]$PortableZip,
    [Parameter(Mandatory)][string]$ExpectedVersion
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$AppGuid = '59D4E691-DE3A-45F6-B026-DAF208839A37'
$UninstallKeyUser = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{$AppGuid}_is1"
$UninstallKeyMachine = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{$AppGuid}_is1"
$script:Checks = 0

function Assert([bool]$Condition, [string]$Message) {
    $script:Checks++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
    Write-Host "  ok: $Message"
}

function Step([string]$Title) { Write-Host "`n=== $Title ===" }

function Get-RawPath([string]$Scope) {
    # Unexpanded registry value, so %VAR% entries can be compared exactly.
    $key = if ($Scope -eq 'User') { 'HKCU:\Environment' }
           else { 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' }
    return [string](Get-Item $key).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
}

function Get-Entries([string]$PathValue) {
    # Windows ignores empty PATH segments, so compare the real entries only.
    return @($PathValue.Split(';') | Where-Object { $_ -ne '' })
}

function Same-Path([string]$A, [string]$B) {
    # Same real entries in the same order. (An empty trailing segment is not an
    # entry, and uninstalling may drop one that the original value had.)
    return (((Get-Entries $A) -join ';') -ceq ((Get-Entries $B) -join ';'))
}

function Set-NewTerminalPath {
    # What a freshly opened terminal would see.
    $m = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $u = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$m;$u"
}

function Invoke-Setup([string]$Exe, [string[]]$SetupArgs) {
    $p = Start-Process -FilePath $Exe -ArgumentList $SetupArgs -Wait -PassThru
    return $p.ExitCode
}

function Wait-Uninstalled([string]$Dir) {
    # Setup returns before the uninstaller has finished deleting itself, so wait
    # until the program files and the unins*.exe/.dat files are all gone.
    for ($i = 0; $i -lt 40; $i++) {
        $left = @(Get-ChildItem $Dir -Force -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -in 'secretshield.exe', 'ss.exe', '_internal' -or $_.Name -like 'unins*' })
        if ($left.Count -eq 0) { return }
        Start-Sleep -Milliseconds 500
    }
}

function Count-Occurrences([string[]]$Entries, [string]$Dir) {
    return @($Entries | Where-Object { $_.TrimEnd('\') -ieq $Dir.TrimEnd('\') }).Count
}

function Invoke-Clean([string]$Exe, [string[]]$CliArgs, [string]$WorkDir) {
    # Run with a minimal environment: no PATH to any Python, no PYTHON* variables.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ($CliArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.WorkingDirectory = $WorkDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.EnvironmentVariables.Clear()
    foreach ($name in 'SystemRoot', 'windir', 'TEMP', 'TMP', 'USERPROFILE') {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) { $psi.EnvironmentVariables[$name] = $value }
    }
    $psi.EnvironmentVariables['PATH'] = "$env:SystemRoot\System32;$env:SystemRoot"
    $proc = [System.Diagnostics.Process]::Start($psi)
    $out = $proc.StandardOutput.ReadToEnd()
    $err = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    return [pscustomobject]@{ ExitCode = $proc.ExitCode; Out = $out; Err = $err }
}

foreach ($f in $Installer, $OlderInstaller, $PortableZip) {
    if (-not (Test-Path $f)) { throw "Missing input file: $f" }
}
$Installer = (Resolve-Path $Installer).Path
$OlderInstaller = (Resolve-Path $OlderInstaller).Path
$PortableZip = (Resolve-Path $PortableZip).Path

$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$root = Join-Path $tempRoot "ss install test $([guid]::NewGuid().ToString('N').Substring(0, 6))"
$installDir = Join-Path $root 'Secret Shield'                  # a space in the path
$project = Join-Path $root ('pr' + [char]0x00F6 + 'jekt ' + [char]0x5BC6 + [char]0x94A5)  # non-ASCII + space
New-Item -ItemType Directory -Force -Path $project | Out-Null

$userPathBefore = Get-RawPath 'User'
$secretKey = 'AKIA' + 'ABCDEFGHIJKLMNOP'                       # fake key, split so this file is not itself a finding
Set-Content -Path (Join-Path $project 'leak.py') -Value "k = `"$secretKey`"" -Encoding UTF8
Set-Content -Path (Join-Path $project 'clean.py') -Value 'print("hello")' -Encoding UTF8
# The user's own SecretShield configuration lives in the project; no install step may touch it.
Set-Content -Path (Join-Path $project 'secretshield.toml') -Value "[scan]`nentropy_threshold = 4.2`n" -Encoding UTF8
Set-Content -Path (Join-Path $project '.secretshield-rules.toml') -Value "[[rules]]`nname = `"My Rule`"`npattern = `"ZZZ_[0-9]{4}`"`n" -Encoding UTF8
Set-Content -Path (Join-Path $project '.secretshieldignore') -Value "ignored-dir/`n" -Encoding UTF8
$userFileHashes = Get-ChildItem $project -File -Force | Get-FileHash | ForEach-Object { "$($_.Path)=$($_.Hash)" }

$silent = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER', "/DIR=`"$installDir`"", '/TASKS="addtopath"')

try {
    Step '1. Fresh per-user install (the older 0.0.1 build first, so step 2 can test an upgrade)'
    Assert ((Invoke-Setup $OlderInstaller ($silent + "/LOG=`"$root\older.log`"")) -eq 0) 'older installer (0.0.1) installs'
    Assert ((Get-ItemProperty $UninstallKeyUser).DisplayVersion -eq '0.0.1') 'older install registered as 0.0.1'
    Assert (Test-Path (Join-Path $installDir 'secretshield.exe')) 'secretshield.exe installed'
    Assert (Test-Path (Join-Path $installDir 'ss.exe')) 'ss.exe installed'
    Assert (Test-Path (Join-Path $installDir '_internal')) 'shared runtime folder installed'
    $entries = Get-Entries (Get-RawPath 'User')
    Assert ((Count-Occurrences $entries $installDir) -eq 1) 'install folder is in the user PATH exactly once'

    Step '2. Upgrade in place (stale files removed, no duplicate executables, user files kept, PATH not duplicated)'
    $stale = Join-Path $installDir '_internal\stale-from-older-version.dll'
    Set-Content -Path $stale -Value 'stale'
    # A file the USER put in the install folder must survive upgrade and uninstall.
    $sentinel = Join-Path $installDir 'keep-me.txt'
    Set-Content -Path $sentinel -Value 'my own notes'
    Assert ((Invoke-Setup $Installer ($silent + "/LOG=`"$root\upgrade.log`"")) -eq 0) 'current installer upgrades the older install'
    Assert (-not (Test-Path $stale)) 'stale file from the older version was removed'
    Assert (Test-Path $sentinel) 'a file the user put in the install folder survived the upgrade'
    $topExes = (Get-ChildItem $installDir -File -Filter '*.exe' | Sort-Object Name | ForEach-Object { $_.Name }) -join ','
    Assert ($topExes -eq 'secretshield.exe,ss.exe,unins000.exe') "exactly one set of executables after the upgrade ($topExes)"
    Assert (@(Get-ChildItem (Join-Path $installDir '_internal') -Recurse -File -Filter '*.exe').Count -eq 0) 'no executables hidden inside the runtime folder'
    Assert ((Get-ItemProperty $UninstallKeyUser).DisplayVersion -eq $ExpectedVersion) "registered version is now $ExpectedVersion"
    Assert ((Count-Occurrences (Get-Entries (Get-RawPath 'User')) $installDir) -eq 1) 'PATH still contains the folder exactly once'

    Step '3. Both commands report the right version (installed exe and a new terminal)'
    foreach ($name in 'secretshield.exe', 'ss.exe') {
        $r = Invoke-Clean (Join-Path $installDir $name) @('--version') $project
        Assert ($r.ExitCode -eq 0 -and $r.Out.Trim() -eq "secretshield $ExpectedVersion") "$name --version -> secretshield $ExpectedVersion (clean environment)"
    }
    Set-NewTerminalPath
    foreach ($cmd in 'ss', 'secretshield') {
        Assert (((Get-Command $cmd -CommandType Application | Select-Object -First 1).Source) -ieq (Join-Path $installDir "$cmd.exe")) "'$cmd' resolves to the installed copy"
    }
    foreach ($cmd in 'ss', 'secretshield') {
        $out = (& cmd.exe /c "$cmd --version" 2>&1 | Out-String).Trim()
        Assert ($LASTEXITCODE -eq 0 -and $out -eq "secretshield $ExpectedVersion") "'$cmd --version' works from a new terminal"
    }

    Step '4. Scan outside the install folder (spaces + non-ASCII path), exit codes, user files untouched'
    Push-Location $project
    try {
        & ss scan . 2>&1 | Out-Null
        Assert ($LASTEXITCODE -eq 1) 'ss scan . exits 1 when a secret is found'
        $json = (& ss scan . --json | Out-String) | ConvertFrom-Json
        Assert ($json.secrets_found -eq 1) '--json reports exactly one finding'
        Assert (-not ($json | ConvertTo-Json -Depth 8).Contains($secretKey)) 'the secret value is not printed'
        & ss scan clean.py 2>&1 | Out-Null
        Assert ($LASTEXITCODE -eq 0) 'ss scan clean.py exits 0'
    } finally { Pop-Location }
    $after = Get-ChildItem $project -File -Force | Get-FileHash | ForEach-Object { "$($_.Path)=$($_.Hash)" }
    Assert (($after -join '|') -eq ($userFileHashes -join '|')) 'user project files are byte-for-byte unchanged'

    Step '5. Reinstall same version (repair)'
    Assert ((Invoke-Setup $Installer ($silent + "/LOG=`"$root\reinstall.log`"")) -eq 0) 'reinstalling the same version succeeds'
    Assert ((Count-Occurrences (Get-Entries (Get-RawPath 'User')) $installDir) -eq 1) 'PATH still has no duplicate'

    Step '6. Downgrade is refused'
    $code = Invoke-Setup $OlderInstaller ($silent + "/LOG=`"$root\downgrade.log`"")
    Assert ($code -ne 0) "older installer exits non-zero (exit code $code)"
    Assert ((Get-ItemProperty $UninstallKeyUser).DisplayVersion -eq $ExpectedVersion) 'installed version unchanged by the refused downgrade'

    Step '6b. Installing beside an existing installation (a different folder) is refused, changing nothing'
    $elsewhere = Join-Path $root 'Elsewhere Copy'
    $otherArgs = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER', "/DIR=`"$elsewhere`"", '/TASKS="addtopath"')
    $code = Invoke-Setup $Installer $otherArgs
    Assert ($code -ne 0) "installing into a second folder exits non-zero (exit code $code)"
    Assert (-not (Test-Path (Join-Path $elsewhere 'secretshield.exe'))) 'no second copy of the program was created'
    Assert ((Count-Occurrences (Get-Entries (Get-RawPath 'User')) $elsewhere) -eq 0) 'no second PATH entry was added'
    Assert ((Count-Occurrences (Get-Entries (Get-RawPath 'User')) $installDir) -eq 1) 'the original PATH entry is intact'
    Assert ((Get-ItemProperty $UninstallKeyUser).DisplayVersion -eq $ExpectedVersion) 'the existing installation is unchanged'

    Step '7. Uninstall removes only what it installed'
    $unins = Get-ChildItem $installDir -Filter 'unins*.exe' | Select-Object -First 1
    Assert ($null -ne $unins) 'uninstaller present'
    Assert ((Invoke-Setup $unins.FullName @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART')) -eq 0) 'uninstaller runs silently'
    Wait-Uninstalled $installDir
    Assert (-not (Test-Path (Join-Path $installDir 'secretshield.exe'))) 'program files removed'
    Assert (-not (Test-Path (Join-Path $installDir 'ss.exe'))) 'the ss launcher removed'
    Assert (-not (Test-Path (Join-Path $installDir '_internal'))) 'the shared runtime folder removed'
    Assert (Test-Path $sentinel) 'a file the user put in the install folder was NOT deleted'
    Assert ((@(Get-ChildItem $installDir -Force | ForEach-Object { $_.Name }) -join ',') -eq 'keep-me.txt') 'nothing but the user file is left in the install folder'
    Remove-Item $sentinel -Force
    Assert (-not (Test-Path $UninstallKeyUser)) 'uninstall registry entry removed'
    Assert ((Count-Occurrences (Get-Entries (Get-RawPath 'User')) $installDir) -eq 0) 'PATH entry removed'
    Assert (Same-Path (Get-RawPath 'User') $userPathBefore) 'user PATH is back to exactly its original entries'
    $after = Get-ChildItem $project -File -Force | Get-FileHash | ForEach-Object { "$($_.Path)=$($_.Hash)" }
    Assert (($after -join '|') -eq ($userFileHashes -join '|')) 'user project files still untouched after uninstall'

    Step '8. Reinstall after uninstall, then uninstall again'
    Assert ((Invoke-Setup $Installer ($silent + "/LOG=`"$root\again.log`"")) -eq 0) 'fresh install after uninstall succeeds'
    Assert ((Count-Occurrences (Get-Entries (Get-RawPath 'User')) $installDir) -eq 1) 'PATH entry present once'
    $unins = Get-ChildItem $installDir -Filter 'unins*.exe' | Select-Object -First 1
    Assert ((Invoke-Setup $unins.FullName @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART')) -eq 0) 'second uninstall succeeds'
    Wait-Uninstalled $installDir

    Step '9. Install without the PATH task leaves PATH alone'
    $noPath = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER', "/DIR=`"$installDir`"", '/TASKS=""')
    Assert ((Invoke-Setup $Installer $noPath) -eq 0) 'install with the PATH task unchecked succeeds'
    Assert (Same-Path (Get-RawPath 'User') $userPathBefore) 'user PATH untouched when the task is not selected'
    $unins = Get-ChildItem $installDir -Filter 'unins*.exe' | Select-Object -First 1
    Invoke-Setup $unins.FullName @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') | Out-Null
    Wait-Uninstalled $installDir

    Step '10. All-users install (administrator) uses the machine PATH, and is fully undone'
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $machineBefore = Get-RawPath 'Machine'
        $allDir = Join-Path $env:ProgramFiles 'SecretShield Installer Test'
        $allArgs = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/ALLUSERS', "/DIR=`"$allDir`"", '/TASKS="addtopath"')
        Assert ((Invoke-Setup $Installer $allArgs) -eq 0) 'all-users install succeeds'
        Assert ((Count-Occurrences (Get-Entries (Get-RawPath 'Machine')) $allDir) -eq 1) 'machine PATH contains the folder once'
        Assert (Same-Path (Get-RawPath 'User') $userPathBefore) 'user PATH untouched by an all-users install'
        $unins = Get-ChildItem $allDir -Filter 'unins*.exe' | Select-Object -First 1
        Assert ((Invoke-Setup $unins.FullName @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART')) -eq 0) 'all-users uninstall succeeds'
        Wait-Uninstalled $allDir
        Assert (Same-Path (Get-RawPath 'Machine') $machineBefore) 'machine PATH back to its original entries'
    } else {
        Write-Host '  skipped: not running as administrator'
    }

    Step '11. Portable archive: runs without installing, changes nothing'
    $portableRoot = Join-Path $root ('portable ' + [char]0x00FC)
    Expand-Archive -Path $PortableZip -DestinationPath $portableRoot
    $portableExe = Join-Path $portableRoot 'secretshield\secretshield.exe'
    $portableSs = Join-Path $portableRoot 'secretshield\ss.exe'
    Assert ((Test-Path $portableExe) -and (Test-Path $portableSs)) 'archive contains secretshield.exe and ss.exe'
    $r = Invoke-Clean $portableSs @('--version') $project
    Assert ($r.ExitCode -eq 0 -and $r.Out.Trim() -eq "secretshield $ExpectedVersion") 'portable ss.exe --version works in a clean environment'
    $r = Invoke-Clean $portableExe @('scan', '.') $project
    Assert ($r.ExitCode -eq 1) 'portable scan finds the planted secret (exit 1)'
    Assert (Same-Path (Get-RawPath 'User') $userPathBefore) 'running the portable build did not touch PATH'

    Write-Host "`nALL INSTALLER LIFECYCLE CHECKS PASSED ($script:Checks assertions)"
}
finally {
    # Best-effort cleanup so a failed run does not leave anything behind.
    foreach ($candidate in @($installDir)) {
        $u = Get-ChildItem $candidate -Filter 'unins*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($u) { Start-Process -FilePath $u.FullName -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait }
    }
    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
}
