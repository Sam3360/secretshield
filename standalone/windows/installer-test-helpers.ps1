<#
.SYNOPSIS
  Helpers for test-installer.ps1 that model "a freshly opened terminal".

.DESCRIPTION
  Dot-sourced by test-installer.ps1. Kept in a separate file so they can be unit
  tested with plain PowerShell on any OS (tests/test_installer_test_helpers.py);
  they use no installer-specific state.

  Why this exists: Windows searches the machine PATH before the user PATH, and
  the installer (rightly) appends to the user PATH. A SecretShield that is
  already on the machine PATH, typically pip's Scripts folder, which a CI job or a
  developer machine has, therefore wins when you type `ss`. That is correct
  behaviour, and the installer's final page warns about it, but it means a test
  that simulates a new terminal must not be fooled by an unrelated copy. These
  helpers leave other SecretShield folders out of the simulated PATH, say so
  loudly, and then check that the INSTALLED copy is what the name resolves to.
#>

function ConvertTo-CanonicalPath {
    # A full, normalized spelling of a path, so two spellings of the same place compare
    # equal (quotes, "..", trailing separators). Returns the trimmed input if it can't be resolved.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $clean = $Path.Trim().Trim('"')
    try {
        return [System.IO.Path]::GetFullPath($clean).TrimEnd([char]'\', [char]'/')
    }
    catch {
        return $clean
    }
}

function Get-ForeignCommandDirs {
    # The PATH entries (other than OwnDir) that contain one of the command names, using
    # the same extensions Windows uses to find programs (PATHEXT).
    param(
        [string[]]$Entries,
        [string]$OwnDir,
        [string[]]$Names = @('ss', 'secretshield')
    )
    $own = ConvertTo-CanonicalPath $OwnDir
    $pathext = $env:PATHEXT
    if ([string]::IsNullOrEmpty($pathext)) { $pathext = '.COM;.EXE;.BAT;.CMD' }
    # Windows file names are case-insensitive, but other file systems are not (WSL, Linux CI),
    # so look for each extension in both its listed and its lower-case spelling.
    $extensions = @($pathext.Split(';') | Where-Object { $_ } | ForEach-Object { $_; $_.ToLowerInvariant() } | Select-Object -Unique)

    foreach ($entry in $Entries) {
        $dir = $entry.Trim().Trim('"')
        if ($dir -eq '') { continue }
        $expanded = [Environment]::ExpandEnvironmentVariables($dir)
        if ((ConvertTo-CanonicalPath $expanded) -ieq $own) { continue }
        $found = $false
        foreach ($name in $Names) {
            foreach ($extension in $extensions) {
                try {
                    if (Test-Path -LiteralPath (Join-Path $expanded "$name$extension") -PathType Leaf) { $found = $true }
                }
                catch {
                    # an unusable PATH entry cannot contain a command
                }
            }
        }
        if ($found) { $entry }
    }
}

function Get-NewTerminalPath {
    # The PATH a new terminal would get (machine entries, then user entries, in order),
    # minus any folder that holds a SecretShield other than the one in OwnDir.
    param([string]$MachinePath, [string]$UserPath, [string]$OwnDir)
    $separator = [System.IO.Path]::PathSeparator
    $entries = @(("$MachinePath$separator$UserPath").Split($separator) | Where-Object { $_.Trim() -ne '' })
    $foreign = @(Get-ForeignCommandDirs -Entries $entries -OwnDir $OwnDir)
    $kept = @($entries | Where-Object { $foreign -notcontains $_ })
    return [pscustomobject]@{
        Path    = ($kept -join $separator)
        Foreign = $foreign
        Entries = $entries
    }
}

function Set-NewTerminalPath {
    # Apply the simulated new-terminal PATH to this process, reporting what was left out.
    param([string]$OwnDir, [string]$MachinePath, [string]$UserPath)
    if (-not $PSBoundParameters.ContainsKey('MachinePath')) { $MachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine') }
    if (-not $PSBoundParameters.ContainsKey('UserPath')) { $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User') }
    $result = Get-NewTerminalPath -MachinePath $MachinePath -UserPath $UserPath -OwnDir $OwnDir
    foreach ($dir in $result.Foreign) {
        Write-Host "  note: ignoring another SecretShield found in the PATH folder '$dir' (for example pip's Scripts folder). It would run instead of the installed copy, so this test leaves it out to check what the INSTALLER put on the PATH."
        Write-Host "::warning::Another ss/secretshield on the PATH ($dir) was left out of the new-terminal simulation"
    }
    $env:PATH = $result.Path
    return $result
}

function Test-CommandResolvesTo {
    # Does typing `Name` run the program at `Expected`? Compares canonical paths, and on a
    # mismatch the Detail says exactly what the PATH resolved to instead.
    param([string]$Name, [string]$Expected)
    $found = @(Get-Command $Name -CommandType Application -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    $wanted = ConvertTo-CanonicalPath $Expected
    $ok = ($found.Count -gt 0) -and ((ConvertTo-CanonicalPath $found[0]) -ieq $wanted)
    $detail = ''
    if (-not $ok) {
        if ($found.Count -eq 0) {
            $detail = " (expected $Expected, but '$Name' was not found on the PATH)"
        }
        else {
            $detail = " (expected $Expected; the PATH resolves '$Name' to, in order: " + ($found -join '; ') + ')'
        }
    }
    return [pscustomobject]@{ Ok = $ok; Found = $found; Detail = $detail }
}
