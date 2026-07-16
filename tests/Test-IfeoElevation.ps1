#Requires -Version 5.1
<#
.SYNOPSIS
    Regression test for the IFEO + gmproxy SYSTEM-elevation layer (normal programs).
.DESCRIPTION
    Source-level assertions (no side effects) that validate:
      - Install-IfeoElevation / Uninstall-IfeoElevation exist in God-Mode-Windows.ps1
      - The curated IFEO app list includes expected normal programs (chrome, notepad,
        regedit, mstsc, office, dev tools, archivers, etc.)
      - The list EXCLUDES shells/terminals (cmd, powershell, pwsh, wt, conhost,
        OpenConsole, WindowsTerminal, wsl, wslhost) and explorer.exe / taskmgr.exe,
        which are managed by other paths -- IFEO-redirecting God Mode's own
        powershell.exe/cmd.exe plumbing would break the monitor loop.
      - The Debugger value targets the installed gmproxy.exe path.
      - Install hardens each key (Harden-RegistryKey); Uninstall restores (Restore-RegistryKey).
      - Enable-GodMode calls Install-IfeoElevation; Disable-GodMode calls Uninstall-IfeoElevation.
      - gmproxy.c still has the IFEO recursion bypass (CreateHardLinkW) the layer depends on.
      - Export-GodModeLogs IFEO diagnostic shows the newly-hooked apps.

    The app-list includes/excludes are scoped to the $IfeoElevationApps array INSIDE
    Install-IfeoElevation (extracted by regex), so the function's comment prose -- which
    names the excluded shells in prose -- does not cause false positives.

    Run: pwsh -File tests/Test-IfeoElevation.ps1
    Exits 0 on success, 1 with a FAIL SUMMARY (N) block on any failure.
#>

$Global:FailedAssertions = @()
$Global:PassedCount = 0

function Add-Assertion {
    param([string]$Name, [bool]$Pass, [string]$Details = "")
    if ($Pass) {
        $Global:PassedCount++
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    } else {
        $Global:FailedAssertions += $Name
        Write-Host "  [FAIL] $Name : $Details" -ForegroundColor Red
    }
}

function Write-Summary {
    Write-Host "`n=====================================================" -ForegroundColor White
    Write-Host "  IFEO ELEVATION TEST SUMMARY" -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor White
    Write-Host "  Passed: $Global:PassedCount" -ForegroundColor Green
    Write-Host "  Failed: $($Global:FailedAssertions.Count)" -ForegroundColor $(if ($Global:FailedAssertions.Count -gt 0) { "Red" } else { "Green" })
    if ($Global:FailedAssertions.Count -gt 0) {
        Write-Host "`n  FAIL SUMMARY ($($Global:FailedAssertions.Count))" -ForegroundColor Red
        foreach ($f in $Global:FailedAssertions) { Write-Host "    - $f" -ForegroundColor Red }
        exit 1
    }
    Write-Host "`n  ALL TESTS PASSED!" -ForegroundColor Green
    exit 0
}

$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = (Get-Location).Path }
$ProjectRoot = Split-Path -Parent $ScriptRoot
if (-not $ProjectRoot) { $ProjectRoot = $ScriptRoot }

$GodMode = Join-Path $ProjectRoot "God-Mode-Windows.ps1"
$GmProxy = Join-Path $ProjectRoot "driver/gmproxy.c"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  God-Mode IFEO + gmproxy Elevation Regression" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

if (-not (Test-Path $GodMode)) {
    Add-Assertion "God-Mode-Windows.ps1 exists" $false "file not found: $GodMode"
    Write-Summary
}

$gm = Get-Content -Raw $GodMode

# --- 1. Function presence ---
Add-Assertion "God-Mode-Windows.ps1: Install-IfeoElevation defined" ($gm -match 'function\s+Install-IfeoElevation\s*\{') "Install-IfeoElevation missing"
Add-Assertion "God-Mode-Windows.ps1: Uninstall-IfeoElevation defined" ($gm -match 'function\s+Uninstall-IfeoElevation\s*\{') "Uninstall-IfeoElevation missing"

# --- 2. Extract Install-IfeoElevation body (it is immediately followed by Uninstall-IfeoElevation) ---
$installMatch = [regex]::Match($gm, '(?s)function\s+Install-IfeoElevation\s*\{(.*?)function\s+Uninstall-IfeoElevation\s*\{')
$installBody = if ($installMatch.Success) { $installMatch.Groups[1].Value } else { "" }
Add-Assertion "Install-IfeoElevation body extractable (adjacent to Uninstall)" ($installMatch.Success) "could not isolate Install-IfeoElevation body"

# Extract the $IfeoElevationApps array text from the Install body (the app list).
$arrMatch = [regex]::Match($installBody, '(?s)\$IfeoElevationApps\s*=\s*@\((.*?)\)')
$arrText = if ($arrMatch.Success) { $arrMatch.Groups[1].Value } else { "" }
Add-Assertion "Install-IfeoElevation: IfeoElevationApps array present" ($arrMatch.Success) "app-list array not found in Install-IfeoElevation"

# --- 3. App list INCLUDES expected normal programs ---
if ($arrMatch.Success) {
    $expectedApps = @(
        "chrome.exe","firefox.exe","msedge.exe","notepad.exe","regedit.exe","mstsc.exe",
        "winword.exe","excel.exe","outlook.exe","code.exe","devenv.exe","7z.exe","winrar.exe",
        "vlc.exe","spotify.exe","foxitreader.exe","putty.exe","filezilla.exe","msconfig.exe",
        "steam.exe","discord.exe","teams.exe"
    )
    foreach ($app in $expectedApps) {
        $pat = '"' + [regex]::Escape($app) + '"'
        Add-Assertion "Install-IfeoElevation list includes $app" ($arrText -match $pat) "$app not in IFEO elevation list"
    }
}

# --- 4. App list EXCLUDES shells/terminals + explorer + taskmgr (scoped to the array) ---
if ($arrMatch.Success) {
    $excludedApps = @(
        "cmd.exe","powershell.exe","pwsh.exe","wt.exe","conhost.exe","OpenConsole.exe",
        "WindowsTerminal.exe","wsl.exe","wslhost.exe","explorer.exe","taskmgr.exe"
    )
    foreach ($app in $excludedApps) {
        $pat = '"' + [regex]::Escape($app) + '"'
        Add-Assertion "Install-IfeoElevation list EXCLUDES $app (shell/host managed elsewhere)" ($arrText -notmatch $pat) "$app must NOT be IFEO-hooked (would break God Mode plumbing or is managed by another path)"
    }
}

# --- 5. Debugger targets the installed gmproxy.exe ---
Add-Assertion "Install-IfeoElevation: resolves gmproxy.exe from GodModeInstallDir" ($installBody -match 'Join-Path\s+\$GodModeInstallDir\s+"gmproxy\.exe"') "gmproxy path not resolved from install dir"
Add-Assertion "Install-IfeoElevation: sets Debugger value to gmproxy path" ($installBody -match 'Set-ItemProperty.*Debugger.*\$GmProxyExe') "Debugger not set to gmproxy path"
Add-Assertion "Install-IfeoElevation: bails when gmproxy.exe missing" ($installBody -match 'gmproxy\.exe not found') "missing-gmproxy guard absent"

# --- 6. Hardening / restore wiring ---
Add-Assertion "Install-IfeoElevation: hardens each IFEO key (Harden-RegistryKey)" ($installBody -match 'Harden-RegistryKey') "Harden-RegistryKey not called in install"
$uninstallMatch = [regex]::Match($gm, '(?s)function\s+Uninstall-IfeoElevation\s*\{(.*?)\nfunction\s+Elevate-Process\s*\{')
$uninstallBody = if ($uninstallMatch.Success) { $uninstallMatch.Groups[1].Value } else { "" }
Add-Assertion "Uninstall-IfeoElevation body extractable" ($uninstallMatch.Success) "could not isolate Uninstall-IfeoElevation body"
if ($uninstallMatch.Success) {
    Add-Assertion "Uninstall-IfeoElevation: restores ACL (Restore-RegistryKey) before delete" ($uninstallBody -match 'Restore-RegistryKey') "Restore-RegistryKey not called in uninstall (hardened keys could not be removed)"
    Add-Assertion "Uninstall-IfeoElevation: removes Debugger value" ($uninstallBody -match 'Remove-ItemProperty.*Debugger') "Debugger removal missing"
    Add-Assertion "Uninstall-IfeoElevation: removes IFEO key" ($uninstallBody -match 'Remove-Item.*appKey') "key removal missing"
}

# --- 7. Enable/Disable-GodMode wiring (standalone call lines, not the definitions) ---
Add-Assertion "Enable-GodMode calls Install-IfeoElevation" ($gm -match '(?m)^\s+Install-IfeoElevation\s*\r?\n') "no standalone Install-IfeoElevation call in Enable-GodMode"
Add-Assertion "Disable-GodMode calls Uninstall-IfeoElevation" ($gm -match '(?m)^\s+Uninstall-IfeoElevation\s*\r?\n') "no standalone Uninstall-IfeoElevation call in Disable-GodMode"

# --- 8. gmproxy.c IFEO recursion bypass (the whole layer depends on it) ---
if (Test-Path $GmProxy) {
    $proxySrc = Get-Content -Raw $GmProxy
    Add-Assertion "gmproxy.c: IFEO recursion bypass (CreateHardLinkW) present" ($proxySrc -match 'CreateHardLinkW') "hardlink bypass missing -- IFEO would launch gmproxy recursively"
    Add-Assertion "gmproxy.c: launches target with stolen SYSTEM token (CreateProcessWithTokenW)" ($proxySrc -match 'CreateProcessWithTokenW') "token launch missing"
} else {
    Add-Assertion "gmproxy.c exists" $false "file not found: $GmProxy"
}

# --- 9. Export-GodModeLogs diagnostic shows newly-hooked apps ---
Add-Assertion "Export-GodModeLogs: IFEO diagnostic includes regedit.exe + mstsc.exe" ($gm -match '"regedit\.exe","mstsc\.exe"') "diagnostic app list not expanded to show hooked apps"

Write-Summary
