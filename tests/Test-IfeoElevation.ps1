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
      - Auto-populate: Install-IfeoElevation also calls Get-IfeoElevationCandidates, which
        scans running processes, AppPaths registry, Program Files, and %LOCALAPPDATA%\Programs,
        applies a triple safety net (canonical name denylist union of all existing critical
        lists, Windows/System32/SysWOW64 path-exclusion, dedup by base name), and merges the
        survivors with the curated seed so any installed normal program is caught at launch
        while critical/shell/OS processes stay intact.
      - Uninstall-IfeoElevation now ENUMERATES IFEO keys by Debugger-contains-gmproxy
        (robust cleanup of curated + auto-populated + legacy + uninstalled apps) instead of
        a fixed app list.

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
    # Robust cleanup: uninstall must ENUMERATE IFEO keys by Debugger-contains-gmproxy, not use a fixed app list.
    Add-Assertion "Uninstall-IfeoElevation: enumerates IFEO keys (Get-ChildItem IfeoBase)" ($uninstallBody -match 'Get-ChildItem.*IfeoBase') "uninstall does not enumerate IFEO keys (not robust to auto-populated/legacy apps)"
    Add-Assertion "Uninstall-IfeoElevation: filters by Debugger-contains-gmproxy" ($uninstallBody -match 'Debugger.*-notlike.*gmproxy|gmproxy.*-notlike') "uninstall does not select keys by gmproxy Debugger (could remove unrelated IFEO keys)"
    Add-Assertion "Uninstall-IfeoElevation: NOT fixed-list based (no hardcoded app array)" ($uninstallBody -notmatch '\$IfeoElevationApps\s*=\s*@\(') "uninstall still uses a fixed app array (cannot clean auto-populated/legacy keys)"
}

# --- 6b. Auto-populate: Get-IfeoElevationCandidates helper + triple safety net ---
Add-Assertion "Get-IfeoElevationCandidates function defined" ($gm -match 'function\s+Get-IfeoElevationCandidates\s*\{') "Get-IfeoElevationCandidates helper missing"
Add-Assertion "Install-IfeoElevation calls Get-IfeoElevationCandidates" ($installBody -match 'Get-IfeoElevationCandidates') "install does not call the auto-populate helper"
Add-Assertion "Install-IfeoElevation merges seed + auto candidates (Select-Object -Unique)" ($installBody.Contains('filteredSeed') -and $installBody.Contains('Select-Object -Unique')) "seed + auto candidates not merged/deduped"
$candMatch = [regex]::Match($gm, '(?s)function\s+Get-IfeoElevationCandidates\s*\{(.*?)\nfunction\s+Install-IfeoElevation\s*\{')
$candBody = if ($candMatch.Success) { $candMatch.Groups[1].Value } else { "" }
Add-Assertion "Get-IfeoElevationCandidates body extractable" ($candMatch.Success) "could not isolate Get-IfeoElevationCandidates body"
if ($candMatch.Success) {
    # The 4 scan sources.
    Add-Assertion "Auto-populate: scans running processes (Win32_Process SessionId>0)" ($candBody -match 'Get-CimInstance\s+Win32_Process' -and $candBody -match 'SessionId\s*-gt\s*0') "running-process source missing"
    Add-Assertion "Auto-populate: scans AppPaths registry" ($candBody -match 'App Paths') "AppPaths registry source missing"
    Add-Assertion "Auto-populate: scans Program Files" ($candBody -match 'Program Files') "Program Files source missing"
    Add-Assertion "Auto-populate: scans %LOCALAPPDATA%\Programs" ($candBody -match 'LOCALAPPDATA.*Programs') "per-user Programs source missing"
    # Triple safety net #1: canonical name denylist covering core OS + shells + God-Mode CLI deps.
    Add-Assertion "Auto-populate: denylist variable present (GmCriticalIfeoExclude)" ($candBody -match '\$GmCriticalIfeoExclude') "canonical name denylist missing"
    Add-Assertion "Auto-populate: denylist contains core OS (svchost)" ($candBody -match '"svchost"') "denylist missing core OS name svchost"
    Add-Assertion "Auto-populate: denylist contains core OS (csrss)" ($candBody -match '"csrss"') "denylist missing core OS name csrss"
    Add-Assertion "Auto-populate: denylist contains shell (powershell)" ($candBody -match '"powershell"') "denylist missing shell name powershell"
    Add-Assertion "Auto-populate: denylist contains shell (cmd)" ($candBody -match '"cmd"') "denylist missing shell name cmd"
    Add-Assertion "Auto-populate: denylist contains terminal (conhost)" ($candBody -match '"conhost"') "denylist missing terminal name conhost"
    Add-Assertion "Auto-populate: denylist contains God-Mode CLI dep (schtasks)" ($candBody -match '"schtasks"') "denylist missing God-Mode CLI dependency schtasks"
    Add-Assertion "Auto-populate: denylist contains God-Mode CLI dep (netsh)" ($candBody -match '"netsh"') "denylist missing God-Mode CLI dependency netsh"
    Add-Assertion "Auto-populate: denylist contains explorer + taskmgr (managed elsewhere)" ($candBody -match '"explorer"' -and $candBody -match '"taskmgr"') "denylist missing explorer/taskmgr"
    Add-Assertion "Auto-populate: denylist contains gmproxy (no self-hook)" ($candBody -match '"gmproxy"') "denylist missing gmproxy"
    Add-Assertion "Auto-populate: denylist stored as bare name and name.exe" ($candBody -match 'excludeSet\[\$name\.ToLower' -and $candBody -match '\$name\.exe') "denylist not stored as both bare name and name.exe"
    # Triple safety net #2: Windows/System32/SysWOW64 path hard-exclusion.
    Add-Assertion "Auto-populate: excludes System32 path" ($candBody -like '*windows*system32*') "System32 path-exclusion missing"
    Add-Assertion "Auto-populate: excludes SysWOW64 path" ($candBody -like '*windows*syswow64*') "SysWOW64 path-exclusion missing"
    # Triple safety net #3: sanity filters (dedup by base name, .exe only).
    Add-Assertion "Auto-populate: dedups by lowercased base name" ($candBody -match 'seen\.ContainsKey\(\$baseKey\)') "dedup-by-base-name missing"
    Add-Assertion "Auto-populate: only accepts .exe paths (notmatch exe guard)" ($candBody -match '-notmatch.*exe') ".exe-only sanity filter missing"
}

# --- 7. Enable/Disable-GodMode wiring (standalone call lines, not the definitions) ---
Add-Assertion "Enable-GodMode calls Install-IfeoElevation" ($gm -match '(?m)^\s+Install-IfeoElevation\s*\r?\n') "no standalone Install-IfeoElevation call in Enable-GodMode"
Add-Assertion "Disable-GodMode calls Uninstall-IfeoElevation" ($gm -match '(?m)^\s+Uninstall-IfeoElevation\s*\r?\n') "no standalone Uninstall-IfeoElevation call in Disable-GodMode"

# --- 8. gmproxy.c IFEO recursion bypass (the whole layer depends on it) ---
if (Test-Path $GmProxy) {
    $proxySrc = Get-Content -Raw $GmProxy
    Add-Assertion "gmproxy.c: IFEO recursion bypass (CreateHardLinkW) present" ($proxySrc -match 'CreateHardLinkW') "hardlink bypass missing -- IFEO would launch gmproxy recursively"
    Add-Assertion "gmproxy.c: launches target with stolen SYSTEM token (CreateProcessWithTokenW)" ($proxySrc -match 'CreateProcessWithTokenW') "token launch missing"
    # Session-correctness fix (born-as-SYSTEM must land in the active interactive session,
    # else the child is ownerless with a blank User column / unusable / instant-killed).
    Add-Assertion "gmproxy.c: session-aware token source (GetActiveConsoleSessionId + ProcessIdToSessionId)" ($proxySrc -match 'GetActiveConsoleSessionId' -and $proxySrc -match 'ProcessIdToSessionId') "session-aware token selection missing -- child could be born ownerless in Session 0"
    Add-Assertion "gmproxy.c: graceful fallback launch as current user (CreateProcessW hardlink)" ($proxySrc -match 'CreateProcessW\s*\(\s*hardlinkPath') "graceful fallback missing -- broken ownerless launch when no session-correct SYSTEM token"
} else {
    Add-Assertion "gmproxy.c exists" $false "file not found: $GmProxy"
}

# --- 9. Export-GodModeLogs diagnostic shows newly-hooked apps ---
Add-Assertion "Export-GodModeLogs: IFEO diagnostic includes regedit.exe + mstsc.exe" ($gm -match '"regedit\.exe","mstsc\.exe"') "diagnostic app list not expanded to show hooked apps"

# --- 10. Instant IFEO new-app watcher (event-driven auto-add, no polling, no retrigger) ---
# Closes the "newly installed programs are never re-scanned into the IFEO set" gap.
# System.IO.FileSystemWatcher on the install dirs fires the INSTANT a new .exe
# lands on disk -> Add-IfeoElevationForApp hooks it idempotently (only genuinely-
# new apps, never retrigger). No Start-Sleep polling; if nothing new is installed,
# no events fire and nothing happens. Uninstall-IfeoElevation already enumerates
# by Debugger-contains-gmproxy, so watcher-added keys are cleaned automatically.
Add-Assertion "Add-IfeoElevationForApp function defined" ($gm -match 'function\s+Add-IfeoElevationForApp\s*\{') "Add-IfeoElevationForApp missing -- instant single-app IFEO add helper absent"
$addMatch = [regex]::Match($gm, '(?s)function\s+Add-IfeoElevationForApp\s*\{(.*?)\nfunction\s+Remove-IfeoElevationForApp\s*\{')
$addBody = if ($addMatch.Success) { $addMatch.Groups[1].Value } else { "" }
Add-Assertion "Add-IfeoElevationForApp body extractable (adjacent to Remove-IfeoElevationForApp)" ($addMatch.Success) "could not isolate Add-IfeoElevationForApp body"
if ($addMatch.Success) {
    Add-Assertion "Add-IfeoElevationForApp: idempotent gate (already-hooked -> no retrigger)" ($addBody -match '\$existing\s*-and\s*\$existing\s*-like\s*"\*gmproxy\*"' -and $addBody -match 'return\s+\$false') "Add-IfeoElevationForApp does not skip already-hooked apps -- would retrigger for every event"
    Add-Assertion "Add-IfeoElevationForApp: safety-net denylist present" ($addBody -match '\$deny' -and ($addBody -match '"svchost"' -or $addBody -match '"powershell"')) "Add-IfeoElevationForApp missing the canonical name denylist -- could hook a critical/shell process"
    Add-Assertion "Add-IfeoElevationForApp: System32 path-exclusion" ($addBody -like '*windows*system32*') "Add-IfeoElevationForApp missing the System32 path-exclusion"
    Add-Assertion "Add-IfeoElevationForApp: sets Debugger to gmproxy" ($addBody -match 'Set-ItemProperty.*Debugger.*\$GmProxyExe') "Add-IfeoElevationForApp does not set Debugger to gmproxy"
    Add-Assertion "Add-IfeoElevationForApp: hardens the new key (Harden-RegistryKey)" ($addBody -match 'Harden-RegistryKey') "Add-IfeoElevationForApp does not harden the new IFEO key"
    Add-Assertion "Add-IfeoElevationForApp: bails when gmproxy.exe missing" ($addBody -match 'Test-Path\s+\$GmProxyExe') "Add-IfeoElevationForApp missing the gmproxy-absent guard"
}
Add-Assertion "Start-IfeoNewAppWatcher function defined" ($gm -match 'function\s+Start-IfeoNewAppWatcher\s*\{') "Start-IfeoNewAppWatcher missing"
Add-Assertion "Stop-IfeoNewAppWatcher function defined" ($gm -match 'function\s+Stop-IfeoNewAppWatcher\s*\{') "Stop-IfeoNewAppWatcher missing"
$startMatch = [regex]::Match($gm, '(?s)function\s+Start-IfeoNewAppWatcher\s*\{(.*?)\nfunction\s+Stop-IfeoNewAppWatcher\s*\{')
$startBody = if ($startMatch.Success) { $startMatch.Groups[1].Value } else { "" }
Add-Assertion "Start-IfeoNewAppWatcher body extractable" ($startMatch.Success) "could not isolate Start-IfeoNewAppWatcher body"
if ($startMatch.Success) {
    Add-Assertion "Instant watcher: uses System.IO.FileSystemWatcher" ($startBody -match 'System\.IO\.FileSystemWatcher') "watcher is not FileSystemWatcher-based -- not event-driven/instant"
    Add-Assertion "Instant watcher: watches Program Files" ($startBody -match 'Program Files') "watcher does not watch Program Files"
    Add-Assertion "Instant watcher: enumerates per-user profiles (C:\\Users + AppData\\Local\\Programs)" ($startBody -match 'C:\\Users' -and $startBody -match 'AppData\\Local\\Programs') "watcher does not enumerate per-user Programs dirs"
    Add-Assertion "Instant watcher: event-driven Created handler attached (+=)" ($startBody -match '\.Created\s*\+=') "watcher does not attach a Created event handler -- not event-driven"
    Add-Assertion "Instant watcher: event-driven Renamed handler attached (catches .tmp->.exe installs)" ($startBody -match '\.Renamed\s*\+=') "watcher does not attach a Renamed event handler -- installs that rename .tmp->.exe would be missed"
    Add-Assertion "Instant watcher: EnableRaisingEvents set" ($startBody -match 'EnableRaisingEvents\s*=\s*\$true') "watcher does not enable events"
    Add-Assertion "Instant watcher: buffer-overflow hardening (InternalBufferSize)" ($startBody -match 'InternalBufferSize') "watcher does not raise InternalBufferSize -- large installs could overflow the event buffer"
    Add-Assertion "Instant watcher: Error event -> catch-up rescan sentinel" ($startBody -match '\.Error\s*\+=' -and $startBody -match '__GMIFEO_RESCAN__') "watcher does not handle buffer-overflow Error -> catch-up rescan sentinel missing"
    Add-Assertion "Instant watcher: synchronized event queue present (IfeoNewAppQueue)" ($gm -match 'IfeoNewAppQueue') "watcher missing the synchronized event queue -- events would be lost"
    Add-Assertion "Instant watcher: per-base-name debounce table (IfeoNewAppDebounce)" ($gm -match 'IfeoNewAppDebounce') "watcher missing the debounce table -- one install burst could spam Add"
    Add-Assertion "Instant watcher: idempotent start guard (no double-register)" ($startBody -match 'if\s+\(\$script:IfeoNewAppWatcherActive\)') "watcher missing the active-guard -- could register duplicate watchers on repeat start"
    Add-Assertion "Instant watcher: NO polling (no Start-Sleep call in the watcher body)" ($startBody -notmatch 'Start-Sleep\s*-') "watcher uses Start-Sleep polling -- not instant/event-driven (a Start-Sleep -<param> call was found in the watcher body)"
}
# Wiring: Start-Monitoring starts the watcher; Disable-GodMode stops it.
Add-Assertion "Start-Monitoring calls Start-IfeoNewAppWatcher" ($gm -match '\$null\s*=\s*Start-IfeoNewAppWatcher') "Start-Monitoring does not start the instant IFEO new-app watcher"
Add-Assertion "Disable-GodMode calls Stop-IfeoNewAppWatcher (standalone call line)" ($gm -match '(?m)^\s+Stop-IfeoNewAppWatcher\s*$') "Disable-GodMode does not stop the instant IFEO new-app watcher"
# Uninstaller stays current: Uninstall-IfeoElevation already enumerates by
# Debugger-contains-gmproxy, so IFEO keys added by the watcher are removed
# automatically on Disable-GodMode (no uninstaller change needed).
Add-Assertion "Uninstaller covers watcher-added IFEO keys (enumerates by gmproxy Debugger)" ($uninstallBody -match 'Debugger.*gmproxy') "uninstaller would not clean watcher-added IFEO keys -- Disable-GodMode could leave dynamic keys behind"

# --- 11. Deferred IFEO stale-prune for uninstalled programs (event-driven, no retrigger) ---
# Closes the "uninstalled program leaves a dormant gmproxy IFEO key" gap. The
# FileSystemWatcher Deleted event enqueues a DEFERRED prune entry with a ~3s
# grace period (so an updater's new .exe lands first); after the grace period
# the Start-Monitoring drain re-scans the watched dirs and removes the gmproxy
# IFEO key ONLY if the .exe is gone everywhere. Updater swaps (delete then
# create) are NOT pruned -- the new .exe's Created event re-hooks it. Never
# touches a non-gmproxy IFEO key; never retriggers (idempotent remove gate).
Add-Assertion "Remove-IfeoElevationForApp function defined" ($gm -match 'function\s+Remove-IfeoElevationForApp\s*\{') "Remove-IfeoElevationForApp missing -- deferred single-app IFEO unhook helper absent"
$removeMatch = [regex]::Match($gm, '(?s)function\s+Remove-IfeoElevationForApp\s*\{(.*?)\nfunction\s+Test-BaseNameGoneEverywhere\s*\{')
$removeBody = if ($removeMatch.Success) { $removeMatch.Groups[1].Value } else { "" }
Add-Assertion "Remove-IfeoElevationForApp body extractable (adjacent to Test-BaseNameGoneEverywhere)" ($removeMatch.Success) "could not isolate Remove-IfeoElevationForApp body"
if ($removeMatch.Success) {
    Add-Assertion "Remove-IfeoElevationForApp: gmproxy-guarded (only touches gmproxy Debugger keys)" ($removeBody -match 'Debugger.*-notlike.*gmproxy|gmproxy.*-notlike') "Remove-IfeoElevationForApp does not guard on gmproxy Debugger -- could remove an unrelated IFEO key"
    Add-Assertion "Remove-IfeoElevationForApp: restores ACL (Restore-RegistryKey) before delete" ($removeBody -match 'Restore-RegistryKey') "Remove-IfeoElevationForApp does not restore the hardened ACL -- key could not be deleted"
    Add-Assertion "Remove-IfeoElevationForApp: removes Debugger value" ($removeBody -match 'Remove-ItemProperty.*Debugger') "Remove-IfeoElevationForApp does not remove the Debugger value"
    Add-Assertion "Remove-IfeoElevationForApp: removes IFEO key" ($removeBody -match 'Remove-Item.*appKey') "Remove-IfeoElevationForApp does not remove the IFEO key"
    Add-Assertion "Remove-IfeoElevationForApp: no retrigger when key absent" ($removeBody -match 'Test-Path.*appKey' -and $removeBody -match 'return\s+\$false') "Remove-IfeoElevationForApp does not bail when the key is absent -- would retrigger"
}
Add-Assertion "Test-BaseNameGoneEverywhere function defined" ($gm -match 'function\s+Test-BaseNameGoneEverywhere\s*\{') "Test-BaseNameGoneEverywhere missing -- base-name re-scan helper absent"
$goneMatch = [regex]::Match($gm, '(?s)function\s+Test-BaseNameGoneEverywhere\s*\{(.*?)\nfunction\s+Test-SystemProcessExists\s*\{')
$goneBody = if ($goneMatch.Success) { $goneMatch.Groups[1].Value } else { "" }
Add-Assertion "Test-BaseNameGoneEverywhere body extractable" ($goneMatch.Success) "could not isolate Test-BaseNameGoneEverywhere body"
if ($goneMatch.Success) {
    Add-Assertion "Test-BaseNameGoneEverywhere: re-scans Program Files" ($goneBody -match 'Program Files') "re-scan does not check Program Files"
    Add-Assertion "Test-BaseNameGoneEverywhere: re-scans per-user Programs (C:\\Users + AppData\\Local\\Programs)" ($goneBody -match 'C:\\Users' -and $goneBody -match 'AppData\\Local\\Programs') "re-scan does not check per-user Programs dirs"
    Add-Assertion "Test-BaseNameGoneEverywhere: recursive base-name search (Get-ChildItem -Recurse)" ($goneBody -match 'Get-ChildItem.*-Recurse') "re-scan is not recursive -- would miss the .exe in a versioned subfolder"
}
Add-Assertion "Instant watcher: Deleted handler attached (catches uninstalls)" ($startBody -match '\.Deleted\s*\+=') "watcher does not attach a Deleted event handler -- uninstalled programs would leave stale IFEO keys"
Add-Assertion "Instant watcher: deferred prune queue present (IfeoPruneQueue)" ($gm -match 'IfeoPruneQueue') "deferred prune queue missing -- Deleted events would have nowhere to enqueue"
Add-Assertion "Instant watcher: grace-period scheduling (AddSeconds in Deleted handler)" ($startBody -match 'AddSeconds') "Deleted handler does not schedule a grace period -- updater swaps could be pruned mid-swap"
Add-Assertion "Instant watcher: Deleted handler enqueues prune entry (BaseName + DueTime)" ($startBody -match 'BaseName' -and $startBody -match 'DueTime') "Deleted handler does not enqueue a structured prune entry -- drain cannot tell what to prune or when"
Add-Assertion "Start-Monitoring: prune drain processes due entries (IfeoPruneQueue + DueTime)" ($gm -match 'IfeoPruneQueue.*Count' -and $gm -match 'DueTime') "Start-Monitoring does not drain the prune queue -- deferred stale-prune entries would never be processed"
Add-Assertion "Start-Monitoring: prune drain re-scans via Test-BaseNameGoneEverywhere" ($gm -match 'Test-BaseNameGoneEverywhere\s+-BaseName') "Start-Monitoring prune drain does not re-scan -- could remove a key mid-updater-swap"
Add-Assertion "Start-Monitoring: prune drain removes via Remove-IfeoElevationForApp" ($gm -match 'Remove-IfeoElevationForApp\s+-BaseName') "Start-Monitoring prune drain does not call the gmproxy-guarded remover -- cleanup not wired"
Add-Assertion "Start-Monitoring: prune drain gated on watcher active (no work when stopped)" ($gm -match 'IfeoNewAppWatcherActive.*IfeoPruneQueue' -or $gm -match 'IfeoPruneQueue.*IfeoNewAppWatcherActive') "prune drain is not gated on the watcher being active -- could run after Disable"
Add-Assertion "Stop-IfeoNewAppWatcher clears IfeoPruneQueue" ($gm -match 'IfeoPruneQueue\.Clear\(\)') "Stop-IfeoNewAppWatcher does not clear the prune queue -- entries could survive across enable/disable cycles"
Add-Assertion "Instant watcher: still NO polling after prune feature (no Start-Sleep call in watcher body)" ($startBody -notmatch 'Start-Sleep\s*-') "watcher body now contains a Start-Sleep call -- the prune feature must stay event-driven, not poll"
# Re-arm hardening: a slow updater (delete old .exe, then write the new one
# over >3s) could let a fixed 3s grace fire before the new .exe lands. Bumped
# to 5s, AND Created/Renamed cancel any pending prune for the same base name
# (the app reappeared -> updater swap, NOT an uninstall) so a gmproxy IFEO key
# is never removed mid-update. The drain's re-scan is the belt-and-suspenders.
Add-Assertion "Instant watcher: grace period bumped to 5s (AddSeconds(5) in Deleted handler)" ($startBody -match 'AddSeconds\(5\)') "grace period is not 5s -- a slow updater's new .exe could land after the prune fires and a launch in the gap would not be born as SYSTEM"
$createdHandlerMatch = [regex]::Match($startBody, '(?s)\$w\.Created\s*\+=\s*\{(.*?)\n\s+\}\s*\n\s+\$w\.Renamed')
$createdHandlerBody = if ($createdHandlerMatch.Success) { $createdHandlerMatch.Groups[1].Value } else { "" }
Add-Assertion "Instant watcher: Created handler re-arms (cancels pending prune on update)" ($createdHandlerBody -match 'IfeoPruneQueue' -and $createdHandlerBody -match 'RemoveAt') "Created handler does not cancel a pending stale-prune for the same base name -- a gmproxy IFEO key could be removed mid-updater-swap"
$renamedHandlerMatch = [regex]::Match($startBody, '(?s)\$w\.Renamed\s*\+=\s*\{(.*?)\n\s+\}\s*\n\s+\$w\.Error')
$renamedHandlerBody = if ($renamedHandlerMatch.Success) { $renamedHandlerMatch.Groups[1].Value } else { "" }
Add-Assertion "Instant watcher: Renamed handler re-arms (cancels pending prune on .tmp->.exe update)" ($renamedHandlerBody -match 'IfeoPruneQueue' -and $renamedHandlerBody -match 'RemoveAt') "Renamed handler does not cancel a pending stale-prune -- updaters that land via .tmp->.exe rename could lose the hook mid-swap"


# --- 12. Detector A: smart SYSTEM-incompatibility drop (AppX/packaged + registered browsers) ---
# Install-IfeoElevation now builds Get-GmSystemCompatExclusions (AppX via WindowsApps
# reparse aliases + Get-AppxPackage Executables; browsers via StartMenuInternet clients)
# and DROPS matching seed + auto candidates so structurally SYSTEM-incompatible apps
# (Win11 Notepad/calc Store stubs, Chrome/Firefox/Edge/Brave/... browsers) launch as the
# normal user instead of via gmproxy->SYSTEM (where they crash / render blank / exit with
# no window). No hardcoded app names; fail-open (empty sets -> no drop -> gmproxy.c
# Detector B runtime crash store is the safety net). The curated seed still LISTS these
# apps (additive) but they are filtered out before hooking.
Add-Assertion "Detector A: Get-GmSystemCompatExclusions function defined" ($gm.Contains('function Get-GmSystemCompatExclusions')) "Get-GmSystemCompatExclusions missing -- no install-time SYSTEM-incompatibility detection"
Add-Assertion "Detector A: scans WindowsApps reparse aliases (AppX/WinUI Store apps)" ($gm.Contains('WindowsApps') -and $gm.Contains('ReparsePoint')) "WindowsApps reparse-point AppX detection missing -- Win11 Notepad/calc Store stubs would be hooked"
Add-Assertion "Detector A: scans Get-AppxPackage application Executables (Store apps without aliases)" ($gm.Contains('Get-AppxPackage') -and $gm.Contains('Executable="')) "Get-AppxPackage Executable detection missing -- Store apps without a WindowsApps alias would slip through"
Add-Assertion "Detector A: scans registered StartMenuInternet clients (all installed browsers)" ($gm.Contains('StartMenuInternet')) "StartMenuInternet browser detection missing -- only a hardcoded name list would catch browsers"
Add-Assertion "Detector A: Get-AppxPackage is fail-open (ErrorAction SilentlyContinue)" ($gm.Contains('Get-AppxPackage -ErrorAction SilentlyContinue')) "Get-AppxPackage not guarded -- a missing Appx module (Server Core) would throw instead of fail-open"
Add-Assertion "Detector A: Get-IfeoElevationCandidates accepts a CompatExclusions param" ($candBody.Contains('$CompatExclusions')) "Get-IfeoElevationCandidates missing the CompatExclusions param -- candidates cannot be filtered"
Add-Assertion "Detector A: candidates filter drops AppX (CompatExclusions.AppX.ContainsKey)" ($candBody.Contains('CompatExclusions.AppX.ContainsKey')) "candidates AppX filter missing -- Store apps in the auto-populate would be hooked"
Add-Assertion "Detector A: candidates filter drops browsers (CompatExclusions.Browser.ContainsKey)" ($candBody.Contains('CompatExclusions.Browser.ContainsKey')) "candidates browser filter missing -- browsers in the auto-populate would be hooked"
Add-Assertion "Detector A: Install-IfeoElevation builds the compat sets once (Get-GmSystemCompatExclusions)" ($installBody.Contains('Get-GmSystemCompatExclusions')) "Install-IfeoElevation does not build CompatExclusions -- no install-time drop"
Add-Assertion "Detector A: Install-IfeoElevation filters the curated seed (filteredSeed)" ($installBody.Contains('filteredSeed')) "Install-IfeoElevation does not filter the seed -- AppX/browser names in the seed (notepad/chrome/firefox) would still be hooked unconditionally"
Add-Assertion "Detector A: Install-IfeoElevation counts seed drops (seedDroppedAppx/seedDroppedBrowser)" ($installBody.Contains('seedDroppedAppx') -and $installBody.Contains('seedDroppedBrowser')) "Install-IfeoElevation does not count seed drops -- the IFEO log cannot report what Detector A removed"
Add-Assertion "Detector A: passes CompatExclusions to Get-IfeoElevationCandidates" ($installBody.Contains('Get-IfeoElevationCandidates -GmProxyExe $GmProxyExe -CompatExclusions $CompatExclusions')) "Install-IfeoElevation does not pass CompatExclusions to the auto-populate -- auto candidates would not be filtered"
Add-Assertion "Detector A: curated seed still lists chrome.exe (additive, filtered not removed)" ($arrText.Contains('chrome.exe')) "curated seed lost chrome.exe -- additive edit regressed the app list"
Add-Assertion "Detector A: curated seed still lists notepad.exe (additive, filtered not removed)" ($arrText.Contains('notepad.exe')) "curated seed lost notepad.exe -- additive edit regressed the app list"
Add-Assertion "Detector A: curated seed still lists firefox.exe (additive, filtered not removed)" ($arrText.Contains('firefox.exe')) "curated seed lost firefox.exe -- additive edit regressed the app list"

Write-Summary
