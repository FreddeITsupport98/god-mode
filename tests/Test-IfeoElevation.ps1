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
        "cmd.exe","powershell.exe","pwsh.exe","powershell_ise.exe","wt.exe","conhost.exe","OpenConsole.exe",
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
    Add-Assertion "Instant watcher: event-driven Created handler bound (Register-ObjectEvent, PS7)" ($startBody -match 'Register-ObjectEvent' -and $startBody -match "'Created'") "watcher does not bind a Created event handler via Register-ObjectEvent -- not event-driven (PS7 removed the += adapter)"
    Add-Assertion "Instant watcher: event-driven Renamed handler bound (Register-ObjectEvent, PS7, catches .tmp->.exe installs)" ($startBody -match 'Register-ObjectEvent' -and $startBody -match "'Renamed'") "watcher does not bind a Renamed event handler via Register-ObjectEvent -- installs that rename .tmp->.exe would be missed (PS7 removed the += adapter)"
    Add-Assertion "Instant watcher: EnableRaisingEvents set" ($startBody -match 'EnableRaisingEvents\s*=\s*\$true') "watcher does not enable events"
    Add-Assertion "Instant watcher: buffer-overflow hardening (InternalBufferSize)" ($startBody -match 'InternalBufferSize') "watcher does not raise InternalBufferSize -- large installs could overflow the event buffer"
    Add-Assertion "Instant watcher: Error event -> catch-up rescan sentinel (Register-ObjectEvent, PS7)" ($startBody -match 'Register-ObjectEvent' -and $startBody -match "'Error'" -and $startBody -match '__GMIFEO_RESCAN__') "watcher does not handle buffer-overflow Error via Register-ObjectEvent -> catch-up rescan sentinel missing (PS7 removed the += adapter)"
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
Add-Assertion "Instant watcher: Deleted handler bound (Register-ObjectEvent, PS7, catches uninstalls)" ($startBody -match 'Register-ObjectEvent' -and $startBody -match "'Deleted'") "watcher does not bind a Deleted event handler via Register-ObjectEvent -- uninstalled programs would leave stale IFEO keys (PS7 removed the += adapter)"
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
$createdHandlerMatch = [regex]::Match($startBody, '(?s)\$createdAction\s*=\s*\{(.*?)\n\s+\}\s*\n\s+\$renamedAction')
$createdHandlerBody = if ($createdHandlerMatch.Success) { $createdHandlerMatch.Groups[1].Value } else { "" }
Add-Assertion "Instant watcher: Created handler re-arms (cancels pending prune on update)" ($createdHandlerBody -match 'Prune' -and $createdHandlerBody -match 'RemoveAt') "Created handler does not cancel a pending stale-prune for the same base name -- a gmproxy IFEO key could be removed mid-updater-swap"
$renamedHandlerMatch = [regex]::Match($startBody, '(?s)\$renamedAction\s*=\s*\{(.*?)\n\s+\}\s*\n\s+\$errorAction')
$renamedHandlerBody = if ($renamedHandlerMatch.Success) { $renamedHandlerMatch.Groups[1].Value } else { "" }
Add-Assertion "Instant watcher: Renamed handler re-arms (cancels pending prune on .tmp->.exe update)" ($renamedHandlerBody -match 'Prune' -and $renamedHandlerBody -match 'RemoveAt') "Renamed handler does not cancel a pending stale-prune -- updaters that land via .tmp->.exe rename could lose the hook mid-swap"


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
Add-Assertion "Detector A: candidates filter drops BROWSERS + AppX (CompatExclusions.AppX.ContainsKey)" ($candBody.Contains('CompatExclusions.Browser.ContainsKey') -and $candBody.Contains('CompatExclusions.AppX.ContainsKey')) "candidates filter does not drop AppX -- AppX/Store stubs must be dropped (cannot run as SYSTEM + gmproxy rename breaks their Store redirect)"
Add-Assertion "Detector A: Get-GmSystemCompatExclusions broadened -- Get-AppxPackage -AllUsers (system-provisioned AppX)" ($gm.Contains('Get-AppxPackage -AllUsers')) "Get-AppxPackage -AllUsers missing -- system-provisioned AppX (Store Notepad) still missed by per-user scan"
Add-Assertion "Detector A: Get-GmSystemCompatExclusions broadened -- all-profiles WindowsApps scan (C:\Users)" ($gm.Contains('C:\Users') -and $gm.Contains('AppData\Local\Microsoft\WindowsApps')) "all-profiles WindowsApps scan missing -- per-user scan only catches the current user's aliases"
Add-Assertion "Detector A: candidates filter drops browsers (CompatExclusions.Browser.ContainsKey)" ($candBody.Contains('CompatExclusions.Browser.ContainsKey')) "candidates browser filter missing -- browsers in the auto-populate would be hooked"
Add-Assertion "Detector A: Install-IfeoElevation builds the compat sets once (Get-GmSystemCompatExclusions)" ($installBody.Contains('Get-GmSystemCompatExclusions')) "Install-IfeoElevation does not build CompatExclusions -- no install-time drop"
Add-Assertion "Detector A: Install-IfeoElevation filters the curated seed (filteredSeed)" ($installBody.Contains('filteredSeed')) "Install-IfeoElevation does not filter the seed -- AppX/browser names in the seed (notepad/chrome/firefox) would still be hooked unconditionally"
Add-Assertion "Detector A: Install-IfeoElevation counts browser + AppX drops (seedDroppedBrowser + seedDroppedAppx)" ($installBody.Contains('seedDroppedBrowser') -and $installBody.Contains('seedDroppedAppx')) "Install-IfeoElevation does not count AppX drops -- AppX/Store stubs must be dropped from the seed"
Add-Assertion "Detector A: Install-IfeoElevation collects dropped browser names (droppedBrowserNames)" ($installBody.Contains('droppedBrowserNames')) "Install-IfeoElevation does not collect dropped browser names -- cannot persist them to the store"
Add-Assertion "Detector A: Install-IfeoElevation persists browser names to store (Add-GmAutoExcludeEntries)" ($installBody.Contains('Add-GmAutoExcludeEntries -BaseNames $droppedBrowserNames')) "Install-IfeoElevation does not persist browser names -- browsers not excluded from launch #1 (gmhook + monitor defense-in-depth)"
Add-Assertion "Detector A: Add-GmAutoExcludeEntries helper defined in God-Mode-Windows.ps1" ($gm.Contains('function Add-GmAutoExcludeEntries')) "Add-GmAutoExcludeEntries missing -- Detector A persist has no backing helper"
Add-Assertion "Detector A: Add-GmAutoExcludeEntries opens Global\\GmProxyAutoExcludeMutex (cross-privilege)" ($gm.Contains('GmProxyAutoExcludeMutex')) "Add-GmAutoExcludeEntries does not use the cross-privilege mutex -- could race a concurrent gmproxy"
Add-Assertion "Detector A: IFEO log line reflects browser + AppX drop strategy (droppedAppx, NOT 'UWP/AppX stay hooked')" ($installBody.Contains('droppedAppx=$seedDroppedAppx') -and -not $installBody.Contains('UWP/AppX stay hooked')) "IFEO log line does not reflect the browser + AppX drop strategy"
Add-Assertion "Detector A: passes CompatExclusions to Get-IfeoElevationCandidates" ($installBody.Contains('Get-IfeoElevationCandidates -GmProxyExe $GmProxyExe -CompatExclusions $CompatExclusions')) "Install-IfeoElevation does not pass CompatExclusions to the auto-populate -- auto candidates would not be filtered"
Add-Assertion "Detector A: curated seed still lists chrome.exe (additive, filtered not removed)" ($arrText.Contains('chrome.exe')) "curated seed lost chrome.exe -- additive edit regressed the app list"
Add-Assertion "Detector A: curated seed still lists notepad.exe (additive, filtered not removed)" ($arrText.Contains('notepad.exe')) "curated seed lost notepad.exe -- additive edit regressed the app list"
Add-Assertion "Detector A: curated seed still lists firefox.exe (additive, filtered not removed)" ($arrText.Contains('firefox.exe')) "curated seed lost firefox.exe -- additive edit regressed the app list"

# --- 12b. Detector A AppX/Store-redirector stub drop (2026-07-19 strategy flip) ---
# AppX/WinUI Store-redirector stubs (notepad/mspaint/calc/photos/...) are now
# DROPPED from IFEO (like browsers) + persisted to the store with reason 'A',
# and any prior IFEO hook for them is removed on a re-enable. They cannot run
# as SYSTEM (AppX activation needs user identity) AND gmproxy's IFEO-bypass
# rename breaks their App Execution Alias redirect + .mui lookup, so native
# user launch is the only way they start. No hardcoded names -- the AppX set
# is the runtime alias-reparse + AppxPackage enumeration. Additive + fail-open.
Add-Assertion "Detector A AppX drop: Add-GmAutoExcludeEntries has a -Reason param (default 'P', 'A' for AppX)" ($gm -match 'param\(\[string\[\]\]\$BaseNames,\s*\[string\]\$Reason\s*=\s*''P''\)') "Add-GmAutoExcludeEntries missing the -Reason param -- AppX drops cannot be tagged reason 'A'"
Add-Assertion "Detector A AppX drop: Install-IfeoElevation persists the full AppX set with -Reason 'A'" ($installBody.Contains('Add-GmAutoExcludeEntries -BaseNames @($CompatExclusions.AppX.Keys) -Reason ''A''')) "Install-IfeoElevation does not persist the AppX set with reason 'A' -- gmproxy/gmhook/monitor won't skip Store stubs from launch #1"
Add-Assertion "Detector A AppX drop: Install-IfeoElevation removes prior AppX IFEO hooks (appxHookRemoved counter)" ($installBody.Contains('appxHookRemoved') -and $installBody.Contains('droppedAppxNames')) "Install-IfeoElevation does not clean up prior AppX IFEO hooks -- a re-enable on a VM that hooked notepad would leave it hooked (broken renamed copy)"
Add-Assertion "Detector A AppX drop: prior-hook cleanup is gmproxy-guarded (Debugger -notlike *gmproxy*)" ($installBody -match 'dbg.*-notlike.*gmproxy|gmproxy.*-notlike.*dbg') "the AppX prior-hook cleanup is not gmproxy-guarded -- could remove an unrelated IFEO key"
Add-Assertion "Detector A AppX drop: debug EXIT reports droppedAppx + persistedAppx + appxHookRemoved" ($installBody.Contains('droppedAppx=$seedDroppedAppx') -and $installBody.Contains('persistedAppx=') -and $installBody.Contains('appxHookRemoved=')) "debug EXIT does not report the AppX drop counts -- regression visibility lost"
Add-Assertion "Detector A AppX drop: Add-IfeoElevationForApp skips App Execution Alias stubs (ReparsePoint)" ($addBody.Contains('WindowsApps') -and $addBody.Contains('ReparsePoint') -and $addBody.Contains('SKIP-APPAlias')) "Add-IfeoElevationForApp does not skip App Execution Alias stubs -- a newly-installed Store app could be IFEO-hooked (broken renamed copy)"

# --- 12b-preseed. Detector B CLEAN-GUI admin-tool pre-seed (2026-07-21) ---
# mmc.exe (hosts every .msc snap-in) silently refuses SYSTEM: launches as SYSTEM,
# exits 0, renders no window (the MMC host relies on per-user profile/COM
# resources). Pre-seeding it in the auto-exclude store at install time with
# reason 'G' means gmproxy launches it as the current user from the FIRST
# launch, skipping the 2 one-time SYSTEM flash-and-disappear attempts that
# Detector B would otherwise need to learn from at runtime. The IFEO hook is
# RETAINED so menu [18] RESET AUTO-EXCLUDE STORE retries SYSTEM. perfmon.exe +
# resmon.exe are NOT pre-seeded (thin launchers that delegate to mmc.exe).
Add-Assertion "Detector B pre-seed: Install-IfeoElevation pre-seeds mmc.exe with reason 'G' (CLEAN-GUI)" ($installBody.Contains('Add-GmAutoExcludeEntries -BaseNames $preseededCleanGui -Reason ''G''')) "Install-IfeoElevation does not pre-seed mmc.exe with reason 'G' -- the 2 SYSTEM flash-and-disappear attempts are not eliminated"
Add-Assertion "Detector B pre-seed: pre-seed variable defines mmc.exe ($preseededCleanGui)" ($installBody.Contains('$preseededCleanGui = @(''mmc.exe'')')) "Install-IfeoElevation pre-seed variable missing or does not list mmc.exe"
Add-Assertion "Detector B pre-seed: debug EXIT reports preseededCleanGui count" ($installBody.Contains('preseededCleanGui=$($preseededCleanGui.Count)')) "Install-IfeoElevation debug EXIT does not report the pre-seed count -- regression visibility lost"
Add-Assertion "Detector B pre-seed: IFEO summary log mentions the mmc.exe pre-seed (CLEAN-GUI)" ($installBody.Contains('Detector B pre-seeded') -and $installBody.Contains('mmc.exe reason ''G''')) "Install-IfeoElevation summary log does not mention the mmc.exe pre-seed -- the user cannot tell why mmc.exe launches as user from launch #1"
Add-Assertion "Detector B pre-seed: seed comment says mmc.exe silently refuses SYSTEM (not 'known-good as SYSTEM')" ($installBody.Contains('mmc.exe silently refuses SYSTEM')) "Install-IfeoElevation seed comment does not say mmc.exe silently refuses SYSTEM -- the pre-seed rationale is not documented"

# --- 12c. notepad detection-miss fix + 3 hardening suggestions (2026-07-19) ---
# Get-GmSystemCompatExclusions gains (4) a direct C:\Program Files\WindowsApps
# manifest scan + (5) a curated Win11 Store-redirector stub fallback
# (notepad/mspaint/calc/snippingtool, Test-Path-validated) so the classic Win11
# stubs are classified AppX even when Get-AppxPackage misses them on an admin
# account -- the actual fix for "notepad still does not start" (Detector A then
# drops them from IFEO + persists 'A' + gmhook consults the store -> native
# launch). Plus Invoke-GmAutoExcludeReconcile (5-min monitor prune of orphaned
# 'A' entries) + the single $reasonLegend hashtable driving both legends.
$compatMatch = [regex]::Match($gm, '(?s)function\s+Get-GmSystemCompatExclusions\s*\{(.*?)\nfunction\s+Get-IfeoElevationCandidates\s*\{')
$compatBody = if ($compatMatch.Success) { $compatMatch.Groups[1].Value } else { "" }
Add-Assertion "Notepad fix: Get-GmSystemCompatExclusions body extractable (12c)" ($compatMatch.Success) "could not isolate Get-GmSystemCompatExclusions body"
if ($compatMatch.Success) {
    Add-Assertion "Notepad fix: curated Win11-stub fallback list present (\$win11StubNames + notepad/mspaint/calc/snippingtool)" ($compatBody.Contains('$win11StubNames') -and $compatBody.Contains('notepad.exe') -and $compatBody.Contains('mspaint.exe') -and $compatBody.Contains('calc.exe') -and $compatBody.Contains('snippingtool.exe')) "curated Win11-stub fallback missing -- notepad/mspaint/calc/snippingtool stay IFEO-hooked on VMs where Get-AppxPackage misses them (the actual notepad-doesn't-start bug)"
    Add-Assertion "Notepad fix: curated fallback validates each stub via Test-Path C:\Windows + System32 (per-VM honest)" ($compatBody.Contains('Test-Path ("C:\Windows\" + $stub)') -and $compatBody.Contains('C:\Windows\System32')) "curated fallback does not Test-Path-gate each stub -- would drop names absent on this VM"
    Add-Assertion "Notepad fix: curated fallback only adds names not already detected (\$appx.ContainsKey skip)" ($compatBody.Contains('$appx.ContainsKey($k)')) "curated fallback does not skip already-detected names -- redundant"
    Add-Assertion "Notepad fix: direct WindowsApps filesystem scan (C:\Program Files\WindowsApps + AppXManifest.xml manifest regex)" ($compatBody.Contains('C:\Program Files\WindowsApps') -and $compatBody.Contains('AppXManifest.xml') -and $compatBody.Contains('Executable="')) "direct WindowsApps filesystem scan missing -- packages Get-AppxPackage misses (Store Notepad on an admin account) are not caught"
}
Add-Assertion "Suggestion 1: Invoke-GmAutoExcludeReconcile function defined (orphaned 'A' prune)" ($gm.Contains('function Invoke-GmAutoExcludeReconcile')) "Invoke-GmAutoExcludeReconcile missing -- orphaned 'A' entries linger after a Store-app uninstall"
Add-Assertion "Suggestion 1: reconcile restricts pruning to install-time 'A' + 'P' entries (\$rsn -ne 'A' guard preserved, keep C/G)" ($gm.Contains('$rsn -ne ''A''')) "reconcile does not restrict pruning to install-time 'A'/'P' entries -- could drop runtime C/G learnings"
Add-Assertion "Suggestion 1: reconcile checks stub + alias existence before pruning" ($gm.Contains('$stubExists') -and $gm.Contains('$aliasExists') -and $gm.Contains('aliasBases')) "reconcile does not verify the stub/alias is gone -- could prune a still-installed Store app"
Add-Assertion "Suggestion 1: monitor calls reconcile on a 5-min cadence (\$lastReconcile + FromMinutes(5))" ($gm.Contains('$lastReconcile = [datetime]::MinValue') -and $gm.Contains('[TimeSpan]::FromMinutes(5)') -and $gm.Contains('Invoke-GmAutoExcludeReconcile')) "monitor does not call reconcile on a 5-min cadence -- orphaned 'A' entries never pruned"
Add-Assertion "Suggestion 2: Export-GodModeLogs builds a single \$reasonLegend hashtable ([ordered]@{) driving both legends" ($gm.Contains('$reasonLegend = [ordered]@{') -and $gm.Contains('$reasonParts = foreach ($k in $reasonLegend.Keys)') -and $gm.Contains('$reasonParts2 = foreach ($k in $reasonLegend.Keys)')) "Export-GodModeLogs missing the single $reasonLegend hashtable driving both legends -- the store + per-app legends can drift"

# --- 12d. Final 3 hardening suggestions: WinRT PE heuristic + reconcile 'P'
# prune (2026-07-20) ---
# S2: Test-GmPeImportsWinrt + AppX source (6) generalizes the curated Win11-stub
# list -- a C:\Windows/System32 .exe that IMPORTS a WinRT activation API
# (RoActivateInstance/WindowsCreateString) is classified AppX. Conservative-safe
# (a WinRT importer cannot run as SYSTEM anyway). Curated list (5) preserved.
# S3: reconcile also prunes stale 'P' browser entries (StartMenuInternet client
# vanished), fail-open on an empty browser scan; never touches runtime C/G.
# (S1 gmhook alias-stub skip is covered by Test-GmProxySession.ps1 section 28 +
# test-gmproxy-session.sh -- this file does not load gmhook.c.)
Add-Assertion "S2 PE heuristic: Test-GmPeImportsWinrt helper defined" ($gm.Contains('function Test-GmPeImportsWinrt')) "Test-GmPeImportsWinrt missing -- no dynamic WinRT-import PE heuristic to catch future Win11 stubs"
Add-Assertion "S2 PE heuristic: checks RoActivateInstance + WindowsCreateString imports" ($gm.Contains('RoActivateInstance') -and $gm.Contains('WindowsCreateString')) "PE heuristic does not check both WinRT activation API import names"
Add-Assertion "S2 PE heuristic: verifies MZ DOS magic + PE signature (0x4D/0x5A + 0x50/0x45 + eLfanew)" ($gm.Contains('0x4D') -and $gm.Contains('0x5A') -and $gm.Contains('0x50') -and $gm.Contains('0x45') -and $gm.Contains('eLfanew')) "PE heuristic does not verify the MZ+PE signatures -- a non-PE file could be misread as a stub"
Add-Assertion "S2 PE heuristic: 1MB size cap bounds the byte read" ($gm.Contains('1MB')) "PE heuristic missing the 1MB size cap -- unbounded read at Enable-time"
Add-Assertion "S2 PE heuristic: AppX source (6) scan ($stubDirs + Test-GmPeImportsWinrt in the compat body)" ($compatBody.Contains('$stubDirs') -and $compatBody.Contains('Test-GmPeImportsWinrt')) "AppX source (6) PE-heuristic scan missing -- future Win11 stubs not caught dynamically"
Add-Assertion "S2 PE heuristic: curated list (5) preserved ($win11StubNames still in the compat body)" ($compatBody.Contains('$win11StubNames')) "curated list (5) removed -- additive rule violated"
Add-Assertion "S3 reconcile: builds $browserBases (StartMenuInternet) for the 'P' prune" ($gm.Contains('$browserBases') -and $gm.Contains('StartMenuInternet')) "reconcile does not build $browserBases -- stale 'P' browser entries cannot be pruned"
Add-Assertion "S3 reconcile: prunes stale 'P' browser entries (\$rsn -ne 'P' guard)" ($gm.Contains('$rsn -ne ''P''')) "reconcile does not prune stale 'P' browser entries -- a browser uninstalled after enable lingers up to 30 days"
Add-Assertion "S3 reconcile: 'P' prune is fail-open on an empty browser scan (\$browserBases.Count -eq 0)" ($gm.Contains('$browserBases.Count -eq 0')) "reconcile 'P' prune not fail-open -- an empty browser scan (registry ACL denied) would prune ALL 'P' entries"

# --- 12e. Interactive-shell auto-elevation (option #2) + ISE hardening +
# self-collision guard (2026-07-20) ---
# Mirrors Test-GmProxySession.ps1 section 29 for the IFEO-layer invariants:
# ISE is added to $GmCriticalIfeoExclude (never IFEO-redirected to gmproxy, same
# as cmd/powershell/pwsh) AND excluded from the curated IFEO app list (section 4
# above now lists powershell_ise.exe). The monitor auto-elevates ISE in place
# (Test-GmPlumbingShell guard + Monitor-ElevateProcess interactive-shell Phase 0
# + Test-SystemProcessExists -InteractiveOnly) -- covered by Test-GmProxySession
# section 29 + the test-gmproxy-session.sh gmhook grep (this file does not load
# gmhook.c).
Add-Assertion "Opt2 ISE: `$GmCriticalIfeoExclude contains powershell_ise (never IFEO-redirected)" ($gm.Contains('"pwsh","powershell_ise","wt"')) "`$GmCriticalIfeoExclude missing powershell_ise -- ISE could be IFEO-redirected to gmproxy (breaks ISE, which launches commands via CreateProcessW)"
Add-Assertion "Opt2 collision: Test-SystemProcessExists has -InteractiveOnly switch (session-aware)" ($gm.Contains('param([string]$ProcessName, [switch]$InteractiveOnly)')) "Test-SystemProcessExists missing -InteractiveOnly -- the monitor's own Session-0 SYSTEM powershell would falsely trigger a purge of the user's shell"
Add-Assertion "Opt2 collision: Monitor-ElevateProcess defines `$interactiveShells (cmd/powershell/pwsh/powershell_ise)" ($gm.Contains('$interactiveShells = @("cmd","powershell","pwsh","powershell_ise")')) "Monitor-ElevateProcess missing `$interactiveShells -- interactive shells cannot be routed to the in-place Phase 0 path"
Add-Assertion "Opt2 collision: Test-GmPlumbingShell function defined (God Mode plumbing guard)" ($gm.Contains('function Test-GmPlumbingShell {')) "Test-GmPlumbingShell missing -- God Mode plumbing shells cannot be detected/protected from a mid-flight token swap"
Add-Assertion "Opt2 collision: Monitor-ElevateProcess non-shell purge uses -InteractiveOnly" ($gm.Contains('Test-SystemProcessExists -ProcessName "$procName.exe" -InteractiveOnly')) "Monitor-ElevateProcess non-shell purge does not use -InteractiveOnly -- a Session-0 SYSTEM instance could falsely trigger a desktop purge"

# --- 12f. PS7 event-watcher compat: FileSystemWatcher += -> Register-ObjectEvent (2026-07-20) ---
# PowerShell 7 removed the `$obj.Event += {}` PSEventReceived adapter (it throws
# "The property '<Event>' cannot be found on this object"), which silently broke
# Start-IfeoNewAppWatcher's four FileSystemWatcher handlers (Created/Renamed/
# Error/Deleted) on PS 7.x -- no newly-installed program was ever auto-hooked.
# Fix: each handler is bound via Register-ObjectEvent with the shared queues
# passed in via -MessageData (the -Action block runs in the event-subscription
# runscape where $script: scope does NOT reliably resolve), and the source
# identifiers are tracked in $script:IfeoNewAppSubscriptions for clean teardown.
Add-Assertion "PS7 watcher: Start-IfeoNewAppWatcher binds handlers via Register-ObjectEvent (not +=)" ($startBody -match 'Register-ObjectEvent -InputObject \$w') "Start-IfeoNewAppWatcher still uses the PS7-broken += adapter -- FileSystemWatcher handlers would silently fail to register"
Add-Assertion "PS7 watcher: NO .Created/.Renamed/.Deleted/.Error += left in Start-IfeoNewAppWatcher" ($startBody -notmatch '\.(Created|Renamed|Deleted|Error)\s*\+=') "Start-IfeoNewAppWatcher still has a .Event += attachment -- PS7 throws 'property cannot be found' and the handler never registers"
Add-Assertion "PS7 watcher: shared queues passed via -MessageData hashtable (runscope-safe)" ($startBody -match 'MessageData \$shared' -and $startBody -match 'Queue = \$script:IfeoNewAppQueue' -and $startBody -match 'Prune = \$script:IfeoPruneQueue') "Start-IfeoNewAppWatcher does not pass the queues via -MessageData -- the -Action block (event runscape) could not reach the queues reliably"
Add-Assertion "PS7 watcher: actions reach the queue via `$Event.MessageData (not `$script:)" ($startBody -match '\$Event\.MessageData') "Start-IfeoNewAppWatcher actions still reference script scope -- unreliable in the event-subscription runscape"
Add-Assertion "PS7 watcher: Register-ObjectEvent source ids tracked (IfeoNewAppSubscriptions)" ($startBody -match 'IfeoNewAppSubscriptions \+= \$sid' -and $gm -match '\$script:IfeoNewAppSubscriptions = @\(\)') "Start-IfeoNewAppWatcher does not track Register-ObjectEvent source ids -- Stop could not unregister the subscriptions"
Add-Assertion "PS7 watcher: Stop-IfeoNewAppWatcher unregisters the FileSystemWatcher subscriptions" ($gm -match 'function\s+Stop-IfeoNewAppWatcher[\s\S]{0,2000}?Unregister-Event -SourceIdentifier \$sid') "Stop-IfeoNewAppWatcher does not Unregister-Event the FileSystemWatcher subscriptions -- event jobs would leak across enable/disable cycles"

Write-Summary
