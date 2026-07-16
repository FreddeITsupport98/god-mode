#Requires -Version 5.1
<#
.SYNOPSIS
    Regression test for the gmproxy "born as SYSTEM" session-correctness fix and
    the monitor blank-owner kill guard.
.DESCRIPTION
    Source-level assertions (no side effects) that validate the fix for the
    reported runtime bug where, with the IFEO + gmproxy layer active:
      - Firefox launched with a blank User column (ownerless, could not tell
        SYSTEM vs admin),
      - Chrome launched then was instantly killed,
      - other programs came up "unusable" in a broken ownerless state.

    Root cause: IFEO launches gmproxy.exe AS THE INVOKING (admin) USER, which
    does NOT hold SeTcbPrivilege, so SetTokenInformation(TokenSessionId) silently
    failed. When the named Session-1 SYSTEM sources (winlogon/dwm/fontdrvhost)
    were PPL-protected and OpenProcess failed, gmproxy fell back to a Session 0
    SYSTEM token (services/svchost) and the child was born in Session 0 with no
    interactive desktop -> ownerless / unusable. The monitor's Stop-NonSystemInstances
    then killed those ownerless (blank-owner) instances during the brief WMI
    GetOwner resolution window -> Chrome instant-kill.

    This test asserts the fix is present in source:
      gmproxy.c:
        - GetActiveConsoleSessionId (dynamic wtsapi32 load of WTSGetActiveConsoleSessionId)
        - IsProcessSessionId (ProcessIdToSessionId) session filter
        - IsOpenableSystemProcess + StealSystemToken helpers
        - FindSystemProcessForToken now takes the active session and REQUIRES it
          (named priority + any-openable-SYSTEM-in-session fallback)
        - FindAnySystemProcessPid for the SeTcb relocate path
        - SeTcbPrivilege enabled (best-effort)
        - GRACEFUL FALLBACK: when no session-correct SYSTEM token + no SeTcb,
          launch the target as the current user via the IFEO-bypass hardlink
          (CreateProcessW) instead of a broken ownerless Session-0 launch
        - Regression guards: WinSta0\Default desktop, CreateHardLinkW IFEO bypass,
          CreateProcessWithTokenW + LOGON_WITH_PROFILE, IsSystemSid still present
      God-Mode-Windows.ps1 monitor:
        - Stop-NonSystemInstances has the blank-owner guard (do NOT kill when
          WMI GetOwner returns blank/null)
        - Both Invoke-ParallelElevation kill sites (sequential + threadjob) have
          the same guard
        - The guard appears >= 3 times overall

    Run: pwsh -File tests/Test-GmProxySession.ps1
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
    Write-Host "  GM-PROXY SESSION + MONITOR GUARD TEST SUMMARY" -ForegroundColor White
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
Write-Host "  God-Mode gmproxy Session Fix + Monitor Guard Regression" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

if (-not (Test-Path $GmProxy)) {
    Add-Assertion "gmproxy.c exists" $false "file not found: $GmProxy"
    Write-Summary
}
if (-not (Test-Path $GodMode)) {
    Add-Assertion "God-Mode-Windows.ps1 exists" $false "file not found: $GodMode"
    Write-Summary
}

$proxy = Get-Content -Raw $GmProxy
$gm = Get-Content -Raw $GodMode

# --- 1. gmproxy.c: active-console-session resolution ---
Add-Assertion "gmproxy.c: GetActiveConsoleSessionId helper defined" ($proxy -match 'static\s+DWORD\s+GetActiveConsoleSessionId\s*\(') "GetActiveConsoleSessionId helper missing"
Add-Assertion "gmproxy.c: dynamically loads WTSGetActiveConsoleSessionId (wtsapi32)" ($proxy -match 'WTSGetActiveConsoleSessionId' -and $proxy -match 'wtsapi32\.dll') "WTSGetActiveConsoleSessionId dynamic load missing"
Add-Assertion "gmproxy.c: ProcessIdToSessionId used for session filtering" ($proxy -match 'ProcessIdToSessionId') "ProcessIdToSessionId missing -- session cannot be verified"
Add-Assertion "gmproxy.c: IsProcessSessionId helper defined" ($proxy -match 'static\s+BOOL\s+IsProcessSessionId\s*\(') "IsProcessSessionId helper missing"

# --- 2. gmproxy.c: openable-SYSTEM + token-steal helpers ---
Add-Assertion "gmproxy.c: IsOpenableSystemProcess helper defined" ($proxy -match 'static\s+BOOL\s+IsOpenableSystemProcess\s*\(') "IsOpenableSystemProcess helper missing"
Add-Assertion "gmproxy.c: StealSystemToken helper defined" ($proxy -match 'static\s+HANDLE\s+StealSystemToken\s*\(') "StealSystemToken helper missing"
Add-Assertion "gmproxy.c: IsSystemSid still present (regression guard)" ($proxy -match 'static\s+BOOL\s+IsSystemSid\s*\(') "IsSystemSid removed -- SYSTEM SID check regressed"

# --- 3. gmproxy.c: FindSystemProcessForToken now requires the active session ---
Add-Assertion "gmproxy.c: FindSystemProcessForToken takes a session parameter" ($proxy -match 'static\s+DWORD\s+FindSystemProcessForToken\s*\(\s*DWORD\s+wantSession\s*\)') "FindSystemProcessForToken no longer takes the active session param"
Add-Assertion "gmproxy.c: FindSystemProcessForToken filters by session (IsProcessSessionId(..., wantSession))" ($proxy -match 'IsProcessSessionId\s*\(\s*pe\.th32ProcessID\s*,\s*wantSession\s*\)') "FindSystemProcessForToken does not call IsProcessSessionId(pid, wantSession) -- candidates are not filtered by the active session"
Add-Assertion "gmproxy.c: FindAnySystemProcessPid helper defined (SeTcb relocate path)" ($proxy -match 'static\s+DWORD\s+FindAnySystemProcessPid\s*\(') "FindAnySystemProcessPid missing -- cannot attempt session relocation"

# --- 4. gmproxy.c: SeTcb + session reassert + graceful fallback ---
Add-Assertion "gmproxy.c: enables SeTcbPrivilege (best-effort)" ($proxy -match 'EnablePrivilege\s*\(\s*L"SeTcbPrivilege"\s*\)') "SeTcbPrivilege not enabled -- SetTokenInformation(TokenSessionId) cannot work"
Add-Assertion "gmproxy.c: SetTokenInformation(TokenSessionId) present" ($proxy -match 'SetTokenInformation[\s\S]{0,120}?TokenSessionId') "SetTokenInformation/TokenSessionId missing"
Add-Assertion "gmproxy.c: haveToken gate variable present" ($proxy -match 'haveToken') "haveToken gate missing -- launch path cannot distinguish token vs fallback"
Add-Assertion "gmproxy.c: GRACEFUL FALLBACK launches as current user (CreateProcessW + hardlink)" ($proxy -match 'CreateProcessW\s*\(\s*hardlinkPath') "graceful fallback (CreateProcessW on hardlink) missing -- broken ownerless Session-0 launch would still occur"

# --- 5. gmproxy.c: regression guards (must not have regressed) ---
Add-Assertion "gmproxy.c: WinSta0\\Default desktop still set (regression guard)" ($proxy -match 'WinSta0\\\\Default') "interactive desktop string removed -- child would have no desktop"
Add-Assertion "gmproxy.c: IFEO recursion bypass (CreateHardLinkW) still present" ($proxy -match 'CreateHardLinkW') "hardlink IFEO bypass removed -- gmproxy would recurse"
Add-Assertion "gmproxy.c: SYSTEM token launch (CreateProcessWithTokenW + LOGON_WITH_PROFILE) still present" ($proxy -match 'CreateProcessWithTokenW' -and $proxy -match 'LOGON_WITH_PROFILE') "token launch path removed"

# --- 6. God-Mode-Windows.ps1: monitor blank-owner kill guard ---
$stopMatch = [regex]::Match($gm, '(?s)function\s+Stop-NonSystemInstances\s*\{(.*?)\nfunction\s+Get-OptimalThreadCount\s*\{')
$stopBody = if ($stopMatch.Success) { $stopMatch.Groups[1].Value } else { "" }
Add-Assertion "Stop-NonSystemInstances body extractable" ($stopMatch.Success) "could not isolate Stop-NonSystemInstances body"
if ($stopMatch.Success) {
    Add-Assertion "Stop-NonSystemInstances: blank-owner guard present (do NOT kill blank owner)" ($stopBody -match '\$owner\s+-and\s+\$owner\.User\s+-and\s+\$owner\.User\s+-ne\s+"SYSTEM"') "Stop-NonSystemInstances kills blank-owner processes (regression: would kill IFEO-launched apps)"
}

$parMatch = [regex]::Match($gm, '(?s)function\s+Invoke-ParallelElevation\s*\{(.*?)\nfunction\s+Get-NonSystemProcessesParallel\s*\{')
$parBody = if ($parMatch.Success) { $parMatch.Groups[1].Value } else { "" }
Add-Assertion "Invoke-ParallelElevation body extractable" ($parMatch.Success) "could not isolate Invoke-ParallelElevation body"
if ($parMatch.Success) {
    $guardCount = ([regex]::Matches($parBody, '\$owner\s+-and\s+\$owner\.User\s+-and\s+\$owner\.User\s+-ne\s+"SYSTEM"')).Count
    Add-Assertion "Invoke-ParallelElevation: blank-owner guard on BOTH kill sites (>=2)" ($guardCount -ge 2) "only $guardCount blank-owner guard(s) in Invoke-ParallelElevation (need 2: sequential + threadjob)"
}

$totalGuardCount = ([regex]::Matches($gm, '\$owner\s+-and\s+\$owner\.User\s+-and\s+\$owner\.User\s+-ne\s+"SYSTEM"')).Count
Add-Assertion "God-Mode-Windows.ps1: blank-owner guard appears >= 3 times (Stop + 2 Parallel)" ($totalGuardCount -ge 3) "only $totalGuardCount blank-owner guard(s) overall (need >= 3)"

Write-Summary
