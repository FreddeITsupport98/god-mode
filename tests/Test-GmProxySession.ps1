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
$GmHook = Join-Path $ProjectRoot "driver/gmhook.c"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  God-Mode gmproxy Session Fix + Monitor Guard Regression" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

if (-not (Test-Path $GmProxy)) {
    Add-Assertion "gmproxy.c exists" $false "file not found: $GmProxy"
    Write-Summary
}
if (-not (Test-Path $GmHook)) {
    Add-Assertion "gmhook.c exists" $false "file not found: $GmHook"
    Write-Summary
}
if (-not (Test-Path $GodMode)) {
    Add-Assertion "God-Mode-Windows.ps1 exists" $false "file not found: $GodMode"
    Write-Summary
}

$proxy = Get-Content -Raw $GmProxy
$gmhook = Get-Content -Raw $GmHook
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

# --- 7. gmproxy.c: durable diagnostic log (%TEMP%\gmproxy.log) ---
Add-Assertion "gmproxy.c: DiagLog helper defined (mirrors stderr to a log file)" ($proxy -match 'static\s+void\s+DiagLog\s*\(') "DiagLog helper missing -- stderr-only diagnostics would be invisible when IFEO launches gmproxy detached"
Add-Assertion "gmproxy.c: GmProxyDiagLogOpen helper defined" ($proxy -match 'static\s+FILE\*\s+GmProxyDiagLogOpen\s*\(') "GmProxyDiagLogOpen helper missing"
Add-Assertion "gmproxy.c: durable log written under TEMP via GetTempPathW + gmproxy.log" ($proxy -match 'GetTempPathW' -and $proxy -match 'gmproxy\.log') "durable gmproxy.log path missing -- diagnostics would not survive a detached launch"
Add-Assertion "gmproxy.c: log file opened append-mode (_wfopen with a)" ($proxy -match '_wfopen\s*\([^)]*L"a"') "log file not opened in append mode"
Add-Assertion "gmproxy.c: DiagLog writes to BOTH stderr and the log file (vfwprintf x2)" (([regex]::Matches($proxy,'vfwprintf')).Count -ge 2) "DiagLog does not mirror to both stderr and the log file"

# --- 8. gmproxy.c: monitor feedback named-pipe handoff (in-place elevation) ---
Add-Assertion "gmproxy.c: SignalGmProxyFeedback helper defined" ($proxy -match 'static\s+void\s+SignalGmProxyFeedback\s*\(') "SignalGmProxyFeedback helper missing -- graceful-fallback PID cannot be handed to the monitor"
Add-Assertion "gmproxy.c: feedback named pipe GodMode-GmProxyFeedback present" ($proxy -match 'GodMode-GmProxyFeedback') "named pipe GodMode-GmProxyFeedback missing"
Add-Assertion "gmproxy.c: feedback payload PID= over the pipe" ($proxy -match 'PID=%lu') "feedback payload PID= missing"
Add-Assertion "gmproxy.c: feedback pipe client is non-blocking (CreateFileW + OPEN_EXISTING)" ($proxy -match 'SignalGmProxyFeedback[\s\S]{0,300}?CreateFileW' -and $proxy -match 'OPEN_EXISTING') "feedback pipe client not non-blocking CreateFileW/OPEN_EXISTING"
Add-Assertion "gmproxy.c: graceful-fallback hands the launched PID to the monitor" ($proxy -match 'SignalGmProxyFeedback\s*\(\s*pi\.dwProcessId') "graceful-fallback does not hand the launched PID to the monitor"

# --- 9. God-Mode-Windows.ps1: monitor feedback listener + in-place elevation ---
Add-Assertion "God-Mode-Windows.ps1: Start-GmProxyFeedbackListener defined" ($gm -match 'function\s+Start-GmProxyFeedbackListener') "Start-GmProxyFeedbackListener missing"
Add-Assertion "God-Mode-Windows.ps1: Stop-GmProxyFeedbackListener defined" ($gm -match 'function\s+Stop-GmProxyFeedbackListener') "Stop-GmProxyFeedbackListener missing"
Add-Assertion "God-Mode-Windows.ps1: Invoke-GmProxyFeedbackElevation defined" ($gm -match 'function\s+Invoke-GmProxyFeedbackElevation') "Invoke-GmProxyFeedbackElevation missing"
Add-Assertion "God-Mode-Windows.ps1: GmProxyFeedbackQueue queue declared" ($gm -match 'GmProxyFeedbackQueue') "GmProxyFeedbackQueue missing"
Add-Assertion "God-Mode-Windows.ps1: listener uses NamedPipeServerStream + GodMode-GmProxyFeedback" ($gm -match 'NamedPipeServerStream' -and $gm -match 'GodMode-GmProxyFeedback') "named pipe server side missing"
Add-Assertion "God-Mode-Windows.ps1: in-place elevation uses ReplaceProcessTokenForPid (no kill-relaunch)" ($gm -match 'function\s+Invoke-GmProxyFeedbackElevation[\s\S]{0,500}?ReplaceProcessTokenForPid') "Invoke-GmProxyFeedbackElevation does not call ReplaceProcessTokenForPid"
Add-Assertion "God-Mode-Windows.ps1: Start-Monitoring starts the feedback listener" ($gm -match 'Start-GmProxyFeedbackListener') "Start-Monitoring does not start the feedback listener"
Add-Assertion "God-Mode-Windows.ps1: Start-Monitoring drains GmProxyFeedbackQueue into in-place elevation" ($gm -match 'GmProxyFeedbackQueue[\s\S]{0,200}?Invoke-GmProxyFeedbackElevation') "Start-Monitoring does not drain GmProxyFeedbackQueue into Invoke-GmProxyFeedbackElevation"
Add-Assertion "God-Mode-Windows.ps1: Disable-GodMode stops the feedback listener" ($gm -match 'Stop-GmProxyFeedbackListener') "Disable-GodMode does not stop the feedback listener"

# --- 10. God-Mode-Windows.ps1: Export-GodModeLogs (option 11) surfaces gmproxy.log ---
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs includes GM-PROXY DIAGNOSTIC LOG section" ($gm -match 'GM-PROXY DIAGNOSTIC LOG') "Export-GodModeLogs does not surface the gmproxy diagnostic log"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs reads gmproxy.log from TEMP" ($gm -match 'Join-Path[\s\S]{0,40}?gmproxy\.log') "Export-GodModeLogs does not read gmproxy.log"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs handles a missing gmproxy log gracefully" ($gm -match 'No gmproxy log found') "Export-GodModeLogs does not guard a missing gmproxy log"

# --- 11. God-Mode-Windows.ps1: CreateProcessAsSystem session-correctness (SeTcb + ownerless guard) ---
# Fixes the monitor's kill+relaunch path birthing Firefox/Chrome ownerless in Session 0
# (empty User column, no visible window) when winlogon/dwm/fontdrvhost are PPL-protected.
Add-Assertion "God-Mode-Windows.ps1: TokenOps enables SeTcbPrivilege in CreateProcessAsSystem" ($gm -match 'EnablePrivilege\(\s*"SeTcbPrivilege"\s*\)') "CreateProcessAsSystem does not enable SeTcbPrivilege -- SetTokenInformation(TokenSessionId) cannot relocate a Session-0 token"
Add-Assertion "God-Mode-Windows.ps1: TokenOps has SESSION0_REFUSED sentinel (ownerless birth refused)" ($gm -match 'SESSION0_REFUSED') "SESSION0_REFUSED sentinel missing -- ownerless Session-0 births would still occur"
Add-Assertion "God-Mode-Windows.ps1: TokenOps has GetTokenInformation P/Invoke (token session query)" ($gm -match 'public static extern bool GetTokenInformation') "GetTokenInformation P/Invoke missing -- cannot query the duplicated token's session"
Add-Assertion "God-Mode-Windows.ps1: TokenOps has WTSGetActiveConsoleSessionId P/Invoke" ($gm -match 'WTSGetActiveConsoleSessionId') "WTSGetActiveConsoleSessionId P/Invoke missing -- cannot resolve the active interactive session in C#"
Add-Assertion "God-Mode-Windows.ps1: CreateProcessAsSystem queries token session before launch" ($gm -match 'GetTokenInformation\(hPrimaryToken,\s*TokenSessionId') "CreateProcessAsSystem does not query the token's session before deciding to relocate"
Add-Assertion "God-Mode-Windows.ps1: CreateProcessAsSystem returns SESSION0_REFUSED on relocation failure" ($gm -match 'return SESSION0_REFUSED') "CreateProcessAsSystem does not refuse ownerless birth when session relocation fails"
Add-Assertion "God-Mode-Windows.ps1: Monitor-ElevateProcess logs SESSION0_REFUSED fall-through to service path" ($gm -match 'SESSION0_REFUSED[\s\S]{0,300}?service path') "Monitor-ElevateProcess does not log the SESSION0_REFUSED fall-through to the service path"
# WTSGetActiveConsoleSessionId fail-open (2026-07-22 VM crash): on Windows 11
# 26100 the wtsapi32.dll P/Invoke throws EntryPointNotFoundException at runtime
# (API-set forwarding quirk). Find-SystemProcessCandidate already catches it +
# defaults to session 1; CreateProcessAsSystem MUST too or the exception kills
# every Monitor-ElevateProcess Phase 1 attempt -> shells stay admin (whoami ->
# admin). The ExactSpelling DllImport hardening + the try/catch defaulting to 1
# are the fix. Source-level tests missed it (none execute the P/Invoke).
Add-Assertion "God-Mode-Windows.ps1: WTSGetActiveConsoleSessionId DllImport uses ExactSpelling + EntryPoint (no A/W suffix probing)" ($gm -match 'DllImport\("wtsapi32\.dll",\s*ExactSpelling\s*=\s*true,\s*EntryPoint\s*=\s*"WTSGetActiveConsoleSessionId"') "WTSGetActiveConsoleSessionId DllImport missing ExactSpelling/EntryPoint -- .NET may probe a non-existent A-suffixed name and fail to resolve the entry point on some Windows 11 builds"
Add-Assertion "God-Mode-Windows.ps1: CreateProcessAsSystem fail-open try/catch around WTSGetActiveConsoleSessionId (defaults to 1)" ($gm -match 'try\s*\{\s*activeSession\s*=\s*WTSGetActiveConsoleSessionId\(\)' -and $gm -match 'catch\s*\{\s*activeSession\s*=\s*1') "CreateProcessAsSystem does NOT catch the WTSGetActiveConsoleSessionId P/Invoke -- an EntryPointNotFoundException on Windows 11 26100 propagates uncaught through Monitor-ElevateProcess -> Start-Monitoring loop exception -> the shell is never elevated (whoami -> admin)"

# --- 12. God-Mode-Windows.ps1: Find-SystemProcessCandidate session-aware (Session 0 excluded) ---
Add-Assertion "God-Mode-Windows.ps1: Find-SystemProcessCandidate resolves activeSession via WTSGetActiveConsoleSessionId" ($gm -match '\[TokenOps\]::WTSGetActiveConsoleSessionId') "Find-SystemProcessCandidate does not resolve the active console session via [TokenOps]::WTSGetActiveConsoleSessionId()"
Add-Assertion "God-Mode-Windows.ps1: Find-SystemProcessCandidate uses \$activeSession (not hardcoded 1)" ($gm -match '\$activeSession') "Find-SystemProcessCandidate does not use an activeSession variable"
Add-Assertion "God-Mode-Windows.ps1: Find-SystemProcessCandidate priority filter uses \$activeSession" ($gm -match '\$_.SessionId\s+-eq\s+\$activeSession') "Find-SystemProcessCandidate priority filter does not use \$activeSession"
Add-Assertion "God-Mode-Windows.ps1: Find-SystemProcessCandidate excludes services.exe (Session-0 SYSTEM)" ($gm -match '"services\.exe"') "Find-SystemProcessCandidate does not exclude services.exe -- could steal a Session-0 SYSTEM token"
Add-Assertion "God-Mode-Windows.ps1: Find-SystemProcessCandidate fallback filters SessionId -gt 0" ($gm -match '\$_.ProcessId\s+-gt\s+4\s+-and\s+\$_.SessionId\s+-gt\s+0') "Find-SystemProcessCandidate fallback does not filter SessionId -gt 0 -- Session-0 SYSTEM tokens would be selected"

# --- 13. gmhook.c: FindSystemPid session-aware (no Session-0 SYSTEM token) ---
Add-Assertion "gmhook.c: GmHookGetActiveConsoleSessionId helper defined (dynamic wtsapi32 load)" ($gmhook -match 'static\s+DWORD\s+GmHookGetActiveConsoleSessionId\s*\(') "GmHookGetActiveConsoleSessionId helper missing -- gmhook cannot resolve the active session"
Add-Assertion "gmhook.c: dynamically loads WTSGetActiveConsoleSessionId (wtsapi32)" ($gmhook -match 'WTSGetActiveConsoleSessionId' -and $gmhook -match 'wtsapi32\.dll') "gmhook does not dynamically load WTSGetActiveConsoleSessionId"
Add-Assertion "gmhook.c: FindSystemPid uses ProcessIdToSessionId session filter" ($gmhook -match 'ProcessIdToSessionId\(pe\.th32ProcessID,\s*&procSession\)') "FindSystemPid does not filter by ProcessIdToSessionId -- could steal a Session-0 SYSTEM token"
Add-Assertion "gmhook.c: FindSystemPid skips non-active-session candidates" ($gmhook -match 'procSession\s*!=\s*activeSession') "FindSystemPid does not skip non-active-session candidates"

# --- 14. Build-version stamps (gmproxy + gmhook) + option-11 surfacing ---
# Each C binary bakes in a compile-time stamp via __DATE__/__TIME__ (changes on
# every recompile) and writes it to %TEMP%\gmproxy.log / %TEMP%\gmhook.log so
# Export-GodModeLogs (option [11]) can confirm at a glance which build is
# deployed (stale vs. freshly rebuilt).
Add-Assertion "gmproxy.c: GmWidenAscii helper defined (ASCII char->wchar_t for __DATE__/__TIME__)" ($proxy -match 'static\s+void\s+GmWidenAscii\s*\(') "GmWidenAscii helper missing -- __DATE__/__TIME__ cannot be widened for the wide DiagLog"
Add-Assertion "gmproxy.c: build stamp uses __DATE__ and __TIME__ (changes every recompile)" ($proxy -match '__DATE__' -and $proxy -match '__TIME__') "gmproxy.c build stamp does not use __DATE__/__TIME__ -- stamp would not change per build"
Add-Assertion "gmproxy.c: emits [GM-PROXY] BUILD stamp via DiagLog in wmain" ($proxy -match '\[GM-PROXY\]\s*BUILD\s+%ls\s+%ls') "gmproxy.c does not emit a [GM-PROXY] BUILD stamp in wmain (expect %ls %ls wide format)"
Add-Assertion "gmhook.c: GmWidenAscii helper defined" ($gmhook -match 'static\s+void\s+GmWidenAscii\s*\(') "gmhook.c GmWidenAscii helper missing"
Add-Assertion "gmhook.c: GmHookWriteBuildStamp helper defined" ($gmhook -match 'static\s+void\s+GmHookWriteBuildStamp\s*\(') "gmhook.c GmHookWriteBuildStamp helper missing"
Add-Assertion "gmhook.c: build stamp uses __DATE__ and __TIME__" ($gmhook -match '__DATE__' -and $gmhook -match '__TIME__') "gmhook.c build stamp does not use __DATE__/__TIME__"
Add-Assertion "gmhook.c: writes [GM-HOOK] BUILD stamp to gmhook.log under TEMP (GetTempPathW)" ($gmhook -match 'GetTempPathW' -and $gmhook -match 'gmhook\.log' -and $gmhook -match '\[GM-HOOK\]\s*BUILD') "gmhook.c does not write a [GM-HOOK] BUILD stamp to %TEMP%\gmhook.log"
Add-Assertion "gmhook.c: build stamp mirrored to OutputDebugStringW (live DebugView)" ($gmhook -match 'OutputDebugStringW') "gmhook.c build stamp not mirrored to OutputDebugStringW"
Add-Assertion "gmhook.c: build stamp mutex-serialized (CreateMutexW + GodMode_GmHookLog, no DllMain block)" ($gmhook -match 'CreateMutexW' -and $gmhook -match 'GodMode_GmHookLog') "gmhook.c build stamp not mutex-serialized -- concurrent attaches could corrupt gmhook.log"
Add-Assertion "gmhook.c: DllMain calls GmHookWriteBuildStamp on DLL_PROCESS_ATTACH" ($gmhook -match 'GmHookWriteBuildStamp\s*\(\s*\)') "DllMain does not call GmHookWriteBuildStamp on attach"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs has GM BUILD VERSIONS section" ($gm -match 'GM BUILD VERSIONS') "Export-GodModeLogs does not have a GM BUILD VERSIONS section"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs extracts last [GM-PROXY] BUILD stamp (escaped bracket)" ($gm -match 'Select-String[\s\S]{0,80}?\\\[GM-PROXY\\\]\s+BUILD') "Export-GodModeLogs does not extract the last [GM-PROXY] BUILD stamp -- the unescaped 'GM-PROXY BUILD' pattern never matches the real '[GM-PROXY] BUILD' log line (the ']' breaks it) -> always '[not yet logged]'"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs extracts last [GM-HOOK] BUILD stamp (escaped bracket)" ($gm -match 'Select-String[\s\S]{0,80}?\\\[GM-HOOK\\\]\s+BUILD') "Export-GodModeLogs does not extract the last [GM-HOOK] BUILD stamp -- the unescaped 'GM-HOOK BUILD' pattern never matches the real '[GM-HOOK] BUILD' log line (the ']' breaks it) -> always '[not yet logged]'"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs reads gmhook.log from TEMP" ($gm -match 'Join-Path[\s\S]{0,40}?gmhook\.log') "Export-GodModeLogs does not read gmhook.log"
Add-Assertion "God-Mode-Windows.ps1: Uninstall-ProcessHook removes gmhook.log (uninstaller kept current)" ($gm -match 'function\s+Uninstall-ProcessHook[\s\S]{0,4000}?gmhook\.log') "Uninstall-ProcessHook does not remove gmhook.log -- uninstaller not kept current with the new diagnostic log"

# --- 15. GetTempPathW trailing-backslash hardening (defensive belt-and-suspenders) ---
# GetTempPathW is documented to return a path ending in '\', and on real Windows
# AND wine it does -- GmEnsureTrailingBackslash is a defensive no-op that appends
# a backslash only if some non-conforming environment ever omitted one. NOTE: the
# actual Cgmhook.log wine artifact was NOT a missing backslash -- see section 16
# (the %s->%ls wide-format fix is the real root cause).
Add-Assertion "gmproxy.c: GmEnsureTrailingBackslash helper defined (trailing-backslash hardening)" ($proxy -match 'static\s+void\s+GmEnsureTrailingBackslash\s*\(') "GmEnsureTrailingBackslash helper missing -- gmproxy.log path not hardened against a non-trailing-backslash GetTempPathW return"
Add-Assertion "gmproxy.c: GmProxyDiagLogOpen calls GmEnsureTrailingBackslash after GetTempPathW" ($proxy -match 'GmProxyDiagLogOpen[\s\S]{0,300}?GetTempPathW[\s\S]{0,120}?GmEnsureTrailingBackslash') "GmProxyDiagLogOpen does not normalize the temp dir after GetTempPathW -- wine could concatenate tempDir+gmproxy.log"
Add-Assertion "gmhook.c: GmEnsureTrailingBackslash helper defined" ($gmhook -match 'static\s+void\s+GmEnsureTrailingBackslash\s*\(') "gmhook.c GmEnsureTrailingBackslash helper missing -- gmhook.log path not hardened"
Add-Assertion "gmhook.c: GmHookWriteBuildStamp calls GmEnsureTrailingBackslash after GetTempPathW" ($gmhook -match 'GmHookWriteBuildStamp[\s\S]{0,300}?GetTempPathW[\s\S]{0,120}?GmEnsureTrailingBackslash') "GmHookWriteBuildStamp does not normalize the temp dir after GetTempPathW -- wine could concatenate tempDir+gmhook.log (the Cgmhook.log artifact)"

# --- 16. Wide-format %ls fix (MinGW swprintf/fwprintf %s truncates wchar_t* to 1 char) ---
# ROOT CAUSE of the wine smoke-test Cgmhook.log/Cgmproxy.log repo-root artifact + the
# garbled [[ stamps: %s in MinGW's wide swprintf/fwprintf/vfwprintf reads a wchar_t*
# argument as a narrow char* and stops at the first 0x00 byte (the high byte of the
# first ASCII wchar_t), truncating to one character. So "%sgmhook.log" with tempDir=
# "C:\...\Temp\" became "Cgmhook.log", and the stamp line wrote only "[" per attach.
# Fix: %s -> %ls (wide, consistent across MSVC and MinGW) for every wchar_t* arg, and
# fputws for pre-built wide line writes. Probe-confirmed under wine.
Add-Assertion "gmproxy.c: log path swprintf uses %ls (wide) for the wchar_t tempDir" ($proxy -match '%lsgmproxy\.log') "gmproxy.c log path still uses %s -- MinGW would truncate tempDir to 1 char -> Cgmproxy.log in CWD"
Add-Assertion "gmproxy.c: BUILD stamp DiagLog uses %ls for widened __DATE__/__TIME__" ($proxy -match '\[GM-PROXY\]\s*BUILD\s+%ls\s+%ls') "gmproxy.c BUILD stamp still uses %s -- MinGW would truncate wdate/wtime to 1 char (garbled stamp)"
Add-Assertion "gmproxy.c: diag session header written via fputws (not fwprintf %s)" ($proxy -match 'fputws\s*\(\s*header') "gmproxy.c header still uses fwprintf %s -- MinGW would truncate the wide header"
Add-Assertion "gmproxy.c: IFEO-bypass hardlink swprintf uses %ls for dirPath + baseName" ($proxy -match '%lsgmproxy_%lu_%ls') "gmproxy.c hardlink path still uses %s -- MinGW would truncate dirPath/baseName"
Add-Assertion "gmproxy.c: graceful-fallback + success DiagLog use %ls for argv[1]" ($proxy -match 'Launched %ls as current user' -and $proxy -match 'Launched %ls as SYSTEM') "gmproxy.c Launched DiagLogs still use %s -- MinGW would truncate argv[1] (the target path)"
Add-Assertion "gmhook.c: log path swprintf uses %ls (wide) for the wchar_t tempDir" ($gmhook -match '%lsgmhook\.log') "gmhook.c log path still uses %s -- MinGW would truncate tempDir to 1 char -> Cgmhook.log in CWD (the artifact)"
Add-Assertion "gmhook.c: BUILD stamp line uses %ls for wdate/wtime/baseName" ($gmhook -match '\[GM-HOOK\]\s*BUILD\s+%ls\s+%ls\s+loaded in %ls') "gmhook.c BUILD line still uses %s -- MinGW would truncate wdate/wtime/baseName to 1 char (garbled [[ stamp)"
Add-Assertion "gmhook.c: stamp line written via fputws (not fwprintf %s)" ($gmhook -match 'fputws\s*\(\s*line') "gmhook.c stamp line still uses fwprintf %s -- MinGW would truncate the wide line to 1 char"

# --- 17. gmproxy.c + Invoke-HybridElevation: ownerless Session-0 birth refusal ---
# Belt-and-suspenders for the Firefox/Chrome "launches without user column" fix.
# (a) gmproxy.c: when gmproxy itself runs in Session 0 (invoked by a SYSTEM
#     service / Session-0 scheduled task) AND no session-correct SYSTEM token is
#     obtainable, it must REFUSE (return 1) instead of falling to a current-user
#     CreateProcessW that would inherit Session 0 -> ownerless child. The normal
#     IFEO path (interactive session) keeps its current-user fallback.
# (b) Invoke-HybridElevation Phase 2: the scheduled-task fallback (S-1-5-18
#     principal, Session 0) must route its task action through gmproxy.exe (which
#     relocates the token to the active session) instead of launching the target
#     directly (which births ownerless). If gmproxy is missing, refuse (graceful
#     degradation). Mirrors Start-ProcessWithService.
Add-Assertion "gmproxy.c: detects own session via ProcessIdToSessionId(GetCurrentProcessId())" ($proxy -match 'ProcessIdToSessionId\s*\(\s*GetCurrentProcessId\s*\(\s*\)\s*,') "gmproxy.c does not query its own session -- cannot detect a Session-0 (service/scheduled-task) invocation"
Add-Assertion "gmproxy.c: mySessionIsZero guard variable present" ($proxy -match 'mySessionIsZero') "mySessionIsZero guard missing -- ownerless-birth refusal cannot gate on Session 0"
Add-Assertion "gmproxy.c: REFUSE diag present (ownerless Session-0 birth refused)" ($proxy -match '\[GM-PROXY\]\s*REFUSE') "REFUSE diag missing -- ownerless-birth refusal not implemented"
Add-Assertion "gmproxy.c: refusal returns 1 on Session-0 ownerless birth (no current-user launch in Session 0)" ($proxy -match 'mySessionIsZero\s*\)\s*\{[\s\S]{0,700}?return\s+1') "refusal does not return 1 when mySessionIsZero -- ownerless Session-0 current-user launch would still occur"
Add-Assertion "gmproxy.c: graceful current-user fallback preserved below the refusal guard (non-Session-0 IFEO path)" ($proxy -match 'mySessionIsZero[\s\S]{0,600}?CreateProcessW\s*\(\s*hardlinkPath') "current-user CreateProcessW fallback not preserved after the refusal guard -- normal IFEO graceful degradation would break"
Add-Assertion "God-Mode-Windows.ps1: Start-ProcessWithService routes Session-0 service through gmproxy (session-correct SYSTEM)" ($gm -match 'refusing Session-0 service launch to avoid ownerless birth') "Start-ProcessWithService does not refuse ownerless when gmproxy missing / does not route the service through gmproxy -- the LIVE monitor ownerless path would regress"
Add-Assertion "God-Mode-Windows.ps1: Invoke-HybridElevation Phase 2 routes scheduled task through gmproxy (not direct target path)" ($gm -match 'New-ScheduledTaskAction\s+-Execute\s+\$GmProxyExe\s+-Argument\s+\$taskArgs') "Invoke-HybridElevation Phase 2 does not route the scheduled-task action through gmproxy -- ownerless Session-0 birth would still occur"
Add-Assertion "God-Mode-Windows.ps1: Invoke-HybridElevation Phase 2 refuses ownerless when gmproxy missing (graceful degradation)" ($gm -match 'refusing Session-0 scheduled-task launch to avoid ownerless birth') "Invoke-HybridElevation Phase 2 does not refuse ownerless birth when gmproxy is missing -- would spawn an unusable Session-0 copy"
Add-Assertion "God-Mode-Windows.ps1: Invoke-HybridElevation Phase 2 no longer launches the target directly as the task action (ownerless path removed)" ($gm -notmatch 'New-ScheduledTaskAction\s+-Execute\s+\$Path\s+-Argument\s+\$Arguments') "Invoke-HybridElevation Phase 2 still launches the target directly as the scheduled-task action -- ownerless Session-0 birth path not removed"

# --- 18. Invoke-HybridElevation Phase 2 kill-AFTER-success + gmproxy test seam ---
# Suggestion 1: Phase 2 no longer kills existing instances BEFORE launching the
# scheduled task (the old kill-before-launch + 800ms settle left the user with
# NO app if gmproxy-as-task refused or the SYSTEM child lost the single-instance
# race). It now mirrors Monitor-ElevateProcess: wait for the SYSTEM child to
# surface AFTER the task enters Running, then purge non-SYSTEM duplicates ONLY
# if a SYSTEM instance is confirmed -- otherwise keep the existing user-context
# process (graceful degradation, no purge). Suggestion 2: gmproxy.c has a
# compile-time test seam (#ifdef GMPROXY_TEST_FORCE_SESSION0) so the ownerless-
# birth REFUSE branch can be exercised at runtime under wine (which does not
# model Session 0); the PRODUCTION build (driver/build.ps1) must NOT define it.
$build = $null
$buildPath = Join-Path $ProjectRoot "driver/build.ps1"
if (Test-Path $buildPath) { $build = Get-Content -Raw $buildPath }
Add-Assertion "God-Mode-Windows.ps1: Invoke-HybridElevation Phase 2 kill-after-success uses `$systemAlive gate" ($gm -match 'systemAlive') "Phase 2 kill-after-success `$systemAlive marker missing -- kill-before-launch may still be in place"
Add-Assertion "God-Mode-Windows.ps1: Phase 2 waits for the SYSTEM child via Test-SystemProcessExists before purging" ($gm -match 'Test-SystemProcessExists\s+-ProcessName\s+"\$procName\.exe"[\s\S]{0,40}?\$systemAlive\s*=\s*\$true') "Phase 2 does not wait for a SYSTEM child via Test-SystemProcessExists before deciding to purge -- could purge with no SYSTEM child alive"
Add-Assertion "God-Mode-Windows.ps1: Phase 2 purge is gated on `$systemAlive (Stop-NonSystemInstances only when SYSTEM alive)" ($gm -match 'if\s+\(\$systemAlive\)\s*\{[\s\S]{0,200}?Stop-NonSystemInstances\s+-ProcessName\s+"\$procName\.exe"') "Phase 2 purge is not gated on `$systemAlive -- would purge non-SYSTEM instances even when no SYSTEM child was born (old kill-before 'no app' state)"
Add-Assertion "God-Mode-Windows.ps1: Phase 2 keeps the user-context process when no SYSTEM child surfaces (graceful degradation)" ($gm -match 'no SYSTEM instance detected[\s\S]{0,200}?keeping user-context process') "Phase 2 does not keep the user-context process when no SYSTEM child surfaces -- would leave the user with no app"
Add-Assertion "God-Mode-Windows.ps1: Phase 2 old kill-before-launch comment removed" ($gm -notmatch 'Kill existing instances first so single-instance apps') "Phase 2 still has the old kill-before-launch comment -- kill-before-launch may not have been removed"
Add-Assertion "gmproxy.c: compile-time test seam #ifdef GMPROXY_TEST_FORCE_SESSION0 present (wine REFUSE runtime proof)" ($proxy -match '#ifdef\s+GMPROXY_TEST_FORCE_SESSION0') "gmproxy.c compile-time test seam missing -- ownerless-birth REFUSE cannot be exercised at runtime under wine (which does not model Session 0)"
Add-Assertion "gmproxy.c: test seam forces mySession=0 / mySessionIsZero=TRUE (exercises the REFUSE branch)" ($proxy -match 'GMPROXY_TEST_FORCE_SESSION0[\s\S]{0,1200}?mySession\s*=\s*0') "gmproxy.c test seam does not force mySession=0 -- the FORCED build would not reach the REFUSE branch"
Add-Assertion "driver/build.ps1: PRODUCTION build does NOT define the test seam (shipped gmproxy.exe unaffected)" ($null -ne $build -and $build -notmatch 'GMPROXY_TEST_FORCE_SESSION0') "driver/build.ps1 references GMPROXY_TEST_FORCE_SESSION0 -- the production build would force-refuse ownerless birth in the field"

# --- 19. gmproxy.c: token-consistent env block (Layer 1) + browser launch flags (Layer 2) ---
# Root cause of "Chrome auto-exits / Firefox opens but cannot browse" when born as
# SYSTEM: gmproxy launched the SYSTEM child with lpEnvironment=NULL, so the
# SYSTEM-token process inherited the invoking USER's APPDATA/LOCALAPPDATA
# (gmproxy's env) -> token/env mismatch. Single-instance + profile-lock apps
# (Chrome, Firefox, Electron) then either IPC-exited to the user's running
# instance or failed to init the content sandbox -> unusable as SYSTEM.
# Layer 1: build the env block from the stolen SYSTEM token via
#   CreateEnvironmentBlock(envBlock, hPrimary, TRUE) so USERPROFILE/APPDATA
#   point at systemprofile\AppData (the SYSTEM child's own profile, no lock
#   conflict). Passed on BOTH token launch sites. Three-tier fallback to NULL
#   (previous behavior) if CreateEnvironmentBlock fails. The graceful
#   current-user fallback (CreateProcessW, no token) stays NULL (correct -- no
#   SYSTEM token to build an env from).
# Layer 2: inject --no-sandbox (Chromium family + Electron) / -no-remote
#   (Firefox) immediately after argv[1] so the SYSTEM child renders and does
#   not IPC-exit. Scoped by exact base-name match; iexplore.exe is NOT
#   Chromium and is excluded. Build links userenv (MinGW -luserenv / MSVC
#   userenv.lib) for CreateEnvironmentBlock/DestroyEnvironmentBlock.
Add-Assertion "gmproxy.c: #include <userenv.h> present (Layer 1 env block)" ($proxy -match '#include\s+<userenv\.h>') "gmproxy.c missing #include <userenv.h> -- CreateEnvironmentBlock undeclared"
Add-Assertion "gmproxy.c: MSVC #pragma comment(lib, userenv.lib) present (auto-link)" ($proxy -match '#pragma\s+comment\s*\(\s*lib\s*,\s*"userenv\.lib"\s*\)') "gmproxy.c MSVC #pragma for userenv.lib missing -- MSVC build would not auto-link userenv"
Add-Assertion "gmproxy.c: CreateEnvironmentBlock called with hPrimary (token-consistent env)" ($proxy -match 'CreateEnvironmentBlock\s*\(\s*&envBlock\s*,\s*hPrimary\s*,\s*TRUE\s*\)') "gmproxy.c does not build the env block from hPrimary -- SYSTEM child inherits the user's APPDATA (token/env mismatch)"
Add-Assertion "gmproxy.c: DestroyEnvironmentBlock frees the env block" ($proxy -match 'DestroyEnvironmentBlock\s*\(\s*envBlock\s*\)') "gmproxy.c does not free the env block -- handle leak on every SYSTEM launch"
Add-Assertion "gmproxy.c: env block freed on the REFUSE return path" ($proxy -match 'mySessionIsZero\s*\)\s*\{[\s\S]{0,600}?DestroyEnvironmentBlock') "env block not freed on the REFUSE path -- leak when gmproxy refuses ownerless Session-0 birth"
Add-Assertion "gmproxy.c: env block freed on the launch-failure return path" ($proxy -match 'launch failed[\s\S]{0,400}?DestroyEnvironmentBlock') "env block not freed on the launch-failure path -- leak when both token + fallback launches fail"
Add-Assertion "gmproxy.c: env block freed on the success return path" ($proxy -match 'CloseHandle\s*\(\s*pi\.hThread\s*\)[\s\S]{0,200}?DestroyEnvironmentBlock') "env block not freed on the success path -- leak on every successful SYSTEM launch"
Add-Assertion "gmproxy.c: env block passed to CreateProcessWithTokenW (not NULL)" ($proxy -match 'cpwt\s*\(\s*hPrimary\s*,\s*LOGON_WITH_PROFILE\s*,\s*hardlinkPath\s*,\s*cmdLine\s*,\s*CREATE_UNICODE_ENVIRONMENT\s*\|\s*CREATE_SUSPENDED\s*,\s*envBlock\s*,'  ) "CreateProcessWithTokenW still passed NULL env -- SYSTEM child inherits user APPDATA"
Add-Assertion "gmproxy.c: env block passed to CreateProcessAsUserW (not NULL)" ($proxy -match 'CreateProcessAsUserW\s*\(\s*hPrimary\s*,\s*hardlinkPath[\s\S]{0,120}?CREATE_UNICODE_ENVIRONMENT\s*\|\s*CREATE_SUSPENDED\s*,\s*envBlock\s*,'  ) "CreateProcessAsUserW still passed NULL env -- fallback token path inherits user APPDATA"
Add-Assertion "gmproxy.c: three-tier fallback (CreateEnvironmentBlock failure -> NULL, no regression)" ($proxy -match 'CreateEnvironmentBlock\s*\(\s*&envBlock[\s\S]{0,120}?envBlock\s*=\s*NULL') "gmproxy.c does not fall back to NULL when CreateEnvironmentBlock fails -- a failed env build would abort the launch"
Add-Assertion "gmproxy.c: graceful current-user fallback CreateProcessW still passes NULL env (no token -> no env block)" ($proxy -match 'CreateProcessW\s*\(\s*hardlinkPath\s*,\s*cmdLine\s*,\s*NULL\s*,\s*NULL\s*,\s*FALSE\s*,\s*CREATE_UNICODE_ENVIRONMENT\s*\|\s*CREATE_SUSPENDED\s*,\s*NULL\s*,'  ) "graceful-fallback CreateProcessW passes envBlock instead of NULL -- would build an env for a non-SYSTEM current-user launch (wrong)"
Add-Assertion "gmproxy.c: GmProxyLaunchFlagForTarget helper defined (Layer 2 flag injection)" ($proxy -match 'static\s+const\s+wchar_t\*\s+GmProxyLaunchFlagForTarget\s*\(') "GmProxyLaunchFlagForTarget helper missing -- browser launch flags cannot be injected"
Add-Assertion "gmproxy.c: --no-sandbox injected for Chromium family + Electron" ($proxy -match 'L"--no-sandbox"') "gmproxy.c does not inject --no-sandbox -- Chromium/Electron SYSTEM children would fail to render (sandbox cannot init under SYSTEM)"
Add-Assertion "gmproxy.c: -no-remote injected for Firefox (no IPC to user instance)" ($proxy -match 'L"-no-remote"') "gmproxy.c does not inject -no-remote for Firefox -- SYSTEM Firefox would IPC-exit to the user's running Firefox"
Add-Assertion "gmproxy.c: chrome.exe in the --no-sandbox set" ($proxy -match 'GmProxyLaunchFlagForTarget[\s\S]{0,1500}?_wcsicmp\s*\(\s*base\s*,\s*L"chrome\.exe"\s*\)') "chrome.exe not in the --no-sandbox set -- Chrome would still auto-exit as SYSTEM"
Add-Assertion "gmproxy.c: firefox.exe in the -no-remote set" ($proxy -match 'GmProxyLaunchFlagForTarget[\s\S]{0,1500}?_wcsicmp\s*\(\s*base\s*,\s*L"firefox\.exe"\s*\)') "firefox.exe not in the -no-remote set -- Firefox would still IPC-exit as SYSTEM"
Add-Assertion "gmproxy.c: msedge/discord/teams/code in the --no-sandbox set (Electron/Chromium)" ($proxy -match 'GmProxyLaunchFlagForTarget[\s\S]{0,1500}?L"msedge\.exe"' -and $proxy -match 'GmProxyLaunchFlagForTarget[\s\S]{0,1500}?L"discord\.exe"' -and $proxy -match 'GmProxyLaunchFlagForTarget[\s\S]{0,1500}?L"teams\.exe"' -and $proxy -match 'GmProxyLaunchFlagForTarget[\s\S]{0,1500}?L"code\.exe"') "one or more of msedge/discord/teams/code missing from the --no-sandbox set -- Electron/Chromium SYSTEM children would fail to render"
Add-Assertion "gmproxy.c: iexplore.exe EXCLUDED from --no-sandbox (not Chromium)" ($proxy -notmatch 'GmProxyLaunchFlagForTarget[\s\S]{0,1500}?L"iexplore\.exe"') "iexplore.exe is in the --no-sandbox set -- it is NOT Chromium and --no-sandbox would be wrong"
Add-Assertion "gmproxy.c: injectFlag inserted after argv[1] in the rebuilt command line" ($proxy -match 'i\s*==\s*1\s*&&\s*injectFlag') "injectFlag not inserted after argv[1] -- flag would appear in the wrong position or not at all"
Add-Assertion "driver/build.ps1: MinGW gmproxy links -luserenv (CreateEnvironmentBlock)" ($null -ne $build -and $build -match '-luserenv') "driver/build.ps1 MinGW gmproxy line does not link -luserenv -- CreateEnvironmentBlock would not resolve at link time"
Add-Assertion "driver/build.ps1: MSVC gmproxy links userenv.lib" ($null -ne $build -and $build -match 'userenv\.lib') "driver/build.ps1 MSVC gmproxy line does not link userenv.lib -- MSVC build would fail at link time"
Add-Assertion "driver/build.ps1: gmhook line UNCHANGED (no userenv -- gmhook has no env block)" ($null -ne $build -and $build -match '-shared\s+-o\s+"\$hookOut"\s+"\$hookSrc"\s*-ladvapi32\s*-lkernel32\s*-lntdll\s*-luser32') "driver/build.ps1 gmhook line changed -- gmhook does not use CreateEnvironmentBlock and should not link userenv"

# --- 20. gmproxy.c: per-app launch telemetry + child-survival observation (big debug) ---
# gmproxy now emits a structured [GM-PROXY] LAUNCH: line for EVERY invocation
# (app, pid, mode=SYSTEM/FALLBACK/REFUSE/FAILED, session, token-source pid,
# injected launch flag, env-block state) and, when a child was actually born,
# observes whether it survived a ~1.5s grace window via WaitForSingleObject --
# a child that EXITED within the window is the "launched but instantly died /
# won't render" signal the user reports per app. Export-GodModeLogs (option
# [11]) aggregates these into a PER-APP LAUNCH REPORT so the IFEO exclusion can
# be scoped to exactly the apps that break as SYSTEM (data-driven, not guessed).
Add-Assertion "gmproxy.c: GmProxyLogLaunchReport per-app telemetry helper defined" ($proxy -match 'static\s+void\s+GmProxyLogLaunchReport\s*\(') "GmProxyLogLaunchReport helper missing -- per-app launch telemetry cannot be emitted"
Add-Assertion "gmproxy.c: GM_CHILD_OBSERVE_MS grace-window define present" ($proxy -match 'GM_CHILD_OBSERVE_MS') "GM_CHILD_OBSERVE_MS define missing -- child-survival observation window not named"
Add-Assertion "gmproxy.c: structured [GM-PROXY] LAUNCH: line present (app/pid/mode/session/srcpid/flag/env)" ($proxy -match '\[GM-PROXY\]\s*LAUNCH:\s*app=%ls\s+pid=%lu\s+mode=%ls\s+session=%lu\s+srcpid=%lu\s+flag=%ls\s+env=%ls') "gmproxy.c [GM-PROXY] LAUNCH: structured line missing -- Export-GodModeLogs cannot aggregate per-app launches"
Add-Assertion "gmproxy.c: structured [GM-PROXY] CHILD-STATUS: line present (result=ALIVE/EXITED)" ($proxy -match '\[GM-PROXY\]\s*CHILD-STATUS:\s*app=%ls\s+pid=%lu\s+result=' -and ($proxy -match 'result=ALIVE' -or $proxy -match 'result=EXITED')) "gmproxy.c [GM-PROXY] CHILD-STATUS: line missing -- child-survival (crash) signal not logged"
Add-Assertion "gmproxy.c: child-survival observation waits on the child handle (WaitForSingleObject)" ($proxy -match 'WaitForSingleObject\s*\(\s*ppi->hProcess\s*,\s*GM_CHILD_OBSERVE_MS\s*\)') "gmproxy.c does not WaitForSingleObject the child handle -- cannot tell ALIVE vs EXITED"
Add-Assertion "gmproxy.c: EXITED branch reads the child exit code (GetExitCodeProcess)" ($proxy -match 'WAIT_OBJECT_0[\s\S]{0,200}?GetExitCodeProcess') "gmproxy.c EXITED branch does not read the exit code -- crash signal lacks the code"
Add-Assertion "gmproxy.c: report called on success path with SYSTEM/FALLBACK mode" ($proxy -match 'haveToken\s*\?\s*L"SYSTEM"\s*:\s*L"FALLBACK"') "gmproxy.c does not call the report on the success path with the SYSTEM/FALLBACK mode"
Add-Assertion "gmproxy.c: report called on the REFUSE path (L\"REFUSE\", no child)" ($proxy -match 'GmProxyLogLaunchReport\s*\(\s*argv\[1\]\s*,\s*L"REFUSE"') "gmproxy.c does not call the report on the REFUSE path -- REFUSE launches would not be aggregated"
Add-Assertion "gmproxy.c: report called on the FAILED path (L\"FAILED\", no child)" ($proxy -match 'GmProxyLogLaunchReport\s*\(\s*argv\[1\]\s*,\s*L"FAILED"') "gmproxy.c does not call the report on the FAILED path -- failed launches would not be aggregated"
Add-Assertion "gmproxy.c: REFUSE/FAILED pass childOk=FALSE + ppi=NULL (no child to observe)" ($proxy -match 'L"REFUSE"[\s\S]{0,80}?FALSE\s*,\s*NULL' -and $proxy -match 'L"FAILED"[\s\S]{0,80}?FALSE\s*,\s*NULL') "gmproxy.c REFUSE/FAILED do not pass childOk=FALSE/NULL -- would attempt to observe a non-existent child"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs has GM-PROXY PER-APP LAUNCH REPORT section" ($gm -match 'GM-PROXY PER-APP LAUNCH REPORT') "Export-GodModeLogs does not have the PER-APP LAUNCH REPORT section"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs parses [GM-PROXY] LAUNCH: lines" ($gm -match 'Select-String[\s\S]{0,120}?GM-PROXY\\\] LAUNCH:') "Export-GodModeLogs does not parse [GM-PROXY] LAUNCH: lines for the per-app report"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs parses [GM-PROXY] CHILD-STATUS: lines" ($gm -match 'Select-String[\s\S]{0,120}?GM-PROXY\\\] CHILD-STATUS:') "Export-GodModeLogs does not parse [GM-PROXY] CHILD-STATUS: lines for the per-app report"
Add-Assertion "God-Mode-Windows.ps1: per-app report notes EXITED = crash signal (scope the exclusion)" ($gm -match 'EXITED = the child process exited within' -and $gm -match 'exclusion can be scoped') "per-app report does not explain EXITED = crash signal -- user would not know which apps to report"

# --- 21. gmproxy.c: grandchild-tree Job observation + elevation-context logging (root-cause debug) ---
# The child-survival observation (section 20) could not tell a launcher/stub that
# DELEGATED to a surviving grandchild (Desktop Firefox copy, Win11 notepad stub --
# the REAL app opened, NOT a failure) from a genuine EXIT with no descendant.
# gmproxy now creates the child CREATE_SUSPENDED, assigns it to a Job Object
# (JOB_OBJECT_LIMIT_BREAKAWAY_OK, no KILL_ON_JOB_CLOSE so the user's real app is
# never killed), resumes it, and walks the job tree after the wait: a child that
# exits cleanly with a surviving grandchild -> result=DELEGATED; otherwise
# result=EXITED class=CLEAN (exitcode 0, graceful refusal as SYSTEM) or class=CRASH
# (exitcode != 0). Elevation-context logging (ELEVATE/TOKEN/CMDLINE/ENV/TARGET +
# per-attempt CREATEPROC result=OK/FAIL gle) catches the ELEVATION-side root cause.
Add-Assertion "gmproxy.c: #include <sddl.h> present (ConvertSidToStringSidW for token SID logging)" ($proxy -match '#include\s+<sddl\.h>') "gmproxy.c missing #include <sddl.h> -- ConvertSidToStringSidW undeclared (token SID cannot be logged)"
Add-Assertion "gmproxy.c: GmProxyImageNameForPid helper defined (resolve a PID's image base name)" ($proxy -match 'static\s+BOOL\s+GmProxyImageNameForPid\s*\(') "GmProxyImageNameForPid helper missing -- cannot log which SYSTEM process donated the token / what a stub spawned"
Add-Assertion "gmproxy.c: GmProxyImageNameForPid loads QueryFullProcessImageNameW dynamically" ($proxy -match 'QueryFullProcessImageNameW_t' -and $proxy -match 'GetProcAddress\s*\(\s*hk\s*,\s*"QueryFullProcessImageNameW"') "GmProxyImageNameForPid does not dynamically load QueryFullProcessImageNameW -- build would gain a link dependency or fail on older headers"
Add-Assertion "gmproxy.c: GmProxyEnumerateJobTree helper defined (walk the job's process list)" ($proxy -match 'static\s+DWORD\s+GmProxyEnumerateJobTree\s*\(') "GmProxyEnumerateJobTree helper missing -- cannot count surviving grandchildren (DELEGATED vs EXITED)"
Add-Assertion "gmproxy.c: GmProxyEnumerateJobTree queries JobObjectBasicProcessIdList" ($proxy -match 'QueryInformationJobObject\s*\(\s*hJob\s*,\s*JobObjectBasicProcessIdList') "GmProxyEnumerateJobTree does not query JobObjectBasicProcessIdList -- cannot enumerate the child's process tree"
Add-Assertion "gmproxy.c: GmProxyEnumerateJobTree excludes the child pid from survivors (counts grandchildren only)" ($proxy -match 'pid\s*==\s*0\s*\|\|\s*pid\s*==\s*childPid') "GmProxyEnumerateJobTree does not exclude childPid -- after the child exits survivors would still count the dead child"
Add-Assertion "gmproxy.c: GmProxyLogElevationContext helper defined (token/cmdline/env context log)" ($proxy -match 'static\s+void\s+GmProxyLogElevationContext\s*\(') "GmProxyLogElevationContext helper missing -- elevation-side root cause (wrong token / missing env / bad cmdline) cannot be logged"
Add-Assertion "gmproxy.c: GmProxyLogElevationContext logs the token source identity (ELEVATE srckind/srcpid/srcsess/srcimg)" ($proxy -match '\[GM-PROXY\]\s*ELEVATE:\s*srckind=%ls\s+srcpid=%lu\s+srcsess=%lu\s+srcimg=%ls') "gmproxy.c ELEVATE context line missing -- cannot tell which SYSTEM process donated the token"
Add-Assertion "gmproxy.c: GmProxyLogElevationContext logs the token SID via ConvertSidToStringSidW (confirm S-1-5-18)" ($proxy -match 'ConvertSidToStringSidW' -and $proxy -match '\[GM-PROXY\]\s*TOKEN:\s*sid=%ls\s+type=%ls\s+elevated=%lu\s+tksess=%lu') "gmproxy.c TOKEN context line missing -- cannot confirm the stolen token is actually S-1-5-18 Local System"
Add-Assertion "gmproxy.c: GmProxyLogElevationContext logs the rebuilt command line (CMDLINE)" ($proxy -match '\[GM-PROXY\]\s*CMDLINE:\s*%ls') "gmproxy.c CMDLINE context line missing -- cannot diagnose a bad/injected command line"
Add-Assertion "gmproxy.c: GmProxyLogElevationContext logs the env-block state + byte size (ENV)" ($proxy -match '\[GM-PROXY\]\s*ENV:\s*block=%ls\s+bytes=%lu') "gmproxy.c ENV context line missing -- cannot diagnose a missing/empty env block"
Add-Assertion "gmproxy.c: child created CREATE_SUSPENDED so the job captures it before it runs" ($proxy -match 'CREATE_UNICODE_ENVIRONMENT\s*\|\s*CREATE_SUSPENDED' -and ($proxy -match 'cpwt[\s\S]{0,200}?CREATE_SUSPENDED' -or $proxy -match 'LOGON_WITH_PROFILE[\s\S]{0,120}?CREATE_SUSPENDED')) "gmproxy.c does not create the child CREATE_SUSPENDED -- a fast-spawning grandchild could escape the job tree before AssignProcessToJobObject"
Add-Assertion "gmproxy.c: CreateJobObjectW creates the observational job" ($proxy -match 'CreateJobObjectW\s*\(\s*NULL\s*,\s*NULL\s*\)') "gmproxy.c does not CreateJobObjectW -- no process tree to walk for DELEGATED detection"
Add-Assertion "gmproxy.c: job sets JOB_OBJECT_LIMIT_BREAKAWAY_OK (no breakaway failure)" ($proxy -match 'JOB_OBJECT_LIMIT_BREAKAWAY_OK') "gmproxy.c job does not set BREAKAWAY_OK -- a child spawning with CREATE_BREAKAWAY_FROM_JOB would fail to assign"
Add-Assertion "gmproxy.c: NO JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (never kill the user's real app)" ($proxy -notmatch 'JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE') "gmproxy.c job sets KILL_ON_JOB_CLOSE -- gmproxy exiting would KILL the user's real app (destructive)"
Add-Assertion "gmproxy.c: AssignProcessToJobObject assigns the suspended child to the job" ($proxy -match 'AssignProcessToJobObject\s*\(\s*hJob\s*,\s*pi\.hProcess\s*\)') "gmproxy.c does not AssignProcessToJobObject -- the child's tree is not captured"
Add-Assertion "gmproxy.c: ResumeThread resumes the suspended child after job assignment" ($proxy -match 'ResumeThread\s*\(\s*pi\.hThread\s*\)') "gmproxy.c does not ResumeThread -- the child would stay suspended forever (never runs)"
Add-Assertion "gmproxy.c: CREATEPROC outcome line logged per CreateProcess attempt (method + result=OK/FAIL)" ($proxy -match '\[GM-PROXY\]\s*CREATEPROC:\s*method=\w+\s+result=\w+' -and $proxy -match 'result=FAIL\s+gle=%lu') "gmproxy.c CREATEPROC outcome line missing -- cannot tell which launch method failed and why (gle)"
Add-Assertion "gmproxy.c: result=DELEGATED classification present (launcher/stub spawned a surviving grandchild)" ($proxy -match 'result=DELEGATED\s+exitcode=%lu\s+treepids=%lu\s+firstgchild=%ls') "gmproxy.c DELEGATED classification missing -- a launcher/stub that delegated to the real app would be misreported as a crash"
Add-Assertion "gmproxy.c: EXITED classification includes class=CLEAN (exitcode 0, graceful) / class=CRASH (non-zero)" ($proxy -match 'class=%ls' -and $proxy -match 'L"CLEAN"' -and $proxy -match 'L"CRASH"') "gmproxy.c EXITED classification lacks the CLEAN/CRASH class -- a graceful exit (0) cannot be told from a crash (non-zero)"
Add-Assertion "gmproxy.c: hJob passed to GmProxyLogLaunchReport on the success path (transferred ownership)" ($proxy.Contains('GmProxyLogLaunchReport(argv[1], launchMode') -and $proxy.Contains('activeSession, hJob)')) "gmproxy.c does not pass hJob to the launch report on the success path -- grandchild tree cannot be walked"
Add-Assertion "gmproxy.c: REFUSE/FAILED paths pass hJob=NULL (no child to observe, no job to close)" ($proxy -match 'L"REFUSE"[\s\S]{0,120}?activeSession\s*,\s*NULL\s*\)' -and $proxy -match 'L"FAILED"[\s\S]{0,120}?activeSession\s*,\s*NULL\s*\)') "gmproxy.c REFUSE/FAILED do not pass hJob=NULL -- would close a garbage handle or observe a non-existent child"
Add-Assertion "gmproxy.c: job handle closed exactly once in GmProxyLogLaunchReport (no double-close / leak)" ($proxy -match 'if\s*\(\s*hJob\s*\)\s*CloseHandle\s*\(\s*hJob\s*\)') "gmproxy.c does not close hJob exactly once in the launch report -- handle leak or double-close"
Add-Assertion "God-Mode-Windows.ps1: per-app report has a DELEGATED column" ($gm -match 'DELEGATED=0' -and $gm -match 'DELEGATED  EXITED\(crash\?\)') "Export-GodModeLogs per-app report does not have a DELEGATED column -- delegation would be invisible"
Add-Assertion "God-Mode-Windows.ps1: per-app report has an ELEVATION FAULTS section (root-cause)" ($gm -match 'ELEVATION FAULTS \(root-cause\)') "Export-GodModeLogs does not have an ELEVATION FAULTS section -- elevation-side root cause not surfaced"
Add-Assertion "God-Mode-Windows.ps1: ELEVATION FAULTS parses CREATEPROC result=FAIL lines" ($gm -match 'CREATEPROC:\s*\.\*result=FAIL') "Export-GodModeLogs ELEVATION FAULTS does not parse CREATEPROC result=FAIL lines -- failed CreateProcess attempts not surfaced"
Add-Assertion "God-Mode-Windows.ps1: ELEVATION FAULTS parses ELEVATE srckind=none (no SYSTEM token)" ($gm -match 'ELEVATE:\s*srckind=none') "Export-GodModeLogs ELEVATION FAULTS does not parse the no-token ELEVATE line -- a missing SYSTEM token would not be flagged"

# --- 22. gmproxy.c: IFEO re-entry recur tag + Export-GodModeLogs SYSTEM-temp collection (root-cause) ---
# Live VM data (option [11] dump) revealed two observation blind spots, NOT elevation
# faults (every CreateProcess succeeded, S-1-5-18 from winlogon, session 1, ELEVATION
# FAULTS: none):
#   (a) Desktop Firefox copy -> DELEGATED firstgchild=gmproxy.exe. The stub spawned
#       the real firefox.exe (IFEO-hooked) -> Windows birthed a NESTED gmproxy.exe as
#       the grandchild (IFEO re-entry), NOT the real app. That nested gmproxy runs as
#       SYSTEM -> its %TEMP% is the SYSTEM temp (C:\Windows\Temp or systemprofile),
#       NOT the admin user's $env:TEMP -> option [11] never collected it -> the stub's
#       DELEGATED verdict was inconclusive (the real app's fate lived in an unread log).
#   (b) C:\Windows\notepad.exe -> EXITED class=CLEAN tree=0. Win11's notepad.exe is a
#       stub to the WinUI Notepad; the real app likely broke away / activated out-of-
#       tree -> escaped the job -> tree=0 -> misclassified CLEAN (could be delegation,
#       not a graceful refusal).
# Fixes: gmproxy tags the DELEGATED survivor with recur=yes (gmproxy.exe itself = IFEO
# re-entry) / recur=no (the real app = genuine delegation); Export-GodModeLogs collects
# the SYSTEM-temp gmproxy.log candidates so the nested gmproxy's CHILD-STATUS is
# aggregated into the per-app report; a DELEGATED-RECUR column + a CAVEAT note on
# EXITED class=CLEAN tree=0 surface both blind spots so the user no longer mistakes
# re-entry for "real app opened" or breakaway for "graceful refusal".
Add-Assertion "gmproxy.c: DELEGATED CHILD-STATUS line carries recur=%ls (yes/no)" ($proxy -match 'result=DELEGATED\s+exitcode=%lu\s+treepids=%lu\s+firstgchild=%ls\s+gchildpid=%lu\s+recur=%ls') "gmproxy.c DELEGATED line lacks recur=%ls -- IFEO re-entry cannot be told from genuine delegation"
Add-Assertion "gmproxy.c: recur detects the survivor is gmproxy.exe (_wcsicmp firstImg)" ($proxy -match 'BOOL\s+recur\s*=\s*\(\s*_wcsicmp\s*\(\s*firstImg\s*,\s*L"gmproxy\.exe"\s*\)\s*==\s*0\s*\)') "gmproxy.c recur detection missing -- a gmproxy.exe grandchild (IFEO re-entry) would be misreported as the real app"
Add-Assertion "gmproxy.c: recur emits yes/no (not a numeric)" ($proxy -match 'recur\s*\?\s*L"yes"\s*:\s*L"no"') "gmproxy.c recur emits something other than yes/no -- the report cannot distinguish re-entry"
Add-Assertion "gmproxy.c: existing DELEGATED regex substring preserved (result=DELEGATED ... firstgchild=%ls ... gchildpid=%lu)" ($proxy -match 'result=DELEGATED\s+exitcode=%lu\s+treepids=%lu\s+firstgchild=%ls\s+gchildpid=%lu') "gmproxy.c DELEGATED substring changed -- section-21 L396 assertion may regress"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs defines SYSTEM-temp gmproxy.log candidates" ($gm -match "GmProxySystemDiagCandidates") "Export-GodModeLogs does not define SYSTEM-temp gmproxy.log candidates -- nested SYSTEM gmproxy logs are never collected"
Add-Assertion "God-Mode-Windows.ps1: SYSTEM-temp candidates include C:\\Windows\\Temp\\gmproxy.log" ($gm -match 'C:\\Windows\\Temp\\gmproxy\.log') "Export-GodModeLogs does not collect C:\Windows\Temp\gmproxy.log -- the primary SYSTEM-temp log is missed"
Add-Assertion "God-Mode-Windows.ps1: SYSTEM-temp candidates include the systemprofile temp gmproxy.log" ($gm -match 'System32\\config\\systemprofile\\AppData\\Local\\Temp\\gmproxy\.log') "Export-GodModeLogs does not collect the systemprofile-temp gmproxy.log -- a nested SYSTEM gmproxy spawned under the SYSTEM profile would log here and be missed"
Add-Assertion "God-Mode-Windows.ps1: GmProxyDiagPaths aggregates admin-temp + SYSTEM-temp logs" ($gm -match 'GmProxyDiagPaths') "Export-GodModeLogs does not aggregate admin-temp + SYSTEM-temp into GmProxyDiagPaths -- the nested gmproxy's lines are never scanned"
Add-Assertion "God-Mode-Windows.ps1: GmProxyDiagPaths starts empty + appends existing admin-temp log" ($gm -match '\$GmProxyDiagPaths\s*=\s*@\(\)') "Export-GodModeLogs GmProxyDiagPaths is not initialized empty -- a stale or null array could corrupt the report"
Add-Assertion "God-Mode-Windows.ps1: GmProxyDiagPaths appends existing SYSTEM-temp candidates (Test-Path guarded)" ($gm -match 'foreach\s*\(\$p\s+in\s*\$GmProxySystemDiagCandidates\)\s*\{\s*if\s*\(\s*Test-Path\s+\$p\s*\)\s*\{\s*\$GmProxyDiagPaths\s*\+=\s*\$p') "Export-GodModeLogs does not append existing SYSTEM-temp candidates to GmProxyDiagPaths -- missing paths would be scanned (error) or existing paths skipped"
Add-Assertion "God-Mode-Windows.ps1: GM-PROXY BUILD extraction scans GmProxyDiagPaths (not just admin-temp)" ($gm -match 'Select-String\s*-Path\s+\$GmProxyDiagPaths[\s\S]{0,80}?\\\[GM-PROXY\\\]\s+BUILD') "Export-GodModeLogs GM-PROXY BUILD extraction does not scan GmProxyDiagPaths -- a nested SYSTEM gmproxy's newer BUILD stamp (different binary/deploy) would be invisible"
Add-Assertion "God-Mode-Windows.ps1: DIAGNOSTIC LOG dumps each SYSTEM-temp candidate under its own source header" ($gm -match 'foreach\s*\(\$p\s+in\s*\$GmProxySystemDiagCandidates\)[\s\S]{0,160}?Source:\s*\$p') "Export-GodModeLogs does not dump SYSTEM-temp candidates under per-source headers -- nested gmproxy BUILD/ELEVATE/CHILD-STATUS lines would not be visible"
Add-Assertion "God-Mode-Windows.ps1: PER-APP report scans GmProxyDiagPaths (nested gmproxy lines aggregated)" ($gm -match 'Select-String\s*-Path\s*\$GmProxyDiagPaths[\s\S]{0,80}?LAUNCH:') "Export-GodModeLogs PER-APP report does not scan GmProxyDiagPaths -- the nested gmproxy's LAUNCH lines are not aggregated"
Add-Assertion "God-Mode-Windows.ps1: per-app report hashtable has a DELEGATEDRECUR key" ($gm -match 'DELEGATED=0;\s*DELEGATEDRECUR=0') "Export-GodModeLogs per-app hashtable lacks the DELEGATEDRECUR key -- recur=yes launches cannot be counted"
Add-Assertion "God-Mode-Windows.ps1: per-app report routes recur=yes to DELEGATEDRECUR (not DELEGATED)" ($gm -match '\$res\s+-eq\s*''DELEGATED''\s*-and\s*\$isRecur') "Export-GodModeLogs does not route recur=yes to DELEGATEDRECUR -- IFEO re-entry would inflate the genuine-DELEGATED count"
Add-Assertion "God-Mode-Windows.ps1: per-app report reads recur=yes from the CHILD-STATUS line" ($gm -match '\$isRecur\s*=\s*\$c\.Line\s*-match\s*''recur=yes''') "Export-GodModeLogs does not read recur=yes from the CHILD-STATUS line -- re-entry cannot be detected"
Add-Assertion "God-Mode-Windows.ps1: per-app report table has a DELEGATED-RECUR column (header)" ($gm -match 'DELEGATED\s+EXITED\(crash\?\)\s+DELEGATED-RECUR') "Export-GodModeLogs per-app table lacks the DELEGATED-RECUR column header -- re-entry count not shown"
Add-Assertion "God-Mode-Windows.ps1: per-app report row formats the DELEGATEDRECUR field" ($gm -match '\$r\.DELEGATEDRECUR') "Export-GodModeLogs per-app row does not format \$r.DELEGATEDRECUR -- the column would be blank"
Add-Assertion "God-Mode-Windows.ps1: per-app report NOTE explains DELEGATED-RECUR = nested gmproxy (IFEO re-entry)" ($gm -match 'DELEGATED-RECUR\s*\(recur=yes\)\s*=\s*the\s+surviving\s+grandchild\s+is\s+gmproxy\.exe' -and $gm -match 'NESTED\s+gmproxy\s+as\s+the\s+grandchild') "Export-GodModeLogs NOTE does not explain DELEGATED-RECUR = nested gmproxy (IFEO re-entry) -- user would not know recur=yes means inconclusive, not success"
Add-Assertion "God-Mode-Windows.ps1: per-app report NOTE has the EXITED class=CLEAN tree=0 breakaway CAVEAT" ($gm -match 'CAVEAT:\s*EXITED\s+class=CLEAN\s+tree=0' -and $gm -match 'breakaway') "Export-GodModeLogs NOTE lacks the EXITED class=CLEAN tree=0 breakaway CAVEAT -- a stub that delegated out-of-tree would be mistaken for a graceful refusal"
Add-Assertion "God-Mode-Windows.ps1: ELEVATION FAULTS scans GmProxyDiagPaths (nested gmproxy faults surfaced)" ($gm -match 'Select-String\s*-Path\s+\$GmProxyDiagPaths[\s\S]{0,80}?CREATEPROC:\s*\.\*result=FAIL') "Export-GodModeLogs ELEVATION FAULTS does not scan GmProxyDiagPaths -- a nested SYSTEM gmproxy's CREATEPROC FAIL would be missed"
Add-Assertion "God-Mode-Windows.ps1: missing-log else branch lists the SYSTEM-temp candidates checked" ($gm -match 'No gmproxy log found.*SYSTEM-temp') "Export-GodModeLogs missing-log branch does not list the SYSTEM-temp candidates -- the user would not know which paths were checked"
# Regression guard: the kept substrings from section 20 MUST still be present (additive edit).
Add-Assertion "God-Mode-Windows.ps1: NOTE keeps 'EXITED = the child process exited within' (additive edit guard)" ($gm -match 'EXITED = the child process exited within') "Export-GodModeLogs NOTE lost 'EXITED = the child process exited within' -- additive edit regressed section 20"
Add-Assertion "God-Mode-Windows.ps1: NOTE keeps 'exclusion can be scoped' (additive edit guard)" ($gm -match 'exclusion can be scoped') "Export-GodModeLogs NOTE lost 'exclusion can be scoped' -- additive edit regressed section 20"
Add-Assertion "God-Mode-Windows.ps1: table header keeps 'DELEGATED  EXITED(crash?)' (additive edit guard)" ($gm -match 'DELEGATED  EXITED\(crash\?\)') "Export-GodModeLogs table header lost 'DELEGATED  EXITED(crash?)' -- additive edit regressed section 21"

# --- 23. gmproxy.c: cross-process gmproxy.log write serialization (concurrent-write corruption fix) ---
# Live VM data (option [11] dump) revealed the SYSTEM-temp gmproxy.log was CORRUPTED with partial
# lines ('dater.exe' / 'YSTEM session=...' / a lone 'system') whenever GoogleUpdater spawned many
# updater.exe CONCURRENTLY as SYSTEM -- every nested gmproxy wrote the SAME log via _wfopen append
# + vfwprintf + fflush, and the C runtime append mode is seek-then-write, so the seeks raced across
# processes and overwrote each other mid-line. Fix: a Global named mutex (NULL DACL so the admin
# user-session gmproxy AND the SYSTEM nested gmproxy can both open it -- a default-DACL mutex created
# by one privilege level can deny the other, which would leave the SYSTEM-temp log un-serialized) is
# acquired in DiagLog around GmProxyDiagLogOpen+vfwprintf+fflush and released after, so every line
# lands atomically at the true end-of-file. Bounded 2000ms wait so a stuck holder never stalls a
# launch; WAIT_ABANDONED (crashed holder) is tolerated (best-effort log). stderr is per-process and
# stays outside the mutex; the mutex is never held across the ~1.5s child observation wait. Mirrors
# gmhook.c's GodMode_GmHookLog try-lock but adds the NULL DACL + Global namespace for the cross-
# privilege gmproxy case.
Add-Assertion "gmproxy.c: g_GmProxyDiagMutex handle global present (cross-process log serializer)" ($proxy -match 'g_GmProxyDiagMutex') "gmproxy.c g_GmProxyDiagMutex missing -- concurrent gmproxy.log writes are not serialized"
Add-Assertion "gmproxy.c: GmProxyDiagMutexAcquire helper defined" ($proxy -match 'static HANDLE GmProxyDiagMutexAcquire') "gmproxy.c GmProxyDiagMutexAcquire missing -- cannot take the log mutex"
Add-Assertion "gmproxy.c: GmProxyDiagMutexRelease helper defined" ($proxy -match 'static void GmProxyDiagMutexRelease') "gmproxy.c GmProxyDiagMutexRelease missing -- cannot release the log mutex"
Add-Assertion "gmproxy.c: Global named mutex GmProxyDiagLogMutex (shared admin + SYSTEM)" ($proxy -match 'GmProxyDiagLogMutex' -and $proxy -match 'Global named mutex') "gmproxy.c Global GmProxyDiagLogMutex missing -- admin + SYSTEM gmproxy would not share one mutex"
Add-Assertion "gmproxy.c: NULL DACL via SetSecurityDescriptorDacl + InitializeSecurityDescriptor (admin + SYSTEM both open)" ($proxy -match 'SetSecurityDescriptorDacl' -and $proxy -match 'InitializeSecurityDescriptor') "gmproxy.c NULL DACL missing -- a default-DACL mutex could deny the other privilege level (SYSTEM-temp log un-serialized)"
Add-Assertion "gmproxy.c: bounded wait GM_DIAG_LOG_MUTEX_TIMEOUT_MS (never stall a launch)" ($proxy -match 'GM_DIAG_LOG_MUTEX_TIMEOUT_MS') "gmproxy.c GM_DIAG_LOG_MUTEX_TIMEOUT_MS missing -- a stuck mutex holder could stall the launch path"
Add-Assertion "gmproxy.c: DiagLog acquires the mutex around the file write (hMutex = GmProxyDiagMutexAcquire)" ($proxy -match 'hMutex = GmProxyDiagMutexAcquire') "gmproxy.c DiagLog does not acquire the mutex -- concurrent writes still race"
Add-Assertion "gmproxy.c: DiagLog releases the mutex only when acquired (if hMutex GmProxyDiagMutexRelease)" ($proxy -match 'if \(hMutex\) GmProxyDiagMutexRelease') "gmproxy.c DiagLog does not guard the release on hMutex -- would release an un-acquired mutex (handle leak / error)"
Add-Assertion "gmproxy.c: WAIT_ABANDONED tolerated (crashed holder does not block logging)" ($proxy -match 'WAIT_ABANDONED') "gmproxy.c WAIT_ABANDONED not handled -- a crashed gmproxy holding the mutex would block all other instances's logging"
Add-Assertion "gmproxy.c: default-DACL fallback CreateMutexW (security-API failure never blocks logging)" ($proxy -match 'Fall back to default-DACL') "gmproxy.c default-DACL fallback missing -- an InitializeSecurityDescriptor/SetSecurityDescriptorDacl failure would leave no mutex at all"


# --- 24. Smart IFEO compatibility layer: Detector A (AppX/browser drop) + Detector B (runtime SYSTEM-crash auto-exclude) ---
# Live VM data showed three apps die when IFEO-elevated to SYSTEM: Chrome crashes
# (0xFFFF7001), Firefox renders blank (content sandbox breaks under a SYSTEM parent),
# Win11 Notepad exits CLEAN with no window (WinUI stub cannot init under SYSTEM). Fix =
# two DYNAMIC detectors, NO hardcoded app names:
#   A (God-Mode-Windows.ps1, install-time): Get-GmSystemCompatExclusions builds the AppX
#     set (WindowsApps reparse aliases + Get-AppxPackage Executables) + the registered-
#     browser set (StartMenuInternet); Install-IfeoElevation + Get-IfeoElevationCandidates
#     DROP matching seed+auto entries so they launch as the user, not via gmproxy->SYSTEM.
#   B (gmproxy.c, launch-time): a persistent crash store records every base name that
#     CRASHED as SYSTEM (EXITED class=CRASH tree=0, SYSTEM mode); at >= threshold crashes
#     the NEXT launch skips the SYSTEM token -> current-user fallback (USER-AUTOEXCLUDE).
#     Fail-open everywhere; Session-0 REFUSE still honored; CRASH-only (CLEAN tree=0 is
#     ambiguous breakaway); 256-cap + 30-day stale; atomic temp+rename; Global NULL-DACL
#     mutex; reset via menu [18] / gmproxy.exe --gm-reset-autoexclude.
Add-Assertion "gmproxy.c: #include <time.h> present (auto-exclude timestamps)" ($proxy.Contains('#include <time.h>')) "gmproxy.c missing #include <time.h>"
Add-Assertion "gmproxy.c: #include <stdlib.h> present (store line parsing)" ($proxy.Contains('#include <stdlib.h>')) "gmproxy.c missing #include <stdlib.h>"
Add-Assertion "gmproxy.c: GM_AUTOEXCLUDE_THRESHOLD constant present" ($proxy.Contains('GM_AUTOEXCLUDE_THRESHOLD')) "GM_AUTOEXCLUDE_THRESHOLD missing"
Add-Assertion "gmproxy.c: GM_AUTOEXCLUDE_STALE_DAYS constant present (30-day reset)" ($proxy.Contains('GM_AUTOEXCLUDE_STALE_DAYS')) "GM_AUTOEXCLUDE_STALE_DAYS missing"
Add-Assertion "gmproxy.c: GM_AUTOEXCLUDE_MAX_ENTRIES constant present (256 cap)" ($proxy.Contains('GM_AUTOEXCLUDE_MAX_ENTRIES')) "GM_AUTOEXCLUDE_MAX_ENTRIES missing"
Add-Assertion "gmproxy.c: GM_AUTOEXCLUDE_MUTEX_TIMEOUT_MS constant present (bounded wait)" ($proxy.Contains('GM_AUTOEXCLUDE_MUTEX_TIMEOUT_MS')) "GM_AUTOEXCLUDE_MUTEX_TIMEOUT_MS missing"
Add-Assertion "gmproxy.c: GmAutoExcludeEntry struct present" ($proxy.Contains('GmAutoExcludeEntry')) "GmAutoExcludeEntry struct missing"
Add-Assertion "gmproxy.c: g_GmProxyAutoExcludeMutex handle global present" ($proxy.Contains('g_GmProxyAutoExcludeMutex')) "g_GmProxyAutoExcludeMutex missing"
Add-Assertion "gmproxy.c: GmProxyAutoExcludeMutexAcquire helper defined" ($proxy.Contains('GmProxyAutoExcludeMutexAcquire')) "GmProxyAutoExcludeMutexAcquire missing"
Add-Assertion "gmproxy.c: GmProxyAutoExcludeMutexRelease helper defined" ($proxy.Contains('GmProxyAutoExcludeMutexRelease')) "GmProxyAutoExcludeMutexRelease missing"
Add-Assertion "gmproxy.c: Global GmProxyAutoExcludeMutex name present (cross-privilege)" ($proxy.Contains('GmProxyAutoExcludeMutex')) "GmProxyAutoExcludeMutex name missing"
Add-Assertion "gmproxy.c: GmProxyAutoExcludeLoad helper defined (parse + prune)" ($proxy.Contains('GmProxyAutoExcludeLoad')) "GmProxyAutoExcludeLoad missing"
Add-Assertion "gmproxy.c: GmProxyAutoExcludeQuery helper defined (excluded lookup)" ($proxy.Contains('GmProxyAutoExcludeQuery')) "GmProxyAutoExcludeQuery missing"
Add-Assertion "gmproxy.c: GmProxyAutoExcludeRecord helper defined (increment + threshold)" ($proxy.Contains('GmProxyAutoExcludeRecord')) "GmProxyAutoExcludeRecord missing"
Add-Assertion "gmproxy.c: GmProxyAutoExcludeReset helper defined (delete store)" ($proxy.Contains('GmProxyAutoExcludeReset')) "GmProxyAutoExcludeReset missing"
Add-Assertion "gmproxy.c: GmProxyAutoExcludeWrite helper defined (atomic write)" ($proxy.Contains('GmProxyAutoExcludeWrite')) "GmProxyAutoExcludeWrite missing"
Add-Assertion "gmproxy.c: GmProxyAutoExcludeParseLine helper defined (manual line parse)" ($proxy.Contains('GmProxyAutoExcludeParseLine')) "GmProxyAutoExcludeParseLine missing"
Add-Assertion "gmproxy.c: store path GodModeAutoExclude/gmproxy_autoexclude.dat present" ($proxy.Contains('GodModeAutoExclude') -and $proxy.Contains('gmproxy_autoexclude.dat')) "auto-exclude store path missing"
Add-Assertion "gmproxy.c: NULL DACL via SetSecurityDescriptorDacl (admin + SYSTEM both open)" ($proxy.Contains('SetSecurityDescriptorDacl')) "auto-exclude NULL DACL missing"
Add-Assertion "gmproxy.c: atomic store write via MoveFileExW + MOVEFILE_REPLACE_EXISTING" ($proxy.Contains('MoveFileExW') -and $proxy.Contains('MOVEFILE_REPLACE_EXISTING')) "atomic MoveFileExW/REPLACE_EXISTING missing"
Add-Assertion "gmproxy.c: stale entries dropped on read (STALE_DAYS * 86400)" ($proxy.Contains('GM_AUTOEXCLUDE_STALE_DAYS * 86400')) "stale-drop math missing"
Add-Assertion "gmproxy.c: 256-cap eviction (n >= MAX_ENTRIES)" ($proxy.Contains('n >= GM_AUTOEXCLUDE_MAX_ENTRIES')) "cap eviction missing"
Add-Assertion "gmproxy.c: wmain queries the store before token acquisition" ($proxy.Contains('GmProxyAutoExcludeQuery(targetBase)')) "wmain does not query the store before acquiring a SYSTEM token"
Add-Assertion "gmproxy.c: autoExcluded gates SYSTEM token acquisition" ($proxy.Contains('autoExcluded ? 0 : FindSystemProcessForToken')) "autoExcluded does not gate SYSTEM token acquisition"
Add-Assertion "gmproxy.c: autoExcluded gates the SeTcb relocation path" ($proxy.Contains('!autoExcluded && !hPrimary')) "autoExcluded does not gate the relocation path"
Add-Assertion "gmproxy.c: USER-AUTOEXCLUDE launch mode emitted" ($proxy.Contains('USER-AUTOEXCLUDE')) "USER-AUTOEXCLUDE mode missing"
Add-Assertion "gmproxy.c: AUTO-EXCLUDE diag line emitted (explains the de-elevation)" ($proxy.Contains('[GM-PROXY] AUTO-EXCLUDE:')) "AUTO-EXCLUDE diag line missing"
Add-Assertion "gmproxy.c: GmProxyIsGuiSubsystem helper present (PE subsystem gate for CLEAN-GUI recording)" ($proxy.Contains('GmProxyIsGuiSubsystem')) "GmProxyIsGuiSubsystem missing -- CLEAN-GUI refusals cannot be recorded (notepad would never auto-exclude)"
Add-Assertion "gmproxy.c: IMAGE_SUBSYSTEM_WINDOWS_GUI constant present (GUI subsystem check)" ($proxy.Contains('IMAGE_SUBSYSTEM_WINDOWS_GUI')) "IMAGE_SUBSYSTEM_WINDOWS_GUI missing -- the PE-subsystem gate has no target value"
Add-Assertion "gmproxy.c: IMAGE_FILE_HEADER read before OptionalHeader (PE parse correctness)" ($proxy.Contains('IMAGE_FILE_HEADER') -and $proxy.Contains('IMAGE_NT_SIGNATURE')) "IMAGE_FILE_HEADER read missing -- OptionalHeader.Subsystem would read from the wrong offset (FileHeader not skipped)"
Add-Assertion "gmproxy.c: widened record guard records CRASH AND CLEAN-GUI refusals (code != 0 || (code == 0 && GmProxyIsGuiSubsystem))" ($proxy.Contains('code != 0') -and $proxy.Contains('GmProxyIsGuiSubsystem(targetPath)') -and $proxy.Contains('_wcsicmp(mode, L"SYSTEM")')) "widened record guard missing -- CLEAN-GUI refusals (notepad) would never be recorded"
Add-Assertion "gmproxy.c: A3 -- SignalGmProxyFeedback gated on !autoExcluded (no re-elevation of auto-excluded PIDs)" ($proxy.Contains('if (!autoExcluded)') -and $proxy.Contains('SignalGmProxyFeedback')) "A3 missing -- auto-excluded PIDs would be handed back to the monitor for SYSTEM re-elevation (defeats the auto-exclude)"
Add-Assertion "gmproxy.c: A3 -- auto-excluded feedback skip diag line present" ($proxy.Contains('skipping monitor feedback handoff')) "A3 skip diag missing -- cannot tell from the log that the feedback was intentionally skipped"
Add-Assertion "gmproxy.c: --gm-reset-autoexclude CLI hook present (mutex-safe reset)" ($proxy.Contains('--gm-reset-autoexclude')) "gmproxy --gm-reset-autoexclude hook missing"
Add-Assertion "gmproxy.c: Session-0 REFUSE guard still present (auto-exclude does not bypass it)" ($proxy.Contains('mySessionIsZero')) "mySessionIsZero guard missing -- auto-exclude could bypass Session-0 REFUSE"
Add-Assertion "God-Mode-Windows.ps1: Get-GmSystemCompatExclusions helper defined (Detector A)" ($gm.Contains('function Get-GmSystemCompatExclusions')) "Get-GmSystemCompatExclusions missing"
Add-Assertion "God-Mode-Windows.ps1: Detector A scans WindowsApps reparse aliases (AppX)" ($gm.Contains('WindowsApps') -and $gm.Contains('ReparsePoint')) "WindowsApps reparse-point AppX detection missing"
Add-Assertion "God-Mode-Windows.ps1: Detector A scans Get-AppxPackage Executable attributes" ($gm.Contains('Get-AppxPackage') -and $gm.Contains('Executable="')) "Get-AppxPackage Executable detection missing"
Add-Assertion "God-Mode-Windows.ps1: Detector A scans StartMenuInternet registered browsers" ($gm.Contains('StartMenuInternet')) "StartMenuInternet browser detection missing"
Add-Assertion "God-Mode-Windows.ps1: Get-IfeoElevationCandidates takes a CompatExclusions param" ($gm.Contains('$CompatExclusions')) "Get-IfeoElevationCandidates missing the CompatExclusions param"
Add-Assertion "God-Mode-Windows.ps1: candidates filter drops BROWSERS + AppX (CompatExclusions.AppX.ContainsKey)" ($gm.Contains('CompatExclusions.Browser.ContainsKey') -and $gm.Contains('CompatExclusions.AppX.ContainsKey($baseKey)')) "candidates filter does not drop AppX -- AppX/Store stubs must be dropped (cannot run as SYSTEM + gmproxy rename breaks their Store redirect)"
Add-Assertion "God-Mode-Windows.ps1: Install-IfeoElevation builds CompatExclusions once" ($gm.Contains('Get-GmSystemCompatExclusions')) "Install-IfeoElevation does not build CompatExclusions"
Add-Assertion "God-Mode-Windows.ps1: seed filtered through CompatExclusions (filteredSeed present)" ($gm.Contains('filteredSeed')) "seed compat filtering missing"
Add-Assertion "God-Mode-Windows.ps1: IFEO log reports Detector A browser drops (droppedBrowser=$seedDroppedBrowser)" ($gm.Contains('droppedBrowser=$seedDroppedBrowser')) "IFEO log line does not report Detector A browser drops"
Add-Assertion "God-Mode-Windows.ps1: seed filtered for browsers + AppX (filteredSeed + droppedBrowserNames + droppedAppxNames + seedDroppedAppx)" ($gm.Contains('filteredSeed') -and $gm.Contains('droppedBrowserNames') -and $gm.Contains('droppedAppxNames') -and $gm.Contains('seedDroppedAppx')) "seed compat filtering missing or does not drop AppX (AppX/Store stubs must be dropped from the seed)"
Add-Assertion "God-Mode-Windows.ps1: Test-GmAutoExcluded helper defined (monitor store consult)" ($gm.Contains('function Test-GmAutoExcluded')) "Test-GmAutoExcluded missing -- monitor cannot consult the auto-exclude store"
Add-Assertion "God-Mode-Windows.ps1: Add-GmAutoExcludeEntries helper defined (Detector A browser persist)" ($gm.Contains('function Add-GmAutoExcludeEntries')) "Add-GmAutoExcludeEntries missing -- Detector A cannot persist browser names to the store"
Add-Assertion "God-Mode-Windows.ps1: Add-GmAutoExcludeEntries opens Global\GmProxyAutoExcludeMutex (same as gmproxy.c)" ($gm.Contains('GmProxyAutoExcludeMutex') -and $gm.Contains('OpenExisting')) "Add-GmAutoExcludeEntries does not open the cross-privilege mutex -- could race a concurrent gmproxy"
Add-Assertion "God-Mode-Windows.ps1: Add-GmAutoExcludeEntries atomic write (temp + Move-Item -Force)" ($gm.Contains('Move-Item') -and $gm.Contains('GodModeAutoExcludeFile.tmp')) "Add-GmAutoExcludeEntries missing atomic write -- a mid-write crash could corrupt the store"
Add-Assertion "God-Mode-Windows.ps1: Install-IfeoElevation calls Add-GmAutoExcludeEntries with dropped browser names" ($gm.Contains('Add-GmAutoExcludeEntries -BaseNames $droppedBrowserNames')) "Install-IfeoElevation does not persist browser names to the store -- browsers not excluded from launch #1"
Add-Assertion "God-Mode-Windows.ps1: Monitor-ElevateProcess consults Test-GmAutoExcluded (skip elevation)" ($gm.Contains('Test-GmAutoExcluded "$procName.exe"')) "Monitor-ElevateProcess does not consult the store -- would re-elevate auto-excluded apps"
Add-Assertion "God-Mode-Windows.ps1: Invoke-GmProxyFeedbackElevation consults Test-GmAutoExcluded (defense-in-depth)" ($gm.Contains('Test-GmAutoExcluded "$($proc.Name).exe"')) "Invoke-GmProxyFeedbackElevation does not consult the store -- A3 bypass possible"
Add-Assertion "God-Mode-Windows.ps1: periodic scan consults Test-GmAutoExcluded (skip auto-excluded)" ($gm.Contains('Test-GmAutoExcluded $procName')) "periodic scan does not consult the store -- would re-elevate auto-excluded apps every 15s"
Add-Assertion "God-Mode-Windows.ps1: Invoke-ExistingProcessElevation dedup consults Test-GmAutoExcluded" ($gm.Contains('Test-GmAutoExcluded "$procName.exe"') -and $gm.Contains('GetFileNameWithoutExtension($proc.ExecutablePath)')) "startup scan does not consult the store -- would force-elevate auto-excluded apps"
Add-Assertion "God-Mode-Windows.ps1: Detector A broadened -- Get-AppxPackage -AllUsers (system-provisioned AppX)" ($gm.Contains('Get-AppxPackage -AllUsers')) "Get-AppxPackage -AllUsers missing -- system-provisioned AppX (Store Notepad) still missed"
Add-Assertion "God-Mode-Windows.ps1: Detector A broadened -- all-profiles WindowsApps scan (C:\Users + WindowsApps)" ($gm.Contains('C:\Users') -and $gm.Contains('WindowsApps') -and $gm.Contains('AppData\Local\Microsoft\WindowsApps')) "all-profiles WindowsApps scan missing -- per-user scan only catches the current user's aliases"
Add-Assertion "God-Mode-Windows.ps1: candidate filter drops BROWSERS + AppX (CompatExclusions.AppX.ContainsKey)" ($gm.Contains('CompatExclusions.Browser.ContainsKey') -and $gm.Contains('CompatExclusions.AppX.ContainsKey($baseKey)')) "candidate filter does not drop AppX -- AppX/Store stubs must be dropped"
Add-Assertion "gmhook.c: GmHookIsAutoExcluded helper present (store consult before SYSTEM birth)" ($gmhook.Contains('GmHookIsAutoExcluded')) "gmhook.c GmHookIsAutoExcluded missing -- gmhook cannot consult the store before birthing a child as SYSTEM"
Add-Assertion "gmhook.c: GmHookIsAutoExcluded 2s TTL cache (GetTickCount64)" ($gmhook.Contains('GetTickCount64') -and $gmhook.Contains('GMHOOK_AUTOEXCLUDE_CACHE_TTL_MS')) "gmhook.c cache TTL missing -- CreateProcess hot path would read the store file every call"
Add-Assertion "gmhook.c: HookCreateProcessW consults GmHookIsAutoExcluded before SYSTEM birth" ($gmhook.Contains('GmHookIsAutoExcluded(baseName)')) "gmhook.c HookCreateProcessW does not consult the store -- excluded apps still born as SYSTEM from hooked hosts"
Add-Assertion "God-Mode-Windows.ps1: Uninstall-ProcessHook removes GodModeAutoExclude dir (uninstaller current)" ($gm.Contains('Remove-Item -Path $GodModeAutoExcludeDir -Recurse')) "uninstaller does not remove the auto-exclude dir"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs has GM-PROXY AUTO-EXCLUDE STORE section" ($gm.Contains('GM-PROXY AUTO-EXCLUDE STORE')) "Export-GodModeLogs auto-exclude store section missing"
Add-Assertion "God-Mode-Windows.ps1: per-app report has USERAUTOEXCLUDE hashtable key" ($gm.Contains('USERAUTOEXCLUDE=0')) "per-app report USERAUTOEXCLUDE key missing"
Add-Assertion "God-Mode-Windows.ps1: per-app modeKey normalizes hyphen (USER-AUTOEXCLUDE -> USERAUTOEXCLUDE)" ($gm.Contains('USER-AUTOEXCLUDE -> USERAUTOEXCLUDE dict key')) "modeKey hyphen normalization missing -- USER-AUTOEXCLUDE would not count"
Add-Assertion "God-Mode-Windows.ps1: per-app table has USER-AUTOEXCLUDE column header" ($gm.Contains('USER-AUTOEXCLUDE')) "per-app table USER-AUTOEXCLUDE column missing"
Add-Assertion "God-Mode-Windows.ps1: Reset-GmProxyAutoExcludeStore helper defined (menu [18])" ($gm.Contains('function Reset-GmProxyAutoExcludeStore')) "Reset-GmProxyAutoExcludeStore missing"
Add-Assertion "God-Mode-Windows.ps1: menu offers [18] RESET AUTO-EXCLUDE STORE" ($gm.Contains('[18] RESET AUTO-EXCLUDE STORE')) "menu [18] missing"
Add-Assertion "God-Mode-Windows.ps1: menu Read-Host range is 1-19" ($gm.Contains('Select an administrative action (1-19)')) "menu range not updated to 1-19"
Add-Assertion "God-Mode-Windows.ps1: switch case 18 calls Reset-GmProxyAutoExcludeStore" ($gm.Contains('Reset-GmProxyAutoExcludeStore')) "switch case 18 does not call Reset-GmProxyAutoExcludeStore"
Add-Assertion "God-Mode-Windows.ps1: reset helper invokes gmproxy.exe --gm-reset-autoexclude (mutex-safe)" ($gm.Contains('--gm-reset-autoexclude')) "reset helper does not use the mutex-safe gmproxy reset hook"

# --- 25. Hardening: reason field (5th) + GMPROXY_TEST_FORCE_SYSTEM_MODE recording seam + gmhook mtime invalidation + Test-GmAutoExcluded cache + mutex create fallback ---
# Five additive hardening improvements on top of the Smart IFEO Compatibility
# Layer (section 24), all backward-compatible (old 4-field store lines still
# parse; production build byte-for-byte unaffected by the test seam):
#   H1 gmproxy.c: the auto-exclude store gains an informational 5th 'reason'
#      field (C=crash, G=clean-gui, P=pre-drop, ?=old line) so Export-GodModeLogs
#      can show WHY each app was excluded. The parser defaults to '?' so old
#      4-field lines still parse (forward/backward compatible).
#   H2 gmproxy.c: GMPROXY_TEST_FORCE_SYSTEM_MODE compile-time seam (mirrors
#      GMPROXY_TEST_FORCE_SESSION0) lets the wine runtime test
#      (test-gmproxy-force-system.sh) exercise the RECORDING path -- the
#      production _wcsicmp(mode,L"SYSTEM") guard never fires under wine (no real
#      SYSTEM token). Production build does NOT define it; #else is the original.
#   H3 gmhook.c: mtime invalidation -- the 2s cache also reloads when the store
#      file's LastWriteTime changes, so a newly-excluded app is respected on the
#      NEXT CreateProcessW instead of waiting up to 2s.
#   H4 God-Mode-Windows.ps1: Test-GmAutoExcluded gains a 15s script-level cache
#      (collapses N-per-scan store reads to ~1 per 15s), invalidated by
#      Add-GmAutoExcludeEntries.
#   H5 God-Mode-Windows.ps1: Add-GmAutoExcludeEntries falls back to creating the
#      Global mutex (New-Object Threading.Mutex) when OpenExisting fails (first-
#      install window before gmproxy has run), closing a narrow writer race.
Add-Assertion "H1 gmproxy.c: GmAutoExcludeEntry struct has a reason field" ($proxy.Contains('wchar_t reason;')) "GmAutoExcludeEntry reason field missing -- refusal flavor cannot be stored"
Add-Assertion "H1 gmproxy.c: GmProxyAutoExcludeRecord takes a reason param (wchar_t reason)" ($proxy -match 'GmProxyAutoExcludeRecord\s*\(\s*const\s+wchar_t\*\s+baseName\s*,\s*wchar_t\s+reason\s*\)') "GmProxyAutoExcludeRecord missing the reason param -- flavor not threaded into the record"
Add-Assertion "H1 gmproxy.c: record call passes reason 'C' (crash) / 'G' (clean-gui)" ($proxy.Contains("GmProxyAutoExcludeRecord(base, (code != 0) ? L'C' : L'G')")) "record call does not pass the reason flavor"
Add-Assertion "H1 gmproxy.c: record sets entries[idx].reason = reason (latest flavor overwrites)" ($proxy.Contains('entries[idx].reason = reason;')) "record does not store the reason on the entry"
Add-Assertion "H1 gmproxy.c: store write emits the 5th reason field (%lc)" ($proxy.Contains('|%lc')) "store write does not emit the 5th reason field"
Add-Assertion "H1 gmproxy.c: parser reads the optional 5th field (p4 = wcschr(p3+1, '|'))" ($proxy.Contains('const wchar_t* p4 = wcschr(p3 + 1, L''|'');')) "parser does not read the optional 5th reason field"
Add-Assertion "H1 gmproxy.c: parser defaults reason to '?' for old 4-field lines" ($proxy.Contains("if (reason) *reason = L'?';")) "parser does not default reason to '?' -- old 4-field store lines would not parse"
Add-Assertion "H2 gmproxy.c: GMPROXY_TEST_FORCE_SYSTEM_MODE compile-time seam present (#ifdef)" ($proxy.Contains('#ifdef GMPROXY_TEST_FORCE_SYSTEM_MODE')) "force-system seam missing -- recording cannot be exercised under wine"
Add-Assertion "H2 gmproxy.c: seam forces recordAsSystem=TRUE (test build records under wine FALLBACK)" ($proxy.Contains('BOOL recordAsSystem = TRUE;')) "seam does not force recordAsSystem=TRUE"
Add-Assertion "H2 gmproxy.c: production #else branch keeps the original _wcsicmp(mode,L""SYSTEM"") guard" ($proxy.Contains('BOOL recordAsSystem = (_wcsicmp(mode, L"SYSTEM") == 0);')) "production #else branch lost the original _wcsicmp(mode,L""SYSTEM"") guard -- production recording regressed"
Add-Assertion "H2 gmproxy.c: job=disabled branch records ONLY under the seam (production never records there)" ($proxy -match 'job=disabled[\s\S]{0,500}#ifdef GMPROXY_TEST_FORCE_SYSTEM_MODE') "job=disabled branch not guarded by the force-system seam -- production would record on unconfirmed tree state OR wine job stubs would block the test"
$BuildPs1 = Join-Path $ProjectRoot "driver/build.ps1"
$buildPs = ""
if (Test-Path $BuildPs1) { $buildPs = Get-Content -Raw $BuildPs1 -ErrorAction SilentlyContinue }
if (-not $buildPs) { $buildPs = "" }
Add-Assertion "H2 driver/build.ps1: production build does NOT define the force-system seam" ($buildPs -and -not $buildPs.Contains('GMPROXY_TEST_FORCE_SYSTEM_MODE')) "driver/build.ps1 references GMPROXY_TEST_FORCE_SYSTEM_MODE (or is missing) -- production binary would force-record in the field"
Add-Assertion "H3 gmhook.c: mtime invalidation reads the store LastWriteTime (GetFileAttributesExW)" ($gmhook.Contains('GetFileAttributesExW')) "gmhook mtime invalidation missing -- a fresh exclusion waits up to the 2s TTL"
Add-Assertion "H3 gmhook.c: tracks the store LastWriteTime (cacheLoadMtime static)" ($gmhook.Contains('cacheLoadMtime')) "gmhook does not track cacheLoadMtime -- mtime change cannot trigger a reload"
Add-Assertion "H3 gmhook.c: WIN32_FILE_ATTRIBUTE_DATA used for the mtime read" ($gmhook.Contains('WIN32_FILE_ATTRIBUTE_DATA')) "gmhook does not use WIN32_FILE_ATTRIBUTE_DATA for the mtime read"
Add-Assertion "H3 gmhook.c: reload fires on mtime change OR TTL expiry (mtimeChanged || TTL)" ($gmhook.Contains('mtimeChanged') -and $gmhook.Contains('GMHOOK_AUTOEXCLUDE_CACHE_TTL_MS')) "gmhook does not gate the reload on mtimeChanged || TTL"
Add-Assertion "H3 gmhook.c: 5th reason field ignored (forward-compat -- parse stops at '|', reason not required)" ($gmhook.Contains('excluded = (_wtoi(p3 + 1) != 0)') -and -not $gmhook.Contains('p4')) "gmhook parser changed -- the 5th reason field is not forward-compatible"
Add-Assertion "H4 God-Mode-Windows.ps1: Test-GmAutoExcluded has a 15s script cache (GmAutoExcludeCache)" ($gm.Contains('GmAutoExcludeCache')) "Test-GmAutoExcluded 15s cache missing -- N-per-scan store reads not collapsed"
Add-Assertion "H4 God-Mode-Windows.ps1: Test-GmAutoExcluded cache TTL is 15s (TotalSeconds -lt 15)" ($gm.Contains('TotalSeconds -lt 15')) "Test-GmAutoExcluded cache TTL is not 15s"
Add-Assertion "H4 God-Mode-Windows.ps1: Test-GmAutoExcluded cache timestamp var (GmAutoExcludeCacheDt)" ($gm.Contains('GmAutoExcludeCacheDt')) "Test-GmAutoExcluded cache timestamp var missing"
Add-Assertion "H4 God-Mode-Windows.ps1: Add-GmAutoExcludeEntries invalidates the cache (sets both to null)" ($gm.Contains('GmAutoExcludeCache = $null') -and $gm.Contains('GmAutoExcludeCacheDt = $null')) "Add-GmAutoExcludeEntries does not invalidate the Test-GmAutoExcluded cache"
Add-Assertion "H4 God-Mode-Windows.ps1: Test-GmAutoExcluded returns the stored VALUE ($cache[$target]), not ContainsKey -- excluded=0 stays \$false" ($gm.Contains('$cache[$target]') -and $gm.Contains('$script:GmAutoExcludeCache[$target]')) "Test-GmAutoExcluded returns ContainsKey (key existence) instead of the stored excluded bool -- an excluded=0 entry (count<threshold) would wrongly return true and over-exclude, breaking Detector B"
Add-Assertion "H5 God-Mode-Windows.ps1: Add-GmAutoExcludeEntries mutex create fallback (New-Object Threading.Mutex)" ($gm.Contains('New-Object System.Threading.Mutex($false, $mutexName)')) "Add-GmAutoExcludeEntries missing the mutex create fallback -- first-install window could race a concurrent gmproxy"
Add-Assertion "H5 God-Mode-Windows.ps1: Add-GmAutoExcludeEntries new entries use the -Reason param (default 'P', 'A' for AppX)" ($gm.Contains('"$key|2|$nowTs|1|$Reason"')) "Add-GmAutoExcludeEntries new entries do not use the -Reason param -- AppX drops cannot be tagged 'A'"
Add-Assertion "H5 God-Mode-Windows.ps1: Add-GmAutoExcludeEntries preserves an existing reason on merge" ($gm.Contains('$parts.Count -ge 5 -and $parts[4]')) "Add-GmAutoExcludeEntries does not preserve an existing reason on merge"
Add-Assertion "H5 God-Mode-Windows.ps1: Export-GodModeLogs reason legend (C=CRASH / G=CLEAN-GUI / P=PRE-DROP via $reasonLegend hashtable)" ($gm.Contains("'C' = 'CRASH") -and $gm.Contains("'G' = 'CLEAN-GUI") -and $gm.Contains("'P' = 'PRE-DROP")) "Export-GodModeLogs reason legend missing -- user cannot tell why an app was excluded"
Add-Assertion "H5 God-Mode-Windows.ps1: Export-GodModeLogs store line-format note includes the reason field" ($gm.Contains('basename|crashCount|lastCrashUnixTs|excluded|reason')) "Export-GodModeLogs line-format note does not include the reason field"

# --- 26. AppX/Store-redirector stub drop + gmproxy alias guard + reset cache + per-app REASON + gmhook token invalidation (2026-07-19) ---
# Six additive improvements: (1) Detector A now DROPS AppX/WinUI Store-redirector
# stubs (notepad/mspaint/calc/photos) from IFEO + persists them to the store with
# reason 'A' + removes prior IFEO hooks on a re-enable -- they cannot run as SYSTEM
# (AppX activation needs user identity) AND gmproxy's IFEO-bypass rename breaks
# their App Execution Alias redirect + .mui lookup, so native user launch is the
# only way they start. (2) gmproxy.c GmProxyIsAppExecutionAliasStub guard skips
# recording a CLEAN-GUI refusal for a base with a Store alias (belt-and-suspenders
# for a stub that slips past Detector A; CRASH is still recorded). (3) Reset-
# GmProxyAutoExcludeStore clears the Test-GmAutoExcluded 15s cache. (4) Export-
# GodModeLogs per-app report gains a REASON column + A=ALIAS-STUB legend. (5) gmhook
# GmHookIsAutoExcluded invalidates on a host-process-token change. (6) Add-
# GmAutoExcludeEntries gains a -Reason param. No hardcoded names; fail-open.
Add-Assertion "AppX drop: gmproxy.c GmProxyIsAppExecutionAliasStub helper defined" ($proxy.Contains('GmProxyIsAppExecutionAliasStub')) "gmproxy.c alias-stub helper missing -- CLEAN-GUI refusals for Store stubs would be recorded (false store pollution)"
Add-Assertion "AppX drop: gmproxy.c alias guard checks the WindowsApps reparse point (GetFileAttributesExW + FILE_ATTRIBUTE_REPARSE_POINT)" ($proxy.Contains('Microsoft\\WindowsApps') -and $proxy.Contains('FILE_ATTRIBUTE_REPARSE_POINT')) "gmproxy.c alias guard does not check the WindowsApps reparse point"
Add-Assertion "AppX drop: gmproxy.c alias guard skip-record DiagLog present (App Execution Alias stub)" ($proxy.Contains('is an App Execution Alias stub')) "gmproxy.c alias guard skip-record DiagLog missing -- the real cause (rename breaks the stub) would not be logged"
Add-Assertion "AppX drop: gmproxy.c alias guard wraps the CLEAN-GUI record (code == 0 && GmProxyIsAppExecutionAliasStub(base))" ($proxy.Contains('code == 0 && GmProxyIsAppExecutionAliasStub(base)')) "gmproxy.c alias guard does not gate the CLEAN-GUI record -- a stub CLEAN exit would still pollute the store"
Add-Assertion "AppX drop: gmproxy.c alias guard leaves CRASH recording intact (GmProxyAutoExcludeRecord in the else)" ($proxy.Contains('GmProxyAutoExcludeRecord(base, (code != 0) ? L''C'' : L''G'')')) "gmproxy.c alias guard removed the CRASH record path -- real crashes would not be recorded"
Add-Assertion "AppX drop: God-Mode-Windows.ps1 Install-IfeoElevation persists the AppX set with -Reason 'A'" ($gm.Contains('Add-GmAutoExcludeEntries -BaseNames @($CompatExclusions.AppX.Keys) -Reason ''A''')) "Install-IfeoElevation does not persist the AppX set with reason 'A'"
Add-Assertion "AppX drop: God-Mode-Windows.ps1 Install-IfeoElevation removes prior AppX IFEO hooks (appxHookRemoved)" ($gm.Contains('appxHookRemoved')) "Install-IfeoElevation does not remove prior AppX IFEO hooks -- a re-enable on a VM that hooked notepad leaves it hooked"
Add-Assertion "AppX drop: God-Mode-Windows.ps1 Add-IfeoElevationForApp skips App Execution Alias stubs (ReparsePoint + SKIP-APPAlias)" ($gm.Contains('WindowsApps') -and $gm.Contains('SKIP-APPAlias')) "Add-IfeoElevationForApp does not skip App Execution Alias stubs"
Add-Assertion "Reset cache: Reset-GmProxyAutoExcludeStore clears GmAutoExcludeCache + GmAutoExcludeCacheDt" ($gm -match 'function\s+Reset-GmProxyAutoExcludeStore[\s\S]{0,4000}?GmAutoExcludeCache\s*=\s*\$null[\s\S]{0,80}?GmAutoExcludeCacheDt\s*=\s*\$null') "Reset-GmProxyAutoExcludeStore does not clear the Test-GmAutoExcluded cache -- a scan right after reset could see stale exclusions for 15s"
Add-Assertion "Per-app REASON: Export-GodModeLogs builds a reasonMap from the store (5th field)" ($gm.Contains('reasonMap') -and $gm.Contains('p[4]')) "Export-GodModeLogs does not build a reasonMap -- the REASON column cannot be populated"
Add-Assertion "Per-app REASON: Export-GodModeLogs per-app table has a REASON column header" ($gm.Contains('USER-AUTOEXCLUDE  REASON')) "Export-GodModeLogs per-app table missing the REASON column header"
Add-Assertion "Per-app REASON: Export-GodModeLogs A=ALIAS-STUB legend present (via $reasonLegend hashtable)" ($gm.Contains("'A' = 'ALIAS-STUB")) "Export-GodModeLogs A=ALIAS-STUB legend missing -- the user cannot tell AppX drops from browser drops"
Add-Assertion "gmhook token: GmHookIsAutoExcluded captures the host token SID (cacheLoadTokenSid)" ($gmhook.Contains('cacheLoadTokenSid')) "gmhook does not capture the host token SID -- a host-token change cannot trigger a reload"
Add-Assertion "gmhook token: GmHookIsAutoExcluded reloads on a token change (tokenChanged + EqualSid)" ($gmhook.Contains('tokenChanged') -and $gmhook.Contains('EqualSid')) "gmhook does not reload on a host-token change -- the 'always fresh' guarantee is incomplete"
Add-Assertion "gmhook token: GmHookIsAutoExcluded token query is fail-open (OpenProcessToken + haveCurSid)" ($gmhook.Contains('OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY') -and $gmhook.Contains('haveCurSid')) "gmhook token query is not fail-open -- a token query failure could break the store consult"

# --- 27. notepad detection-miss fix + 3 hardening suggestions (2026-07-19) ---
# Five additive improvements: (1) Get-GmSystemCompatExclusions gains a curated
# Win11 Store-redirector stub fallback (notepad/mspaint/calc/snippingtool,
# Test-Path-validated) + a direct C:\Program Files\WindowsApps manifest scan,
# so the classic Win11 stubs are classified AppX + dropped from IFEO + persisted
# 'A' even when Get-AppxPackage misses them (the actual "notepad doesn't start"
# fix -- gmhook then consults the store and lets them launch natively). (2) gmproxy
# same-directory copy fallback (current token, then SYSTEM impersonation) keeps
# the canonical-directory context for path-relative targets whose hardlink fails.
# (3) Invoke-GmAutoExcludeReconcile prunes orphaned 'A' entries on a 5-min monitor
# cadence (Store-app uninstall tidy-up; never touches C/G/P). (4) Export-GodModeLogs
# reason legend is driven by a single $reasonLegend hashtable (no drift). (5) gmproxy
# GmProxyAutoExcludeRecord preserves an install-time 'A' reason (not downgraded to
# G/C for a stub that slips past Detector A). Additive + fail-open.
$compatMatch = [regex]::Match($gm, '(?s)function\s+Get-GmSystemCompatExclusions\s*\{(.*?)\nfunction\s+Get-IfeoElevationCandidates\s*\{')
$compatBody = if ($compatMatch.Success) { $compatMatch.Groups[1].Value } else { "" }
Add-Assertion "Notepad fix: Get-GmSystemCompatExclusions body extractable" ($compatMatch.Success) "could not isolate Get-GmSystemCompatExclusions body"
if ($compatMatch.Success) {
    Add-Assertion "Notepad fix: curated Win11-stub fallback list present ($win11StubNames + 4 stubs)" ($compatBody.Contains('$win11StubNames') -and $compatBody.Contains('notepad.exe') -and $compatBody.Contains('mspaint.exe') -and $compatBody.Contains('calc.exe') -and $compatBody.Contains('snippingtool.exe')) "curated Win11-stub fallback missing -- notepad/mspaint/calc/snippingtool stay IFEO-hooked on VMs where Get-AppxPackage misses them"
    Add-Assertion "Notepad fix: curated fallback validates each stub via Test-Path C:\Windows + System32" ($compatBody.Contains('Test-Path ("C:\Windows\" + $stub)') -and $compatBody.Contains('C:\Windows\System32')) "curated fallback does not Test-Path-gate each stub -- would drop names absent on this VM"
    Add-Assertion "Notepad fix: curated fallback only adds names not already detected (ContainsKey skip)" ($compatBody.Contains('$appx.ContainsKey($k)')) "curated fallback does not skip already-detected names -- redundant"
    Add-Assertion "Notepad fix: direct WindowsApps filesystem scan (C:\Program Files\WindowsApps + AppXManifest.xml)" ($compatBody.Contains('C:\Program Files\WindowsApps') -and $compatBody.Contains('AppXManifest.xml')) "direct WindowsApps filesystem scan missing -- packages Get-AppxPackage misses (Store Notepad on admin) are not caught"
}
Add-Assertion "Suggestion 3: gmproxy same-dir copy fallback (CopyFileW to hardlinkPath before Temp)" ($proxy.Contains('CopyFileW(argv[1], hardlinkPath, FALSE)')) "gmproxy same-dir copy fallback missing -- a hardlink failure jumps straight to Temp (loses canonical-directory context)"
Add-Assertion "Suggestion 3: gmproxy same-dir copy retries under SYSTEM impersonation (DuplicateTokenEx TokenImpersonation)" ($proxy.Contains('DuplicateTokenEx(hPrimary, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hImp)')) "gmproxy same-dir copy does not impersonate SYSTEM -- C:\Windows/System32 targets the admin can't write stay broken"
Add-Assertion "Suggestion 3: gmproxy impersonation uses ImpersonateLoggedOnUser + RevertToSelf (always reverts)" ($proxy.Contains('ImpersonateLoggedOnUser(hImp)') -and $proxy.Contains('RevertToSelf()')) "gmproxy impersonation does not RevertToSelf -- gmproxy would keep running as SYSTEM after the copy"
Add-Assertion "Suggestion 3: gmproxy same-dir copy gated on haveToken + hPrimary (fail-open)" ($proxy.Contains('!usedHardlink && haveToken && hPrimary')) "gmproxy same-dir copy not gated on haveToken/hPrimary -- would attempt impersonation without a token"
Add-Assertion "Suggestion 3: gmproxy Temp copy remains the final fallback (GetTempPathW + gmproxy_%lu_%ls)" ($proxy.Contains('GetTempPathW') -and $proxy.Contains('gmproxy_%lu_%ls')) "gmproxy Temp fallback removed -- a same-dir copy failure would abort the launch"
Add-Assertion "Suggestion 1: Invoke-GmAutoExcludeReconcile function defined" ($gm.Contains('function Invoke-GmAutoExcludeReconcile')) "Invoke-GmAutoExcludeReconcile missing -- orphaned 'A' entries linger after a Store-app uninstall"
Add-Assertion "Suggestion 1: reconcile restricts pruning to install-time 'A' + 'P' entries ($rsn -ne 'A' guard preserved, keep C/G)" ($gm.Contains('$rsn -ne ''A''')) "reconcile does not restrict pruning to install-time 'A'/'P' entries -- could drop runtime C/G learnings"
Add-Assertion "Suggestion 1: reconcile checks stub + alias existence before pruning (stubExists + aliasExists + aliasBases)" ($gm.Contains('$stubExists') -and $gm.Contains('$aliasExists') -and $gm.Contains('aliasBases')) "reconcile does not verify the stub/alias is gone -- could prune a still-installed Store app"
Add-Assertion "Suggestion 1: reconcile is mutex-safe (Global\GmProxyAutoExcludeMutex)" ($gm -match 'function\s+Invoke-GmAutoExcludeReconcile[\s\S]{0,3000}?GmProxyAutoExcludeMutex') "reconcile does not hold the cross-privilege mutex -- could race a concurrent gmproxy write"
Add-Assertion "Suggestion 1: reconcile atomic write (temp + Move-Item -Force to GodModeAutoExcludeFile)" ($gm -match 'function\s+Invoke-GmAutoExcludeReconcile[\s\S]{0,7000}?Move-Item\s+-Path\s+\$tmp\s+-Destination\s+\$GodModeAutoExcludeFile\s+-Force') "reconcile missing atomic temp+rename -- a mid-write crash could corrupt the store"
Add-Assertion "Suggestion 1: reconcile invalidates the Test-GmAutoExcluded cache after a prune" ($gm -match 'function\s+Invoke-GmAutoExcludeReconcile[\s\S]{0,9000}?GmAutoExcludeCache\s*=\s*\$null') "reconcile does not invalidate the cache -- a consult right after a prune could see stale entries"
Add-Assertion "Suggestion 1: monitor calls reconcile on a 5-min cadence ($lastReconcile + FromMinutes(5))" ($gm.Contains('$lastReconcile = [datetime]::MinValue') -and $gm.Contains('[TimeSpan]::FromMinutes(5)') -and $gm.Contains('Invoke-GmAutoExcludeReconcile')) "monitor does not call reconcile on a 5-min cadence -- orphaned 'A' entries never pruned"
Add-Assertion "Suggestion 2: Export-GodModeLogs builds a single $reasonLegend hashtable ([ordered])" ($gm.Contains('$reasonLegend = [ordered]@{')) "Export-GodModeLogs missing the single $reasonLegend hashtable -- legends can drift"
Add-Assertion "Suggestion 2: store legend emitted from $reasonLegend ($reasonParts -join)" ($gm.Contains('$reasonParts = foreach ($k in $reasonLegend.Keys)') -and $gm.Contains('($reasonParts -join '', '')')) "store legend not emitted from $reasonLegend -- drift risk"
Add-Assertion "Suggestion 2: per-app REASON legend emitted from the same $reasonLegend ($reasonParts2)" ($gm.Contains('$reasonParts2 = foreach ($k in $reasonLegend.Keys)')) "per-app REASON legend not emitted from $reasonLegend -- the two legends can drift"
Add-Assertion "Belt-and-suspenders: gmproxy GmProxyAutoExcludeRecord preserves reason 'A' (if reason != L'A')" ($proxy.Contains("if (entries[idx].reason != L'A')")) "gmproxy record overwrites an install-time 'A' with a runtime G/C -- a stub that slips past Detector A loses its AppX classification"

# --- 28. Final 3 hardening suggestions: gmhook alias-stub skip + WinRT PE
# heuristic + reconcile 'P' prune (2026-07-20) ---
# Three additive improvements (all backward-compatible + fail-open):
#   S1 gmhook.c: GmHookIsAppExecutionAliasStub (mirrors gmproxy.c) -- a direct
#     reparse-point skip in HookCreateProcessW for a Win11 App Execution Alias
#     stub whose auto-exclude store entry was pruned by reconcile or never
#     written (Detector A miss). Belt-and-suspenders alongside the store consult.
#   S2 God-Mode-Windows.ps1: Test-GmPeImportsWinrt + AppX source (6) -- a dynamic
#     C:\Windows/System32 stub-PE heuristic that classifies any .exe IMPORTING a
#     WinRT activation API (RoActivateInstance/WindowsCreateString) as AppX,
#     generalizing the curated name list (5) to catch FUTURE Win11 stubs.
#     Conservative-safe (a WinRT importer cannot run as SYSTEM anyway). Curated
#     list (5) preserved (additive -- never removed).
#   S3 Invoke-GmAutoExcludeReconcile: also prunes stale 'P' browser entries
#     whose registered StartMenuInternet client vanished (browser uninstalled),
#     fail-open on an empty browser scan; never touches runtime C/G.
Add-Assertion "S1 gmhook: GmHookIsAppExecutionAliasStub helper defined (mirrors gmproxy.c)" ($gmhook.Contains('GmHookIsAppExecutionAliasStub')) "gmhook GmHookIsAppExecutionAliasStub missing -- a stub whose store entry was pruned/never-written would still be born as SYSTEM"
Add-Assertion "S1 gmhook: alias check uses the WindowsApps reparse point (Microsoft\WindowsApps + FILE_ATTRIBUTE_REPARSE_POINT)" ($gmhook.Contains('Microsoft\WindowsApps') -and $gmhook.Contains('FILE_ATTRIBUTE_REPARSE_POINT')) "gmhook alias check does not use the WindowsApps reparse point"
Add-Assertion "S1 gmhook: HookCreateProcessW consults GmHookIsAppExecutionAliasStub(baseName) before SYSTEM birth" ($gmhook.Contains('GmHookIsAppExecutionAliasStub(baseName)')) "gmhook HookCreateProcessW does not consult the alias-stub check -- the belt-and-suspenders skip is not wired"
Add-Assertion "S1 gmhook: alias-stub consult falls through to the real CreateProcessW (pOrigCreateProcessW)" ($gmhook -match 'GmHookIsAppExecutionAliasStub\(baseName\)[\s\S]{0,400}?pOrigCreateProcessW') "gmhook alias-stub consult does not fall through to the real CreateProcessW -- a stub would be born as SYSTEM instead of native launch"
Add-Assertion "S1 gmhook: alias check reads LOCALAPPDATA (GetEnvironmentVariableW)" ($gmhook.Contains('GetEnvironmentVariableW(L"LOCALAPPDATA"')) "gmhook alias check does not read LOCALAPPDATA -- cannot build the WindowsApps alias path"
Add-Assertion "S2 PE heuristic: Test-GmPeImportsWinrt helper defined" ($gm.Contains('function Test-GmPeImportsWinrt')) "Test-GmPeImportsWinrt missing -- no dynamic WinRT-import PE heuristic to catch future Win11 stubs"
Add-Assertion "S2 PE heuristic: checks RoActivateInstance + WindowsCreateString imports" ($gm.Contains('RoActivateInstance') -and $gm.Contains('WindowsCreateString')) "PE heuristic does not check both WinRT activation API import names"
Add-Assertion "S2 PE heuristic: verifies the MZ DOS magic (0x4D / 0x5A)" ($gm.Contains('0x4D') -and $gm.Contains('0x5A')) "PE heuristic does not verify the MZ DOS magic -- a non-PE file could be misread as a stub"
Add-Assertion "S2 PE heuristic: verifies the PE signature at e_lfanew (0x50 / 0x45 + eLfanew)" ($gm.Contains('0x50') -and $gm.Contains('0x45') -and $gm.Contains('eLfanew')) "PE heuristic does not verify the PE signature at e_lfanew -- a non-PE file could be misread"
Add-Assertion "S2 PE heuristic: 1MB size cap bounds the byte read (stubs are small)" ($gm.Contains('1MB')) "PE heuristic missing the 1MB size cap -- the byte read is unbounded at Enable-time"
Add-Assertion "S2 PE heuristic: AppX source (6) scans C:\Windows/System32 + calls Test-GmPeImportsWinrt ($stubDirs)" ($compatBody.Contains('$stubDirs') -and $compatBody.Contains('Test-GmPeImportsWinrt')) "AppX source (6) PE-heuristic scan missing -- future Win11 stubs won't be caught dynamically"
Add-Assertion "S2 PE heuristic: source (6) size-filters files >1MB before the byte read ($_.Length -gt 1MB)" ($compatBody.Contains('$_.Length -gt 1MB')) "source (6) does not size-filter before the byte read -- large System32 exes would be read needlessly"
Add-Assertion "S2 PE heuristic: curated list (5) preserved ($win11StubNames still present in the body)" ($compatBody.Contains('$win11StubNames')) "curated list (5) was removed -- the last-resort safety net regressed (additive rule violated)"
Add-Assertion "S3 reconcile: builds $browserBases (StartMenuInternet scan) alongside $aliasBases" ($gm.Contains('$browserBases') -and $gm.Contains('StartMenuInternet')) "reconcile does not build $browserBases -- stale 'P' browser entries cannot be pruned"
Add-Assertion "S3 reconcile: prunes stale 'P' browser entries ($rsn -ne 'P' guard)" ($gm.Contains('$rsn -ne ''P''')) "reconcile does not prune stale 'P' browser entries -- a browser uninstalled after enable lingers up to 30 days"
Add-Assertion "S3 reconcile: 'P' prune is fail-open on an empty browser scan ($browserBases.Count -eq 0)" ($gm.Contains('$browserBases.Count -eq 0')) "reconcile 'P' prune is not fail-open -- an empty browser scan (registry ACL denied) would prune ALL 'P' entries"
Add-Assertion "S3 reconcile: keeps the 'A' stub+alias existence check (stubExists + aliasExists)" ($gm.Contains('$stubExists') -and $gm.Contains('$aliasExists')) "reconcile lost the 'A' stub+alias existence check -- could prune a still-installed Store app"

# --- 29. Interactive-shell auto-elevation (option #2) + ISE hardening +
# self-collision guard (2026-07-20) ---
# Four additive improvements (all backward-compatible + fail-open):
#   A. Test-SystemProcessExists gains -InteractiveOnly (only count a SYSTEM
#      instance in Session>0) -- stops the monitor's OWN headless Session-0
#      SYSTEM powershell.exe from falsely satisfying "a SYSTEM instance exists"
#      for an interactive-shell name (which would make Stop-NonSystemInstances
#      kill the user's admin shell instead of in-place-elevating it). Mirrors
#      Find-SystemProcessCandidate Session>0 + gmhook FindSystemPid.
#   B. Monitor-ElevateProcess: interactive shells (cmd/powershell/pwsh/ISE) SKIP
#      the aggressive "SYSTEM instance exists -> purge non-SYSTEM" branch and go
#      straight to Phase 0 in-place ReplaceProcessTokenForPid -- no kill, no
#      flicker, every instance gets its own SYSTEM token (whoami -> SYSTEM).
#   C. Test-GmPlumbingShell guard: God Mode's OWN plumbing shells (cmdline
#      carries -ToggleOn/-ElevateAllProcesses/-SystemDesktop/GodMode.ps1) are
#      left untouched so a mid-flight token swap never disturbs the
#      monitor/watchdog/guardian/SystemDesktop work. Fail-open.
#   D. ISE hardening: powershell_ise added to IsShellLauncherProcess (gmhook) +
#      $GmCriticalIfeoExclude + $SkipNames + $CriticalProcs (both) + the
#      interactive-shells set. Polling new-process scan now passes -ProcessId
#      (mirrors the WMI watcher) so Phase 0 works from both paths.
Add-Assertion "Opt2 A: Test-SystemProcessExists has -InteractiveOnly switch (session-aware)" ($gm.Contains('param([string]$ProcessName, [switch]$InteractiveOnly)')) "Test-SystemProcessExists missing the -InteractiveOnly switch -- cannot session-filter the SYSTEM-instance check"
Add-Assertion "Opt2 A: Test-SystemProcessExists -InteractiveOnly skips Session 0 (`$p.SessionId -le 0 continue)" ($gm.Contains('if ($InteractiveOnly -and $p.SessionId -le 0) { continue }')) "Test-SystemProcessExists does not skip Session 0 under -InteractiveOnly -- the monitor's own Session-0 SYSTEM powershell would still falsely satisfy the check"
Add-Assertion "Opt2 B: Monitor-ElevateProcess defines `$interactiveShells (cmd/powershell/pwsh/powershell_ise)" ($gm.Contains('$interactiveShells = @("cmd","powershell","pwsh","powershell_ise")')) "Monitor-ElevateProcess missing the `$interactiveShells set -- interactive shells cannot be routed to the in-place Phase 0 path"
Add-Assertion "Opt2 B: Monitor-ElevateProcess consults Test-GmPlumbingShell for interactive shells" ($gm.Contains('if ($isInteractiveShell) {') -and $gm.Contains('Test-GmPlumbingShell -ProcessId $ProcessId')) "Monitor-ElevateProcess does not consult Test-GmPlumbingShell for interactive shells -- God Mode plumbing shells could be token-swapped mid-flight"
Add-Assertion "Opt2 B: Monitor-ElevateProcess non-shell purge uses -InteractiveOnly" ($gm.Contains('Test-SystemProcessExists -ProcessName "$procName.exe" -InteractiveOnly')) "Monitor-ElevateProcess non-shell purge does not use -InteractiveOnly -- a Session-0 SYSTEM instance could falsely trigger a desktop purge"
Add-Assertion "Opt2 B: interactive shells skip the purge branch (fall through to Phase 0)" ($gm.Contains('Fall through to Phase 0 in-place token replacement (skip the purge branch)')) "interactive shells do not skip the purge branch -- the monitor would kill the user's admin shell"
Add-Assertion "Opt2 B: Phase 0 in-place swap still present (ReplaceProcessTokenForPid)" ($gm.Contains('[TokenOps]::ReplaceProcessTokenForPid($ProcessId, $systemPid)')) "Phase 0 in-place token replacement removed -- shells would fall to kill+relaunch"
Add-Assertion "Opt2 C: Test-GmPlumbingShell function defined (God Mode plumbing guard)" ($gm.Contains('function Test-GmPlumbingShell {')) "Test-GmPlumbingShell missing -- God Mode plumbing shells cannot be detected/protected"
Add-Assertion "Opt2 C: Test-GmPlumbingShell checks the ElevateAll temp copy (GodMode_ElevateAll)" ($gm.Contains("'GodMode_ElevateAll'")) "Test-GmPlumbingShell does not check for GodMode_ElevateAll -- the ElevateAll task shell would be swapped mid-flight"
Add-Assertion "Opt2 C: Test-GmPlumbingShell checks the SystemDesktop temp copy (GodMode_SystemDesktop)" ($gm.Contains("'GodMode_SystemDesktop'")) "Test-GmPlumbingShell does not check for GodMode_SystemDesktop"
Add-Assertion "Opt2 C: Test-GmPlumbingShell checks GodMode CLI flags (-ToggleOn/-ToggleOff/-ElevateAllProcesses/-SystemDesktop)" ($gm.Contains("'-ToggleOn','-ToggleOff','-ElevateAllProcesses','-SystemDesktop'")) "Test-GmPlumbingShell does not check GodMode CLI flags -- plumbing shells would be swapped mid-flight"
Add-Assertion "Opt2 C: Test-GmPlumbingShell is fail-open (ProcessId -le 0 -> return `$false)" ($gm.Contains('if ($ProcessId -le 0) { return $false }')) "Test-GmPlumbingShell is not fail-open on ProcessId -le 0 -- a bad PID could throw"
Add-Assertion "Opt2 C: Test-GmPlumbingShell is fail-open (catch -> return `$false)" ($gm.Contains('} catch { return $false }')) "Test-GmPlumbingShell is not fail-open on a query exception -- a WMI/CIM failure could break the consult"
Add-Assertion "Opt2 D: gmhook IsShellLauncherProcess excludes powershell_ise.exe (ISE hardening)" ($gmhook.Contains('L"powershell_ise.exe"')) "gmhook IsShellLauncherProcess does not exclude powershell_ise.exe -- ISE would be IAT-hooked (0xC0000005 crash risk)"
Add-Assertion "Explorer crash fix: gmhook IsShellLauncherProcess excludes explorer.exe (STARTUPINFOEX downgrade crash/restart loop)" ($gmhook.Contains('L"explorer.exe"')) "gmhook IsShellLauncherProcess does not exclude explorer.exe -- IAT-hooking explorer's STARTUPINFOEX launches drops the extended attribute list (cb clamp + EXTENDED bit clear) -> explorer crashes on its next CreateProcessW expecting those attributes -> repeated explorer.exe crash/restart loop (blank User column alongside the live monitor loop missing)"
Add-Assertion "Opt2 D: `$GmCriticalIfeoExclude contains powershell_ise (never IFEO-redirected)" ($gm.Contains('"pwsh","powershell_ise","wt"')) "`$GmCriticalIfeoExclude missing powershell_ise -- ISE could be IFEO-redirected to gmproxy"
Add-Assertion "Opt2 D: `$SkipNames (Invoke-GmProxyFeedbackElevation) contains powershell_ise" ($gm.Contains('"cmd","powershell_ise","conhost"')) "`$SkipNames missing powershell_ise -- a feedback PID for ISE could be token-swapped (defense-in-depth gap)"
Add-Assertion "Opt2 D: Invoke-ExistingProcessElevation `$CriticalProcs contains powershell_ise.exe" ($gm.Contains('"powershell_ise.exe", "conhost.exe", "explorer.exe")')) "Invoke-ExistingProcessElevation `$CriticalProcs missing powershell_ise.exe -- the startup scan could kill+relaunch ISE"
Add-Assertion "Opt2 D: Start-Monitoring `$CriticalProcs contains powershell_ise.exe" ($gm.Contains('"powershell_ise.exe", "conhost.exe", "explorer.exe", "ShellHost.exe"')) "Start-Monitoring `$CriticalProcs missing powershell_ise.exe -- the periodic scan could kill+relaunch ISE"
Add-Assertion "Opt2 D: polling new-process scan passes -ProcessId `$proc.ProcessId (Phase 0 for shells)" ($gm.Contains('Monitor-ElevateProcess -Path $path -Arguments $arguments -ProcessId $proc.ProcessId -HideWindow')) "polling new-process scan does not pass -ProcessId -- shells would fall to kill+relaunch (loses session/cwd)"
Add-Assertion "Opt2 D: WMI watcher drain still passes -ProcessId `$evt.ProcessId" ($gm.Contains('Monitor-ElevateProcess -Path $path -Arguments $arguments -ProcessId $evt.ProcessId -HideWindow')) "WMI watcher drain no longer passes -ProcessId -- regression in the in-place elevation path"

# --- 30. PS7 WMI process-creation watcher compat (+= -> Register-ObjectEvent ->
# ThreadJob+WaitForNextEvent) + persistent-monitor registration (2026-07-20) ---
# Interactive shells (cmd/powershell/pwsh/ISE) are NOT IFEO-hooked (by design) and
# the global WH_GETMESSAGE hook does not auto-inject them, so a WMI process-creation
# watcher is their SOLE event-driven elevator (Phase 0 in-place ReplaceProcessTokenForPid).
# Three iterations of PS7 compat:
#   (1) PS 5.1 used `$watcher.EventArrived += {}`. PS 7.x removed that adapter (it
#       throws "The property 'EventArrived' cannot be found") -> the watcher silently
#       failed to register (log: "WMI process creation watcher failed to register").
#   (2) An earlier fix switched to `Register-ObjectEvent -Action`. That REGISTERS on
#       PS7 without error, BUT the -Action block only runs when the runscape PUMPS the
#       PowerShell event queue -- which a non-interactive scheduled-task runscape
#       (-WindowStyle Hidden, no console "pulse") does NOT do reliably. So the watcher
#       reported Active=$true, the 5s polling fallback was gated OFF (it only ran when
#       Active=$false), and shells got NEITHER path -> stayed admin (whoami -> admin).
#       This is the symptom that persisted across two prior fix rounds.
#   (3) FINAL fix: drive delivery from a background ThreadJob calling
#       ManagementEventWatcher.WaitForNextEvent() in a loop. WaitForNextEvent() blocks
#       the ThreadJob's own thread until a WMI event fires -- independent of the
#       runscape event-queue pump. The ThreadJob populates the shared synchronized
#       queue + a heartbeat counter; the 5s polling fallback now runs UNCONDITIONALLY
#       (throttled) as a guaranteed safety net so a dead watcher never strands shells.
# The watcher MUST live in THIS persistent monitor (Start-Monitoring, the scheduled
# task), not only in Enable-GodMode (a one-shot activator that exits) -- otherwise it
# dies with the activator. The 5s polling fallback is the universal safety net.
Add-Assertion "PS7 WMI: Register-ProcessCreationWatcher uses Start-ThreadJob + WaitForNextEvent (pump-independent delivery)" ($gm -match 'function\s+Register-ProcessCreationWatcher[\s\S]{0,6000}?Start-ThreadJob[\s\S]{0,3000}?WaitForNextEvent') "Register-ProcessCreationWatcher does not use a ThreadJob + WaitForNextEvent delivery loop -- PS7 Register-ObjectEvent -Action does not pump in a non-interactive scheduled-task runscape, so shells would never be event-elevated"
Add-Assertion "PS7 WMI: NO .EventArrived += left (PS7-incompatible adapter)" ($gm -notmatch '\.EventArrived\s*\+=') "Register-ProcessCreationWatcher still has .EventArrived += -- PS7 throws 'property EventArrived cannot be found' and the watcher never registers"
Add-Assertion "PS7 WMI: queue + watcher passed to the ThreadJob via -ArgumentList (runscope-safe)" ($gm -match 'function\s+Register-ProcessCreationWatcher[\s\S]{0,8000}?\-ArgumentList \$watcher, \$queue, \$state') "Register-ProcessCreationWatcher does not pass the watcher+queue+state to the ThreadJob via -ArgumentList -- the ThreadJob could not reach them reliably"
Add-Assertion "PS7 WMI: ThreadJob reads `$evt.TargetInstance from WaitForNextEvent" ($gm -match 'WaitForNextEvent\(\)[\s\S]{0,500}?\$evt\.TargetInstance') "Register-ProcessCreationWatcher ThreadJob does not read `$evt.TargetInstance from WaitForNextEvent -- the new process instance could not be extracted"
Add-Assertion "PS7 WMI: defensive Add-Type System.Management (assembly load)" ($gm -match 'Add-Type -AssemblyName System\.Management') "Register-ProcessCreationWatcher missing the defensive Add-Type System.Management -- ManagementEventWatcher could be unresolved on a clean PS7 runspace"
Add-Assertion "PS7 WMI: ThreadJob increments a shared heartbeat counter (`$state.Beats / `$st.Beats)" ($gm.Contains('$st.Beats = [int]$st.Beats + 1')) "Register-ProcessCreationWatcher ThreadJob does not increment a heartbeat counter -- the liveness check cannot prove the watcher is delivering"
Add-Assertion "PS7 WMI: Start-Monitoring registers the watcher (persistent SYSTEM monitor)" ($gm -match 'function\s+Start-Monitoring[\s\S]{0,8000}?\$null = Register-ProcessCreationWatcher') "Start-Monitoring does NOT call Register-ProcessCreationWatcher -- the watcher was only registered in Enable-GodMode (one-shot, exits) so the persistent monitor's event-driven shell elevator is dead"
Add-Assertion "PS7 WMI: Unregister-ProcessCreationWatcher stops the ThreadJob + watcher (no leak)" ($gm -match 'function\s+Unregister-ProcessCreationWatcher[\s\S]{0,2000}?ProcessCreationWatcherJob[\s\S]{0,500}?Stop-Job' -and $gm -match 'function\s+Unregister-ProcessCreationWatcher[\s\S]{0,2000}?ProcessCreationWatcher\.Stop\(\)') "Unregister-ProcessCreationWatcher does not stop the ThreadJob + watcher -- re-registration / Disable-GodMode would leak the job and WMI subscription"

# --- 31. WMI watcher drain ArrayList-dequeue fix + CriticalProcs/shell guards
# (2026-07-20) ---
# Two residual bugs after the PS7 Register-ObjectEvent fix (section 30) kept
# interactive shells from elevating even though the watcher now registered:
# (1) the Start-Monitoring drain called $script:ProcessCreationQueue.TryDequeue
#     on a Synchronized ARRAYLIST (it has no TryDequeue method). The PS7
#     registration bug had MASKED this -- the queue was always empty so
#     TryDequeue was never reached. Once Register-ObjectEvent actually
#     populated the queue, TryDequeue threw every tick, was caught by the
#     loop's catch (5s sleep + retry), and the drain NEVER dequeued -- shells
#     were enqueued by the watcher but never elevated. Fix: [0]+RemoveAt(0)
#     (same pattern as GmProxyFeedbackQueue / IfeoNewAppQueue).
# (2) neither the event drain nor the 5s polling fallback had a CriticalProcs
#     skip (unlike the 15s periodic scan), so once the drain worked it would
#     in-place-swap explorer.exe/dwm.exe/conhost.exe to SYSTEM and break the
#     desktop. Fix: skip CriticalProcs EXCEPT the interactive shells
#     ($shellNames exempts them -- they are the watcher's targets) and skip
#     auto-excluded AppX stubs (Test-GmAutoExcluded), mirroring the periodic
#     scan guards at L6941/L6945.
Add-Assertion "Drain fix: NO TryDequeue on `$script:ProcessCreationQueue (ArrayList has no such method)" (-not $gm.Contains('ProcessCreationQueue.TryDequeue')) "WMI watcher drain still calls TryDequeue on the Synchronized ArrayList -- throws every tick once the queue is populated, caught by the loop catch, never drains (shells enqueued but never elevated)"
Add-Assertion "Drain fix: uses [0] + RemoveAt(0) (ArrayList-safe dequeue)" ($gm.Contains('$script:ProcessCreationQueue[0]') -and $gm.Contains('$script:ProcessCreationQueue.RemoveAt(0)')) "WMI watcher drain does not use the [0]+RemoveAt(0) ArrayList dequeue pattern -- the drain cannot remove queued shell PIDs"
Add-Assertion "Drain guard: `$shellNames defined in Start-Monitoring (cmd/powershell/pwsh/ISE)" ($gm.Contains('$shellNames = @("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")')) "Start-Monitoring missing `$shellNames -- the CriticalProcs-except-shells guard cannot exempt interactive shells"
Add-Assertion "Drain guard: event drain skips CriticalProcs except shells (`$shellNames -notcontains `$procBase)" ($gm.Contains('($CriticalProcs -contains $procBase) -and ($shellNames -notcontains $procBase)')) "WMI watcher drain has no CriticalProcs-except-shells guard -- explorer/dwm/conhost would be in-place-swapped to SYSTEM (desktop break)"
Add-Assertion "Drain guard: event drain skips auto-excluded apps (Test-GmAutoExcluded `$procBase)" ($gm.Contains('if (Test-GmAutoExcluded $procBase)')) "WMI watcher drain does not consult Test-GmAutoExcluded -- an auto-excluded AppX stub could be kill+relaunched (breaks the stub)"
Add-Assertion "Drain guard: 5s polling skips CriticalProcs except shells (`$shellNames -notcontains `$pollBase)" ($gm.Contains('($CriticalProcs -contains $pollBase) -and ($shellNames -notcontains $pollBase)')) "5s polling fallback has no CriticalProcs-except-shells guard -- explorer/dwm would be in-place-swapped when the watcher is down"
Add-Assertion "Drain guard: 5s polling skips auto-excluded apps (Test-GmAutoExcluded `$pollBase)" ($gm.Contains('if (Test-GmAutoExcluded $pollBase)')) "5s polling fallback does not consult Test-GmAutoExcluded -- an auto-excluded AppX stub could be kill+relaunched"

# --- 32. WMI watcher liveness heartbeat + unconditional 5s polling safety net
# (2026-07-20) ---
# Two belt-and-suspenders guarantees so interactive shells can NEVER be stranded by
# a dead/stuck WMI watcher (the failure mode that persisted across the prior PS7 +
# drain-fix rounds: watcher registered Active=$true but never delivered -> 5s polling
# was gated OFF -> shells stayed admin):
#   A. The 5s new-process polling fallback now runs UNCONDITIONALLY (throttled to ~3s),
#      regardless of $ProcessCreationWatcherActive. It was previously gated on
#      `-not $ProcessCreationWatcherActive`, so a registered-but-not-delivering watcher
#      disabled the only reliable (direct WMI query) elevation path for shells.
#      $lastElevatedPid dedup prevents double-elevation when both the watcher and
#      polling catch the same PID. Shells are caught within ~3s no matter what.
#   B. A 30s liveness heartbeat checks the watcher ThreadJob State; if it died (not
#      Running), the watcher is auto-re-registered to restore the ~1s fast path, and
#      the death is logged. Beats delta is logged for observability. The polling
#      safety net (A) means a dead watcher never strands shells even before the
#      heartbeat re-registers it.
Add-Assertion "Heartbeat A: 5s polling runs UNCONDITIONALLY (no -not ProcessCreationWatcherActive gate)" ($gm.Contains('if ($isSystem -and ((Get-Date) - $lastNewProcPoll -gt [TimeSpan]::FromSeconds(3)))')) "5s polling is still gated on -not $ProcessCreationWatcherActive -- a registered-but-not-delivering watcher would disable the only reliable shell-elevation path"
Add-Assertion "Heartbeat A: 5s polling throttle var `$lastNewProcPoll initialized" ($gm.Contains('$lastNewProcPoll = [datetime]::MinValue')) "Start-Monitoring missing $lastNewProcPoll -- the 3s polling throttle cannot work"
Add-Assertion "Heartbeat A: 5s polling sets `$lastNewProcPoll inside the gate" ($gm.Contains('$lastNewProcPoll = Get-Date')) "5s polling does not set $lastNewProcPoll inside the gate -- it would fire every iteration (WMI query storm)"
Add-Assertion "Heartbeat B: 30s liveness heartbeat check present (`$lastWatcherHealthCheck -gt 30s)" ($gm.Contains('((Get-Date) - $lastWatcherHealthCheck -gt [TimeSpan]::FromSeconds(30))')) "Start-Monitoring missing the 30s watcher liveness heartbeat -- a dead watcher would not be detected/re-registered"
Add-Assertion "Heartbeat B: heartbeat checks ThreadJob State -eq 'Running'" ($gm -match '\$script:ProcessCreationWatcherJob\.State -eq ''Running''') "heartbeat does not check the watcher ThreadJob State -- cannot detect a dead watcher"
Add-Assertion "Heartbeat B: heartbeat auto-re-registers a dead watcher (Register-ProcessCreationWatcher)" ($gm -match 'if \(\$script:ProcessCreationWatcherActive -and -not \$jobAlive\)[\s\S]{0,800}?Register-ProcessCreationWatcher') "heartbeat does not re-register a dead watcher -- the fast ~1s elevation path would stay down"
Add-Assertion "Heartbeat B: heartbeat reads `$script:ProcessCreationWatcherState.Beats (delivery proof)" ($gm.Contains('$script:ProcessCreationWatcherState.Beats')) "heartbeat does not read the watcher Beats counter -- no delivery-proof liveness signal"
Add-Assertion "Heartbeat B: `$lastWatcherHealthCheck + `$lastWatcherBeats initialized" ($gm.Contains('$lastWatcherHealthCheck = [datetime]::MinValue') -and $gm.Contains('$lastWatcherBeats = 0')) "Start-Monitoring missing $lastWatcherHealthCheck / $lastWatcherBeats -- the heartbeat timers cannot work"
Add-Assertion "Heartbeat: `$script:ProcessCreationWatcherJob + `$script:ProcessCreationWatcherState defined" ($gm.Contains('$script:ProcessCreationWatcherJob = $null') -and $gm.Contains('$script:ProcessCreationWatcherState = [hashtable]::Synchronized')) "watcher ThreadJob job + heartbeat state vars missing -- the liveness heartbeat cannot inspect/re-register the watcher"

# --- 33. On-demand SYSTEM shell (-LaunchShellAsSystem / menu [19]) + collision hardening (2026-07-21) ---
# Final improvement batch (the four proposals left on the table when the prior
# round was interrupted). Two were ALREADY landed in c6d3ba1 (Test-SystemProcessExists
# -InteractiveOnly Session-0 filter + Monitor-ElevateProcess Test-GmPlumbingShell
# consult); this section covers the remaining two + supporting hardening:
#   A. -LaunchShellAsSystem CLI flag + -Shell <cmd|powershell|pwsh|ise> (default
#      powershell) + menu [19]: an on-demand interactive SYSTEM shell launcher
#      (Start-SystemShell) that mirrors -LaunchTaskMgrAsSystem -- steals a
#      Session>0 SYSTEM token via CreateProcessWithTokenW (SeImpersonate only,
#      held by an interactive Administrator) and births the shell visible in the
#      active console session (whoami -> nt authority\system). Fails open to a
#      normal launch. Gated on the Built-in Administrator (RID-500).
#   B. Stop-NonSystemInstances gains a Test-GmPlumbingShell exemption so a purge
#      called from ANY path can never kill God Mode's own plumbing shells.
#   C. Monitor-ElevateProcess: an already-SYSTEM shell (the [19] on-demand launch)
#      is skipped via Test-PidIsSystem (no redundant SYSTEM->SYSTEM swap); Phase 1
#      + Phase 2 fallbacks for shells now kill ONLY the specific failed in-place
#      instance (not every non-SYSTEM sibling -- preserves the user's other
#      admin/SYSTEM shells) AND force the fallback SYSTEM shell VISIBLE (the
#      drain calls pass -HideWindow, which would hide a fallback shell).
Add-Assertion "Shell A: param block has [switch]`$LaunchShellAsSystem" ($gm.Contains('[switch]$LaunchShellAsSystem')) "param block missing -LaunchShellAsSystem switch"
Add-Assertion "Shell A: param block has [string]`$Shell = `"`" (default empty so non-shell CLIs are unaffected)" ($gm.Contains('[string]$Shell = ""')) "param block missing -Shell string param (or non-empty default would leak -Shell into every elevated relaunch)"
Add-Assertion "Shell A: auto-elevation forwards -LaunchShellAsSystem" ($gm.Contains('if ($LaunchShellAsSystem) { $ArgsString += " -LaunchShellAsSystem" }')) "auto-elevation does not forward -LaunchShellAsSystem -- a non-admin -LaunchShellAsSystem would drop the flag on re-elevation"
Add-Assertion "Shell A: auto-elevation forwards -Shell value (ContainsKey + non-empty)" ($gm.Contains('if ($PSBoundParameters.ContainsKey(''Shell'') -and $Shell) { $ArgsString += " -Shell $Shell" }')) "auto-elevation does not forward -Shell -- the chosen shell would default to powershell on re-elevation"
Add-Assertion "Shell A: PS7 preferred launcher forwards the -Shell string param" ($gm.Contains('if ($PSBoundParameters.ContainsKey(''Shell'') -and $Shell) { $ArgList += @("-Shell", $Shell) }')) "PS5->PS7 relaunch does not forward -Shell -- the switch loop only handles switches"
Add-Assertion "Shell A: Start-SystemShell function defined" ($gm.Contains('function Start-SystemShell {')) "Start-SystemShell missing -- the on-demand SYSTEM shell launcher is not implemented"
Add-Assertion "Shell A: Start-SystemShell validates the shell name (`$validShells cmd/powershell/pwsh/ise)" ($gm.Contains('$validShells = @("cmd","powershell","pwsh","ise")')) "Start-SystemShell does not validate the shell name -- an unknown shell would launch garbage"
Add-Assertion "Shell A: Start-SystemShell resolves cmd.exe (System32)" ($gm.Contains('Join-Path $env:WINDIR "System32\cmd.exe"')) "Start-SystemShell does not resolve cmd.exe"
Add-Assertion "Shell A: Start-SystemShell resolves powershell.exe (WindowsPowerShell v1.0)" ($gm.Contains('Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"')) "Start-SystemShell does not resolve powershell.exe"
Add-Assertion "Shell A: Start-SystemShell resolves pwsh.exe (PowerShell 7 + C:\ fallback)" ($gm.Contains('Join-Path $env:ProgramFiles "PowerShell\7\pwsh.exe"') -and $gm.Contains('"C:\Program Files\PowerShell\7\pwsh.exe"')) "Start-SystemShell does not resolve pwsh.exe with a fallback"
Add-Assertion "Shell A: Start-SystemShell ensures seclogon running (CreateProcessWithTokenW)" ($gm -match 'function\s+Start-SystemShell\s*\{[\s\S]{0,5000}?Get-Service -Name seclogon') "Start-SystemShell does not ensure seclogon -- CreateProcessWithTokenW could silently fail"
Add-Assertion "Shell A: Start-SystemShell launches VISIBLE via CreateProcessFromToken (`$false)" ($gm.Contains('[TokenOps]::CreateProcessFromToken($systemPid, $shellExe, $shellExe, $false)')) "Start-SystemShell does not launch the shell visible -- the on-demand SYSTEM shell would be invisible"
Add-Assertion "Shell A: Start-SystemShell falls back to a normal Start-Process on SYSTEM-token failure" ($gm.Contains('Start-Process $shellExe')) "Start-SystemShell does not fail-open to a normal launch -- a SYSTEM-token failure would leave the user with no shell"
Add-Assertion "Shell A: CLI handler -LaunchShellAsSystem gates on the Built-in Administrator" ($gm -match 'if \(\$LaunchShellAsSystem\) \{[\s\S]{0,600}?Test-BuiltInAdmin') "CLI -LaunchShellAsSystem does not gate on the Built-in Administrator -- a non-RID-500 admin could launch a SYSTEM shell"
Add-Assertion "Shell A: CLI handler calls Start-SystemShell -ShellName `$Shell" ($gm -match 'if \(\$LaunchShellAsSystem\) \{[\s\S]{0,900}?Start-SystemShell -ShellName \$Shell') "CLI -LaunchShellAsSystem does not call Start-SystemShell"
Add-Assertion "Shell A: menu offers [19] LAUNCH SHELL AS SYSTEM" ($gm.Contains('[19] LAUNCH SHELL AS SYSTEM')) "menu [19] LAUNCH SHELL AS SYSTEM missing"
Add-Assertion "Shell A: menu switch case 19 calls Start-SystemShell -ShellName `$shellName" ($gm -match '"19" \{[\s\S]{0,1500}?Start-SystemShell -ShellName \$shellName') "menu switch case 19 does not call Start-SystemShell"
Add-Assertion "Shell A: menu [19] sub-prompt offers cmd/powershell/pwsh/ise (1-4)" ($gm.Contains('Select shell (1-4, default 2)')) "menu [19] sub-prompt missing -- the user cannot pick the shell type"
Add-Assertion "Shell B: Stop-NonSystemInstances exempts God Mode plumbing (Test-GmPlumbingShell)" ($gm -match 'function\s+Stop-NonSystemInstances\s*\{[\s\S]{0,1500}?Test-GmPlumbingShell -ProcessId \$p\.ProcessId') "Stop-NonSystemInstances does not exempt God Mode plumbing shells -- a purge could kill the monitor/watchdog plumbing"
Add-Assertion "Shell C: Test-PidIsSystem helper defined (per-PID SYSTEM check)" ($gm.Contains('function Test-PidIsSystem {')) "Test-PidIsSystem missing -- Monitor-ElevateProcess cannot skip an already-SYSTEM shell"
Add-Assertion "Shell C: Test-PidIsSystem is fail-open (ProcessId -le 0 -> return `$false)" ($gm -match 'function Test-PidIsSystem \{[\s\S]{0,900}?if \(\$ProcessId -le 0\) \{ return \$false \}') "Test-PidIsSystem is not fail-open on ProcessId -le 0 -- a bad PID could throw"
Add-Assertion "Shell C: Monitor-ElevateProcess skips an already-SYSTEM shell (Test-PidIsSystem consult)" ($gm.Contains('Test-PidIsSystem -ProcessId $ProcessId')) "Monitor-ElevateProcess does not consult Test-PidIsSystem -- an already-SYSTEM shell (the [19] launch) would get a redundant SYSTEM->SYSTEM swap"
Add-Assertion "Shell C: Phase 1 shells use a targeted kill (Stop-Process -Id `$ProcessId), not a blanket purge" ($gm.Contains('$launchHidden = [bool]$HideWindow -and -not $isInteractiveShell') -and $gm.Contains('[TokenOps]::CreateProcessAsSystem($systemPid, $Path, $cmdLine, $launchHidden)')) "Phase 1 does not force shells visible + targeted kill -- a fallback SYSTEM shell would be hidden and the user's other admin shells killed"
Add-Assertion "Shell C: Phase 1/2 targeted shell kill appears on BOTH fallback paths (>= 2)" (([regex]::Matches($gm, 'if \(\$isInteractiveShell\) \{[\s\S]{0,300}?Stop-Process -Id \$ProcessId -Force')).Count -ge 2) "Phase 1/2 targeted shell kill is not on both fallback paths -- one path still blanket-purges the user's other shells"
Add-Assertion "Shell C: Phase 2 shells forced visible (`$svcHidden) + targeted kill" ($gm.Contains('$svcHidden = [bool]$HideWindow -and -not $isInteractiveShell') -and $gm.Contains('Start-ProcessWithService -Path $Path -Arguments $Arguments -HideWindow:$svcHidden')) "Phase 2 does not force shells visible + targeted kill -- a service-fallback SYSTEM shell would be hidden"
Add-Assertion "Shell A: Test-GmPlumbingShell `$gmFlags includes -LaunchShellAsSystem (CLI launcher protected)" ($gm.Contains("'-LaunchShellAsSystem'")) "Test-GmPlumbingShell `$gmFlags missing -LaunchShellAsSystem -- the on-demand CLI launcher could be in-place token-swapped mid-launch"

# --- 34. Shell auto-elevation after [7]+reboot: flap-proof stealth task +
# Phase 0 verify/fallback + drain retry + Start-SystemShell verify/inactive (2026-07-21) ---
# The user's core requirement: after [7] Enable + reboot, running cmd/powershell/
# pwsh/ISE normally -> whoami shows nt authority\system (the monitor's in-place
# token swap, NOT the manual [19]). Three runtime gaps that left whoami -> admin:
#   A. Boot flapping: Register-StealthTask unregistered ALL stealth tasks whenever
#      none was momentarily "Running" -- concurrent -ToggleOn layers at boot killed
#      Start-Monitoring mid-startup -> no stable monitor -> shells never elevated.
#      Flap-proof fix: if a stealth task EXISTS in ANY state, nudge it (never
#      unregister from here); only create when none exists.
#   B. Silent/hard in-place swap failure: ReplaceProcessTokenForPid can report
#      STATUS_SUCCESS yet leave the shell admin (whoami -> admin), OR return
#      false outright. Phase 0 now VERIFIES the swap for interactive shells
#      (Test-PidIsSystem after a 300ms settle) and on EITHER failure mode LEAVES
#      the shell as admin (no kill) -- Phase 1/2 would birth an invisible
#      Session-0 shell + kill the visible one (the "it kill shell that is non
#      admin and still fails to elevate" / "same problem and same issue"
#      symptom). The 15s periodic scan + WMI watcher retry Phase 0 on the next
#      tick. Non-shell apps keep the fast return.
#   C. No retry: the lastElevatedPid dedup marked a shell before elevation; if all
#      phases failed, it was never retried. The drains now remove the PID on
#      $false for shells so the next 5s polling tick retries.
# Plus the two Start-SystemShell suggestions: post-launch SYSTEM verify (before/
# after PID snapshot + Test-PidIsSystem) + a "God Mode inactive" best-effort
# warning (Test-GodModeActive). All additive + fail-open; section 33 intact.
Add-Assertion "ShellAuto: Test-GodModeActive helper defined" ($gm.Contains('function Test-GodModeActive')) "Test-GodModeActive missing -- Start-SystemShell cannot warn when God Mode is inactive"
$tgmaMatch = [regex]::Match($gm, '(?s)function\s+Test-GodModeActive\s*\{(.*?)\nfunction\s+Test-SystemContext\s*\{')
$tgmaBody = if ($tgmaMatch.Success) { $tgmaMatch.Groups[1].Value } else { "" }
Add-Assertion "ShellAuto: Test-GodModeActive body extractable" ($tgmaMatch.Success) "could not isolate Test-GodModeActive body"
if ($tgmaMatch.Success) {
    Add-Assertion "ShellAuto: Test-GodModeActive reads the flag (GodModeFlagRegPath + GodModeFlagRegName -eq 1)" ($tgmaBody.Contains('$GodModeFlagRegPath') -and $tgmaBody.Contains('$GodModeFlagRegName') -and $tgmaBody.Contains('-eq 1')) "Test-GodModeActive does not read the GodMode flag -- cannot report active state"
    Add-Assertion "ShellAuto: Test-GodModeActive is fail-open (catch/missing -> false)" ($tgmaBody.Contains('return $false')) "Test-GodModeActive is not fail-open -- a registry error could throw"
}
Add-Assertion "ShellAuto: Start-SystemShell warns when God Mode inactive (Test-GodModeActive consult)" ($gm -match 'function\s+Start-SystemShell\s*\{[\s\S]{0,6000}?\(Test-GodModeActive\)') "Start-SystemShell does not warn when God Mode is inactive -- the on-demand SYSTEM shell's best-effort expectation is unset"
Add-Assertion "ShellAuto: Start-SystemShell snapshots PIDs before launch + resolves shell base name" ($gm.Contains('$beforePids') -and $gm.Contains('$shellBaseName')) "Start-SystemShell does not snapshot before-PIDs / resolve the shell base name -- cannot identify the new child for verify"
Add-Assertion "ShellAuto: Start-SystemShell verifies the new child is SYSTEM (Test-PidIsSystem -ProcessId newShellPid)" ($gm.Contains('Test-PidIsSystem -ProcessId $newShellPid')) "Start-SystemShell does not verify the new child is SYSTEM -- a silent de-elevation would look like success"
Add-Assertion "ShellAuto: Start-SystemShell warns when verify fails (could NOT verify SYSTEM)" ($gm.Contains('could NOT verify SYSTEM')) "Start-SystemShell does not warn on verify failure -- the user would not know to run whoami to confirm"
$stealthMatch = [regex]::Match($gm, '(?s)function\s+Register-StealthTask\s*\{(.*?)\nfunction\s+Unregister-StealthTask\s*\{')
$stealthBody = if ($stealthMatch.Success) { $stealthMatch.Groups[1].Value } else { "" }
Add-Assertion "ShellAuto: Register-StealthTask body extractable" ($stealthMatch.Success) "could not isolate Register-StealthTask body"
if ($stealthMatch.Success) {
    Add-Assertion "ShellAuto: Register-StealthTask flap-proof -- existing task nudged (Start-ScheduledTask -TaskName nudge.TaskName)" ($stealthBody.Contains('Start-ScheduledTask -TaskName $nudge.TaskName')) "Register-StealthTask does not nudge an existing stealth task -- a transitional-state task would be recreated (flap)"
    Add-Assertion "ShellAuto: Register-StealthTask flap-proof -- NO Unregister-StealthTask call inside the body" (-not ($stealthBody -match '(?m)^\s*Unregister-StealthTask\b')) "Register-StealthTask still calls Unregister-StealthTask -- a concurrent -ToggleOn at boot would kill a just-started monitor (flap -> shells never elevate after reboot)"
    Add-Assertion "ShellAuto: Register-StealthTask flap-proof -- Running-state skip preserved" ($stealthBody.Contains('State -eq ''Running''')) "Register-StealthTask lost the Running-state skip -- an already-running monitor could be touched"
    Add-Assertion "ShellAuto: Register-StealthTask creates a new task only when none exists" ($stealthBody.Contains('$taskName = $GodModeTaskPrefix')) "Register-StealthTask does not gate the create path on no-existing-task -- could accumulate stealth tasks"
    # Quoting regression (2026-07-21 VM crash): the stealth task -Argument MUST
    # backtick-QUOTE the script path inside the double-quoted -Argument so -File
    # gets a literal quoted path. A backtick-DOLLAR-quote (emits a literal `$ +
    # terminates the outer string early) leaked `$GodModeInstallScript + -Launch
    # as a positional arg -> New-ScheduledTaskAction threw "a positional
    # parameter cannot be found" -> uncaught trap killed Enable-GodMode -> no
    # stealth monitor task -> [NO LIVE MONITOR LOOP] -> shells stayed admin.
    # Source-level tests missed it (none execute New-ScheduledTaskAction); this
    # asserts the exact byte pattern so it can never regress.
    Add-Assertion "ShellAuto: Register-StealthTask -Argument backtick-QUOTE-escapes the script path (literal `"`$GodModeInstallScript`" inside -File)" ($stealthBody.Contains('`"$GodModeInstallScript`"')) "Register-StealthTask -Argument does not backtick-quote the script path -- -File would not receive a literal quoted path"
    Add-Assertion "ShellAuto: Register-StealthTask -Argument has NO broken backtick-DOLLAR-quote (the positional-parameter trap that killed Enable-GodMode)" (-not $stealthBody.Contains('`$"$GodModeInstallScript`$"')) "Register-StealthTask -Argument uses backtick-DOLLAR-quote around `$GodModeInstallScript -- that emits a literal `$ and terminates the outer string early, leaking -Launch as a positional arg -> New-ScheduledTaskAction throws 'a positional parameter cannot be found' (uncaught trap -> no stealth monitor -> shells stay admin)"
    Add-Assertion "ShellAuto: Register-StealthTask action pins -WorkingDirectory (ERROR_DIRECTORY 267 fix)" ($stealthBody.Contains('-WorkingDirectory $GodModeInstallDir')) "Register-StealthTask action missing -WorkingDirectory `$GodModeInstallDir -- a SYSTEM task with no WorkingDirectory can die with error 267 (ERROR_DIRECTORY) -> no monitor loop -> shells stay admin"
}
# The first-hop window is 4000 (not 2000) because the Phase 0 explanatory
# comments (SeTcbPrivilege rationale + the verify/fail-stop rationale) grew the
# header->isInteractiveShell distance to ~2017 bytes; the lazy quantifier still
# binds to the FIRST (Phase 0) occurrence -- Phase 1's isInteractiveShell sits
# at ~6474 bytes, far beyond the window -- so the assertion stays specific.
Add-Assertion "ShellAuto: Phase 0 verifies the in-place swap for shells (Test-PidIsSystem within Phase 0)" ($gm -match '# --- Phase 0:[\s\S]{0,4000}?\$isInteractiveShell[\s\S]{0,400}?Test-PidIsSystem -ProcessId \$ProcessId') "Phase 0 does not verify the in-place swap for shells -- a silent NtSetInformationProcess success would leave whoami -> admin with no fallback"
Add-Assertion "ShellAuto: Phase 0 settle sleep before the verify (Start-Sleep -Milliseconds 300)" ($gm -match '# --- Phase 0:[\s\S]{0,4000}?Start-Sleep -Milliseconds 300') "Phase 0 does not settle before verifying -- the owner query could race the token swap"
Add-Assertion "ShellAuto: Phase 0 silent-failure LEAVES the shell as admin (no kill, no Phase 1/2 fall-through)" ($gm.Contains('Phase 0 silent-failure for interactive shell') -and $gm.Contains('leaving as admin (not killing -- Phase 1/2 would birth an invisible Session-0 shell + kill this one).')) "Phase 0 silent-failure still falls through to Phase 1/2 -- an invisible Session-0 shell would be born + the visible shell killed (the 'it kill shell' symptom)"
Add-Assertion "ShellAuto: Phase 0 hard-failure LEAVES the shell as admin (no kill, no Phase 1/2 fall-through)" ($gm.Contains('Phase 0 failed for interactive shell') -and $gm.Contains('leaving as admin (not killing -- Phase 1/2 would birth an invisible Session-0 shell + kill this one).')) "Phase 0 hard-failure still falls through to Phase 1/2 -- an invisible Session-0 shell would be born + the visible shell killed (the 'it kill shell' symptom)"
Add-Assertion "ShellAuto: Phase 0 NO LONGER falls through to born-as-SYSTEM on silent swap failure (old kill+invisible-shell path removed)" (-not $gm.Contains('falling back to born-as-SYSTEM (Phase 1) so the shell is SYSTEM')) "Phase 0 still contains the old 'falling back to born-as-SYSTEM (Phase 1)' fall-through -- the kill+invisible-Session-0-shell regression returned"
Add-Assertion "ShellAuto: Phase 0 keeps the fast return for NON-shells (in-place token replacement, no verify)" ($gm.Contains('Monitor elevated: $procName PID=$ProcessId (in-place token replacement)')) "Phase 0 lost the non-shell fast return -- per-app latency would be added to every elevation"
Add-Assertion "ShellAuto: WMI watcher drain captures the elevation result (meResult)" ($gm.Contains('$meResult = Monitor-ElevateProcess -Path $path -Arguments $arguments -ProcessId $evt.ProcessId -HideWindow')) "WMI watcher drain does not capture the elevation result -- cannot retry on failure"
Add-Assertion "ShellAuto: WMI watcher drain retries shells on failure (lastElevatedPid.Remove evt.ProcessId + shellNames procBase)" ($gm.Contains('$lastElevatedPid.Remove($evt.ProcessId)') -and $gm.Contains('$shellNames -contains $procBase')) "WMI watcher drain does not retry shells on failure -- a transient no-SYSTEM-token strands the shell as admin forever"
Add-Assertion "ShellAuto: 5s polling drain captures the elevation result (meResult)" ($gm.Contains('$meResult = Monitor-ElevateProcess -Path $path -Arguments $arguments -ProcessId $proc.ProcessId -HideWindow')) "5s polling drain does not capture the elevation result -- cannot retry on failure"
Add-Assertion "ShellAuto: 5s polling drain retries shells on failure (lastElevatedPid.Remove proc.ProcessId + shellNames pollBase)" ($gm.Contains('$lastElevatedPid.Remove($proc.ProcessId)') -and $gm.Contains('$shellNames -contains $pollBase')) "5s polling drain does not retry shells on failure -- a transient failure strands the shell as admin forever"

# --- 35. Option-11 (Export-GodModeLogs) monitor/elevation-path diagnostics (2026-07-21) ---
# The user reported "it still fails -- no SYSTEM privileges at powershell/cmd" after
# [7]+reboot and asked for more debug in option 11 "so we dont go blind". The dump was
# gmproxy/IFEO-centric but the SHELL elevation path is MONITOR-centric
# (Start-Monitoring -> in-place token swap), and option 11 only read the ADMIN user's
# $env:TEMP logs -- the monitor runs as SYSTEM and logs to C:\Windows\Temp, which was
# NEVER collected. Plus no live task/process/flag/token-source state was captured, so
# the dump could not show whether the monitor was even running. This section asserts
# the new SYSTEM-TEMP LOGS collection + the Get-GodModeElevationPathDiagnostics helper
# (flag, scheduled tasks + LastTaskResult, live monitor process, shell owner ground
# truth, SYSTEM token source, seclogon, critical-procs reference, monitor marker scan)
# are present and wired into Export-GodModeLogs. Additive; sections 1-34 intact.
Add-Assertion "Opt11: `$GodModeSystemTempLogCandidates var defined (SYSTEM-temp monitor log paths)" ($gm.Contains('$GodModeSystemTempLogCandidates') -and $gm.Contains('C:\Windows\Temp\DNS_Lockdown_Enterprise.log')) "Export-GodModeLogs has no SYSTEM-temp log candidate list -- the monitor's SYSTEM-context logs are never collected (the blind spot)"
Add-Assertion "Opt11: Get-GodModeElevationPathDiagnostics helper defined" ($gm.Contains('function Get-GodModeElevationPathDiagnostics')) "Get-GodModeElevationPathDiagnostics missing -- option 11 has no monitor/elevation-path section"
Add-Assertion "Opt11: Export-GodModeLogs calls Get-GodModeElevationPathDiagnostics" ($gm -match 'function Export-GodModeLogs\s*\{[\s\S]*?Get-GodModeElevationPathDiagnostics') "Export-GodModeLogs does not call Get-GodModeElevationPathDiagnostics -- the monitor section is not wired into option 11"
Add-Assertion "Opt11: MONITOR / SHELL-ELEVATION PATH section header present" ($gm.Contains('===== MONITOR / SHELL-ELEVATION PATH =====')) "monitor/elevation-path section header missing"
Add-Assertion "Opt11: SYSTEM-TEMP LOGS section header present" ($gm.Contains('===== SYSTEM-TEMP LOGS (monitor as SYSTEM) =====')) "SYSTEM-TEMP LOGS section header missing -- the monitor's SYSTEM-context logs are not collected"
$epdMatch = [regex]::Match($gm, '(?s)function\s+Get-GodModeElevationPathDiagnostics\s*\{(.*?)\nfunction\s+Export-GodModeLogs\s*\{')
$epdBody = if ($epdMatch.Success) { $epdMatch.Groups[1].Value } else { "" }
Add-Assertion "Opt11: Get-GodModeElevationPathDiagnostics body extractable" ($epdMatch.Success) "could not isolate Get-GodModeElevationPathDiagnostics body"
if ($epdMatch.Success) {
    Add-Assertion "Opt11: diagnostics reads the God Mode flag (Test-GodModeActive)" ($epdBody.Contains('Test-GodModeActive')) "diagnostics does not read the God Mode flag -- cannot report active state"
    Add-Assertion "Opt11: diagnostics resolves the SYSTEM token source (Find-SystemProcessCandidate)" ($epdBody.Contains('Find-SystemProcessCandidate')) "diagnostics does not call Find-SystemProcessCandidate -- cannot report token-source availability"
    Add-Assertion "Opt11: diagnostics enumerates scheduled tasks + LastTaskResult (Get-ScheduledTaskInfo)" ($epdBody.Contains('Get-ScheduledTaskInfo') -and $epdBody.Contains('LastTaskResult')) "diagnostics does not dump task LastTaskResult -- a failed monitor launch would be invisible"
    Add-Assertion "Opt11: diagnostics detects a live monitor loop (Win32_Process + GodMode.ps1 -Launch)" ($epdBody.Contains('Get-CimInstance Win32_Process') -and $epdBody.Contains('GodMode.ps1') -and $epdBody.Contains('-Launch')) "diagnostics does not detect a live monitor process -- cannot tell if the monitor is running"
    Add-Assertion "Opt11: diagnostics reports shell owner identity (Invoke-CimMethod GetOwner)" ($epdBody.Contains('Invoke-CimMethod') -and $epdBody.Contains('GetOwner')) "diagnostics does not report shell owner identity -- cannot prove admin vs SYSTEM (ground truth)"
    Add-Assertion "Opt11: diagnostics checks seclogon (Phase 1 fallback dependency)" ($epdBody.Contains('Get-Service -Name seclogon')) "diagnostics does not check seclogon -- Phase 1 CreateProcessWithTokenW dependency is invisible"
    Add-Assertion "Opt11: diagnostics scans logs for monitor markers (Select-String + Monitor-ElevateProcess)" ($epdBody.Contains('Select-String') -and $epdBody.Contains('Monitor-ElevateProcess')) "diagnostics does not scan logs for monitor markers -- monitor activity stays buried in a big log"
    Add-Assertion "Opt11: diagnostics scans SYSTEM-temp candidate logs (`$GodModeSystemTempLogCandidates)" ($epdBody.Contains('$GodModeSystemTempLogCandidates')) "diagnostics does not scan the SYSTEM-temp candidates -- monitor-as-SYSTEM activity is missed"
    Add-Assertion "Opt11: diagnostics is best-effort (try/catch around the section probes)" ($epdBody -match 'catch\s*\{\s*\$sec \+=') "diagnostics is not best-effort -- a single probe failure could abort the whole section"
    Add-Assertion "Opt11: diagnostics answers the 'critical process' question (CriticalProcs + shellNames reference)" ($epdBody.Contains('CriticalProcs') -and $epdBody.Contains('shellNames')) "diagnostics does not explain the CriticalProcs/shellNames exemption -- the 'why is my shell critical' question stays unanswered"
    Add-Assertion "Opt11: diagnostics reports dump context (IsSystem + DumpTEMP)" ($epdBody.Contains('IsSystem') -and $epdBody.Contains('DumpTEMP')) "diagnostics does not report the dump context -- cannot tell which user-temp the dump read"
}
Add-Assertion "Opt11: SYSTEM-TEMP collection is best-effort (Test-Path guarded foreach loop)" ($gm -match 'foreach \(\$stPath in \$GodModeSystemTempLogCandidates\)[\s\S]{0,400}?Test-Path \$stPath') "SYSTEM-TEMP log collection is not Test-Path guarded -- an inaccessible path could throw"

# --- 36. SYSTEM-context crash fixes: read-only $PID collision + empty-Desktop
# Join-Path (2026-07-21) ---
# The section-35 option-11 diagnostics finally exposed the two root-cause
# uncaught traps that left shells admin after [7]+reboot (whoami -> admin):
#   A. A foreach loop variable named $pid in Get-NonSystemProcessesParallel
#      (chunk + map loops) and Start-Monitoring PID cleanup -- $pid is the
#      read-only automatic $PID (PS vars are case-insensitive, so $pid IS
#      $PID), so the loop assignment throws "Cannot overwrite variable PID
#      because it is read-only or a constant". This killed the SYSTEM aggressive
#      elevation (Invoke-ExistingProcessElevation) AND the monitor -Launch
#      startup (Start-Monitoring -> Invoke-ExistingProcessElevation -> here),
#      leaving NO live monitor loop (stealth task LastTaskResult=2147942667,
#      [NO LIVE MONITOR LOOP]) -> interactive shells were never in-place
#      elevated. Renamed the loop variable to $procId in all three sites.
#   B. [Environment]::GetFolderPath("Desktop") returns "" as SYSTEM (no user
#      profile); Join-Path "" threw "Cannot bind argument to parameter 'Path'
#      ..." UNCAUGHT in Install-ProcessHook (build-log, caught -> returns
#      false) + Enable-GodMode (abort-log, UNCAUGHT trap), killing every
#      scheduled-task -ToggleOn relaunch. Fixed via a Get-GodModeLogDir helper
#      (Desktop -> $env:TEMP -> C:\Windows\Temp, all guarded) + try/catch
#      around the abort-log. Additive; sections 1-35 intact.
Add-Assertion "BugFix: no foreach loop over `$pid anywhere -- read-only `$PID collision eliminated" ($gm -notmatch 'foreach \(\$pid\b') "a foreach loop over `$pid remains -- `$pid is the read-only automatic `$PID; the loop assignment throws 'Cannot overwrite variable PID' (killed the SYSTEM aggressive elevation + monitor -Launch startup)"
$gnspMatch = [regex]::Match($gm, '(?s)function\s+Get-NonSystemProcessesParallel\s*\{(.*?)\nfunction\s+Register-ProcessCreationWatcher\s*\{')
$gnspBody = if ($gnspMatch.Success) { $gnspMatch.Groups[1].Value } else { "" }
Add-Assertion "BugFix: Get-NonSystemProcessesParallel body extractable" ($gnspMatch.Success) "could not isolate Get-NonSystemProcessesParallel body"
if ($gnspMatch.Success) {
    Add-Assertion "BugFix: Get-NonSystemProcessesParallel chunk loop uses `$procId (not `$pid)" ($gnspBody.Contains('foreach ($procId in $pids)')) "Get-NonSystemProcessesParallel chunk loop still uses `$pid -- the SYSTEM aggressive elevation + monitor -Launch startup would crash"
    Add-Assertion "BugFix: Get-NonSystemProcessesParallel map loop uses `$procId (not `$pid)" ($gnspBody.Contains('foreach ($procId in $nonSystemPids)')) "Get-NonSystemProcessesParallel map loop still uses `$pid -- PID-to-instance mapping would crash"
    Add-Assertion "BugFix: Get-NonSystemProcessesParallel carries the read-only-`$PID warning comment" ($gnspBody -match 'read-only automatic') "Get-NonSystemProcessesParallel missing the `$pid-is-`$PID warning -- the bug could be reintroduced"
}
$smMatch = [regex]::Match($gm, '(?s)function\s+Start-Monitoring\s*\{(.*?)\nfunction\s+Enable-GodMode\s*\{')
$smBody = if ($smMatch.Success) { $smMatch.Groups[1].Value } else { "" }
Add-Assertion "BugFix: Start-Monitoring body extractable" ($smMatch.Success) "could not isolate Start-Monitoring body"
if ($smMatch.Success) {
    Add-Assertion "BugFix: Start-Monitoring PID cleanup uses `$procId (not `$pid)" ($smBody.Contains('foreach ($procId in $oldPids)')) "Start-Monitoring PID cleanup still uses `$pid -- faults the monitor loop every 2 min (loop catch -> 5s recovery -> skips resurrection-killer + periodic elevation that tick)"
}
Add-Assertion "BugFix: Get-GodModeLogDir helper defined (SYSTEM-safe log-dir resolver)" ($gm.Contains('function Get-GodModeLogDir')) "Get-GodModeLogDir missing -- the empty-Desktop-as-SYSTEM Join-Path crash has no fix"
$glmMatch = [regex]::Match($gm, '(?s)function\s+Get-GodModeLogDir\s*\{(.*?)\nfunction\s+Export-ElevationDiagnostics\s*\{')
$glmBody = if ($glmMatch.Success) { $glmMatch.Groups[1].Value } else { "" }
Add-Assertion "BugFix: Get-GodModeLogDir body extractable" ($glmMatch.Success) "could not isolate Get-GodModeLogDir body"
if ($glmMatch.Success) {
    Add-Assertion "BugFix: Get-GodModeLogDir prefers the Desktop first (admin finds the logs)" ($glmBody.Contains('GetFolderPath("Desktop")')) "Get-GodModeLogDir does not prefer the Desktop -- admin logs would not land where the user can find them"
    Add-Assertion "BugFix: Get-GodModeLogDir falls back to `$env:TEMP (SYSTEM temp)" ($glmBody.Contains('$env:TEMP')) "Get-GodModeLogDir has no `$env:TEMP fallback -- SYSTEM would still get an empty Desktop"
    Add-Assertion "BugFix: Get-GodModeLogDir final fallback C:\Windows\Temp" ($glmBody.Contains('C:\Windows\Temp')) "Get-GodModeLogDir has no C:\Windows\Temp final fallback -- a no-profile no-temp context would still return empty"
}
Add-Assertion "BugFix: Install-ProcessHook build-log uses Get-GodModeLogDir (not raw Desktop)" ($gm -match 'function\s+Install-ProcessHook\s*\{[\s\S]{0,2000}?\$BuildLog = Join-Path \(Get-GodModeLogDir\)') "Install-ProcessHook build-log still uses GetFolderPath(Desktop) -- crashes as SYSTEM (empty Desktop) before the build/inject"
$iphMatch = [regex]::Match($gm, '(?s)function\s+Install-ProcessHook\s*\{(.*?)\nfunction\s+Uninstall-ProcessHook\s*\{')
$iphBody = if ($iphMatch.Success) { $iphMatch.Groups[1].Value } else { "" }
Add-Assertion "BugFix: Install-ProcessHook body extractable" ($iphMatch.Success) "could not isolate Install-ProcessHook body"
if ($iphMatch.Success) {
    Add-Assertion "BugFix: Install-ProcessHook has no raw GetFolderPath(Desktop) call left" (-not ($iphBody -match 'GetFolderPath\("Desktop"\)')) "Install-ProcessHook still calls GetFolderPath(Desktop) -- the SYSTEM-context empty-Path crash site remains"
}
Add-Assertion "BugFix: Export-GodModeLogs build-log uses Get-GodModeLogDir" ($gm -match 'function\s+Export-GodModeLogs\s*\{[\s\S]{0,8000}?\$BuildLog = Join-Path \(Get-GodModeLogDir\)') "Export-GodModeLogs build-log still uses GetFolderPath(Desktop) -- read/write path mismatch with Install-ProcessHook"
Add-Assertion "BugFix: Export-GodModeLogs destination default is Get-GodModeLogDir (SYSTEM-safe)" ($gm.Contains('param([string]$DestinationFolder = (Get-GodModeLogDir))')) "Export-GodModeLogs destination default still uses GetFolderPath(Desktop) -- a SYSTEM-context dump would crash at Join-Path"
Add-Assertion "BugFix: Export-ElevationDiagnostics destination default is Get-GodModeLogDir" ($gm -match 'function\s+Export-ElevationDiagnostics\s*\{[\s\S]{0,300}?\$DestinationFolder = \(Get-GodModeLogDir\)') "Export-ElevationDiagnostics destination default still uses GetFolderPath(Desktop)"
$egmMatch = [regex]::Match($gm, '(?s)function\s+Enable-GodMode\s*\{(.*?)\nfunction\s+Disable-GodMode\s*\{')
$egmBody = if ($egmMatch.Success) { $egmMatch.Groups[1].Value } else { "" }
Add-Assertion "BugFix: Enable-GodMode body extractable" ($egmMatch.Success) "could not isolate Enable-GodMode body"
if ($egmMatch.Success) {
    Add-Assertion "BugFix: Enable-GodMode abort-log uses Get-GodModeLogDir (not raw Desktop)" ($egmBody.Contains('Join-Path (Get-GodModeLogDir) "GodMode_CompilerError.log"')) "Enable-GodMode abort-log still uses GetFolderPath(Desktop) -- crashes UNCAUGHT as SYSTEM (the reported -ToggleOn killer)"
    Add-Assertion "BugFix: Enable-GodMode abort-log is try/catch guarded (no uncaught trap)" ($egmBody.Contains('Abort-log write failed')) "Enable-GodMode abort-log is not try/catch guarded -- a logging failure still kills the -ToggleOn relaunch with an uncaught trap"
    Add-Assertion "BugFix: Enable-GodMode has no raw GetFolderPath(Desktop) call left" (-not ($egmBody -match 'GetFolderPath\("Desktop"\)')) "Enable-GodMode still calls GetFolderPath(Desktop) -- the SYSTEM-context uncaught-trap site remains"
}

# --- 37. Admin-tool SYSTEM elevation + option-11 donor/Detector-B diagnostics (2026-07-21) ---
# Three additive, non-destructive features (no gmproxy.c change -- PowerShell-only, no
# driver rebuild; no kill/TerminateProcess path anywhere):
#   (1) Admin tools mmc.exe (hosts ALL .msc snap-ins -- services/eventvwr/compmgmt/
#       gpedit/secpol/lusrmgr/certmgr/diskmgmt/taskschd/...), perfmon.exe, resmon.exe.
#       STRATEGY FLIP (2026-07-21): these are NOT IFEO-hooked. mmc.exe silently refuses
#       SYSTEM (exits 0, no window) AND gmproxy's IFEO-bypass RENAME breaks MMC snap-in
#       loading EVEN as the current user (COM/snap-in/resource lookup uses the exe name ->
#       a renamed gmproxy_<pid>_mmc.exe can't load snap-ins -> exit 0, no window, USER-
#       AUTOEXCLUDE mode a VM log dump proved). So mmc/perfmon/resmon are DROPPED from
#       the IFEO seed entirely, added to the $GmCriticalIfeoExclude denylist (auto-
#       populate never hooks them), pre-seeded in the Detector B store with reason 'G'
#       (so the monitor + gmhook skip SYSTEM-birth), and any prior gmproxy Debugger hook
#       is removed on re-enable. They launch NATIVELY as the admin user from launch #1.
#       They STAY in the Uninstall-ProcessHook legacy list (belt-and-suspenders cleanup)
#       + the Export-GodModeLogs IFEO-status check (the dump reports their hook status).
#   (2) Option-11 SYSTEM token DONOR INVENTORY: Get-GodModeElevationPathDiagnostics probes
#       each Session>0 SYSTEM process with the read-only [TokenOps]::TestOpenProcess (the
#       SAME probe Find-SystemProcessCandidate uses -- opens PROCESS_QUERY_LIMITED_INFORMATION,
#       duplicates the token, closes every handle; NO kill, NO retained handle) and tags it
#       [OPENABLE] vs [PPL/DENIED] vs [?], with gmproxy's priority donors
#       (winlogon/dwm/fontdrvhost) marked <<priority. Tally + a root-cause line when ALL
#       donors are denied (elevation degrades to a current-user launch).
#   (3) Option-11 Detector B AUTO-EXCLUDE STORE view: reads $GodModeAutoExcludeFile, prints
#       each entry + the reason legend (C/G/P/A/?) + the threshold, tallies EXCLUDED vs
#       PENDING, hints at menu [18] to retry. Fail-open on a missing store.
# Self-contained body extraction (mirrors section 35 but with a section-37-local var so
# this block stays robust if section 35 ever moves). Additive; sections 1-36 intact.
$epd37Match = [regex]::Match($gm, '(?s)function\s+Get-GodModeElevationPathDiagnostics\s*\{([\s\S]*?)\nfunction\s+Export-GodModeLogs\s*\{')
$epd37Body = if ($epd37Match.Success) { $epd37Match.Groups[1].Value } else { "" }
Add-Assertion "AdminTools+Opt11: Get-GodModeElevationPathDiagnostics body extractable (section 37)" ($epd37Match.Success) "could not isolate Get-GodModeElevationPathDiagnostics body for section 37"
# Feature 1 -- admin tools DROPPED from IFEO (strategy flip 2026-07-21).
Add-Assertion "AdminTools: mmc/perfmon/resmon DROPPED from Install-IfeoElevation seed (no IFEO hook -- gmproxy rename breaks MMC)" ($gm -notmatch 'function\s+Install-IfeoElevation\s*\{[\s\S]*?"mmc\.exe","perfmon\.exe","resmon\.exe"') "Install-IfeoElevation seed still has the old mmc/perfmon/resmon entry -- they would be IFEO-hooked (gmproxy rename breaks MMC snap-in loading; exit 0, no window, even as user)"
Add-Assertion "AdminTools: mmc/perfmon/resmon in the auto-populate denylist (\$GmCriticalIfeoExclude)" ($gm.Contains('"mmc","perfmon","resmon"')) "mmc/perfmon/resmon missing from the denylist -- auto-populate could IFEO-hook them (gmproxy rename breaks MMC)"
Add-Assertion "AdminTools: Install-IfeoElevation removes prior admin-tool IFEO hooks (\$adminHookRemoved)" ($gm.Contains('$adminHookRemoved') -and $gm.Contains('$adminToolNames')) "Install-IfeoElevation missing the admin-tool prior-IFEO-hook cleanup -- a re-enable on a VM that hooked mmc would leave it hooked (broken renamed copy)"
Add-Assertion "AdminTools: mmc/perfmon/resmon in Uninstall-ProcessHook legacy list (uninstaller sync)" ($gm -match 'function\s+Uninstall-ProcessHook\s*\{[\s\S]*?"mmc\.exe", "perfmon\.exe", "resmon\.exe"') "Uninstall-ProcessHook legacy list missing mmc/perfmon/resmon -- uninstaller not current with the admin-tool set"
Add-Assertion "AdminTools: mmc/perfmon/resmon in Export-GodModeLogs IFEO-status check (\`$TargetApps)" ($gm -match 'function\s+Export-GodModeLogs\s*\{[\s\S]*?\$TargetApps[\s\S]*?"mmc\.exe","perfmon\.exe","resmon\.exe"') "Export-GodModeLogs \`$TargetApps does not include mmc/perfmon/resmon -- the dump cannot show whether the admin tools are IFEO-hooked"
# Feature 2 -- SYSTEM token donor inventory (read-only, no kill).
if ($epd37Match.Success) {
    Add-Assertion "Opt11Donor: diagnostics probes each SYSTEM donor via [TokenOps]::TestOpenProcess (read-only, no kill)" ($epd37Body.Contains('[TokenOps]::TestOpenProcess($p.ProcessId)')) "diagnostics does not call [TokenOps]::TestOpenProcess per donor -- cannot classify openable vs PPL (donor usability stays hidden)"
    Add-Assertion "Opt11Donor: classifies donors [OPENABLE] vs [PPL/DENIED]" ($epd37Body.Contains('[OPENABLE]') -and $epd37Body.Contains('[PPL/DENIED]')) "diagnostics does not tag donors OPENABLE/PPL/DENIED -- gmproxy cannot tell which SYSTEM processes are usable token sources"
    Add-Assertion "Opt11Donor: marks gmproxy priority donors (winlogon/dwm/fontdrvhost) <<priority" ($epd37Body.Contains('<<priority') -and $epd37Body.Contains('winlogon.exe') -and $epd37Body.Contains('dwm.exe') -and $epd37Body.Contains('fontdrvhost.exe')) "diagnostics does not mark the priority donors -- gmproxy's preferred token sources are not highlighted in the dump"
    Add-Assertion "Opt11Donor: tallies the donor inventory (DONOR INVENTORY summary line)" ($epd37Body.Contains('DONOR INVENTORY:')) "diagnostics does not tally the donor inventory -- openable/denied counts are missing"
    Add-Assertion "Opt11Donor: reports the degrade-to-current-user root cause when all donors denied" ($epd37Body.Contains('degrades to a current-user launch')) "diagnostics does not explain the degrade-to-current-user outcome when all donors are PPL-protected -- the 'whoami -> admin' root cause stays unstated"
    # Feature 3 -- Detector B auto-exclude store view.
    Add-Assertion "Opt11DetB: diagnostics reads the Detector B store (`$GodModeAutoExcludeFile)" ($epd37Body.Contains('$GodModeAutoExcludeFile')) "diagnostics does not read the Detector B auto-exclude store -- gmproxy's runtime SYSTEM-crash learnings are invisible in the dump"
    Add-Assertion "Opt11DetB: Detector B section header present (DETECTOR B AUTO-EXCLUDE STORE)" ($epd37Body.Contains('----- DETECTOR B AUTO-EXCLUDE STORE -----')) "Detector B section header missing -- the store view is not a labeled section"
    Add-Assertion "Opt11DetB: prints the reason legend (C=CRASH / G=CLEAN-GUI / P=PRE-DROP / A=AppX)" ($epd37Body.Contains('C=CRASH') -and $epd37Body.Contains('G=CLEAN-GUI') -and $epd37Body.Contains('P=PRE-DROP') -and $epd37Body.Contains('A=AppX')) "diagnostics does not print the Detector B reason legend -- store entries are uninterpretable"
    Add-Assertion "Opt11DetB: prints the auto-exclude threshold (GM_AUTOEXCLUDE_THRESHOLD)" ($epd37Body.Contains('GM_AUTOEXCLUDE_THRESHOLD')) "diagnostics does not print the Detector B threshold -- the crash-count-to-exclude rule is unstated"
    Add-Assertion "Opt11DetB: hints at menu [18] RESET AUTO-EXCLUDE STORE to retry elevation" ($epd37Body.Contains('RESET AUTO-EXCLUDE STORE')) "diagnostics does not hint at menu [18] to retry SYSTEM elevation for excluded apps"
    Add-Assertion "Opt11DetB: fail-open on a missing store (store not present message)" ($epd37Body.Contains('store not present')) "diagnostics is not fail-open on a missing Detector B store -- a missing store could throw"
}
# Feature 4 -- mmc.exe Detector B pre-seed (CLEAN-GUI admin tool, 2026-07-21).
# mmc.exe silently refuses SYSTEM (exits 0, no window -- the MMC host relies on
# per-user profile/COM resources). Pre-seeding it in the auto-exclude store at
# install time with reason 'G' means gmproxy launches it as the current user
# from the FIRST launch, skipping the 2 one-time SYSTEM flash-and-disappear
# attempts that Detector B would otherwise need to learn from at runtime. The
# IFEO hook is RETAINED, so menu [18] RESET AUTO-EXCLUDE STORE clears the
# pre-seed and retries SYSTEM. perfmon.exe + resmon.exe are ALSO pre-seeded
# with reason 'G' (they delegate to mmc.exe; an in-place SYSTEM token swap by
# the monitor would break them the same way). Pre-seeding means the monitor +
# gmhook skip SYSTEM-birth for all three from launch #1. (Strategy flip: the
# IFEO hook is NO LONGER retained for these -- they are DROPPED from IFEO +
# cleaned up on re-enable, see Feature 1 above; the pre-seed stays so the
# monitor + gmhook still skip them.)
Add-Assertion "AdminToolsPreSeed: Install-IfeoElevation pre-seeds mmc.exe in the auto-exclude store (reason 'G')" ($gm.Contains('Add-GmAutoExcludeEntries -BaseNames $preseededCleanGui -Reason ''G''')) "Install-IfeoElevation does not pre-seed mmc.exe with reason 'G' -- the 2 SYSTEM flash-and-disappear attempts are not eliminated"
Add-Assertion "AdminToolsPreSeed: pre-seed variable defines mmc.exe (`$preseededCleanGui = @('mmc.exe'))" ($gm.Contains('$preseededCleanGui = @(''mmc.exe'')')) "Install-IfeoElevation pre-seed variable missing or does not list mmc.exe"
Add-Assertion "AdminToolsPreSeed: debug EXIT reports the pre-seed count (preseededCleanGui)" ($gm.Contains('preseededCleanGui=$($preseededCleanGui.Count)')) "Install-IfeoElevation debug EXIT does not report the pre-seed count -- regression visibility lost"
Add-Assertion "AdminToolsPreSeed: summary log mentions the mmc.exe pre-seed (CLEAN-GUI reason 'G')" ($gm -match 'pre-seeded .*CLEAN-GUI admin tool.*mmc\.exe reason ''G''') "Install-IfeoElevation summary log does not mention the mmc.exe pre-seed -- the user cannot tell why mmc.exe launches as user from launch #1"
Add-Assertion "AdminToolsPreSeed: seed comment reflects mmc.exe SYSTEM refusal (silently refuses SYSTEM)" ($gm.Contains('mmc.exe silently refuses SYSTEM')) "Install-IfeoElevation seed comment does not say mmc.exe silently refuses SYSTEM -- the pre-seed rationale is not documented"
Add-Assertion "AdminToolsPreSeed: seed comment no longer says 'known-good as SYSTEM -- the PsExec' (stale claim removed)" (-not ($gm -match 'known-good as SYSTEM -- the PsExec')) "Install-IfeoElevation seed comment still says 'known-good as SYSTEM -- the PsExec -s mmc pattern' -- the pre-seed contradicts this claim"

# --- 38. SYSTEM shell elevation fix: hardened TokenOps compile + unguarded-
#     [TokenOps]:: guard + option-11 TokenOps availability probe (2026-07-21) ---
# The user reported "the terminal does not open instant to cmd or powershell or
# other shell into system privileges" (whoami -> admin after [7]+reboot). The
# option-11 dump proved the root-cause chain: at boot, multiple stealth -ToggleOn
# tasks fire concurrently -> each compiles the TokenOps C# P/Invoke class via
# Add-Type at the same instant -> N concurrent in-memory C# compilations exhaust
# memory -> OutOfMemoryException -> the old WARN-only catch swallowed it + left
# TokenOps UNLOADED -> the monitor's Invoke-ExistingProcessElevation hit an
# unguarded [TokenOps]::EnablePrivilege -> "Unable to find type [TokenOps]"
# uncaught trap (the global trap { ... break } terminates the scope) -> monitor
# died -> [NO LIVE MONITOR LOOP] -> shells never elevated. This section asserts
# the 5-part fix: (1) hardened compile (serialize + retry + skip-if-loaded),
# (2) Assert-TokenOpsAvailable + Invoke-TokenOpsPrivilege helpers, (3) every
# unguarded [TokenOps]::EnablePrivilege site replaced + the monitor startup
# Invoke-ExistingProcessElevation call try/catch wrapped + Get-ProcessElevationContext
# fail-open, (4) Start-Monitoring startup TokenOps Assert, (5) option-11 section K.
# Additive; sections 1-37 intact.

# Part 1 -- hardened TokenOps compile.
Add-Assertion "ShellElev: Test-TokenOpsAvailable helper defined" ($gm.Contains('function Test-TokenOpsAvailable')) "Test-TokenOpsAvailable missing -- the compile/callers cannot skip-if-loaded"
Add-Assertion "ShellElev: hardened compile serializes via Global\GodModeTokenOpsCompile mutex" ($gm.Contains('Global\GodModeTokenOpsCompile')) "the compile mutex is missing -- concurrent -ToggleOn tasks can still race the Add-Type + OOM"
Add-Assertion "ShellElev: hardened compile retries on OutOfMemoryException (maxAttempts=3)" ($gm.Contains('$maxAttempts = 3') -and ($gm -match 'Insufficient memory|OutOfMemory|OutOfMemoryException')) "no OutOfMemoryException retry -- a sibling task's compile can still starve this one"
Add-Assertion "ShellElev: hardened compile GC.Collect + WaitForPendingFinalizers between retries" ($gm.Contains('[System.GC]::Collect()') -and $gm.Contains('[System.GC]::WaitForPendingFinalizers()')) "no GC between retries -- a sibling's in-memory assembly is not freed before the retry"
Add-Assertion "ShellElev: hardened compile stores TokenOpsCompileReason (debug surface)" ($gm.Contains('$script:TokenOpsCompileReason')) "TokenOpsCompileReason missing -- the option-11 dump cannot show why TokenOps failed to compile"
Add-Assertion "ShellElev: hardened compile skip-if-loaded outer guard present" ($gm -match 'if \(-not \(Test-TokenOpsAvailable\)\) \{') "no skip-if-loaded outer guard -- a sibling that already loaded TokenOps would recompile (the OOM cause)"
Add-Assertion "ShellElev: old WARN-only compile catch GONE (TokenOps P/Invoke already loaded...)" (-not ($gm.Contains('TokenOps P/Invoke already loaded or compilation failed'))) "the bare Add-Type + WARN-only catch remains -- a compile failure is still swallowed + TokenOps left unloaded"

# Part 2 -- helpers.
Add-Assertion "ShellElev: Assert-TokenOpsAvailable helper defined" ($gm.Contains('function Assert-TokenOpsAvailable')) "Assert-TokenOpsAvailable missing -- elevation entry points cannot degrade gracefully on TokenOps-missing"
Add-Assertion "ShellElev: Invoke-TokenOpsPrivilege helper defined" ($gm.Contains('function Invoke-TokenOpsPrivilege')) "Invoke-TokenOpsPrivilege missing -- the unguarded [TokenOps]::EnablePrivilege sites cannot be replaced"

# Part 3 -- guarded call sites.
Add-Assertion "ShellElev: Invoke-ExistingProcessElevation Asserts TokenOps (graceful skip, no uncaught trap)" ($gm.Contains('Assert-TokenOpsAvailable -Caller ''Invoke-ExistingProcessElevation''')) "Invoke-ExistingProcessElevation does not Assert TokenOps -- the SYSTEM branch can still throw 'Unable to find type [TokenOps]' (the monitor killer)"
Add-Assertion "ShellElev: Invoke-GmProxyFeedbackElevation Asserts TokenOps" ($gm.Contains('Assert-TokenOpsAvailable -Caller ''Invoke-GmProxyFeedbackElevation''')) "Invoke-GmProxyFeedbackElevation does not Assert TokenOps -- can still throw unguarded"
Add-Assertion "ShellElev: Start-ProcessWithStolenToken Asserts TokenOps" ($gm.Contains('Assert-TokenOpsAvailable -Caller ''Start-ProcessWithStolenToken''')) "Start-ProcessWithStolenToken does not Assert TokenOps"
Add-Assertion "ShellElev: NO unguarded [TokenOps]::EnablePrivilege('SeIncreaseQuotaPrivilege') | Out-Null sites remain (count 0)" (([regex]::Matches($gm, '\[TokenOps\]::EnablePrivilege\("SeIncreaseQuotaPrivilege"\) \| Out-Null')).Count -eq 0) "unguarded SeIncreaseQuotaPrivilege sites remain -- any one throws 'Unable to find type [TokenOps]' when TokenOps is missing"
Add-Assertion "ShellElev: Start-Monitoring wraps the startup Invoke-ExistingProcessElevation call in try/catch" ($gm.Contains('Invoke-ExistingProcessElevation threw at startup')) "Start-Monitoring does not try/catch the startup Invoke-ExistingProcessElevation call -- a throw here kills the monitor before the while loop"
Add-Assertion "ShellElev: Get-ProcessElevationContext fail-open on TokenOps-missing (RootCause string, no throw)" ($gm.Contains('TokenOps C# P/Invoke not loaded -- elevation diagnostics unavailable')) "Get-ProcessElevationContext does not fail-open -- an uncaught throw propagates via Export-ElevationDiagnostics <- Find-SystemProcessCandidate"

# Part 4 + 5 -- monitor startup debug + option-11 section K.
Add-Assertion "ShellElev: Start-Monitoring startup Asserts TokenOps (-Caller 'Start-Monitoring')" ($gm.Contains('Assert-TokenOpsAvailable -Caller ''Start-Monitoring''')) "Start-Monitoring does not log TokenOps availability at startup -- the monitor-side failure stays invisible"
$epd38Match = [regex]::Match($gm, '(?s)function\s+Get-GodModeElevationPathDiagnostics\s*\{(.*?)\nfunction\s+Export-GodModeLogs\s*\{')
$epd38Body = if ($epd38Match.Success) { $epd38Match.Groups[1].Value } else { "" }
Add-Assertion "ShellElev: Get-GodModeElevationPathDiagnostics body extractable (section 38)" ($epd38Match.Success) "could not isolate Get-GodModeElevationPathDiagnostics body for section 38"
if ($epd38Match.Success) {
    Add-Assertion "ShellElev: option-11 section K TOKENOPS P/INVOKE AVAILABILITY header present" ($epd38Body.Contains('TOKENOPS P/INVOKE AVAILABILITY')) "option-11 has no TokenOps availability section -- the dump cannot self-diagnose the shell-elevation root cause"
    Add-Assertion "ShellElev: option-11 section K reports Test-TokenOpsAvailable" ($epd38Body.Contains('Test-TokenOpsAvailable')) "option-11 section K does not call Test-TokenOpsAvailable -- cannot report whether TokenOps is loaded"
    Add-Assertion "ShellElev: option-11 section K reports the stored CompileReason" ($epd38Body.Contains('CompileReason') -and $epd38Body.Contains('$script:TokenOpsCompileReason')) "option-11 section K does not surface the compile failure reason"
}

# --- 39. INSTANT shell elevation via gmhook birth-signal + core/thread
#     auto-detection improvements (2026-07-22) ---
# The user asked "why doesn't the DLL hook shells to auto-elevate instead of
# waiting?" Synchronous SYSTEM-birth of shells is unsafe (bootstrap paradox --
# God Mode's own persistence launches powershell.exe; 0xC0000005 crash when the
# shell's CreateProcessW is rerouted through the stolen-token path; no SeTcb in
# explorer for the safe in-place swap). The fix: gmhook (injected into explorer
# + user GUI hosts) does NOT elevate the shell -- it NOTIFIES the SYSTEM monitor
# the instant a shell CHILD is born (SHELLPID=<n> over the existing
# GodMode-GmProxyFeedback pipe), and the monitor does the safe in-place SYSTEM
# token swap within the loop tick (~<=500ms) instead of waiting for the 3s/15s
# scan. Plus core/thread auto-detection: GODMODE_JOBS override + [1,64] clamp +
# candidate-aware chunking. Additive; sections 1-38 intact.

# Part A -- gmhook.c birth-signal.
Add-Assertion "InstantShell: gmhook IsInteractiveShell helper defined" ($gmhook -match 'static BOOL IsInteractiveShell\(const wchar_t\* baseName\)') "IsInteractiveShell helper missing -- gmhook cannot gate the shell birth-signal"
$iisMatch = [regex]::Match($gmhook, '(?s)static BOOL IsInteractiveShell\(const wchar_t\* baseName\) \{(.*?)\nstatic void SignalShellBirth')
$iisBody = if ($iisMatch.Success) { $iisMatch.Groups[1].Value } else { "" }
Add-Assertion "InstantShell: IsInteractiveShell body extractable" ($iisMatch.Success) "could not isolate IsInteractiveShell body"
if ($iisMatch.Success) {
    Add-Assertion "InstantShell: IsInteractiveShell includes cmd/powershell/pwsh/ise (the 4 interactive shells)" ($iisBody.Contains('L"cmd.exe"') -and $iisBody.Contains('L"powershell.exe"') -and $iisBody.Contains('L"pwsh.exe"') -and $iisBody.Contains('L"powershell_ise.exe"')) "IsInteractiveShell does not list all 4 interactive shells -- a shell birth would not be signaled"
    Add-Assertion "InstantShell: IsInteractiveShell EXCLUDES launcher hosts (no explorer/wt/conhost -- swapping those to SYSTEM breaks the desktop)" (-not ($iisBody -match 'L"explorer\.exe"|L"wt\.exe"|L"conhost\.exe"|L"OpenConsole\.exe"|L"WindowsTerminal\.exe"')) "IsInteractiveShell includes a launcher host (explorer/wt/conhost) -- an in-place SYSTEM swap on it would break the desktop/taskbar"
}
Add-Assertion "InstantShell: gmhook SignalShellBirth helper defined" ($gmhook -match 'static void SignalShellBirth\(DWORD pid\)') "SignalShellBirth helper missing -- gmhook cannot hand the shell PID to the monitor"
Add-Assertion "InstantShell: SignalShellBirth writes a SHELLPID= payload (distinct from gmproxy's PID=)" ($gmhook -match 'SHELLPID=%lu') "SignalShellBirth does not write a SHELLPID= payload -- the monitor listener cannot route shell signals to the shell-elevation path"
Add-Assertion "InstantShell: SignalShellBirth uses the SAME GodMode-GmProxyFeedback pipe (one listener, two payloads)" ($gmhook -match 'SignalShellBirth[\s\S]{0,300}?GodMode-GmProxyFeedback') "SignalShellBirth does not use the GodMode-GmProxyFeedback pipe -- a second listener would be needed"
Add-Assertion "InstantShell: SignalShellBirth is non-blocking + fail-open (CreateFileW + OPEN_EXISTING + INVALID_HANDLE_VALUE bail)" ($gmhook -match 'SignalShellBirth[\s\S]{0,300}?CreateFileW' -and $gmhook -match 'SignalShellBirth[\s\S]{0,400}?OPEN_EXISTING' -and $gmhook -match 'SignalShellBirth[\s\S]{0,500}?INVALID_HANDLE_VALUE') "SignalShellBirth is not non-blocking/fail-open -- a missing monitor could stall the CreateProcessW hook or fault the host"
Add-Assertion "InstantShell: shell pass-through calls SignalShellBirth AFTER the real CreateProcessW succeeds (gated on result + IsInteractiveShell + dwProcessId)" ($gmhook -match 'if \(result && IsInteractiveShell\(baseName\) && lpProcessInformation &&' -and $gmhook -match 'IsInteractiveShell\(baseName\) && lpProcessInformation &&[\s\S]{0,120}?SignalShellBirth\(lpProcessInformation->dwProcessId\)') "the shell pass-through branch does not signal the shell PID after the real CreateProcessW -- the instant-elevation fast path is not wired"

# Part B -- God-Mode-Windows.ps1 listener routing + shell-elevation handler.
Add-Assertion "InstantShell: GmHookShellQueue declared (separate from GmProxyFeedbackQueue)" ($gm -match 'GmHookShellQueue = \[System\.Collections\.ArrayList\]::Synchronized') "GmHookShellQueue missing -- SHELLPID signals have no queue"
Add-Assertion "InstantShell: listener routes ^SHELLPID= to the shell queue" ($gm -match '\^SHELLPID=\(\\d\+\)' -and $gm -match 'SHELLPID[\s\S]{0,200}?shellQueue\.Add') "the listener does not route SHELLPID= to a shell queue -- shell signals would be lost"
Add-Assertion "InstantShell: listener still routes ^PID= to the normal queue (gmproxy path unchanged)" ($gm -match '\^PID=\(\\d\+\)[\s\S]{0,300}?normalQueue\.Add') "the listener no longer routes PID= to the normal queue -- the gmproxy graceful-fallback path regressed"
Add-Assertion "InstantShell: listener passes BOTH queues (normalQueue + shellQueue params)" ($gm -match 'param\(\$normalQueue, \$shellQueue\)') "the listener does not take two queue params -- one payload type would be dropped"
Add-Assertion "InstantShell: Invoke-GmHookShellFeedbackElevation defined" ($gm -match 'function Invoke-GmHookShellFeedbackElevation') "Invoke-GmHookShellFeedbackElevation missing -- the SHELLPID drain has no handler"
$ishMatch = [regex]::Match($gm, '(?s)function Invoke-GmHookShellFeedbackElevation \{(.*?)\nfunction Test-GmPlumbingShell \{')
$ishBody = if ($ishMatch.Success) { $ishMatch.Groups[1].Value } else { "" }
Add-Assertion "InstantShell: Invoke-GmHookShellFeedbackElevation body extractable" ($ishMatch.Success) "could not isolate Invoke-GmHookShellFeedbackElevation body"
if ($ishMatch.Success) {
    Add-Assertion "InstantShell: handler requires SYSTEM context (S-1-5-18)" ($ishBody.Contains('S-1-5-18')) "handler does not check SYSTEM context -- a non-SYSTEM monitor could attempt the swap"
    Add-Assertion "InstantShell: handler defense-checks the PID is an interactive shell (not a launcher host)" ($ishBody.Contains('$interactiveShells') -and $ishBody -match 'interactiveShells -notcontains \$proc\.Name') "handler does not defense-check the PID is an interactive shell -- a stray signal could swap explorer/conhost to SYSTEM (breaks the desktop)"
    Add-Assertion "InstantShell: handler skips God Mode plumbing (Test-GmPlumbingShell -- bootstrap guard)" ($ishBody.Contains('Test-GmPlumbingShell')) "handler does not skip God Mode plumbing shells -- the monitor's own -ToggleOn/-Launch powershell could be mid-flight swapped (bootstrap break)"
    Add-Assertion "InstantShell: handler skips an already-SYSTEM shell (Test-PidIsSystem)" ($ishBody.Contains('Test-PidIsSystem')) "handler does not skip an already-SYSTEM shell -- a redundant SYSTEM->SYSTEM swap could race"
    Add-Assertion "InstantShell: handler honors the Detector B auto-exclude store (Test-GmAutoExcluded)" ($ishBody.Contains('Test-GmAutoExcluded')) "handler does not consult the auto-exclude store -- an auto-excluded base could be re-elevated"
    Add-Assertion "InstantShell: handler enables SeTcbPrivilege (Phase 0 NtSetInformationProcess requires it)" ($ishBody -match 'Invoke-TokenOpsPrivilege -PrivilegeName "SeTcbPrivilege"') "handler does not enable SeTcbPrivilege -- ReplaceProcessTokenForPid would fail (STATUS_PRIVILEGE_NOT_HELD) and the shell would stay admin"
    Add-Assertion "InstantShell: handler does the in-place swap (ReplaceProcessTokenForPid)" ($ishBody -match '\[TokenOps\]::ReplaceProcessTokenForPid') "handler does not call ReplaceProcessTokenForPid -- no in-place SYSTEM swap"
    Add-Assertion "InstantShell: handler is fail-stop no-kill on Phase 0 failure (LEAVES AS ADMIN, no Stop-Process)" ($ishBody.Contains('leaving as admin') -and -not ($ishBody -match 'Stop-Process')) "handler kills the shell on Phase 0 failure (or has no fail-stop) -- the 'it kills my shell' symptom would recur"
}
Add-Assertion "InstantShell: Start-Monitoring drains GmHookShellQueue into Invoke-GmHookShellFeedbackElevation" ($gm -match 'GmHookShellQueue[\s\S]{0,200}?Invoke-GmHookShellFeedbackElevation') "Start-Monitoring does not drain GmHookShellQueue -- SHELLPID signals would queue undrained"
Add-Assertion "InstantShell: Start-Monitoring retries shells on transient failure (removes the shPid dedup key)" ($gm -match 'Invoke-GmHookShellFeedbackElevation -ProcessId \$shPid[\s\S]{0,400}?lastElevatedPid\.Remove\(\$shPid\)') "Start-Monitoring does not retry shells on transient failure -- a transient no-SYSTEM-token would strand the shell as admin"
Add-Assertion "InstantShell: Stop-GmProxyFeedbackListener clears GmHookShellQueue (teardown parity)" ($gm -match 'function Stop-GmProxyFeedbackListener [\s\S]{0,700}?GmHookShellQueue\.Clear') "Stop-GmProxyFeedbackListener does not clear GmHookShellQueue -- a stale SHELLPID could elevate a recycled PID after re-enable"

# Part C -- core/thread auto-detection improvements.
Add-Assertion "ThreadDetect: Get-OptimalThreadCount honors the GODMODE_JOBS env override" ($gm -match 'function Get-OptimalThreadCount[\s\S]{0,1000}?GODMODE_JOBS') "Get-OptimalThreadCount does not honor GODMODE_JOBS -- the user cannot tune a low-core VM or force serial (inconsistent with syntax_check.ps1)"
Add-Assertion "ThreadDetect: Get-OptimalThreadCount clamps to [1,64] (Min 64 + Max 1)" ($gm -match '\[math\]::Min\(64, \[math\]::Max\(1,') "Get-OptimalThreadCount does not clamp to [1,64] -- hundreds of ThreadJobs could spawn on a big server (per-job overhead)"
Add-Assertion "ThreadDetect: Get-NonSystemProcessesParallel uses candidate-aware chunking (Max(8, ceil(candidates/(threads*2))))" ($gm -match '\$ChunkSize = \[math\]::Max\(8, \[math\]::Ceiling\(\$candidates\.Count / \(\$MaxThreads \* 2\)\)\)') "Get-NonSystemProcessesParallel does not use candidate-aware chunking -- load balancing does not scale with core count"
Add-Assertion "ThreadDetect: Get-NonSystemProcessesParallel ChunkSize param default is 0 (compute in body)" ($gm -match 'function Get-NonSystemProcessesParallel[\s\S]{0,900}?\[int\]\$ChunkSize = 0') "Get-NonSystemProcessesParallel ChunkSize default is not 0 -- the old hardcoded formula may still bind"
Add-Assertion "ThreadDetect: old hardcoded-50 chunk formula GONE (no Ceiling(50 /)" (-not ($gm -match 'Ceiling\(50 /')) "the old hardcoded-50 chunk formula remains -- candidate-aware chunking did not replace it"

# Part D -- Phase 0 NTSTATUS diagnostic surfacing (2026-07-23). The VM dump
# showed ReplaceProcessTokenForPid failing 100% (every shell + every non-shell)
# but the log said only "In-place replacement failed" with NO error code -- the
# C# method swallowed the NTSTATUS (returned status == 0) + discarded the
# SeTcb-enable result. These assertions guard the 3 static diagnostic fields +
# the PS-side logging that surfaces them, so the next dump shows the exact
# NTSTATUS (e.g. 0xC0000061 PRIVILEGE_NOT_HELD / 0xC0000022 ACCESS_DENIED) +
# the SeTcb-enable Win32 error (1300 = ERROR_NOT_ALL_ASSIGNED) + the target-open
# error (5 = ACCESS_DENIED / PPL). Additive; no behavior change (logging only).
Add-Assertion "Phase0Diag: TokenOps LastReplaceNtStatus static field present (surfaces the NtSetInformationProcess NTSTATUS)" ($gm.Contains('public static int LastReplaceNtStatus')) "LastReplaceNtStatus missing -- the Phase 0 NTSTATUS is still swallowed, the dump cannot root-cause the 100% failure"
Add-Assertion "Phase0Diag: TokenOps LastSeTcbEnableErr static field present (surfaces the SeTcb enable Win32 error)" ($gm.Contains('public static int LastSeTcbEnableErr')) "LastSeTcbEnableErr missing -- the dump cannot tell SeTcb-not-held (1300) from NtSetInformationProcess-rejected"
Add-Assertion "Phase0Diag: TokenOps LastTargetOpenErr static field present (surfaces the OpenProcess(hTarget) Win32 error)" ($gm.Contains('public static int LastTargetOpenErr')) "LastTargetOpenErr missing -- the dump cannot distinguish 'could not open target' (5/PPL) from 'NtSetInformationProcess rejected'"
Add-Assertion "Phase0Diag: ReplaceProcessTokenForPid sets LastReplaceNtStatus = status (no longer swallowed)" ($gm -match 'LastReplaceNtStatus = status;') "ReplaceProcessTokenForPid does not store the NTSTATUS -- the 100% Phase 0 failure stays undiagnosable"
Add-Assertion "Phase0Diag: ReplaceProcessTokenForPid captures the SeTcb enable result (LastSeTcbEnableErr on failure)" ($gm -match 'bool tcbOk = EnablePrivilege\("SeTcbPrivilege"\);' -and $gm -match 'if \(!tcbOk\) \{ LastSeTcbEnableErr = Marshal\.GetLastWin32Error\(\); \}') "ReplaceProcessTokenForPid discards the SeTcb enable result -- the dump cannot tell a SeTcb-not-held token from a NtSetInformationProcess rejection"
Add-Assertion "Phase0Diag: ReplaceProcessTokenForPid captures the target-open error (LastTargetOpenErr on OpenProcess(hTarget) failure)" ($gm -match 'if \(hTarget == IntPtr\.Zero\) \{ LastTargetOpenErr = Marshal\.GetLastWin32Error\(\); return false; \}') "ReplaceProcessTokenForPid does not capture the target-open error -- a PPL/ACL open denial looks identical to a NtSetInformationProcess rejection"
Add-Assertion "Phase0Diag: Monitor-ElevateProcess Phase 0 logs the NTSTATUS on failure (NTSTATUS=0x... SeTcbErr=... TargetOpenErr=...)" ($gm -match 'In-place replacement failed for \$procName PID=\$ProcessId, falling back to kill-relaunch \(NTSTATUS=0x') "Monitor-ElevateProcess Phase 0 does not log the NTSTATUS on failure -- the dump cannot root-cause the 100% Phase 0 failure"
Add-Assertion "Phase0Diag: Invoke-GmHookShellFeedbackElevation logs the NTSTATUS on instant-path failure" ($gm -match 'Instant in-place failed for shell PID=\$ProcessId name=\$\(\$proc\.Name\) \(NTSTATUS=0x') "Invoke-GmHookShellFeedbackElevation does not log the NTSTATUS on failure -- the instant-path failure stays undiagnosable"

Write-Summary
