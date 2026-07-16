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
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs extracts last GM-PROXY BUILD stamp" ($gm -match "Select-String[\s\S]{0,80}?GM-PROXY BUILD") "Export-GodModeLogs does not extract the last GM-PROXY BUILD stamp"
Add-Assertion "God-Mode-Windows.ps1: Export-GodModeLogs extracts last GM-HOOK BUILD stamp" ($gm -match "Select-String[\s\S]{0,80}?GM-HOOK BUILD") "Export-GodModeLogs does not extract the last GM-HOOK BUILD stamp"
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

Write-Summary
