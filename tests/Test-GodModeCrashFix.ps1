#Requires -Version 5.1
<#
.SYNOPSIS
    Regression test for the 0xC0000005 CreateProcess crash fix.
.DESCRIPTION
    Validates that the gmhook / gmproxy / God-Mode-Windows.ps1 fixes for the
    "Defender processes terminated." -> 0xC0000005 access violation are present
    and correct, and compiles+runs the C guard-logic regression (Test-GmHookFix.c)
    via MinGW + wine when available.

    Run: pwsh -File tests/Test-GodModeCrashFix.ps1
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
    Write-Host "  GOD-MODE CRASH-FIX TEST SUMMARY" -ForegroundColor White
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

$GmHook    = Join-Path $ProjectRoot "driver/gmhook.c"
$GmProxy   = Join-Path $ProjectRoot "driver/gmproxy.c"
$GodMode   = Join-Path $ProjectRoot "God-Mode-Windows.ps1"
$CTestSrc  = Join-Path $ScriptRoot "Test-GmHookFix.c"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  God-Mode 0xC0000005 Crash-Fix Regression" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

# --- 1. Source-content assertions (the fix must be present) ---
if (Test-Path $GmHook) {
    $hookSrc = Get-Content -Raw $GmHook
    Add-Assertion "gmhook.c: cb clamp present (siCopy.cb = sizeof(siCopy))" `
        ($hookSrc -match 'siCopy\.cb\s*=\s*sizeof\(siCopy\)') "cb not clamped to sizeof(STARTUPINFOW)"
    Add-Assertion "gmhook.c: extended STARTUPINFO skip (cb > sizeof(STARTUPINFOW))" `
        ($hookSrc -match 'cb\s*>\s*sizeof\(STARTUPINFOW\)') "extended SI not skipped -> 0xC0000005 returns"
    Add-Assertion "gmhook.c: NULL PROCESS_INFORMATION guard" `
        ($hookSrc -match '!lpProcessInformation') "NULL PI guard missing"
    Add-Assertion "gmhook.c: isolated token helper TryCreateProcessWithSystemToken" `
        ($hookSrc -match 'TryCreateProcessWithSystemToken') "helper missing"
    Add-Assertion "gmhook.c: EXTENDED_STARTUPINFO_PRESENT bypass" `
        ($hookSrc -match '0x00080000') "EXTENDED flag bypass missing"
    Add-Assertion "gmhook.c: e_lfanew sanity in HookModuleIAT" `
        ($hookSrc -match 'e_lfanew\s*<=\s*0') "e_lfanew sanity missing"
    # --- Shell/launcher host exclusion (the actual 0xC0000005 fix) ---
    Add-Assertion "gmhook.c: IsShellLauncherProcess helper present" `
        ($hookSrc -match 'IsShellLauncherProcess') "IsShellLauncherProcess helper missing"
    Add-Assertion "gmhook.c: pwsh.exe excluded from hooking" `
        ($hookSrc -match 'L"pwsh\.exe"') "pwsh.exe not in shell exclusion list"
    Add-Assertion "gmhook.c: powershell.exe excluded from hooking" `
        ($hookSrc -match 'L"powershell\.exe"') "powershell.exe not in shell exclusion list"
    Add-Assertion "gmhook.c: cmd.exe excluded from hooking" `
        ($hookSrc -match 'L"cmd\.exe"') "cmd.exe not in shell exclusion list"
    Add-Assertion "gmhook.c: HookCreateProcessW uses shell exclusion" `
        ($hookSrc -match 'IsCriticalProcess\(baseName\)\s*\|\|\s*IsShellLauncherProcess\(baseName\)') "HookCreateProcessW does not OR IsShellLauncherProcess"
    Add-Assertion "gmhook.c: auto-install sites use shell exclusion (GetMsgProc/DllMain)" `
        ($hookSrc -match '!IsCriticalProcess\(baseName\)\s*&&\s*!IsShellLauncherProcess\(baseName\)') "GetMsgProc/DllMain do not AND IsShellLauncherProcess"
    Add-Assertion "gmhook.c: recursion guard resets on re-entry return" `
        ($hookSrc -match 'InterlockedExchange\(&inHook,\s*0\);\s*\r?\n\s*return pOrigCreateProcessW') "recursion guard leak (inHook not reset before return)"
    Add-Assertion "gmhook.c: IsHookInstalled diagnostic export present" `
        ($hookSrc -match '__declspec\(dllexport\)\s+BOOL\s+IsHookInstalled') "IsHookInstalled export missing (wine smoke test depends on it)"
} else {
    Add-Assertion "gmhook.c exists" $false "file not found: $GmHook"
}

if (Test-Path $GmProxy) {
    $proxySrc = Get-Content -Raw $GmProxy
    Add-Assertion "gmproxy.c: path-length guard (wcslen(argv[1]) >= MAX_PATH)" `
        ($proxySrc -match 'wcslen\(argv\[1\]\)\s*>=\s*MAX_PATH') "path-length guard missing"
    Add-Assertion "gmproxy.c: SEH guard around create (EXCEPTION_EXECUTE_HANDLER)" `
        ($proxySrc -match 'EXCEPTION_EXECUTE_HANDLER') "SEH guard missing"
} else {
    Add-Assertion "gmproxy.c exists" $false "file not found: $GmProxy"
}

if (Test-Path $GodMode) {
    $gm = Get-Content -Raw $GodMode
    # Extract the Disable-SecurityAuditing function body to scope the checks.
    $funcMatch = [regex]::Match($gm, '(?s)function Disable-SecurityAuditing \{.*?\n\}')
    $funcBody = if ($funcMatch.Success) { $funcMatch.Value } else { "" }
    Add-Assertion "God-Mode-Windows.ps1: Disable-SecurityAuditing exists" `
        ($funcMatch.Success) "function not found"
    Add-Assertion "God-Mode-Windows.ps1: wevtutil el wrapped in try/catch" `
        ($funcBody -match 'try\s*\{\s*\r?\n\s*\$Channels\s*=\s*wevtutil el') "wevtutil el not wrapped"
    Add-Assertion "God-Mode-Windows.ps1: per-channel clear loop" `
        ($funcBody -match 'foreach\s*\(\s*\$ch\s+in\s+\$ChannelList\s*\)') "per-channel loop missing"
    Add-Assertion "God-Mode-Windows.ps1: per-channel try/catch" `
        ($funcBody -match '(?s)foreach\s*\(\s*\$ch\s+in\s+\$ChannelList\s*\).*?try\s*\{.*?wevtutil cl') "per-channel try/catch missing"
    Add-Assertion "God-Mode-Windows.ps1: empty-channel skip" `
        ($funcBody -match 'Trim\(\)\.Length\s*-gt\s*0') "empty-channel skip missing"
} else {
    Add-Assertion "God-Mode-Windows.ps1 exists" $false "file not found: $GodMode"
}

# --- 1b. Install-ProcessHook injection skip-list must exclude shell hosts ---
if (Test-Path $GodMode) {
    if (-not $gm) { $gm = Get-Content -Raw $GodMode }
    Add-Assertion "God-Mode-Windows.ps1: CriticalProcs skips pwsh/powershell/cmd injection" `
        ($gm -match '"pwsh",\s*"powershell",\s*"cmd"') "shell hosts not in Install-ProcessHook CriticalProcs"
    Add-Assertion "God-Mode-Windows.ps1: CriticalProcs skips terminal host injection" `
        ($gm -match '"OpenConsole",\s*"WindowsTerminal"') "terminal hosts not in Install-ProcessHook CriticalProcs"
} else {
    Add-Assertion "God-Mode-Windows.ps1 exists (skip-list check)" $false "file not found: $GodMode"
}

# --- 2. C guard-logic regression: compile with MinGW, run via wine ---
$Mingw = Get-Command x86_64-w64-mingw32-gcc -ErrorAction SilentlyContinue
$Wine  = Get-Command wine -ErrorAction SilentlyContinue
if (-not (Test-Path $CTestSrc)) {
    Add-Assertion "Test-GmHookFix.c exists" $false "file not found: $CTestSrc"
} elseif (-not $Mingw) {
    Add-Assertion "C regression: MinGW available (skip compile if absent)" $true "x86_64-w64-mingw32-gcc not found; C compile/run skipped (source guards already asserted)"
} else {
    $Exe = Join-Path $ScriptRoot "Test-GmHookFix.exe"
    try {
        $args = @('-O2', '-Wall', '-Wextra', '-o', $Exe, $CTestSrc)
        & $Mingw.Source @args 2>&1 | Out-Null
        $compileOk = ($LASTEXITCODE -eq 0) -and (Test-Path $Exe)
        Add-Assertion "C regression: Test-GmHookFix.c compiles with MinGW" $compileOk "gcc exit=$LASTEXITCODE"
        if ($compileOk -and $Wine) {
            $out = & $Wine.Source $Exe 2>&1 | Out-String
            $wineExit = $LASTEXITCODE
            Add-Assertion "C regression: Test-GmHookFix.exe runs (exit 0)" `
                ($wineExit -eq 0) "wine exit=$wineExit"
            Add-Assertion "C regression: all C assertions passed" `
                ($out -match 'ALL ASSERTIONS PASSED') "output did not report success"
        } elseif ($compileOk -and -not $Wine) {
            Add-Assertion "C regression: wine available (skip run if absent)" $true "wine not found; run skipped (compile + source guards asserted)"
        }
    } catch {
        Add-Assertion "C regression: compile/run exception-free" $false $_.Exception.Message
    } finally {
        if (Test-Path $Exe) { Remove-Item $Exe -Force -ErrorAction SilentlyContinue }
    }
}

Write-Summary
