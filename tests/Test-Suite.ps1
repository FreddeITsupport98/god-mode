#Requires -Version 5.1
<#
.SYNOPSIS
    Regression Test Suite for DNSGuard and Launch-SystemShell
.DESCRIPTION
    Validates syntax, script structure, and installer logic WITHOUT modifying
    the system. Must be run as Administrator to test privilege checks.
    
    Run: .\Test-Suite.ps1
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

function Write-Section {
    param([string]$Title)
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
}

function Write-Summary {
    Write-Host "`n=====================================================" -ForegroundColor White
    Write-Host "  TEST SUMMARY" -ForegroundColor White
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

# --- Locate scripts under test ---
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = (Get-Location).Path }
# Scripts live in the parent directory; tests live in the tests/ subfolder
$ProjectRoot = Split-Path -Parent $ScriptRoot
if (-not $ProjectRoot) { $ProjectRoot = $ScriptRoot }

$DnsScript = Join-Path $ProjectRoot "God-Mode-Windows.ps1"
$SystemScript = Join-Path $ProjectRoot "Launch-SystemShell.ps1"

# ============================================================================
# 1. FILE EXISTENCE
# ============================================================================
Write-Section "FILE EXISTENCE"
Add-Assertion -Name "God-Mode-Windows.ps1 exists" -Pass (Test-Path $DnsScript)
# Launch-SystemShell.* and God_mode.bat are optional companion launchers not
# required in every checkout; skip (do not fail) when absent.
if (Test-Path $SystemScript) {
    Add-Assertion -Name "Launch-SystemShell.ps1 exists" -Pass $true
} else {
    Write-Host "  [SKIP] Launch-SystemShell.ps1 not present (optional companion launcher)." -ForegroundColor DarkGray
}
if (Test-Path (Join-Path $ProjectRoot "God_mode.bat")) {
    Add-Assertion -Name "God_mode.bat exists" -Pass $true
} else {
    Write-Host "  [SKIP] God_mode.bat not present (optional companion launcher)." -ForegroundColor DarkGray
}
if (Test-Path (Join-Path $ProjectRoot "Launch-SystemShell.bat")) {
    Add-Assertion -Name "Launch-SystemShell.bat exists" -Pass $true
} else {
    Write-Host "  [SKIP] Launch-SystemShell.bat not present (optional companion launcher)." -ForegroundColor DarkGray
}

# ============================================================================
# 2. SYNTAX VALIDATION (PowerShell parser)
# ============================================================================
Write-Section "POWERSHELL SYNTAX CHECK"

$ScriptsToCheck = @($DnsScript, $SystemScript)
foreach ($s in $ScriptsToCheck) {
    if (-not (Test-Path $s)) { continue }
    $Tokens = $null
    $ParseErrors = $null
    $AST = [System.Management.Automation.Language.Parser]::ParseFile($s, [ref]$Tokens, [ref]$ParseErrors)
    $Name = Split-Path -Leaf $s
    Add-Assertion -Name "$Name parses without errors" -Pass ($ParseErrors.Count -eq 0) -Details ($ParseErrors | Out-String)
}

# ============================================================================
# 3. SCRIPT STRUCTURE CHECKS
# ============================================================================
Write-Section "SCRIPT STRUCTURE"

if (Test-Path $DnsScript) {
    $Content = Get-Content -Path $DnsScript -Raw
    Add-Assertion -Name "God-Mode-Windows.ps1 has #Requires or auto-elevation" -Pass (
        $Content -match '#Requires -RunAsAdministrator' -or $Content -match 'runAs'
    )
    Add-Assertion -Name "God-Mode-Windows.ps1 defines Install function" -Pass ($Content -match 'function Install-Persistence')
    Add-Assertion -Name "God-Mode-Windows.ps1 defines Uninstall function" -Pass ($Content -match 'function Uninstall-Persistence')
    Add-Assertion -Name "God-Mode-Windows.ps1 defines Lock function" -Pass ($Content -match 'function Enable-DNSLock')
    Add-Assertion -Name "God-Mode-Windows.ps1 defines Unlock function" -Pass ($Content -match 'function Disable-DNSLock')
    Add-Assertion -Name "God-Mode-Windows.ps1 has integrity checking" -Pass ($Content -match 'Test-IntegrityStatus|Get-FileHash')
    Add-Assertion -Name "God-Mode-Windows.ps1 handles IPv6" -Pass ($Content -match 'Tcpip6')
    Add-Assertion -Name "God-Mode-Windows.ps1 handles Browser DoH" -Pass ($Content -match 'DnsOverHttps|Firefox|Edge|Chrome')
    Add-Assertion -Name "God-Mode-Windows.ps1 has WMI cleanup in Uninstall" -Pass ($Content -match 'Remove-WmiObject')
    Add-Assertion -Name "God-Mode-Windows.ps1 has SYSTEM helper (Invoke-AsSystem)" -Pass ($Content -match 'Invoke-AsSystem')
}

if (Test-Path $SystemScript) {
    $Content = Get-Content -Path $SystemScript -Raw
    Add-Assertion -Name "SystemShell has #Requires -RunAsAdministrator" -Pass ($Content -match '#Requires -RunAsAdministrator')
    Add-Assertion -Name "SystemShell has explicit confirmation prompt" -Pass ($Content -match "Read-Host")
    Add-Assertion -Name "SystemShell has cleanup function" -Pass ($Content -match 'Invoke-Cleanup')
    Add-Assertion -Name "SystemShell does NOT use 'runAs' verb (no UAC bypass)" -Pass ($Content -notmatch 'Verb.*runAs|Verb = "runAs"')
    Add-Assertion -Name "SystemShell is non-persistent (no AtStartup trigger)" -Pass ($Content -notmatch 'AtStartup')
    Add-Assertion -Name "SystemShell uses SYSTEM account explicitly" -Pass ($Content -match 'NT AUTHORITY\\SYSTEM')
}

# ============================================================================
# 4. ADMIN PRIVILEGE CHECK
# ============================================================================
Write-Section "RUNTIME PRIVILEGE CHECK"
$IsWindowsEnv = ($PSVersionTable.Platform -ne "Unix")
try {
    $IsAdmin = $IsWindowsEnv -and ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $IsAdmin = $false
}
if ($IsWindowsEnv) {
    Add-Assertion -Name "Running as Administrator" -Pass $IsAdmin -Details "Tests requiring admin checks will be skipped."
} else {
    $IsAdmin = $false
    Write-Host "  [SKIP] Running as Administrator (non-Windows host; admin checks skipped)." -ForegroundColor DarkGray
}

# ============================================================================
# 5. INTEGRITY CHECK (God_mode.ps1) -- NO-SIDE-EFFECT
# ============================================================================
Write-Section "INTEGRITY CHECK (NO-SIDE-EFFECT)"
if ($IsAdmin -and (Test-Path $DnsScript)) {
    # Parse the script to verify hash logic exists without executing it
    $Content = Get-Content -Path $DnsScript -Raw
    Add-Assertion -Name "Install-Persistence computes SHA256 hash" -Pass ($Content -match 'Get-FileHash.*Algorithm SHA256')
    Add-Assertion -Name "Install-Persistence stores hash in file" -Pass ($Content -match 'integrity\.sha256')
    Add-Assertion -Name "Install-Persistence stores hash in registry" -Pass ($Content -match 'PushConfigBackoffInterval')
    Add-Assertion -Name "Uninstall-Persistence removes registry hash" -Pass ($Content -match 'Remove-ItemProperty.*PushConfigBackoffInterval')
} else {
    Write-Host "  [SKIP] Admin + script present for hash checks (need Windows admin + God-Mode-Windows.ps1)." -ForegroundColor DarkGray
}

# ============================================================================
# 6. UNINSTALLER VALIDATION -- NO-SIDE-EFFECT
# ============================================================================
Write-Section "UNINSTALLER VALIDATION (NO-SIDE-EFFECT)"
if (Test-Path $DnsScript) {
    $Content = Get-Content -Path $DnsScript -Raw
    Add-Assertion -Name "Uninstall removes scheduled task" -Pass ($Content -match 'Unregister-ScheduledTask.*TaskName \$TaskName')
    Add-Assertion -Name "Uninstall removes Guardian 1" -Pass ($Content -match 'Unregister-ScheduledTask.*GuardianTaskName')
    Add-Assertion -Name "Uninstall removes Guardian 2" -Pass ($Content -match 'Unregister-ScheduledTask.*Guardian2Name')
    Add-Assertion -Name "Uninstall removes WMI filter" -Pass ($Content -match 'Get-WmiObject.*__EventFilter.*Remove-WmiObject')
    Add-Assertion -Name "Uninstall removes WMI consumer" -Pass ($Content -match 'Get-WmiObject.*CommandLineEventConsumer.*Remove-WmiObject')
    Add-Assertion -Name "Uninstall removes WMI binding" -Pass ($Content -match 'Get-WmiObject.*__FilterToConsumerBinding.*Remove-WmiObject')
    Add-Assertion -Name "Uninstall removes CLI wrapper" -Pass ($Content -match 'Remove-Item.*CmdPath')
    Add-Assertion -Name "Uninstall removes install dir" -Pass ($Content -match 'Remove-Item.*InstallDir')
    Add-Assertion -Name "Uninstall calls Disable-DNSLock first" -Pass ($Content -match 'Disable-DNSLock')
    Add-Assertion -Name "Uninstall uses Invoke-AsSystem for cleanup" -Pass ($Content -match 'Invoke-AsSystem')
    Add-Assertion -Name "Uninstall handles missing install gracefully" -Pass ($Content -match 'IsInstalled.*Test-Path.*InstallDir')
} else {
    Add-Assertion -Name "Script present for uninstall checks" -Pass $false -Details "Skipped (God-Mode-Windows.ps1 missing)"
}

# ============================================================================
# 7. INSTALLER VALIDATION -- NO-SIDE-EFFECT
# ============================================================================
Write-Section "INSTALLER VALIDATION (NO-SIDE-EFFECT)"
if (Test-Path $DnsScript) {
    $Content = Get-Content -Path $DnsScript -Raw
    Add-Assertion -Name "Install prevents double-install" -Pass ($Content -match 'Test-Path \$InstallDir' -and $Content -match 'already exists')
    Add-Assertion -Name "Install copies payload to install dir" -Pass ($Content -match 'Copy-Item.*InstallScript')
    Add-Assertion -Name "Install registers main task" -Pass ($Content -match 'Register-ScheduledTask.*TaskName \$TaskName')
    Add-Assertion -Name "Install registers guardian tasks" -Pass ($Content -match 'Register-ScheduledTask.*GuardianTaskName')
    Add-Assertion -Name "Install registers WMI subscription" -Pass ($Content -match 'Set-WmiInstance.*CommandLineEventConsumer')
    Add-Assertion -Name "Install enables DNS lock after setup" -Pass ($Content -match 'Enable-DNSLock')
    Add-Assertion -Name "Install adds to PATH" -Pass ($Content -match 'SetEnvironmentVariable.*PATH')
    Add-Assertion -Name "Install hardens NTFS ACLs" -Pass ($Content -match 'Set-Acl.*InstallDir')
    Add-Assertion -Name "Install sets owner to SYSTEM" -Pass ($Content -match 'SetOwner.*SidSystem')
} else {
    Add-Assertion -Name "Script present for install checks" -Pass $false -Details "Skipped (God-Mode-Windows.ps1 missing)"
}

# ============================================================================
# 8. MENU VALIDATION
# ============================================================================
Write-Section "INTERACTIVE MENU VALIDATION"
if (Test-Path $DnsScript) {
    $Content = Get-Content -Path $DnsScript -Raw
    Add-Assertion -Name "Menu has option 1 (Deploy Lock)" -Pass ($Content -match '\[1\].*DEPLOY LOCK')
    Add-Assertion -Name "Menu has option 2 (Remove Lock)" -Pass ($Content -match '\[2\].*REMOVE LOCK')
    Add-Assertion -Name "Menu has option 3 (Install Service)" -Pass ($Content -match '\[3\].*INSTALL SERVICE')
    Add-Assertion -Name "Menu has option 4 (Uninstall Service)" -Pass ($Content -match '\[4\].*UNINSTALL SERVICE')
    Add-Assertion -Name "Menu has option 5 (Refresh)" -Pass ($Content -match '\[5\].*REFRESH')
    Add-Assertion -Name "Menu has option 12 (Exit)" -Pass ($Content -match '\[12\].*EXIT')
    Add-Assertion -Name "Menu blocks tampered integrity options 1-3" -Pass ($Content -match 'BLOCKED.*tampered')
    Add-Assertion -Name "Menu allows Uninstall even if tampered" -Pass ($Content -match 'Uninstall-Persistence' -and $Content -notmatch 'BLOCKED.*Uninstall-Persistence')
} else {
    Add-Assertion -Name "Script present for menu checks" -Pass $false -Details "Skipped (God-Mode-Windows.ps1 missing)"
}

# ============================================================================
# 9. LOGGING VALIDATION
# ============================================================================
Write-Section "LOGGING VALIDATION"
if (Test-Path $DnsScript) {
    $Content = Get-Content -Path $DnsScript -Raw
    Add-Assertion -Name "Write-Log function exists" -Pass ($Content -match 'function Write-Log')
    Add-Assertion -Name "Log writes to temp file" -Pass ($Content -match 'Out-File.*LogFile')
    Add-Assertion -Name "Log timestamps entries" -Pass ($Content -match 'Get-Date.*yyyy-MM-dd HH:mm:ss')
} else {
    Add-Assertion -Name "Script present for logging checks" -Pass $false -Details "Skipped (God-Mode-Windows.ps1 missing)"
}

# ============================================================================
# 10. FINAL SUMMARY
# ============================================================================
Write-Summary
