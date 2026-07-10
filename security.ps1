<#
.SYNOPSIS
    Enterprise OS Child Lockdown + DNS Hijack Protection Suite (IPv4 & IPv6 + DoH)
.DESCRIPTION
    A highly verbose, enterprise-grade PowerShell tool that enforces:
    1. Zero-Trust Registry padlock on network interface DNS configurations (IPv4 & IPv6)
    2. Browser DNS-over-HTTPS (DoH) loophole closure (Edge, Chrome, Firefox)
    3. STRICT child-safe OS lockdown on a dedicated standard user account
       - Auto-creates a PASSWORDLESS child account if missing
       - Blocks software installation, settings changes, CMD, Run, Control Panel, Regedit, TaskMgr
       - Maxes UAC so the child cannot turn it off
       - Removes Windows Store
       - Leaves the built-in Administrator account with FULL privileges to install/modify
    4. Self-healing background persistence (scheduled tasks + WMI) re-applies everything
       on boot, logon, network change, and every 5/10 minutes.

    NEW FEATURES:
    - Global CLI: Installs 'oslock' command to Windows PATH for easy cmd access.
    - Automated Installation: Scheduled Tasks re-apply locks on boot/network change/logon.
    - Background Guardians: Protects against Windows Updates and driver reinstalls.
    - Child Account Management: Auto-creates passwordless 'Child' standard user.
    - Advanced Auditing: UI tracks DNS locks, OS restrictions, and install status.
    - Payload Self-Defense: NTFS ACL hardening locks the install directory against tampering.
#>

param (
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Lock,
    [switch]$Unlock,
    [switch]$SilentLock,
    [switch]$ChildLock,
    [switch]$ParentMode,
    [switch]$SetParentPassword,
    [switch]$ChildGameRequest,
    [switch]$ContinueParentMode,
    [switch]$LockNow,
    [switch]$ChildLogout,
    [switch]$ProgramScan,
    [switch]$SetScreenTime,
    [switch]$ScreenTimeStatus,
    [switch]$GrantBrowserTime,
    [switch]$ScreenTimeEnforce,
    [switch]$TamperLockout,
    [switch]$ApproveChildInstall,
    [switch]$RehardenChildInstall,
    [switch]$ReviewGameRequests,
    [switch]$ReviewBlockedPrograms,
    [switch]$ManageProgramWhitelist,
    [switch]$ProcessEnforce,
    [switch]$ChildAccessLog,
    [switch]$BypassMitigation,
    [switch]$RemoveBypassMitigation,
    [switch]$HealthCheck,
    [switch]$WhatIf,
    [switch]$ExportReport,
    [switch]$FirstRun,
    [switch]$SetAfkTimeout,
    [string]$ChildUser = "Child",
    [string[]]$ChildUsers = @(),
    [string]$BrandingOrg = "OS-Guard",
    [string]$HomeSSID = ""
)

# --- PowerShell 7 Runtime Guard ---
# OS-Guard requires PowerShell 7 (pwsh) for correct Unicode handling and parser compatibility.
# If launched from Windows PowerShell 5.1, auto-relaunch in pwsh.exe and forward all parameters.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $PwshPath = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
    if (-not $PwshPath) { $PwshPath = "C:\Program Files\PowerShell\7\pwsh.exe" }
    if (Test-Path $PwshPath) {
        $ArgList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath)
        foreach ($bp in $MyInvocation.BoundParameters.GetEnumerator()) {
            $key = $bp.Key
            $val = $bp.Value
            if ($val -is [switch]) {
                if ($val.IsPresent) { $ArgList += "-$key" }
            } elseif ($val -is [array]) {
                foreach ($v in $val) { $ArgList += "-$key"; $ArgList += "$v" }
            } else {
                $ArgList += "-$key"
                $ArgList += "$val"
            }
        }
        $proc = Start-Process -FilePath $PwshPath -ArgumentList $ArgList -Wait -PassThru
        exit $proc.ExitCode
    } else {
        $Msg = "PowerShell 7 (pwsh.exe) is required but not found.`n`nPlease install PowerShell 7 from the official Microsoft GitHub releases page:`nhttps://github.com/PowerShell/PowerShell/releases"
        Write-Host $Msg -ForegroundColor Red
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            [System.Windows.Forms.MessageBox]::Show($Msg, "PowerShell 7 Required - OS-Guard", "OK", "Error") | Out-Null
        } catch {
            $wshell = New-Object -ComObject WScript.Shell -ErrorAction SilentlyContinue
            if ($wshell) { $wshell.Popup($Msg, 0, "PowerShell 7 Required - OS-Guard", 16) | Out-Null }
        }
        exit 1
    }
}

Set-StrictMode -Version Latest

# Validate $ChildUser parameter: must be non-empty and contain only valid Windows username characters
if ([string]::IsNullOrWhiteSpace($ChildUser) -or $ChildUser -match '[<>"/\|?*]' -or $ChildUser -match '^[\s\.]+$') {
    Write-Error 'Invalid ChildUser parameter: must be non-empty and not contain invalid characters (< > : " / \ | ? *).'
    exit 1
}

# ============================================================================
# 1. AUTO-ELEVATION & PRE-FLIGHT CHECKS
# ============================================================================

# Automatically relaunch as Administrator if not already elevated
$Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$Role = [Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $Principal.IsInRole($Role)) {
    if ($Install -or $Uninstall -or $Lock -or $Unlock -or $SilentLock -or $ParentMode -or $SetParentPassword -or $LockNow -or $ProgramScan -or $SetScreenTime -or $ScreenTimeStatus -or $GrantBrowserTime -or $ScreenTimeEnforce -or $TamperLockout -or $ApproveChildInstall -or $ReviewGameRequests -or $ReviewBlockedPrograms -or $ManageProgramWhitelist -or $ProcessEnforce -or $ChildAccessLog) {
        Write-Warning "CRITICAL: Administrative privileges required for CLI commands. Access Denied."
        return
    }
    # ChildLock and ChildGameRequest write only to the current user's own HKCU, no elevation needed
    if (-not $ChildLock -and -not $ChildGameRequest) {
        Write-Warning "Administrative privileges required. Attempting auto-elevation..."
        Start-Sleep -Seconds 1
        try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = "pwsh.exe"

            # Forward any CLI flags (like -Uninstall) to the elevated process
            $ArgsString = ""
            if ($Install) { $ArgsString += " -Install" }
            if ($Uninstall) { $ArgsString += " -Uninstall" }
            if ($Lock) { $ArgsString += " -Lock" }
            if ($Unlock) { $ArgsString += " -Unlock" }
            if ($SilentLock) { $ArgsString += " -SilentLock" }
            if ($ChildLock) { $ArgsString += " -ChildLock" }
            if ($ParentMode) { $ArgsString += " -ParentMode" }
            if ($SetParentPassword) { $ArgsString += " -SetParentPassword" }
            if ($ChildGameRequest) { $ArgsString += " -ChildGameRequest" }
            if ($ContinueParentMode) { $ArgsString += " -ContinueParentMode" }
            if ($LockNow) { $ArgsString += " -LockNow" }
            if ($ChildLogout) { $ArgsString += " -ChildLogout" }
            if ($ProgramScan) { $ArgsString += " -ProgramScan" }
            if ($SetScreenTime) { $ArgsString += " -SetScreenTime" }
            if ($ScreenTimeStatus) { $ArgsString += " -ScreenTimeStatus" }
            if ($GrantBrowserTime) { $ArgsString += " -GrantBrowserTime" }
            if ($ScreenTimeEnforce) { $ArgsString += " -ScreenTimeEnforce" }
            if ($TamperLockout) { $ArgsString += " -TamperLockout" }
            if ($ApproveChildInstall) { $ArgsString += " -ApproveChildInstall" }
            if ($RehardenChildInstall) { $ArgsString += " -RehardenChildInstall" }
    if ($ReviewGameRequests) { $ArgsString += " -ReviewGameRequests" }
    if ($ReviewBlockedPrograms) { $ArgsString += " -ReviewBlockedPrograms" }
    if ($ManageProgramWhitelist) { $ArgsString += " -ManageProgramWhitelist" }
            if ($ProcessEnforce) { $ArgsString += " -ProcessEnforce" }
            if ($ChildAccessLog) { $ArgsString += " -ChildAccessLog" }
            if ($BypassMitigation) { $ArgsString += " -BypassMitigation" }
            if ($RemoveBypassMitigation) { $ArgsString += " -RemoveBypassMitigation" }
            if ($HealthCheck) { $ArgsString += " -HealthCheck" }
            if ($WhatIf) { $ArgsString += " -WhatIf" }
            if ($ExportReport) { $ArgsString += " -ExportReport" }
            if ($FirstRun) { $ArgsString += " -FirstRun" }
            if ($SetAfkTimeout) { $ArgsString += " -SetAfkTimeout" }
            if ($ChildUser -ne "Child") { $ArgsString += " -ChildUser `"$ChildUser`"" }
            if ($ChildUsers.Count -gt 0) { $ArgsString += " -ChildUsers `"$($ChildUsers -join ',')`"" }
    if ($BrandingOrg -ne "OS-Guard") { $ArgsString += " -BrandingOrg `"$BrandingOrg`"" }
    if ($HomeSSID) { $ArgsString += " -HomeSSID `"$HomeSSID`"" }
    if ($SetAfkTimeout) { $ArgsString += " -SetAfkTimeout" }

            $ProcessInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $ArgsString"
            $ProcessInfo.UseShellExecute = $true
            $ProcessInfo.Verb = "runAs"
            [System.Diagnostics.Process]::Start($ProcessInfo) | Out-Null
            return
        } catch {
            Write-Error "Failed to elevate. Please right-click and 'Run as Administrator'."
            return
        }
    }
}

# Auto-enable ExecutionPolicy for CurrentUser when elevated (so the script and future runs work without manual intervention)
if ($Principal.IsInRole($Role)) {
    $CurrentPolicy = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue
    $PolicyNeedsChange = $false
    if ($CurrentPolicy -eq 'Restricted' -or $CurrentPolicy -eq 'AllSigned' -or $CurrentPolicy -eq 'Undefined') {
        $PolicyNeedsChange = $true
    }
    if ($PolicyNeedsChange) {
        try {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "ExecutionPolicy auto-set to RemoteSigned for CurrentUser (was $CurrentPolicy)." -ForegroundColor Green
        } catch {
            Write-Host "Failed to auto-set ExecutionPolicy for CurrentUser: $_" -ForegroundColor Yellow
        }
    }
}

# ============================================================================
# 2. GLOBAL CONFIGURATION & PATHS
# ============================================================================

# Define Installation Paths (renamed from DNSGuard to OSGuard)
$InstallDir = "C:\ProgramData\OSGuard"
$InstallScript = Join-Path -Path $InstallDir -ChildPath "OS_Lockdown.ps1"
$CmdPath = "C:\Windows\oslock.cmd"
$TaskName = "OS-Guard-Protection"
$Guardian1Name = "OSGuard-Guardian1"
$Guardian2Name = "OSGuard-Guardian2"
$ChildLogonTaskName = "OSGuard-ChildLogon"
$WmiEventName = "OSGuardWmiHealth"
$ParentModeWatchName = "OSGuard-ParentModeWatch"
$ProgramScannerName = "OSGuard-ProgramScanner"
$ScreenTimeTaskName = "OSGuard-ScreenTime"
$ScreenTimeConfigFile = Join-Path $InstallDir "ScreenTime.json"
$ScreenTimeTrackerFile = Join-Path $InstallDir "ScreenTimeTracker.json"
$BrowserLauncherPath = Join-Path $InstallDir "BrowserLauncher.ps1"
$TempUnlockTimerPath = Join-Path $InstallDir "TempUnlockTimer.ps1"
$TempUnlockTimerPidFile = Join-Path $InstallDir "TempUnlockTimer.pid"
$IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
$TamperDetectedRegName = "OSGuardTamperDetected"

# Process Enforcer live guardian
$ProcessEnforcerName = "OSGuard-ProcessEnforcer"
$BlockedProcessLogFile = Join-Path $InstallDir "BlockedProcessLog.json"

# Program Guardian aggressive block allowlist / blocked log
$ProgramWhitelistFile = Join-Path $InstallDir "ProgramWhitelist.json"
$ProgramAllowlistFile = Join-Path $InstallDir "ProgramAllowlist.json"
$BlockedProgramLogFile = Join-Path $InstallDir "BlockedPrograms.json"
$BlockedHashesFile = Join-Path $InstallDir "BlockedProcessHashes.json"
$AdminSessionFile = Join-Path $InstallDir "AdminSession.json"

# Child Access Log file (tamper-protected) tracks logins to the child account
$ChildAccessLogFile = Join-Path $InstallDir "ChildAccessLog.json"
$ChildAccessLogHashFile = Join-Path $InstallDir "ChildAccessLog.sha256"
$HeartbeatFile = Join-Path $InstallDir "Heartbeat.json"

# Parent Mode AFK Watch script embedded as Base64 (written fresh at install and every silent heal)
$ParentModeWatchB64 = "JFJlZ1BhdGggPSAiSEtMTTpcU09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cV3BuUGxhdGZvcm1cU2V0dGluZ3MiDQp0cnkgeyAkUGFyZW50QWN0aXZlID0gKEdldC1JdGVtUHJvcGVydHlWYWx1ZSAtUGF0aCAkUmVnUGF0aCAtTmFtZSAiT1NHdWFyZFBhcmVudE1vZGVBY3RpdmUiIC1FcnJvckFjdGlvbiBTdG9wKSB9IGNhdGNoIHsgJFBhcmVudEFjdGl2ZSA9ICRudWxsIH0NCnRyeSB7ICRUZW1wQWN0aXZlID0gKEdldC1JdGVtUHJvcGVydHlWYWx1ZSAtUGF0aCAkUmVnUGF0aCAtTmFtZSAiT1NHdWFyZFRlbXBVbmxvY2tBY3RpdmUiIC1FcnJvckFjdGlvbiBTdG9wKSB9IGNhdGNoIHsgJFRlbXBBY3RpdmUgPSAkbnVsbCB9DQppZiAoJFBhcmVudEFjdGl2ZSAtbmUgMSAtYW5kICRUZW1wQWN0aXZlIC1uZSAxKSB7IHJldHVybiB9DQoNCiRUaW1lb3V0TWludXRlcyA9IDUNCnRyeSB7ICRUaW1lb3V0TWludXRlcyA9IChHZXQtSXRlbVByb3BlcnR5VmFsdWUgLVBhdGggJFJlZ1BhdGggLU5hbWUgIk9TR3VhcmRQYXJlbnRNb2RlQUZLVGltZW91dCIgLUVycm9yQWN0aW9uIFN0b3ApIH0gY2F0Y2gge30NCmlmICgkVGltZW91dE1pbnV0ZXMgLWx0IDEgLW9yICRUaW1lb3V0TWludXRlcyAtZ3QgMTIwKSB7ICRUaW1lb3V0TWludXRlcyA9IDUgfQ0KDQokSGVhcnRiZWF0T2xkID0gJHRydWUNCiRIZWFydGJlYXQgPSAkbnVsbA0KdHJ5IHsgJEhlYXJ0YmVhdCA9IChHZXQtSXRlbVByb3BlcnR5VmFsdWUgLVBhdGggJFJlZ1BhdGggLU5hbWUgIk9TR3VhcmRQYXJlbnRNb2RlTGFzdEFjdGl2aXR5IiAtRXJyb3JBY3Rpb24gU3RvcCkgfSBjYXRjaCB7fQ0KaWYgKCRIZWFydGJlYXQpIHsNCiAgICB0cnkgew0KICAgICAgICAkSGVhcnRiZWF0VGltZSA9IFtkYXRldGltZV06OlBhcnNlKCRIZWFydGJlYXQpDQogICAgICAgIGlmICgoKEdldC1EYXRlKSAtICRIZWFydGJlYXRUaW1lKS5Ub3RhbE1pbnV0ZXMgLWx0ICRUaW1lb3V0TWludXRlcykgeyAkSGVhcnRiZWF0T2xkID0gJGZhbHNlIH0NCiAgICB9IGNhdGNoIHt9DQp9DQoNCiRDb25zb2xlSWRsZU9sZCA9ICRmYWxzZQ0KdHJ5IHsNCiAgICAkcXVzZXIgPSBxdWVyeSB1c2VyIDI+JG51bGwNCiAgICBpZiAoJHF1c2VyKSB7DQogICAgICAgIGZvcmVhY2ggKCRsaW5lIGluICgkcXVzZXIgLXNwbGl0ICJgbiIpKSB7DQogICAgICAgICAgICBpZiAoJGxpbmUgLW1hdGNoICdeXHMqPlxzJykgew0KICAgICAgICAgICAgICAgICRwYXJ0cyA9ICRsaW5lIC1zcGxpdCAnXHN7Mix9JyB8IFdoZXJlLU9iamVjdCB7ICRfIC1uZSAnJyB9DQogICAgICAgICAgICAgICAgaWYgKCRwYXJ0cy5Db3VudCAtZ2UgNSkgew0KICAgICAgICAgICAgICAgICAgICAkaWRsZSA9ICRwYXJ0c1s0XS5UcmltKCkNCiAgICAgICAgICAgICAgICAgICAgaWYgKCRpZGxlIC1lcSAnbm9uZScgLW9yICRpZGxlIC1lcSAnLicpIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICRDb25zb2xlSWRsZU9sZCA9ICRmYWxzZQ0KICAgICAgICAgICAgICAgICAgICB9IGVsc2VpZiAoJGlkbGUgLW1hdGNoICdeXGQrOlxkezJ9JCcpIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICRhID0gW2ludF0oJGlkbGUgLXNwbGl0ICc6JylbMF0NCiAgICAgICAgICAgICAgICAgICAgICAgIGlmICgkYSAtZ2UgJFRpbWVvdXRNaW51dGVzKSB7ICRDb25zb2xlSWRsZU9sZCA9ICR0cnVlIH0NCiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgeyAkQ29uc29sZUlkbGVPbGQgPSAkZmFsc2UgfQ0KICAgICAgICAgICAgICAgICAgICB9IGVsc2Ugew0KICAgICAgICAgICAgICAgICAgICAgICAgJENvbnNvbGVJZGxlT2xkID0gJHRydWUNCiAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIH0gZWxzZSB7DQogICAgICAgICAgICAgICAgICAgICRDb25zb2xlSWRsZU9sZCA9ICRmYWxzZQ0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICBicmVhaw0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQogICAgfSBlbHNlIHsNCiAgICAgICAgJENvbnNvbGVJZGxlT2xkID0gJGZhbHNlDQogICAgfQ0KfSBjYXRjaCB7ICRDb25zb2xlSWRsZU9sZCA9ICRmYWxzZSB9DQoNCmlmICgkSGVhcnRiZWF0T2xkIC1hbmQgJENvbnNvbGVJZGxlT2xkKSB7DQogICAgJiAiQzpcV2luZG93c1xvc2xvY2suY21kIiAtTG9ja05vdw0KfQ0K"

# Setup Auto-Logging
$ScriptDir = Split-Path -Parent -Path $PSCommandPath
if (-not $ScriptDir) { $ScriptDir = $PWD.Path }
# Log to a protected location (hardened install dir) so child cannot tamper with logs
$LogFile = Join-Path -Path $InstallDir -ChildPath "OS_Lockdown_Enterprise.log"

function Write-Log {
    param ([string]$Message, [string]$Type = "INFO", [ConsoleColor]$Color = "White")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
        if (-not $script:SuppressLogDirCreation -and -not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction SilentlyContinue | Out-Null }
        if (Test-Path $InstallDir) { "[$TimeStamp] [$Type] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction Stop }
    } catch {}

    # Write to Windows Event Log for tamper-resistant auditing
    if ($Type -in @("SECURITY","ERROR","WARN","AUDIT","ACTION")) {
        try {
            $SourceName = "OS-Guard"
            $LogName = "Application"
            if (-not [System.Diagnostics.EventLog]::SourceExists($SourceName)) {
                # Requires elevation to create; silently ignore if not present
                try { New-EventLog -LogName $LogName -Source $SourceName -ErrorAction Stop } catch {}
            }
            $EntryType = switch ($Type) {
                "SECURITY"  { "Warning" }
                "ERROR"     { "Error" }
                "WARN"      { "Warning" }
                "AUDIT"     { "Information" }
                "ACTION"    { "Information" }
                default     { "Information" }
            }
            Write-EventLog -LogName $LogName -Source $SourceName -EventId 1001 -EntryType $EntryType -Message "[$script:Branding] $Message" -ErrorAction SilentlyContinue
        } catch {}
    }

    # Only print to screen if we are NOT running silently in the background
    if (-not $SilentLock) {
        Write-Host "[$Type] $Message" -ForegroundColor $Color
    }
}

if (-not $SilentLock -and -not $ChildLock) { Write-Log -Message "Enterprise OS+DNS Lockdown Suite Initialized." -Type "SYSTEM" -Color Cyan }

# ============================================================================
# 3. SYSTEM AUDIT & HARDWARE DISCOVERY
# ============================================================================

function Run-SystemAudit {
    Write-Log -Message "Running Pre-Flight System Audit..." -Type "AUDIT" -Color DarkGray
    $OS = Get-CimInstance Win32_OperatingSystem
    Write-Log -Message "OS Version: $($OS.Caption) (Build $($OS.BuildNumber))" -Type "AUDIT" -Color DarkGray
    Write-Log -Message "PS Version: $($PSVersionTable.PSVersion)" -Type "AUDIT" -Color DarkGray
    Write-Log -Message "Execution Path: $ScriptDir" -Type "AUDIT" -Color DarkGray
    Write-Log -Message "Target Child User: $ChildUser" -Type "AUDIT" -Color DarkGray
}

if (-not $SilentLock -and -not $ChildLock) { Run-SystemAudit }

# Fetch all network adapters (excluding hidden virtual ones if possible, but keeping all physical)
$Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue } # Fallback

$SidAdmin = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$SidSystem = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
$SidUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")

# WhatIf/DryRun support: wrap modifying calls in a preview flag
$script:WhatIfPreference = $WhatIf.IsPresent
function Invoke-WhatIf {
    param([scriptblock]$Action, [string]$Description)
    if ($script:WhatIfPreference) {
        Write-Log -Message "[WhatIf] $Description" -Type "WhatIf" -Color Yellow
    } else {
        & $Action
    }
}

function Wait-AnyKey {
    <#
        Waits for a key press in a terminal-safe way.
        Uses a non-blocking 30-second poll loop that checks [Console]::KeyAvailable
        every 100ms to avoid freezes in Windows Terminal / VS Code.
        Falls back to Read-Host if the console input buffer is in a bad state.
    #>
    param([string]$Message = "Press Enter to continue...")
    try {
        if ($Host.Name -eq 'ConsoleHost') {
            $Timeout = 300
            for ($i = 0; $i -lt $Timeout; $i++) {
                if ([Console]::KeyAvailable) {
                    $null = [Console]::ReadKey($true)
                    return
                }
                Start-Sleep -Milliseconds 100
            }
            # Timeout reached - fall through to Read-Host
        }
    } catch {}
    Write-Host "`n[ $Message ]" -ForegroundColor Cyan
    $null = Read-Host
}

# ============================================================================
# 2.5.1 ATOMIC JSON FILE HELPERS (Prevents corruption from concurrent writes)
# ============================================================================

function Get-JsonMutexName {
    param([string]$FilePath)
    $Leaf = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    # Sanitize and truncate for mutex naming (max 260 chars, keep it short)
    $Safe = ($Leaf -replace '[^a-zA-Z0-9]', '')
    if ($Safe.Length -gt 50) { $Safe = $Safe.Substring(0,50) }
    return "Global\OSGuard-Json-$Safe"
}

function Write-JsonFile {
    <#
        Atomically writes JSON data to a file using a cross-process mutex and
        temp-file-then-rename to prevent corruption from concurrent writers
        (e.g., Process Enforcer + SilentLock both writing BlockedProcessHashes.json).
    #>
    param(
        [string]$Path,
        [object]$Data,
        [int]$Depth = 3,
        [switch]$Compress
    )
    if (-not $Path) { return $false }
    $MutexName = Get-JsonMutexName -FilePath $Path
    $Mutex = $null
    $GotLock = $false
    try {
        $Created = $false
        $Mutex = New-Object System.Threading.Mutex($false, $MutexName, [ref]$Created)
        $GotLock = $Mutex.WaitOne(30000)
        if (-not $GotLock) { return $false }
        $Json = if ($Compress) { $Data | ConvertTo-Json -Depth $Depth -Compress } else { $Data | ConvertTo-Json -Depth $Depth }
        $TempPath = "$Path.tmp.$PID"
        [System.IO.File]::WriteAllText($TempPath, $Json, [System.Text.UTF8Encoding]::new($false))
        # Atomic rename (replace existing)
        [System.IO.File]::Move($TempPath, $Path, $true)
        return $true
    } catch {
        return $false
    } finally {
        if ($GotLock) { try { $Mutex.ReleaseMutex() } catch {} }
        if ($Mutex) { try { $Mutex.Dispose() } catch {} }
        if (Test-Path "$Path.tmp.$PID") { Remove-Item -Path "$Path.tmp.$PID" -Force -ErrorAction SilentlyContinue }
    }
}

function Read-JsonFile {
    <#
        Reads JSON from a file using a cross-process shared mutex so it does not
        read a partially-written file. Returns $null on failure or missing file.
    #>
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return $null }
    $MutexName = Get-JsonMutexName -FilePath $Path
    $Mutex = $null
    $GotLock = $false
    try {
        $Created = $false
        $Mutex = New-Object System.Threading.Mutex($false, $MutexName, [ref]$Created)
        $GotLock = $Mutex.WaitOne(30000)
        if (-not $GotLock) { return $null }
        $Content = [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false))
        if ([string]::IsNullOrWhiteSpace($Content)) { return $null }
        return ($Content | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        return $null
    } finally {
        if ($GotLock) { try { $Mutex.ReleaseMutex() } catch {} }
        if ($Mutex) { try { $Mutex.Dispose() } catch {} }
    }
}

# ============================================================================
# 2.6 HEARTBEAT CRASH DETECTION
# ============================================================================

function Write-Heartbeat {
    <#
        Writes a lightweight heartbeat JSON to the heartbeat file every
        time the interactive menu loop iterates. Used by guardian tasks to
        detect unexpected terminal freezes or crashes vs. clean exits.
    #>
    try {
        $Heartbeat = @{
            Timestamp = (Get-Date -Format "o")
            Pid = $PID
            RunId = [System.Guid]::NewGuid().ToString("N")
        }
        Write-JsonFile -Path $HeartbeatFile -Data $Heartbeat -Compress | Out-Null
    } catch {}
}

function Write-CleanExit {
    <#
        Writes a clean-exit flag when the user exits via menu option [6].
        Guardians check this to distinguish a clean shutdown from a crash.
    #>
    try {
        $Clean = @{
            CleanExit = $true
            Timestamp = (Get-Date -Format "o")
            Pid = $PID
        }
        Write-JsonFile -Path $HeartbeatFile -Data $Clean -Compress | Out-Null
    } catch {}
}

function Test-Heartbeat {
    <#
        Checks the heartbeat file and returns a status string:
        OK          - Heartbeat is fresh (< 2 minutes)
        STALE       - Heartbeat is older than 2 minutes, no clean exit
        CLEAN_EXIT  - Last write was a clean exit
        MISSING     - Heartbeat file does not exist
    #>
    $Data = Read-JsonFile -Path $HeartbeatFile
    if (-not $Data) { return "MISSING" }
    if ($Data.CleanExit -eq $true) { return "CLEAN_EXIT" }
    $HeartbeatTime = $null
    try { $HeartbeatTime = [datetime]::Parse($Data.Timestamp) } catch { return "STALE" }
    if (-not $HeartbeatTime) { return "STALE" }
    if (((Get-Date) - $HeartbeatTime).TotalMinutes -gt 2) { return "STALE" }
    return "OK"
}

# ============================================================================
# 2.5 MULTIPLE INSTANCE PROTECTION
# ============================================================================

$script:InstanceMutex = $null

function Initialize-InstanceLock {
    <#
        Acquires a named mutex to prevent multiple instances of the script
        from running simultaneously. This protects registry operations, child hive
        mount/unmount, file writes (ProgramWhitelist.json, ScreenTimeTracker.json),
        and scheduled task modifications from race conditions.

        Background tasks (SilentLock, ScreenTimeEnforce, ProcessEnforce, ChildLock,
        ProgramScan, ChildAccessLog) use a short 5-second timeout and skip if busy.
        Interactive/CLI modes use a longer 30-second timeout and error if busy.

        Tries Global\ namespace first (cross-session), falls back to Local\ if
        access is denied (e.g., when a SYSTEM instance holds the global lock).
    #>
    param(
        [int]$TimeoutSeconds = 30,
        [switch]$BackgroundTask
    )
    $MutexPrefixes = @("Global\", "Local\")
    foreach ($Prefix in $MutexPrefixes) {
        $MutexName = "$Prefix`OSGuard-InstanceLock"
        $Created = $false
        try {
            $script:InstanceMutex = New-Object System.Threading.Mutex($false, $MutexName, [ref]$Created)
            if ($Created) {
                return $true
            }
            # Another instance already holds the mutex; try to acquire
            $WaitMs = if ($BackgroundTask) { 5000 } else { $TimeoutSeconds * 1000 }
            $GotLock = $script:InstanceMutex.WaitOne($WaitMs)
            if (-not $GotLock) {
                if ($BackgroundTask) {
                    Write-Log -Message "Another instance is already running. Skipping background task to avoid race conditions." -Type "WARN" -Color Yellow
                } else {
                    Write-Warning "Another instance of OS-Guard is already running. Exiting."
                }
                return $false
            }
            return $true
        } catch {
            $LastError = $_
            # If Global\ fails with access denied, try Local\ namespace next
            if ($Prefix -eq "Global\" -and ($LastError.Exception.Message -like "*Access*denied*" -or $LastError.Exception.Message -like "*Unauthorized*")) {
                continue
            }
            if ($BackgroundTask) {
                Write-Log -Message "Failed to acquire instance lock: $LastError" -Type "WARN" -Color Yellow
            } else {
                Write-Warning "Failed to acquire instance lock: $LastError"
            }
            return $false
        }
    }
    return $false
}

function Remove-InstanceLock {
    <#
        Releases the global instance mutex so another instance can run.
    #>
    if ($script:InstanceMutex) {
        try { $script:InstanceMutex.ReleaseMutex() } catch {}
        try { $script:InstanceMutex.Dispose() } catch {}
        $script:InstanceMutex = $null
    }
}

# Branding
$script:Branding = $BrandingOrg

# Home SSID for geofencing
$script:HomeSSID = $HomeSSID

# Multi-child support: build effective list
$script:EffectiveChildUsers = if ($ChildUsers.Count -gt 0) { $ChildUsers } else { @($ChildUser) }

# Canary file path
$CanaryFile = Join-Path $InstallDir ".osguard.canary"
$CanaryHashFile = Join-Path $InstallDir ".osguard.canary.sha256"

# Cache for expensive lookups
$script:CachedChildSid = @{}
$script:CachedChildProfilePath = @{}
$script:CacheTimestamp = $null
$script:CategoryGridCache = $null
$script:CategoryGridTimestamp = $null
$script:IntegrityHashCache = $null
$script:IntegrityHashTimestamp = $null

# Network UI restrictions are USER policies (HKCU)
$GpoPath = "HKCU:\Software\Policies\Microsoft\Windows\Network Connections"

# Define Browser DoH GPO Paths
$EdgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$ChromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$FirefoxPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"

# ============================================================================
# 3.1 OS LOCKDOWN POLICY DEFINITIONS
# ============================================================================

# Machine-wide (HKLM) policies. These apply to all users, but the built-in
# Administrator can elevate/bypass as needed. Standard users (child) are blocked.
$MachinePolicies = @(
    # UAC Maxed - child cannot turn off UAC
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableLUA"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorAdmin"; Value = 2 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "PromptOnSecureDesktop"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorUser"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableInstallerDetection"; Value = 1 },
    # MACHINE-WIDE NOTE: Hiding the Switch User button from the Ctrl+Alt+Del screen cannot be done per-user.
    # There is no documented HKCU policy for this. The only known Windows mechanism is HideFastUserSwitching in HKLM,
    # which applies to ALL users (admin and child). This means the admin will also not see Switch User on the lock
    # screen and Ctrl+Alt+Del while this policy is active. If you need Switch User as admin, uninstall or re-enable it.
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "HideFastUserSwitching"; Value = 1 }
)

# OOBE block policies: applied during install/Enable-OSLock, but NOT removed during Disable-OSLock
# so the child never gets the first-logon OOBE popup even during Parent Mode. Removed only during uninstall.
$OOBEBlockPolicies = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableFirstLogonAnimation"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"; Name = "DisablePrivacyExperience"; Value = 1 }
)

# Per-user (HKCU) policies applied to the child account only.
# SubPaths are relative to the user's hive root (no HKCU: prefix).
$ChildBasePolicies = @(
    # Disable Task Manager
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableTaskMgr"; Value = 1 },
    # Disable Registry Editor
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableRegistryTools"; Value = 1 },
    # Block password change
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableChangePassword"; Value = 1 },
    # Disable Lock Workstation (child cannot lock the session without parent)
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableLockWorkstation"; Value = 1 },
    # Disable Logoff in Windows Security (Ctrl+Alt+Del) -- only the admin-approved shortcut is allowed
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableLogoff"; Value = 1 },
    # Disable Themes tab
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "NoThemesTab"; Value = 1 },
    # Disable wallpaper change
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"; Name = "NoChangingWallPaper"; Value = 1 },
    # Disable Run dialog
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoRun"; Value = 1 },
    # Disable Control Panel & Settings app
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoControlPanel"; Value = 1 },
    # Disable AutoPlay for all drive types
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoDriveTypeAutoRun"; Value = 255 },
    # Hide Administrative Tools from start menu
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "StartMenuAdminTools"; Value = 0 },
    # Disable Add/Remove Programs (classic appwiz)
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall"; Name = "NoAddRemovePrograms"; Value = 1 },
    # Disable Command Prompt
    @{ SubPath = "Software\Policies\Microsoft\Windows\System"; Name = "DisableCMD"; Value = 2 },
    # Disable Windows Update UI for the child
    @{ SubPath = "Software\Policies\Microsoft\Windows\WindowsUpdate"; Name = "NoWindowsUpdate"; Value = 1 },
    # Network Connections UI restrictions (also applied machine-wide by DNS module)
    @{ SubPath = "Software\Policies\Microsoft\Windows\Network Connections"; Name = "NC_LanProperties"; Value = 0 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Network Connections"; Name = "NC_LanChangeProperties"; Value = 0 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Network Connections"; Name = "NC_AllowAdvancedTCPIPConfig"; Value = 0 },
    # Disable right-click context menu (prevents "Run as administrator", properties, etc.)
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoViewContextMenu"; Value = 1 },
    # Hide Sign Out from Start Menu user tile and Ctrl+Alt+Del so only the admin-approved shortcut is allowed
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "StartMenuLogOff"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoLogoff"; Value = 1 },
    # Hide Folder Options (prevent showing hidden/system files)
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoFolderOptions"; Value = 1 },
    # Block taskbar changes
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoSetTaskbar"; Value = 1 },
    # Block adding/removing printers
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoAddPrinter"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoDeletePrinter"; Value = 1 },
    # Hide "This PC" from desktop and start menu
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum"; Name = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"; Value = 1 },
    # Block exploit tools (Notepad, WordPad, Paint, Write) that can browse files via File -> Open
    # Disable "Open With" dialog to prevent file browsing via Choose Another App
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoOpenWith"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoInternetOpenWith"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoSecurityTab"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoHardwareTab"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoManageMyComputerVerb"; Value = 1 },
    # Start Menu hardening: lock pinning, drag-drop, context menus, and taskbar tray
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuPinnedList"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuDragDrop"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoTrayContextMenu"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoMovingBands"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoCloseDragDropBands"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuNetworkPlaces"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuEjectPC"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuMyGames"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuMyMusic"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuMyPictures"; Value = 1 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Explorer"; Name = "DisableNotificationCenter"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuDocuments"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuRecordings"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuHomegroup"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuFavorites"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuRecentDocs"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuRun"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuFind"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuHelp"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoBalloonTips"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "DisableContextMenusInStart"; Value = 1 },
    # Block child from signing out / shutting down via Start Menu and Windows Security (Ctrl+Alt+Del)
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoClose"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "HidePowerOptions"; Value = 1 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Explorer"; Name = "DisableNotificationCenter"; Value = 1 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsConsumerFeatures"; Value = 1 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Explorer"; Name = "DisableSearchBoxSuggestions"; Value = 1 },
    # GameDVR / Game Bar block (child-only HKCU)
    @{ SubPath = "Software\Policies\Microsoft\Windows\GameDVR"; Name = "AllowGameDVR"; Value = 0 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\GameDVR"; Name = "AllowOpenGameBar"; Value = 0 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\GameDVR"; Name = "AllowGameDVRRecording"; Value = 0 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\GameDVR"; Name = "AllowGameDVRCapture"; Value = 0 },
    # Cortana / Web Search block (child-only HKCU)
    @{ SubPath = "Software\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortana"; Value = 0 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Windows Search"; Name = "DisableWebSearch"; Value = 1 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Windows Search"; Name = "ConnectedSearchUseWeb"; Value = 0 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Windows Search"; Name = "ConnectedSearchUseWebOverMeteredConnections"; Value = 0 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Windows Search"; Name = "ConnectedSearchSafeSearch"; Value = 1 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Windows Search"; Name = "ConnectedSearchPrivacy"; Value = 1 },
    # AppInstaller / winget block (child-only HKCU)
    @{ SubPath = "Software\Policies\Microsoft\Windows\AppInstaller"; Name = "EnableAppInstaller"; Value = 0 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\AppInstaller"; Name = "EnableWindowsPackageManager"; Value = 0 },
    # Browser DoH blocks (child-only HKCU)
    @{ SubPath = "Software\Policies\Microsoft\Edge"; Name = "DnsOverHttpsMode"; Value = "off" },
    @{ SubPath = "Software\Policies\Microsoft\Edge"; Name = "BuiltInDnsClientEnabled"; Value = 0 },
    @{ SubPath = "Software\Policies\Google\Chrome"; Name = "DnsOverHttpsMode"; Value = "off" },
    @{ SubPath = "Software\Policies\Mozilla\Firefox\DNSOverHTTPS"; Name = "Enabled"; Value = 0 },
    # Edge bypass policies (child-only HKCU)
    @{ SubPath = "Software\Policies\Microsoft\Edge"; Name = "DefaultPopupsSetting"; Value = 2 },
    @{ SubPath = "Software\Policies\Microsoft\Edge"; Name = "RendererCodeIntegrityEnabled"; Value = 1 },
    @{ SubPath = "Software\Policies\Microsoft\Edge"; Name = "BrowserLegacyExtensionPointsBlocked"; Value = 1 },
    @{ SubPath = "Software\Policies\Microsoft\Edge"; Name = "AllowDeletingBrowserHistory"; Value = 0 },
    # Edge URL blocklist (child-only HKCU) - cloud gaming, remote shell, IDE bypass URLs
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "1"; Value = "xbox.com/play" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "2"; Value = "play.geforcenow.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "3"; Value = "cloud.boosteroid.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "4"; Value = "luna.amazon.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "5"; Value = "stadia.google.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "6"; Value = "parsec.app" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "7"; Value = "moonlight-stream.org" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "8"; Value = "rainway.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "9"; Value = "shadow.tech" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "10"; Value = "airgpu.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "11"; Value = "maximumsettings.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "12"; Value = "shell.cloud.google.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "13"; Value = "github.com/codespaces" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "14"; Value = "replit.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "15"; Value = "codesandbox.io" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "16"; Value = "codepen.io" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "17"; Value = "jsfiddle.net" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "18"; Value = "stackblitz.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "19"; Value = "gitpod.io" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "20"; Value = "heroku.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "21"; Value = "aws.amazon.com/cloud9" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "22"; Value = "shell.azure.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "23"; Value = "console.cloud.google.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "24"; Value = "ide.goorm.io" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "25"; Value = "glot.io" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "26"; Value = "tio.run" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "27"; Value = "paiza.io" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "28"; Value = "onlinegdb.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "29"; Value = "rextester.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "30"; Value = "ideone.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "31"; Value = "dotnetfiddle.net" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "32"; Value = "plnkr.co" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "33"; Value = "glitch.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "34"; Value = "coder.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "35"; Value = "vscode.dev" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "36"; Value = "github.dev" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "37"; Value = "gitpod.ws" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "38"; Value = "anydesk.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "39"; Value = "teamviewer.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "40"; Value = "remotedesktop.google.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "41"; Value = "rustdesk.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "42"; Value = "nomachine.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "43"; Value = "splashtop.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "44"; Value = "logmein.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "45"; Value = "goto.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "46"; Value = "join.me" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "47"; Value = "discord.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "48"; Value = "discordapp.com" },
    @{ SubPath = "Software\Policies\Microsoft\Edge\URLBlocklist"; Name = "49"; Value = "web.telegram.org" }
)
$ChildDisallowRunPolicies = @(
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "DisallowRun"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "1"; Value = "notepad.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "2"; Value = "wordpad.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "3"; Value = "mspaint.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "4"; Value = "write.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "5"; Value = "explorer.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "6"; Value = "pwsh.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "7"; Value = "pwsh.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "8"; Value = "cmd.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "9"; Value = "wscript.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "10"; Value = "cscript.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "11"; Value = "mshta.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "12"; Value = "certutil.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "13"; Value = "bitsadmin.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "14"; Value = "wmic.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "15"; Value = "regsvr32.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "16"; Value = "rundll32.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "17"; Value = "msiexec.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "18"; Value = "msconfig.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "19"; Value = "mmc.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "20"; Value = "eventvwr.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "21"; Value = "fodhelper.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "22"; Value = "computerdefaults.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "23"; Value = "slui.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "24"; Value = "dccw.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "25"; Value = "xwizard.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "26"; Value = "taskkill.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "27"; Value = "ftp.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "28"; Value = "tftp.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "29"; Value = "telnet.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "30"; Value = "curl.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "31"; Value = "robocopy.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "32"; Value = "takeown.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "33"; Value = "icacls.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "34"; Value = "net.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "35"; Value = "net1.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "36"; Value = "schtasks.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "37"; Value = "at.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "38"; Value = "cleanmgr.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "39"; Value = "sdclt.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "40"; Value = "systempropertiesadvanced.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "41"; Value = "ms-settings.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "42"; Value = "control.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "43"; Value = "inetcpl.cpl" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "44"; Value = "appwiz.cpl" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "45"; Value = "compmgmt.msc" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "46"; Value = "diskmgmt.msc" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "47"; Value = "devmgmt.msc" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "48"; Value = "taskmgr.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "49"; Value = "regedit.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "50"; Value = "perfmon.exe" },
    # Block all alternative browsers so Edge is the only viable option
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "51"; Value = "chrome.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "52"; Value = "firefox.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "53"; Value = "brave.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "54"; Value = "opera.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "55"; Value = "vivaldi.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "56"; Value = "waterfox.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "57"; Value = "tor.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "58"; Value = "iexplore.exe" },
    # Extended bypass mitigation entries
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "59"; Value = "powershell_ise.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "60"; Value = "wt.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "61"; Value = "WindowsTerminal.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "62"; Value = "Code.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "63"; Value = "python.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "64"; Value = "python3.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "65"; Value = "py.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "66"; Value = "node.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "67"; Value = "java.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "68"; Value = "javaw.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "69"; Value = "dotnet.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "70"; Value = "docker.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "71"; Value = "winget.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "72"; Value = "AppInstaller.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "73"; Value = "steam.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "74"; Value = "epicgameslauncher.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "75"; Value = "origin.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "76"; Value = "uplay.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "77"; Value = "battle.net.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "78"; Value = "Discord.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "79"; Value = "Telegram.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "80"; Value = "AnyDesk.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "81"; Value = "TeamViewer.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "82"; Value = "mstsc.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "83"; Value = "VirtualBox.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "84"; Value = "vmware.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "85"; Value = "qemu-system-x86_64.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "86"; Value = "PuTTY.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "87"; Value = "WinSCP.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "88"; Value = "FileZilla.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "89"; Value = "openvpn.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "90"; Value = "nordvpn.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "91"; Value = "expressvpn.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "92"; Value = "protonvpn.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "93"; Value = "ssh.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "94"; Value = "wsl.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "95"; Value = "bash.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "96"; Value = "vmcompute.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "97"; Value = "vmwp.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "98"; Value = "msdt.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "99"; Value = "sdbinst.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "100"; Value = "wusa.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "101"; Value = "tscon.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "102"; Value = "tsdiscon.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "103"; Value = "shadow.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "104"; Value = "tskill.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "105"; Value = "qwinsta.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "106"; Value = "rwinsta.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "107"; Value = "reset_session.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "108"; Value = "SnippingTool.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "109"; Value = "ScreenSketch.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "110"; Value = "SpeechRuntime.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "111"; Value = "SearchIndexer.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "112"; Value = "SearchUI.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "113"; Value = "Cortana.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "114"; Value = "GameBar.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "115"; Value = "GameBarPresenceWriter.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "116"; Value = "XboxApp.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "117"; Value = "XboxGameBar.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "118"; Value = "XboxGameBarSpotify.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "119"; Value = "ms-teams.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "120"; Value = "Teams.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "121"; Value = "slack.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "122"; Value = "zoom.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "123"; Value = "webex.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "124"; Value = "gotomeeting.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "125"; Value = "join.me.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "126"; Value = "remotedesktop.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "127"; Value = "chrome_remote_desktop.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "128"; Value = "parsec.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "129"; Value = "moonlight.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "130"; Value = "rainway.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "131"; Value = "shadow.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "132"; Value = "airgpu.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "133"; Value = "maximumsettings.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "134"; Value = "cloud gaming.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "135"; Value = "geforcenow.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "136"; Value = "boosteroid.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "137"; Value = "luna.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "138"; Value = "stadia.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "139"; Value = "xboxcloudgaming.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "140"; Value = "playstationnow.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "141"; Value = "psremoteplay.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "142"; Value = "steamlink.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "143"; Value = "nvidiashield.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "144"; Value = "amdlink.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "145"; Value = "intelunison.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "146"; Value = "linktowindows.exe" },
    # IFEO backdoor tools (child-only via DisallowRun instead of machine-wide IFEO)
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "147"; Value = "sethc.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "148"; Value = "utilman.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "149"; Value = "osk.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "150"; Value = "magnify.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "151"; Value = "narrator.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "152"; Value = "DisplaySwitch.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "153"; Value = "logoff.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "154"; Value = "shutdown.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "155"; Value = "ms-windows-store.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "156"; Value = "WinStore.App.exe" }
)

# RestrictRun (whitelist) master switch -- entries are written dynamically from ProgramWhitelist.json
$ChildRestrictRunPolicies = @(
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "RestrictRun"; Value = 1 }
)

# ============================================================================
# 4. CHILD ACCOUNT MANAGEMENT
# ============================================================================

function Get-ChildAccount {
    param([string]$UserName = $ChildUser)
    # Returns the LocalUser object for the child account, or $null
    try {
        return (Get-LocalUser -Name $UserName -ErrorAction Stop)
    } catch {
        return $null
    }
}

function Get-ChildSid {
    param([string]$UserName = $ChildUser)
    # Check cache first
    if ($script:CachedChildSid.ContainsKey($UserName)) {
        return $script:CachedChildSid[$UserName]
    }
    $Acct = Get-ChildAccount -UserName $UserName
    $Result = $null
    if ($Acct) { $Result = $Acct.SID.Value }
    $script:CachedChildSid[$UserName] = $Result
    return $Result
}

function Get-AllChildProfilePaths {
    param([string]$UserName = $ChildUser)
    <#
        Returns ALL existing profile folders matching C:\Users\$UserName*.
        Used for cleanup operations that must target every stale folder.
    #>
    $Paths = @()
    $UsersDir = "C:\Users"
    if (Test-Path $UsersDir) {
        try {
            $Matches = Get-ChildItem -Path $UsersDir -Directory -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -eq $UserName -or $_.Name -like "$UserName.*"
            }
            $Paths = $Matches | Select-Object -ExpandProperty FullName
        } catch {}
    }
    return $Paths
}

function Get-ChildProfilePath {
    param([string]$UserName = $ChildUser, [string]$ChildSidValue, [switch]$NoCache)
    if (-not $ChildSidValue) { $ChildSidValue = Get-ChildSid -UserName $UserName }
    if (-not $ChildSidValue) { return $null }
    # Always query the live profile path from WMI first so we never target a stale folder
    try {
        $Profile = Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.SID -eq $ChildSidValue } | Select-Object -First 1
        if ($Profile -and $Profile.LocalPath -and (Test-Path $Profile.LocalPath)) {
            $script:CachedChildProfilePath[$UserName] = $Profile.LocalPath
            return $Profile.LocalPath
        }
    } catch {}
    # If WMI returned nothing, the child may not have logged in yet or the account was deleted.
    # Scan the filesystem for the most recently modified matching folder to avoid targeting a stale profile.
    $CandidatePaths = Get-AllChildProfilePaths -UserName $UserName
    if ($CandidatePaths.Count -gt 0) {
        # Prefer the most recently modified folder (the active one)
        $MostRecent = $CandidatePaths | Sort-Object { (Get-Item $_ -ErrorAction SilentlyContinue).LastWriteTime } -Descending | Select-Object -First 1
        if ($MostRecent -and (Test-Path $MostRecent)) {
            if (-not $NoCache) { $script:CachedChildProfilePath[$UserName] = $MostRecent }
            return $MostRecent
        }
    }
    # Last resort: use cache only if it still exists
    if (-not $NoCache -and $script:CachedChildProfilePath.ContainsKey($UserName)) {
        $Cached = $script:CachedChildProfilePath[$UserName]
        if ($Cached -and (Test-Path $Cached)) { return $Cached }
        $script:CachedChildProfilePath.Remove($UserName)
    }
    return $null
}

function Clear-ChildCache {
    $script:CachedChildSid = @{}
    $script:CachedChildProfilePath = @{}
}

# PBKDF2 helpers
function New-PBKDF2Hash {
    param([string]$Password, [string]$SaltBase64, [int]$Iterations = 100000)
    $SaltBytes = [Convert]::FromBase64String($SaltBase64)
    $Derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $SaltBytes, $Iterations)
    $HashBytes = $Derive.GetBytes(32)
    $Derive.Dispose()
    return [Convert]::ToBase64String($HashBytes)
}

function Get-PBKDF2Salt {
    $Salt = [byte[]]::new(32)
    $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Rng.GetBytes($Salt)
    $Rng.Dispose()
    return [Convert]::ToBase64String($Salt)
}

function Show-SetAfkTimeoutDialog {
    <#
        Interactive dialog to set the Parent Mode AFK timeout in minutes.
    #>
    Clear-Host
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " SET PARENT MODE AFK TIMEOUT " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host "`nHow many minutes of inactivity before auto-locking?" -ForegroundColor White
    Write-Host '  (1-120 minutes, default=5)' -ForegroundColor DarkGray

    $InputVal = Read-Host "Enter timeout in minutes"
    if ($InputVal -match '^\d+$') {
        $Minutes = [int]$InputVal
        if ($Minutes -ge 1 -and $Minutes -le 120) {
            try {
                if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
                Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeAFKTimeout" -Value $Minutes -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Host "`[SUCCESS] AFK timeout set to $Minutes minute(s)." -ForegroundColor Green

            } catch {
                Write-Host "`[ERROR] Failed to set AFK timeout: $_" -ForegroundColor Red

            }
        } else {
            Write-Host '[ERROR] Must be between 1 and 120 minutes.' -ForegroundColor Red

        }
    } else {
        Write-Host '[ERROR] Invalid input. Please enter a number.' -ForegroundColor Red

    }
    Write-Host "`n[ PRESS ANY KEY TO RETURN ]" -ForegroundColor DarkGray; Wait-AnyKey
}

function New-MemorablePassword {
    <#
        Generates a memorable password using a common word + 2-digit number + easy symbol.
        Easy symbols are limited to keys found on all keyboards: ! # $ % & + - = ? _ @
    #>
    $Words = @(
        "Dragon","Tiger","Lion","Bear","Wolf","Eagle","Fox","Cat","Dog","Bird",
        "Fish","Owl","Frog","Snake","House","Cloud","Moon","Star","Tree","Fire",
        "Ice","Wind","Sun","Road","Lake","Rock","Sand","Snow","Wave","Rose",
        "Sky","Sea","Gold","Boat","Car","Train","Plane","Ship","Door","Wall",
        "Desk","Chair","Table","Bed","Book","Pen","Cup","Hat","Shoe","Coat",
        "Bag","Box","Ring","Game","Ball","Toy","Flag","Map","Sword","Robot",
        "Knight","Castle","Tower","Bridge","Garden","Park","Forest","Beach","Hill","River"
    )
    $Symbols = @("!","#","$","%","&","+","-","=","?","_","@")
    $Word = $Words | Get-Random
    $Number = Get-Random -Minimum 10 -Maximum 99
    $Symbol = $Symbols | Get-Random
    $Patterns = @(
        "{0}{1}{2}",    # WordNumberSymbol  e.g. Dragon42!
        "{0}{2}{1}",    # WordSymbolNumber  e.g. Dragon!42
        "{1}{0}{2}",    # NumberWordSymbol  e.g. 42Dragon!
        "{2}{0}{1}"     # SymbolWordNumber  e.g. !Dragon42
    )
    $Pattern = $Patterns | Get-Random
    return ($Pattern -f $Word, $Number, $Symbol)
}

function Test-PasswordComplexity {
    param([string]$Password)
    # Relaxed complexity: at least 6 chars, at least one letter and one number
    if ($Password.Length -lt 6) { return $false }
    $HasLetter = $Password -match '[a-zA-Z]'
    $HasNumber = $Password -match '\d'
    return ($HasLetter -and $HasNumber)
}

function New-ChildAccount {
    <#
        Creates a PASSWORDLESS local standard user if it does not already exist.
        Ensures it is NOT a member of Administrators and IS a member of Users.
        Prevents the child from changing or setting a password.
    #>
    $Existing = Get-ChildAccount
    if ($Existing) {
        Write-Log -Message "Child account '$ChildUser' already exists. Patching existing account to standard-user membership." -Type "INFO" -Color Gray
        # Ensure NOT an administrator
        try {
            $AdminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Where-Object { $_.Name -match "$ChildUser$" }
            if ($AdminGroup) {
                Remove-LocalGroupMember -Group "Administrators" -Member $ChildUser -ErrorAction SilentlyContinue
                Write-Log -Message "Removed '$ChildUser' from Administrators group." -Type "WARN" -Color Yellow
            }
        } catch {}
        # Ensure IS a member of Users
        try {
            Add-LocalGroupMember -Group "Users" -Member $ChildUser -ErrorAction Stop
        } catch {}
        # Prevent password change
        net user $ChildUser /passwordchg:no 2>&1 | Out-Null
        net user $ChildUser /passwordreq:no 2>&1 | Out-Null
        Clear-ChildCache
        return $false  # not newly created
    }

    # Create passwordless account
    # Use net user as the primary path because it reliably creates an empty-password
    # account that Windows accepts at first interactive logon. New-LocalUser -NoPassword
    # sometimes leaves the password hash in a null state that Windows rejects.
    $Created = $false
    $netResult = net user $ChildUser /add /active:yes /passwordreq:no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log -Message "Created PASSWORDLESS child account '$ChildUser' via net user." -Type "SUCCESS" -Color Green
        $Created = $true
    } else {
        Write-Log -Message "net user failed for '$ChildUser': $netResult. Trying New-LocalUser fallback..." -Type "WARN" -Color Yellow
        try {
            New-LocalUser -Name $ChildUser -NoPassword -Description "OS-Guard managed child account (passwordless)" -PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop | Out-Null
            # Ensure the password hash is explicitly initialized to empty so logon works
            try {
                $EmptyPassword = New-Object System.Security.SecureString
                Set-LocalUser -Name $ChildUser -Password $EmptyPassword -ErrorAction Stop
            } catch {
                # If Set-LocalUser is blocked by password policy, use ADSI which bypasses it
                $User = [ADSI]"WinNT://./$ChildUser,user"
                $User.SetPassword("")
                $User.SetInfo()
            }
            Write-Log -Message "Created PASSWORDLESS child account '$ChildUser' via New-LocalUser." -Type "SUCCESS" -Color Green
            $Created = $true
        } catch {
            Write-Log -Message "Failed to create child account '$ChildUser' via New-LocalUser: $_" -Type "ERROR" -Color Red
            return $false
        }
    }

    # Add to standard Users group
    try {
        Add-LocalGroupMember -Group "Users" -Member $ChildUser -ErrorAction Stop
        Write-Log -Message "Added '$ChildUser' to Users group." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Add-LocalGroupMember failed for Users: $_. Trying net localgroup fallback..." -Type "WARN" -Color Yellow
        net localgroup Users $ChildUser /add 2>&1 | Out-Null
    }

    # Prevent the child from changing or setting a password (lockdown reinforcement)
    net user $ChildUser /passwordchg:no 2>&1 | Out-Null
    net user $ChildUser /passwordreq:no 2>&1 | Out-Null
    Write-Log -Message "Password change disabled for '$ChildUser'." -Type "INFO" -Color Gray

    # Enable the account (in case it was created disabled)
    Enable-LocalUser -Name $ChildUser -ErrorAction SilentlyContinue

    Clear-ChildCache
    return $true  # newly created
}

# ============================================================================
# 5. CHILD REGISTRY HIVE MOUNT/DISMOUNT
# ============================================================================

function Mount-ChildHive {
    <#
        Loads the child's NTUSER.DAT into HKEY_USERS\OSGuardChildPolicy so we can
        write per-user HKCU policies even when the child is not logged in.
        Returns the hive mount name, or $null on failure (including when the child
        is logged in and the hive is locked, in which case live-session policies apply).
    #>
    $ChildSidValue = Get-ChildSid
    if (-not $ChildSidValue) {
        Write-Log -Message "Cannot mount child hive: child account '$ChildUser' not found." -Type "WARN" -Color Yellow
        return $null
    }
    $ProfilePath = Get-ChildProfilePath -ChildSidValue $ChildSidValue
    if (-not $ProfilePath) {
        Write-Log -Message "Cannot mount child hive: no profile path for '$ChildUser' (never logged in?)." -Type "WARN" -Color Yellow
        return $null
    }
    $NtUserDat = Join-Path $ProfilePath "NTUSER.DAT"
    if (-not (Test-Path $NtUserDat)) {
        Write-Log -Message "Cannot mount child hive: NTUSER.DAT missing at $NtUserDat." -Type "WARN" -Color Yellow
        return $null
    }

    # If the child is currently logged in, the live session hive is available and
    # NTUSER.DAT is locked. Skip the offline mount and signal the caller to use the live session.
    $LiveSessionPath = "Registry::HKEY_USERS\$ChildSidValue"
    if (Test-Path $LiveSessionPath) {
        Write-Log -Message "Child '$ChildUser' is currently logged in. Offline hive will not be mounted; policies will be applied to the live session ($ChildSidValue)." -Type "INFO" -Color Gray
        return $null
    }

    $HiveMount = "OSGuardChildPolicy"
    # If already mounted (e.g. left over), unload first
    if (Test-Path "Registry::HKEY_USERS\$HiveMount") {
        Dismount-ChildHive -HiveMount $HiveMount
    }

    $Output = & reg.exe load "HKU\$HiveMount" "$NtUserDat" 2>&1
    $RegExit = $LASTEXITCODE
    # Retry Test-Path up to 5 times because registry visibility may lag behind reg.exe success
    $Retries = 0
    while ($Retries -lt 5) {
        if (Test-Path "Registry::HKEY_USERS\$HiveMount") {
            Write-Log -Message "Child hive mounted at HKU\$HiveMount." -Type "INFO" -Color Gray
            return $HiveMount
        }
        if ($RegExit -eq 0) {
            Start-Sleep -Milliseconds 200
            $Retries++
        } else {
            break
        }
    }
    # Translate common error into a clear message
    $ErrorText = $Output -join " "
    if ($ErrorText -match "används av en annan process" -or $ErrorText -match "being used by another process" -or $ErrorText -match "Access is denied" -or $ErrorText -match ".*?åt filen.*?") {
        Write-Log -Message "Cannot mount child hive: NTUSER.DAT is locked (child is likely logged in). Policies will be applied to the live session." -Type "INFO" -Color Gray
    } elseif ($RegExit -eq 0) {
        Write-Log -Message "reg.exe load succeeded for child hive but hive is not visible after retries. $ErrorText" -Type "WARN" -Color Yellow
    } else {
        Write-Log -Message "Failed to mount child hive (exit $RegExit): $Output" -Type "WARN" -Color Yellow
    }
    return $null
}

function Dismount-ChildHive {
    param([string]$HiveMount = "OSGuardChildPolicy")
    # Only unload if the hive is actually mounted (avoids 'parameter is incorrect' spam)
    if (-not (Test-Path "Registry::HKEY_USERS\$HiveMount")) { return }
    # Release any open handles before unloading
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Start-Sleep -Milliseconds 300
    $Output = & reg.exe unload "HKU\$HiveMount" 2>&1
    if ($LASTEXITCODE -ne 0) {
        $IgnoreErrors = @("ERROR: The parameter is incorrect", "ERROR: Invalid parameter", "ERROR: Det går inte att hitta den angivna filen", "ERROR: The system cannot find the file specified")
        $ShouldIgnore = $false
        foreach ($Pattern in $IgnoreErrors) {
            if ($Output -join " " -match [regex]::Escape($Pattern)) { $ShouldIgnore = $true; break }
        }
        if (-not $ShouldIgnore) {
            Write-Log -Message "Child hive unload returned (exit $LASTEXITCODE): $Output" -Type "AUDIT" -Color DarkGray
        }
    }
}

function Mount-DefaultProfileHive {
    <#
        Loads the Default user profile NTUSER.DAT into HKEY_USERS\OSGuardDefaultPolicy
        so we can seed child policies for first-logon profile creation.
        Returns the hive mount name, or $null on failure.
    #>
    $DefaultProfile = "C:\Users\Default"
    $NtUserDat = Join-Path $DefaultProfile "NTUSER.DAT"
    if (-not (Test-Path $NtUserDat)) {
        Write-Log -Message "Default profile NTUSER.DAT not found at $NtUserDat." -Type "WARN" -Color Yellow
        return $null
    }
    $HiveMount = "OSGuardDefaultPolicy"
    if (Test-Path "Registry::HKEY_USERS\$HiveMount") {
        Dismount-ChildHive -HiveMount $HiveMount
    }
    $Output = & reg.exe load "HKU\$HiveMount" "$NtUserDat" 2>&1
    $RegExit = $LASTEXITCODE
    $Retries = 0
    while ($Retries -lt 5) {
        if (Test-Path "Registry::HKEY_USERS\$HiveMount") {
            Write-Log -Message "Default profile hive mounted at HKU\$HiveMount." -Type "INFO" -Color Gray
            return $HiveMount
        }
        if ($RegExit -eq 0) {
            Start-Sleep -Milliseconds 200
            $Retries++
        } else {
            break
        }
    }
    if ($RegExit -eq 0) {
        Write-Log -Message "reg.exe load succeeded for default profile hive but hive is not visible after retries. $Output" -Type "WARN" -Color Yellow
    } else {
        Write-Log -Message "Failed to mount default profile hive (exit $RegExit): $Output" -Type "WARN" -Color Yellow
    }
    return $null
}

function Apply-ChildPoliciesToDefaultProfile {
    <#
        Applies child base policies, DisallowRun, and Edge policies to the
        Default user profile so newly created profiles inherit them on first logon.
    #>
    $HiveMount = Mount-DefaultProfileHive
    if (-not $HiveMount) {
        Write-Log -Message "Default profile hive not available - skipping seed." -Type "WARN" -Color Yellow
        return
    }
    try {
        if (Test-Path "Registry::HKEY_USERS\$HiveMount") {
            Apply-ChildHivePolicies -HiveMount $HiveMount -Policies $ChildBasePolicies
            Apply-ChildHivePolicies -HiveMount $HiveMount -Policies $ChildDisallowRunPolicies
            Apply-EdgePolicies -HiveMount $HiveMount
            Write-Log -Message "Child policies seeded into Default profile (first-logon inheritance)." -Type "SUCCESS" -Color Green
        } else {
            Write-Log -Message "Default profile hive was unloaded before policies could be applied." -Type "WARN" -Color Yellow
        }
    } catch {
        Write-Log -Message "Failed to seed policies into Default profile: $_" -Type "WARN" -Color Yellow
    } finally {
        Dismount-ChildHive -HiveMount $HiveMount
    }
}

function Remove-ChildPoliciesFromDefaultProfile {
    <#
        Removes child policies from the Default user profile during uninstall.
    #>
    $HiveMount = Mount-DefaultProfileHive
    if (-not $HiveMount) { return }
    try {
        Remove-ChildHivePolicies -HiveMount $HiveMount -Policies $ChildBasePolicies
        Remove-ChildHivePolicies -HiveMount $HiveMount -Policies $ChildDisallowRunPolicies
        Remove-EdgePolicies -HiveMount $HiveMount
        Write-Log -Message "Child policies removed from Default profile." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to remove policies from Default profile: $_" -Type "WARN" -Color Yellow
    } finally {
        Dismount-ChildHive -HiveMount $HiveMount
    }
}

# ============================================================================
# 6. OS LOCKDOWN MODULE (ENABLE)
# ============================================================================

function Apply-ChildHivePolicies {
    param(
        [string]$HiveMount,
        [array]$Policies = $ChildBasePolicies
    )
    if (-not $HiveMount) { return }
    $HiveRoot = "Registry::HKEY_USERS\$HiveMount"
    foreach ($Policy in $Policies) {
        $KeyPath = "$HiveRoot\$($Policy.SubPath)"
        try {
            if (-not (Test-Path $KeyPath)) {
                New-Item -Path $KeyPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
            $PropType = if ($Policy.Value -is [string]) { "String" } else { "DWord" }
            Set-ItemProperty -Path $KeyPath -Name $Policy.Name -Value $Policy.Value -Type $PropType -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log -Message "Failed to set child policy $($Policy.Name) at $($Policy.SubPath): $_" -Type "WARN" -Color Yellow
        }
    }
}

function Remove-ChildHivePolicies {
    param(
        [string]$HiveMount,
        [array]$Policies = $ChildBasePolicies
    )
    if (-not $HiveMount) { return }
    $HiveRoot = "Registry::HKEY_USERS\$HiveMount"
    foreach ($Policy in $Policies) {
        $KeyPath = "$HiveRoot\$($Policy.SubPath)"
        try {
            if (Test-Path $KeyPath) {
                Remove-ItemProperty -Path $KeyPath -Name $Policy.Name -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    # Clean up entire DisallowRun subkey to remove stale entries from previous lists
    try {
        $DisallowRunPath = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"
        if (Test-Path $DisallowRunPath) {
            Remove-Item -Path $DisallowRunPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

# ============================================================================
# 6.1 PROGRAM WHITELIST MANAGEMENT (RestrictRun)
# ============================================================================

function Scan-CommonProgramsForWhitelist {
    <#
        Scans common installation directories (Program Files, WindowsApps, child profile)
        for executable files and returns a list of suggested whitelist entries.
        Excludes system directories and known dangerous paths.
    #>
    $Suggestions = @()
    $ScanPaths = @(
        $env:ProgramFiles,
        "${env:ProgramFiles(x86)}",
        "C:\Program Files\WindowsApps",
        (Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps")
    )
    $ChildProfilePath = Get-ChildProfilePath
    if ($ChildProfilePath) {
        $ScanPaths += (Join-Path $ChildProfilePath "AppData\Local\Programs")
    }
    foreach ($BasePath in $ScanPaths) {
        if (-not $BasePath -or -not (Test-Path $BasePath)) { continue }
        try {
            $Exes = Get-ChildItem -Path $BasePath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 50
            foreach ($Exe in $Exes) {
                $Name = $Exe.Name.ToLower()
                if ($Suggestions -notcontains $Name) { $Suggestions += $Name }
            }
        } catch {}
    }
    return ,@($Suggestions | Sort-Object)
}

function Get-DefaultProgramWhitelist {
    <#
        Returns the default list of allowed executables for RestrictRun.
        Includes critical Windows processes, Edge, and common built-in apps.
    #>
    return ,@(
        "explorer.exe",
        "ApplicationFrameHost.exe",
        "WWAHost.exe",
        "dllhost.exe",
        "sihost.exe",
        "RuntimeBroker.exe",
        "ShellExperienceHost.exe",
        "StartMenuExperienceHost.exe",
        "TextInputHost.exe",
        "SearchApp.exe",
        "SearchIndexer.exe",
        "SecurityHealthSystray.exe",
        "dwm.exe",
        "csrss.exe",
        "lsass.exe",
        "services.exe",
        "smss.exe",
        "wininit.exe",
        "winlogon.exe",
        "fontdrvhost.exe",
        "taskhostw.exe",
        "conhost.exe",
        "ctfmon.exe",
        "notepad.exe",
        "calc.exe",
        "mspaint.exe",
        "write.exe",
        "SnippingTool.exe",
        "ScreenSketch.exe",
        "SoundRecorder.exe",
        "Video.UI.exe",
        "Microsoft.Photos.exe",
        "solitaire.exe",
        "pwsh.exe",
        "pwsh.exe",
        "GameBar.exe",
        "GameBarPresenceWriter.exe",
        "XboxGameBar.exe",
        "XboxApp.exe",
        "XboxGameBarSpotify.exe",
        "GameBarFT.exe"
    )
}

function Get-ProgramWhitelist {
    $Data = Read-JsonFile -Path $ProgramWhitelistFile
    if ($Data -is [array]) { return ,$Data }
    if ($Data) { return ,@($Data) }
    return ,@()
}

function Set-ProgramWhitelist {
    param([array]$List)
    $Success = Write-JsonFile -Path $ProgramWhitelistFile -Data $List -Depth 3
    if ($Success) {
        Harden-ScreenTimeFile -FilePath $ProgramWhitelistFile
    } else {
        Write-Log -Message "Failed to save program whitelist (mutex/atomic write failed)." -Type "WARN" -Color Yellow
    }
}

function Get-RestrictRunStrictMode {
    <#
        Returns $true if RestrictRun should use ONLY the explicit whitelist
        (no automatic fallback to default programs). Returns $false by default.
    #>
    try {
        $val = Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardRestrictRunStrictMode" -ErrorAction Stop
        return ($val -eq 1)
    } catch { return $false }
}

function Set-RestrictRunStrictMode {
    param([bool]$Enabled)
    try {
        $val = if ($Enabled) { 1 } else { 0 }
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardRestrictRunStrictMode" -Value $val -Type DWord -Force -ErrorAction Stop
        Write-Log -Message "RestrictRun strict mode set to $Enabled" -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to set RestrictRun strict mode: $_" -Type "WARN" -Color Yellow
    }
}

function Add-BrowserToWhitelist {
    <#
        Temporarily adds msedge.exe to the program whitelist so the child
        can use the browser during an approved browser time window.
        Re-applies RestrictRun to the live child hive immediately.
    #>
    $Whitelist = Get-ProgramWhitelist
    if ($Whitelist.Count -eq 0 -and -not (Get-RestrictRunStrictMode)) {
        $Whitelist = Get-DefaultProgramWhitelist
    }
    if ($Whitelist -notcontains "msedge.exe") {
        $Whitelist += "msedge.exe"
        Set-ProgramWhitelist -List $Whitelist
        Write-Log -Message "Browser (msedge.exe) added to program whitelist." -Type "INFO" -Color Green
    }
    # Re-apply RestrictRun to live child hive if child is currently logged in
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        Apply-RestrictRunPolicies -HiveMount $ChildSidValue
        Write-Log -Message "RestrictRun re-applied to live child hive (browser unlocked)." -Type "INFO" -Color Gray
    }
}

function Remove-BrowserFromWhitelist {
    <#
        Removes msedge.exe from the program whitelist so the child can no longer
        launch the browser. Re-applies RestrictRun to the live child hive immediately.
    #>
    $Whitelist = Get-ProgramWhitelist
    if ($Whitelist.Count -eq 0 -and -not (Get-RestrictRunStrictMode)) {
        $Whitelist = Get-DefaultProgramWhitelist
    }
    if ($Whitelist -contains "msedge.exe") {
        $Whitelist = $Whitelist | Where-Object { $_ -ne "msedge.exe" }
        Set-ProgramWhitelist -List $Whitelist
        Write-Log -Message "Browser (msedge.exe) removed from program whitelist." -Type "INFO" -Color Yellow
    }
    # Re-apply RestrictRun to live child hive if child is currently logged in
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        Apply-RestrictRunPolicies -HiveMount $ChildSidValue
        Write-Log -Message "RestrictRun re-applied to live child hive (browser locked)." -Type "INFO" -Color Gray
    }
}

function Show-ProgramWhitelistReview {
    <#
        Interactive CLI to review and manage the RestrictRun program whitelist.
    #>
    do {
        Clear-Host
        Write-Host "`n=====================================================" -ForegroundColor Cyan
        Write-Host " MANAGE PROGRAM WHITELIST (RestrictRun) " -ForegroundColor Cyan
        Write-Host "=====================================================" -ForegroundColor Cyan
        $StrictMode = (Get-RestrictRunStrictMode)
        $Whitelist = Get-ProgramWhitelist
        $EffectiveList = $Whitelist
        if (-not $StrictMode -and $Whitelist.Count -eq 0) {
            Write-Host "`n[INFO] Whitelist is empty. Using default whitelist (strict mode OFF)." -ForegroundColor Gray
            $EffectiveList = Get-DefaultProgramWhitelist
        } else {
            $modeStr = if ($StrictMode) { "STRICT MODE ON: only explicit whitelist entries are allowed (explorer.exe is always enforced)" } else { "Strict mode OFF: defaults are used when whitelist is empty" }
            Write-Host "`n[INFO] $modeStr" -ForegroundColor Cyan
        }
        $Index = 0
        foreach ($Entry in $EffectiveList) {
            $Index++
            Write-Host "[$Index] $Entry" -ForegroundColor Green
        }
        Write-Host "`n[A] Add a program" -ForegroundColor Yellow
        Write-Host '[R] Remove a program (enter number)' -ForegroundColor Red

        Write-Host '[S] Auto-scan common programs' -ForegroundColor Cyan

        Write-Host '[D] Reset to defaults' -ForegroundColor Cyan

        Write-Host '[T] Toggle strict mode (current: ' -NoNewline -ForegroundColor Cyan
        if ($StrictMode) { Write-Host 'ON' -NoNewline -ForegroundColor Green } else { Write-Host 'OFF' -NoNewline -ForegroundColor DarkGray }
        Write-Host ')' -ForegroundColor Cyan

        Write-Host '[Q] Quit / Return' -ForegroundColor Gray

        $Choice = (Read-Host "`nSelect action").ToUpper()
        if ($Choice -eq "Q") { return }
        if ($Choice -eq "T") {
            $NewStrict = -not $StrictMode
            Set-RestrictRunStrictMode -Enabled $NewStrict
            Write-Host "`n[OK] Strict mode set to $(if($NewStrict){'ON'}else{'OFF'})." -ForegroundColor Green
            Wait-AnyKey
        }
        if ($Choice -eq "S") {
            $Found = Scan-CommonProgramsForWhitelist
            if ($Found.Count -eq 0) {
                Write-Host '[INFO] No new executables found in common directories.' -ForegroundColor Gray

            } else {
                Write-Host "`n=== Found executables ===" -ForegroundColor Cyan
                foreach ($Exe in $Found) {
                    if ($Whitelist -contains $Exe) {
                        Write-Host "  `[SKIP] $Exe (already in whitelist)" -ForegroundColor Gray

                    } else {
                        Write-Host "  `[NEW]  $Exe" -ForegroundColor Green

                    }
                }
                $AddAll = (Read-Host "`nAdd all new entries to whitelist? (Y/N)").ToUpper()
                if ($AddAll -eq "Y") {
                    $Added = 0
                    foreach ($Exe in $Found) {
                        if ($Whitelist -notcontains $Exe) {
                            $Whitelist += $Exe
                            $Added++
                        }
                    }
                    Set-ProgramWhitelist -List $Whitelist
                    Write-Host "`[SUCCESS] Added $Added new program(s) to whitelist." -ForegroundColor Green

                }
            }
            Write-Host "`n[ PRESS ANY KEY TO CONTINUE ]" -ForegroundColor DarkGray; Wait-AnyKey
        }
        if ($Choice -eq "D") {
            Set-ProgramWhitelist -List (Get-DefaultProgramWhitelist)
            Write-Host '[SUCCESS] Whitelist reset to defaults.' -ForegroundColor Green

            Write-Host "`n[ PRESS ANY KEY TO CONTINUE ]" -ForegroundColor DarkGray; Wait-AnyKey
        }
        elseif ($Choice -eq "A") {
            $NewProg = Read-Host "Enter executable name (e.g., notepad.exe)"
            if ($NewProg -match "\.exe$") {
                $Whitelist += $NewProg
                Set-ProgramWhitelist -List $Whitelist
                Write-Host "`[SUCCESS] Added: $NewProg" -ForegroundColor Green

            } else {
                Write-Host '[ERROR] Must end with .exe' -ForegroundColor Red

            }
            Write-Host "`n[ PRESS ANY KEY TO CONTINUE ]" -ForegroundColor DarkGray; Wait-AnyKey
        }
        elseif ($Choice -eq "R") {
            $Num = Read-Host "Enter program number to remove"
            if ($Num -match "^\d+$") {
                $Idx = [int]$Num - 1
                if ($Idx -ge 0 -and $Idx -lt $Whitelist.Count) {
                    $NewList = @()
                    for ($i = 0; $i -lt $Whitelist.Count; $i++) {
                        if ($i -ne $Idx) { $NewList += $Whitelist[$i] }
                    }
                    Set-ProgramWhitelist -List $NewList
                    Write-Host "`[SUCCESS] Removed: $($Whitelist[$Idx])" -ForegroundColor Green

                } else {
                    Write-Host '[ERROR] Invalid number.' -ForegroundColor Red

                }
            }
            Write-Host "`n[ PRESS ANY KEY TO CONTINUE ]" -ForegroundColor DarkGray; Wait-AnyKey
        }
    } while ($true)
}

# ============================================================================
# 6.2 RESTRICTRUN POLICY APPLICATION
# ============================================================================

function Apply-RestrictRunPolicies {
    param(
        [string]$HiveMount = "",
        [switch]$UseHKCU
    )
    if ($UseHKCU) {
        $ExplorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    } elseif ($HiveMount) {
        $ExplorerPath = "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    } else {
        return
    }
    try {
        if (-not (Test-Path $ExplorerPath)) {
            New-Item -Path $ExplorerPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-ItemProperty -Path $ExplorerPath -Name "RestrictRun" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to enable RestrictRun in child hive: $_" -Type "WARN" -Color Yellow
    }
    # Remove DisallowRun to prevent conflicts with RestrictRun (DisallowRun takes precedence over RestrictRun)
    try {
        Remove-ItemProperty -Path $ExplorerPath -Name "DisallowRun" -Force -ErrorAction SilentlyContinue
    } catch {}
    $DisallowRunPath = "$ExplorerPath\DisallowRun"
    if (Test-Path $DisallowRunPath) {
        try { Remove-Item -Path $DisallowRunPath -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
    $Whitelist = Get-ProgramWhitelist
    $StrictMode = (Get-RestrictRunStrictMode)
    if ($Whitelist.Count -eq 0 -and -not $StrictMode) {
        $Whitelist = Get-DefaultProgramWhitelist
    }
    # explorer.exe is required for the desktop shell to load; always enforce it
    if ($Whitelist -notcontains "explorer.exe") {
        $Whitelist = @("explorer.exe") + $Whitelist
    }
    $RestrictRunPath = "$ExplorerPath\RestrictRun"
    if (Test-Path $RestrictRunPath) {
        try { Remove-Item -Path $RestrictRunPath -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
    try {
        New-Item -Path $RestrictRunPath -Force -ErrorAction SilentlyContinue | Out-Null
        $i = 1
        foreach ($Exe in $Whitelist) {
            Set-ItemProperty -Path $RestrictRunPath -Name "$i" -Value $Exe -Type String -Force -ErrorAction SilentlyContinue
            $i++
        }
        Write-Log -Message "RestrictRun whitelist applied with $($Whitelist.Count) entries (strict mode: $StrictMode)." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to write RestrictRun whitelist: $_" -Type "WARN" -Color Yellow
    }
}

function Remove-RestrictRunPolicies {
    param(
        [string]$HiveMount = "",
        [switch]$UseHKCU,
        [switch]$NoDisallowRunFallback
    )
    if ($UseHKCU) {
        $ExplorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    } elseif ($HiveMount) {
        $ExplorerPath = "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    } else {
        return
    }
    try {
        Remove-ItemProperty -Path $ExplorerPath -Name "RestrictRun" -Force -ErrorAction SilentlyContinue
    } catch {}
    $RestrictRunPath = "$ExplorerPath\RestrictRun"
    if (Test-Path $RestrictRunPath) {
        try { Remove-Item -Path $RestrictRunPath -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
    # Also restore DisallowRun as a fallback when RestrictRun is removed (so child is not left unprotected)
    # Skip this fallback when entering Parent Mode so the admin has full access.
    if (-not $NoDisallowRunFallback) {
        try {
            $DisallowRunValue = Get-ItemProperty -Path $ExplorerPath -Name "DisallowRun" -ErrorAction SilentlyContinue
            if (-not $DisallowRunValue) {
                Set-ItemProperty -Path $ExplorerPath -Name "DisallowRun" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                $DisallowRunSubPath = "$ExplorerPath\DisallowRun"
                if (-not (Test-Path $DisallowRunSubPath)) {
                    New-Item -Path $DisallowRunSubPath -Force -ErrorAction SilentlyContinue | Out-Null
                }
                $i = 1
                foreach ($Policy in $ChildDisallowRunPolicies) {
                    if ($Policy.SubPath -like "*DisallowRun" -and $Policy.Name -ne "DisallowRun") {
                        Set-ItemProperty -Path $DisallowRunSubPath -Name $Policy.Name -Value $Policy.Value -Type String -Force -ErrorAction SilentlyContinue
                        $i++
                    }
                }
            }
        } catch {
            Write-Log -Message "Failed to restore DisallowRun fallback after removing RestrictRun: $_" -Type "WARN" -Color Yellow
        }
    }
    Write-Log -Message "RestrictRun policies removed from child hive." -Type "INFO" -Color Gray
}

# ============================================================================
# 6.3 CHILD-ONLY USB GUARDIAN
# ============================================================================

function Install-ChildUSBGuard {
    <#
        Creates a scheduled task that monitors the active console user
        and stops/starts the USBSTOR service based on whether the child is active.
    #>
    $GuardScriptPath = Join-Path $InstallDir "ChildUSBGuard.ps1"
    $GuardContent = @'
$ChildUser = "Child"
$ActiveChild = $false
try {
$ChildProcs = Get-Process -Name "explorer" -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -like "*\$ChildUser" -or $_.UserName -like "*\$ChildUser.*" }
    if ($ChildProcs) { $ActiveChild = $true }
} catch {}
if ($ActiveChild) {
    try { Stop-Service -Name "USBSTOR" -Force -ErrorAction SilentlyContinue } catch {}
} else {
    try { Start-Service -Name "USBSTOR" -ErrorAction SilentlyContinue } catch {}
}
'@
    try {
        Set-Content -Path $GuardScriptPath -Value $GuardContent -Encoding UTF8 -Force
        $Acl = Get-Acl -Path $GuardScriptPath
        $Acl.SetOwner($SidSystem)
        $Acl.SetAccessRuleProtection($true, $false)
        $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
        Set-Acl -Path $GuardScriptPath -AclObject $Acl -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to write ChildUSBGuard script: $_" -Type "WARN" -Color Yellow
    }
    try {
        $Action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$GuardScriptPath`""
        $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "OSGuard-ChildUSBGuard" -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
        Write-Log -Message 'Child USB Guard installed (1-minute heartbeat).' -Type "SUCCESS" -Color Green

    } catch {
        Write-Log -Message "Failed to register Child USB Guard task: $_" -Type "WARN" -Color Yellow
    }
}

function Remove-ChildUSBGuard {
    $tn = "OSGuard-ChildUSBGuard"
    $task = $null
    try { $task = Get-ScheduledTask -TaskName $tn -ErrorAction Stop } catch { $task = $null }
    if (-not $task) { return }
    try {
        Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Milliseconds 500
        Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Log -Message "Child USB Guard task removed." -Type "INFO" -Color Gray
    } catch {
        try {
            $proc = Start-Process -FilePath "schtasks.exe" -ArgumentList "/delete", "/tn", $tn, "/f" -Wait -WindowStyle Hidden -PassThru
            if ($proc.ExitCode -eq 0) {
                Write-Log -Message "Child USB Guard task removed (schtasks fallback)." -Type "INFO" -Color Gray
            } else {
                Write-Log -Message "Failed to remove Child USB Guard task (schtasks exit $($proc.ExitCode))." -Type "WARN" -Color Yellow
            }
        } catch {
            Write-Log -Message "Failed to remove Child USB Guard task: $_" -Type "WARN" -Color Yellow
        }
    }
    $GuardScriptPath = Join-Path $InstallDir "ChildUSBGuard.ps1"
    if (Test-Path $GuardScriptPath) {
        Remove-Item -Path $GuardScriptPath -Force -ErrorAction SilentlyContinue
    }
}

function Set-ChildLogoutShortcut {
    <#
        Creates a shortcut on the child's desktop that logs the user out.
        The shortcut is flagged to run as administrator, so the child sees a UAC prompt
        and cannot approve it without an admin password.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    # Guard: only create in the actual child profile directory
    $LeafName = Split-Path -Path $ChildProfilePath -Leaf
    if ($LeafName -ne $ChildUser -and $LeafName -notlike "$ChildUser.*") {
        Write-Log -Message "Child profile path '$ChildProfilePath' does not match username '$ChildUser'. Skipping logout shortcut creation." -Type "WARN" -Color Yellow
        return
    }
    $DesktopPath = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $DesktopPath)) {
        New-Item -ItemType Directory -Path $DesktopPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $ShortcutPath = Join-Path $DesktopPath "Log out.lnk"
    try {
        Reset-HardenedFile -Path $ShortcutPath
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = "pwsh.exe"
        # Use the installed script via oslock so the logic is centralized and testable.
        # After UAC elevation, the script runs as admin; the handler uses quser to find the
        # child's session ID and calls logoff <id> so the CHILD is logged off, not the admin.
        $EffectiveScript = if (Test-Path $InstallScript) { $InstallScript } else { $PSCommandPath }
        $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$EffectiveScript`" -ChildLogout -ChildUser `"$ChildUser`""
        $Shortcut.Description = "Log out (requires administrator approval via UAC)"
        $Shortcut.IconLocation = "shell32.dll,48"
        $Shortcut.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Harden-FileACL -FilePath $ShortcutPath
        Write-Log -Message "Admin-approval logout shortcut created at '$ShortcutPath' for '$ChildUser'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create logout shortcut for '$ChildUser': $_" -Type "WARN" -Color Yellow
    }
}

function Remove-ChildLogoutShortcut {
    <#
        Removes the admin-approval logout shortcut from the child's desktop.
        Cleans ALL matching profile folders to catch stale profiles.
    #>
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        $ShortcutPath = Join-Path $ProfilePath "Desktop\Log out.lnk"
        if (Test-Path $ShortcutPath) {
            Remove-Item -Path $ShortcutPath -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed logout shortcut from '$ProfilePath'." -Type "INFO" -Color Gray
        }
    }
}

function Disable-AutoAdminLogon {
    <#
        Disables automatic admin logon by clearing Winlogon auto-login keys.
        Prevents the system from bypassing the login screen after boot or unlock.
    #>
    $WinlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    try {
        Set-ItemProperty -Path $WinlogonPath -Name "AutoAdminLogon" -Value "0" -Type String -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinlogonPath -Name "DefaultUserName" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinlogonPath -Name "DefaultPassword" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinlogonPath -Name "DefaultDomainName" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinlogonPath -Name "AutoLogonCount" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinlogonPath -Name "ForceAutoLogon" -ErrorAction SilentlyContinue
        Write-Log -Message "Auto-admin logon disabled (Winlogon keys cleared)." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to disable auto-admin logon: $_" -Type "WARN" -Color Yellow
    }
}

function Restore-AutoAdminLogon {
    <#
        Clears stored auto-login credentials from Winlogon during uninstall.
        This does not re-enable auto-login; it only strips cached credentials
        so the system falls back to the normal credential prompt.
    #>
    $WinlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    try {
        Remove-ItemProperty -Path $WinlogonPath -Name "DefaultUserName" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinlogonPath -Name "DefaultPassword" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinlogonPath -Name "DefaultDomainName" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinlogonPath -Name "AutoLogonCount" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinlogonPath -Name "ForceAutoLogon" -ErrorAction SilentlyContinue
        Write-Log -Message "Auto-login credentials cleared from Winlogon." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to clear auto-login credentials: $_" -Type "WARN" -Color Yellow
    }
}

function Apply-EdgePolicies {
    param([string]$HiveMount = "")
    <#
        Applies deep lockdown policies to Microsoft Edge.
        If HiveMount is provided, targets the child hive (HKCU).
        Otherwise defaults to HKLM for backward compatibility.
    #>
    if (-not $HiveMount) {
        Write-Log -Message "Apply-EdgePolicies called with empty HiveMount - skipping to avoid HKLM pollution." -Type "WARN" -Color Yellow
        return
    }
    $EdgePolicyPath = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Edge"
    Write-Log -Message "Applying Edge deep lockdown policies to $EdgePolicyPath..." -Type "INFO" -Color Yellow
    if (-not (Test-Path $EdgePolicyPath)) { New-Item -Path $EdgePolicyPath -Force -ErrorAction SilentlyContinue | Out-Null }

    $Policies = @{
        "BookmarkBarEnabled" = 0
        "EdgeCollectionsEnabled" = 0
        "BrowserAddProfileEnabled" = 0
        "BrowserGuestModeEnabled" = 0
        "BrowserSignin" = 0
        "DeveloperToolsAvailability" = 2
        "HideFirstRunExperience" = 1
        "InPrivateModeAvailability" = 1
        "PasswordManagerEnabled" = 0
        "SyncDisabled" = 1
        "AllowDeletingBrowserHistory" = 0
        "ForceGoogleSafeSearch" = 1
        "ForceYouTubeRestrict" = 1
        "DownloadRestrictions" = 3
        "DefaultSearchProviderEnabled" = 1
        "DefaultSearchProviderName" = "Bing"
        "DefaultSearchProviderSearchURL" = "https://www.bing.com/search?q={searchTerms}"
        "HomepageLocation" = "https://www.bing.com"
        "NewTabPageLocation" = "https://www.bing.com"
        "ShowHomeButton" = 1
        "PreventSmartScreenPromptOverride" = 1
        "SmartScreenPuaEnabled" = 1
    }

    foreach ($Name in $Policies.Keys) {
        $Value = $Policies[$Name]
        $Type = if ($Value -is [string]) { "String" } else { "DWord" }
        try {
            Set-ItemProperty -Path $EdgePolicyPath -Name $Name -Value $Value -Type $Type -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log -Message "Failed to set Edge policy $Name`: $_" -Type "WARN" -Color Yellow
        }
    }

    # URL Blocklist (prevent access to internal settings pages)
    try {
        $UrlBlockPath = Join-Path $EdgePolicyPath "URLBlocklist"
        if (-not (Test-Path $UrlBlockPath)) { New-Item -Path $UrlBlockPath -Force -ErrorAction SilentlyContinue | Out-Null }
        $BlockedUrls = @("edge://settings","edge://flags","edge://extensions","edge://downloads","edge://passwords","edge://history","edge://bookmarks","chrome://settings","chrome://flags","about:config")
        # Find highest existing numeric key so we append rather than overwrite existing blocklists
        $UrlBlockObj = Get-ItemProperty -Path $UrlBlockPath -ErrorAction SilentlyContinue
        $ExistingKeys = if ($UrlBlockObj) { $UrlBlockObj | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -match '^\d+$' } | Select-Object -ExpandProperty Name | ForEach-Object { [int]$_ } | Sort-Object -Descending } else { @() }
        $i = if ($ExistingKeys) { $ExistingKeys[0] + 1 } else { 1 }
        foreach ($Url in $BlockedUrls) {
            Set-ItemProperty -Path $UrlBlockPath -Name "$i" -Value $Url -Type String -Force -ErrorAction SilentlyContinue
            $i++
        }
    } catch {
        Write-Log -Message "Failed to apply Edge URL blocklist: $_" -Type "WARN" -Color Yellow
    }

    # Extension Install Blocklist (block all extensions)
    try {
        $ExtBlockPath = Join-Path $EdgePolicyPath "ExtensionInstallBlocklist"
        if (-not (Test-Path $ExtBlockPath)) { New-Item -Path $ExtBlockPath -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $ExtBlockPath -Name "1" -Value "*" -Type String -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to apply Edge extension blocklist: $_" -Type "WARN" -Color Yellow
    }

    Write-Log -Message "Edge deep lockdown policies applied." -Type "SUCCESS" -Color Green
}

function Remove-EdgePolicies {
    param([string]$HiveMount = "")
    <#
        Removes Edge deep lockdown policies.
        If HiveMount is provided, targets the child hive (HKCU).
    #>
    $EdgePolicyPath = if ($HiveMount) { "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Edge" } else { "HKLM:\SOFTWARE\Policies\Microsoft\Edge" }
    Write-Log -Message "Removing Edge deep lockdown policies from $EdgePolicyPath..." -Type "INFO" -Color Yellow
    if (Test-Path $EdgePolicyPath) {
        $Keys = @("BookmarkBarEnabled","EdgeCollectionsEnabled","BrowserAddProfileEnabled","BrowserGuestModeEnabled","BrowserSignin","DeveloperToolsAvailability","HideFirstRunExperience","InPrivateModeAvailability","PasswordManagerEnabled","SyncDisabled","AllowDeleteBrowserHistory","ForceGoogleSafeSearch","ForceYouTubeRestrict","DownloadRestrictions","DefaultSearchProviderEnabled","DefaultSearchProviderName","DefaultSearchProviderSearchURL","HomepageLocation","NewTabPageLocation","ShowHomeButton","PreventSmartScreenPromptOverride","SmartScreenPuaEnabled")
        foreach ($Key in $Keys) {
            Remove-ItemProperty -Path $EdgePolicyPath -Name $Key -ErrorAction SilentlyContinue
        }
        Remove-Item -Path (Join-Path $EdgePolicyPath "URLBlocklist") -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path (Join-Path $EdgePolicyPath "ExtensionInstallBlocklist") -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log -Message "Edge deep lockdown policies removed." -Type "SUCCESS" -Color Green
}

function Harden-FileACL {
    <#
        Reusable ACL hardener for a single file (e.g., .lnk shortcuts).
        SYSTEM = FullControl, Admins/Users = ReadAndExecute + Deny Delete/ChangePermissions/TakeOwnership.
    #>
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return }
    try {
        $Acl = Get-Acl -Path $FilePath
        $Acl.SetOwner($SidSystem)
        $Acl.SetAccessRuleProtection($true, $false)
        $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
    $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Write", "None", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Read", "None", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "None", "None", "Allow")))
        Set-Acl -Path $FilePath -AclObject $Acl -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to harden ACL for $FilePath`: $_" -Type "WARN" -Color Yellow
    }
}

function Set-ParentPassword {
    <#
        Prompts the admin to set (or change) the Parent Mode password.
        Stores a PBKDF2 hash (100,000 iterations) in the protected registry key.
    #>
    $PwRegName = "OSGuardParentPasswordHash"
    $SaltRegName = "OSGuardParentPasswordSalt"
    $IterRegName = "OSGuardParentPasswordIterations"
    Write-Host "`n[SET PARENT MODE PASSWORD]" -ForegroundColor Cyan
    Write-Host "  Suggested memorable passwords (easy to remember, still secure):" -ForegroundColor DarkGray
    for ($i = 1; $i -le 3; $i++) {
        $Suggestion = New-MemorablePassword
        Write-Host "    $i`) $Suggestion" -ForegroundColor Yellow

    }
    Write-Host "  (You can type your own, or use one of the suggestions above)" -ForegroundColor DarkGray
    Write-Host "  Allowed easy symbols: ! # $ % & + - = ? _ @" -ForegroundColor DarkGray
    $NewPw = Read-Host "Enter new Parent Mode password" -AsSecureString
    $ConfirmPw = Read-Host "Confirm new Parent Mode password" -AsSecureString
    $NewPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPw))
    $ConfirmPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPw))
    if ($NewPlain -ne $ConfirmPlain) {
        Write-Host '[ERROR] Passwords do not match. Password NOT changed.' -ForegroundColor Red

        return
    }
    if (-not (Test-PasswordComplexity -Password $NewPlain)) {
        Write-Host '[ERROR] Password must be at least 6 characters and contain at least one letter and one number.' -ForegroundColor Red

        Write-Host "        Example: Dragon42!  (word + number + symbol)" -ForegroundColor Yellow
        return
    }
    $SaltStr = Get-PBKDF2Salt
    $HashStr = New-PBKDF2Hash -Password $NewPlain -SaltBase64 $SaltStr -Iterations 100000
    try {
        if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
        Set-ItemProperty -Path $IntegrityRegPath -Name $PwRegName -Value $HashStr -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $IntegrityRegPath -Name $SaltRegName -Value $SaltStr -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $IntegrityRegPath -Name $IterRegName -Value 100000 -Type DWord -Force -ErrorAction Stop
        # Harden the registry key so only SYSTEM can read the hash
        $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if ($RegKey) {
            $Acl = $RegKey.GetAccessControl()
            $Acl.SetAccessRuleProtection($true, $false)
            $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidSystem, "FullControl", "Allow")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidAdmin, "WriteKey", "Allow")))
            $RegKey.SetAccessControl($Acl)
            $RegKey.Close()
        }
        # Also write a hardened hash file so the child session can verify during tamper lockout
        $HashFile = Join-Path $InstallDir "parent.hash"
        "$HashStr|$SaltStr|100000" | Set-Content -Path $HashFile -Encoding UTF8 -Force
        # Harden hash file ACL: only SYSTEM and Admin have access (child cannot read hash to brute-force)
        $HashAcl = Get-Acl -Path $HashFile
        $HashAcl.SetOwner($SidSystem)
        $HashAcl.SetAccessRuleProtection($true, $false)
        $HashAcl.Access | ForEach-Object { $HashAcl.RemoveAccessRule($_) | Out-Null }
        $HashAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $HashAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Write", "None", "None", "Allow")))
        $HashAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Read", "None", "None", "Allow")))
        Set-Acl -Path $HashFile -AclObject $HashAcl -ErrorAction SilentlyContinue
        Write-Log -Message "Parent Mode PBKDF2 password hash stored (100k iterations)." -Type "SUCCESS" -Color Green
        Write-Host '[SUCCESS] Parent Mode password updated.' -ForegroundColor Green

    } catch {
        Write-Log -Message "Failed to store parent password hash: $_" -Type "ERROR" -Color Red
        Write-Host '[ERROR] Could not store password hash.' -ForegroundColor Red

    }
}

function Test-ParentPassword {
    <#
        Prompts for the Parent Mode password and returns $true if correct.
        Uses the stored PBKDF2 salt to compute the hash.
    #>
    $PwRegName = "OSGuardParentPasswordHash"
    $SaltRegName = "OSGuardParentPasswordSalt"
    $IterRegName = "OSGuardParentPasswordIterations"
    $StoredHash = $null
    $StoredSalt = $null
    $StoredIterations = 100000
    try { $StoredHash = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name $PwRegName -ErrorAction Stop) } catch {}
    try { $StoredSalt = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name $SaltRegName -ErrorAction Stop) } catch {}
    try { $StoredIterations = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name $IterRegName -ErrorAction Stop) } catch {}
    if (-not $StoredHash -or -not $StoredSalt) {
        Write-Host "`[ERROR] No Parent Mode password set. Run 'oslock -SetParentPassword' first." -ForegroundColor Red

        return $false
    }
    $InputPw = Read-Host "Enter Parent Mode password" -AsSecureString
    $InputPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($InputPw))
    $InputHash = New-PBKDF2Hash -Password $InputPlain -SaltBase64 $StoredSalt -Iterations $StoredIterations
    if ($InputHash -eq $StoredHash) {
        return $true
    } else {
        Write-Host '[ERROR] Incorrect password.' -ForegroundColor Red

        return $false
    }
}

function Start-WindowGuard {
    <#
        Starts a background process that monitors for new windows during Parent Mode.
        If a new process with a visible window is detected, it prompts for the Parent Mode password.
        3 wrong passwords or Cancel triggers immediate lock.
    #>
    $GuardPath = Join-Path $InstallDir "WindowGuard.ps1"
    $GuardContent = @'
$ErrorActionPreference = "Stop"
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
$Hash = $null
$Salt = $null
$Iterations = 100000
try { $Hash = (Get-ItemPropertyValue -Path $RegPath -Name "OSGuardParentPasswordHash" -ErrorAction Stop) } catch {}
try { $Salt = (Get-ItemPropertyValue -Path $RegPath -Name "OSGuardParentPasswordSalt" -ErrorAction Stop) } catch {}
try { $Iterations = (Get-ItemPropertyValue -Path $RegPath -Name "OSGuardParentPasswordIterations" -ErrorAction Stop) } catch {}
if (-not $Hash -or -not $Salt) { exit }

Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue

function New-PBKDF2Hash {
    param([string]$Password, [string]$SaltBase64, [int]$Iterations = 100000)
    $SaltBytes = [Convert]::FromBase64String($SaltBase64)
    $Derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $SaltBytes, $Iterations)
    $HashBytes = $Derive.GetBytes(32)
    $Derive.Dispose()
    return [Convert]::ToBase64String($HashBytes)
}

function Test-GuardPassword {
    param([string]$Prompt)
    $Pw = [Microsoft.VisualBasic.Interaction]::InputBox($Prompt, "Parent Mode Window Guard", "", -1, -1)
    if ([string]::IsNullOrWhiteSpace($Pw)) { return $false }
    $InputHash = New-PBKDF2Hash -Password $Pw -SaltBase64 $Salt -Iterations $Iterations
    return ($InputHash -eq $Hash)
}

$SystemProcs = @("explorer","SearchApp","SearchUI","ShellExperienceHost","TextInputHost","ApplicationFrameHost","sihost","RuntimeBroker","dllhost","StartMenuExperienceHost","SecurityHealthSystray","WpnUserService","Dwm","csrss","lsass","services","smss","wininit","winlogon","fontdrvhost","Memory Compression","System","Registry","Secure System","Idle","svchost","searchhost","shellhost","userinit","widgetservice","widgetboard","microsoftstartfeedprovider","useroobebroker","phoneexperiencehost","crossdeviceservice","crossdeviceresume","apphostregistrationverifier","cncmd","radeonsoftware","softlandingtask")

$InitialProcs = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $SystemProcs -notcontains $_.ProcessName } | Select-Object -ExpandProperty Id
$KnownProcs = @($InitialProcs)
$FailureCount = 0

while ($true) {
    Start-Sleep -Seconds 5
    try {
        $Active = (Get-ItemPropertyValue -Path $RegPath -Name "OSGuardParentModeActive" -ErrorAction Stop)
    } catch { $Active = 0 }
    if ($Active -ne 1) { break }

    $CurrentProcs = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $SystemProcs -notcontains $_.ProcessName } | Select-Object Id, ProcessName
    $NewProcs = $CurrentProcs | Where-Object { $KnownProcs -notcontains $_.Id }

    if ($NewProcs.Count -gt 0) {
        $Names = ($NewProcs | Select-Object -ExpandProperty ProcessName -Unique) -join ", "
        $Result = Test-GuardPassword -Prompt "New window detected ($Names). Enter password to continue, or click Cancel to lock."
        if (-not $Result) {
            $FailureCount++
            if ($FailureCount -ge 3) {
                try { & "C:\Windows\oslock.cmd" -LockNow } catch { try { Stop-Process -Id $PID -Force } catch {} }
                break
            }
        } else {
            $FailureCount = 0
            $KnownProcs = @($CurrentProcs | Select-Object -ExpandProperty Id)
        }
    } else {
        $KnownProcs = @($CurrentProcs | Select-Object -ExpandProperty Id)
    }
}
'@
    try {
        Set-Content -Path $GuardPath -Value $GuardContent -Encoding UTF8 -Force
        $GuardAcl = Get-Acl -Path $GuardPath
        $GuardAcl.SetOwner($SidSystem)
        $GuardAcl.SetAccessRuleProtection($true, $false)
        $GuardAcl.Access | ForEach-Object { $GuardAcl.RemoveAccessRule($_) | Out-Null }
        $GuardAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $GuardAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
        Set-Acl -Path $GuardPath -AclObject $GuardAcl -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to write WindowGuard script: $_" -Type "WARN" -Color Yellow
    }
    try {
        Start-Process -FilePath "pwsh.exe" -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$GuardPath`"" -WindowStyle Hidden
        Write-Log -Message "Window Guard started for Parent Mode session." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to start Window Guard: $_" -Type "WARN" -Color Yellow
    }
}

function Stop-WindowGuard {
    try {
        $Procs = Get-CimInstance Win32_Process -Filter "Name = 'pwsh.exe'" | Where-Object { $_.CommandLine -like "*WindowGuard.ps1*" }
        foreach ($Proc in $Procs) {
            Stop-Process -Id $Proc.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Write-Log -Message "Window Guard stopped." -Type "INFO" -Color Gray
    } catch {}
}

function Harden-ScreenTimeFile {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return }
    try {
        $Acl = Get-Acl -Path $FilePath
        $Acl.SetOwner($SidSystem)
        $Acl.SetAccessRuleProtection($true, $false)
        $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Write", "None", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Read", "None", "None", "Allow")))
        $ChildSidValue = Get-ChildSid
        if ($ChildSidValue) {
            $ChildSidObj = New-Object System.Security.Principal.SecurityIdentifier($ChildSidValue)
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($ChildSidObj, "Read", "None", "None", "Allow")))
        }
        Set-Acl -Path $FilePath -AclObject $Acl -ErrorAction Stop
    } catch {
        Write-Log -Message "Failed to harden ScreenTime file $FilePath`: $_" -Type "WARN" -Color Yellow
    }
}

function Write-ChildAccessLog {
    <#
        Writes a timestamped entry to the child access log (JSON) and updates its SHA256 hash.
        Runs as SYSTEM so the file can be written to the protected InstallDir.
    #>
    $Entry = [PSCustomObject]@{
        Timestamp = (Get-Date -Format "o")
        User = $ChildUser
        Event = "Logon"
    }
    $Log = @()
    if (Test-Path $ChildAccessLogFile) {
        try {
            $Data = Read-JsonFile -Path $ChildAccessLogFile
            if ($Data -is [array]) { $Log = $Data } elseif ($Data) { $Log = @($Data) }
        } catch { $Log = @() }
    }
    $Log += $Entry
    $Success = Write-JsonFile -Path $ChildAccessLogFile -Data $Log -Depth 3
    if ($Success) {
        try {
            $Hash = Get-FileHashSafe -Path $ChildAccessLogFile
            Set-Content -Path $ChildAccessLogHashFile -Value $Hash -Encoding UTF8 -Force -ErrorAction Stop
            Harden-ScreenTimeFile -FilePath $ChildAccessLogFile
            Harden-ScreenTimeFile -FilePath $ChildAccessLogHashFile
            Write-Log -Message "Child access logged for '$ChildUser' at $($Entry.Timestamp)." -Type "AUDIT" -Color DarkGray
        } catch {
            Write-Log -Message "Failed to write child access log hash: $_" -Type "WARN" -Color Yellow
        }
    } else {
        Write-Log -Message "Failed to write child access log (mutex/atomic write failed)." -Type "WARN" -Color Yellow
    }
}

function Test-ChildAccessLogTamper {
    <#
        Checks if the child access log has been tampered with by comparing its
        current SHA256 hash to the stored hash. Returns $true if tampered.
    #>
    if (-not (Test-Path $ChildAccessLogFile) -or -not (Test-Path $ChildAccessLogHashFile)) {
        return $false
    }
    try {
        $StoredHash = (Get-Content -Path $ChildAccessLogHashFile -Raw -ErrorAction Stop).Trim()
        $ActualHash = Get-FileHashSafe -Path $ChildAccessLogFile
        return ($StoredHash -ne $ActualHash)
    } catch {
        return $true
    }
}

function Get-ScreenTimeConfig {
    $Data = Read-JsonFile -Path $ScreenTimeConfigFile
    if ($Data) { return $Data }
    return $null
}

function Set-ScreenTimeConfig {
    param(
        [string]$DailyStart = "08:00",
        [string]$DailyEnd = "20:00",
        [int]$DailyMaxMinutes = 120,
        [int]$BrowserMaxMinutes = 60,
        [int]$WeekendDailyMaxMinutes = 180,
        [int]$WeekendBrowserMaxMinutes = 90,
        [bool]$Enabled = $true
    )
    $Config = @{
        Enabled = $Enabled
        DailyStart = $DailyStart
        DailyEnd = $DailyEnd
        DailyMaxMinutes = $DailyMaxMinutes
        BrowserMaxMinutes = $BrowserMaxMinutes
        WeekendDailyMaxMinutes = $WeekendDailyMaxMinutes
        WeekendBrowserMaxMinutes = $WeekendBrowserMaxMinutes
    }
    $Success = Write-JsonFile -Path $ScreenTimeConfigFile -Data $Config -Depth 3
    if ($Success) {
        Harden-ScreenTimeFile -FilePath $ScreenTimeConfigFile
        Write-Log -Message "ScreenTime config saved." -Type "INFO" -Color Gray
    } else {
        Write-Log -Message "Failed to save ScreenTime config (mutex/atomic write failed)." -Type "ERROR" -Color Red
    }
}

function Get-ScreenTimeTracker {
    $Data = Read-JsonFile -Path $ScreenTimeTrackerFile
    if ($Data) { return $Data }
    return $null
}

function Update-ScreenTimeTracker {
    param([PSCustomObject]$Tracker)
    $Success = Write-JsonFile -Path $ScreenTimeTrackerFile -Data $Tracker -Depth 3
    if ($Success) {
        Harden-ScreenTimeFile -FilePath $ScreenTimeTrackerFile
    } else {
        Write-Log -Message "Failed to update ScreenTime tracker (mutex/atomic write failed)." -Type "WARN" -Color Yellow
    }
}

function Reset-ScreenTimeTrackerIfNewDay {
    $Tracker = Get-ScreenTimeTracker
    $Today = (Get-Date).ToString("yyyy-MM-dd")
    if (-not $Tracker -or $Tracker.LastDate -ne $Today) {
        $Tracker = @{
            LastDate = $Today
            DailySecondsUsed = 0
            BrowserSecondsUsed = 0
            LastResetTimestamp = (Get-Date -Format "o")
            BrowserAllowanceActive = $false
            BrowserAllowanceExpiry = $null
            BrowserAllowanceMinutes = 0
        }
        Update-ScreenTimeTracker -Tracker $Tracker
        Write-Log -Message "ScreenTime tracker reset for new day ($Today`)." -Type "INFO" -Color Gray

    }
    return $Tracker
}

function Test-ScreenTimeLimit {
    $Config = Get-ScreenTimeConfig
    if (-not $Config -or -not $Config.Enabled) { return $false }
    $Now = Get-Date
    $Tracker = Reset-ScreenTimeTrackerIfNewDay

    # Check browser allowance first (admin-granted override)
    if ($Tracker.BrowserAllowanceActive -eq $true) {
        if ($Tracker.BrowserAllowanceExpiry -and ([DateTime]$Tracker.BrowserAllowanceExpiry) -gt $Now) {
            return $false
        } else {
            $Tracker.BrowserAllowanceActive = $false
            Update-ScreenTimeTracker -Tracker $Tracker
            # Allowance expired - lock browser by removing from whitelist
            Remove-BrowserFromWhitelist
            return $true
        }
    }

    # Check daily hours
    try {
        $StartTime = [DateTime]::ParseExact($Config.DailyStart, "HH:mm", $null)
        $EndTime = [DateTime]::ParseExact($Config.DailyEnd, "HH:mm", $null)
        $StartToday = $Now.Date.Add($StartTime.TimeOfDay)
        $EndToday = $Now.Date.Add($EndTime.TimeOfDay)
        if ($StartToday -le $EndToday) {
            if ($Now -lt $StartToday -or $Now -gt $EndToday) { return $true }
        } else {
            if ($Now -gt $EndToday -and $Now -lt $StartToday) { return $true }
        }
    } catch {
        Write-Log -Message "ScreenTime config has invalid time format." -Type "WARN" -Color Yellow
    }

    # Check daily max minutes
    $DailyUsedMin = [math]::Floor($Tracker.DailySecondsUsed / 60)
    $IsWeekend = ($Now.DayOfWeek -eq 'Saturday') -or ($Now.DayOfWeek -eq 'Sunday')
    $DailyLimit = if ($IsWeekend -and $Config.WeekendDailyMaxMinutes) { $Config.WeekendDailyMaxMinutes } else { $Config.DailyMaxMinutes }
    if ($DailyUsedMin -ge $DailyLimit) { return $true }

    # Check browser max minutes (total daily)
    $BrowserUsedMin = [math]::Floor($Tracker.BrowserSecondsUsed / 60)
    $BrowserLimit = if ($IsWeekend -and $Config.WeekendBrowserMaxMinutes) { $Config.WeekendBrowserMaxMinutes } else { $Config.BrowserMaxMinutes }
    if ($BrowserUsedMin -ge $BrowserLimit) { return $true }

    return $false
}

function Invoke-ScreenTimeEnforcement {
    $Exceeded = Test-ScreenTimeLimit
    $BrowserProcs = @()
    $ChildSidValue = Get-ChildSid
    foreach ($BrowserName in @("msedge", "chrome", "firefox")) {
        $Procs = Get-Process -Name $BrowserName -ErrorAction SilentlyContinue | Where-Object {
            # Only target browsers owned by the child user (avoid killing admin browsers)
            if (-not $ChildSidValue) { return $true }
            try {
                $Owner = $_.GetOwner().User
                $OwnerSid = (New-Object System.Security.Principal.NTAccount($Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                return ($OwnerSid -eq $ChildSidValue)
            } catch { return $false }
        }
        if ($Procs) { $BrowserProcs += $Procs }
    }
    if ($Exceeded -and $BrowserProcs) {
        foreach ($Proc in $BrowserProcs) {
            try { Stop-Process -Id $Proc.Id -Force -ErrorAction Stop } catch {}
        }
        Write-Log -Message "ScreenTime limit exceeded. Browsers terminated." -Type "SECURITY" -Color Red
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            [System.Windows.Forms.MessageBox]::Show("Your browser time is up or outside allowed hours. Please ask your admin for more time.", "Browser Time Limit", "OK", "Warning") | Out-Null
        } catch {}
        # Lock browser again by removing from RestrictRun whitelist
        Remove-BrowserFromWhitelist
    }
    $Tracker = Get-ScreenTimeTracker
    if (-not $Tracker) { return }
    if ($BrowserProcs) {
        $Tracker.DailySecondsUsed += 60
        $AllowanceActive = $Tracker.BrowserAllowanceActive -eq $true -and $Tracker.BrowserAllowanceExpiry -and ([DateTime]$Tracker.BrowserAllowanceExpiry) -gt (Get-Date)
        if (-not $AllowanceActive) {
            $Tracker.BrowserSecondsUsed += 60
        }
        Update-ScreenTimeTracker -Tracker $Tracker
    }
}

function Show-SetScreenTimeDialog {
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " SET SCREEN TIME (ADMIN ONLY) " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    if (-not (Test-ParentPassword)) { return }
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
    $ExistingConfig = Get-ScreenTimeConfig
    $DefaultStart = if ($ExistingConfig -and $ExistingConfig.DailyStart) { $ExistingConfig.DailyStart } else { "08:00" }
    $DefaultEnd = if ($ExistingConfig -and $ExistingConfig.DailyEnd) { $ExistingConfig.DailyEnd } else { "20:00" }
    $DefaultDailyMax = if ($ExistingConfig -and $ExistingConfig.DailyMaxMinutes) { [string]$ExistingConfig.DailyMaxMinutes } else { "120" }
    $DefaultBrowserMax = if ($ExistingConfig -and $ExistingConfig.BrowserMaxMinutes) { [string]$ExistingConfig.BrowserMaxMinutes } else { "60" }
    $DefaultWeekendDailyMax = if ($ExistingConfig -and $ExistingConfig.WeekendDailyMaxMinutes) { [string]$ExistingConfig.WeekendDailyMaxMinutes } else { "180" }
    $DefaultWeekendBrowserMax = if ($ExistingConfig -and $ExistingConfig.WeekendBrowserMaxMinutes) { [string]$ExistingConfig.WeekendBrowserMaxMinutes } else { "90" }
    $Start = [Microsoft.VisualBasic.Interaction]::InputBox("Daily allowed start time (HH:mm):", "Screen Time", $DefaultStart, -1, -1)
    if ([string]::IsNullOrWhiteSpace($Start)) { return }
    $End = [Microsoft.VisualBasic.Interaction]::InputBox("Daily allowed end time (HH:mm):", "Screen Time", $DefaultEnd, -1, -1)
    if ([string]::IsNullOrWhiteSpace($End)) { return }
    try {
        [DateTime]::ParseExact($Start, "HH:mm", $null) | Out-Null
        [DateTime]::ParseExact($End, "HH:mm", $null) | Out-Null
    } catch {
        Write-Host '[ERROR] Invalid time format. Use HH:mm (e.g. 08:00).' -ForegroundColor Red

        return
    }
    $tmp = 0
    $DailyMax = [Microsoft.VisualBasic.Interaction]::InputBox("Daily max computer minutes (weekday):", "Screen Time", $DefaultDailyMax, -1, -1)
    if ([string]::IsNullOrWhiteSpace($DailyMax) -or -not [int]::TryParse($DailyMax, [ref]$tmp)) { Write-Host "[ERROR] Invalid daily max." -ForegroundColor Red; return }
    $BrowserMax = [Microsoft.VisualBasic.Interaction]::InputBox("Daily max browser minutes (weekday):", "Screen Time", $DefaultBrowserMax, -1, -1)
    if ([string]::IsNullOrWhiteSpace($BrowserMax) -or -not [int]::TryParse($BrowserMax, [ref]$tmp)) { Write-Host "[ERROR] Invalid browser max." -ForegroundColor Red; return }
    $WeekendDailyMax = [Microsoft.VisualBasic.Interaction]::InputBox("Daily max computer minutes (weekend):", "Screen Time", $DefaultWeekendDailyMax, -1, -1)
    if ([string]::IsNullOrWhiteSpace($WeekendDailyMax) -or -not [int]::TryParse($WeekendDailyMax, [ref]$tmp)) { Write-Host "[ERROR] Invalid weekend daily max." -ForegroundColor Red; return }
    $WeekendBrowserMax = [Microsoft.VisualBasic.Interaction]::InputBox("Daily max browser minutes (weekend):", "Screen Time", $DefaultWeekendBrowserMax, -1, -1)
    if ([string]::IsNullOrWhiteSpace($WeekendBrowserMax) -or -not [int]::TryParse($WeekendBrowserMax, [ref]$tmp)) { Write-Host "[ERROR] Invalid weekend browser max." -ForegroundColor Red; return }
    Set-ScreenTimeConfig -DailyStart $Start -DailyEnd $End -DailyMaxMinutes ([int]$DailyMax) -BrowserMaxMinutes ([int]$BrowserMax) -WeekendDailyMaxMinutes ([int]$WeekendDailyMax) -WeekendBrowserMaxMinutes ([int]$WeekendBrowserMax) -Enabled $true
    Write-Host '[SUCCESS] ScreenTime settings updated.' -ForegroundColor Green

    Write-Log -Message "Admin updated ScreenTime settings." -Type "ACTION" -Color Magenta
}

function Show-ScreenTimeStatus {
    $Config = Get-ScreenTimeConfig
    $Tracker = Reset-ScreenTimeTrackerIfNewDay
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " SCREEN TIME STATUS " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    if (-not $Config -or -not $Config.Enabled) {
        Write-Host "  ScreenTime is not configured or disabled." -ForegroundColor Yellow
    } else {
        Write-Host "  Allowed hours: $($Config.DailyStart) - $($Config.DailyEnd)" -ForegroundColor Gray
        Write-Host "  Daily max: $($Config.DailyMaxMinutes) minutes" -ForegroundColor Gray
        Write-Host "  Browser max: $($Config.BrowserMaxMinutes) minutes" -ForegroundColor Gray
        $DailyUsed = [math]::Floor($Tracker.DailySecondsUsed / 60)
        $BrowserUsed = [math]::Floor($Tracker.BrowserSecondsUsed / 60)
        Write-Host "  Daily used: $DailyUsed minutes" -ForegroundColor Gray
        Write-Host "  Browser used: $BrowserUsed minutes" -ForegroundColor Gray
        if ($Tracker.BrowserAllowanceActive -eq $true -and $Tracker.BrowserAllowanceExpiry -and ([DateTime]$Tracker.BrowserAllowanceExpiry) -gt (Get-Date)) {
            Write-Host "  Active browser allowance: expires at $([DateTime]::Parse($Tracker.BrowserAllowanceExpiry).ToString('HH:mm'))" -ForegroundColor Green
        } else {
            Write-Host "  No active browser allowance." -ForegroundColor Yellow
        }
    }
    Write-Host "=====================================================" -ForegroundColor Cyan
}

function Show-GrantBrowserTimeDialog {
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " GRANT BROWSER TIME (ADMIN ONLY) " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    if (-not (Test-ParentPassword)) { return }
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
    $Minutes = [Microsoft.VisualBasic.Interaction]::InputBox("Enter minutes to grant the child for browser access:`n(Presets: 15, 30, 60, 120)", "Grant Browser Time", "30", -1, -1)
    if ([string]::IsNullOrWhiteSpace($Minutes)) { return }
    $tmp = 0
    if (-not [int]::TryParse($Minutes, [ref]$tmp)) {
        Write-Host '[ERROR] Invalid number.' -ForegroundColor Red

        return
    }
    $MinutesInt = [int]$Minutes
    if ($MinutesInt -le 0 -or $MinutesInt -gt 720) {
        Write-Host '[ERROR] Minutes must be between 1 and 720.' -ForegroundColor Red

        return
    }
    $Tracker = Reset-ScreenTimeTrackerIfNewDay
    $Expiry = (Get-Date).AddMinutes($MinutesInt).ToString("o")
    $Tracker.BrowserAllowanceActive = $true
    $Tracker.BrowserAllowanceExpiry = $Expiry
    $Tracker.BrowserAllowanceMinutes = $MinutesInt
    Update-ScreenTimeTracker -Tracker $Tracker
    Write-Host "`n`[SUCCESS] Browser time granted: $MinutesInt minutes (expires at $([DateTime]::Parse($Expiry).ToString('HH:mm')))." -ForegroundColor Green

    Write-Log -Message "Admin granted $MinutesInt minutes of browser time." -Type "ACTION" -Color Magenta

    # Unlock browser in RestrictRun whitelist so child can launch Edge
    Add-BrowserToWhitelist
}

function New-BrowserLauncher {
    $LauncherContent = @'
param([switch]$Request)
$InstallDir = "C:\ProgramData\OSGuard"
$TrackerFile = Join-Path $InstallDir "ScreenTimeTracker.json"
$RequestsDir = Join-Path $InstallDir "Requests"
function Get-Tracker {
    if (Test-Path $TrackerFile) {
        try { return Get-Content -Path $TrackerFile -Raw -ErrorAction Stop | ConvertFrom-Json } catch {}
    }
    return $null
}
function Show-Info {
    param([string]$Message)
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    [System.Windows.Forms.MessageBox]::Show($Message, "Browser Access", "OK", "Information") | Out-Null
}
$Tracker = Get-Tracker
$Now = Get-Date
$Allowed = $false
if ($Tracker -and $Tracker.BrowserAllowanceActive -eq $true) {
    if ($Tracker.BrowserAllowanceExpiry -and ([DateTime]$Tracker.BrowserAllowanceExpiry) -gt $Now) {
        $Allowed = $true
    }
}
if ($Allowed) {
    Start-Process "msedge.exe" -ErrorAction SilentlyContinue
} else {
    Show-Info -Message "EDGE BROWSER IS LOCKED. Please ask your parent to approve browser time.`n`nYour parent can click 'Grant Browser Time' on their desktop to let you use the browser for a set time."
    if (-not (Test-Path $RequestsDir)) { New-Item -ItemType Directory -Path $RequestsDir -Force -ErrorAction SilentlyContinue | Out-Null }
    $ReqFile = Join-Path $RequestsDir ("browser_request_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt")
    @"
Browser Access Request
----------------------
From: Child
Timestamp: $($Now.ToString("yyyy-MM-dd HH:mm:ss"))
Message: Child requested browser access but no active allowance exists.
"@ | Set-Content -Path $ReqFile -Encoding UTF8 -Force -ErrorAction SilentlyContinue
}
'@
    try {
        Set-Content -Path $BrowserLauncherPath -Value $LauncherContent -Encoding UTF8 -Force
        Harden-ScreenTimeFile -FilePath $BrowserLauncherPath
        Write-Log -Message "Browser launcher script written." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to write browser launcher: $_" -Type "WARN" -Color Yellow
    }
}

function New-BrowserRequestShortcut {
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    # Guard: only create in the actual child profile directory
    $LeafName = Split-Path -Path $ChildProfilePath -Leaf
    if ($LeafName -ne $ChildUser -and $LeafName -notlike "$ChildUser.*") {
        Write-Log -Message "Child profile path '$ChildProfilePath' does not match username '$ChildUser'. Skipping browser request shortcut creation." -Type "WARN" -Color Yellow
        return
    }
    $DesktopPath = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $DesktopPath)) { New-Item -ItemType Directory -Path $DesktopPath -Force -ErrorAction SilentlyContinue | Out-Null }
    $ShortcutPath = Join-Path $DesktopPath "Browser Request.lnk"
    Reset-HardenedFile -Path $ShortcutPath
    try {
        $Wsh = New-Object -ComObject WScript.Shell
        $Lnk = $Wsh.CreateShortcut($ShortcutPath)
        $Lnk.TargetPath = "pwsh.exe"
        $Lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$BrowserLauncherPath`""
        $Lnk.Description = "Request browser access (requires admin approval)"
        $Lnk.IconLocation = "shell32.dll,14"
        $Lnk.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Harden-FileACL -FilePath $ShortcutPath
        Write-Log -Message "Created child browser request shortcut at '$ShortcutPath'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create browser request shortcut: $_" -Type "WARN" -Color Yellow
    }
}

function Remove-BrowserRequestShortcut {
    <#
        Removes the browser request shortcut from the child's desktop.
        Cleans ALL matching profile folders to catch stale profiles.
    #>
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        $Path = Join-Path $ProfilePath "Desktop\Browser Request.lnk"
        if (Test-Path $Path) {
            Reset-HardenedFile -Path $Path
            Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed browser request shortcut from '$ProfilePath'." -Type "INFO" -Color Gray
        }
    }
}

function New-AdminRequestShortcut {
    <#
        Creates a shortcut on the child's desktop to request admin help.
        The shortcut is ACL-hardened so the child cannot delete or modify it.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    # Guard: only create in the actual child profile directory
    $LeafName = Split-Path -Path $ChildProfilePath -Leaf
    if ($LeafName -ne $ChildUser -and $LeafName -notlike "$ChildUser.*") {
        Write-Log -Message "Child profile path '$ChildProfilePath' does not match username '$ChildUser'. Skipping admin request shortcut creation." -Type "WARN" -Color Yellow
        return
    }
    $DesktopPath = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $DesktopPath)) { New-Item -ItemType Directory -Path $DesktopPath -Force -ErrorAction SilentlyContinue | Out-Null }
    $ShortcutPath = Join-Path $DesktopPath "Admin Request.lnk"
    Reset-HardenedFile -Path $ShortcutPath
    try {
        $Wsh = New-Object -ComObject WScript.Shell
        $Lnk = $Wsh.CreateShortcut($ShortcutPath)
        $Lnk.TargetPath = "pwsh.exe"
        $Lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue; [System.Windows.Forms.MessageBox]::Show('Admin request has been sent. Please wait for a response.','Admin Request','OK','Information') | Out-Null; if (-not (Test-Path '$InstallDir\Requests')) { New-Item -ItemType Directory -Path '$InstallDir\Requests' -Force -ErrorAction SilentlyContinue | Out-Null }; 'Admin help request from child at ' + [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss') | Out-File -FilePath ('$InstallDir\Requests\admin_request_' + [DateTime]::Now.ToString('yyyyMMdd_HHmmss') + '.txt') -Encoding UTF8 -Force`""
        $Lnk.Description = "Request help from an administrator"
        $Lnk.IconLocation = "shell32.dll,23"
        $Lnk.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Harden-FileACL -FilePath $ShortcutPath
        Write-Log -Message "Created child admin request shortcut at '$ShortcutPath'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create admin request shortcut: $_" -Type "WARN" -Color Yellow
    }
}

function Remove-AdminRequestShortcut {
    <#
        Removes the admin request shortcut from the child's desktop.
        Cleans ALL matching profile folders to catch stale profiles.
    #>
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        $Path = Join-Path $ProfilePath "Desktop\Admin Request.lnk"
        if (Test-Path $Path) {
            Reset-HardenedFile -Path $Path
            Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed admin request shortcut from '$ProfilePath'." -Type "INFO" -Color Gray
        }
    }
}

function New-AdminOnlyLogoutShortcut {
    <#
        Creates an admin-only 'Log out' shortcut on the child desktop.
        Requires admin elevation so the parent can use it when logged in as the child.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    # Guard: only create in the actual child profile directory
    $LeafName = Split-Path -Path $ChildProfilePath -Leaf
    if ($LeafName -ne $ChildUser -and $LeafName -notlike "$ChildUser.*") {
        Write-Log -Message "Child profile path '$ChildProfilePath' does not match username '$ChildUser'. Skipping admin-only logout shortcut creation." -Type "WARN" -Color Yellow
        return
    }
    $AdminDesktop = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $AdminDesktop)) { New-Item -ItemType Directory -Path $AdminDesktop -Force -ErrorAction SilentlyContinue | Out-Null }
    $EffectiveScript = if (Test-Path $InstallScript) { $InstallScript } else { $PSCommandPath }
    $Path = Join-Path $AdminDesktop "Admin Only Logout.lnk"
    try {
        Reset-HardenedFile -Path $Path
        $Wsh = New-Object -ComObject WScript.Shell
        $Lnk = $Wsh.CreateShortcut($Path)
        $Lnk.TargetPath = "pwsh.exe"
        # First re-lock the child (Exit-ParentMode), then log out the current session
        $Lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"& '$EffectiveScript' -LockNow; Start-Process 'shutdown.exe' -ArgumentList '/l','/t','0' -WindowStyle Hidden -ErrorAction SilentlyContinue`""
        $Lnk.Description = "Re-lock child and log out (admin use only)"
        $Lnk.IconLocation = "shell32.dll,48"
        $Lnk.Save()
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($Path, $bytes)
        Harden-FileACL -FilePath $Path
        Write-Log -Message "Created admin-only logout shortcut at '$Path' (re-locks child before logout)." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create admin-only logout shortcut: $_" -Type "WARN" -Color Yellow
    }
}

function Remove-AdminOnlyLogoutShortcut {
    <#
        Removes the admin-only logout shortcut from the child's desktop.
        Cleans ALL matching profile folders to catch stale profiles.
    #>
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        $AdminDesktop = Join-Path $ProfilePath "Desktop"
        $Path = Join-Path $AdminDesktop "Admin Only Logout.lnk"
        if (Test-Path $Path) {
            Reset-HardenedFile -Path $Path
            Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed admin-only logout shortcut from '$ProfilePath'." -Type "INFO" -Color Gray
        }
    }
}

function Test-ChildOOBEComplete {
    $OOBEFile = Join-Path $env:USERPROFILE ".OSGuardOOBE"
    if (Test-Path $OOBEFile) { return $true }
    try {
        $Val = Get-ItemProperty -Path "HKCU:\Software\OSGuard" -Name "ChildOOBEComplete" -ErrorAction Stop
        return $Val.ChildOOBEComplete -eq 1
    } catch { return $false }
}

function Show-ChildOOBEWelcome {
    <#
        Schedules a background process that waits for the child desktop to be ready,
        shows a confirmation popup, sets the OOBE complete flag, and forces a logout.
    #>
    $OOBEScript = @'
$Start = Get-Date
$Timeout = New-TimeSpan -Minutes 5
$ExplorerFound = $false
while ((Get-Date) - $Start -lt $Timeout) {
    try {
        $Procs = Get-Process -Name 'explorer' -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -ne 0 }
        if ($Procs) { $ExplorerFound = $true; break }
    } catch {}
    Start-Sleep -Seconds 5
}
if (-not $ExplorerFound) { Start-Sleep -Seconds 30 }
else { Start-Sleep -Seconds 15 }

Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
[System.Windows.Forms.MessageBox]::Show("All safety rules are now enforced on this computer.`n`nPlease confirm that you understand these rules. You will be logged out now and must log back in to continue.", "OS-Guard Rules Enforced", "OK", "Information") | Out-Null

$FlagPath = "HKCU:\Software\OSGuard"
if (-not (Test-Path $FlagPath)) { New-Item -Path $FlagPath -Force -ErrorAction SilentlyContinue | Out-Null }
Set-ItemProperty -Path $FlagPath -Name "ChildOOBEComplete" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

# Also write a hidden file-based flag as a more reliable fallback
$OOBEFile = Join-Path $env:USERPROFILE ".OSGuardOOBE"
"Complete" | Out-File -FilePath $OOBEFile -Encoding UTF8 -Force
attrib +h $OOBEFile

# Give the registry a moment to flush before logging out so the flag is persisted
Start-Sleep -Seconds 2

    # Force immediate logout (/t 0 /f) so the child cannot bypass the OOBE popup by closing the window
    Start-Process "shutdown.exe" -ArgumentList "/l /t 0 /f" -WindowStyle Hidden -ErrorAction SilentlyContinue
'@

    try {
        $TempScript = Join-Path $env:TEMP "OSGuard_OOBE_$(Get-Random).ps1"
        Set-Content -Path $TempScript -Value $OOBEScript -Encoding UTF8 -Force
        Start-Process "pwsh.exe" -ArgumentList "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", "`"$TempScript`"" -WindowStyle Hidden
        Write-Log -Message "Child OOBE welcome popup scheduled (background)." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to schedule child OOBE welcome: $_" -Type "WARN" -Color Yellow
    }
}

function New-GrantBrowserTimeShortcut {
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    # Guard: only create in the actual child profile directory
    $LeafName = Split-Path -Path $ChildProfilePath -Leaf
    if ($LeafName -ne $ChildUser -and $LeafName -notlike "$ChildUser.*") {
        Write-Log -Message "Child profile path '$ChildProfilePath' does not match username '$ChildUser'. Skipping Grant Browser Time shortcut creation." -Type "WARN" -Color Yellow
        return
    }
    $AdminDesktop = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $AdminDesktop)) { New-Item -ItemType Directory -Path $AdminDesktop -Force -ErrorAction SilentlyContinue | Out-Null }
    $EffectiveScript = if (Test-Path $InstallScript) { $InstallScript } else { $PSCommandPath }
    $ShortcutPath = Join-Path $AdminDesktop "Grant Browser Time.lnk"
    try {
        Reset-HardenedFile -Path $ShortcutPath
        $Wsh = New-Object -ComObject WScript.Shell
        $Lnk = $Wsh.CreateShortcut($ShortcutPath)
        $Lnk.TargetPath = "pwsh.exe"
        $Lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$EffectiveScript`" -GrantBrowserTime"
        $Lnk.Description = "Grant the child browser access time (password protected)"
        $Lnk.IconLocation = "shell32.dll,14"
        $Lnk.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Harden-FileACL -FilePath $ShortcutPath
        Write-Log -Message "Created admin 'Grant Browser Time' shortcut at '$ShortcutPath'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create Grant Browser Time shortcut: $_" -Type "WARN" -Color Yellow
    }
}

function Remove-GrantBrowserTimeShortcut {
    <#
        Removes the Grant Browser Time shortcut from the child's desktop.
        Cleans ALL matching profile folders to catch stale profiles.
    #>
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        $AdminDesktop = Join-Path $ProfilePath "Desktop"
        $Path = Join-Path $AdminDesktop "Grant Browser Time.lnk"
        if (Test-Path $Path) {
            try {
                $Acl = Get-Acl -Path $Path
                $Acl.SetAccessRuleProtection($false, $false)
                Set-Acl -Path $Path -AclObject $Acl -ErrorAction SilentlyContinue
            } catch {}
            Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed Grant Browser Time shortcut from '$ProfilePath'." -Type "INFO" -Color Gray
        }
    }
}

function Install-ScreenTimeWatcher {
    Write-Log -Message "Installing ScreenTime watcher task..." -Type "INFO" -Color Yellow
    try {
        $Action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -ScreenTimeEnforce"
        $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $ScreenTimeTaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
        Write-Log -Message "ScreenTime watcher '$ScreenTimeTaskName' registered `(1-minute heartbeat)." -Type "SUCCESS" -Color Green

    } catch {
        Write-Log -Message "Failed to register ScreenTime watcher: $_" -Type "ERROR" -Color Red
    }
}

function Remove-ScreenTimeWatcher {
    if (Get-ScheduledTask -TaskName $ScreenTimeTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $ScreenTimeTaskName -Confirm:$false | Out-Null
        Write-Log -Message "Removed ScreenTime watcher task." -Type "INFO" -Color Gray
    }
}

function Update-ParentModeActivity {
    <#
        Records the current timestamp as the last parent activity.
        Call this from any parent-facing interactive function to reset the AFK timer.
    #>
    try {
        if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeLastActivity" -Value (Get-Date -Format "o") -Type String -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to update Parent Mode activity timestamp: $_" -Type "WARN" -Color Yellow
    }
    Save-AdminSession
}

function Save-AdminSession {
    <#
        Captures the current admin user's visible processes to a JSON file
        so they can be restored after an unexpected Windows restart.
        Only saves when Parent Mode is active.
    #>
    $ParentModeActive = $false
    try { $ParentModeActive = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue) -eq 1 } catch {}
    if (-not $ParentModeActive) { return }

    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    try {
        $Procs = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {
            $_.UserName -eq $CurrentUser -and
            $_.MainWindowHandle -ne 0 -and
            $_.ProcessName -notin @("explorer","powershell","pwsh","cmd","SearchApp","SearchIndexer","RuntimeBroker","sihost","ShellExperienceHost","StartMenuExperienceHost","TextInputHost","ApplicationFrameHost","SecurityHealthSystray","dwm","fontdrvhost","taskhostw","conhost","ctfmon","LockApp","backgroundTaskHost","browser_broker","smartscreen","rundll32","TiWorker","Search","WindowsInternal.ComposableShell.Experiences.TextInput.InputApp")
        } | Select-Object ProcessName, MainWindowTitle, Path)
        Write-JsonFile -Path $AdminSessionFile -Data $Procs -Depth 2 | Out-Null
    } catch {
        Write-Log -Message "Failed to save admin session: $_" -Type "WARN" -Color Yellow
    }
}

function Clear-AdminSession {
    if (Test-Path $AdminSessionFile) {
        Remove-Item -Path $AdminSessionFile -Force -ErrorAction SilentlyContinue
    }
}

function Restore-AdminSession {
    $Session = Read-JsonFile -Path $AdminSessionFile
    if (-not $Session) { return }
    $SessionArr = @()
    if ($Session -is [array]) { $SessionArr = $Session } elseif ($Session) { $SessionArr = @($Session) }
    if ($SessionArr.Count -eq 0) { Clear-AdminSession; return }
    $Restored = 0
    $Failed = 0
    foreach ($Proc in $SessionArr) {
        $ExePath = $Proc.Path
        if (-not $ExePath) { continue }
        $AlreadyRunning = Get-Process -Name $Proc.ProcessName -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -eq [Security.Principal.WindowsIdentity]::GetCurrent().Name }
        if ($AlreadyRunning) { continue }
        try {
            Start-Process -FilePath $ExePath -ErrorAction Stop
            Write-Log -Message "Restored admin session process: $($Proc.ProcessName)" -Type "INFO" -Color Green
            $Restored++
        } catch {
            Write-Log -Message "Failed to restore process $($Proc.ProcessName): $_" -Type "WARN" -Color Yellow
            $Failed++
        }
    }
    if ($Restored -gt 0) { Write-Host "[SUCCESS] Restored $Restored process(es)." -ForegroundColor Green }
    if ($Failed -gt 0) { Write-Host "[WARN] Failed to restore $Failed process(es)." -ForegroundColor Yellow }
    Clear-AdminSession
}

function Show-AdminSessionRestoreDialog {
    if (-not (Test-Path $AdminSessionFile)) { return }
    $Session = @()
    try {
        $Raw = Get-Content -Path $AdminSessionFile -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($Raw -is [array]) { $Session = $Raw } elseif ($Raw) { $Session = @($Raw) }
    } catch { return }
    if ($Session.Count -eq 0) { Clear-AdminSession; return }

    Clear-Host
    Write-Host "`n=====================================================" -ForegroundColor Yellow
    Write-Host " PREVIOUS ADMIN SESSION INTERRUPTED " -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host '[INFO] Windows may have restarted or crashed while Parent Mode was active.' -ForegroundColor Cyan

    Write-Host "`nSaved processes from the previous session:" -ForegroundColor White
    foreach ($Proc in $Session) {
        $Title = if ($Proc.MainWindowTitle) { $Proc.MainWindowTitle } else { "(no title)" }
        Write-Host "  - $($Proc.ProcessName) | $Title" -ForegroundColor Gray
    }
    Write-Host "`n[R] Restore these processes" -ForegroundColor Green
    Write-Host '[D] Discard and continue' -ForegroundColor DarkGray

    $Choice = (Read-Host "`nSelect action").ToUpper()
    if ($Choice -eq "R") {
        Restore-AdminSession
    } else {
        Clear-AdminSession
        Write-Host '[INFO] Session discarded.' -ForegroundColor Gray

    }
    Write-Host "`n[ PRESS ANY KEY TO CONTINUE ]" -ForegroundColor DarkGray; Wait-AnyKey
}

function Enter-ParentMode {
    <#
        Unlocks the system for the admin after password verification.
        Sets a registry flag and timestamp so the AFK watcher can auto-lock.
    #>
    Update-ParentModeActivity
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " ENTER PARENT MODE (ADMIN UNLOCK) " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan

    if (-not $SilentLock) {
        $IntegrityCheck = Test-IntegrityStatus
        if ($IntegrityCheck -eq $false) {
            Write-Log -Message "Action blocked: script integrity failure before Enter-ParentMode." -Type "SECURITY" -Color Red
            Write-Host '[BLOCKED] Tamper detected. Use uninstall and reinstall.' -ForegroundColor Red -BackgroundColor Black

            return
        }
    }

    if (-not (Test-ParentPassword)) { return }

    Write-Log -Message "Parent Mode activated by admin. Unlocking system..." -Type "ACTION" -Color Magenta

    # Temporarily unlock everything for the Parent Mode session
    Disable-OSLock -NoDisallowRunFallback
    Disable-DNSLock

    # Remove child hive restrictions from live hive if child is currently logged in, and offline hive if not
    $ChildSidValue = Get-ChildSid
    $LiveHive = $null
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        $LiveHive = $ChildSidValue
    }
    $OfflineHive = $null
    if (-not $LiveHive) {
        $OfflineHive = Mount-ChildHive
    }
    foreach ($Policy in $ChildBasePolicies) {
        if ($LiveHive) {
            $KeyPath = "Registry::HKEY_USERS\$LiveHive\$($Policy.SubPath)"
            try { Remove-ItemProperty -Path $KeyPath -Name $Policy.Name -Force -ErrorAction SilentlyContinue } catch {}
        }
        if ($OfflineHive) {
            $KeyPath = "Registry::HKEY_USERS\$OfflineHive\$($Policy.SubPath)"
            try { Remove-ItemProperty -Path $KeyPath -Name $Policy.Name -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
    foreach ($Policy in $ChildDisallowRunPolicies) {
        if ($LiveHive) {
            $KeyPath = "Registry::HKEY_USERS\$LiveHive\$($Policy.SubPath)"
            try { Remove-ItemProperty -Path $KeyPath -Name $Policy.Name -Force -ErrorAction SilentlyContinue } catch {}
        }
        if ($OfflineHive) {
            $KeyPath = "Registry::HKEY_USERS\$OfflineHive\$($Policy.SubPath)"
            try { Remove-ItemProperty -Path $KeyPath -Name $Policy.Name -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
    if ($OfflineHive) { Dismount-ChildHive -HiveMount $OfflineHive }

    # Remove RestrictRun whitelist from child hives (live and offline) without re-applying DisallowRun
    if ($LiveHive) { Remove-RestrictRunPolicies -HiveMount $LiveHive -NoDisallowRunFallback }
    if ($OfflineHive) { Remove-RestrictRunPolicies -HiveMount $OfflineHive -NoDisallowRunFallback }

    # Refresh Windows UI so the unlock takes effect immediately (only current session, not system-wide)
    Write-Log -Message "Refreshing Windows UI after unlock..." -Type "INFO" -Color Gray
    try {
        $CurrentSessionId = (Get-Process -Id $PID).SessionId
        Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $CurrentSessionId } | ForEach-Object {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
        Start-Process "explorer" -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to restart explorer for UI refresh: $_" -Type "WARN" -Color Yellow
    }

    # Recreate Parent Mode shortcuts so the admin can lock, continue, or approve installs
    New-ParentModeShortcut
    New-GrantBrowserTimeShortcut
    # Create Admin tool shortcuts for Parent Mode session
    New-ParentModeAdminTools
    New-AdminOnlyLogoutShortcut

    # Set parent mode flag and timestamp
    try {
        if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 1 -Type DWord -Force -ErrorAction Stop
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value (Get-Date -Format "o") -Type String -Force -ErrorAction Stop
    } catch {
        Write-Log -Message "Failed to set parent mode flag: $_" -Type "ERROR" -Color Red
    }

    Write-Host "`n[PARENT MODE ACTIVE]" -ForegroundColor Green -BackgroundColor Black
    Write-Host "  System UI is UNLOCKED. You can modify settings or view the child account." -ForegroundColor Green
    Write-Host "  SOFTWARE INSTALLATION RESTRICTED: Child directory ACLs and DisallowRun remain active." -ForegroundColor Yellow
    Write-Host "  To install software to the child account, use 'Approve Child Install' on the admin desktop." -ForegroundColor Yellow
    Write-Host "  Auto-lock after 5 minutes of inactivity (AFK timer)." -ForegroundColor Yellow
    Write-Host "  Click 'Lock Now' on the admin desktop or run 'oslock -LockNow' to re-lock immediately." -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Cyan

    # Start Window Guard to detect new windows and re-prompt for password
    Start-WindowGuard
    Update-ParentModeActivity
}

function Exit-ParentMode {
    <#
        Re-locks everything and clears the parent mode flag.
    #>
    Update-ParentModeActivity
    Write-Log -Message "Exiting Parent Mode and re-locking system..." -Type "ACTION" -Color Magenta
    Stop-WindowGuard
    Stop-TempUnlockTimer
    Remove-ParentModeAdminTools
    Remove-AdminOnlyLogoutShortcut
    Enable-OSLock
    Enable-DNSLock

    # Refresh Windows UI so the lock takes effect immediately (only current session, not system-wide)
    Write-Log -Message "Refreshing Windows UI after re-lock..." -Type "INFO" -Color Gray
    try {
        $CurrentSessionId = (Get-Process -Id $PID).SessionId
        Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $CurrentSessionId } | ForEach-Object {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
        Start-Process "explorer" -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to restart explorer for UI refresh: $_" -Type "WARN" -Color Yellow
    }

    # Program Guardian: immediately scan and harden any newly installed programs after Parent Mode
    Scan-And-Harden-ChildPrograms

    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
    } catch {}
    Clear-AdminSession
    Write-Log -Message "Parent Mode ended. System re-locked." -Type "SUCCESS" -Color Green
    Write-Host '[LOCKED] System is secured again.' -ForegroundColor Green

}

function Invoke-OSGuardFirewall {
    <#
        Creates or removes Windows Firewall rules via netsh advfirewall to block
        child-specific processes from outbound internet unless whitelisted.
    #>
    param([switch]$Enable, [switch]$Disable)
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { return }
    # Common child game/program directories
    $ProgramDirs = Get-ChildInstallDirectories
    $RulePrefix = "OSGuard-BlockOutbound"
    # Remove old rules first
    $ExistingRules = netsh advfirewall firewall show rule name=all dir=out | Select-String "^Rule Name:\s+($RulePrefix.*)" | ForEach-Object { ($_ -split "\s+", 3)[2].Trim() }
    foreach ($Rule in $ExistingRules) {
        if ($Disable) {
            try { netsh advfirewall firewall delete rule name="$Rule" | Out-Null } catch {}
        }
    }
    if ($Enable) {
        foreach ($Dir in $ProgramDirs) {
            $ExeFiles = Get-ChildItem -Path $Dir -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
            foreach ($Exe in $ExeFiles) {
                $RuleName = "$RulePrefix-$([System.IO.Path]::GetFileNameWithoutExtension($Exe))"
                try {
                    netsh advfirewall firewall add rule name="$RuleName" dir=out action=block program="$Exe" enable=yes | Out-Null
                    Write-Log -Message "Firewall outbound block added for $Exe" -Type "INFO" -Color Gray
                } catch {}
            }
        }
        # Browser blocks are child-only via DisallowRun; do not add global firewall rules
    }
}

function Test-HomeNetwork {
    <#
        Returns $true if the PC is connected to the home SSID (or if no HomeSSID is configured).
        Returns $false if connected to a different network, triggering stricter lockdown.
    #>
    if ([string]::IsNullOrWhiteSpace($script:HomeSSID)) { return $true }
    try {
        $ConnectedSSID = (netsh wlan show interfaces | Select-String "^\s+SSID\s+:" | ForEach-Object { ($_ -split ":\s+")[1].Trim() } | Select-Object -First 1)
        if ($ConnectedSSID -and $ConnectedSSID -eq $script:HomeSSID) { return $true }
    } catch {}
    return $false
}

function Invoke-GeofenceLockdown {
    <#
        If not on the home network, enforces stricter lockdown by killing browsers and games
        and temporarily adding extra firewall rules. Called during SilentLock and health check.
    #>
    if (Test-HomeNetwork) { return }
    Write-Log -Message "Geofence: Not connected to home network '$script:HomeSSID'. Enforcing stricter lockdown." -Type "SECURITY" -Color Red
    # Kill non-Edge browsers and games in child session only
    $BlockList = @("chrome","firefox","opera","brave","vivaldi","steam","epicgameslauncher","origin","uplay")
    foreach ($ProcName in $BlockList) {
        Get-Process -Name $ProcName -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {
            $_.UserName -like "*\$ChildUser" -or $_.UserName -like "*\$ChildUser.*"
        } | ForEach-Object {
            try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
    # Add emergency firewall blocks
    Invoke-OSGuardFirewall -Enable
}

function Show-HealthCheck {
    <#
        Read-only drift audit. Reports all missing tasks, wrong registry values,
        missing ACLs, and policy drift without fixing anything. Perfect for MSP audits.
    #>
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host ' OS-GUARD HEALTH CHECK (READ-ONLY) ' -ForegroundColor Cyan

    Write-Host "=====================================================" -ForegroundColor Cyan
    $Drift = [System.Collections.Generic.List[string]]::new()

    # Check persistence tasks
    $Tasks = @($TaskName, $Guardian1Name, $Guardian2Name, $ChildLogonTaskName, $ParentModeWatchName, $ProgramScannerName, $ScreenTimeTaskName)
    foreach ($T in $Tasks) {
        if (-not (Get-ScheduledTask -TaskName $T -ErrorAction SilentlyContinue)) {
            $Drift.Add("MISSING TASK: $T")
        }
    }
    # Check canary
    if (-not (Test-Canary)) { $Drift.Add("CANARY MISSING OR TAMPERED") }
    # Check install dir
    if (-not (Test-Path $InstallDir)) { $Drift.Add("INSTALL DIR MISSING: $InstallDir") }
    if (-not (Test-Path $InstallScript)) { $Drift.Add("INSTALL SCRIPT MISSING: $InstallScript") }
    # Check wrapper
    if (-not (Test-Path $CmdPath)) { $Drift.Add("GLOBAL CLI MISSING: $CmdPath") }
    # Check PATH
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($CurrentPath -notlike "*$InstallDir*") { $Drift.Add("PATH MISSING: $InstallDir") }
    # Check machine policies (sample)
    $UacLUA = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "EnableLUA" -ErrorAction SilentlyContinue
    if ($UacLUA -ne 1) { $Drift.Add("UAC LUA NOT ENFORCED") }
    # Check child account
    if (-not (Get-ChildAccount)) { $Drift.Add("CHILD ACCOUNT MISSING: $ChildUser") }
    # Check geofence
    if (-not (Test-HomeNetwork)) { $Drift.Add("GEOFENCE: NOT ON HOME NETWORK ($script:HomeSSID)") }

    if ($Drift.Count -eq 0) {
        Write-Host '  [HEALTHY] No drift detected.' -ForegroundColor Green

    } else {
        Write-Host "  `[DRIFT] $($Drift.Count) issues found:" -ForegroundColor Red

        foreach ($Item in $Drift) { Write-Host "    - $Item" -ForegroundColor Yellow }
    }
    Write-Host "=====================================================" -ForegroundColor Cyan
    return $Drift
}

function Export-OSGuardReport {
    <#
        Exports a CSV report for admin/MSP review including:
        lock status, last tamper event, screen time usage, installed programs, policy drift.
    #>
    param([string]$OutputPath = (Join-Path $InstallDir "OSGuard_Report.csv"))
    $Drift = Show-HealthCheck
    $Tracker = Get-ScreenTimeTracker
    $Config = Get-ScreenTimeConfig
    $InstalledPrograms = Get-ChildInstallDirectories
    $TamperActive = Test-TamperDetected
    $LastTamper = "N/A"
    try { $LastTamper = Get-ItemProperty -Path $IntegrityRegPath -Name $TamperDetectedRegName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $TamperDetectedRegName -ErrorAction SilentlyContinue } catch {}

    $Report = [PSCustomObject]@{
        Timestamp         = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Branding          = $script:Branding
        ChildUser         = $ChildUser
        TamperActive      = $TamperActive
        PolicyDriftCount  = $Drift.Count
        ScreenTimeEnabled = if ($Config) { $Config.Enabled } else { $false }
        DailyUsedMin      = if ($Tracker) { [math]::Floor($Tracker.DailySecondsUsed / 60) } else { 0 }
        BrowserUsedMin    = if ($Tracker) { [math]::Floor($Tracker.BrowserSecondsUsed / 60) } else { 0 }
        InstalledPrograms = ($InstalledPrograms -join ";")
        HomeNetwork       = (Test-HomeNetwork)
    }
    try {
        if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction SilentlyContinue | Out-Null }
        $Report | Export-Csv -Path $OutputPath -NoTypeInformation -Force -Encoding UTF8
        Write-Log -Message "Report exported to $OutputPath" -Type "INFO" -Color Gray
        Write-Host "`[INFO] Report exported to $OutputPath" -ForegroundColor Green

    } catch {
        Write-Log -Message "Failed to export report to $OutputPath`: $_" -Type "ERROR" -Color Red
        Write-Host "`[ERROR] Failed to export report: $_" -ForegroundColor Red

    }
}

function Export-DevReport {
    <#
        Collects all OS-Guard logs, config files, Windows Event Log entries,
        running processes, system state, scheduled task status, registry state,
        network status, and child account info into a zip on the Desktop.
        Instructs the user to post the zip to GitHub.
    #>
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Desktop = [Environment]::GetFolderPath("Desktop")
    $TempDir = Join-Path $Desktop "OSGuard_DevReport_$Timestamp"
    $ZipPath = "$TempDir.zip"

    Write-Host "`n[INFO] Collecting diagnostic data... This may take 10-30 seconds." -ForegroundColor Cyan
    try {
        New-Item -ItemType Directory -Path $TempDir -Force -ErrorAction Stop | Out-Null
        $DiagDir = Join-Path $TempDir "Diagnostics"
        New-Item -ItemType Directory -Path $DiagDir -Force -ErrorAction SilentlyContinue | Out-Null

        # Collect all OS-Guard files from install dir
        if (Test-Path $InstallDir) {
            $Files = Get-ChildItem -Path $InstallDir -Recurse -File -ErrorAction SilentlyContinue
            foreach ($File in $Files) {
                $Relative = $File.FullName.Substring($InstallDir.Length).TrimStart('\')
                $Dest = Join-Path $TempDir $Relative
                $DestDir = Split-Path -Parent $Dest
                if (-not (Test-Path $DestDir)) { New-Item -ItemType Directory -Path $DestDir -Force -ErrorAction SilentlyContinue | Out-Null }
                Copy-Item -Path $File.FullName -Destination $Dest -Force -ErrorAction SilentlyContinue
            }
        }

        # Also grab the main script if it exists
        if (Test-Path $InstallScript) {
            Copy-Item -Path $InstallScript -Destination (Join-Path $TempDir "OS_Lockdown.ps1") -Force -ErrorAction SilentlyContinue
        }

        # Export Windows Event Log entries for OS-Guard source (Application + System)
        $EventLogFile = Join-Path $DiagDir "OSGuard_EventLog.txt"
        try {
            $AppEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='OS-Guard'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue
            $SysEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*OS-Guard*" -or $_.Message -like "*OSGuard*" -or $_.Message -like "*Task Scheduler*" }
            $AllEvents = @($AppEvents) + @($SysEvents)
            if ($AllEvents.Count -gt 0) {
                $AllEvents | Sort-Object TimeCreated | Select-Object TimeCreated, Id, LevelDisplayName, LogName, Message | Format-Table -AutoSize | Out-String -Width 4096 | Set-Content -Path $EventLogFile -Encoding UTF8 -ErrorAction SilentlyContinue
            } else {
                "No OS-Guard events found in the last 7 days (or Event Log source does not exist yet)." | Set-Content -Path $EventLogFile -Encoding UTF8
            }
        } catch {
            "Event log query failed: $_" | Set-Content -Path $EventLogFile -Encoding UTF8
        }

        # 1. All running processes with full details
        $ProcFile = Join-Path $DiagDir "RunningProcesses.txt"
        try {
            $Procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object Name, ProcessId, ParentProcessId, CommandLine, ExecutablePath, @{N='Owner';E={try { ($_|Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User } catch { 'N/A' }}}, @{N='MemoryMB';E={[math]::Round($_.WorkingSetSize/1MB,2)}}, CreationDate
            $Procs | Sort-Object Name | Format-Table -AutoSize | Out-String -Width 4096 | Set-Content -Path $ProcFile -Encoding UTF8
        } catch {
            "Failed to collect processes: $_" | Set-Content -Path $ProcFile -Encoding UTF8
        }

        # 2. System Information
        $SysFile = Join-Path $DiagDir "SystemInfo.txt"
        try {
            $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
            $CS = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
            $BIOS = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
            $BootTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime
            $SysInfo = @"
OS-Guard Dev Report - System Information
Generated: $(Get-Date -Format "o")
========================================

OS Name        : $($OS.Caption)
OS Version     : $($OS.Version)
Build Number   : $($OS.BuildNumber)
Architecture   : $($OS.OSArchitecture)
PS Version     : $($PSVersionTable.PSVersion)
PS Edition     : $($PSVersionTable.PSEdition)
Computer Name  : $($CS.Name)
Manufacturer   : $($CS.Manufacturer)
Model          : $($CS.Model)
BIOS Version   : $($BIOS.SMBIOSBIOSVersion)
Total RAM      : $([math]::Round($CS.TotalPhysicalMemory/1GB,2)) GB
Free RAM       : $([math]::Round($OS.FreePhysicalMemory/1MB,2)) MB
Last Boot      : $BootTime
Install Date   : $($OS.InstallDate)
Current User   : $([Environment]::UserName)
Elevated       : $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

Logical Disks:
"@
            $Disks = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 3 } | Select-Object DeviceID, @{N='SizeGB';E={[math]::Round($_.Size/1GB,2)}}, @{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,2)}}, @{N='PercentFree';E={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}
            $SysInfo += ($Disks | Format-Table -AutoSize | Out-String)
            $SysInfo | Set-Content -Path $SysFile -Encoding UTF8
        } catch {
            "Failed to collect system info: $_" | Set-Content -Path $SysFile -Encoding UTF8
        }

        # 3. Scheduled Task Status (all OS-Guard tasks)
        $TaskFile = Join-Path $DiagDir "ScheduledTasks.txt"
        try {
            $TaskNames = @($TaskName, $Guardian1Name, $Guardian2Name, $ChildLogonTaskName, $ParentModeWatchName, $ProgramScannerName, $ScreenTimeTaskName, $ProcessEnforcerName, "OSGuard-ChildAccessLog", "OSGuard-ProcessEnforcer-ChildLogon", "OSGuard-ChildUSBGuard", "OSGuard-TamperLockout")
            $TaskReport = @()
            foreach ($Tn in $TaskNames) {
                $T = Get-ScheduledTask -TaskName $Tn -ErrorAction SilentlyContinue
                if ($T) {
                    $Ti = Get-ScheduledTaskInfo -TaskName $Tn -ErrorAction SilentlyContinue
                    $TaskReport += [PSCustomObject]@{
                        TaskName = $Tn
                        State = $T.State
                        LastRunTime = $Ti.LastRunTime
                        NextRunTime = $Ti.NextRunTime
                        LastTaskResult = $Ti.LastTaskResult
                        Actions = ($T.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join "; "
                    }
                } else {
                    $TaskReport += [PSCustomObject]@{ TaskName = $Tn; State = 'NOT FOUND'; LastRunTime = $null; NextRunTime = $null; LastTaskResult = $null; Actions = $null }
                }
            }
            $TaskReport | Format-Table -AutoSize | Out-String -Width 4096 | Set-Content -Path $TaskFile -Encoding UTF8
        } catch {
            "Failed to collect task status: $_" | Set-Content -Path $TaskFile -Encoding UTF8
        }

        # 4. Registry State
        $RegFile = Join-Path $DiagDir "RegistryState.txt"
        try {
            $RegReport = @"
OS-Guard Registry Keys
======================
"@
            $RegKeys = @(
                "$IntegrityRegPath",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
            )
            foreach ($Rk in $RegKeys) {
                $RegReport += "`n--- $Rk ---`n"
                try {
                    $Item = Get-Item -Path $Rk -ErrorAction SilentlyContinue
                    if ($Item) {
                        $Item.Property | ForEach-Object {
                            $Val = $Item.GetValue($_)
                            $RegReport += "$_ = $Val`n"
                        }
                    } else {
                        $RegReport += "KEY NOT FOUND`n"
                    }
                } catch {
                    $RegReport += "ERROR: $_`n"
                }
            }
            $RegReport | Set-Content -Path $RegFile -Encoding UTF8
        } catch {
            "Failed to collect registry state: $_" | Set-Content -Path $RegFile -Encoding UTF8
        }

        # 5. Network Status
        $NetFile = Join-Path $DiagDir "NetworkStatus.txt"
        try {
            $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed
            $IPConfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, IPv4Address, IPv6Address, NetProfile.Name, NetProfile.NetworkCategory
            $FWRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*OSGuard*" -or $_.DisplayName -like "*OS-Guard*" } | Select-Object DisplayName, Enabled, Direction, Action, Profile
            $NetReport = @"
Network Adapters:
"@
            $NetReport += ($Adapters | Format-Table -AutoSize | Out-String)
            $NetReport += "`nIP Configuration:`n"
            $NetReport += ($IPConfig | Format-Table -AutoSize | Out-String)
            $NetReport += "`nOS-Guard Firewall Rules:`n"
            $NetReport += ($FWRules | Format-Table -AutoSize | Out-String)
            $NetReport | Set-Content -Path $NetFile -Encoding UTF8
        } catch {
            "Failed to collect network status: $_" | Set-Content -Path $NetFile -Encoding UTF8
        }

        # 6. Child Account Status
        $ChildFile = Join-Path $DiagDir "ChildAccountStatus.txt"
        try {
            $ChildAcct = Get-LocalUser -Name $ChildUser -ErrorAction SilentlyContinue
            $ChildSid = Get-ChildSid
            $ChildProfile = Get-ChildProfilePath
            $ChildSession = $null
            try { $ChildSession = query user $ChildUser 2>$null } catch {}
            $AcctExists = ($ChildAcct -ne $null)
            $AcctEnabled = if ($ChildAcct) { $ChildAcct.Enabled } else { 'N/A' }
            $AcctPwReq = if ($ChildAcct) { $ChildAcct.PasswordRequired } else { 'N/A' }
            $AcctPwChange = if ($ChildAcct) { $ChildAcct.PasswordChangeableDate } else { 'N/A' }
            $AcctLastLogon = if ($ChildAcct) { $ChildAcct.LastLogon } else { 'N/A' }
            $ChildReport = @"
Child Account: $ChildUser
SID: $ChildSid
Profile Path: $ChildProfile
Account Exists: $AcctExists
Enabled: $AcctEnabled
PasswordRequired: $AcctPwReq
PasswordChangeableDate: $AcctPwChange
LastLogon: $AcctLastLogon
Session Status:`n$ChildSession
"@
            $ChildReport | Set-Content -Path $ChildFile -Encoding UTF8
        } catch {
            "Failed to collect child account status: $_" | Set-Content -Path $ChildFile -Encoding UTF8
        }

        # 7. Error/Failure Summary (scan Event Log for all ERROR and WARNING level events)
        $ErrorSummaryFile = Join-Path $DiagDir "ErrorFailureSummary.txt"
        try {
            $ErrorEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='OS-Guard'; Level=2,3; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue
            if ($ErrorEvents) {
                $ErrorEvents | Sort-Object TimeCreated | Select-Object TimeCreated, LevelDisplayName, Id, Message | Format-Table -AutoSize | Out-String -Width 4096 | Set-Content -Path $ErrorSummaryFile -Encoding UTF8
            } else {
                "No OS-Guard ERROR or WARNING events in the last 7 days." | Set-Content -Path $ErrorSummaryFile -Encoding UTF8
            }
        } catch {
            "Error summary query failed: $_" | Set-Content -Path $ErrorSummaryFile -Encoding UTF8
        }

        # 8. Script Runtime State
        $RuntimeFile = Join-Path $DiagDir "ScriptRuntimeState.txt"
        try {
            $RuntimeState = @"
OS-Guard Script Runtime State
=============================
Script Path: $PSCommandPath
Install Dir: $InstallDir
Install Script: $InstallScript
Cmd Path: $CmdPath
Log File: $LogFile
Child User: $ChildUser
Branding: $script:Branding
Home SSID: $script:HomeSSID
Current PID: $PID
Is Admin: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

Environment Variables (relevant):
PATH contains InstallDir: $(([Environment]::GetEnvironmentVariable("PATH", "Machine")) -like "*$InstallDir*")
ExecutionPolicy (CurrentUser): $(Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue)
ExecutionPolicy (LocalMachine): $(Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue)
"@
            $RuntimeState | Set-Content -Path $RuntimeFile -Encoding UTF8
        } catch {
            "Failed to collect runtime state: $_" | Set-Content -Path $RuntimeFile -Encoding UTF8
        }

        # Compress
        Compress-Archive -Path "$TempDir\*" -DestinationPath $ZipPath -Force -ErrorAction Stop
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

        Write-Host "`n[SUCCESS] Dev report exported to:" -ForegroundColor Green
        Write-Host "  $ZipPath" -ForegroundColor Cyan
        Write-Host "`nReport includes:" -ForegroundColor Yellow
        Write-Host "  - All OS-Guard config/log files" -ForegroundColor Gray
        Write-Host "  - All running processes (with owners, paths, command lines)" -ForegroundColor Gray
        Write-Host "  - System info (OS, RAM, disk, boot time)" -ForegroundColor Gray
        Write-Host "  - Scheduled task status (all OS-Guard tasks)" -ForegroundColor Gray
        Write-Host "  - Registry state (key values)" -ForegroundColor Gray
        Write-Host "  - Network status (adapters, IPs, firewall rules)" -ForegroundColor Gray
        Write-Host "  - Child account status (SID, profile, session)" -ForegroundColor Gray
        Write-Host "  - ERROR/WARNING event summary (last 7 days)" -ForegroundColor Gray
        Write-Host "  - Script runtime state" -ForegroundColor Gray
        Write-Host "`nPlease post this zip file to the GitHub issue tracker:" -ForegroundColor Yellow
        Write-Host "  https://github.com/FreddeITsupport98/OS-Guard-DNS-Guard/issues" -ForegroundColor Cyan
        Write-Host "`nInclude a short description of the problem and your Windows version." -ForegroundColor Yellow

    } catch {
        Write-Host "`n[ERROR] Failed to export dev report: $_" -ForegroundColor Red
        if (Test-Path $TempDir) { Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Show-SetupWizard {
    <#
        First-Run Wizard: WinForms dialog that asks for child username, daily screen time,
        weekend limit, then auto-deploys everything. Removes the "read the menu" barrier.
    #>
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "$script:Branding - First Run Wizard"
    $form.Size = New-Object System.Drawing.Size(500, 420)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false

    $y = 20
    $labels = @(
        @("Child username:", "Child"),
        @("Daily start time (HH:mm):", "08:00"),
        @("Daily end time (HH:mm):", "20:00"),
        @("Daily max minutes (weekday):", "120"),
        @("Browser max minutes (weekday):", "60"),
        @("Weekend daily max minutes:", "180"),
        @("Weekend browser max minutes:", "90")
    )
    $controls = @()
    foreach ($pair in $labels) {
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = $pair[0]
        $lbl.Location = New-Object System.Drawing.Point(20, $y)
        $lbl.Size = New-Object System.Drawing.Size(200, 20)
        $form.Controls.Add($lbl)
        $txt = New-Object System.Windows.Forms.TextBox
        $txt.Text = $pair[1]
        $txt.Location = New-Object System.Drawing.Point(230, $y)
        $txt.Size = New-Object System.Drawing.Size(220, 20)
        $form.Controls.Add($txt)
        $controls += $txt
        $y += 35
    }

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = "DEPLOY"
    $btn.Location = New-Object System.Drawing.Point(180, $y + 10)
    $btn.Size = New-Object System.Drawing.Size(120, 30)
    $btn.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })
    $form.Controls.Add($btn)
    $form.AcceptButton = $btn

    [void]$form.ShowDialog()
    if ($form.DialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        $ChildUser = $controls[0].Text
        $DailyStart = $controls[1].Text
        $DailyEnd = $controls[2].Text
        $DailyMax = [int]$controls[3].Text
        $BrowserMax = [int]$controls[4].Text
        $WeekendDailyMax = [int]$controls[5].Text
        $WeekendBrowserMax = [int]$controls[6].Text
        Set-ScreenTimeConfig -DailyStart $DailyStart -DailyEnd $DailyEnd -DailyMaxMinutes $DailyMax -BrowserMaxMinutes $BrowserMax -WeekendDailyMaxMinutes $WeekendDailyMax -WeekendBrowserMaxMinutes $WeekendBrowserMax -Enabled $true
        Write-Log -Message "First Run Wizard configured for '$ChildUser'. Deploying locks..." -Type "ACTION" -Color Magenta
        Install-Persistence
    }
}

function New-ParentModeShortcut {
    <#
        Creates Parent Mode, Lock Now, and Continue shortcuts on the child desktop.
        Requires admin elevation so the parent can use them when logged in as the child.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    # Guard: only create in the actual child profile directory
    $LeafName = Split-Path -Path $ChildProfilePath -Leaf
    if ($LeafName -ne $ChildUser -and $LeafName -notlike "$ChildUser.*") {
        Write-Log -Message "Child profile path '$ChildProfilePath' does not match username '$ChildUser'. Skipping parent mode shortcuts creation." -Type "WARN" -Color Yellow
        return
    }
    $AdminDesktop = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $AdminDesktop)) { New-Item -ItemType Directory -Path $AdminDesktop -Force -ErrorAction SilentlyContinue | Out-Null }

    $Shortcuts = @(
        @{ Name = "Parent Mode.lnk"; Args = "-ParentMode"; Icon = "shell32.dll,48"; Desc = "Enter Parent Mode (unlock system)" }
    )

    $EffectiveScript = if (Test-Path $InstallScript) { $InstallScript } else { $PSCommandPath }
    foreach ($Sc in $Shortcuts) {
        $Path = Join-Path $AdminDesktop $Sc.Name
        try {
            Reset-HardenedFile -Path $Path
            $Wsh = New-Object -ComObject WScript.Shell
            $Lnk = $Wsh.CreateShortcut($Path)
            $Lnk.TargetPath = "pwsh.exe"
            $Lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$EffectiveScript`" $($Sc.Args)"
            $Lnk.Description = $Sc.Desc
            $Lnk.IconLocation = $Sc.Icon
            $Lnk.Save()
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($Path, $bytes)
            Harden-FileACL -FilePath $Path
            Write-Log -Message "Created admin shortcut: $($Sc.Name)" -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to create admin shortcut $($Sc.Name): $_" -Type "WARN" -Color Yellow
        }
    }
}

function Remove-ParentModeShortcut {
    <#
        Removes Parent Mode shortcuts from the child's desktop.
        Cleans ALL matching profile folders to catch stale profiles.
    #>
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        $AdminDesktop = Join-Path $ProfilePath "Desktop"
        foreach ($Name in @("Parent Mode.lnk", "Admin CMD.lnk", "Admin PowerShell.lnk", "Admin Only Logout.lnk")) {
            $Path = Join-Path $AdminDesktop $Name
            if (Test-Path $Path) {
                Reset-HardenedFile -Path $Path
                Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Removed admin shortcut: $Name from '$ProfilePath'." -Type "INFO" -Color Gray
            }
        }
    }
}

function New-ParentModeAdminTools {
    <#
        Creates Admin CMD and Admin PowerShell shortcuts on the child desktop.
        Requires admin elevation so the parent can use them when logged in as the child.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    # Guard: only create in the actual child profile directory
    $LeafName = Split-Path -Path $ChildProfilePath -Leaf
    if ($LeafName -ne $ChildUser -and $LeafName -notlike "$ChildUser.*") {
        Write-Log -Message "Child profile path '$ChildProfilePath' does not match username '$ChildUser'. Skipping Parent Mode admin tools creation." -Type "WARN" -Color Yellow
        return
    }
    $AdminDesktop = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $AdminDesktop)) { New-Item -ItemType Directory -Path $AdminDesktop -Force -ErrorAction SilentlyContinue | Out-Null }

    $Tools = @(
        @{ Name = "Admin CMD.lnk"; Target = "C:\Windows\System32\cmd.exe"; Args = "/k cd %USERPROFILE%"; Icon = "cmd.exe,0"; Desc = "Admin Command Prompt (Parent Mode)" },
        @{ Name = "Admin PowerShell.lnk"; Target = "pwsh.exe"; Args = "-NoExit -Command `"Set-Location ~`""; Icon = "pwsh.exe,0"; Desc = "Admin PowerShell (Parent Mode)" }
    )

    foreach ($T in $Tools) {
        $Path = Join-Path $AdminDesktop $T.Name
        try {
            $Wsh = New-Object -ComObject WScript.Shell
            $Lnk = $Wsh.CreateShortcut($Path)
            $Lnk.TargetPath = $T.Target
            $Lnk.Arguments = $T.Args
            $Lnk.Description = $T.Desc
            $Lnk.IconLocation = $T.Icon
            $Lnk.Save()
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($Path, $bytes)
            Harden-FileACL -FilePath $Path
            Write-Log -Message "Created Parent Mode admin tool: $($T.Name)" -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to create admin tool $($T.Name): $_" -Type "WARN" -Color Yellow
        }
    }
}

function Remove-ParentModeAdminTools {
    <#
        Removes the Admin CMD and Admin PowerShell shortcuts from the child desktop.
        Cleans ALL matching profile folders to catch stale profiles.
    #>
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        $AdminDesktop = Join-Path $ProfilePath "Desktop"
        foreach ($Name in @("Admin CMD.lnk", "Admin PowerShell.lnk", "Admin Only Logout.lnk")) {
            $Path = Join-Path $AdminDesktop $Name
            if (Test-Path $Path) {
                Reset-HardenedFile -Path $Path
                Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Removed admin tool: $Name from '$ProfilePath'." -Type "INFO" -Color Gray
            }
        }
    }
}

function New-ChildLockNowShortcut {
    <#
        Creates a "Lock Now" shortcut on the child's desktop.
        The shortcut is ACL-hardened so the child cannot delete or modify it.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    $LeafName = Split-Path -Path $ChildProfilePath -Leaf
    if ($LeafName -ne $ChildUser -and $LeafName -notlike "$ChildUser.*") {
        Write-Log -Message "Child profile path '$ChildProfilePath' does not match username '$ChildUser'. Skipping lock now shortcut creation." -Type "WARN" -Color Yellow
        return
    }
    $DesktopPath = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $DesktopPath)) { New-Item -ItemType Directory -Path $DesktopPath -Force -ErrorAction SilentlyContinue | Out-Null }
    $EffectiveScript = if (Test-Path $InstallScript) { $InstallScript } else { $PSCommandPath }
    $ShortcutPath = Join-Path $DesktopPath "Lock Now.lnk"
    try {
        Reset-HardenedFile -Path $ShortcutPath
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = "pwsh.exe"
        $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$EffectiveScript`" -LockNow"
        $Shortcut.Description = "Immediately re-lock the system"
        $Shortcut.IconLocation = "shell32.dll,47"
        $Shortcut.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Harden-FileACL -FilePath $ShortcutPath
        Write-Log -Message "Created child lock now shortcut at '$ShortcutPath' for '$ChildUser'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create lock now shortcut for '$ChildUser': $_" -Type "WARN" -Color Yellow
    }
}

function Remove-ChildLockNowShortcut {
    <#
        Removes the "Lock Now" shortcut from the child's desktop.
    #>
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        $Path = Join-Path $ProfilePath "Desktop\Lock Now.lnk"
        if (Test-Path $Path) {
            Reset-HardenedFile -Path $Path
            Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed lock now shortcut from '$ProfilePath'." -Type "INFO" -Color Gray
        }
    }
}

function New-ChildContinueParentModeShortcut {
    <#
        Creates a "Continue Parent Mode" shortcut on the child's desktop.
        The shortcut is ACL-hardened so the child cannot delete or modify it.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    $LeafName = Split-Path -Path $ChildProfilePath -Leaf
    if ($LeafName -ne $ChildUser -and $LeafName -notlike "$ChildUser.*") {
        Write-Log -Message "Child profile path '$ChildProfilePath' does not match username '$ChildUser'. Skipping continue parent mode shortcut creation." -Type "WARN" -Color Yellow
        return
    }
    $DesktopPath = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $DesktopPath)) { New-Item -ItemType Directory -Path $DesktopPath -Force -ErrorAction SilentlyContinue | Out-Null }
    $EffectiveScript = if (Test-Path $InstallScript) { $InstallScript } else { $PSCommandPath }
    $ShortcutPath = Join-Path $DesktopPath "Continue Parent Mode.lnk"
    try {
        Reset-HardenedFile -Path $ShortcutPath
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = "pwsh.exe"
        $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$EffectiveScript`" -ContinueParentMode"
        $Shortcut.Description = "Reset AFK timer while in Parent Mode"
        $Shortcut.IconLocation = "shell32.dll,45"
        $Shortcut.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Harden-FileACL -FilePath $ShortcutPath
        Write-Log -Message "Created child continue parent mode shortcut at '$ShortcutPath' for '$ChildUser'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create continue parent mode shortcut for '$ChildUser': $_" -Type "WARN" -Color Yellow
    }
}

function Remove-ChildContinueParentModeShortcut {
    <#
        Removes the "Continue Parent Mode" shortcut from the child's desktop.
    #>
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        $Path = Join-Path $ProfilePath "Desktop\Continue Parent Mode.lnk"
        if (Test-Path $Path) {
            Reset-HardenedFile -Path $Path
            Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed continue parent mode shortcut from '$ProfilePath'." -Type "INFO" -Color Gray
        }
    }
}

function New-ChildApproveInstallShortcut {
    <#
        Creates an "Approve Child Install" shortcut on the child's desktop.
        The shortcut is ACL-hardened so the child cannot delete or modify it.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    $LeafName = Split-Path -Path $ChildProfilePath -Leaf
    if ($LeafName -ne $ChildUser -and $LeafName -notlike "$ChildUser.*") {
        Write-Log -Message "Child profile path '$ChildProfilePath' does not match username '$ChildUser'. Skipping approve install shortcut creation." -Type "WARN" -Color Yellow
        return
    }
    $DesktopPath = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $DesktopPath)) { New-Item -ItemType Directory -Path $DesktopPath -Force -ErrorAction SilentlyContinue | Out-Null }
    $EffectiveScript = if (Test-Path $InstallScript) { $InstallScript } else { $PSCommandPath }
    $ShortcutPath = Join-Path $DesktopPath "Approve Child Install.lnk"
    try {
        Reset-HardenedFile -Path $ShortcutPath
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = "pwsh.exe"
        $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$EffectiveScript`" -ApproveChildInstall"
        $Shortcut.Description = "Temporarily allow software install to child account (15 min)"
        $Shortcut.IconLocation = "shell32.dll,44"
        $Shortcut.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Harden-FileACL -FilePath $ShortcutPath
        Write-Log -Message "Created child approve install shortcut at '$ShortcutPath' for '$ChildUser'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create approve install shortcut for '$ChildUser': $_" -Type "WARN" -Color Yellow
    }
}

function Remove-ChildApproveInstallShortcut {
    <#
        Removes the "Approve Child Install" shortcut from the child's desktop.
    #>
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        $Path = Join-Path $ProfilePath "Desktop\Approve Child Install.lnk"
        if (Test-Path $Path) {
            Reset-HardenedFile -Path $Path
            Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed approve install shortcut from '$ProfilePath'." -Type "INFO" -Color Gray
        }
    }
}

function Reset-HardenedFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $stream.Close()
        return
    } catch {}
    try {
        $proc = Start-Process -FilePath "takeown.exe" -ArgumentList "/F", $Path -Wait -WindowStyle Hidden -PassThru
        if ($proc.ExitCode -ne 0) { Write-Log -Message "takeown failed on $Path (exit $($proc.ExitCode))" -Type "WARN" -Color Yellow }
    } catch { Write-Log -Message "takeown exception on $Path`: $_" -Type "WARN" -Color Yellow }
    try {
        $proc = Start-Process -FilePath "icacls.exe" -ArgumentList $Path, "/grant:r", "BUILTIN\Administrators:F", "/C" -Wait -WindowStyle Hidden -PassThru
        if ($proc.ExitCode -ne 0) { Write-Log -Message "icacls failed on $Path (exit $($proc.ExitCode))" -Type "WARN" -Color Yellow }
    } catch { Write-Log -Message "icacls exception on $Path`: $_" -Type "WARN" -Color Yellow }
}

function New-ChildGameRequestShortcut {
    <#
        Creates a "Request Game Install" shortcut on the child's desktop.
        The shortcut is ACL-hardened so the child cannot delete or modify it.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    # Guard: only create in the actual child profile directory
    $LeafName = Split-Path -Path $ChildProfilePath -Leaf
    if ($LeafName -ne $ChildUser -and $LeafName -notlike "$ChildUser.*") {
        Write-Log -Message "Child profile path '$ChildProfilePath' does not match username '$ChildUser'. Skipping game request shortcut creation." -Type "WARN" -Color Yellow
        return
    }
    $DesktopPath = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $DesktopPath)) { New-Item -ItemType Directory -Path $DesktopPath -Force -ErrorAction SilentlyContinue | Out-Null }
    $EffectiveScript = if (Test-Path $InstallScript) { $InstallScript } else { $PSCommandPath }
    $ShortcutPath = Join-Path $DesktopPath "Request Game Install.lnk"
    Reset-HardenedFile -Path $ShortcutPath
    try {
        $Wsh = New-Object -ComObject WScript.Shell
        $Lnk = $Wsh.CreateShortcut($ShortcutPath)
        $Lnk.TargetPath = "pwsh.exe"
        $Lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$EffectiveScript`" -ChildGameRequest -ChildUser `"$ChildUser`""
        $Lnk.Description = "Request a game installation (requires admin approval)"
        $Lnk.IconLocation = "shell32.dll,15"
        $Lnk.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Harden-FileACL -FilePath $ShortcutPath
        Write-Log -Message "Created child game request shortcut at '$ShortcutPath'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create child game request shortcut: $_" -Type "WARN" -Color Yellow
    }
}

function Remove-ChildGameRequestShortcut {
    <#
        Removes the game request shortcut from the child's desktop.
        Cleans ALL matching profile folders to catch stale profiles.
    #>
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        $Path = Join-Path $ProfilePath "Desktop\Request Game Install.lnk"
        if (Test-Path $Path) {
            Reset-HardenedFile -Path $Path
            Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed child game request shortcut from '$ProfilePath'." -Type "INFO" -Color Gray
        }
    }
}

function Show-GameRequestDialog {
    <#
        Displays a simple input dialog for the child to request a game.
        Writes the request to a protected file in $InstallDir\Requests.
    #>
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
    $GameName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the game name you want to install:`n(Admin will review and approve)", "Game Install Request", "", -1, -1)
    if ([string]::IsNullOrWhiteSpace($GameName)) { return }
    $RequestDir = Join-Path $InstallDir "Requests"
    if (-not (Test-Path $RequestDir)) { New-Item -ItemType Directory -Path $RequestDir -Force -ErrorAction SilentlyContinue | Out-Null }
    $RequestFile = Join-Path $RequestDir "request_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $Content = @"
Game Install Request
--------------------
From user: $ChildUser
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Game name: $GameName

This request was submitted by the child user and requires administrator approval.
"@
    try {
        Set-Content -Path $RequestFile -Value $Content -Encoding UTF8 -Force -ErrorAction Stop
        Write-Log -Message "Game request saved to '$RequestFile'." -Type "INFO" -Color Gray
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        [System.Windows.Forms.MessageBox]::Show("Your request for '$GameName' has been submitted to the administrator.`n`nThe admin will review and install it if approved.", "Request Sent", "OK", "Information") | Out-Null
    } catch {
        Write-Log -Message "Failed to save game request: $_" -Type "ERROR" -Color Red
    }
}

function Show-GameRequestReview {
    <#
        Parent-facing TUI to review all pending game install requests.
        Lists request files from $InstallDir\Requests, shows game name, child, and timestamp.
        Parent can approve a request (opens 15-min install window), clear all, or return.
    #>
    Clear-Host
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " REVIEW PENDING GAME INSTALL REQUESTS " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan

    $RequestDir = Join-Path $InstallDir "Requests"
    if (-not (Test-Path $RequestDir)) {
        Write-Host "`n[INFO] No request directory found. No pending requests." -ForegroundColor Gray
        Write-Host "`n[ PRESS ANY KEY TO RETURN ]" -ForegroundColor DarkGray; Wait-AnyKey
        return
    }

    $RequestFiles = Get-ChildItem -Path $RequestDir -Filter "request_*.txt" -File | Sort-Object LastWriteTime -Descending
    if ($RequestFiles.Count -eq 0) {
        Write-Host "`n[INFO] No pending game install requests." -ForegroundColor Gray
        Write-Host "`n[ PRESS ANY KEY TO RETURN ]" -ForegroundColor DarkGray; Wait-AnyKey
        return
    }

    Write-Host "`nFound $($RequestFiles.Count) pending request(s):" -ForegroundColor White
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    $Index = 1
    foreach ($File in $RequestFiles) {
        $Content = Get-Content -Path $File.FullName -ErrorAction SilentlyContinue
        $GameName = "(unknown)"
        $Timestamp = $File.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        $FromUser = $ChildUser
        foreach ($Line in $Content) {
            if ($Line -match '^Game name:\s*(.+)$') { $GameName = $Matches[1].Trim() }
            if ($Line -match '^From user:\s*(.+)$') { $FromUser = $Matches[1].Trim() }
            if ($Line -match '^Timestamp:\s*(.+)$') { $Timestamp = $Matches[1].Trim() }
        }
        Write-Host "[$Index] Game: $GameName" -ForegroundColor Yellow
        Write-Host "      From: $FromUser  |  $Timestamp" -ForegroundColor DarkGray
        Write-Host "      File: $($File.Name)" -ForegroundColor DarkGray
        Write-Host ""
        $Index++
    }

    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[A] APPROVE a request (select by number, then opens 15-min install window)" -ForegroundColor Green
    Write-Host "[C] CLEAR ALL requests (delete all pending files)" -ForegroundColor Red
    Write-Host "[R] RETURN to menu" -ForegroundColor Gray
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    $Choice = Read-Host "Select an action (A/C/R or 1-$($RequestFiles.Count))"
    if ($Choice -eq 'C' -or $Choice -eq 'c') {
        Write-Host "`n[WARNING] This will DELETE all pending request files." -ForegroundColor Yellow
        $Confirm = Read-Host "Type 'yes' to confirm"
        if ($Confirm -eq 'yes') {
            foreach ($File in $RequestFiles) {
                try {
                    Remove-Item -Path $File.FullName -Force -ErrorAction Stop
                    Write-Host "  [DELETED] $($File.Name)" -ForegroundColor Green
                } catch {
                    Write-Host "  [FAILED]  $($File.Name): $_" -ForegroundColor Red
                }
            }
            Write-Host "`n[SUCCESS] All pending requests cleared." -ForegroundColor Green
        } else {
            Write-Host "[CANCELLED] No files were deleted." -ForegroundColor Gray
        }
    } elseif ($Choice -eq 'A' -or $Choice -eq 'a') {
        $ApproveNum = Read-Host "Enter request number to approve (1-$($RequestFiles.Count))"
        if ($ApproveNum -match '^\d+$') {
            $Num = [int]$ApproveNum
            if ($Num -ge 1 -and $Num -le $RequestFiles.Count) {
                $SelectedFile = $RequestFiles[$Num - 1]
                $Content = Get-Content -Path $SelectedFile.FullName -ErrorAction SilentlyContinue
                $GameName = "(unknown)"
                foreach ($Line in $Content) {
                    if ($Line -match '^Game name:\s*(.+)$') { $GameName = $Matches[1].Trim() }
                }
                Write-Host "`nApproving request for '$GameName'..." -ForegroundColor Cyan
                Approve-ChildInstall
                # Optionally remove the approved request file after approval
                try {
                    Remove-Item -Path $SelectedFile.FullName -Force -ErrorAction Stop
                    Write-Host "[INFO] Approved request file removed." -ForegroundColor Gray
                } catch {
                    Write-Host "[WARN] Could not remove approved request file: $_" -ForegroundColor Yellow
                }
            } else {
                Write-Host "[ERROR] Invalid request number." -ForegroundColor Red
            }
        } else {
            Write-Host "[ERROR] Invalid input." -ForegroundColor Red
        }
    } elseif ($Choice -match '^\d+$') {
        $Num = [int]$Choice
        if ($Num -ge 1 -and $Num -le $RequestFiles.Count) {
            $SelectedFile = $RequestFiles[$Num - 1]
            $Content = Get-Content -Path $SelectedFile.FullName -ErrorAction SilentlyContinue
            $GameName = "(unknown)"
            foreach ($Line in $Content) {
                if ($Line -match '^Game name:\s*(.+)$') { $GameName = $Matches[1].Trim() }
            }
            Write-Host "`nApproving request for '$GameName'..." -ForegroundColor Cyan
            Approve-ChildInstall
            try {
                Remove-Item -Path $SelectedFile.FullName -Force -ErrorAction Stop
                Write-Host "[INFO] Approved request file removed." -ForegroundColor Gray
            } catch {
                Write-Host "[WARN] Could not remove approved request file: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[ERROR] Invalid request number." -ForegroundColor Red
        }
    }

    Write-Host "`n[ PRESS ANY KEY TO RETURN ]" -ForegroundColor DarkGray; Wait-AnyKey
}

function Get-ChildInstallDirectories {
    <#
        Discovers program install directories and shortcuts within the child profile.
        Scans Desktop, Start Menu, AppData\Local\Programs, and AppData\Roaming.
        Uses [System.IO.Directory]::EnumerateDirectories for performance.
        Returns an array of unique directory paths.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { return @() }

    $Dirs = [System.Collections.Generic.List[string]]::new()

    # --- Scan common user install locations ---
    $ScanPaths = @(
        (Join-Path $ChildProfilePath "AppData\Local\Programs"),
        (Join-Path $ChildProfilePath "AppData\Local"),
        (Join-Path $ChildProfilePath "AppData\Roaming"),
        (Join-Path $ChildProfilePath "Desktop"),
        (Join-Path $ChildProfilePath "Documents")
    )

    foreach ($ScanPath in $ScanPaths) {
        if (-not (Test-Path $ScanPath)) { continue }
        try {
            $Candidates = [System.IO.Directory]::EnumerateDirectories($ScanPath) | Where-Object {
                $Name = [System.IO.Path]::GetFileName($_)
                # Skip Windows system folders that are not user-installed programs
                if ($Name -match "^(Microsoft|Windows|Temp|Packages|Temp\w*|Media\w*)$") { return $false }
                # Heuristic: contains .exe or .dll files, or looks like a program folder
                $HasFiles = $false
                try {
                    $SubDirs = [System.IO.Directory]::EnumerateDirectories($_, "*", [System.IO.SearchOption]::AllDirectories)
                    foreach ($SubDir in $SubDirs) {
                        if ([System.IO.Directory]::GetFiles($SubDir, "*.exe").Count -gt 0 -or
                            [System.IO.Directory]::GetFiles($SubDir, "*.dll").Count -gt 0 -or
                            [System.IO.Directory]::GetFiles($SubDir, "*.json").Count -gt 0) {
                            $HasFiles = $true
                            break
                        }
                    }
                } catch { $HasFiles = $false }
                $HasFiles
            }
            foreach ($Candidate in $Candidates) {
                if (-not $Dirs.Contains($Candidate)) { $Dirs.Add($Candidate) }
            }
        } catch {}
    }

    # --- Scan Start Menu shortcuts to discover program targets ---
    $StartMenuPaths = @(
        (Join-Path $ChildProfilePath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs"),
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
    )
    foreach ($StartMenu in $StartMenuPaths) {
        if (-not (Test-Path $StartMenu)) { continue }
        try {
            $Shortcuts = Get-ChildItem -Path $StartMenu -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue
            foreach ($Shortcut in $Shortcuts) {
                try {
                    $Wsh = New-Object -ComObject WScript.Shell
                    $Lnk = $Wsh.CreateShortcut($Shortcut.FullName)
                    $Target = $Lnk.TargetPath
                    if ($Target -and (Test-Path $Target) -and $Target -match "\.exe$") {
                        $TargetDir = Split-Path -Parent $Target
                        if ($TargetDir -and $TargetDir -notlike "*\Windows\*" -and $TargetDir -notlike "*\Program Files\*" -and $TargetDir -notlike "*\System32\*" -and $TargetDir -notlike "*\SysWOW64\*") {
                            if (-not $Dirs.Contains($TargetDir)) { $Dirs.Add($TargetDir) }
                        }
                    }
                } catch {}
            }
        } catch {}
    }

    return ,($Dirs.ToArray())
}

function Harden-ProgramDirectory {
    <#
        Hardens a program directory so the child can execute files but cannot:
        - Modify, delete, or rename files/folders
        - Change permissions or take ownership
        - Write new files
        The child retains ReadAndExecute (can run the game/program).
    #>
    param([string]$DirPath)
    if (-not (Test-Path $DirPath)) { return }

    $ChildSidValue = Get-ChildSid
    if (-not $ChildSidValue) { return }
    $ChildSidObj = New-Object System.Security.Principal.SecurityIdentifier($ChildSidValue)

    try {
        $Acl = Get-Acl -Path $DirPath
        $Acl.SetOwner($SidSystem)
        $Acl.SetAccessRuleProtection($true, $false)

        # Remove any existing child-specific rules
        $Acl.Access | Where-Object {
            try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $ChildSidValue } catch { $false }
        } | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }

        # SYSTEM and Admin: FullControl so the directory remains accessible to admin after scan/reharden
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $SidAdmin, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))

        # Child: ReadAndExecute on files (can run programs), but Deny Modify/Delete/Write on folder+files
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "Modify", "ContainerInherit,ObjectInherit", "None", "Deny")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "Delete", "ContainerInherit,ObjectInherit", "None", "Deny")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "WriteData", "ContainerInherit,ObjectInherit", "None", "Deny")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "AppendData", "ContainerInherit,ObjectInherit", "None", "Deny")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "ChangePermissions", "ContainerInherit,ObjectInherit", "None", "Deny")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "TakeOwnership", "ContainerInherit,ObjectInherit", "None", "Deny")))

        Set-Acl -Path $DirPath -AclObject $Acl -ErrorAction Stop
        Write-Log -Message "Program directory hardened: $DirPath" -Type "INFO" -Color Gray
    } catch {
    Write-Log -Message "Failed to harden program directory $DirPath`: $_" -Type "WARN" -Color Yellow
    }
}

function Get-ProgramAllowlist {
    $Data = Read-JsonFile -Path $ProgramAllowlistFile
    if ($Data -is [array]) { return ,$Data }
    if ($Data) { return ,@($Data) }
    return ,@()
}

function Save-ProgramAllowlist {
    param([array]$List)
    $Success = Write-JsonFile -Path $ProgramAllowlistFile -Data $List -Depth 3
    if ($Success) {
        Harden-ScreenTimeFile -FilePath $ProgramAllowlistFile
    } else {
        Write-Log -Message "Failed to save program allowlist (mutex/atomic write failed)." -Type "WARN" -Color Yellow
    }
}

function Get-BlockedProgramLog {
    $Data = Read-JsonFile -Path $BlockedProgramLogFile
    if ($Data -is [array]) { return ,$Data }
    if ($Data) { return ,@($Data) }
    return ,@()
}

function Save-BlockedProgramLog {
    param([array]$Log)
    $Success = Write-JsonFile -Path $BlockedProgramLogFile -Data $Log -Depth 3
    if ($Success) {
        Harden-ScreenTimeFile -FilePath $BlockedProgramLogFile
    } else {
        Write-Log -Message "Failed to save blocked program log (mutex/atomic write failed)." -Type "WARN" -Color Yellow
    }
}

function Block-ProgramDirectory {
    <#
        Aggressively blocks a program directory by denying ReadAndExecute for the child.
        This prevents the child from running any executables inside the directory.
    #>
    param([string]$DirPath)
    if (-not (Test-Path $DirPath)) { return }
    $ChildSidValue = Get-ChildSid
    if (-not $ChildSidValue) { return }
    $ChildSidObj = New-Object System.Security.Principal.SecurityIdentifier($ChildSidValue)
    try {
        $Acl = Get-Acl -Path $DirPath
        $Acl.SetOwner($SidSystem)
        $Acl.SetAccessRuleProtection($true, $false)
        $Acl.Access | Where-Object {
            try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $ChildSidValue } catch { $false }
        } | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $SidAdmin, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Deny")))
        Set-Acl -Path $DirPath -AclObject $Acl -ErrorAction Stop
        Write-Log -Message "Program directory aggressively blocked: $DirPath" -Type "SECURITY" -Color Red
    } catch {
        Write-Log -Message "Failed to block program directory $DirPath`: $_" -Type "WARN" -Color Yellow
    }
}

function Show-BlockedProgramReview {
    <#
        Interactive CLI to review blocked programs discovered by Program Guardian.
        Admin can allow (harden but executable) or re-block them.
    #>
    do {
        Clear-Host
        Write-Host "`n=====================================================" -ForegroundColor Cyan
        Write-Host " REVIEW BLOCKED PROGRAMS " -ForegroundColor Cyan
        Write-Host "=====================================================" -ForegroundColor Cyan
        $BlockedLog = Get-BlockedProgramLog
        $Allowlist = Get-ProgramAllowlist
        if ($BlockedLog.Count -eq 0) {
            Write-Host "`n[INFO] No blocked programs recorded." -ForegroundColor Gray
            Write-Host "`n[ PRESS ANY KEY TO RETURN ]" -ForegroundColor DarkGray; Wait-AnyKey
            return
        }
        $Index = 0
        foreach ($Entry in $BlockedLog) {
            $Index++
            $StatusColor = switch ($Entry.Status) {
                "Blocked"   { "Red" }
                "Allowed"   { "Green" }
                default     { "Yellow" }
            }
            Write-Host "[$Index] $($Entry.Path)" -ForegroundColor $StatusColor
            Write-Host "     Discovered: $($Entry.DiscoveredAt) | Status: $($Entry.Status)" -ForegroundColor Gray
        }
        Write-Host "`n[A] Allow a program (enter number)" -ForegroundColor Green
        Write-Host '[B] Block a program (enter number)' -ForegroundColor Red

        Write-Host '[R] Remove from list (enter number)' -ForegroundColor Yellow

        Write-Host '[Q] Quit / Return' -ForegroundColor Gray

        $Choice = (Read-Host "`nSelect action").ToUpper()
        if ($Choice -eq "Q") { return }
        if ($Choice -match "^[ABR]$") {
            $Num = Read-Host "Enter program number"
            if ($Num -match "^\d+$") {
                $Idx = [int]$Num - 1
                if ($Idx -ge 0 -and $Idx -lt $BlockedLog.Count) {
                    $Selected = $BlockedLog[$Idx]
                    switch ($Choice) {
                        "A" {
                            Harden-ProgramDirectory -DirPath $Selected.Path
                            $Allowlist += $Selected.Path
                            Save-ProgramAllowlist -List $Allowlist
                            Sync-ProgramDirectoryToWhitelist -DirPath $Selected.Path -Allow
                            $Selected.Status = "Allowed"
                            Save-BlockedProgramLog -Log $BlockedLog
                            Write-Host "`[SUCCESS] Allowed: $($Selected.Path)" -ForegroundColor Green

                        }
                        "B" {
                            Block-ProgramDirectory -DirPath $Selected.Path
                            Sync-ProgramDirectoryToWhitelist -DirPath $Selected.Path
                            $Selected.Status = "Blocked"
                            Save-BlockedProgramLog -Log $BlockedLog
                            Write-Host "`[SUCCESS] Blocked: $($Selected.Path)" -ForegroundColor Red

                        }
                        "R" {
                            $BlockedLog = $BlockedLog | Where-Object { $_.Path -ne $Selected.Path }
                            Save-BlockedProgramLog -Log $BlockedLog
                            Write-Host "`[INFO] Removed from blocked log: $($Selected.Path)" -ForegroundColor Gray

                        }
                    }
                } else {
                    Write-Host '[ERROR] Invalid number.' -ForegroundColor Red

                }
            }
            Write-Host "`n[ PRESS ANY KEY TO CONTINUE ]" -ForegroundColor DarkGray; Wait-AnyKey
        }
    } while ($true)
}

function Harden-ProgramShortcuts {
    <#
        Hardens all .lnk shortcuts in the child profile Desktop and Start Menu
        so the child cannot delete, modify, or rename them.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { return }

    $ShortcutPaths = @(
        (Join-Path $ChildProfilePath "Desktop"),
        (Join-Path $ChildProfilePath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs")
    )

    foreach ($BasePath in $ShortcutPaths) {
        if (-not (Test-Path $BasePath)) { continue }
        try {
            $Shortcuts = Get-ChildItem -Path $BasePath -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue
            foreach ($Sc in $Shortcuts) {
                try {
                    Harden-FileACL -FilePath $Sc.FullName
                } catch {
                    Write-Log -Message "Failed to harden shortcut $($Sc.FullName): $_" -Type "WARN" -Color Yellow
                }
            }
        } catch {}
    }
}

function Scan-And-Harden-ChildPrograms {
    <#
        Main Program Guardian scan routine.
        Discovers newly installed programs in the child profile and hardens them.
        Also hardens all shortcuts.
        Skips expensive scan if the child is not currently logged in.
        NEW: Aggressive auto-block -- new programs are blocked unless in allowlist.
    #>
    # Performance: skip scan if child is not logged in
    $ChildIsLoggedIn = $false
    try {
        $LoggedOn = Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue | Where-Object { $_.Antecedent -match "Name=`"$ChildUser`"" }
        if ($LoggedOn) { $ChildIsLoggedIn = $true }
    } catch { $ChildIsLoggedIn = $true }
    if (-not $ChildIsLoggedIn) {
        Write-Log -Message "Program Guardian: child '$ChildUser' is not logged in. Skipping scan." -Type "INFO" -Color Gray
        return
    }

    Write-Log -Message "Program Guardian: scanning child profile for installed programs..." -Type "ACTION" -Color Cyan

    $Allowlist = Get-ProgramAllowlist
    $BlockedLog = Get-BlockedProgramLog
    $DiscoveredDirs = Get-ChildInstallDirectories

    $NewBlocks = 0
    $NewAllows = 0

    foreach ($Dir in $DiscoveredDirs) {
        $NormalizedDir = (Resolve-Path $Dir -ErrorAction SilentlyContinue).Path.TrimEnd('\')
        if (-not $NormalizedDir) { $NormalizedDir = $Dir.TrimEnd('\') }

        if ($Allowlist -contains $NormalizedDir) {
            Harden-ProgramDirectory -DirPath $Dir
            Sync-ProgramDirectoryToWhitelist -DirPath $Dir -Allow
            $NewAllows++
            continue
        }

        $ExistingEntry = $BlockedLog | Where-Object { $_.Path -eq $NormalizedDir }
        if (-not $ExistingEntry) {
            Block-ProgramDirectory -DirPath $Dir
            Sync-ProgramDirectoryToWhitelist -DirPath $Dir
            $BlockedLog += [PSCustomObject]@{
                Path = $NormalizedDir
                DiscoveredAt = (Get-Date -Format "o")
                Status = "Blocked"
            }
            Write-Log -Message "AGGRESSIVE BLOCK: New program discovered and blocked: $NormalizedDir" -Type "SECURITY" -Color Red
            $NewBlocks++
        } else {
            if ($ExistingEntry.Status -eq "Blocked") {
                Block-ProgramDirectory -DirPath $Dir
                Sync-ProgramDirectoryToWhitelist -DirPath $Dir
            } elseif ($ExistingEntry.Status -eq "Allowed") {
                Harden-ProgramDirectory -DirPath $Dir
                Sync-ProgramDirectoryToWhitelist -DirPath $Dir -Allow
            }
        }
    }

    $BlockedLog = @($BlockedLog | Where-Object { Test-Path $_.Path })

    if ($NewBlocks -gt 0 -or $NewAllows -gt 0) {
        Save-BlockedProgramLog -Log $BlockedLog
    }

    if ($NewBlocks -gt 0) {
        Write-Log -Message "Program Guardian: $NewBlocks new program(s) aggressively blocked. Use 'Review Blocked Programs' in the menu to allow them." -Type "WARN" -Color Yellow
    }
    if ($NewAllows -gt 0) {
        Write-Log -Message "Program Guardian: $NewAllows allowed program(s) hardened." -Type "INFO" -Color Gray
    }

    Harden-ProgramShortcuts
    Write-Log -Message "Program Guardian: scan complete." -Type "SUCCESS" -Color Green
}

# ============================================================================
# 5.5 PROCESS ENFORCER - LIVE PROCESS ENFORCEMENT (Child-Only)
# ============================================================================

function Get-FileHashSafe {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return $null }
    try {
        $Stream = [System.IO.File]::OpenRead($Path)
        try {
            $Sha256 = [System.Security.Cryptography.SHA256]::Create()
            $HashBytes = $Sha256.ComputeHash($Stream)
            $Sha256.Dispose()
            $Hex = New-Object System.Text.StringBuilder ($HashBytes.Length * 2)
            foreach ($Byte in $HashBytes) {
                [void]$Hex.Append($Byte.ToString("x2"))
            }
            return $Hex.ToString()
        } finally {
            $Stream.Dispose()
        }
    } catch {
        return $null
    }
}

function Get-BlockedProcessHashes {
    $Data = Read-JsonFile -Path $BlockedHashesFile
    if ($Data -is [array]) { return ,$Data }
    if ($Data) { return ,@($Data) }
    return ,@()
}

function Sync-ProgramDirectoryToWhitelist {
    <#
        Scans a program directory for executables and synchronizes them with the
        RestrictRun whitelist and the blocked hash database.
        -Allow adds all .exe names to the whitelist and removes their hashes from the blocklist.
        Without -Allow, removes .exe names from the whitelist and adds their hashes to the blocklist.
    #>
    param(
        [string]$DirPath,
        [switch]$Allow
    )
    if (-not (Test-Path $DirPath)) { return }

    $Exes = @()
    try {
        $Exes = Get-ChildItem -Path $DirPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
    } catch { return }

    if ($Exes.Count -eq 0) { return }

    $Whitelist = Get-ProgramWhitelist
    if ($Whitelist.Count -eq 0) {
        $Whitelist = Get-DefaultProgramWhitelist
    }

    $BlockedHashes = @(Get-BlockedProcessHashes)
    $WhitelistChanged = $false
    $HashesChanged = $false

    foreach ($Exe in $Exes) {
        $ExeName = $Exe.Name.ToLower()
        if ($Allow) {
            if ($Whitelist -notcontains $ExeName) {
                $Whitelist += $ExeName
                $WhitelistChanged = $true
                Write-Log -Message "Auto-whitelisted $ExeName from allowed directory $DirPath" -Type "INFO" -Color Green
            }
            $Hash = Get-FileHashSafe -Path $Exe.FullName
            if ($Hash) {
                $BeforeCount = $BlockedHashes.Count
                $BlockedHashes = $BlockedHashes | Where-Object { $_.Hash -ne $Hash }
                if ($BlockedHashes.Count -ne $BeforeCount) {
                    $HashesChanged = $true
                }
            }
        } else {
            if ($Whitelist -contains $ExeName) {
                $Whitelist = $Whitelist | Where-Object { $_ -ne $ExeName }
                $WhitelistChanged = $true
                Write-Log -Message "Removed $ExeName from whitelist (directory blocked)" -Type "SECURITY" -Color Red
            }
            $Hash = Get-FileHashSafe -Path $Exe.FullName
            if ($Hash -and ($BlockedHashes.Hash -notcontains $Hash)) {
                $BlockedHashes += [PSCustomObject]@{ Path = $Exe.FullName; Hash = $Hash }
                $HashesChanged = $true
                Write-Log -Message "Auto-blocked hash for $ExeName from blocked directory $DirPath" -Type "SECURITY" -Color Red
            }
        }
    }

    if ($WhitelistChanged) {
        Set-ProgramWhitelist -List $Whitelist
    }
    if ($HashesChanged) {
        Write-JsonFile -Path $BlockedHashesFile -Data $BlockedHashes -Depth 3 | Out-Null
        Harden-ScreenTimeFile -FilePath $BlockedHashesFile
    }
}

function Initialize-BlockedProcessHashes {
    <#
        Pre-populates the blocked hash database with known dangerous system executables.
        This catches renamed copies of blocked tools (e.g., pwsh.exe renamed to notepad.exe).
    #>
    $KnownPaths = @(
        "pwsh.exe",
        "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\pwsh.exe",
        "C:\Windows\System32\cmd.exe",
        "C:\Windows\SysWOW64\cmd.exe",
        "C:\Windows\System32\wscript.exe",
        "C:\Windows\System32\cscript.exe",
        "C:\Windows\System32\mshta.exe",
        "C:\Program Files\PowerShell\7\pwsh.exe",
        "C:\Program Files\PowerShell\7-preview\pwsh.exe",
        "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
    )
    $Hashes = @()
    foreach ($Path in $KnownPaths) {
        if (Test-Path $Path) {
            try {
                $Hash = Get-FileHashSafe -Path $Path
                if ($Hash) { $Hashes += [PSCustomObject]@{ Path = $Path; Hash = $Hash } }
            } catch {}
        }
    }
    if ($Hashes.Count -gt 0) {
        $Success = Write-JsonFile -Path $BlockedHashesFile -Data $Hashes -Depth 3
        if ($Success) {
            Harden-ScreenTimeFile -FilePath $BlockedHashesFile
            Write-Log -Message "Blocked process hash database initialized with $($Hashes.Count) entries." -Type "INFO" -Color Gray
        } else {
            Write-Log -Message "Failed to initialize blocked process hashes (mutex/atomic write failed)." -Type "WARN" -Color Yellow
        }
    }
}

function Add-BlockedProcessHash {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return }
    $Hash = Get-FileHashSafe -Path $Path
    if (-not $Hash) { return }
    $Entries = @(Get-BlockedProcessHashes)
    $ExistingHashes = $Entries | Select-Object -ExpandProperty Hash
    if ($ExistingHashes -contains $Hash) { return }
    $Entries += [PSCustomObject]@{ Path = $Path; Hash = $Hash }
    Write-JsonFile -Path $BlockedHashesFile -Data $Entries -Depth 3 | Out-Null
    Harden-ScreenTimeFile -FilePath $BlockedHashesFile
}

function Write-BlockedProcessLog {
    param([string]$ProcessName, [int]$ProcessId, [string]$Path = "", [string]$CommandLine = "", [string]$Hash = "", [string]$Reason = "Not in whitelist")
    $Entry = [PSCustomObject]@{
        Timestamp = (Get-Date -Format "o")
        ProcessName = $ProcessName
        ProcessId = $ProcessId
        Path = $Path
        CommandLine = $CommandLine
        Hash = $Hash
        Reason = $Reason
    }
    $Log = @()
    if (Test-Path $BlockedProcessLogFile) {
        $Data = Read-JsonFile -Path $BlockedProcessLogFile
        if ($Data -is [array]) { $Log = $Data } elseif ($Data) { $Log = @($Data) }
    }
    $Log += $Entry
    Write-JsonFile -Path $BlockedProcessLogFile -Data $Log -Depth 3 | Out-Null
    Harden-ScreenTimeFile -FilePath $BlockedProcessLogFile
}

function Invoke-ChildProcessEnforcement {
    <#
        Live process enforcement guardian.
        Kills processes owned by the child account that are NOT in the ProgramWhitelist.
        Runs as SYSTEM (via scheduled task) to reliably inspect process owners.
        Hash check is performed BEFORE name checks to catch renamed executables.
        Critical Windows shell processes are protected even if not explicitly whitelisted.
    #>
    param([switch]$Continuous)
    $ChildSidValue = Get-ChildSid
    if (-not $ChildSidValue) { return }

    # Use the RestrictRun whitelist (individual executables) for the allowlist
    $Whitelist = Get-ProgramWhitelist
    if ($Whitelist.Count -eq 0) { $Whitelist = Get-DefaultProgramWhitelist }

    $BlockedHashEntries = Get-BlockedProcessHashes
    $BlockedHashStrings = @($BlockedHashEntries | Select-Object -ExpandProperty Hash | Where-Object { $_ })

    # Critical Windows shell / UWP processes that should NEVER be killed,
    # even if they are not explicitly in the whitelist (safety net)
    $CriticalProcesses = @(
        "explorer.exe",
        "StartMenuExperienceHost.exe",
        "SearchApp.exe",
        "Search.exe",
        "ShellExperienceHost.exe",
        "RuntimeBroker.exe",
        "sihost.exe",
        "dllhost.exe",
        "ApplicationFrameHost.exe",
        "SecurityHealthSystray.exe",
        "TextInputHost.exe",
        "conhost.exe",
        "taskhostw.exe",
        "ctfmon.exe",
        "LockApp.exe",
        "backgroundTaskHost.exe",
        "browser_broker.exe",
        "smartscreen.exe",
        "rundll32.exe",
        "SettingSyncHost.exe",
        "SearchIndexer.exe",
        "PresentationFontCache.exe",
        "audiodg.exe",
        "fontdrvhost.exe",
        "WMIRegistrationService.exe",
        "WmiPrvSE.exe",
        "unsecapp.exe",
        "DeviceCensus.exe",
        "CompattelRunner.exe",
        "MoUsoCoreWorker.exe",
        "UsoClient.exe",
        "TiWorker.exe",
        "ServiceShell.exe",
        "WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe",
        "MicrosoftEdge.exe",
        "MicrosoftEdgeCP.exe",
        "MicrosoftEdgeSH.exe",
        "msedgewebview2.exe",
        # Windows core system services that run in the child session (must be protected)
        "svchost.exe",
        "searchhost.exe",
        "shellhost.exe",
        "userinit.exe",
        "widgetservice.exe",
        "widgetboard.exe",
        "microsoftstartfeedprovider.exe",
        "useroobebroker.exe",
        "phoneexperiencehost.exe",
        "crossdeviceservice.exe",
        "crossdeviceresume.exe",
        "apphostregistrationverifier.exe",
        "cncmd.exe",
        "radeonsoftware.exe",
        "softlandingtask.exe"
    )

    $EndTime = if ($Continuous) { (Get-Date).AddSeconds(55) } else { (Get-Date) }

    do {
        $Processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        $Killed = 0
        foreach ($Proc in $Processes) {
            try {
                $Owner = Invoke-CimMethod -InputObject $Proc -MethodName GetOwner -ErrorAction SilentlyContinue
                if (-not $Owner -or $Owner.User -ne $ChildUser) { continue }

                # Normalize executable name
                $ExePath = $Proc.ExecutablePath
                if ($ExePath) {
                    $ExeName = [System.IO.Path]::GetFileName($ExePath).ToLower()
                } else {
                    $ExeName = ($Proc.Name -replace '\.exe$', '') + ".exe"
                    $ExeName = $ExeName.ToLower()
                }
                if ([string]::IsNullOrWhiteSpace($ExeName)) { continue }

                $CommandLine = $Proc.CommandLine
                $FileHash = $null
                $HashMatch = $false

                # 1. Hash check FIRST (catches renamed blocked tools even if whitelisted by name)
                if ($ExePath -and (Test-Path $ExePath)) {
                    $FileHash = Get-FileHashSafe -Path $ExePath
                    if ($FileHash -and ($BlockedHashStrings -contains $FileHash)) {
                        $HashMatch = $true
                    }
                }

                # Skip OS-Guard's own scheduled tasks and scripts (e.g., ChildLogon, SilentLock)
                if ($HashMatch -and $CommandLine -and ($CommandLine -like "*$InstallScript*" -or $CommandLine -like "*OS_Lockdown.ps1*")) {
                    continue
                }

                if ($HashMatch) {
                    try {
                        Stop-Process -Id $Proc.ProcessId -Force -ErrorAction Stop
                        Write-Log -Message "Process Enforcer killed unauthorized child process: $ExeName (PID $($Proc.ProcessId)) [Blocked hash match - renamed executable]" -Type "SECURITY" -Color Red
                        Write-BlockedProcessLog -ProcessName $ExeName -ProcessId $Proc.ProcessId -Path $ExePath -CommandLine $CommandLine -Hash $FileHash -Reason "Blocked hash match (renamed executable)"
                        $Killed++
                    } catch {
                        Write-Log -Message "Process Enforcer failed to kill $ExeName (PID $($Proc.ProcessId)): $_" -Type "WARN" -Color Yellow
                    }
                    continue
                }

                # 2. Allow if in whitelist
                if ($Whitelist -contains $ExeName) { continue }

                # 3. Allow if in critical process list
                if ($CriticalProcesses -contains $ExeName) { continue }

                # 4. Kill unauthorized process owned by the child
                try {
                    Stop-Process -Id $Proc.ProcessId -Force -ErrorAction Stop
                    Write-Log -Message "Process Enforcer killed unauthorized child process: $ExeName (PID $($Proc.ProcessId)) [Not in whitelist]" -Type "SECURITY" -Color Red
                    Write-BlockedProcessLog -ProcessName $ExeName -ProcessId $Proc.ProcessId -Path $ExePath -CommandLine $CommandLine -Hash $FileHash -Reason "Not in whitelist"
                    $Killed++
                } catch {
                    Write-Log -Message "Process Enforcer failed to kill $ExeName (PID $($Proc.ProcessId)): $_" -Type "WARN" -Color Yellow
                }
            } catch {}
        }

        if ($Killed -gt 0) {
            Write-Log -Message "Process Enforcer: $Killed unauthorized child process(es) terminated." -Type "SECURITY" -Color Red
        }

        if (-not $Continuous) { break }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -le $EndTime)
}

function Install-ProcessEnforcer {
    <#
        Installs a scheduled task that runs Invoke-ChildProcessEnforcement every 1 minute.
        The script loops internally every 5 seconds for 55 seconds, giving near-real-time enforcement.
        Runs as SYSTEM to reliably inspect process owners across all sessions.
        This function is idempotent: if the task already exists with correct arguments, it is left alone.
        If the task exists with outdated arguments, it is removed and re-registered.
    #>
    Write-Log -Message 'Installing Process Enforcer scheduled task (5-second continuous polling)...' -Type "INFO" -Color Yellow

    try {
        $ExpectedArg = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -ProcessEnforce -Continuous"
        $Task = Get-ScheduledTask -TaskName $ProcessEnforcerName -ErrorAction SilentlyContinue
        if ($Task) {
            $CurrentArg = $Task.Actions.Arguments
            if ($CurrentArg -eq $ExpectedArg) {
                # Task already exists with correct arguments; just ensure it is running
                $TaskInfo = Get-ScheduledTaskInfo -TaskName $ProcessEnforcerName -ErrorAction SilentlyContinue
        if ($Task.State -ne 'Running') {
                    try { Start-ScheduledTask -TaskName $ProcessEnforcerName -ErrorAction SilentlyContinue } catch {}
                    Write-Log -Message "Process Enforcer task already registered; started from idle." -Type "INFO" -Color Yellow
                } else {
                    Write-Log -Message "Process Enforcer task already registered and running." -Type "INFO" -Color Gray
                }
                return
            }
            # Outdated arguments: remove and re-register
            Write-Log -Message "Process Enforcer task arguments outdated ($CurrentArg). Re-registering..." -Type "INFO" -Color Yellow

            Remove-ProcessEnforcer
        }
        $Action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument $ExpectedArg
        $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $ProcessEnforcerName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $ProcessEnforcerName -ErrorAction SilentlyContinue
        Write-Log -Message "Process Enforcer '$ProcessEnforcerName' registered and started (1-minute heartbeat, 5-second internal polling)." -Type "SUCCESS" -Color Green

    } catch {
        Write-Log -Message "Failed to register Process Enforcer task: $_" -Type "ERROR" -Color Red
    }
}

function Remove-ProcessEnforcer {
    if (Get-ScheduledTask -TaskName $ProcessEnforcerName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $ProcessEnforcerName -Confirm:$false | Out-Null
        Write-Log -Message "Removed Process Enforcer task: $ProcessEnforcerName" -Type "INFO" -Color Gray
    }
}

function Show-ProcessEnforcerStatus {
    <#
        Shows the current status of the Process Enforcer scheduled task.
    #>
    Clear-Host
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " PROCESS ENFORCER STATUS " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    $Task = Get-ScheduledTask -TaskName $ProcessEnforcerName -ErrorAction SilentlyContinue
    if (-not $Task) {
        Write-Host '[WARN] Process Enforcer task is NOT registered.' -ForegroundColor Red

        Write-Host "       Run option [14] RUN PROCESS ENFORCER NOW or reinstall." -ForegroundColor Yellow
    } else {
        Write-Host "Task Name: $ProcessEnforcerName" -ForegroundColor Cyan
        Write-Host "State:     $($Task.State)" -ForegroundColor $(if ($Task.State -eq 'Running') { 'Green' } else { 'Yellow' })
        $TaskInfo = Get-ScheduledTaskInfo -TaskName $ProcessEnforcerName -ErrorAction SilentlyContinue
        if ($TaskInfo) {
            $LastRun = $TaskInfo | Select-Object -ExpandProperty LastRunTime -ErrorAction SilentlyContinue
            $NextRun = $TaskInfo | Select-Object -ExpandProperty NextRunTime -ErrorAction SilentlyContinue
            $LastResult = $TaskInfo | Select-Object -ExpandProperty LastTaskResult -ErrorAction SilentlyContinue
            if ($LastRun) { Write-Host "Last Run:  $LastRun" -ForegroundColor Gray }
            if ($NextRun) { Write-Host "Next Run:  $NextRun" -ForegroundColor Gray }
            if ($LastResult -ne $null) { Write-Host "Result:    $LastResult" -ForegroundColor Gray }
        }
        Write-Host "Arguments: $($Task.Actions.Arguments)" -ForegroundColor DarkGray
        Write-Host "`n[NOTE] Task runs every 1 minute with -Continuous (55s of active scanning)." -ForegroundColor Green
    }
    Write-Host "`n[ PRESS ANY KEY TO RETURN ]" -ForegroundColor DarkGray; Wait-AnyKey
}

function Test-AppLockerAvailable {
    <#
        Returns $true if AppLocker module is available and functional.
        AppLocker requires Windows Pro/Enterprise and the AppLocker feature.
    #>
    try {
        if (-not (Get-Module -ListAvailable AppLocker -ErrorAction SilentlyContinue)) { return $false }
        $Policy = Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue
        return ($null -ne $Policy)
    } catch { return $false }
}

function Get-OSGuardAppLockerPolicyXml {
    <#
        Generates a safe AppLocker policy XML that adds OS-Guard rules.
        These rules are MERGED with existing rules; they never replace them.
        Rules created:
          - Allow Windows system, Program Files, and SysWOW64
          - Deny execution from Downloads, Desktop, Temp, browser cache, and per-user install dirs
        No catch-all deny is used, so the admin is not locked out.
    #>
    # Generate real, unique GUIDs for each rule to pass AppLocker XML schema validation
    # (fake patterned GUIDs like {A1111111...} fail the GuidType pattern restriction)
    $RuleIds = @{
        AllowWindows     = [System.Guid]::NewGuid().ToString("D").ToUpper()
        AllowProgFiles   = [System.Guid]::NewGuid().ToString("D").ToUpper()
        AllowProgFiles86 = [System.Guid]::NewGuid().ToString("D").ToUpper()
        AllowSysWOW64    = [System.Guid]::NewGuid().ToString("D").ToUpper()
        DenyDownloads    = [System.Guid]::NewGuid().ToString("D").ToUpper()
        DenyDesktop      = [System.Guid]::NewGuid().ToString("D").ToUpper()
        DenyTemp         = [System.Guid]::NewGuid().ToString("D").ToUpper()
        DenyLocalTemp    = [System.Guid]::NewGuid().ToString("D").ToUpper()
        DenyInetCache    = [System.Guid]::NewGuid().ToString("D").ToUpper()
        DenyLocalPrograms= [System.Guid]::NewGuid().ToString("D").ToUpper()
    }

    $Xml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="$($RuleIds.AllowWindows)" Name="OSGuard: Allow Windows" Description="Windows system files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$($RuleIds.AllowProgFiles)" Name="OSGuard: Allow Program Files" Description="64-bit installed applications" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$($RuleIds.AllowProgFiles86)" Name="OSGuard: Allow Program Files (x86)" Description="32-bit installed applications" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES(X86)%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$($RuleIds.AllowSysWOW64)" Name="OSGuard: Allow SysWOW64" Description="32-bit system files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$($RuleIds.DenyDownloads)" Name="OSGuard: Deny Downloads" Description="Block execution from Downloads folder" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Downloads\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$($RuleIds.DenyDesktop)" Name="OSGuard: Deny Desktop" Description="Block execution from Desktop" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Desktop\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$($RuleIds.DenyTemp)" Name="OSGuard: Deny Temp" Description="Block execution from Temp folders" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%TEMP%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$($RuleIds.DenyLocalTemp)" Name="OSGuard: Deny LocalAppData Temp" Description="Block execution from local temp" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Temp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$($RuleIds.DenyInetCache)" Name="OSGuard: Deny INetCache" Description="Block execution from browser cache" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Microsoft\Windows\INetCache\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$($RuleIds.DenyLocalPrograms)" Name="OSGuard: Deny Local Programs" Description="Block execution from per-user install dirs" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Programs\*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@
    return $Xml
}

function Enable-AppLockerChildPolicy {
    <#
        Applies OS-Guard AppLocker rules as a MERGED layer on top of any existing policy.
        Only runs if AppLocker is available (Pro/Enterprise).
        Safe: no catch-all deny, so admins are never fully locked out.
    #>
    if (-not (Test-AppLockerAvailable)) {
        Write-Log -Message "AppLocker not available (requires Pro/Enterprise). Skipping AppLocker layer." -Type "INFO" -Color Gray
        return
    }
    Write-Log -Message "Applying AppLocker layer (Downloads, Desktop, Temp, cache blocks)..." -Type "INFO" -Color Yellow
    try {
        $XmlContent = Get-OSGuardAppLockerPolicyXml
        $TempFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "OSGuard_AppLocker_$(Get-Random).xml")
        Set-Content -Path $TempFile -Value $XmlContent -Encoding UTF8 -Force -ErrorAction Stop
        Set-AppLockerPolicy -XmlPolicy $TempFile -Merge -ErrorAction Stop
        Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue
        Write-Log -Message "AppLocker layer applied successfully." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to apply AppLocker layer: $_" -Type "WARN" -Color Yellow
    }
}

function Disable-AppLockerChildPolicy {
    <#
        Removes only OS-Guard rules from the AppLocker policy, preserving any other rules.
    #>
    if (-not (Test-AppLockerAvailable)) { return }
    Write-Log -Message "Removing AppLocker layer..." -Type "INFO" -Color Yellow
    try {
        $TempFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "OSGuard_AppLocker_Current_$(Get-Random).xml")
        Get-AppLockerPolicy -Local -Xml | Out-File -FilePath $TempFile -Encoding UTF8 -Force -ErrorAction Stop
        [xml]$Doc = Get-Content -Path $TempFile -Raw -ErrorAction Stop
        $Collections = $null
        if ($Doc.AppLockerPolicy -and $Doc.AppLockerPolicy.RuleCollection) {
            $Collections = $Doc.AppLockerPolicy.RuleCollection
        }
        if ($Collections) {
            foreach ($Collection in $Collections) {
                if (-not $Collection) { continue }
                $RulesToRemove = $Collection.FilePathRule | Where-Object { $_.Name -like "OSGuard:*" }
                foreach ($Rule in $RulesToRemove) {
                    $Collection.RemoveChild($Rule) | Out-Null
                }
            }
        }
        $CleanFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "OSGuard_AppLocker_Clean_$(Get-Random).xml")
        $Doc.Save($CleanFile)
        Set-AppLockerPolicy -XmlPolicy $CleanFile -ErrorAction Stop
        Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $CleanFile -Force -ErrorAction SilentlyContinue
        Write-Log -Message "AppLocker layer removed successfully." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to remove AppLocker layer: $_" -Type "WARN" -Color Yellow
    }
}

function Clear-AllAppLockerAndSRP {
    <#
        Nuclear cleanup: completely removes AppLocker and Software Restriction Policies.
        This is called during uninstall and disable to ensure the admin is never blocked.
    #>
    $Fixed = @()
    $Skipped = @()

    # 1. Disable and stop AppLocker service
    $svc = Get-Service -Name 'AppIDSvc' -ErrorAction SilentlyContinue
    if ($svc) {
        try {
            Stop-Service -Name 'AppIDSvc' -Force -ErrorAction SilentlyContinue
            Set-Service -Name 'AppIDSvc' -StartupType Disabled -ErrorAction SilentlyContinue
            $Fixed += 'Disabled AppIDSvc service'
        } catch {
            $Skipped += ('Could not disable AppIDSvc: ' + $_.Exception.Message)
        }
    }

    # 2. Clear AppLocker policy via empty XML
    if (Get-Module -ListAvailable AppLocker -ErrorAction SilentlyContinue) {
        try {
            $EmptyXml = '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /><RuleCollection Type="Dll" EnforcementMode="NotConfigured" /><RuleCollection Type="Script" EnforcementMode="NotConfigured" /><RuleCollection Type="Msi" EnforcementMode="NotConfigured" /><RuleCollection Type="Appx" EnforcementMode="NotConfigured" /></AppLockerPolicy>'
            $TempFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'OSGuard_ClearAppLocker_' + (Get-Random) + '.xml')
            Set-Content -Path $TempFile -Value $EmptyXml -Encoding UTF8 -Force -ErrorAction Stop
            Set-AppLockerPolicy -XmlPolicy $TempFile -ErrorAction Stop
            Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue
            $Fixed += 'Cleared AppLocker policy'
        } catch {
            $Skipped += ('Could not clear AppLocker policy: ' + $_.Exception.Message)
        }
    }

    # 3. Remove SrpV2 registry keys
    $SrpV2Roots = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2',
        'HKLM:\SOFTWARE\Microsoft\Windows\SrpV2',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\SrpV2',
        'HKCU:\SOFTWARE\Microsoft\Windows\SrpV2'
    )
    foreach ($Root in $SrpV2Roots) {
        if (Test-Path $Root) {
            try {
                Remove-Item -Path $Root -Recurse -Force -ErrorAction Stop
                $Fixed += ('Removed ' + $Root)
            } catch {
                $Skipped += ('Failed to remove ' + $Root + ': ' + $_.Exception.Message)
            }
        }
    }

    # 4. Remove Software Restriction Policies
    $SrpRoots = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
    )
    foreach ($Root in $SrpRoots) {
        if (Test-Path $Root) {
            try {
                Remove-Item -Path $Root -Recurse -Force -ErrorAction Stop
                $Fixed += ('Removed ' + $Root)
            } catch {
                $Skipped += ('Failed to remove ' + $Root + ': ' + $_.Exception.Message)
            }
        }
    }

    # 5. Remove GPO cache files
    $GpFiles = @(
        'C:\Windows\System32\GroupPolicy\Machine\Registry.pol',
        'C:\Windows\System32\GroupPolicy\User\Registry.pol'
    )
    foreach ($File in $GpFiles) {
        if (Test-Path $File) {
            try {
                Remove-Item -Path $File -Force -ErrorAction Stop
                $Fixed += ('Removed GPO cache: ' + $File)
            } catch {
                $Skipped += ('Failed to remove GPO cache: ' + $File)
            }
        }
    }
    $GpUserDirs = Get-ChildItem -Path 'C:\Windows\System32\GroupPolicyUsers' -ErrorAction SilentlyContinue
    foreach ($Dir in $GpUserDirs) {
        $RegPol = Join-Path $Dir.FullName 'User\Registry.pol'
        if (Test-Path $RegPol) {
            try {
                Remove-Item -Path $RegPol -Force -ErrorAction Stop
                $Fixed += ('Removed GPO user cache: ' + $RegPol)
            } catch {
                $Skipped += ('Failed to remove GPO user cache: ' + $RegPol)
            }
        }
    }

    # 6. Remove AppLocker cache files
    $AppLockerCaches = @(
        'C:\Windows\System32\AppLocker\Policy.v2',
        'C:\Windows\System32\AppLocker\MSI Policy.v2',
        'C:\Windows\System32\AppLocker\Script Policy.v2',
        'C:\Windows\System32\AppLocker\Packaged App Policy.v2'
    )
    foreach ($File in $AppLockerCaches) {
        if (Test-Path $File) {
            try {
                Remove-Item -Path $File -Force -ErrorAction Stop
                $Fixed += ('Removed AppLocker cache: ' + $File)
            } catch {
                $Skipped += ('Failed to remove AppLocker cache: ' + $File)
            }
        }
    }

    # 7. Run gpupdate to clear cached policies
    try {
        $gpResult = Start-Process -FilePath 'gpupdate.exe' -ArgumentList '/force' -Wait -WindowStyle Hidden -PassThru
        if ($gpResult.ExitCode -eq 0) {
            $Fixed += 'Group Policy refreshed'
        } else {
            $Skipped += ('gpupdate exit code: ' + $gpResult.ExitCode)
        }
    } catch {
        $Skipped += ('gpupdate failed: ' + $_.Exception.Message)
    }

    # 8. Restart AppIDSvc to force policy reload
    try {
        Start-Service -Name 'AppIDSvc' -ErrorAction SilentlyContinue
        $Fixed += 'Restarted AppIDSvc'
    } catch {
        $Skipped += ('Could not restart AppIDSvc: ' + $_.Exception.Message)
    }

    foreach ($f in $Fixed) { Write-Log -Message ('[AppLocker/SRP Clear] ' + $f) -Type 'INFO' -Color Gray }
    foreach ($s in $Skipped) { Write-Log -Message ('[AppLocker/SRP Clear] ' + $s) -Type 'WARN' -Color Yellow }
}

function Get-AppLockerChildStatus {
    <#
        Returns $true if any OS-Guard AppLocker rules are present in the local policy.
    #>
    if (-not (Test-AppLockerAvailable)) { return $false }
    try {
        $Policy = Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue
        if (-not $Policy) { return $false }
        foreach ($Collection in $Policy.RuleCollections) {
            # Some AppLocker versions nest rules under .Rules; others make the collection directly enumerable
            $Rules = @()
            if ($Collection.Rules) { $Rules = $Collection.Rules }
            elseif ($Collection.GetEnumerator) { $Rules = $Collection }
            foreach ($Rule in $Rules) {
                if ($Rule.Name -like "OSGuard:*") { return $true }
            }
        }
        return $false
    } catch { return $false }
}

function Show-BlockedProcessReview {
    <#
        Interactive CLI to review processes killed by the Process Enforcer.
        Shows command line, hash, and allows one-click approval to whitelist.
    #>
    do {
        Clear-Host
        Write-Host "`n=====================================================" -ForegroundColor Cyan
        Write-Host " REVIEW BLOCKED PROCESSES " -ForegroundColor Cyan
        Write-Host "=====================================================" -ForegroundColor Cyan
    if (-not (Test-Path $BlockedProcessLogFile)) {
            Write-Host "`n[INFO] No blocked processes recorded." -ForegroundColor Gray
            Write-Host "`n[ PRESS ANY KEY TO RETURN ]" -ForegroundColor DarkGray; Wait-AnyKey
            return
        }
        $Recent = $null
        try {
            $Log = Get-Content -Path $BlockedProcessLogFile -Raw | ConvertFrom-Json
            if ($Log.Count -eq 0) {
                Write-Host "`n[INFO] No blocked processes recorded." -ForegroundColor Gray
            } else {
                Write-Host "`n=== Recently Blocked Processes (last 20) ===" -ForegroundColor Cyan
                $Recent = $Log | Select-Object -Last 20
                $i = 1
                foreach ($Entry in $Recent) {
                    Write-Host "[$i] $($Entry.Timestamp) | $($Entry.ProcessName) (PID $($Entry.ProcessId)) | $($Entry.Reason)" -ForegroundColor Red
                    if ($Entry.Hash) { Write-Host "    Hash: $($Entry.Hash)" -ForegroundColor DarkGray }
                    if ($Entry.CommandLine) { Write-Host "    Cmd:  $($Entry.CommandLine)" -ForegroundColor DarkGray }
                    $i++
                }
                Write-Host "`n[A] Approve a process to whitelist (enter number)" -ForegroundColor Green
                Write-Host '[C] Clear log' -ForegroundColor Yellow

            }
        } catch {
            Write-Host "Could not read blocked process log." -ForegroundColor Red
        }
        Write-Host '[Q] Return' -ForegroundColor Gray

        $Choice = (Read-Host "`nSelect action").ToUpper()
        if ($Choice -eq "Q") { return }
        if ($Choice -eq "C") {
            try { Remove-Item -Path $BlockedProcessLogFile -Force -ErrorAction SilentlyContinue } catch {}
            Write-Host '[SUCCESS] Blocked process log cleared.' -ForegroundColor Green

            Write-Host "`n[ PRESS ANY KEY TO CONTINUE ]" -ForegroundColor DarkGray; Wait-AnyKey
        }
        elseif ($Choice -eq "A" -and $Recent) {
            $Num = Read-Host "Enter process number to approve"
            if ($Num -match "^\d+$") {
                $Idx = [int]$Num - 1
                if ($Idx -ge 0 -and $Idx -lt $Recent.Count) {
                    $Selected = $Recent[$Idx]
                    $Whitelist = Get-ProgramWhitelist
                    if ($Whitelist.Count -eq 0) { $Whitelist = Get-DefaultProgramWhitelist }
                    $ExeName = $Selected.ProcessName
                    if ($Whitelist -notcontains $ExeName) {
                        $Whitelist += $ExeName
                        Set-ProgramWhitelist -List $Whitelist
                        Write-Host "`[SUCCESS] Added '$ExeName' to whitelist." -ForegroundColor Green

                    } else {
                        Write-Host "`[INFO] '$ExeName' is already in the whitelist." -ForegroundColor Gray

                    }
                } else {
                    Write-Host '[ERROR] Invalid number.' -ForegroundColor Red

                }
            }
            Write-Host "`n[ PRESS ANY KEY TO CONTINUE ]" -ForegroundColor DarkGray; Wait-AnyKey
        }
    } while ($true)
}

function Harden-ChildInstallDirectories {
    <#
        Proactively hardens per-user install directories in the child profile
        so the child cannot install software even when Parent Mode is active.
        Hardens AppData\Local\Programs with ReadAndExecute only for the child.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { return }

    $InstallPaths = @(
        (Join-Path $ChildProfilePath "AppData\Local\Programs")
    )

    $ChildSidValue = Get-ChildSid
    if (-not $ChildSidValue) { return }
    $ChildSidObj = New-Object System.Security.Principal.SecurityIdentifier($ChildSidValue)

    foreach ($Path in $InstallPaths) {
        if (-not (Test-Path $Path)) {
            try { New-Item -ItemType Directory -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null } catch { continue }
        }
        try {
            $Acl = Get-Acl -Path $Path
            $Acl.SetOwner($SidSystem)
            $Acl.SetAccessRuleProtection($true, $false)

            $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }

            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $SidAdmin, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ChildSidObj, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ChildSidObj, "Modify", "ContainerInherit,ObjectInherit", "None", "Deny")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ChildSidObj, "Write", "ContainerInherit,ObjectInherit", "None", "Deny")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ChildSidObj, "Delete", "ContainerInherit,ObjectInherit", "None", "Deny")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ChildSidObj, "CreateFiles", "ContainerInherit,ObjectInherit", "None", "Deny")))

            Set-Acl -Path $Path -AclObject $Acl -ErrorAction Stop
            Write-Log -Message "Child install directory hardened: $Path" -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to harden child install directory $Path`: $_" -Type "WARN" -Color Yellow
        }
    }
}

function Remove-ChildInstallDirectoryHardening {
    <#
        Resets ACLs on the child's per-user install directories back to inherited defaults.
        Used during Disable-OSLock / Uninstall.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { return }

    $InstallPaths = @(
        (Join-Path $ChildProfilePath "AppData\Local\Programs")
    )

    foreach ($Path in $InstallPaths) {
        if (-not (Test-Path $Path)) { continue }
        try {
            & icacls.exe $Path /reset /T /C 2>&1 | Out-Null
            Write-Log -Message "Child install directory ACLs reset: $Path" -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to reset ACLs on $Path`: $_" -Type "WARN" -Color Yellow
        }
    }
}

function Approve-ChildInstall {
    <#
        Prompts for the Parent Mode password and temporarily relaxes ACLs on the
        child's per-user install directories so the admin can install software.
        After 15 minutes, a scheduled task re-hardens the directories.
    #>
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " APPROVE CHILD SOFTWARE INSTALL (ADMIN ONLY) " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan

    if (-not (Test-ParentPassword)) { return }

    Write-Log -Message "Admin approved child software installation. Relaxing install directory ACLs..." -Type "ACTION" -Color Magenta

    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) {
        Write-Host '[ERROR] Could not locate child profile path.' -ForegroundColor Red

        return
    }

    $InstallPaths = @(
        (Join-Path $ChildProfilePath "AppData\Local\Programs")
    )

    foreach ($Path in $InstallPaths) {
        if (-not (Test-Path $Path)) { continue }
        try {
            $Acl = Get-Acl -Path $Path
            $ChildSidValue = Get-ChildSid
            if ($ChildSidValue) {
                $RulesToRemove = $Acl.Access | Where-Object {
                    try {
                        $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                        $sid.Value -eq $ChildSidValue -and $_.AccessControlType -eq "Deny"
                    } catch { $false }
                }
                foreach ($Rule in $RulesToRemove) { $Acl.RemoveAccessRule($Rule) | Out-Null }
            }
            $Acl.SetOwner($SidAdmin)
            Set-Acl -Path $Path -AclObject $Acl -ErrorAction Stop
            Write-Log -Message "Relaxed install directory ACLs: $Path" -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to relax ACLs on $Path`: $_" -Type "WARN" -Color Yellow
        }
    }

    try {
        $RehardenAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -RehardenChildInstall"
        $RehardenTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(15)
        $RehardenPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "OSGuard-ApproveInstallReharden" -Action $RehardenAction -Trigger $RehardenTrigger -Principal $RehardenPrincipal -Force | Out-Null
        Write-Log -Message "Scheduled re-hardening task for 15 minutes from now." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to schedule re-hardening task: $_" -Type "WARN" -Color Yellow
    }

    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    [System.Windows.Forms.MessageBox]::Show("Install approval active for 15 minutes.`n`nYou can now install software to the child account.`n`nACLs will be automatically re-hardened after 15 minutes.", "Install Approval", "OK", "Information") | Out-Null
    Write-Host '[SUCCESS] Install approval active for 15 minutes.' -ForegroundColor Green

}

function Invoke-ChildInstallReharden {
    <#
        Re-hardens child install directories after an approval period.
        Called by the scheduled task created by Approve-ChildInstall.
    #>
    Write-Log -Message "Re-hardening child install directories after approval period..." -Type "ACTION" -Color Magenta
    Harden-ChildInstallDirectories
    Scan-And-Harden-ChildPrograms

    # LOCKBACK: If Parent Mode is still active, force re-lock the system
    $ParentModeActive = $false
    try { $ParentModeActive = (Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "OSGuardParentModeActive" -ErrorAction SilentlyContinue) -eq 1 } catch {}
    if ($ParentModeActive) {
        Write-Log -Message "Lockback triggered: Install approval window expired. Re-locking system..." -Type "SECURITY" -Color Red
        try { Stop-WindowGuard } catch { Write-Log -Message "Stop-WindowGuard failed during lockback: $_" -Type "WARN" -Color Yellow }
        Remove-ParentModeAdminTools
        try {
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
        } catch {}
        Enable-OSLock
        Enable-DNSLock

        Write-Log -Message "Lockback complete: System re-locked after install approval expired." -Type "SUCCESS" -Color Green
    }

    if (Get-ScheduledTask -TaskName "OSGuard-ApproveInstallReharden" -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName "OSGuard-ApproveInstallReharden" -Confirm:$false | Out-Null
        Write-Log -Message "Removed re-hardening scheduled task." -Type "INFO" -Color Gray
    }
}

function Install-ProgramGuardian {
    <#
        Installs the OSGuard-ProgramScanner scheduled task (10-minute heartbeat).
        This task scans the child profile for new programs and hardens them automatically.
    #>
    Write-Log -Message "Installing Program Guardian scheduled task..." -Type "INFO" -Color Yellow
    try {
        $ScanAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -ProgramScan"
        $ScanTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 9999)
        $ScanPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $ProgramScannerName -Action $ScanAction -Trigger $ScanTrigger -Principal $ScanPrincipal -Force | Out-Null
        Write-Log -Message "Program Guardian '$ProgramScannerName' registered `(10-minute heartbeat)." -Type "SUCCESS" -Color Green

    } catch {
        Write-Log -Message "Failed to register Program Guardian task: $_" -Type "ERROR" -Color Red
    }
}

function Remove-ProgramGuardian {
    if (Get-ScheduledTask -TaskName $ProgramScannerName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $ProgramScannerName -Confirm:$false | Out-Null
        Write-Log -Message "Removed Program Guardian task: $ProgramScannerName" -Type "INFO" -Color Gray
    }
}

function Apply-OOBEBlock {
    <#
        Applies OOBE (Out-of-Box Experience) block policies machine-wide.
        These are intentionally separate from $MachinePolicies so they survive
        Disable-OSLock / Enter-ParentMode. Only removed during full uninstall.
    #>
    Write-Log -Message "Applying OOBE block (first-logon animation + privacy experience disabled)..." -Type "INFO" -Color Yellow
    foreach ($Policy in $OOBEBlockPolicies) {
        try {
            if (-not (Test-Path $Policy.Path)) {
                New-Item -Path $Policy.Path -Force -ErrorAction SilentlyContinue | Out-Null
            }
            $PropType = if ($Policy.Value -is [string]) { "String" } else { "DWord" }
            Set-ItemProperty -Path $Policy.Path -Name $Policy.Name -Value $Policy.Value -Type $PropType -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log -Message "Failed to set OOBE policy $($Policy.Name) at $($Policy.Path): $_" -Type "WARN" -Color Yellow
        }
    }
    Write-Log -Message "OOBE block enforced." -Type "SUCCESS" -Color Green
}

function Remove-OOBEBlock {
    <#
        Removes OOBE block policies. Called ONLY during full uninstall so the child
        account returns to a normal first-logon experience.
    #>
    Write-Log -Message "Removing OOBE block policies..." -Type "INFO" -Color Yellow
    foreach ($Policy in $OOBEBlockPolicies) {
        try {
            if (Test-Path $Policy.Path) {
                Remove-ItemProperty -Path $Policy.Path -Name $Policy.Name -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    Write-Log -Message "OOBE block removed." -Type "SUCCESS" -Color Green
}

function Apply-MachinePolicies {
    Write-Log -Message "Applying machine-wide OS policies (UAC max, Installer block)..." -Type "INFO" -Color Yellow
    foreach ($Policy in $MachinePolicies) {
        try {
            if (-not (Test-Path $Policy.Path)) {
                New-Item -Path $Policy.Path -Force -ErrorAction SilentlyContinue | Out-Null
            }
            $PropType = if ($Policy.Value -is [string]) { "String" } else { "DWord" }
            Set-ItemProperty -Path $Policy.Path -Name $Policy.Name -Value $Policy.Value -Type $PropType -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log -Message "Failed to set machine policy $($Policy.Name) at $($Policy.Path): $_" -Type "WARN" -Color Yellow
        }
    }
    Write-Log -Message "Machine-wide OS policies enforced." -Type "SUCCESS" -Color Green
}

function Remove-MachinePolicies {
    Write-Log -Message "Removing machine-wide OS policies..." -Type "INFO" -Color Yellow
    foreach ($Policy in $MachinePolicies) {
        try {
            if (Test-Path $Policy.Path) {
                Remove-ItemProperty -Path $Policy.Path -Name $Policy.Name -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    # Remove legacy machine-wide policies that are now applied child-only or have been removed
    $LegacyPolicies = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DisableWindowsUpdateAccess" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "DisableNotificationCenter" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsConsumerFeatures" },
        # Removed in recent versions (too restrictive for normal users)
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "AutoDownload" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "DisableStoreApps" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "RemoveWindowsStore" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableSmartScreen" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "ShellSmartScreenLevel" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "HideFastUserSwitching" },
        # Removed in recent versions (machine-wide MSI blocks prevent admin installs)
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name = "DisableMSI" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name = "DisableUserInstalls" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name = "DisableUserInstallsViaModifications" }
    )
    foreach ($Policy in $LegacyPolicies) {
        try {
            if (Test-Path $Policy.Path) {
                Remove-ItemProperty -Path $Policy.Path -Name $Policy.Name -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    # Restore UAC to a sane default (prompt for non-Windows binaries) instead of leaving blank
    try {
        $UacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $UacPath -Name "EnableLUA" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $UacPath -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $UacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    } catch {}
    # Re-enable USB storage service
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue
        Start-Service -Name "USBSTOR" -ErrorAction SilentlyContinue
        Write-Log -Message "USB storage service restored to Manual (Start=3)." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Could not restore USBSTOR service: $_" -Type "WARN" -Color Yellow
    }
    # Re-enable Windows Script Host (WSH) if it was disabled
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Windows Script Host re-enabled." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Could not re-enable Windows Script Host: $_" -Type "WARN" -Color Yellow
    }
    # NOTE: OOBE block policies are intentionally NOT removed here.
    # They survive Disable-OSLock / Enter-ParentMode so the child never gets the OOBE popup.
    # Remove-OOBEBlock is called only during full uninstall.
    Write-Log -Message "Machine-wide OS policies removed (UAC restored to default). OOBE block preserved." -Type "SUCCESS" -Color Green
}

function Enable-OSLock {
    Write-Log -Message "Initiating OS Child Lockdown..." -Type "ACTION" -Color Magenta

    if (-not $SilentLock) {
        $IntegrityCheck = Test-IntegrityStatus
        if ($IntegrityCheck -eq $false) {
            Write-Log -Message "Action blocked: script integrity failure before Enable-OSLock." -Type "SECURITY" -Color Red
            Write-Host '[BLOCKED] Tamper detected. Use uninstall and reinstall.' -ForegroundColor Red -BackgroundColor Black

            return
        }
    }

    # Clear any temporary unlock flags when re-locking
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
    } catch {}

    Stop-TempUnlockTimer

    # 1. Ensure child account exists and is a standard user (passwordless)
    New-ChildAccount | Out-Null

    # 1a. Disable auto-admin logon so the system never bypasses the login screen
    Disable-AutoAdminLogon

    # 2. Machine-wide policies (UAC maxed)
    Apply-MachinePolicies

    # 2a. OOBE block (child never sees first-logon animation / privacy experience)
    Apply-OOBEBlock

    # 3. Per-user policies on the child's offline hive
    $HiveMount = Mount-ChildHive
    if ($HiveMount) {
        Apply-ChildHivePolicies -HiveMount $HiveMount -Policies $ChildBasePolicies
        Apply-ChildHivePolicies -HiveMount $HiveMount -Policies $ChildDisallowRunPolicies
        Write-Log -Message "Child hive policies applied to '$ChildUser' (offline)." -Type "SUCCESS" -Color Green
        Dismount-ChildHive -HiveMount $HiveMount
    } else {
        Write-Log -Message "Child hive not available - policies will apply at next child logon via ChildLogon task." -Type "WARN" -Color Yellow
    }

    # 3.0 Seed policies into the Default profile so first-logon profiles inherit restrictions
    Apply-ChildPoliciesToDefaultProfile
    # Also apply to live session if child is currently logged in
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        Apply-ChildHivePolicies -HiveMount $ChildSidValue -Policies $ChildBasePolicies
        Apply-ChildHivePolicies -HiveMount $ChildSidValue -Policies $ChildDisallowRunPolicies
        Write-Log -Message "Child hive policies applied to '$ChildUser' (live session)." -Type "SUCCESS" -Color Green
    }

    # Force child StartMenuExperienceHost / ShellExperienceHost to restart so NoLogOff policy is picked up
    Restart-ChildShell

    # 3a. Apply RestrictRun whitelist to offline and live hives
    $HiveMount = Mount-ChildHive
    if ($HiveMount) {
        Apply-RestrictRunPolicies -HiveMount $HiveMount
        Dismount-ChildHive -HiveMount $HiveMount
    }
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        Apply-RestrictRunPolicies -HiveMount $ChildSidValue
    }

    # 3b. Install child-only USB guardian
    Install-ChildUSBGuard

    # 4. Block password change at the account level (belt and suspenders)
    net user $ChildUser /passwordchg:no 2>&1 | Out-Null
    net user $ChildUser /passwordreq:no 2>&1 | Out-Null

    New-BrowserLauncher

    # Apply Edge policies to the child hive (offline + live session)
    $HiveMount = Mount-ChildHive
    if ($HiveMount) {
        Apply-EdgePolicies -HiveMount $HiveMount
        Dismount-ChildHive -HiveMount $HiveMount
    }
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        Apply-EdgePolicies -HiveMount $ChildSidValue
    }

    # Program Guardian: scan and harden any newly installed programs immediately
    Scan-And-Harden-ChildPrograms

    # Initialize blocked hash database (catches renamed dangerous executables)
    Initialize-BlockedProcessHashes

    # Process Enforcer: immediate kill of unauthorized child processes
    Invoke-ChildProcessEnforcement

    # Ensure the continuous Process Enforcer task is registered and running immediately
    Install-ProcessEnforcer

    # Harden per-user install directories so child cannot install even in Parent Mode
    Harden-ChildInstallDirectories

    # Clear cache before resolving the child profile so we don't target a stale folder
    Clear-ChildCache
    # Child-facing shortcuts are created at child logon by the ChildLogonTask.
    # Only create them proactively at install time if the child profile already exists.
    if (-not $SilentLock) {
        $InstallChildProfilePath = Get-ChildProfilePath
        if ($InstallChildProfilePath) {
            Set-ChildLogoutShortcut
            New-ChildGameRequestShortcut
            New-BrowserRequestShortcut
            New-AdminRequestShortcut
            New-ChildLockNowShortcut
            New-ChildContinueParentModeShortcut
            New-ChildApproveInstallShortcut
        } else {
            Write-Log -Message "Child profile not found yet - shortcuts will be created at first child logon." -Type "INFO" -Color Gray
        }
    }

    Write-Log -Message "OS Child Lockdown deployed." -Type "SUCCESS" -Color Green

    # Verification
    $FailedCount = 0
    foreach ($Policy in $MachinePolicies) {
        try {
            $Val = Get-ItemProperty -Path $Policy.Path -Name $Policy.Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Policy.Name -ErrorAction SilentlyContinue
            if ($Val -ne $Policy.Value) { $FailedCount++; Write-Log -Message "Machine policy $($Policy.Name) not enforced (got $Val)." -Type "ERROR" -Color Red }
        } catch { $FailedCount++ }
    }
    $ChildExists = Get-ChildAccount
    if (-not $ChildExists) { $FailedCount++; Write-Log -Message "Child account '$ChildUser' missing." -Type "ERROR" -Color Red }
    else {
        # Verify not an administrator
        try {
            $IsAdmin = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Where-Object { $_.Name -match "$ChildUser$" }
            if ($IsAdmin) { $FailedCount++; Write-Log -Message "Child '$ChildUser' is still an administrator!" -Type "ERROR" -Color Red }
        } catch {}
    }
    # Verify child shortcuts (only if child profile exists; may not exist before first login)
    $VerifyChildProfilePath = Get-ChildProfilePath
    if (-not $VerifyChildProfilePath) { $VerifyChildProfilePath = "C:\Users\$ChildUser" }
    $ChildSidValue = Get-ChildSid
    $ChildDesktopPath = Join-Path $VerifyChildProfilePath "Desktop"
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue") -and (Test-Path $ChildDesktopPath)) {
        $ExpectedShortcuts = @(
            "Log out.lnk",
            "Request Game Install.lnk",
            "Browser Request.lnk",
            "Admin Request.lnk"
        )
        foreach ($ScName in $ExpectedShortcuts) {
            $ScPath = Join-Path $ChildDesktopPath $ScName
            if (-not (Test-Path $ScPath)) {
                $FailedCount++; Write-Log -Message "Shortcut '$ScName' for '$ChildUser' not found." -Type "ERROR" -Color Red
            }
        }
    } elseif (-not (Test-Path $ChildDesktopPath)) {
        Write-Log -Message "Child desktop not found yet - shortcuts will be verified at first child logon." -Type "INFO" -Color Gray
    }

    # Verify child hive policies (sample check on live or offline hive)
    $VerifyHive = $null
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        $VerifyHive = $ChildSidValue
    } else {
        $VerifyHive = Mount-ChildHive
    }
    if ($VerifyHive) {
        $SamplePath = "Registry::HKEY_USERS\$VerifyHive\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $SampleTaskMgr = Get-ItemProperty -Path $SamplePath -Name "DisableTaskMgr" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableTaskMgr" -ErrorAction SilentlyContinue
        $SampleRegedit = Get-ItemProperty -Path $SamplePath -Name "DisableRegistryTools" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableRegistryTools" -ErrorAction SilentlyContinue
        if ($SampleTaskMgr -ne 1) { $FailedCount++; Write-Log -Message "Child hive policy DisableTaskMgr not enforced (got $SampleTaskMgr)." -Type "ERROR" -Color Red }
        if ($SampleRegedit -ne 1) { $FailedCount++; Write-Log -Message "Child hive policy DisableRegistryTools not enforced (got $SampleRegedit)." -Type "ERROR" -Color Red }

        # Verify RestrictRun whitelist
        $ExplorerPath = "Registry::HKEY_USERS\$VerifyHive\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        $RestrictRunVal = Get-ItemProperty -Path $ExplorerPath -Name "RestrictRun" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "RestrictRun" -ErrorAction SilentlyContinue
        if ($RestrictRunVal -ne 1) { $FailedCount++; Write-Log -Message "Child hive RestrictRun not enabled (got $RestrictRunVal)." -Type "ERROR" -Color Red }

        # Verify Edge policies sample
        $EdgePolicyPath = "Registry::HKEY_USERS\$VerifyHive\Software\Policies\Microsoft\Edge"
        $EdgeGuestMode = Get-ItemProperty -Path $EdgePolicyPath -Name "BrowserGuestModeEnabled" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "BrowserGuestModeEnabled" -ErrorAction SilentlyContinue
        if ($EdgeGuestMode -ne 0) { $FailedCount++; Write-Log -Message "Child hive Edge BrowserGuestModeEnabled not enforced (got $EdgeGuestMode)." -Type "ERROR" -Color Red }

        if ($VerifyHive -ne $ChildSidValue) { Dismount-ChildHive -HiveMount $VerifyHive }
    } else {
        Write-Log -Message "Child hive not mountable for verification - will verify at next child logon." -Type "WARN" -Color Yellow
    }

    if ($FailedCount -eq 0) {
        if (-not $SilentLock) { Write-Host "[SUCCESS] ALL OS LOCKS DEPLOYED!" -ForegroundColor Green }
    } else {
        if (-not $SilentLock) { Write-Host "[PARTIAL] OS LOCKS DEPLOYED WITH ERRORS! ($FailedCount items failed)" -ForegroundColor Yellow }
    }
}

function Disable-OSLock {
    param(
        [switch]$KeepChildAccount,
        [switch]$SetTempUnlockFlag,
        [switch]$NoDisallowRunFallback
    )
    Write-Log -Message "Initiating OS Child Lockdown removal..." -Type "ACTION" -Color Magenta

    if (-not $SilentLock) {
        $IntegrityCheck = Test-IntegrityStatus
        if ($IntegrityCheck -eq $false) {
            Write-Log -Message "Action blocked: script integrity failure before Disable-OSLock." -Type "SECURITY" -Color Red
            Write-Host '[BLOCKED] Tamper detected. Use uninstall and reinstall.' -ForegroundColor Red -BackgroundColor Black

            return
        }
    }

    # 1. Remove machine-wide policies
    # NOTE: These policies apply to ALL users (no per-user equivalent). Removing them opens the entire system.
    Write-Log -Message "WARNING: Machine-wide OS policies are being removed. This affects ALL users including the admin." -Type "WARN" -Color Yellow
    Remove-MachinePolicies

    # Warn that guardian tasks will re-apply locks soon unless uninstalled
    if (-not $SilentLock) {
        Write-Host '[WARNING] Guardian tasks (5/10 min heartbeat) will re-apply locks soon.' -ForegroundColor Yellow

        Write-Host "          Use option [4] UNINSTALL to permanently remove protection." -ForegroundColor Yellow
    }

    # Clear Parent Mode flags so the AFK watcher doesn't trigger after unlock
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
    } catch {}

    # Set temporary unlock flag if requested (prevents guardian re-lock)
    if ($SetTempUnlockFlag -and -not $SilentLock) {
        try {
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -Value 1 -Type DWord -Force -ErrorAction Stop
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -Value (Get-Date -Format "o") -Type String -Force -ErrorAction Stop
        } catch {
            Write-Log -Message "Failed to set temp unlock flag: $_" -Type "WARN" -Color Yellow
        }
    }

    if (-not $KeepChildAccount) {
        # 2. Remove per-user policies from the child's live and offline hives
        $ChildSidValue = Get-ChildSid
        $LiveHive = $null
        if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
            $LiveHive = $ChildSidValue
        }
        $OfflineHive = $null
        if (-not $LiveHive) {
            $OfflineHive = Mount-ChildHive
        }
        if ($LiveHive) {
            Remove-ChildHivePolicies -HiveMount $LiveHive -Policies $ChildBasePolicies
            Remove-ChildHivePolicies -HiveMount $LiveHive -Policies $ChildDisallowRunPolicies
            Remove-RestrictRunPolicies -HiveMount $LiveHive -NoDisallowRunFallback:$NoDisallowRunFallback
            Remove-EdgePolicies -HiveMount $LiveHive
            Write-Log -Message "Child hive policies removed from '$ChildUser' (live session)." -Type "SUCCESS" -Color Green
        }
        if ($OfflineHive) {
            Remove-ChildHivePolicies -HiveMount $OfflineHive -Policies $ChildBasePolicies
            Remove-ChildHivePolicies -HiveMount $OfflineHive -Policies $ChildDisallowRunPolicies
            Remove-RestrictRunPolicies -HiveMount $OfflineHive -NoDisallowRunFallback:$NoDisallowRunFallback
            Remove-EdgePolicies -HiveMount $OfflineHive
            Write-Log -Message "Child hive policies removed from '$ChildUser' (offline)." -Type "SUCCESS" -Color Green
            Dismount-ChildHive -HiveMount $OfflineHive
        }
        if (-not $LiveHive -and -not $OfflineHive) {
            Write-Log -Message "Child hive not available for cleanup - policies will clear at next logon if ChildLogon task removed." -Type "WARN" -Color Yellow
        }

        # Remove child OOBE completion flag from live and offline hives
        $OOBEKey = "Software\OSGuard"
        if ($LiveHive) {
            try {
                $LiveOOBEPath = "Registry::HKEY_USERS\$LiveHive\$OOBEKey"
                if (Test-Path $LiveOOBEPath) {
                    Remove-Item -Path $LiveOOBEPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log -Message "Removed child OOBE flag from live hive." -Type "INFO" -Color Gray
                }
            } catch {}
        }
        if ($OfflineHive) {
            try {
                $OfflineOOBEPath = "Registry::HKEY_USERS\$OfflineHive\$OOBEKey"
                if (Test-Path $OfflineOOBEPath) {
                    Remove-Item -Path $OfflineOOBEPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log -Message "Removed child OOBE flag from offline hive." -Type "INFO" -Color Gray
                }
            } catch {}
        }

        # 3. Re-enable password change capability
        net user $ChildUser /passwordchg:yes 2>&1 | Out-Null

        Remove-ChildLogoutShortcut
        Remove-ChildGameRequestShortcut
        Remove-BrowserRequestShortcut
        Remove-AdminRequestShortcut
        Remove-ScreenTimeWatcher
        Remove-ChildInstallDirectoryHardening
        Remove-BypassMitigations
    } else {
        Write-Log -Message "KeepChildAccount specified: child account policies, shortcuts, screen time, and install directory hardening are preserved." -Type "INFO" -Color Gray
    }

    Remove-ChildUSBGuard

    # Remove AppLocker and SRP (machine-wide, affects all users)
    Clear-AllAppLockerAndSRP

    Remove-ParentModeShortcut
    Remove-ParentModeAdminTools
    Remove-GrantBrowserTimeShortcut
    Remove-AdminOnlyLogoutShortcut

    Write-Log -Message "OS Child Lockdown removed." -Type "SUCCESS" -Color Green
}

# ============================================================================
# 6.5 BYPASS MITIGATION MODULE (CHILD-SPECIFIC)
# ============================================================================

# File extensions that are remapped to txtfile in the child hive (HKCU\Software\Classes)
$script:BlockedExtensions = @(
    @{ Ext = ".scr"; Original = "scrfile" },
    @{ Ext = ".com"; Original = "comfile" },
    @{ Ext = ".pif"; Original = "piffile" }
)

function Apply-ChildFileAssociationBlock {
    param([string]$HiveMount)
    if (-not $HiveMount) { return }
    $HiveRoot = "Registry::HKEY_USERS\$HiveMount"
    foreach ($item in $script:BlockedExtensions) {
        $path = "$HiveRoot\Software\Classes\$($item.Ext)"
        try {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
            }
            $current = $null
            try {
                $regItem = Get-Item -Path $path -ErrorAction SilentlyContinue
                if ($regItem) { $current = $regItem.GetValue("(Default)") }
            } catch {}
            if ($current -and $current -ne "txtfile") {
                Set-ItemProperty -Path $path -Name "OSGuardOriginalProgID" -Value $current -Type String -Force -ErrorAction SilentlyContinue
            }
            Set-ItemProperty -Path $path -Name "(Default)" -Value "txtfile" -Type String -Force -ErrorAction Stop
            Write-Log -Message "Blocked $($item.Ext) execution in child hive (assoc -> txtfile)." -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to block $($item.Ext) in child hive: $_" -Type "WARN" -Color Yellow
        }
    }
    Write-Log -Message "Child file association lockdown applied." -Type "SUCCESS" -Color Green
}

function Remove-ChildFileAssociationBlock {
    param([string]$HiveMount)
    if (-not $HiveMount) { return }
    $HiveRoot = "Registry::HKEY_USERS\$HiveMount"
    foreach ($item in $script:BlockedExtensions) {
        $path = "$HiveRoot\Software\Classes\$($item.Ext)"
        if (Test-Path $path) {
            try {
                $original = (Get-ItemProperty -Path $path -Name "OSGuardOriginalProgID" -ErrorAction SilentlyContinue)."OSGuardOriginalProgID"
                if ($original) {
                    Set-ItemProperty -Path $path -Name "(Default)" -Value $original -Type String -Force -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $path -Name "OSGuardOriginalProgID" -Force -ErrorAction SilentlyContinue
                } else {
                    Set-ItemProperty -Path $path -Name "(Default)" -Value $item.Original -Type String -Force -ErrorAction SilentlyContinue
                }
                Write-Log -Message "Restored $($item.Ext) association in child hive." -Type "INFO" -Color Gray
            } catch {}
        }
    }
    Write-Log -Message "Child file association lockdown removed." -Type "INFO" -Color Gray
}

function Invoke-ChildLogoff {
    <#
        Forces logoff of the child user session to unlock NTUSER.DAT
        and allow clean install/uninstall operations without leaving a blank desktop.
    #>
    $ChildSession = $null
    try {
        $Sessions = query user 2>&1 | Where-Object { $_ -match [regex]::Escape($ChildUser) }
        foreach ($Line in $Sessions) {
            $Trimmed = $Line.Trim()
            if ($Trimmed -match '^\S+\s+(\S+)?\s+(\d+)\s+') {
                $SessionId = $Matches[2]
                $ChildSession = $SessionId
                break
            }
        }
    } catch {}

    if ($ChildSession) {
        try {
            logoff $ChildSession 2>&1 | Out-Null
            Write-Log -Message "Child session $ChildSession forcefully logged off to allow clean install/uninstall." -Type "INFO" -Color Gray
            Start-Sleep -Seconds 3
        } catch {
            Write-Log -Message "Failed to log off child session: $_" -Type "WARN" -Color Yellow
        }
    }
}

function Restart-ChildShell {
 <#
        Restarts the child's StartMenuExperienceHost and ShellExperienceHost processes
        so the Start Menu re-reads policies (e.g., NoLogOff).
        We deliberately do NOT touch explorer.exe because killing it from another session
        (e.g., SYSTEM) leaves the child with a blank desktop since Windows won't auto-restart it.
        Works whether running as SYSTEM/admin (finds child session) or as the child.
    #>
    $TargetSessionId = $null
    $CurrentSessionId = (Get-Process -Id $PID).SessionId

    # Try to find the child's session by looking for explorer.exe owned by the child
    try {
        $ChildExplorers = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue
        foreach ($Proc in $ChildExplorers) {
            $Owner = $Proc | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($Owner -and $Owner.User -eq $ChildUser) {
                $TargetSessionId = $Proc.SessionId
                break
            }
        }
    } catch {}

    # If we couldn't find the child explorer, and we're running as the child, use current session
    if (-not $TargetSessionId) {
        $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        if ($CurrentUser -match "$ChildUser$") {
            $TargetSessionId = $CurrentSessionId
        }
    }

    if (-not $TargetSessionId) { return }

    $ShellProcs = @("StartMenuExperienceHost", "ShellExperienceHost")
    foreach ($ProcName in $ShellProcs) {
        Get-Process -Name $ProcName -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $TargetSessionId } | ForEach-Object {
            try {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Restarted child $ProcName (PID $($_.Id), Session $TargetSessionId) to refresh Start Menu policies." -Type "INFO" -Color Gray
            } catch {}
        }
    }

    # NOTE: We do NOT kill explorer.exe here. When a cross-session process (e.g., SYSTEM)
    # kills explorer, Windows does NOT auto-restart it, leaving the child with a blank
    # desktop and no taskbar. Only the UWP shell apps above are safe to restart.
}

function Apply-FolderExecutionDeny {
    $ChildSidValue = Get-ChildSid
    if (-not $ChildSidValue) { return }
    $ChildSidObj = New-Object System.Security.Principal.SecurityIdentifier($ChildSidValue)
    $ProfilePath = Get-ChildProfilePath
    if (-not $ProfilePath) { return }
    $Folders = @(
        (Join-Path $ProfilePath "Desktop"),
        (Join-Path $ProfilePath "Documents"),
        (Join-Path $ProfilePath "Downloads"),
        (Join-Path $ProfilePath "Music"),
        (Join-Path $ProfilePath "Pictures"),
        (Join-Path $ProfilePath "Videos"),
        (Join-Path $ProfilePath "AppData\Local\Temp"),
        (Join-Path $ProfilePath "AppData\Local\Microsoft\WindowsApps")
    )
    foreach ($Dir in $Folders) {
        if (-not (Test-Path $Dir)) { continue }
        try {
            $Acl = Get-Acl -Path $Dir
            $Acl.Access | Where-Object {
                try {
                    $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                    $sid.Value -eq $ChildSidValue -and $_.AccessControlType -eq "Deny"
                } catch { $false }
            } | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
            $DenyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ChildSidObj, "ExecuteFile", "ContainerInherit,ObjectInherit", "None", "Deny"
            )
            $Acl.AddAccessRule($DenyRule)
            Set-Acl -Path $Dir -AclObject $Acl -ErrorAction Stop
            Write-Log -Message "Denied execute on $Dir" -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to deny execute on $Dir`: $_" -Type "WARN" -Color Yellow
        }
    }
    Write-Log -Message "Folder execution deny applied." -Type "SUCCESS" -Color Green
}

function Remove-FolderExecutionDeny {
    $ChildSidValue = Get-ChildSid
    if (-not $ChildSidValue) { return }
    $ProfilePath = Get-ChildProfilePath
    if (-not $ProfilePath) { return }
    $Folders = @(
        (Join-Path $ProfilePath "Desktop"), (Join-Path $ProfilePath "Documents"),
        (Join-Path $ProfilePath "Downloads"), (Join-Path $ProfilePath "Music"),
        (Join-Path $ProfilePath "Pictures"), (Join-Path $ProfilePath "Videos"),
        (Join-Path $ProfilePath "AppData\Local\Temp"),
        (Join-Path $ProfilePath "AppData\Local\Microsoft\WindowsApps")
    )
    foreach ($Dir in $Folders) {
        if (-not (Test-Path $Dir)) { continue }
        try {
            $Acl = Get-Acl -Path $Dir
            $Acl.Access | Where-Object {
                try {
                    $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                    $sid.Value -eq $ChildSidValue -and $_.AccessControlType -eq "Deny"
                } catch { $false }
            } | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
            Set-Acl -Path $Dir -AclObject $Acl -ErrorAction Stop
        } catch {}
    }
    Write-Log -Message "Folder execution deny removed." -Type "INFO" -Color Gray
}

function Apply-BypassMitigations {
    Write-Log -Message 'Applying OS-Guard Bypass Mitigations (child-specific)...' -Type "ACTION" -Color Cyan

    Apply-FolderExecutionDeny

    # Apply file association block to child hive (offline + live session)
    $HiveMount = Mount-ChildHive
    if ($HiveMount) {
        Apply-ChildFileAssociationBlock -HiveMount $HiveMount
        Dismount-ChildHive -HiveMount $HiveMount
    } else {
        # Mount-ChildHive returns $null when child is logged in; live session is handled below
        Write-Log -Message "Offline hive not mounted for file association block (child may be logged in). Applying to live session." -Type "INFO" -Color Gray
    }
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        Apply-ChildFileAssociationBlock -HiveMount $ChildSidValue
    }

    Write-Log -Message 'Bypass Mitigations applied (child-specific).' -Type "SUCCESS" -Color Green

}

function Remove-BypassMitigations {
    Write-Log -Message 'Removing OS-Guard Bypass Mitigations (child-specific)...' -Type "ACTION" -Color Cyan

    Remove-FolderExecutionDeny

    # Remove file association block from child hive (live + offline)
    $ChildSidValue = Get-ChildSid
    $LiveHive = $null
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        $LiveHive = $ChildSidValue
    }
    $OfflineHive = $null
    if (-not $LiveHive) {
        $OfflineHive = Mount-ChildHive
    }
    if ($LiveHive) {
        Remove-ChildFileAssociationBlock -HiveMount $LiveHive
    }
    if ($OfflineHive) {
        Remove-ChildFileAssociationBlock -HiveMount $OfflineHive
        Dismount-ChildHive -HiveMount $OfflineHive
    }

    Write-Log -Message 'Bypass Mitigations removed (child-specific).' -Type "SUCCESS" -Color Green

}

# ============================================================================
# 7. DNS LOCKDOWN MODULE (ENABLE) - PRESERVED FROM ORIGINAL
# ============================================================================

function Enable-DNSLock {
    Write-Log -Message 'Initiating Targeted DNS Lock (Admin/SYSTEM Only on IPv4 & IPv6)...' -Type "ACTION" -Color Magenta


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
                    Write-Log -Message "Applied DNS lock ($Proto`) for adapter: $($Adapter.Name)" -Type "SUCCESS" -Color Green


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

    Write-Log -Message "Resetting Network Stack..." -Type "INFO" -Color Yellow
    ipconfig /flushdns | Out-Null

    # Only force DHCP renewal during interactive runs; avoid network disruption in background task
    if (-not $SilentLock) {
        ipconfig /renew | Out-Null
        Write-Log -Message "DNS protection deployed. DHCP Lease Renewal Successful!" -Type "SUCCESS" -Color Green
    } else {
        Write-Log -Message "DNS protection deployed silently (no DHCP renewal in background task)." -Type "SUCCESS" -Color Green
    }

    # Final DNS status verification
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
                    if (-not $HasDeny) { $FailedCount++; Write-Log -Message "DNS lock missing for adapter $($Adapter.Name) ($Proto)." -Type "ERROR" -Color Red }
                    $RegKey.Close()
                }
            } catch { $FailedCount++; Write-Log -Message "Could not verify DNS lock for adapter $($Adapter.Name) ($Proto)." -Type "ERROR" -Color Red }
        }
    }
    # Verify child hive policies (network UI + browser DoH) instead of HKLM/admin-HKCU
    $ChildSidValue = Get-ChildSid
    $DnsHiveMount = $null
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        $DnsHiveMount = $ChildSidValue
    } else {
        $DnsHiveMount = Mount-ChildHive
    }
    if ($DnsHiveMount) {
        $NetConnPath = "Registry::HKEY_USERS\$DnsHiveMount\Software\Policies\Microsoft\Windows\Network Connections"
        $NetConn = Get-ItemProperty -Path $NetConnPath -ErrorAction SilentlyContinue
        $EdgePathCheck = "Registry::HKEY_USERS\$DnsHiveMount\Software\Policies\Microsoft\Edge"
        $Edge = Get-ItemProperty -Path $EdgePathCheck -ErrorAction SilentlyContinue
        if ($Edge -and $Edge.DnsOverHttpsMode -ne "off") { $FailedCount++; Write-Log -Message "Edge DoH not disabled for child." -Type "ERROR" -Color Red }
        $ChromePathCheck = "Registry::HKEY_USERS\$DnsHiveMount\Software\Policies\Google\Chrome"
        $Chrome = Get-ItemProperty -Path $ChromePathCheck -ErrorAction SilentlyContinue
        if ($Chrome -and $Chrome.DnsOverHttpsMode -ne "off") { $FailedCount++; Write-Log -Message "Chrome DoH not disabled for child." -Type "ERROR" -Color Red }
        $FirefoxPathCheck = "Registry::HKEY_USERS\$DnsHiveMount\Software\Policies\Mozilla\Firefox\DNSOverHTTPS"
        $Firefox = Get-ItemProperty -Path $FirefoxPathCheck -ErrorAction SilentlyContinue
        if ($Firefox -and $Firefox.Enabled -ne 0) { $FailedCount++; Write-Log -Message "Firefox DoH not disabled for child." -Type "ERROR" -Color Red }
        if ($DnsHiveMount -ne $ChildSidValue) { Dismount-ChildHive -HiveMount $DnsHiveMount }
    }
    if ($FailedCount -eq 0) {
        if (-not $SilentLock) { Write-Host "[SUCCESS] ALL DNS LOCKS DEPLOYED!" -ForegroundColor Green }
    } else {
        if (-not $SilentLock) { Write-Host "[PARTIAL] DNS LOCKS DEPLOYED WITH ERRORS! ($FailedCount items failed)" -ForegroundColor Yellow }
    }
}

# ============================================================================
# 8. DNS UNLOCK MODULE (DISABLE)
# ============================================================================

function Disable-DNSLock {
    Write-Log -Message "Initiating Total DNS Unlock..." -Type "ACTION" -Color Magenta

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
                            if (($RuleSid.Value -eq "S-1-5-32-544" -or $RuleSid.Value -eq "S-1-5-18" -or $RuleSid.Value -eq "S-1-1-0") -and $Rule.AccessControlType -eq "Deny") {
                                $RulesToRemove += $Rule
                            }
                        } catch {}
                    }

                    if ($RulesToRemove.Count -gt 0) {
                        foreach ($Rule in $RulesToRemove) { $Acl.RemoveAccessRule($Rule) }
                        $RegKey.SetAccessControl($Acl)
                        Write-Log -Message "Stripped Deny rules ($Proto`) for adapter: $($Adapter.Name)" -Type "SUCCESS" -Color Green

                    }
                    $RegKey.Close()
                }
            } catch {
                Write-Log -Message "Failed to read $Proto adapter $($Adapter.Name)." -Type "ERROR" -Color Red
            }
        }
    }

    ipconfig /flushdns | Out-Null

    Write-Log -Message "DNS restored to default Windows behaviors." -Type "SUCCESS" -Color Green
}

# ============================================================================
# 9. COMBINED STATUS CHECKER (DNS + OS)
# ============================================================================

function Get-LockStatus {
    $DnsLocked = $true
    $AnyDnsLocked = $false
    $OsLocked = $true

    # Refresh adapter list each time (USB/Wi-Fi may change while menu is open)
    $Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
    if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }

    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " LIVE HARDWARE ADAPTER STATUS (DNS) " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray

    # --- 1. CHECK HARDWARE ADAPTERS ---
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $AdapterLocked = $false
        $StatusColor = if ($Adapter.Status -eq "Up") { "Green" } else { "DarkGray" }

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

        if ($AdapterLocked) {
            Write-Host '  `-> DNS Security: [X] LOCKED (IPv4/IPv6)' -ForegroundColor Red

            Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
            $AnyDnsLocked = $true
        } else {
            Write-Host "  `-> DNS Security: [ ] UNLOCKED (Vulnerable)" -ForegroundColor Green
            Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
            $DnsLocked = $false
        }
    }

    # --- 2. CHECK DNS SYSTEM POLICIES ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " DNS POLICIES (DoH) " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray

    $GpoEnforced = $false
    # Check child hive for network UI and browser DoH policies (admin HKCU is not the target)
    $ChildNetConn = $null
    $ChildEdgeDoH = $null
    $ChildChromeDoH = $null
    $ChildFirefoxDoH = $null
    $ChildSidValue = Get-ChildSid
    $DnsHiveMount = $null
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        $DnsHiveMount = $ChildSidValue
    } else {
        $DnsHiveMount = Mount-ChildHive
    }
    if ($DnsHiveMount) {
        $ChildEdgePath = "Registry::HKEY_USERS\$DnsHiveMount\Software\Policies\Microsoft\Edge"
        if (Test-Path $ChildEdgePath) { $ChildEdgeDoH = Get-ItemProperty -Path $ChildEdgePath -ErrorAction SilentlyContinue }
        $ChildChromePath = "Registry::HKEY_USERS\$DnsHiveMount\Software\Policies\Google\Chrome"
        if (Test-Path $ChildChromePath) { $ChildChromeDoH = Get-ItemProperty -Path $ChildChromePath -ErrorAction SilentlyContinue }
        $ChildFirefoxPath = "Registry::HKEY_USERS\$DnsHiveMount\Software\Policies\Mozilla\Firefox\DNSOverHTTPS"
        if (Test-Path $ChildFirefoxPath) { $ChildFirefoxDoH = Get-ItemProperty -Path $ChildFirefoxPath -ErrorAction SilentlyContinue }
        $GpoEnforced = $true
        if ($ChildEdgeDoH -and $ChildEdgeDoH.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }
        if ($ChildChromeDoH -and $ChildChromeDoH.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }
        if ($ChildFirefoxDoH -and $ChildFirefoxDoH.Enabled -ne 0) { $GpoEnforced = $false }
        if ($DnsHiveMount -ne $ChildSidValue) { Dismount-ChildHive -HiveMount $DnsHiveMount }
    }

    if ($GpoEnforced) {
        Write-Host '  [X] DNS GPO Restrictions -> ENFORCED (Browsers & GUI)' -ForegroundColor Red

    } else {
        Write-Host "  [ ] DNS GPO Restrictions -> NOT ENFORCED" -ForegroundColor Green
        $DnsLocked = $false
    }

    # --- 3. CHECK OS CHILD LOCKDOWN ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " OS CHILD LOCKDOWN " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray

    $ChildExists = Get-ChildAccount
    if (-not $ChildExists) {
        Write-Host "  `[ ] Child Account      -> NOT CREATED ($ChildUser`)" -ForegroundColor DarkGray

        $OsLocked = $false
    } else {
        $ChildEnabled = $ChildExists.Enabled
        Write-Host "  `[X] Child Account      -> EXISTS ($ChildUser, Enabled=$ChildEnabled`)" -ForegroundColor Cyan

        # Verify not an administrator
        try {
            $IsAdmin = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Where-Object { $_.Name -match "$ChildUser$" }
            if ($IsAdmin) {
                Write-Host "  [!] Child is Admin     -> SHOULD BE STANDARD USER!" -ForegroundColor Yellow
                $OsLocked = $false
            } else {
                Write-Host '  [X] Child Membership   -> Standard User (not Admin)' -ForegroundColor Cyan

            }
        } catch {}

        # Check machine policies (UAC)
        $UacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $UacLUA = Get-ItemProperty -Path $UacPath -Name "EnableLUA" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "EnableLUA" -ErrorAction SilentlyContinue
        $UacAdmin = Get-ItemProperty -Path $UacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
        if ($UacLUA -eq 1 -and $UacAdmin -eq 2) {
            Write-Host '  [X] UAC Maxed          -> ENFORCED (child cannot disable)' -ForegroundColor Red

        } else {
            Write-Host "  [ ] UAC Maxed          -> NOT ENFORCED" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check child USB guard (replaces machine-wide USBSTOR disable)
        $UsbGuardTask = Get-ScheduledTask -TaskName "OSGuard-ChildUSBGuard" -ErrorAction SilentlyContinue
        if ($UsbGuardTask) {
            Write-Host '  [X] USB Storage Guard  -> ACTIVE (child-only USB block)' -ForegroundColor Red

        } else {
            Write-Host "  [ ] USB Storage Guard  -> NOT ACTIVE" -ForegroundColor Green
            $OsLocked = $false
        }


        # Check child hive policies (mount + verify samples)
        $HiveMount = Mount-ChildHive
        if ($HiveMount) {
            $SamplePath = "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            $TaskMgrDisabled = Get-ItemProperty -Path $SamplePath -Name "DisableTaskMgr" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableTaskMgr" -ErrorAction SilentlyContinue
            $RegDisabled = Get-ItemProperty -Path $SamplePath -Name "DisableRegistryTools" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableRegistryTools" -ErrorAction SilentlyContinue
            if ($TaskMgrDisabled -eq 1 -and $RegDisabled -eq 1) {
                Write-Host '  [X] TaskMgr/Regedit    -> DISABLED for child' -ForegroundColor Red

            } else {
                Write-Host "  [ ] TaskMgr/Regedit    -> ENABLED for child" -ForegroundColor Green
                $OsLocked = $false
            }

            # Check Windows Update UI block in child hive
            $WuPath = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Windows\WindowsUpdate"
            $WuBlocked = Get-ItemProperty -Path $WuPath -Name "NoWindowsUpdate" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoWindowsUpdate" -ErrorAction SilentlyContinue
            if ($WuBlocked -eq 1) {
                Write-Host '  [X] Windows Update UI  -> BLOCKED for child' -ForegroundColor Red

            } else {
                Write-Host "  [ ] Windows Update UI  -> AVAILABLE for child" -ForegroundColor Green
                $OsLocked = $false
            }

            $ExplorerPath = "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            $NoCtx = Get-ItemProperty -Path $ExplorerPath -Name "NoViewContextMenu" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoViewContextMenu" -ErrorAction SilentlyContinue
            $NoFolder = Get-ItemProperty -Path $ExplorerPath -Name "NoFolderOptions" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoFolderOptions" -ErrorAction SilentlyContinue
            $NoTaskbar = Get-ItemProperty -Path $ExplorerPath -Name "NoSetTaskbar" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoSetTaskbar" -ErrorAction SilentlyContinue
            $NoAddPrinter = Get-ItemProperty -Path $ExplorerPath -Name "NoAddPrinter" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoAddPrinter" -ErrorAction SilentlyContinue
            $NoDelPrinter = Get-ItemProperty -Path $ExplorerPath -Name "NoDeletePrinter" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoDeletePrinter" -ErrorAction SilentlyContinue

            if ($NoCtx -eq 1) {
                Write-Host '  [X] Right-Click Menu   -> DISABLED for child' -ForegroundColor Red

            } else {
                Write-Host "  [ ] Right-Click Menu   -> ENABLED for child" -ForegroundColor Green
                $OsLocked = $false
            }
            if ($NoFolder -eq 1) {
                Write-Host '  [X] Folder Options     -> HIDDEN for child' -ForegroundColor Red

            } else {
                Write-Host "  [ ] Folder Options     -> VISIBLE for child" -ForegroundColor Green
                $OsLocked = $false
            }
            if ($NoTaskbar -eq 1) {
                Write-Host '  [X] Taskbar Changes    -> BLOCKED for child' -ForegroundColor Red

            } else {
                Write-Host "  [ ] Taskbar Changes    -> ALLOWED for child" -ForegroundColor Green
                $OsLocked = $false
            }
            if ($NoAddPrinter -eq 1 -and $NoDelPrinter -eq 1) {
                Write-Host '  [X] Printer Changes    -> BLOCKED for child' -ForegroundColor Red

            } else {
                Write-Host "  [ ] Printer Changes    -> ALLOWED for child" -ForegroundColor Green
                $OsLocked = $false
            }

            # Check sign-out / power restrictions
            $NoClose = Get-ItemProperty -Path $ExplorerPath -Name "NoClose" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoClose" -ErrorAction SilentlyContinue
            $HidePower = Get-ItemProperty -Path $ExplorerPath -Name "HidePowerOptions" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "HidePowerOptions" -ErrorAction SilentlyContinue
            $NoLock = Get-ItemProperty -Path $SamplePath -Name "DisableLockWorkstation" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableLockWorkstation" -ErrorAction SilentlyContinue
            if ($NoClose -eq 1 -and $HidePower -eq 1 -and $NoLock -eq 1) {
                Write-Host '  [X] Sign Out / Power   -> BLOCKED for child (admin shortcut required)' -ForegroundColor Red

            } else {
                Write-Host "  [ ] Sign Out / Power   -> ALLOWED for child" -ForegroundColor Green
                $OsLocked = $false
            }

            # Check RestrictRun whitelist in child hive
            $RestrictRunVal = Get-ItemProperty -Path $ExplorerPath -Name "RestrictRun" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "RestrictRun" -ErrorAction SilentlyContinue
            if ($RestrictRunVal -eq 1) {
                $WhitelistCount = 0
                $RestrictRunSubPath = "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RestrictRun"
                if (Test-Path $RestrictRunSubPath) {
                    $RestrictRunProps = Get-ItemProperty -Path $RestrictRunSubPath -ErrorAction SilentlyContinue
                    if ($RestrictRunProps) {
                        $WhitelistCount = ($RestrictRunProps | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\d+$' }).Count
                    }
                }
                Write-Host "  `[X] Program Whitelist  -> ACTIVE ($WhitelistCount entries)" -ForegroundColor Red

            } else {
                Write-Host "  [ ] Program Whitelist  -> NOT ACTIVE" -ForegroundColor Green
                $OsLocked = $false
            }

            Dismount-ChildHive -HiveMount $HiveMount
        } else {
            Write-Host "  [~] Child Hive         -> Not mountable (will apply at logon)" -ForegroundColor DarkGray
        }

        # Check logout shortcut (scan all matching profile folders)
        $ShortcutFound = $false
        foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
            $ShortcutPath = Join-Path $ProfilePath "Desktop\Log out.lnk"
            if (Test-Path $ShortcutPath) { $ShortcutFound = $true; break }
        }
        if ($ShortcutFound) {
            Write-Host '  [X] Logout Shortcut    -> CREATED (requires admin approval)' -ForegroundColor Cyan

        } else {
            Write-Host "  [ ] Logout Shortcut    -> MISSING" -ForegroundColor DarkGray
            $OsLocked = $false
        }
    }

    # --- 4. CHECK INSTALLATION STATUS ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " PERSISTENCE & INSTALLATION " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray
    $TaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $CmdExists = Test-Path $CmdPath
    if ($TaskExists -and $CmdExists) {
        Write-Host "  `[X] Background Service -> INSTALLED ('oslock' active)" -ForegroundColor Cyan

    } else {
        Write-Host "  [ ] Background Service -> NOT INSTALLED" -ForegroundColor DarkGray
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    # --- 5. INTEGRITY CHECK ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " INTEGRITY CHECK " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray
    $TamperFlag = $false
    if (Test-Path $InstallScript) {
        $ExpectedHash = $null
        try { $ExpectedHash = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings" -Name "OSGuardIntegrity" -ErrorAction Stop) } catch {}
        if (-not $ExpectedHash -and (Test-Path (Join-Path $InstallDir "integrity.sha256"))) {
            $ExpectedHash = Get-Content -Path (Join-Path $InstallDir "integrity.sha256") -Raw
        }
        if ($ExpectedHash) {
            $ActualHash = Get-FileHashSafe -Path $InstallScript
            if ($ExpectedHash.Trim() -eq $ActualHash.Trim()) {
                Write-Host '  [X] Script Integrity    -> VERIFIED' -ForegroundColor Green

            } else {
                Write-Host "  [ ] Script Integrity    -> TAMPER DETECTED" -ForegroundColor Red
                Write-Host "`n  *** TAMPER DETECTED! ACTION REQUIRED ***" -ForegroundColor Yellow
                Write-Host "  - Run a full antivirus scan immediately." -ForegroundColor Yellow
                Write-Host "  - Do NOT use options [1], [2], or [3] (they may run malicious code)." -ForegroundColor Yellow
                Write-Host "  - Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
                $TamperFlag = $true
            }
        } else {
            Write-Host "  [ ] Script Integrity    -> NO BASELINE" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [ ] Script Integrity    -> NOT INSTALLED" -ForegroundColor DarkGray
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    # --- 5.1 TAMPER LOCKOUT STATUS ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " SCRIPT TAMPER DETECTION " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray
    $TamperLockoutActive = $false
    try { $TamperLockoutActive = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings" -Name $TamperDetectedRegName -ErrorAction Stop) -eq 1 } catch {}
    if ($TamperLockoutActive) {
        Write-Host '  [X] Tamper Lockout      -> ACTIVE (Child session locked)' -ForegroundColor Red

        Write-Host "  *** Child session is locked due to script tampering. ***" -ForegroundColor Red
        Write-Host "  Admin password required to unlock the child session." -ForegroundColor Yellow
    } else {
        Write-Host "  [ ] Tamper Lockout      -> NOT ACTIVE" -ForegroundColor Green
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    # Master Status Banner Logic
    if ($TamperLockoutActive) {
        Write-Host " *** TAMPER LOCKOUT ACTIVE: CHILD SESSION LOCKED *** " -ForegroundColor Magenta
    } elseif ($DnsLocked -and $OsLocked -and $GpoEnforced) {
        Write-Host " *** SYSTEM FULLY LOCKED: DNS + OS CHILD PADLOCK ACTIVE *** " -ForegroundColor Red
    } elseif ($AnyDnsLocked -or $GpoEnforced -or $OsLocked) {
        Write-Host " *** SYSTEM PARTIALLY LOCKED: MIXED STATE *** " -ForegroundColor Yellow
    } else {
        Write-Host " *** SYSTEM UNLOCKED: NO PADLOCK ACTIVE *** " -ForegroundColor Green
    }

    return @{ Dns = $DnsLocked; Os = $OsLocked }
}

function Show-CategoryGrid {
    <#
        Prints a compact two-column category status grid at the top of the TUI.
        Reads key registry values directly so it is independent of Get-LockStatus.
    #>
    param([switch]$ForceRefresh)

    # Cache expensive computations so the menu loop doesn't freeze on every refresh.
    $CacheTtl = [timespan]::FromSeconds(5)
    if (-not $ForceRefresh -and $script:CategoryGridCache -and $script:CategoryGridTimestamp -and ((Get-Date) - $script:CategoryGridTimestamp) -lt $CacheTtl) {
        $Categories = $script:CategoryGridCache
        Write-Host "`n=====================================================" -ForegroundColor DarkGray
        Write-Host " CATEGORY STATUS GRID " -ForegroundColor White
        Write-Host "=====================================================" -ForegroundColor DarkGray
        if ($Categories.Values -contains "PENDING") {
            Write-Host "  Note: [PENDING] policies will be enforced when the child first logs in." -ForegroundColor Cyan
        }
        $Keys = @($Categories.Keys)
        $i = 0
        while ($i -lt $Keys.Count) {
            $LeftKey = $Keys[$i]
            $LeftVal = $Categories[$LeftKey]
            $LeftStr = if ($LeftVal -eq $true) { "[ENABLED]  " } elseif ($LeftVal -eq $false) { "[DISABLED] " } else { "[UNKNOWN]  " }
            $LeftColor = if ($LeftVal -eq $true) { "Green" } elseif ($LeftVal -eq $false) { "DarkGray" } else { "Yellow" }
            if ($i + 1 -lt $Keys.Count) {
                $RightKey = $Keys[$i + 1]
                $RightVal = $Categories[$RightKey]
                $RightStr = if ($RightVal -eq $true) { "[ENABLED]  " } elseif ($RightVal -eq $false) { "[DISABLED] " } else { "[UNKNOWN]  " }
                $RightColor = if ($RightVal -eq $true) { "Green" } elseif ($RightVal -eq $false) { "DarkGray" } else { "Yellow" }
                Write-Host "  $LeftStr" -NoNewline -ForegroundColor $LeftColor
                Write-Host ("{0,-22}  " -f $LeftKey) -NoNewline -ForegroundColor $LeftColor
                Write-Host "$RightStr" -NoNewline -ForegroundColor $RightColor
                Write-Host ("{0,-22}" -f $RightKey) -ForegroundColor $RightColor
            } else {
                Write-Host ("  {0}{1,-22}" -f $LeftStr, $LeftKey) -ForegroundColor $LeftColor
            }
            $i += 2
        }
        Write-Host "=====================================================" -ForegroundColor DarkGray
        return $Categories
    }

    $Categories = [ordered]@{}

    # --- Switch User (machine-wide) ---
    $HideFastUserSwitchingVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "HideFastUserSwitching" -ErrorAction SilentlyContinue
    $Categories["Switch User"] = ($HideFastUserSwitchingVal -eq 1)

    # --- DNS ---
    $AnyDns = $false
    $Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
    if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        foreach ($SubKeyPath in @("SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid", "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid")) {
            try {
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    foreach ($Rule in $Acl.Access) {
                        try {
                            $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                            if (($RuleSid.Value -eq $SidAdmin.Value -or $RuleSid.Value -eq $SidSystem.Value) -and $Rule.AccessControlType -eq "Deny") { $AnyDns = $true }
                        } catch {}
                    }
                    $RegKey.Close()
                }
            } catch {}
        }
    }
    $Categories["DNS Lock"] = $AnyDns

    # --- Child Hive: prefer live session if child is logged in ---
    $HiveMount = $null
    $HiveLoaded = $false
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        $HiveMount = $ChildSidValue
    } else {
        $ChildProfile = $null
        try { $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" -or $_.LocalPath -like "*\$ChildUser.*" } | Select-Object -First 1 } catch {}
        if ($ChildProfile) {
            $NtUserDat = Join-Path $ChildProfile.LocalPath "NTUSER.DAT"
            if (Test-Path $NtUserDat) {
                if (Test-Path "Registry::HKEY_USERS\OSGuardChildPolicy") { reg.exe unload "HKU\OSGuardChildPolicy" 2>&1 | Out-Null }
                $Output = & reg.exe load "HKU\OSGuardChildPolicy" "$NtUserDat" 2>&1
                if (Test-Path "Registry::HKEY_USERS\OSGuardChildPolicy") { $HiveMount = "OSGuardChildPolicy"; $HiveLoaded = $true }
            }
        }
    }

    $GpoEnforced = $false
    # Check child hive for network UI and browser DoH
    $ChildNetConn = $null
    $ChildEdgeDoH = $null
    $ChildChromeDoH = $null
    $ChildFirefoxDoH = $null
    if ($HiveMount) {
        $ChildNetConnPath = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Windows\Network Connections"
        if (Test-Path $ChildNetConnPath) { $ChildNetConn = Get-ItemProperty -Path $ChildNetConnPath -ErrorAction SilentlyContinue }
        $ChildEdgePath = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Edge"
        if (Test-Path $ChildEdgePath) { $ChildEdgeDoH = Get-ItemProperty -Path $ChildEdgePath -ErrorAction SilentlyContinue }
        $ChildChromePath = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Google\Chrome"
        if (Test-Path $ChildChromePath) { $ChildChromeDoH = Get-ItemProperty -Path $ChildChromePath -ErrorAction SilentlyContinue }
        $ChildFirefoxPath = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Mozilla\Firefox\DNSOverHTTPS"
        if (Test-Path $ChildFirefoxPath) { $ChildFirefoxDoH = Get-ItemProperty -Path $ChildFirefoxPath -ErrorAction SilentlyContinue }
        $GpoEnforced = $true
        if (-not $ChildNetConn -or $ChildNetConn.NC_LanProperties -ne 0) { $GpoEnforced = $false }
        if ($ChildEdgeDoH -and $ChildEdgeDoH.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }
        if ($ChildChromeDoH -and $ChildChromeDoH.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }
        if ($ChildFirefoxDoH -and $ChildFirefoxDoH.Enabled -ne 0) { $GpoEnforced = $false }
    }
    $Categories["DNS GPO/DoH"] = $GpoEnforced

    # --- OS Machine-wide ---
    $UacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $UacLUA = Get-ItemProperty -Path $UacPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "EnableLUA" -ErrorAction SilentlyContinue
    $UacAdmin = Get-ItemProperty -Path $UacPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
    $Categories["UAC Max"] = ($UacLUA -eq 1 -and $UacAdmin -eq 2)

    $OobeBypass = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisablePrivacyExperience" -ErrorAction SilentlyContinue
    $Categories["OOBE Bypass"] = ($OobeBypass -eq 1)

    $WuBlocked = $false
    if ($HiveMount) {
        $WuPath = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Windows\WindowsUpdate"
        $WuBlocked = ((Get-ItemProperty -Path $WuPath -Name "NoWindowsUpdate" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoWindowsUpdate" -ErrorAction SilentlyContinue) -eq 1)
    }
    $Categories["Windows Update UI"] = $WuBlocked

    # --- Child Account ---
    $Categories["Child Account"] = ($null -ne (Get-ChildAccount))

    if ($HiveMount) {
        $TaskMgr = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableTaskMgr" -ErrorAction SilentlyContinue
        $Regedit = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableRegistryTools" -ErrorAction SilentlyContinue
        $NoRun = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoRun" -ErrorAction SilentlyContinue
        $NoControlPanel = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoControlPanel" -ErrorAction SilentlyContinue
        $NoCtx = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoViewContextMenu" -ErrorAction SilentlyContinue
        $NoFolder = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoFolderOptions" -ErrorAction SilentlyContinue
        $NoTaskbar = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoSetTaskbar" -ErrorAction SilentlyContinue
        $NoAddPrinter = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoAddPrinter" -ErrorAction SilentlyContinue
        $NoDelPrinter = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoDeletePrinter" -ErrorAction SilentlyContinue
        $NoThemes = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoThemesTab" -ErrorAction SilentlyContinue
        $NoWallpaper = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoChangingWallPaper" -ErrorAction SilentlyContinue
        $NoAutoPlay = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
        $NoAdminTools = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "StartMenuAdminTools" -ErrorAction SilentlyContinue
        $NoAddRemove = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoAddRemovePrograms" -ErrorAction SilentlyContinue
        $NoPassChange = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableChangePassword" -ErrorAction SilentlyContinue
        $NoNetUi = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Windows\Network Connections" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NC_LanProperties" -ErrorAction SilentlyContinue
        $NoThisPC = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
        $NoClose = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoClose" -ErrorAction SilentlyContinue
        $HidePower = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "HidePowerOptions" -ErrorAction SilentlyContinue
        $NoLock = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableLockWorkstation" -ErrorAction SilentlyContinue

    $Categories["Task Manager"] = ($TaskMgr -eq 1)
        $Categories["Registry Tools"] = ($Regedit -eq 1)
        $Categories["CMD / Run"] = ($NoRun -eq 1)
        $Categories["Control Panel"] = ($NoControlPanel -eq 1)
        $Categories["Right-Click Menu"] = ($NoCtx -eq 1)
        $Categories["Folder Options"] = ($NoFolder -eq 1)
        $Categories["Taskbar"] = ($NoTaskbar -eq 1)
        $Categories["Printers"] = ($NoAddPrinter -eq 1 -and $NoDelPrinter -eq 1)
        $Categories["Wallpaper/Themes"] = ($NoThemes -eq 1 -or $NoWallpaper -eq 1)
        $Categories["AutoPlay"] = ($NoAutoPlay -eq 255)
        $Categories["Admin Tools"] = ($NoAdminTools -eq 0)
        $Categories["Add/Remove Prog"] = ($NoAddRemove -eq 1)
        $Categories["Password Change"] = ($NoPassChange -eq 1)
        $Categories["Network UI"] = ($NoNetUi -eq 0)
        $Categories["This PC Hidden"] = ($NoThisPC -eq 1)
        $Categories["Sign Out / Power"] = ($NoClose -eq 1 -and $HidePower -eq 1 -and $NoLock -eq 1)
        $RestrictRunVal = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "RestrictRun" -ErrorAction SilentlyContinue
        $WhitelistCount = 0
        $RestrictRunSubPath = "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RestrictRun"
        if (Test-Path $RestrictRunSubPath) {
            $RestrictRunProps = Get-ItemProperty -Path $RestrictRunSubPath -ErrorAction SilentlyContinue
            if ($RestrictRunProps) {
                $WhitelistCount = ($RestrictRunProps | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\d+$' }).Count
            }
        }
        $Categories["Program Whitelist"] = ($RestrictRunVal -eq 1 -and $WhitelistCount -gt 0)
    } else {
        $Pending = "PENDING"
        $Categories["Task Manager"] = $Pending
        $Categories["Registry Tools"] = $Pending
        $Categories["CMD / Run"] = $Pending
        $Categories["Control Panel"] = $Pending
        $Categories["Right-Click Menu"] = $Pending
        $Categories["Folder Options"] = $Pending
        $Categories["Taskbar"] = $Pending
        $Categories["Printers"] = $Pending
        $Categories["Wallpaper/Themes"] = $Pending
        $Categories["AutoPlay"] = $Pending
        $Categories["Admin Tools"] = $Pending
        $Categories["Add/Remove Prog"] = $Pending
        $Categories["Password Change"] = $Pending
        $Categories["Network UI"] = $Pending
        $Categories["This PC Hidden"] = $Pending
        $Categories["Sign Out / Power"] = $Pending
        $Categories["Program Whitelist"] = $Pending
        $Categories["DNS GPO/DoH"] = $Pending
        $Categories["Edge Incognito"] = $Pending
        $Categories["Edge DevTools"] = $Pending
        $Categories["Edge Downloads"] = $Pending
        $Categories["Edge Sync"] = $Pending
        $Categories["Edge SafeSearch"] = $Pending
        $Categories["Edge Guest Mode"] = $Pending
        $Categories["Edge Bookmark Bar"] = $Pending
        $Categories["Edge Password Mgr"] = $Pending
        $Categories["Edge URL Block"] = $Pending
        $Categories["Edge Ext Block"] = $Pending
        $Categories["Chrome DoH"] = $Pending
        $Categories["Firefox DoH"] = $Pending
        $Categories["Net Change GPO"] = $Pending
        $Categories["Net Adv GPO"] = $Pending
        $Categories["Edge-Only Browser"] = $Pending
    }

    # --- Browser Lockdown (Edge-Only) ---
    if ($HiveMount) {
        $EdgeGuest = $false
        $EdgeAddProfile = $false
        $EdgePolicyPath = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Edge"
        if (Test-Path $EdgePolicyPath) {
            $EdgeProps = Get-ItemProperty -Path $EdgePolicyPath -ErrorAction SilentlyContinue
            $EdgeGuest = ($EdgeProps | Select-Object -ExpandProperty "BrowserGuestModeEnabled" -ErrorAction SilentlyContinue) -eq 0
            $EdgeAddProfile = ($EdgeProps | Select-Object -ExpandProperty "BrowserAddProfileEnabled" -ErrorAction SilentlyContinue) -eq 0
        }
        $Categories["Edge-Only Browser"] = ($EdgeGuest -and $EdgeAddProfile)
    }

    # --- Batch scheduled task checks in one query for speed ---
    $TaskNames = @($TaskName, $ScreenTimeTaskName, $ProgramScannerName, $ProcessEnforcerName, $ChildLogonTaskName, $ParentModeWatchName)
    $TaskMap = @{}
    try {
        $AllTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $TaskNames -contains $_.TaskName }
        foreach ($t in $AllTasks) { $TaskMap[$t.TaskName] = $t }
    } catch {}
    $Categories["Program Guardian"] = $TaskMap.ContainsKey($ProgramScannerName)
    $Categories["Process Enforcer"] = $TaskMap.ContainsKey($ProcessEnforcerName)
    $Categories["Background Service"] = ($TaskMap.ContainsKey($TaskName) -and (Test-Path $CmdPath))
    $Categories["Child Logon Task"] = $TaskMap.ContainsKey($ChildLogonTaskName)
    $Categories["Parent Mode Watch"] = $TaskMap.ContainsKey($ParentModeWatchName)
    $Categories["Task Scheduler"] = $TaskMap.ContainsKey($TaskName)

    # --- Screen Time ---
    $ScreenTimeEnabled = $false
    if (Test-Path $ScreenTimeConfigFile) {
        $STConfig = Get-ScreenTimeConfig
        if ($STConfig -and $STConfig.Enabled) { $ScreenTimeEnabled = $true }
    }
    $Categories["Screen Time"] = ($ScreenTimeEnabled -and $TaskMap.ContainsKey($ScreenTimeTaskName))

    # --- Logout Shortcut (scan all matching profile folders) ---
    $ShortcutFound = $false
    foreach ($ProfilePath in (Get-AllChildProfilePaths)) {
        if (Test-Path (Join-Path $ProfilePath "Desktop\Log out.lnk")) { $ShortcutFound = $true; break }
    }
    $Categories["Logout Shortcut"] = $ShortcutFound

    # --- Integrity (cache SHA256 for 1 minute) ---
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    $IntegrityFile = Join-Path $InstallDir "integrity.sha256"
    $IntegrityOk = $false
    if ($script:IntegrityHashCache -and $script:IntegrityHashTimestamp -and ((Get-Date) - $script:IntegrityHashTimestamp) -lt [timespan]::FromMinutes(1)) {
        $IntegrityOk = $script:IntegrityHashCache
    } elseif (Test-Path $InstallScript) {
        $ExpectedHash = $null
        try { $ExpectedHash = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardIntegrity" -ErrorAction Stop) } catch {}
        if (-not $ExpectedHash -and (Test-Path $IntegrityFile)) { $ExpectedHash = Get-Content -Path $IntegrityFile -Raw }
        if ($ExpectedHash) {
            $ActualHash = Get-FileHashSafe -Path $InstallScript
            $IntegrityOk = ($ExpectedHash.Trim() -eq $ActualHash.Trim())
            $script:IntegrityHashCache = $IntegrityOk
            $script:IntegrityHashTimestamp = Get-Date
        }
    }
    $Categories["Integrity"] = $IntegrityOk

    # --- Script Tamper Lockout ---
    $TamperFlag = $false
    try { $TamperFlag = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name $TamperDetectedRegName -ErrorAction Stop) -eq 1 } catch {}
    $Categories["Script Tamper Lockout"] = $TamperFlag

    # --- Canary File ---
    $Categories["Canary File"] = (Test-Canary)

    # --- Firewall Rules (only meaningful when geofencing is active) ---
    if ([string]::IsNullOrWhiteSpace($script:HomeSSID)) {
        $Categories["Firewall Rules"] = $false
    } else {
        $FwRules = $null
        try { $FwRules = Get-NetFirewallRule -Direction Outbound -DisplayName "OSGuard-BlockOutbound*" -ErrorAction SilentlyContinue } catch {}
        $Categories["Firewall Rules"] = ($null -ne $FwRules -and $FwRules.Count -gt 0)
    }

    # --- Geofencing (Stricter Lockdown Active) ---
    if ([string]::IsNullOrWhiteSpace($script:HomeSSID)) {
        $Categories["Geofencing"] = $false
    } else {
        $Categories["Geofencing"] = -not (Test-HomeNetwork)
    }

    # --- Parent Mode Active ---
    $ParentModeActive = $false
    try { $ParentModeActive = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction Stop) -eq 1 } catch {}
    $Categories["Parent Mode Active"] = $ParentModeActive

    # --- WMI Subscription ---
    $WmiFilterExists = Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue
    $WmiConsumerExists = Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue
    $WmiBindingExists = Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" -Filter "__PATH LIKE '%$WmiEventName%'" -ErrorAction SilentlyContinue
    $Categories["WMI Subscription"] = ($null -ne $WmiFilterExists -and $null -ne $WmiConsumerExists -and $null -ne $WmiBindingExists)

    # --- Browser Launcher ---
    $Categories["Browser Launcher"] = (Test-Path $BrowserLauncherPath)

    # --- Requests Directory ---
    $Categories["Requests Dir"] = (Test-Path (Join-Path $InstallDir "Requests"))

    # --- Install Directory ---
    $Categories["Install Dir"] = (Test-Path $InstallDir)

    # --- PATH Entry ---
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    $Categories["PATH Entry"] = ($CurrentPath -like "*$InstallDir*")

    # --- Edge URL Blocklist ---
    if ($HiveMount) {
        $EdgeUrlBlock = $false
        $EdgeExtBlock = $false
        $ChromeDoH = $false
        $FirefoxDoH = $false
        $NetChange = $false
        $NetAdv = $false
        $EdgePathCheck = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Edge"
        $EdgeUrlBlock = Test-Path (Join-Path $EdgePathCheck "URLBlocklist")
        $EdgeExtBlock = Test-Path (Join-Path $EdgePathCheck "ExtensionInstallBlocklist")
        $ChromePathCheck = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Google\Chrome"
        if (Test-Path $ChromePathCheck) { $ChromeDoH = (Get-ItemProperty -Path $ChromePathCheck -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DnsOverHttpsMode" -ErrorAction SilentlyContinue) -eq "off" }
        $FirefoxPathCheck = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Mozilla\Firefox\DNSOverHTTPS"
        if (Test-Path $FirefoxPathCheck) { $FirefoxDoH = (Get-ItemProperty -Path $FirefoxPathCheck -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "Enabled" -ErrorAction SilentlyContinue) -eq 0 }
        $GpoPathCheck = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Windows\Network Connections"
        if (Test-Path $GpoPathCheck) {
            $NetConn = Get-ItemProperty -Path $GpoPathCheck -ErrorAction SilentlyContinue
            $NetChange = ($NetConn | Select-Object -ExpandProperty "NC_LanChangeProperties" -ErrorAction SilentlyContinue) -eq 0
            $NetAdv = ($NetConn | Select-Object -ExpandProperty "NC_AllowAdvancedTCPIPConfig" -ErrorAction SilentlyContinue) -eq 0
        }
        $Categories["Edge URL Block"] = $EdgeUrlBlock
        $Categories["Edge Ext Block"] = $EdgeExtBlock
        $Categories["Chrome DoH"] = $ChromeDoH
        $Categories["Firefox DoH"] = $FirefoxDoH
        $Categories["Net Change GPO"] = $NetChange
        $Categories["Net Adv GPO"] = $NetAdv
    }

    # --- Disable Consumer Features ---
    if ($HiveMount) {
        $ConsumerFeat = $false
        $ConsumerPath = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Windows\CloudContent"
        $ConsumerFeat = (Get-ItemProperty -Path $ConsumerPath -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue) -eq 1
        $Categories["Consumer Features"] = $ConsumerFeat
    }

    # --- Disable Notification Center ---
    if ($HiveMount) {
        $NotifCenter = $false
        $NotifPath = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Windows\Explorer"
        $NotifCenter = (Get-ItemProperty -Path $NotifPath -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableNotificationCenter" -ErrorAction SilentlyContinue) -eq 1
        $Categories["Notification Center"] = $NotifCenter
    }

    # --- Child Is Standard User ---
    $ChildIsAdmin = $false
    try { $ChildIsAdmin = ($null -ne (Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Where-Object { $_.Name -match "$ChildUser$" })) } catch {}
    $Categories["Child Not Admin"] = (-not $ChildIsAdmin)

    # --- Password Change Disabled ---
    $ChildAcct = $null
    try { $ChildAcct = Get-LocalUser -Name $ChildUser -ErrorAction Stop } catch {}
    $Categories["Password Locked"] = ($ChildAcct -and $ChildAcct.PasswordChangeableDate -eq $null)

    # --- Edge Incognito ---
    if ($HiveMount) {
        $EdgeIncognito = $false
        $EdgeDevTools = $false
        $EdgeDownloads = $false
        $EdgeSync = $false
        $EdgeSafeSearch = $false
        $EdgeGuestMode = $false
        $EdgeBookmark = $false
        $EdgePassMgr = $false
        $EdgePathCheck = "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Edge"
        if (Test-Path $EdgePathCheck) {
            $EdgeProps = Get-ItemProperty -Path $EdgePathCheck -ErrorAction SilentlyContinue
            $EdgeIncognito = ($EdgeProps | Select-Object -ExpandProperty "InPrivateModeAvailability" -ErrorAction SilentlyContinue) -eq 1
            $EdgeDevTools = ($EdgeProps | Select-Object -ExpandProperty "DeveloperToolsAvailability" -ErrorAction SilentlyContinue) -eq 2
            $EdgeDownloads = ($EdgeProps | Select-Object -ExpandProperty "DownloadRestrictions" -ErrorAction SilentlyContinue) -eq 3
            $EdgeSync = ($EdgeProps | Select-Object -ExpandProperty "SyncDisabled" -ErrorAction SilentlyContinue) -eq 1
            $EdgeSafeSearch = ($EdgeProps | Select-Object -ExpandProperty "ForceGoogleSafeSearch" -ErrorAction SilentlyContinue) -eq 1
            $EdgeGuestMode = ($EdgeProps | Select-Object -ExpandProperty "BrowserGuestModeEnabled" -ErrorAction SilentlyContinue) -eq 0
            $EdgeBookmark = ($EdgeProps | Select-Object -ExpandProperty "BookmarkBarEnabled" -ErrorAction SilentlyContinue) -eq 0
            $EdgePassMgr = ($EdgeProps | Select-Object -ExpandProperty "PasswordManagerEnabled" -ErrorAction SilentlyContinue) -eq 0
        }
        $Categories["Edge Incognito"] = $EdgeIncognito
        $Categories["Edge DevTools"] = $EdgeDevTools
        $Categories["Edge Downloads"] = $EdgeDownloads
        $Categories["Edge Sync"] = $EdgeSync
        $Categories["Edge SafeSearch"] = $EdgeSafeSearch
        $Categories["Edge Guest Mode"] = $EdgeGuestMode
        $Categories["Edge Bookmark Bar"] = $EdgeBookmark
        $Categories["Edge Password Mgr"] = $EdgePassMgr
    }

    # Unload offline child hive only after ALL category checks that depend on it are complete
    if ($HiveLoaded) {
        [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 300
        reg.exe unload "HKU\OSGuardChildPolicy" 2>&1 | Out-Null
    }

    # Print two-column grid
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " CATEGORY STATUS GRID " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray
    if ($Categories.Values -contains "PENDING") {
        Write-Host "  Note: [PENDING] policies will be enforced when the child first logs in." -ForegroundColor Cyan
    }
    # Standalone Switch User note at the top of the grid (machine-wide policy)
    if ($Categories["Switch User"] -eq $true) {
        Write-Host "  [ENABLED]  Switch User -> HIDDEN for ALL users (machine-wide policy)." -ForegroundColor Yellow
        Write-Host "             Tip: Use Sign Out instead of Switch User when you need to change accounts." -ForegroundColor Yellow
    }
    $Keys = @($Categories.Keys) | Where-Object { $_ -ne "Switch User" }
    $i = 0
    while ($i -lt $Keys.Count) {
        $LeftKey = $Keys[$i]
        $LeftVal = $Categories[$LeftKey]
        $LeftStr = if ($LeftVal -eq $true) { "[ENABLED]  " } elseif ($LeftVal -eq $false) { "[DISABLED] " } elseif ($LeftVal -eq "PENDING") { "[PENDING]  " } else { "[UNKNOWN]  " }
        $LeftColor = if ($LeftVal -eq $true) { "Green" } elseif ($LeftVal -eq $false) { "DarkGray" } elseif ($LeftVal -eq "PENDING") { "Cyan" } else { "Yellow" }

        if ($i + 1 -lt $Keys.Count) {
            $RightKey = $Keys[$i + 1]
            $RightVal = $Categories[$RightKey]
            $RightStr = if ($RightVal -eq $true) { "[ENABLED]  " } elseif ($RightVal -eq $false) { "[DISABLED] " } elseif ($RightVal -eq "PENDING") { "[PENDING]  " } else { "[UNKNOWN]  " }
            $RightColor = if ($RightVal -eq $true) { "Green" } elseif ($RightVal -eq $false) { "DarkGray" } elseif ($RightVal -eq "PENDING") { "Cyan" } else { "Yellow" }
            Write-Host "  $LeftStr" -NoNewline -ForegroundColor $LeftColor
            Write-Host ("{0,-22}  " -f $LeftKey) -NoNewline -ForegroundColor $LeftColor
            Write-Host "$RightStr" -NoNewline -ForegroundColor $RightColor
            Write-Host ("{0,-22}" -f $RightKey) -ForegroundColor $RightColor
        } else {
            Write-Host ("  {0}{1,-22}" -f $LeftStr, $LeftKey) -ForegroundColor $LeftColor
        }
        $i += 2
    }
    Write-Host "=====================================================" -ForegroundColor DarkGray

    $script:CategoryGridCache = $Categories
    $script:CategoryGridTimestamp = Get-Date
    return $Categories
}

function Test-IntegrityStatus {
    # Returns $true if installed and hash matches; $false if tampered; $null if not installed
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    $IntegrityFile = Join-Path $InstallDir "integrity.sha256"
    if (-not (Test-Path $InstallScript)) { return $null }
    $ExpectedHash = $null
    try { $ExpectedHash = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardIntegrity" -ErrorAction Stop) } catch {}
    if (-not $ExpectedHash -and (Test-Path $IntegrityFile)) { $ExpectedHash = Get-Content -Path $IntegrityFile -Raw }
    if (-not $ExpectedHash) { return $null }
    $ActualHash = Get-FileHashSafe -Path $InstallScript
    return ($ExpectedHash.Trim() -eq $ActualHash.Trim())
}

function Test-Canary {
    <#
        Checks for the presence and integrity of the canary file.
        If the canary file is missing or its hash does not match, tampering is detected.
    #>
    if (-not (Test-Path $CanaryFile)) { return $false }
    if (-not (Test-Path $CanaryHashFile)) { return $false }
    try {
        $ExpectedHash = (Get-Content -Path $CanaryHashFile -Raw -ErrorAction Stop).Trim()
        $ActualHash = Get-FileHashSafe -Path $CanaryFile
        return ($ExpectedHash -eq $ActualHash)
    } catch { return $false }
}

function Set-Canary {
    <#
        Creates a hidden canary file with random content and stores its hash.
    #>
    try {
        $RandomBytes = [byte[]]::new(64)
        $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $Rng.GetBytes($RandomBytes)
        $Rng.Dispose()
        [System.IO.File]::WriteAllBytes($CanaryFile, $RandomBytes)
        (Get-Item $CanaryFile).Attributes = 'Hidden'
        $CanaryHash = Get-FileHashSafe -Path $CanaryFile
        Set-Content -Path $CanaryHashFile -Value $CanaryHash -Encoding UTF8 -Force -ErrorAction Stop
        # Harden canary files so they can't be tampered with by child
        Harden-FileACL -FilePath $CanaryFile
        Harden-FileACL -FilePath $CanaryHashFile
        Write-Log -Message "Canary file created and hardened." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create canary file: $_" -Type "WARN" -Color Yellow
    }
}

function Test-TaskSchedulerTamper {
    <#
        Detects if the Task Scheduler (Schedule) service has been tampered with (disabled).
        Returns $true if tampered, $false otherwise.
    #>
    try {
        $Svc = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Schedule" -Name "Start" -ErrorAction Stop
        if ($Svc.Start -eq 4) {
            Write-Log -Message "Task Scheduler service has been disabled (Start=4). Tamper detected!" -Type "SECURITY" -Color Red
            return $true
        }
    } catch {}
    return $false
}

function Test-TamperDetected {
    try {
        return (Get-ItemPropertyValue -Path $IntegrityRegPath -Name $TamperDetectedRegName -ErrorAction Stop) -eq 1
    } catch { return $false }
}

function Set-TamperDetected {
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name $TamperDetectedRegName -Value 1 -Type DWord -Force -ErrorAction Stop
        Write-Log -Message "Tamper detected flag SET in registry." -Type "SECURITY" -Color Red
    } catch {
        Write-Log -Message "Failed to set tamper detected flag: $_" -Type "ERROR" -Color Red
    }
}

function Clear-TamperDetected {
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name $TamperDetectedRegName -Value 0 -Type DWord -Force -ErrorAction Stop
        Write-Log -Message "Tamper detected flag CLEARED." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to clear tamper detected flag: $_" -Type "ERROR" -Color Red
    }
}

function Show-TamperLockoutScreen {
    <#
        Full-screen lockout that appears when tampering is detected.
        Kills explorer to hide the taskbar, shows a single always-on-top window
        with a red warning. Admin must enter the Parent Mode password to unlock.
        Also provides a button to view the last 50 log lines.
    #>
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

    # Hide taskbar / desktop by killing explorer for the current session only
    try {
        $CurrentSessionId = (Get-Process -Id $PID).SessionId
        $MyExplorer = Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $CurrentSessionId }
        if ($MyExplorer) { Stop-Process -Id $MyExplorer.Id -Force -ErrorAction SilentlyContinue }
    } catch {}

    $script:TamperUnlockSuccess = $false

    $form = New-Object System.Windows.Forms.Form
    $form.WindowState = 'Maximized'
    $form.FormBorderStyle = 'None'
    $form.TopMost = $true
    $form.BackColor = [System.Drawing.Color]::Black
    $form.StartPosition = 'CenterScreen'
    $form.KeyPreview = $true

    # Block Alt+F4 and Escape
    $form.Add_KeyDown({
        param($sender, $e)
        if ($e.Alt -and $e.KeyCode -eq [System.Windows.Forms.Keys]::F4) {
            $e.Handled = $true
            $e.SuppressKeyPress = $true
        }
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
            $e.Handled = $true
            $e.SuppressKeyPress = $true
        }
    })

    # Prevent closing unless the correct password was entered
    $form.Add_FormClosing({
        if ($script:TamperUnlockSuccess -ne $true) {
            $_.Cancel = $true
        }
    })

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "TAMPERING DETECTED`n`nADMIN REVIEW REQUIRED`n`n[$script:Branding] This system has been locked due to unauthorized modification.`nOnly an administrator can unlock this session."
    $label.ForeColor = [System.Drawing.Color]::Red
    $label.Font = New-Object System.Drawing.Font("Consolas", 24, [System.Drawing.FontStyle]::Bold)
    $label.AutoSize = $false
    $label.TextAlign = 'MiddleCenter'
    $label.Dock = 'Fill'
    $form.Controls.Add($label)

    $pwPanel = New-Object System.Windows.Forms.Panel
    $pwPanel.Dock = 'Bottom'
    $pwPanel.Height = 120
    $pwPanel.BackColor = [System.Drawing.Color]::DarkRed

    $pwLabel = New-Object System.Windows.Forms.Label
    $pwLabel.Text = "Admin Password:"
    $pwLabel.ForeColor = [System.Drawing.Color]::White
    $pwLabel.Font = New-Object System.Drawing.Font("Consolas", 16)
    $pwLabel.AutoSize = $true
    $pwLabel.Location = New-Object System.Drawing.Point(50, 30)

    $pwBox = New-Object System.Windows.Forms.TextBox
    $pwBox.PasswordChar = '*'
    $pwBox.Font = New-Object System.Drawing.Font("Consolas", 16)
    $pwBox.Width = 350
    $pwBox.Location = New-Object System.Drawing.Point(300, 28)

    $unlockBtn = New-Object System.Windows.Forms.Button
    $unlockBtn.Text = "UNLOCK"
    $unlockBtn.Font = New-Object System.Drawing.Font("Consolas", 16, [System.Drawing.FontStyle]::Bold)
    $unlockBtn.BackColor = [System.Drawing.Color]::Black
    $unlockBtn.ForeColor = [System.Drawing.Color]::Red
    $unlockBtn.Size = New-Object System.Drawing.Size(150, 40)
    $unlockBtn.Location = New-Object System.Drawing.Point(680, 25)
    $unlockBtn.Add_Click({
        $pw = $pwBox.Text
        $StoredHash = $null
        $StoredSalt = $null
        # Child session cannot read the hardened registry key, so read from the hardened hash file instead
        $HashFile = Join-Path $InstallDir "parent.hash"
        if (Test-Path $HashFile) {
        $Content = Get-Content -Path $HashFile -Raw -ErrorAction SilentlyContinue
            if ($Content) {
                $Parts = $Content.Trim() -split '\|'
                if ($Parts.Count -ge 2) { $StoredHash = $Parts[0]; $StoredSalt = $Parts[1] }
                if ($Parts.Count -ge 3) { $StoredIterations = [int]$Parts[2] } else { $StoredIterations = 100000 }
            }
        }
        # Fallback to registry if file is missing (admin session)
        if (-not $StoredHash -or -not $StoredSalt) {
            try { $StoredHash = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardParentPasswordHash" -ErrorAction Stop) } catch {}
            try { $StoredSalt = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardParentPasswordSalt" -ErrorAction Stop) } catch {}
            try { $StoredIterations = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardParentPasswordIterations" -ErrorAction Stop) } catch {}
        }
        if ($StoredHash -and $StoredSalt) {
            # Inline PBKDF2 for the lockout screen (self-contained)
            $SaltBytes = [Convert]::FromBase64String($StoredSalt)
            $Derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($pw, $SaltBytes, $StoredIterations)
            $HashBytes = $Derive.GetBytes(32)
            $Derive.Dispose()
            $InputHash = [Convert]::ToBase64String($HashBytes)
            if ($InputHash -eq $StoredHash) {
                Clear-TamperDetected
                # Clean up the scheduled task that triggered this lockout
                if (Get-ScheduledTask -TaskName "OSGuard-TamperLockout" -ErrorAction SilentlyContinue) {
                    Unregister-ScheduledTask -TaskName "OSGuard-TamperLockout" -Confirm:$false | Out-Null
                }
                [System.Windows.Forms.MessageBox]::Show("Tamper lockout cleared. Restarting Windows UI...", "Unlocked", "OK", "Information") | Out-Null
                try {
                    $CurrentSessionId = (Get-Process -Id $PID).SessionId
                    $MyExplorer = Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $CurrentSessionId }
                    if ($MyExplorer) { Stop-Process -Id $MyExplorer.Id -Force -ErrorAction SilentlyContinue }
                } catch {}
                Start-Sleep -Seconds 1
                Start-Process "explorer" -ErrorAction SilentlyContinue
                $script:TamperUnlockSuccess = $true
                $form.Close()
            } else {
                [System.Windows.Forms.MessageBox]::Show("Incorrect password. Tamper lockout remains active.", "Access Denied", "OK", "Error") | Out-Null
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("No admin password configured. Unlock from admin account using 'oslock -ParentMode'.", "Access Denied", "OK", "Error") | Out-Null
        }
    })

    $logsBtn = New-Object System.Windows.Forms.Button
    $logsBtn.Text = "VIEW LOGS"
    $logsBtn.Font = New-Object System.Drawing.Font("Consolas", 16)
    $logsBtn.BackColor = [System.Drawing.Color]::Black
    $logsBtn.ForeColor = [System.Drawing.Color]::White
    $logsBtn.Size = New-Object System.Drawing.Size(150, 40)
    $logsBtn.Location = New-Object System.Drawing.Point(850, 25)
    $logsBtn.Add_Click({
        if (Test-Path $LogFile) {
            $logs = Get-Content -Path $LogFile -Tail 50 -Raw
            [System.Windows.Forms.MessageBox]::Show($logs, "OS-Guard Logs (Last 50 Lines)", "OK", "Information") | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show("No log file found at $LogFile", "Logs", "OK", "Warning") | Out-Null
        }
    })

    $pwPanel.Controls.Add($pwLabel)
    $pwPanel.Controls.Add($pwBox)
    $pwPanel.Controls.Add($unlockBtn)
    $pwPanel.Controls.Add($logsBtn)
    $form.Controls.Add($pwPanel)

    $form.Add_Shown({ $form.Activate(); $form.TopMost = $true })

    [void]$form.ShowDialog()

    # Clean up the temporary scheduled task that triggered this lockout
    if (Get-ScheduledTask -TaskName "OSGuard-TamperLockout" -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName "OSGuard-TamperLockout" -Confirm:$false | Out-Null
    }

    # SAFE LOCK FALLBACK: If the form closed without a successful unlock,
    # forcibly re-lock the system to prevent a child from exploiting an accidental close.
    if ($script:TamperUnlockSuccess -ne $true) {
        Write-Log -Message "Tamper lockout screen closed without unlock. Initiating safe re-lock..." -Type "SECURITY" -Color Red
        try {
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
        } catch {}
        try { Stop-WindowGuard } catch {}
        try { Enable-OSLock } catch {}
        try { Enable-DNSLock } catch {}
        try {
            $CurrentSessionId = (Get-Process -Id $PID).SessionId
            $MyExplorer = Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $CurrentSessionId }
            if ($MyExplorer) { Stop-Process -Id $MyExplorer.Id -Force -ErrorAction SilentlyContinue }
        } catch {}
        Start-Sleep -Seconds 1
    }

    # Ensure explorer is running only in an interactive session (never from Session 0 / SYSTEM)
    $CurrentSessionId = (Get-Process -Id $PID).SessionId
    if ($CurrentSessionId -ne 0) {
        Start-Process "explorer" -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# 10. INSTALLER / PERSISTENCE MODULE (HARDENED)
# ============================================================================

function Set-ConsoleCloseButton {
    param([bool]$Enable)
    <#
        Removes or restores the console window close button (X) using Win32 API.
        Strips/restores WS_SYSMENU style to prevent accidental closure during critical operations.
        Also disables Ctrl+C in the current session (not system-wide) using both console mode
        and SetConsoleCtrlHandler. In Windows Terminal the tab close button cannot be removed
        from the child process, but Ctrl+C is blocked.
    #>
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ConsoleWindow {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll", SetLastError = true)]
    public static extern int GetWindowLong(IntPtr hWnd, int nIndex);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
    public delegate bool HandlerRoutine(uint dwCtrlType);
    [DllImport("kernel32.dll")]
    public static extern bool SetConsoleCtrlHandler(HandlerRoutine handler, bool add);
    [DllImport("kernel32.dll")]
    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetStdHandle(int nStdHandle);
}
"@ -ErrorAction SilentlyContinue
        $hWnd = [ConsoleWindow]::GetConsoleWindow()
        $GWL_STYLE = -16
        $WS_SYSMENU = 0x00080000
        $style = [ConsoleWindow]::GetWindowLong($hWnd, $GWL_STYLE)
        if ($Enable) {
            [ConsoleWindow]::SetWindowLong($hWnd, $GWL_STYLE, $style -bor $WS_SYSMENU) | Out-Null
            [Console]::TreatControlCAsInput = $false
        } else {
            [ConsoleWindow]::SetWindowLong($hWnd, $GWL_STYLE, $style -band -bnot $WS_SYSMENU) | Out-Null
            [Console]::TreatControlCAsInput = $true
        }
        $STD_INPUT_HANDLE = -10
        $ENABLE_PROCESSED_INPUT = 0x0001
        $hStdIn = [ConsoleWindow]::GetStdHandle($STD_INPUT_HANDLE)
        if ($Enable) {
            [ConsoleWindow]::SetConsoleMode($hStdIn, $ENABLE_PROCESSED_INPUT) | Out-Null
        } else {
            [ConsoleWindow]::SetConsoleMode($hStdIn, 0) | Out-Null
        }
    } catch {}
}

function Install-Persistence {
    Write-Log -Message "Installing OS-Guard to System ($InstallDir`)..." -Type "ACTION" -Color Yellow

    # Prevent accidental window closure during install
    Set-ConsoleCloseButton -Enable $false


    # 0. Installation Gate: Prevent overwriting existing installs
    # Stale-task repair: if the scheduled task exists but the installed script is missing, auto-remove the stale task and continue.
    $TaskExists = $false
    try { $TaskExists = [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop) } catch { $TaskExists = $false }
    if ($TaskExists -and -not (Test-Path $InstallScript)) {
        Write-Log -Message "Stale task '$TaskName' found without installed script. Auto-removing stale task and continuing installation..." -Type "WARN" -Color Yellow
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop | Out-Null
        } catch {
            Start-Process -FilePath "schtasks.exe" -ArgumentList "/delete", "/tn", $TaskName, "/f" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Log -Message "Stale task removed. Proceeding with fresh install." -Type "INFO" -Color Green
    }
    if (Test-Path $InstallScript) {
        Write-Log -Message "Installation aborted: $InstallScript already exists." -Type "ERROR" -Color Red
        Write-Host '[ERROR] OS-Guard is already installed. Uninstall first.' -ForegroundColor Red
        return
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Write-Log -Message "Installation aborted: Scheduled task '$TaskName' already exists." -Type "ERROR" -Color Red
        Write-Host '[ERROR] OS-Guard is already installed. Uninstall first.' -ForegroundColor Red
        return
    }

    # Force log off child session to unlock NTUSER.DAT and prevent blank desktop during install
    Invoke-ChildLogoff

    # 1. Secure Copy
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    } else {
        # Reset hardened ACLs from a previous install so we can write files
        Write-Log -Message "Resetting ACLs on existing $InstallDir..." -Type "INFO" -Color Yellow
        try {
            $proc = Start-Process -FilePath "takeown.exe" -ArgumentList "/F", $InstallDir, "/R", "/D", "Y" -Wait -WindowStyle Hidden -PassThru
            if ($proc.ExitCode -eq 0) { Write-Log -Message "Ownership reset on $InstallDir." -Type "INFO" -Color Gray } else { Write-Log -Message "takeown exit $($proc.ExitCode)" -Type "WARN" -Color Yellow }
        } catch { Write-Log -Message "takeown failed: $_" -Type "WARN" -Color Yellow }
        try {
            $proc = Start-Process -FilePath "icacls.exe" -ArgumentList $InstallDir, "/reset", "/T", "/C" -Wait -WindowStyle Hidden -PassThru
            if ($proc.ExitCode -eq 0) { Write-Log -Message "ACLs reset on $InstallDir." -Type "INFO" -Color Gray } else { Write-Log -Message "icacls exit $($proc.ExitCode)" -Type "WARN" -Color Yellow }
        } catch { Write-Log -Message "icacls failed: $_" -Type "WARN" -Color Yellow }
        try {
            $proc = Start-Process -FilePath "icacls.exe" -ArgumentList $InstallDir, "/grant:r", "BUILTIN\Administrators:(OI)(CI)F", "/T", "/C" -Wait -WindowStyle Hidden -PassThru
            if ($proc.ExitCode -eq 0) { Write-Log -Message "Admin full control restored on $InstallDir." -Type "INFO" -Color Gray } else { Write-Log -Message "icacls grant exit $($proc.ExitCode)" -Type "WARN" -Color Yellow }
        } catch { Write-Log -Message "icacls grant failed: $_" -Type "WARN" -Color Yellow }
    }
    Copy-Item -Path $PSCommandPath -Destination $InstallScript -Force
    Write-Log -Message "Payload copied to $InstallScript." -Type "INFO" -Color Gray

    # Pre-build wrapper content and create all files inside $InstallDir BEFORE hardening ACLs
    $CmdBatContent = "@echo off`r`npwsh.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallScript`" %*"
    $CmdPathLocal = Join-Path $InstallDir "oslock.cmd"
    Out-File -FilePath $CmdPathLocal -InputObject $CmdBatContent -Encoding ASCII -Force
    Write-Log -Message "Local wrapper created at $CmdPathLocal." -Type "INFO" -Color Gray

    # Pre-calculate integrity hash and write backup file before hardening
    $ScriptHash = Get-FileHashSafe -Path $InstallScript
    $IntegrityFile = Join-Path $InstallDir "integrity.sha256"
    Set-Content -Path $IntegrityFile -Value $ScriptHash -Encoding UTF8 -Force
    Write-Log -Message "Self-integrity hash file written." -Type "INFO" -Color Gray


    # 2. Build the Global CLI Command (oslock) in C:\Windows (ASCII encoding, no BOM)
    Out-File -FilePath $CmdPath -InputObject $CmdBatContent -Encoding ASCII -Force
    if (-not (Test-Path $CmdPath)) {
        Write-Log -Message "CRITICAL: Wrapper file was not created at $CmdPath!" -Type "ERROR" -Color Red
    } else {
        Write-Log -Message "Global CLI wrapper created at $CmdPath." -Type "SUCCESS" -Color Green
    }

    # 2.2 Add InstallDir to system PATH so oslock is discoverable from any shell
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
    Write-Log -Message "Hardening oslock wrapper files..." -Type "INFO" -Color Yellow
    $SidUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
    foreach ($WrapperPath in @($CmdPath, $CmdPathLocal)) {
        if (Test-Path $WrapperPath) {
            try {
                $CmdAcl = Get-Acl -Path $WrapperPath
                $CmdAcl.SetOwner($SidSystem)
                $CmdAcl.SetAccessRuleProtection($true, $false)
                $CmdAcl.Access | ForEach-Object { $CmdAcl.RemoveAccessRule($_) | Out-Null }
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Write", "None", "None", "Allow")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "None", "None", "Allow")))
                Set-Acl -Path $WrapperPath -AclObject $CmdAcl
            } catch {
                Write-Log -Message "Failed to harden wrapper ACLs for $WrapperPath`: $_" -Type "ERROR" -Color Red
            }
        }
    }
    Write-Log -Message "Wrapper files locked to SYSTEM (FullControl), Admins (ReadOnly+NoDelete), Users (ReadAndExecute)." -Type "SUCCESS" -Color Green

    Write-Log -Message "Registering self-healing background tasks..." -Type "INFO" -Color Yellow

    # 3. Main task: Run at System Startup, User Logon, and Event ID 10000 (Network Connected)
    $Action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
    $Trigger1 = New-ScheduledTaskTrigger -AtStartup

    $CimClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace "Root/Microsoft/Windows/TaskScheduler"
    $Trigger3 = New-CimInstance -CimClass $CimClass -ClientOnly
    $Trigger3.Subscription = "<QueryList><Query Id='0' Path='Microsoft-Windows-NetworkProfile/Operational'><Select Path='Microsoft-Windows-NetworkProfile/Operational'>*[System[EventID=10000]]</Select></Query></QueryList>"
    $Trigger3.Enabled = $True

    $PrincipalSettings = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger @($Trigger1, $Trigger3) -Principal $PrincipalSettings -Force | Out-Null
    Write-Log -Message "Registered Main Task: auto-heal on Reboot & Network Change." -Type "INFO" -Color Gray

    # 4. Guardian 1: Monitors every 5 minutes and restores if tampered
    $GuardianAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
    $GuardianTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
    $GuardianPrincipal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $Guardian1Name -Action $GuardianAction -Trigger $GuardianTrigger -Principal $GuardianPrincipal -Force | Out-Null
    Write-Log -Message "Guardian 1 '$Guardian1Name' registered `(5-minute heartbeat)." -Type "INFO" -Color Gray


    # 4.1 Guardian 2: Additional watcher with a 10-minute interval
    $Guardian2Action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
    $Guardian2Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 9999)
    $Guardian2Principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $Guardian2Name -Action $Guardian2Action -Trigger $Guardian2Trigger -Principal $Guardian2Principal -Force | Out-Null
    Write-Log -Message "Guardian 2 '$Guardian2Name' registered `(10-minute heartbeat)." -Type "INFO" -Color Gray


    # 4.3 Program Guardian: scans and hardens newly installed programs every 10 minutes
    Install-ProgramGuardian

    # 4.5 Process Enforcer: live process enforcement (30-second heartbeat)
    Install-ProcessEnforcer

    # 4.4 WMI Event Subscription: Third hidden persistence layer
    Write-Log -Message "Registering WMI event subscription for persistence..." -Type "INFO" -Color Gray
    try {
        $WmiFilterExists = Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue
        $WmiConsumerExists = Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue
        $WmiBindingExists = Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" -Filter "__PATH LIKE '%$WmiEventName%'" -ErrorAction SilentlyContinue
        if ($WmiFilterExists -and $WmiConsumerExists -and $WmiBindingExists) {
            Write-Log -Message "WMI subscription already exists. Skipping registration." -Type "INFO" -Color Gray
        } else {
            $WmiQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name = 'Schedule'"
            $WmiConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$WmiEventName; CommandLineTemplate="pwsh.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"; RunInteractively=$false} -ErrorAction Stop
            $WmiFilter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{Name=$WmiEventName; EventNamespace="root\cimv2"; QueryLanguage="WQL"; Query=$WmiQuery} -ErrorAction Stop
            Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$WmiFilter; Consumer=$WmiConsumer} -ErrorAction Stop | Out-Null
            Write-Log -Message "WMI subscription registered (triggers if Schedule service is modified)." -Type "SUCCESS" -Color Green
        }
    } catch {
        Write-Log -Message "WMI subscription registration failed: $_" -Type "WARN" -Color Yellow
    }

    # 5. Self-Integrity: Store SHA256 hash in a misleading registry key
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
    Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardIntegrity" -Value $ScriptHash -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Self-integrity hash stored in registry (backup file already written)." -Type "INFO" -Color Gray

    # 6. Apply ALL locks immediately (DNS + OS + child account)
    Enable-DNSLock
    Enable-OSLock

    # 6.0 Create child-facing shortcuts on the child desktop (only during install, not during every re-lock)
    New-ParentModeShortcut
    New-GrantBrowserTimeShortcut
    New-ChildLockNowShortcut
    New-ChildContinueParentModeShortcut
    New-ChildApproveInstallShortcut

    # 6.0 Child Logon Task: Applies HKCU policies in the child's own session at logon.
    # Runs as the child user (no elevation) so it writes to the live HKCU hive.
    # NOTE: Moved here so the child account is created by Enable-OSLock before we register the task.
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue) {
        try {
            $ChildAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -ChildLock -ChildUser `"$ChildUser`""
            $ChildTrigger = New-ScheduledTaskTrigger -AtLogOn
            $ChildTrigger.UserId = $ChildUser
            $ChildPrincipalObj = New-ScheduledTaskPrincipal -UserId $ChildUser -LogonType Interactive -RunLevel Limited
            Register-ScheduledTask -TaskName $ChildLogonTaskName -Action $ChildAction -Trigger $ChildTrigger -Principal $ChildPrincipalObj -Force | Out-Null
            Write-Log -Message "Child Logon Task '$ChildLogonTaskName' registered (applies HKCU at child logon)." -Type "SUCCESS" -Color Green
        } catch {
            Write-Log -Message "Failed to register child logon task: $_" -Type "WARN" -Color Yellow
        }
    } else {
        Write-Log -Message "Child account not available after Enable-OSLock - child logon task will be created on next silent heal." -Type "WARN" -Color Yellow
    }

    # 6.0.1 Child Access Log Task: Runs as SYSTEM on child logon to record timestamp and update hash.
    try {
        $AccessLogAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -ChildAccessLog -ChildUser `"$ChildUser`""
        $AccessLogTrigger = New-ScheduledTaskTrigger -AtLogOn
        $AccessLogTrigger.UserId = $ChildUser
        $AccessLogPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "OSGuard-ChildAccessLog" -Action $AccessLogAction -Trigger $AccessLogTrigger -Principal $AccessLogPrincipal -Force | Out-Null
        Write-Log -Message "Child Access Log task registered (SYSTEM on child logon)." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to register child access log task: $_" -Type "WARN" -Color Yellow
    }

    # 6.0.2 Process Enforcer Child-Logon Trigger: Runs as SYSTEM on child logon to immediately start the continuous Process Enforcer.
    # The child logon task (6.0) runs as the child user and cannot start a SYSTEM task, so this dedicated SYSTEM trigger ensures
    # the process killer is active within seconds of the child logging in.
    try {
        $PEChildLogonAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command try { Start-ScheduledTask -TaskName $ProcessEnforcerName -ErrorAction SilentlyContinue } catch {}"
        $PEChildLogonTrigger = New-ScheduledTaskTrigger -AtLogOn
        $PEChildLogonTrigger.UserId = $ChildUser
        $PEChildLogonPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "OSGuard-ProcessEnforcer-ChildLogon" -Action $PEChildLogonAction -Trigger $PEChildLogonTrigger -Principal $PEChildLogonPrincipal -Force | Out-Null
        Write-Log -Message "Process Enforcer child-logon trigger registered (SYSTEM on child logon)." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to register Process Enforcer child-logon trigger: $_" -Type "WARN" -Color Yellow
    }

    # 6.1 Initialize ScreenTime config and watcher if not already present
    if (-not (Test-Path $ScreenTimeConfigFile)) {
        Set-ScreenTimeConfig -DailyStart "08:00" -DailyEnd "20:00" -DailyMaxMinutes 120 -BrowserMaxMinutes 60 -WeekendDailyMaxMinutes 180 -WeekendBrowserMaxMinutes 90 -Enabled $true
    }
    Install-ScreenTimeWatcher

    # 7. Set default Parent Mode password and create requests directory
    Write-Log -Message "Setting default Parent Mode password and creating requests directory..." -Type "INFO" -Color Yellow
    try {
        if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeAFKTimeout" -Value 5 -Type DWord -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to set default AFK timeout: $_" -Type "WARN" -Color Yellow
    }
    $DefaultPw = New-MemorablePassword
    Write-Host "`n╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║                   PARENT MODE PASSWORD GENERATED                     ║" -ForegroundColor Magenta
    Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host "  Your default Parent Mode password is: " -NoNewline -ForegroundColor White
    Write-Host "$DefaultPw" -ForegroundColor Black -BackgroundColor Yellow
    Write-Host "`n  *** WRITE THIS DOWN NOW! ***" -ForegroundColor Red
    Write-Host "  You will need it to enter Parent Mode and approve installations." -ForegroundColor Cyan
    Write-Host "  Pattern: Word + Number + Easy symbol  (e.g., Dragon42`!)" -ForegroundColor DarkGray
    Write-Host "  Change anytime via menu option [12] or 'oslock -SetParentPassword'." -ForegroundColor DarkGray
    $SaltStr = Get-PBKDF2Salt
    $HashStr = New-PBKDF2Hash -Password $DefaultPw -SaltBase64 $SaltStr -Iterations 100000
    try {
        if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordHash" -Value $HashStr -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordSalt" -Value $SaltStr -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordIterations" -Value 100000 -Type DWord -Force -ErrorAction Stop
        Write-Log -Message "Default Parent Mode password set (change it with 'oslock -SetParentPassword')." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to set default Parent Mode password: $_" -Type "WARN" -Color Yellow
    }

    # 7.1 Create Canary file for tamper detection
    Write-Log -Message "Creating canary file for tamper detection..." -Type "INFO" -Color Yellow
    Set-Canary
    $RequestDir = Join-Path $InstallDir "Requests"
    if (-not (Test-Path $RequestDir)) { New-Item -ItemType Directory -Path $RequestDir -Force -ErrorAction SilentlyContinue | Out-Null }
    try {
        $RequestsDirAcl = Get-Acl -Path $RequestDir
        $RequestsDirAcl.SetOwner($SidSystem)
        $RequestsDirAcl.SetAccessRuleProtection($true, $false)
        $RequestsDirAcl.Access | ForEach-Object { $RequestsDirAcl.RemoveAccessRule($_) | Out-Null }
        $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "DeleteSubdirectoriesAndFiles", "ContainerInherit,ObjectInherit", "None", "Deny")))
        # Child user: WriteData only (can create request files, cannot read/list/delete)
        $ChildSidValue = Get-ChildSid
        if ($ChildSidValue) {
            $ChildSidObj = New-Object System.Security.Principal.SecurityIdentifier($ChildSidValue)
            $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($ChildSidObj, "WriteData, AppendData", "ContainerInherit,ObjectInherit", "None", "Allow")))
            $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($ChildSidObj, "Delete", "ContainerInherit,ObjectInherit", "None", "Deny")))
            $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($ChildSidObj, "DeleteSubdirectoriesAndFiles", "ContainerInherit,ObjectInherit", "None", "Deny")))
        }
        Set-Acl -Path $RequestDir -AclObject $RequestsDirAcl -ErrorAction Stop
    } catch {
        Write-Log -Message "Failed to harden Requests directory ACL: $_" -Type "WARN" -Color Yellow
    }

    # 8. Register Parent Mode AFK Watcher (1-minute dead man's switch)
    Write-Log -Message 'Registering Parent Mode AFK watcher (1-minute heartbeat) ...' -Type "INFO" -Color Yellow

    $WatchScriptPath = Join-Path $InstallDir "ParentModeWatch.ps1"
    try {
        $WatchScriptContent = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ParentModeWatchB64))
        Set-Content -Path $WatchScriptPath -Value $WatchScriptContent -Encoding UTF8 -Force
        $WatchAcl = Get-Acl -Path $WatchScriptPath
        $WatchAcl.SetOwner($SidSystem)
        $WatchAcl.SetAccessRuleProtection($true, $false)
        $WatchAcl.Access | ForEach-Object { $WatchAcl.RemoveAccessRule($_) | Out-Null }
        $WatchAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $WatchAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
        Set-Acl -Path $WatchScriptPath -AclObject $WatchAcl -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to write ParentModeWatch script: $_" -Type "WARN" -Color Yellow
    }
    $WatchAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$WatchScriptPath`""
    $WatchTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
    $WatchPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $ParentModeWatchName -Action $WatchAction -Trigger $WatchTrigger -Principal $WatchPrincipal -Force | Out-Null
    Write-Log -Message 'Parent Mode AFK watcher registered (1-minute heartbeat, 1-minute idle timeout).' -Type "INFO" -Color Gray


    # 8.1 Create Temp Unlock Timer script
    New-TempUnlockTimerScript

    # --- NTFS PAYLOAD SELF-DEFENSE (runs after all files are written) ---
    Write-Log -Message "Hardening NTFS Permissions on installation directory and files..." -Type "INFO" -Color Yellow
    try {
        $SidUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")

        # Set owner to SYSTEM on directory and all existing files
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
        # Admins: Write + ReadAndExecute (can update configs, but cannot delete directory or change permissions)
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Write", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Delete", "ContainerInherit,ObjectInherit", "None", "Deny")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "ContainerInherit,ObjectInherit", "None", "Deny")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "ContainerInherit,ObjectInherit", "None", "Deny")))
        # Authenticated Users: ReadAndExecute
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))

        Set-Acl -Path $InstallDir -AclObject $DirAcl

        # Explicitly harden each file
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

    Write-Log -Message "INSTALLATION COMPLETE! System is permanently protected." -Type "SUCCESS" -Color Green

    # Force Group Policy refresh so any domain/local GPO changes take effect immediately
    Write-Log -Message "Forcing Group Policy update (gpupdate /force) after installation..." -Type "INFO" -Color Yellow
    try {
        $gpOutput = gpupdate /force 2>&1
        Write-Log -Message "Group Policy update completed successfully." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to execute gpupdate /force: $_" -Type "WARN" -Color Yellow
    }

    # Final status verification
    $FailedCount = 0
    if (-not (Test-Path $InstallDir)) { $FailedCount++; Write-Log -Message "Install directory $InstallDir missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $InstallScript)) { $FailedCount++; Write-Log -Message "Install script $InstallScript missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $CmdPath)) { $FailedCount++; Write-Log -Message "Global CLI wrapper $CmdPath missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $IntegrityFile)) { $FailedCount++; Write-Log -Message "Integrity file $IntegrityFile missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Main task $TaskName missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $Guardian1Name -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Guardian 1 $Guardian1Name missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $Guardian2Name -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Guardian 2 $Guardian2Name missing." -Type "ERROR" -Color Red }
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($CurrentPath -notlike "*$InstallDir*") { $FailedCount++; Write-Log -Message "System PATH does not contain $InstallDir." -Type "ERROR" -Color Red }
    if (-not (Get-ChildAccount)) { $FailedCount++; Write-Log -Message "Child account '$ChildUser' not created." -Type "ERROR" -Color Red }
    # Use SID-based profile lookup for consistency with shortcut creation functions.
    # Child shortcuts are only created by Enable-OSLock when the profile is already in WMI.
    # If the profile hasn't been logged in yet, they are deferred to the ChildLogon task.
    $ChildProfilePath = Get-ChildProfilePath
    $DesktopPath = if ($ChildProfilePath) { Join-Path $ChildProfilePath "Desktop" } else { $null }
    if ($DesktopPath -and (Test-Path $DesktopPath)) {
        # Child-facing shortcuts (created at install time by Enable-OSLock only if profile exists)
        $ExpectedChildShortcuts = @("Log out.lnk", "Request Game Install.lnk", "Browser Request.lnk", "Admin Request.lnk")
        foreach ($ScName in $ExpectedChildShortcuts) {
            if (-not (Test-Path (Join-Path $DesktopPath $ScName))) { $FailedCount++; Write-Log -Message "Shortcut '$ScName' for '$ChildUser' not found." -Type "ERROR" -Color Red }
        }
        # Parent/admin shortcuts (created at install time by New-ParentModeShortcut / New-GrantBrowserTimeShortcut)
        $ExpectedAdminShortcuts = @("Parent Mode.lnk", "Lock Now.lnk", "Continue Parent Mode.lnk", "Approve Child Install.lnk", "Grant Browser Time.lnk")
        foreach ($ScName in $ExpectedAdminShortcuts) {
            if (-not (Test-Path (Join-Path $DesktopPath $ScName))) { $FailedCount++; Write-Log -Message "Admin shortcut '$ScName' not found on child desktop." -Type "ERROR" -Color Red }
        }
    } else {
        # Profile not in WMI yet (child never logged in). Child shortcuts are deferred to first logon.
        # Admin shortcuts may have been created at the fallback path; verify them there.
        Write-Log -Message "Child profile not found yet - child shortcuts will be verified at first child logon." -Type "INFO" -Color Gray
        $FallbackDesktop = Join-Path "C:\Users\$ChildUser" "Desktop"
        if (Test-Path $FallbackDesktop) {
            $ExpectedAdminShortcuts = @("Parent Mode.lnk", "Lock Now.lnk", "Continue Parent Mode.lnk", "Approve Child Install.lnk", "Grant Browser Time.lnk")
            foreach ($ScName in $ExpectedAdminShortcuts) {
                if (-not (Test-Path (Join-Path $FallbackDesktop $ScName))) { $FailedCount++; Write-Log -Message "Admin shortcut '$ScName' not found on fallback desktop." -Type "ERROR" -Color Red }
            }
        } else {
            Write-Log -Message "Admin desktop not found yet - admin shortcuts will be verified at first child logon." -Type "INFO" -Color Gray
        }
    }
    if (-not (Get-ScheduledTask -TaskName $ParentModeWatchName -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Parent Mode watch task $ParentModeWatchName missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path (Join-Path $InstallDir "Requests"))) { $FailedCount++; Write-Log -Message "Requests directory missing." -Type "ERROR" -Color Red }
    if ($FailedCount -eq 0) {
        Write-Host '[SUCCESS] INSTALLATION COMPLETE!' -ForegroundColor Green

    } else {
        Write-Host "[PARTIAL] INSTALLATION COMPLETE WITH ERRORS`! ($FailedCount items missing)" -ForegroundColor Yellow

    }

    # Re-enable close button after install completes
    Set-ConsoleCloseButton -Enable $true
}

function Invoke-AsSystem {
    param([string]$Command)
    $TempTaskName = "OSGuard-Uninstall-Helper"
    $CommonTemp = "C:\Windows\Temp"
    $ResultFile = "$CommonTemp\OSGuard_CleanupResult.txt"
    $TempScript = "$CommonTemp\OSGuard_Cleanup.ps1"
    Write-Host "`[DEBUG] Invoke-AsSystem called. CommonTemp=$CommonTemp" -ForegroundColor Yellow

    try {
        # Ensure SYSTEM can write to the common temp directory
        $TempAcl = Get-Acl -Path $CommonTemp
        $SystemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $TempAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SystemSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl -Path $CommonTemp -AclObject $TempAcl -ErrorAction SilentlyContinue
        # Write the cleanup command to a temporary script file with error capture
        $ScriptContent = "try { `$ErrorActionPreference = 'Stop'; $Command; 'SUCCESS' | Out-File -FilePath '$ResultFile' -Encoding UTF8 -Force } catch { `$_.Exception.Message | Out-File -FilePath '$ResultFile' -Encoding UTF8 -Force }"
        $ScriptContent | Out-File -FilePath $TempScript -Encoding UTF8 -Force
        Write-Host "`[DEBUG] Temp script written to $TempScript" -ForegroundColor Yellow

        # Use full PowerShell path and execute the temp script
        $Action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-ExecutionPolicy Bypass -File `"$TempScript`""
        $Principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TempTaskName -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $TempTaskName
        Write-Host '[DEBUG] SYSTEM task started. Waiting for completion...' -ForegroundColor Yellow

        # Wait up to 30 seconds
        $MaxWait = 30
        $Waited = 0
        while ($Waited -lt $MaxWait) {
            Start-Sleep -Seconds 2
            $Waited += 2
            $Task = Get-ScheduledTask -TaskName $TempTaskName -ErrorAction SilentlyContinue
            if (-not $Task) { break }
        }
        Unregister-ScheduledTask -TaskName $TempTaskName -Confirm:$false | Out-Null
        Write-Host '[DEBUG] SYSTEM task completed and unregistered.' -ForegroundColor Yellow

        if (Test-Path $ResultFile) {
            $Result = Get-Content -Path $ResultFile -Raw
            Write-Host "`[DEBUG] SYSTEM task result: $Result" -ForegroundColor Yellow

            Remove-Item -Path $ResultFile -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "`[DEBUG] No result file found at $ResultFile" -ForegroundColor Red

        }
        Remove-Item -Path $TempScript -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "SYSTEM helper task failed: $_" -Type "ERROR" -Color Red
        Remove-Item -Path $ResultFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $TempScript -Force -ErrorAction SilentlyContinue
    }
}

function Uninstall-Persistence {
    # Exit early if nothing is installed
    $IsInstalled = (Test-Path $InstallDir) -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    if (-not $IsInstalled) {
        Write-Host '[WARN] OS-Guard is not installed. Nothing to uninstall.' -ForegroundColor Yellow

        return
    }

    # Prevent accidental window closure during uninstall
    Set-ConsoleCloseButton -Enable $false

    Write-Log -Message "Uninstalling OS-Guard from System..." -Type "ACTION" -Color Yellow

    # Force log off child session to unlock NTUSER.DAT and allow clean uninstall
    Invoke-ChildLogoff

    # Suppress auto-directory-creation in Write-Log so we can cleanly delete the install dir
    $script:SuppressLogDirCreation = $true

    # Stop any running Window Guard process
    Stop-WindowGuard
    Stop-TempUnlockTimer

    # Unlock everything FIRST (DNS + OS)
    Disable-DNSLock
    Disable-OSLock

    # Nuclear cleanup: clear all machine-wide AppLocker/SRP policies that may block all users
    Clear-AllAppLockerAndSRP

    # Remove OOBE block so child gets normal first-logon experience after uninstall
    Remove-OOBEBlock

    # Restore auto-login credentials so the system can fall back to normal credential prompt
    Restore-AutoAdminLogon
    # Remove child-facing shortcuts and admin tools (Disable-OSLock already handles most of these)
    Remove-ChildGameRequestShortcut
    Remove-AdminRequestShortcut
    Remove-ParentModeShortcut
    Remove-ParentModeAdminTools
    Remove-GrantBrowserTimeShortcut
    Remove-AdminOnlyLogoutShortcut
    Remove-ChildLockNowShortcut
    Remove-ChildContinueParentModeShortcut
    Remove-ChildApproveInstallShortcut

    # Clean up child OOBE flag from offline hive if live cleanup was missed
    $OfflineOOBEHive = Mount-ChildHive
    if ($OfflineOOBEHive) {
        try {
            $OOBEPath = "Registry::HKEY_USERS\$OfflineOOBEHive\Software\OSGuard"
            if (Test-Path $OOBEPath) {
                Remove-Item -Path $OOBEPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Removed child OOBE flag from offline hive during uninstall." -Type "INFO" -Color Gray
            }
        } catch {}
        Dismount-ChildHive -HiveMount $OfflineOOBEHive
    }

    # Remove file-based OOBE flag from child profile
    $ChildProfilePath = $null
    try {
        $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" -or $_.LocalPath -like "*\$ChildUser.*" } | Select-Object -First 1
        if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
    } catch {}
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    $ChildOOBEFile = Join-Path $ChildProfilePath ".OSGuardOOBE"
    if (Test-Path $ChildOOBEFile) {
        Remove-Item -Path $ChildOOBEFile -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Removed child OOBE file-based flag." -Type "INFO" -Color Gray
    }

    # Remove ScreenTime, whitelist, process enforcer, and hash files
    foreach ($STFile in @($ScreenTimeConfigFile, $ScreenTimeTrackerFile, $BrowserLauncherPath, $ProgramWhitelistFile, $BlockedProcessLogFile, $BlockedHashesFile)) {
        if (Test-Path $STFile) { Remove-Item -Path $STFile -Force -ErrorAction SilentlyContinue }
    }

    # Remove ChildUSBGuard script if not already removed by Disable-OSLock
    $GuardScriptPath = Join-Path $InstallDir "ChildUSBGuard.ps1"
    if (Test-Path $GuardScriptPath) { Remove-Item -Path $GuardScriptPath -Force -ErrorAction SilentlyContinue }

    # Remove Canary files
    foreach ($CFile in @($CanaryFile, $CanaryHashFile)) {
        if (Test-Path $CFile) { Remove-Item -Path $CFile -Force -ErrorAction SilentlyContinue }
    }

    # Remove admin session save file
    if (Test-Path $AdminSessionFile) { Remove-Item -Path $AdminSessionFile -Force -ErrorAction SilentlyContinue }

    # Remove firewall rules (fast PowerShell cmdlet instead of netsh show-all)
    Write-Log -Message "Removing OS-Guard firewall rules..." -Type "INFO" -Color Gray
    try {
        Get-NetFirewallRule -DisplayName "OSGuard-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Log -Message "Firewall rules removed." -Type "INFO" -Color Gray
    } catch { Write-Log -Message "Failed to remove firewall rules: $_" -Type "WARN" -Color Yellow }

    # Remove the Scheduled Tasks individually with fallback to schtasks.exe for stubborn/running tasks
    # Continuous tasks (ProcessEnforcer, ScreenTime, ChildUSBGuard) may be running and must be stopped
    # before Unregister-ScheduledTask will succeed.
    $TaskNamesToRemove = @($TaskName, $Guardian1Name, $Guardian2Name, $ChildLogonTaskName, $ParentModeWatchName, $ProgramScannerName, $ProcessEnforcerName, $ScreenTimeTaskName, "OSGuard-TamperLockout", "OSGuard-ApproveInstallReharden", "OSGuard-ChildAccessLog", "OSGuard-ProcessEnforcer-ChildLogon", "OSGuard-ChildUSBGuard")
    foreach ($tn in $TaskNamesToRemove) {
        $task = $null
        try { $task = Get-ScheduledTask -TaskName $tn -ErrorAction Stop } catch { $task = $null }
        if (-not $task) { continue }
        # Stop the task first if it is running; Unregister-ScheduledTask will fail on a running task
        try {
            Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Milliseconds 500
        } catch {}
        try {
            Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Log -Message "Removed task: $tn" -Type "INFO" -Color Gray
        } catch {
            # If the task is still running, try schtasks /end first, then /delete
            try {
                $procEnd = Start-Process -FilePath "schtasks.exe" -ArgumentList "/end", "/tn", "$tn" -Wait -WindowStyle Hidden -PassThru
                Start-Sleep -Milliseconds 500
                $proc = Start-Process -FilePath "schtasks.exe" -ArgumentList "/delete", "/tn", "$tn", "/f" -Wait -WindowStyle Hidden -PassThru
                if ($proc.ExitCode -eq 0) {
                    Write-Log -Message "Removed task (schtasks end+delete fallback): $tn" -Type "INFO" -Color Gray
                } else {
                    Write-Log -Message "Failed to remove task $tn (schtasks end exit $($procEnd.ExitCode), delete exit $($proc.ExitCode)): $_" -Type "WARN" -Color Yellow
                }
            } catch {
                Write-Log -Message "Failed to remove task $tn`: $_" -Type "WARN" -Color Yellow
            }
        }
    }

    # Remove child access log and hash files
    foreach ($ALFile in @($ChildAccessLogFile, $ChildAccessLogHashFile)) {
        if (Test-Path $ALFile) {
            try {
                Remove-Item -Path $ALFile -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Removed child access log file: $ALFile" -Type "INFO" -Color Gray
            } catch {}
        }
    }

    # Remove WMI Event Subscription
    Write-Log -Message "Removing WMI event subscription..." -Type "INFO" -Color Gray
    try {
        Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" -Filter "__PATH LIKE '%$WmiEventName%'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Failed to remove WMI subscription: $_" -Type "WARN" -Color Yellow }

    # Remove the integrity hash and parent password registry keys
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    if (Test-Path $IntegrityRegPath) {
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardIntegrity" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordHash" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordSalt" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordIterations" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeLastActivity" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeAFKTimeout" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name $TamperDetectedRegName -ErrorAction SilentlyContinue
    }

    # Force Group Policy refresh to restore original domain/local GPO settings (run in background so uninstall isn't blocked)
    Write-Log -Message "Starting Group Policy update (gpupdate /force) in background..." -Type "INFO" -Color Yellow
    try {
        Start-Job -ScriptBlock { gpupdate /force 2>&1 | Out-Null } | Out-Null
        Write-Log -Message "Group Policy update started in background." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to start gpupdate /force: $_" -Type "WARN" -Color Yellow
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
            Invoke-AsSystem -Command "takeown.exe /F $CmdPath; icacls.exe $CmdPath /reset; Remove-Item -Path $CmdPath -Force -ErrorAction Stop"
        }
        if (Test-Path $CmdPath) {
            Write-Log -Message "Failed to remove 'oslock' CLI Alias at $CmdPath." -Type "ERROR" -Color Red
        } else {
            Write-Log -Message "Removed 'oslock' CLI Alias." -Type "INFO" -Color Gray
        }
    }

    # Remove local wrapper and PATH entry
    $CmdPathLocal = Join-Path $InstallDir "oslock.cmd"
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
        try {
            Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop
            Write-Log -Message "Installation directory removed." -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Direct deletion failed (hardened ACLs). Spawning SYSTEM cleanup task..." -Type "INFO" -Color Yellow
            Invoke-AsSystem -Command "takeown.exe /F $InstallDir /R /D Y; icacls.exe $InstallDir /reset /T; Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop"
            # Fallback: try one last direct delete immediately (SYSTEM task is fast)
            if (Test-Path $InstallDir) {
                try { Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
            }
            if (Test-Path $InstallDir) {
                Write-Log -Message "SYSTEM cleanup failed: $InstallDir still exists." -Type "ERROR" -Color Red
            } else {
                Write-Log -Message "Installation directory removed by SYSTEM. Goodbye!" -Type "INFO" -Color Gray
            }
        }
    }

    # Note: We do NOT delete the child account on uninstall - only remove restrictions.
    # This preserves any data the child has. To delete the account manually:
    #   Remove-LocalUser -Name $ChildUser
    Write-Host "`n[INFO] Child account '$ChildUser' was NOT deleted (data preserved)." -ForegroundColor Cyan
    Write-Host "       Restrictions removed. To delete the account entirely:" -ForegroundColor Cyan
    Write-Host "       Remove-LocalUser -Name '$ChildUser'" -ForegroundColor Cyan

    # Final status verification (single batch query for all tasks)
    $FailedCount = 0
    $RemainingTasks = @()
    try { $RemainingTasks = (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "OSGuard-*" }).TaskName } catch {}
    $TaskNamesToVerify = @($TaskName, $Guardian1Name, $Guardian2Name, $ChildLogonTaskName, $ParentModeWatchName, $ProgramScannerName, $ScreenTimeTaskName, "OSGuard-TamperLockout", "OSGuard-ChildUSBGuard", "OSGuard-ApproveInstallReharden", "OSGuard-ChildAccessLog", "OSGuard-ProcessEnforcer-ChildLogon", $ProcessEnforcerName)
    foreach ($TName in $TaskNamesToVerify) {
        if ($RemainingTasks -contains $TName) {
            $FailedCount++
            Write-Log -Message "Task $TName still exists." -Type "ERROR" -Color Red
        }
    }
    if (Test-Path $InstallDir) { $FailedCount++; Write-Log -Message "Install directory $InstallDir still exists." -Type "ERROR" -Color Red }
    if (Test-Path $CmdPath) { $FailedCount++; Write-Log -Message "Global CLI $CmdPath still exists." -Type "ERROR" -Color Red }
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($CurrentPath -like "*$InstallDir*") { $FailedCount++; Write-Log -Message "System PATH still contains $InstallDir." -Type "ERROR" -Color Red }
    # Verify parent/admin shortcuts were removed from child desktop.
    # Check both the resolved profile path and the fallback path to catch stale installs.
    $ProfilePaths = @()
    $ResolvedProfilePath = Get-ChildProfilePath
    if ($ResolvedProfilePath) { $ProfilePaths += $ResolvedProfilePath }
    $ProfilePaths += "C:\Users\$ChildUser"
    $ExpectedRemovedShortcuts = @("Parent Mode.lnk", "Lock Now.lnk", "Continue Parent Mode.lnk", "Approve Child Install.lnk", "Admin CMD.lnk", "Admin PowerShell.lnk", "Admin Only Logout.lnk", "Grant Browser Time.lnk")
    foreach ($ProfilePath in $ProfilePaths) {
        $ChildDesktop = Join-Path $ProfilePath "Desktop"
        if (Test-Path $ChildDesktop) {
            foreach ($ScName in $ExpectedRemovedShortcuts) {
                $ScPath = Join-Path $ChildDesktop $ScName
                if (Test-Path $ScPath) {
                    $FailedCount++
                    Write-Log -Message "Shortcut '$ScName' still exists on child desktop after uninstall." -Type "ERROR" -Color Red
                }
            }
        }
    }

    # Re-enable log directory creation for future operations
    $script:SuppressLogDirCreation = $false

    if ($FailedCount -eq 0) {
        Write-Host "`n[SUCCESS] UNINSTALLATION COMPLETE!" -ForegroundColor Green
    } else {
        Write-Host "[PARTIAL] UNINSTALLATION COMPLETE WITH ERRORS`! ($FailedCount items failed to remove)" -ForegroundColor Yellow
    }

    # Re-enable close button after uninstall completes
    Set-ConsoleCloseButton -Enable $true
}

# ============================================================================
# 11. CLI EXECUTION HANDLER
# ============================================================================

# ChildLock: applies HKCU policies to the CURRENT user's session (no elevation needed).
# Used by the child logon task so the child's live hive gets the restrictions directly.
if ($ChildLock) {
    # Clear caches so we resolve the live profile path (not a stale folder)
    Clear-ChildCache
    # Only apply if the current user IS the child (defense: don't lock an admin by accident)
    $CurrentUserName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($CurrentUserName -notmatch "$ChildUser$") {
        return
    }
    # Skip child lockdown if Parent Mode or Temporary Unlock is currently active
    $ParentModeActive = $false
    $TempUnlockActive = $false
    try { $ParentModeActive = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue) -eq 1 } catch {}
    try { $TempUnlockActive = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -ErrorAction SilentlyContinue) -eq 1 } catch {}
    if ($ParentModeActive -or $TempUnlockActive) {
        return
    }
    # If tamper lockout is active, show the lockout screen instead of normal policies
    if (Test-TamperDetected) {
        Show-TamperLockoutScreen
        return
    }
    # Check if the child access log has been tampered with; if so, lockout immediately.
    if (Test-ChildAccessLogTamper) {
        Write-Log -Message "Child access log tampered with! Locking out child account." -Type "SECURITY" -Color Red
        Show-TamperLockoutScreen
        return
    }
    # Apply all child base policies to the live HKCU hive using correct property types (via Apply-ChildHivePolicies)
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue) {
        Apply-ChildHivePolicies -HiveMount $ChildSidValue -Policies $ChildBasePolicies
        Apply-ChildHivePolicies -HiveMount $ChildSidValue -Policies $ChildDisallowRunPolicies
        Apply-EdgePolicies -HiveMount $ChildSidValue
    }

    # Force child StartMenuExperienceHost / ShellExperienceHost to restart so NoLogOff policy is picked up
    Restart-ChildShell

    # Apply RestrictRun whitelist to the live HKCU session
    Apply-RestrictRunPolicies -UseHKCU

    # Trigger immediate Process Enforcer scan for this child session
    try { Start-ScheduledTask -TaskName $ProcessEnforcerName -ErrorAction SilentlyContinue } catch {}

    # Create child-facing shortcuts and apply bypass mitigations only when child actually logs in
    Set-ChildLogoutShortcut
    New-ChildGameRequestShortcut
    New-BrowserRequestShortcut
    New-AdminRequestShortcut
    New-ChildLockNowShortcut
    New-ChildContinueParentModeShortcut
    New-ChildApproveInstallShortcut
    Apply-FolderExecutionDeny
    Apply-ChildFileAssociationBlock -HiveMount (Get-ChildSid)

    # Verify and repair any missing child shortcuts
    $ChildProfilePath = Get-ChildProfilePath
    if ($ChildProfilePath) {
        $DesktopPath = Join-Path $ChildProfilePath "Desktop"
        $ExpectedShortcuts = @{
            "Log out.lnk" = { Set-ChildLogoutShortcut }
            "Request Game Install.lnk" = { New-ChildGameRequestShortcut }
            "Browser Request.lnk" = { New-BrowserRequestShortcut }
            "Admin Request.lnk" = { New-AdminRequestShortcut }
            "Lock Now.lnk" = { New-ChildLockNowShortcut }
            "Continue Parent Mode.lnk" = { New-ChildContinueParentModeShortcut }
            "Approve Child Install.lnk" = { New-ChildApproveInstallShortcut }
        }
        foreach ($ScName in $ExpectedShortcuts.Keys) {
            $ScPath = Join-Path $DesktopPath $ScName
            if (-not (Test-Path $ScPath)) {
                Write-Log -Message "Shortcut '$ScName' missing on child desktop - attempting repair..." -Type "WARN" -Color Yellow
                try {
                    & $ExpectedShortcuts[$ScName]
                } catch {
                    Write-Log -Message "Repair failed for '$ScName': $_" -Type "ERROR" -Color Red
                }
            }
        }
    }

    # Show browser lock notification when child logs in (Edge is blocked by default)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        [System.Windows.Forms.MessageBox]::Show("Edge browser is LOCKED. Please ask your parent to grant browser time before using the internet.", "Browser Locked - Parent Approval Required", "OK", "Information") | Out-Null
    } catch {}

    # First-login OOBE welcome: show confirmation popup and force logout after OOBE completes
    if (-not (Test-ChildOOBEComplete)) {
        Show-ChildOOBEWelcome
    }

    return
}

# SilentLock: background re-apply (used by guardian tasks). Verifies integrity first.
if ($SilentLock) {
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    $IntegrityFile = Join-Path $InstallDir "integrity.sha256"
    $HashCheckPassed = $true

    # --- Heartbeat crash detection (non-blocking) ---
    $HeartbeatStatus = Test-Heartbeat
    switch ($HeartbeatStatus) {
        "STALE" {
            Write-Log -Message "HEARTBEAT CRASH DETECTED: Interactive terminal stopped unexpectedly (stale heartbeat > 2 min). Check Windows Event Viewer for .NET Runtime errors." -Type "ERROR" -Color Red
        }
        "MISSING" {
            Write-Log -Message "HEARTBEAT MISSING: No interactive session heartbeat file found. This is normal if the menu has never been launched." -Type "INFO" -Color Gray
        }
        "OK" {
            Write-Log -Message "Heartbeat OK: Interactive terminal is alive." -Type "AUDIT" -Color DarkGray
        }
        "CLEAN_EXIT" {
            Write-Log -Message "Heartbeat CLEAN_EXIT: Interactive terminal exited cleanly." -Type "AUDIT" -Color DarkGray
        }
    }

    # --- Canary check (catches deletion before script hash check) ---
    if (-not (Test-Canary)) {
        Write-Log -Message "CANARY FAILURE: Canary file missing or tampered! Tamper lockout activated." -Type "SECURITY" -Color Red
        Set-TamperDetected
        $HashCheckPassed = $false
    }

    # --- Task Scheduler tamper check ---
    if (Test-TaskSchedulerTamper) {
        Set-TamperDetected
        $HashCheckPassed = $false
    }

    # Primary check: registry stored hash
    $ExpectedHash = $null
    try { $ExpectedHash = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardIntegrity" -ErrorAction Stop) } catch {}

    if ($ExpectedHash) {
        $ActualHash = Get-FileHashSafe -Path $InstallScript
        if ($ExpectedHash.Trim() -ne $ActualHash.Trim()) {
            Write-Log -Message "INTEGRITY FAILURE: Registry hash mismatch! Tamper lockout activated." -Type "SECURITY" -Color Red
            Set-TamperDetected
            # Trigger immediate lockout if child is currently logged in
            $ChildSession = $null
            try { $ChildSession = Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue | Where-Object { $_.Antecedent -match "Name=`"$ChildUser`"" } | Select-Object -First 1 } catch {}
            if ($ChildSession -and -not (Get-ScheduledTask -TaskName "OSGuard-TamperLockout" -ErrorAction SilentlyContinue)) {
                Write-Log -Message "Child session detected. Scheduling immediate tamper lockout..." -Type "SECURITY" -Color Red
                try {
                    $TamperAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -TamperLockout"
                    $TamperTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(3)
                    $TamperPrincipal = New-ScheduledTaskPrincipal -UserId $ChildUser -LogonType Interactive
                    Register-ScheduledTask -TaskName "OSGuard-TamperLockout" -Action $TamperAction -Trigger $TamperTrigger -Principal $TamperPrincipal -Force | Out-Null
                    Start-ScheduledTask -TaskName "OSGuard-TamperLockout"
                } catch {
                    Write-Log -Message "Failed to schedule immediate tamper lockout: $_" -Type "WARN" -Color Yellow
                }
            }
            $HashCheckPassed = $false
        }
    } elseif (Test-Path $IntegrityFile) {
        $ExpectedHash = Get-Content -Path $IntegrityFile -Raw
        $ActualHash = Get-FileHashSafe -Path $InstallScript
        if ($ExpectedHash.Trim() -ne $ActualHash.Trim()) {
            Write-Log -Message "INTEGRITY FAILURE: File hash mismatch! Tamper lockout activated." -Type "SECURITY" -Color Red
            Set-TamperDetected
            $ChildSession = $null
            try { $ChildSession = Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue | Where-Object { $_.Antecedent -match "Name=`"$ChildUser`"" } | Select-Object -First 1 } catch {}
            if ($ChildSession -and -not (Get-ScheduledTask -TaskName "OSGuard-TamperLockout" -ErrorAction SilentlyContinue)) {
                Write-Log -Message "Child session detected. Scheduling immediate tamper lockout..." -Type "SECURITY" -Color Red
                try {
                    $TamperAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -TamperLockout"
                    $TamperTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(3)
                    $TamperPrincipal = New-ScheduledTaskPrincipal -UserId $ChildUser -LogonType Interactive
                    Register-ScheduledTask -TaskName "OSGuard-TamperLockout" -Action $TamperAction -Trigger $TamperTrigger -Principal $TamperPrincipal -Force | Out-Null
                    Start-ScheduledTask -TaskName "OSGuard-TamperLockout"
                } catch {
                    Write-Log -Message "Failed to schedule immediate tamper lockout: $_" -Type "WARN" -Color Yellow
                }
            }
            $HashCheckPassed = $false
        }
    }

    # Geofence: enforce stricter lockdown if not on home network
    Invoke-GeofenceLockdown

    # Even on integrity failure, re-apply locks to keep the child locked down.
    # Guardian: ensure main task still exists and recreate it if deleted
    $MainTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $MainTask) {
        Write-Log -Message "Main task '$TaskName' is missing! Recreating from guardian..." -Type "SECURITY" -Color Red
        $Action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
        $Trigger1 = New-ScheduledTaskTrigger -AtStartup
        $CimClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace "Root/Microsoft/Windows/TaskScheduler"
        $Trigger3 = New-CimInstance -CimClass $CimClass -ClientOnly
        $Trigger3.Subscription = "<QueryList><Query Id='0' Path='Microsoft-Windows-NetworkProfile/Operational'><Select Path='Microsoft-Windows-NetworkProfile/Operational'>*[System[EventID=10000]]</Select></Query></QueryList>"
        $Trigger3.Enabled = $True
        $PrincipalSettings = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger @($Trigger1, $Trigger3) -Principal $PrincipalSettings -Force | Out-Null
    }

    # Re-apply the child logon task if missing
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and -not (Get-ScheduledTask -TaskName $ChildLogonTaskName -ErrorAction SilentlyContinue)) {
        try {
            $ChildAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -ChildLock -ChildUser `"$ChildUser`""
            $ChildTrigger = New-ScheduledTaskTrigger -AtLogOn
            $ChildTrigger.UserId = $ChildUser
            $ChildPrincipalObj = New-ScheduledTaskPrincipal -UserId $ChildUser -LogonType Interactive -RunLevel Limited
            Register-ScheduledTask -TaskName $ChildLogonTaskName -Action $ChildAction -Trigger $ChildTrigger -Principal $ChildPrincipalObj -Force | Out-Null
        } catch {}
    }

    # Re-apply the child access log SYSTEM task if missing
    if ($ChildSidValue -and -not (Get-ScheduledTask -TaskName "OSGuard-ChildAccessLog" -ErrorAction SilentlyContinue)) {
        try {
            $AccessLogAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -ChildAccessLog -ChildUser `"$ChildUser`""
            $AccessLogTrigger = New-ScheduledTaskTrigger -AtLogOn
            $AccessLogTrigger.UserId = $ChildUser
            $AccessLogPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName "OSGuard-ChildAccessLog" -Action $AccessLogAction -Trigger $AccessLogTrigger -Principal $AccessLogPrincipal -Force | Out-Null
        } catch {}
    }

    # Re-apply the Process Enforcer child-logon SYSTEM trigger if missing
    if ($ChildSidValue -and -not (Get-ScheduledTask -TaskName "OSGuard-ProcessEnforcer-ChildLogon" -ErrorAction SilentlyContinue)) {
        try {
            $PEChildLogonAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command try { Start-ScheduledTask -TaskName $ProcessEnforcerName -ErrorAction SilentlyContinue } catch {}"
            $PEChildLogonTrigger = New-ScheduledTaskTrigger -AtLogOn
            $PEChildLogonTrigger.UserId = $ChildUser
            $PEChildLogonPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName "OSGuard-ProcessEnforcer-ChildLogon" -Action $PEChildLogonAction -Trigger $PEChildLogonTrigger -Principal $PEChildLogonPrincipal -Force | Out-Null
        } catch {}
    }

    # Check child access log tamper from guardian as well
    if (Test-ChildAccessLogTamper) {
        Write-Log -Message "Child access log tamper detected during guardian scan!" -Type "SECURITY" -Color Red
        Set-TamperDetected
    }

    # Re-write ParentModeWatch script from embedded Base64 (fresh every heal) and re-register task if missing
    $WatchScriptPath = Join-Path $InstallDir "ParentModeWatch.ps1"
    try {
        $WatchScriptContent = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ParentModeWatchB64))
        Set-Content -Path $WatchScriptPath -Value $WatchScriptContent -Encoding UTF8 -Force
        $WatchAcl = Get-Acl -Path $WatchScriptPath
        $WatchAcl.SetOwner($SidSystem)
        $WatchAcl.SetAccessRuleProtection($true, $false)
        $WatchAcl.Access | ForEach-Object { $WatchAcl.RemoveAccessRule($_) | Out-Null }
        $WatchAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $WatchAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
        Set-Acl -Path $WatchScriptPath -AclObject $WatchAcl -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to write ParentModeWatch script during silent heal: $_" -Type "WARN" -Color Yellow
    }
    if (-not (Get-ScheduledTask -TaskName $ParentModeWatchName -ErrorAction SilentlyContinue)) {
        try {
            $WatchAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$WatchScriptPath`""
            $WatchTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
            $WatchPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $ParentModeWatchName -Action $WatchAction -Trigger $WatchTrigger -Principal $WatchPrincipal -Force | Out-Null
        } catch {}
    }

    # Re-apply Program Guardian task if missing
    if (-not (Get-ScheduledTask -TaskName $ProgramScannerName -ErrorAction SilentlyContinue)) {
        try {
            Install-ProgramGuardian
        } catch {
            Write-Log -Message "Failed to re-register Program Guardian task during silent heal: $_" -Type "WARN" -Color Yellow
        }
    }

    # Re-apply ScreenTime watcher if missing
    if (-not (Get-ScheduledTask -TaskName $ScreenTimeTaskName -ErrorAction SilentlyContinue)) {
        try {
            Install-ScreenTimeWatcher
        } catch {
            Write-Log -Message "Failed to re-register ScreenTime watcher during silent heal: $_" -Type "WARN" -Color Yellow
        }
    }

    # Re-apply Process Enforcer task if missing or outdated, and ensure it is actively running
    Install-ProcessEnforcer

    # Enforce ScreenTime limits immediately during silent heal
    Invoke-ScreenTimeEnforcement

    # Program Guardian: scan and harden any newly installed programs
    Scan-And-Harden-ChildPrograms

    # Process Enforcer: kill unauthorized child processes immediately
    Invoke-ChildProcessEnforcement

    # Check WMI subscription health and re-register if missing or corrupted
    $WmiFilterExists = Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue
    $WmiConsumerExists = Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue
    $WmiBindingExists = Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" -Filter "__PATH LIKE '%$WmiEventName%'" -ErrorAction SilentlyContinue
    if (-not $WmiFilterExists -or -not $WmiConsumerExists -or -not $WmiBindingExists) {
        Write-Log -Message "WMI subscription missing or corrupted during silent heal. Re-registering..." -Type "SECURITY" -Color Red
        try {
            $WmiQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name = 'Schedule'"
            $WmiConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$WmiEventName; CommandLineTemplate="pwsh.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"; RunInteractively=$false} -ErrorAction Stop
            $WmiFilter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{Name=$WmiEventName; EventNamespace="root\cimv2"; QueryLanguage="WQL"; Query=$WmiQuery} -ErrorAction Stop
            Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$WmiFilter; Consumer=$WmiConsumer} -ErrorAction Stop | Out-Null
            Write-Log -Message "WMI subscription re-registered successfully." -Type "SUCCESS" -Color Green
        } catch {
            Write-Log -Message "Failed to re-register WMI subscription during silent heal: $_" -Type "WARN" -Color Yellow
        }
    }

    # Check Task Scheduler service and auto-start if stopped
    $ScheduleService = Get-Service -Name "Schedule" -ErrorAction SilentlyContinue
    if ($ScheduleService -and $ScheduleService.Status -ne "Running") {
        Write-Log -Message "Task Scheduler service is stopped! Starting it..." -Type "SECURITY" -Color Red
        try {
            Start-Service -Name "Schedule" -ErrorAction Stop
            Write-Log -Message "Task Scheduler service started." -Type "SUCCESS" -Color Green
        } catch {
            Write-Log -Message "Failed to start Task Scheduler service: $_" -Type "ERROR" -Color Red
        }
    }

    # Only clear Parent Mode and re-apply locks if Parent Mode is NOT active
    $ParentModeActive = $false
    try { $ParentModeActive = (Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "OSGuardParentModeActive" -ErrorAction SilentlyContinue) -eq 1 } catch {}
    $TempUnlockActive = $false
    try { $TempUnlockActive = (Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "OSGuardTempUnlockActive" -ErrorAction SilentlyContinue) -eq 1 } catch {}
    if (-not $ParentModeActive -and -not $TempUnlockActive) {
        try {
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        } catch {}

        Enable-DNSLock
        Enable-OSLock
    }
    return
}

function New-TempUnlockTimerScript {
    $TimerContent = @'
# TempUnlockTimer.ps1 - Live countdown for OS-Guard Temporary Unlock
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
$InstallDir = "C:\ProgramData\OSGuard"
$PidFile = Join-Path $InstallDir "TempUnlockTimer.pid"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "OS-Guard Temp Unlock Timer"
$form.Size = New-Object System.Drawing.Size(420, 160)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false

$label = New-Object System.Windows.Forms.Label
$label.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$label.TextAlign = "MiddleCenter"
$label.Dock = "Fill"
$form.Controls.Add($label)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000

$timer.Add_Tick({
    $TempActive = 0
    try { $TempActive = Get-ItemPropertyValue -Path $RegPath -Name "OSGuardTempUnlockActive" -ErrorAction Stop } catch { $TempActive = 0 }
    if ($TempActive -ne 1) {
        $timer.Stop()
        $form.Close()
        return
    }
    $TimestampStr = $null
    try { $TimestampStr = Get-ItemPropertyValue -Path $RegPath -Name "OSGuardTempUnlockTimestamp" -ErrorAction Stop } catch { $TimestampStr = $null }
    $Elapsed = [timespan]::Zero
    if ($TimestampStr) {
        try { $Elapsed = (Get-Date) - [datetime]::Parse($TimestampStr) } catch { $Elapsed = [timespan]::Zero }
    }
    $Remaining = [timespan]::FromMinutes(1) - $Elapsed
    if ($Remaining.TotalSeconds -le 0) {
        $label.Text = "LOCKING NOW..."
        $timer.Stop()
        Start-Sleep -Milliseconds 500
        & "C:\Windows\oslock.cmd" -LockNow
        $form.Close()
    } else {
        $label.Text = ("Temp Unlock: {0:mm\:ss}" -f $Remaining)
    }
})

$form.Add_FormClosing({
    $timer.Stop()
    $TempActive = 0
    try { $TempActive = Get-ItemPropertyValue -Path $RegPath -Name "OSGuardTempUnlockActive" -ErrorAction Stop } catch { $TempActive = 0 }
    if ($TempActive -eq 1) {
        & "C:\Windows\oslock.cmd" -LockNow
    }
    if (Test-Path $PidFile) { Remove-Item -Path $PidFile -Force -ErrorAction SilentlyContinue }
})

$form.Add_Shown({
    $PID | Out-File -FilePath $PidFile -Encoding UTF8 -Force
    $timer.Start()
})

[void][System.Windows.Forms.Application]::EnableVisualStyles()
[void]$form.ShowDialog()
'@
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction SilentlyContinue | Out-Null }
    Set-Content -Path $TempUnlockTimerPath -Value $TimerContent -Encoding UTF8 -Force
}

function Start-TempUnlockTimer {
    if (-not (Test-Path $TempUnlockTimerPath)) {
        New-TempUnlockTimerScript
    }
    Stop-TempUnlockTimer
    try {
        if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction SilentlyContinue | Out-Null }
        $Process = Start-Process -FilePath "pwsh.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$TempUnlockTimerPath`"" -WindowStyle Normal -PassThru
        $Process.Id | Out-File -FilePath $TempUnlockTimerPidFile -Encoding UTF8 -Force
    } catch {
        Write-Log -Message "Failed to start temp unlock timer: $_" -Type "WARN" -Color Yellow
    }
}

function Stop-TempUnlockTimer {
    if (Test-Path $TempUnlockTimerPidFile) {
        try {
            $PidValue = Get-Content -Path $TempUnlockTimerPidFile -Raw -ErrorAction Stop
            $TimerPid = [int]$PidValue
            if ($TimerPid -gt 0) {
                Stop-Process -Id $TimerPid -Force -ErrorAction SilentlyContinue
            }
        } catch {}
        Remove-Item -Path $TempUnlockTimerPidFile -Force -ErrorAction SilentlyContinue
    }
    try {
        Get-Process -Name "pwsh" -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -eq "OS-Guard Temp Unlock Timer" } | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
}

# ============================================================================
# 11.5 INSTANCE LOCK (Multiple Instance Protection)
# ============================================================================

$IsBackgroundTask = ($SilentLock -or $ScreenTimeEnforce -or $ProcessEnforce -or $ChildLock -or $ProgramScan -or $ChildAccessLog)
if (-not (Initialize-InstanceLock -BackgroundTask:$IsBackgroundTask)) {
    exit 1
}

try {

if ($Lock)       { Enable-DNSLock; Enable-OSLock; return }
if ($Unlock)     { Disable-DNSLock; Disable-OSLock; return }
if ($Install)    { Install-Persistence; return }
if ($ParentMode) { Enter-ParentMode; return }
if ($SetParentPassword) { Set-ParentPassword; return }
if ($ChildGameRequest) { Show-GameRequestDialog; return }
if ($ContinueParentMode) {
    Update-ParentModeActivity
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value (Get-Date -Format "o") -Type String -Force -ErrorAction Stop
        Write-Log -Message "Parent Mode AFK timer reset by admin." -Type "INFO" -Color Green
    } catch {
        Write-Log -Message "Failed to reset Parent Mode AFK timer: $_" -Type "ERROR" -Color Red
    }
    return
}
if ($TamperLockout) { Show-TamperLockoutScreen; return }
if ($ProgramScan) { Scan-And-Harden-ChildPrograms; return }
    if ($ReviewBlockedPrograms) { Show-BlockedProgramReview; return }
    if ($ManageProgramWhitelist) { Show-ProgramWhitelistReview; return }
    if ($ProcessEnforce) { Invoke-ChildProcessEnforcement -Continuous; return }
    if ($ChildAccessLog) { Write-ChildAccessLog; return }
if ($SetScreenTime) { Show-SetScreenTimeDialog; return }
if ($ScreenTimeStatus) { Show-ScreenTimeStatus; return }
if ($GrantBrowserTime) { Show-GrantBrowserTimeDialog; return }
if ($ScreenTimeEnforce) { Invoke-ScreenTimeEnforcement; return }
if ($ApproveChildInstall) { Approve-ChildInstall; return }
if ($RehardenChildInstall) { Invoke-ChildInstallReharden; return }
if ($HealthCheck) { Show-HealthCheck; return }
if ($ReviewGameRequests) { Show-GameRequestReview; return }
if ($WhatIf) { $script:WhatIfPreference = $true; Install-Persistence; return }
if ($ExportReport) { Export-OSGuardReport; return }
if ($FirstRun) { Show-SetupWizard; return }
if ($SetAfkTimeout) { Show-SetAfkTimeoutDialog; return }
if ($LockNow)    { Update-ParentModeActivity; Exit-ParentMode; return }
if ($ChildLogout) {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    $r = [System.Windows.Forms.MessageBox]::Show("Log out now?","Admin Approval Required","YesNo","Question")
    if ($r -eq "Yes") {
        $SessionId = $null
        try {
            $Output = quser $ChildUser 2>&1 | Out-String
            if ($Output -match '\s+(\d+)\s+(\w+)\s+') {
                $SessionId = $matches[1].Trim()
            }
        } catch {}
        if (-not $SessionId) {
            try {
                $Lines = quser 2>&1 | Out-String -Stream
                foreach ($Line in $Lines) {
                    if ($Line -match ([regex]::Escape($ChildUser) + '\s+(\d+)')) {
                        $SessionId = $matches[1].Trim()
                        break
                    }
                }
            } catch {}
        }
        if ($SessionId) {
            try {
                Start-Process "logoff" -ArgumentList $SessionId -WindowStyle Hidden -Wait -ErrorAction Stop
                Write-Log -Message "Child logout executed for session $SessionId ($ChildUser)." -Type "INFO" -Color Gray
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to log off session $SessionId`: $_", "Logout Failed", "OK", "Error") | Out-Null
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Could not find '$ChildUser' session. The child may not be logged in.", "Logout Failed", "OK", "Error") | Out-Null
        }
    }
    return
}
if ($BypassMitigation) { Update-ParentModeActivity; Apply-BypassMitigations; return }
if ($RemoveBypassMitigation) { Update-ParentModeActivity; Remove-BypassMitigations; return }
if ($Uninstall) {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $CurrentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($CurrentUserSid.Value -ne "S-1-5-18") {
        Write-Host "`[SECURITY] CLI Uninstall denied: Must run as SYSTEM. Current user: $CurrentUser" -ForegroundColor Red

        Write-Host "Run from a SYSTEM shell (e.g., psexec -s pwsh.exe -File `"$InstallScript`" -Uninstall)" -ForegroundColor Yellow
        return
    }
    Uninstall-Persistence
    return
}

# ============================================================================
# 12. INTERACTIVE MENU
# ============================================================================

$script:AdminSessionPrompted = $false

# If no flags are passed, load the Interactive Menu
$script:LastHeartbeat = [datetime]::MinValue

do {
    # Write heartbeat every 30 seconds so guardians can detect a crash/freeze
    $Now = Get-Date
    if (($Now - $script:LastHeartbeat).TotalSeconds -ge 30) {
        Write-Heartbeat
        $script:LastHeartbeat = $Now
    }

    Update-ParentModeActivity
    if (-not $script:AdminSessionPrompted) {
        $PmActive = $false
        try { $PmActive = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue) -eq 1 } catch {}
        if (-not $PmActive -and (Test-Path $AdminSessionFile)) {
            Show-AdminSessionRestoreDialog
            $script:AdminSessionPrompted = $true
        }
    }
    # Flush any stray buffered key presses so they don't leak into the next Read-Host
    try {
        while ([Console]::KeyAvailable) {
            $null = [Console]::ReadKey($true)
        }
    } catch {}
    Clear-Host
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host "    ENTERPRISE OS + DNS LOCKDOWN SUITE (INSTALLER)   " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host "  NOTE: To update to a new version, uninstall [4] then" -ForegroundColor DarkGray
    Write-Host "        reinstall [3] with the new script. Do not overwrite." -ForegroundColor DarkGray

    $CurrentStatus = Get-LockStatus
    $CategoryGrid = Show-CategoryGrid

    $TempUnlockActive = $false
    try { $TempUnlockActive = (Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "OSGuardTempUnlockActive" -ErrorAction SilentlyContinue) -eq 1 } catch {}

    Write-Host "`n-----------------------------------------------------"
    if ($TempUnlockActive) {
        $TempUnlockTimestamp = $null
        try { $TempUnlockTimestamp = Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "OSGuardTempUnlockTimestamp" -ErrorAction SilentlyContinue } catch {}
        $Elapsed = [timespan]::Zero
        if ($TempUnlockTimestamp) {
            try { $Elapsed = (Get-Date) - [datetime]::Parse($TempUnlockTimestamp) } catch {}
        }
        $Remaining = [timespan]::FromMinutes(1) - $Elapsed
        if ($Remaining.TotalSeconds -lt 0) { $Remaining = [timespan]::Zero }
        $CountdownStr = "{0:mm\:ss}" -f $Remaining
        Write-Host "*** TEMP UNLOCK ACTIVE - Countdown: $CountdownStr remaining `(auto-locks after 1 min idle) ***" -ForegroundColor Yellow -BackgroundColor Black

    }
    Write-Host "[1] DEPLOY ALL LOCKS (DNS + OS Child Lockdown)" -ForegroundColor Cyan
    if ($TempUnlockActive) {
        Write-Host "[2] RE-LOCK SYSTEM (End Temporary Unlock)" -ForegroundColor Cyan
    } else {
        Write-Host "[2] TEMPORARY UNLOCK (Restore Access)" -ForegroundColor Yellow
    }
    if (-not (Test-Path $InstallScript)) {
        Write-Host "[3] INSTALL SERVICE `(Auto-Heal `& Create 'oslock' command)" -ForegroundColor Green

    }
    $TaskExists = $false
    try { $TaskExists = [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) } catch {}
    if ((Test-Path $InstallScript) -or $TaskExists) {
        Write-Host "[4] UNINSTALL SERVICE (Remove background tasks `& Unlock)" -ForegroundColor Red
    }
    Write-Host "[5] REFRESH SYSTEM STATUS" -ForegroundColor Gray
    Write-Host "[6] EXIT TERMINAL" -ForegroundColor Gray
    Write-Host "[7] ENTER PARENT MODE (Unlock with password)" -ForegroundColor Green
    Write-Host '[8] LOCK NOW (Re-lock immediately)' -ForegroundColor Cyan

    Write-Host "[9] SET SCREEN TIME" -ForegroundColor Cyan
    Write-Host "[10] SCREEN TIME STATUS" -ForegroundColor Cyan
    Write-Host "[11] GRANT BROWSER TIME" -ForegroundColor Cyan
    Write-Host "[12] SET PARENT MODE PASSWORD" -ForegroundColor Green
    Write-Host '[13] APPROVE CHILD INSTALL (15-min window)' -ForegroundColor Green

    Write-Host "[14] RUN PROCESS ENFORCER NOW" -ForegroundColor Magenta
    Write-Host "[15] SHOW PROCESS ENFORCER STATUS" -ForegroundColor Cyan
    Write-Host "[16] FIRST RUN WIZARD" -ForegroundColor Green
    Write-Host "[17] EXPORT REPORT (CSV)" -ForegroundColor Green
    Write-Host "[18] HEALTH CHECK (DRIFT AUDIT)" -ForegroundColor Green
    Write-Host "[19] APPLY BYPASS MITIGATIONS (Lockdown+)" -ForegroundColor Green
    Write-Host "[20] REMOVE BYPASS MITIGATIONS" -ForegroundColor Yellow
    Write-Host "[21] REVIEW BLOCKED PROGRAMS" -ForegroundColor Magenta
    Write-Host "[22] MANAGE PROGRAM WHITELIST" -ForegroundColor Green
    Write-Host "[23] REVIEW BLOCKED PROCESSES" -ForegroundColor Magenta
    Write-Host "[24] SET AFK TIMEOUT" -ForegroundColor Green
    Write-Host "[25] REVIEW PENDING GAME REQUESTS" -ForegroundColor Green
    Write-Host "[26] REPORT TO DEV (Export logs for GitHub)" -ForegroundColor Cyan
    Write-Host "-----------------------------------------------------"

    $Choice = Read-Host "Select an administrative action (1-26)"
    $IntegrityStatus = Test-IntegrityStatus

    switch ($Choice) {
        "1" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [1] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Enable-DNSLock
                Enable-OSLock
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "2" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [2] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                if ($TempUnlockActive) {
                    # Re-lock system
                    try {
                        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
                    } catch {}
                    Stop-TempUnlockTimer
                    Enable-DNSLock
                    Enable-OSLock
                    Write-Host "`n[LOCKED] System re-locked. Temporary unlock ended." -ForegroundColor Green
                } else {
                    Disable-DNSLock
                    Disable-OSLock -KeepChildAccount -SetTempUnlockFlag
                    Start-TempUnlockTimer
                    Write-Host "`n[UNLOCKED] Temporary admin unlock active. Guardians suppressed." -ForegroundColor Yellow
                    Write-Host "  Press [2] again to re-lock, or use [8] LOCK NOW." -ForegroundColor Yellow
                    Write-Host "  Auto-locks after 1 minute of inactivity." -ForegroundColor Yellow
                }
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "3" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [3] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } elseif (Test-Path $InstallScript) {
                Write-Warning "OS-Guard is already installed. Option [3] is unavailable."
            } else {
                Write-Host "`n*** DO NOT CLOSE THIS WINDOW DURING INSTALL! ***" -ForegroundColor Red -BackgroundColor Black
                Write-Host "    Closing now will corrupt the installation." -ForegroundColor Red
                Install-Persistence
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "4" {
            Write-Host "`n*** DO NOT CLOSE THIS WINDOW DURING UNINSTALL! ***" -ForegroundColor Red -BackgroundColor Black
            Write-Host "    Closing now will leave orphaned tasks and files." -ForegroundColor Red
            Uninstall-Persistence
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "5" { $null = Show-CategoryGrid -ForceRefresh; Start-Sleep -Milliseconds 200 }
        "6" { Write-Host "Returning to terminal..." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 500; Write-CleanExit; break }
        "7" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [7] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Enter-ParentMode
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "8" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [8] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Exit-ParentMode
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "9" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [9] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Show-SetScreenTimeDialog
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "10" {
            Show-ScreenTimeStatus
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "11" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [11] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Show-GrantBrowserTimeDialog
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "12" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [12] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Set-ParentPassword
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "13" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [13] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Approve-ChildInstall
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "14" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [14] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Invoke-ChildProcessEnforcement
                Write-Host "`n[OK] Process Enforcer scan completed." -ForegroundColor Green
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "15" {
            Show-ProcessEnforcerStatus
        }
        "16" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [16] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Show-SetupWizard
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "17" {
            Export-OSGuardReport
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "18" {
            Show-HealthCheck
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "19" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [19] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Apply-BypassMitigations
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "20" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [20] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Remove-BypassMitigations
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        "21" {
            Show-BlockedProgramReview
            Start-Sleep -Milliseconds 200
        }
        "22" {
            Show-ProgramWhitelistReview
            Start-Sleep -Milliseconds 200
        }
        "23" {
            Show-BlockedProcessReview
            Start-Sleep -Milliseconds 200
        }
        "24" {
            Show-SetAfkTimeoutDialog
            Start-Sleep -Milliseconds 200
        }
        "25" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [25] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Show-GameRequestReview
            }
            Start-Sleep -Milliseconds 200
        }
        "26" {
            Export-DevReport
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor Cyan; Wait-AnyKey
        }
        default { Write-Warning "Invalid Selection."; Start-Sleep -Seconds 1 }
    }
} while ($Choice -ne "6")

} finally {
    Remove-InstanceLock
}


