#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v10 - EXTREMELY DANGEROUS
    WARNING: This version actively tries to disable/kill security features
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch
)

$ToggleFile  = "C:\Windows\GodMode_Enabled.flag"
$LogFile     = "C:\Windows\GodMode_Log.txt"
$WatcherTask = "GodMode_Extreme"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Time] [$Level] $Message" | Out-File $LogFile -Append -Encoding UTF8
    if ($Level -ne "STEALTH") {
        Write-Host "[$Time] [$Level] $Message"
    }
}

function Apply-ExtremeDangerousSettings {
    Write-Log "=== EXTREME DANGEROUS MODE ACTIVATED ===" "WARN"

    # Disable Defender, Firewall, SmartScreen
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Force -ErrorAction SilentlyContinue
        Write-Log "Core security features disabled." "WARN"
    } catch {}

    # Try to kill Defender processes
    try {
        Get-Process -Name MsMpEng, smartscreen, SecurityHealthService -ErrorAction SilentlyContinue | 
            Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Log "Attempted to kill Defender/SmartScreen processes." "WARN"
    } catch {}

    # Disable UAC
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 0 -Force
        Write-Log "UAC fully disabled." "WARN"
    } catch {}

    # Disable more telemetry
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log "Telemetry reduced." "WARN"
    } catch {}
}

function Revert-ExtremeSettings {
    Write-Log "Reverting extreme settings..." "WARN"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "On" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 -Force
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
        Write-Log "Security features restored." "OK"
    } catch {
        Write-Log "Could not fully restore settings." "ERROR"
    }
}

function Set-Toggle {
    param([bool]$Enabled)
    if ($Enabled) {
        "ON" | Out-File $ToggleFile -Force
        Apply-ExtremeDangerousSettings
        Write-Log "God Mode ENABLED - EXTREME DANGEROUS" "WARN"
        Start-ProcessMonitor
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Revert-ExtremeSettings
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON (EXTREME DANGEROUS MODE)" -ForegroundColor Red
    } else {
        Write-Host "God Mode: OFF" -ForegroundColor Yellow
    }
}

function Start-ProcessMonitor {
    Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"
    $Trigger = New-ScheduledTaskTrigger -AtLogon
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $WatcherTask -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
}

function Elevate-Program {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Write-Log "Elevating: $Path" "STEALTH"
    try {
        $Action = New-ScheduledTaskAction -Execute $Path
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        \( temp = "GodMode_Elev_ \)([Guid]::NewGuid())"
        Register-ScheduledTask -TaskName $temp -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $temp
        Start-Sleep -Milliseconds 300
        Unregister-ScheduledTask -TaskName $temp -Confirm:$false
    } catch {}
}

function Start-GodMode {
    if (-not (Test-Path $ToggleFile)) {
        Write-Log "God Mode is OFF" "ERROR"
        return
    }

    Write-Log "God Mode EXTREME active..." "WARN"

    $seen = @{}
    while ($true) {
        Start-Sleep -Seconds 2
        $recent = Get-WmiObject Win32_Process | Where-Object {
            $_.CreationDate -and ([datetime]::ParseExact($_.CreationDate.Substring(0,14), "yyyyMMddHHmmss", $null)) -gt (Get-Date).AddSeconds(-8)
        }
        foreach ($p in $recent) {
            if ($p.ExecutablePath -like "*.exe" -and -not $seen.ContainsKey($p.ExecutablePath)) {
                $seen[$p.ExecutablePath] = $true
                Elevate-Program $p.ExecutablePath
            }
        }
    }
}

# === CLI ===
if ($ToggleOn)  { Set-Toggle $true; exit }
if ($ToggleOff) { Set-Toggle $false; exit }
if ($Status)    { Get-Status; exit }

if ($Launch) {
    Start-GodMode
} else {
    Write-Host "`n=== GOD MODE v10 - EXTREME DANGEROUS ===" -ForegroundColor Red
    Write-Host "This version actively disables/kills multiple security components."
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable (EXTREME mode)"
    Write-Host "  -ToggleOff    Disable + attempt restore"
    Write-Host "  -Status       Check status"
    Write-Host "  -Launch       Start monitoring"
}