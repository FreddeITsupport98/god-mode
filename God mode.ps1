#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v8 - More Dangerous (Disables Defender + Firewall when ON)
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch
)

$ToggleFile  = "C:\Windows\GodMode_Enabled.flag"
$LogFile     = "C:\Windows\GodMode_Log.txt"
$WatcherTask = "GodMode_DangerousMonitor"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Time] [$Level] $Message" | Out-File $LogFile -Append -Encoding UTF8
    Write-Host "[$Time] [$Level] $Message"
}

function Disable-DefenderAndFirewall {
    Write-Log "Disabling Windows Defender and Firewall (DANGEROUS MODE)..." "WARN"

    try {
        # Disable Windows Defender Real-time Protection
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Write-Log "Windows Defender Real-time Protection disabled." "WARN"

        # Disable Windows Firewall
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue
        Write-Log "Windows Firewall disabled." "WARN"
    } catch {
        Write-Log "Failed to disable some security features: $_" "ERROR"
    }
}

function Enable-DefenderAndFirewall {
    Write-Log "Re-enabling Windows Defender and Firewall..." "WARN"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
        Write-Log "Defender and Firewall re-enabled." "OK"
    } catch {
        Write-Log "Could not fully re-enable security features." "ERROR"
    }
}

function Set-Toggle {
    param([bool]$Enabled)
    if ($Enabled) {
        "ON" | Out-File $ToggleFile -Force
        Disable-DefenderAndFirewall
        Write-Log "God Mode ENABLED (More Dangerous)" "WARN"
        Start-ProcessMonitor
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Enable-DefenderAndFirewall
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON (Dangerous Mode - Defender + Firewall disabled)" -ForegroundColor Red
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
    Write-Log "Elevating: $Path" "OK"
    try {
        $Action = New-ScheduledTaskAction -Execute $Path
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        \( temp = "GodMode_Elev_ \)([Guid]::NewGuid())"
        Register-ScheduledTask -TaskName $temp -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $temp
        Start-Sleep -Milliseconds 500
        Unregister-ScheduledTask -TaskName $temp -Confirm:$false
    } catch {
        Write-Log "Failed to elevate $Path" "ERROR"
    }
}

function Start-GodMode {
    if (-not (Test-Path $ToggleFile)) {
        Write-Log "God Mode is OFF" "ERROR"
        return
    }

    Write-Log "God Mode active (Dangerous) - Elevating user-started programs..." "WARN"

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

# === CLI Commands ===
if ($ToggleOn)  { Set-Toggle $true; exit }
if ($ToggleOff) { Set-Toggle $false; exit }
if ($Status)    { Get-Status; exit }

if ($Launch) {
    Start-GodMode
} else {
    Write-Host "`n=== GOD MODE v8 (More Dangerous) ===" -ForegroundColor Red
    Write-Host "WARNING: This version disables Windows Defender and Firewall when enabled."
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable (disables Defender + Firewall)"
    Write-Host "  -ToggleOff    Disable + re-enable security features"
    Write-Host "  -Status       Check status"
    Write-Host "  -Launch       Start monitoring"
}