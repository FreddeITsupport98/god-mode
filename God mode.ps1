#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v9 - Very Dangerous Mode
    WARNING: Disables multiple core Windows security features
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch
)

$ToggleFile  = "C:\Windows\GodMode_Enabled.flag"
$LogFile     = "C:\Windows\GodMode_Log.txt"
$WatcherTask = "GodMode_VeryDangerous"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Time] [$Level] $Message" | Out-File $LogFile -Append -Encoding UTF8
    Write-Host "[$Time] [$Level] $Message"
}

function Apply-DangerousSettings {
    Write-Log "=== APPLYING VERY DANGEROUS SETTINGS ===" "WARN"

    # 1. Disable Windows Defender Real-time Protection
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Write-Log "Windows Defender Real-time Protection: DISABLED" "WARN"
    } catch {}

    # 2. Disable Windows Firewall
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue
        Write-Log "Windows Firewall: DISABLED" "WARN"
    } catch {}

    # 3. Disable SmartScreen
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Force -ErrorAction SilentlyContinue
        Write-Log "SmartScreen: DISABLED" "WARN"
    } catch {}

    # 4. Try to stop Windows Defender service
    try {
        Stop-Service -Name WinDefend -Force -ErrorAction SilentlyContinue
        Write-Log "Windows Defender Service: STOPPED" "WARN"
    } catch {}

    # 5. Disable UAC (already strong)
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 0 -Force
        Write-Log "UAC: DISABLED" "WARN"
    } catch {}
}

function Revert-DangerousSettings {
    Write-Log "Reverting dangerous settings..." "WARN"

    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "On" -Force -ErrorAction SilentlyContinue
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 -Force
        Write-Log "Security features re-enabled." "OK"
    } catch {
        Write-Log "Could not fully restore all settings." "ERROR"
    }
}

function Set-Toggle {
    param([bool]$Enabled)
    if ($Enabled) {
        "ON" | Out-File $ToggleFile -Force
        Apply-DangerousSettings
        Write-Log "God Mode ENABLED - VERY DANGEROUS MODE" "WARN"
        Start-ProcessMonitor
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Revert-DangerousSettings
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON (VERY DANGEROUS - Defender + Firewall + SmartScreen disabled)" -ForegroundColor Red
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
        Start-Sleep -Milliseconds 400
        Unregister-ScheduledTask -TaskName $temp -Confirm:$false
    } catch {
        Write-Log "Failed to elevate: $Path" "ERROR"
    }
}

function Start-GodMode {
    if (-not (Test-Path $ToggleFile)) {
        Write-Log "God Mode is OFF" "ERROR"
        return
    }

    Write-Log "God Mode VERY DANGEROUS active - Monitoring..." "WARN"

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
    Write-Host "`n=== GOD MODE v9 - VERY DANGEROUS ===" -ForegroundColor Red
    Write-Host "This version disables Defender, Firewall, and SmartScreen."
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable (very dangerous mode)"
    Write-Host "  -ToggleOff    Disable + restore security"
    Write-Host "  -Status       Check status"
    Write-Host "  -Launch       Start monitoring"
}