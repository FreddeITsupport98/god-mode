#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v6 - With Strong Registry Elevation (Disable UAC when ON)
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch
)

$ToggleFile  = "C:\Windows\GodMode_Enabled.flag"
$LogFile     = "C:\Windows\GodMode_Log.txt"
$WatcherTask = "GodMode_UserStartMonitor"
$RegPath     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Time] [$Level] $Message" | Out-File $LogFile -Append -Encoding UTF8
    Write-Host "[$Time] [$Level] $Message"
}

function Apply-StrongElevation {
    Write-Log "Applying strong elevation registry changes..." "WARN"

    # Backup current values (if not already backed up)
    if (-not (Test-Path "HKLM:\SOFTWARE\GodModeBackup")) {
        New-Item -Path "HKLM:\SOFTWARE\GodModeBackup" -Force | Out-Null
        try {
            $currentEnableLUA = (Get-ItemProperty -Path $RegPath -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
            $currentConsent   = (Get-ItemProperty -Path $RegPath -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
            Set-ItemProperty -Path "HKLM:\SOFTWARE\GodModeBackup" -Name EnableLUA -Value $currentEnableLUA
            Set-ItemProperty -Path "HKLM:\SOFTWARE\GodModeBackup" -Name ConsentPromptBehaviorAdmin -Value $currentConsent
        } catch {}
    }

    # Apply strong changes
    Set-ItemProperty -Path $RegPath -Name EnableLUA -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $RegPath -Name ConsentPromptBehaviorAdmin -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $RegPath -Name PromptOnSecureDesktop -Value 0 -Type DWord -Force

    Write-Log "UAC disabled and elevation maximized via registry." "OK"
}

function Revert-RegistryChanges {
    Write-Log "Reverting registry changes..." "WARN"
    try {
        if (Test-Path "HKLM:\SOFTWARE\GodModeBackup") {
            $backupLUA = (Get-ItemProperty -Path "HKLM:\SOFTWARE\GodModeBackup" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
            $backupConsent = (Get-ItemProperty -Path "HKLM:\SOFTWARE\GodModeBackup" -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin

            if ($backupLUA -ne $null) { Set-ItemProperty -Path $RegPath -Name EnableLUA -Value $backupLUA -Force }
            if ($backupConsent -ne $null) { Set-ItemProperty -Path $RegPath -Name ConsentPromptBehaviorAdmin -Value $backupConsent -Force }

            Remove-Item "HKLM:\SOFTWARE\GodModeBackup" -Force -ErrorAction SilentlyContinue
        } else {
            # Fallback to safe defaults
            Set-ItemProperty -Path $RegPath -Name EnableLUA -Value 1 -Force
            Set-ItemProperty -Path $RegPath -Name ConsentPromptBehaviorAdmin -Value 5 -Force
        }
        Write-Log "Registry settings restored." "OK"
    } catch {
        Write-Log "Failed to fully restore registry: $_" "ERROR"
    }
}

function Set-Toggle {
    param([bool]$Enabled)
    if ($Enabled) {
        "ON" | Out-File $ToggleFile -Force
        Apply-StrongElevation
        Write-Log "God Mode ENABLED with strong elevation" "OK"
        Start-ProcessMonitor
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Revert-RegistryChanges
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON (UAC Disabled + Auto Elevation)" -ForegroundColor Red
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

    Write-Log "God Mode active - Elevating programs you start..." "INFO"

    $seen = @{}
    while ($true) {
        Start-Sleep -Seconds 2
        $recent = Get-WmiObject Win32_Process | Where-Object {
            $_.CreationDate -and ([datetime]::ParseExact($_.CreationDate.Substring(0,14),"yyyyMMddHHmmss",$null)) -gt (Get-Date).AddSeconds(-8)
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
    Write-Host "`n=== GOD MODE v6 (With Registry Elevation) ===" -ForegroundColor Red
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable + Apply strong registry changes (UAC disabled)"
    Write-Host "  -ToggleOff    Disable + Restore original settings"
    Write-Host "  -Status       Check current state"
    Write-Host "  -Launch       Start monitoring"
}