#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v5 - Elevate programs when user starts them (not auto-launch)
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch
)

$ToggleFile  = "C:\Windows\GodMode_Enabled.flag"
$LogFile     = "C:\Windows\GodMode_Log.txt"
$WatcherTask = "GodMode_ProcessMonitor"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Time] [$Level] $Message" | Out-File $LogFile -Append -Encoding UTF8
    Write-Host "[$Time] [$Level] $Message"
}

function Set-Toggle {
    param([bool]$Enabled)
    if ($Enabled) {
        "ON" | Out-File $ToggleFile -Force
        Write-Log "God Mode ENABLED (Elevate on user start)" "OK"
        Start-ProcessMonitor
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON (Elevates programs when user starts them)" -ForegroundColor Green
    } else {
        Write-Host "God Mode: OFF" -ForegroundColor Yellow
    }
}

function Start-ProcessMonitor {
    Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue

    # This task will run the monitoring script
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"
    $Trigger = New-ScheduledTaskTrigger -AtLogon
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $WatcherTask -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
    Write-Log "Process monitor registered (runs at logon)" "OK"
}

function Elevate-Process {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Write-Log "User started program → Elevating: $Path" "OK"

    $Action = New-ScheduledTaskAction -Execute $Path
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    \( temp = "GodMode_Elevate_ \)([Guid]::NewGuid())"
    Register-ScheduledTask -TaskName $temp -Action $Action -Principal $Principal -Force | Out-Null
    Start-ScheduledTask -TaskName $temp
    Start-Sleep -Milliseconds 500
    Unregister-ScheduledTask -TaskName $temp -Confirm:$false
}

function Start-GodMode {
    if (-not (Test-Path $ToggleFile)) {
        Write-Log "God Mode is OFF" "ERROR"
        return
    }

    Write-Log "God Mode active - Monitoring for user-started programs..." "INFO"

    # Monitor for new processes (simple loop version)
    while ($true) {
        Start-Sleep -Seconds 3

        # Get recently started processes
        $recent = Get-WmiObject Win32_Process | Where-Object {
            $_.CreationDate -and 
            ([datetime]::ParseExact($_.CreationDate.Substring(0,14), "yyyyMMddHHmmss", $null)) -gt (Get-Date).AddSeconds(-10)
        }

        foreach ($proc in $recent) {
            if ($proc.ExecutablePath -and $proc.ExecutablePath -like "*.exe") {
                Elevate-Process $proc.ExecutablePath
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
    Write-Host "`n=== GOD MODE v5 ===" -ForegroundColor Cyan
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable (elevates programs when user starts them)"
    Write-Host "  -ToggleOff    Disable"
    Write-Host "  -Status       Check status"
    Write-Host "  -Launch       Start monitoring manually"
    Write-Host ""
    Write-Host "When ON: Any program the user starts will be automatically elevated to SYSTEM." -ForegroundColor Yellow
}