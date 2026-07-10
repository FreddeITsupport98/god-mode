#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode - Elevate when user manually starts a program
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
        Write-Log "God Mode ENABLED (Elevates when user starts programs)" "OK"
        Start-ProcessMonitor
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON (Elevates programs you manually start)" -ForegroundColor Green
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
    Write-Log "Process monitor started (will elevate programs you start)" "OK"
}

function Elevate-Program {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) { return }

    Write-Log "User started program → Elevating to SYSTEM: $Path" "OK"

    try {
        $Action = New-ScheduledTaskAction -Execute $Path
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        \( tempTask = "GodMode_Elev_ \)([Guid]::NewGuid())"
        
        Register-ScheduledTask -TaskName $tempTask -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $tempTask
        
        Start-Sleep -Milliseconds 600
        Unregister-ScheduledTask -TaskName $tempTask -Confirm:$false
    }
    catch {
        Write-Log "Failed to elevate $Path : $($_.Exception.Message)" "ERROR"
    }
}

function Start-GodMode {
    if (-not (Test-Path $ToggleFile)) {
        Write-Log "God Mode is OFF" "ERROR"
        return
    }

    Write-Log "God Mode active - Waiting for you to start programs..." "INFO"

    $seenProcesses = @{}

    while ($true) {
        Start-Sleep -Seconds 2

        # Get processes started in the last 8 seconds
        $recentProcesses = Get-WmiObject Win32_Process | Where-Object {
            $_.CreationDate -and 
            ([datetime]::ParseExact($_.CreationDate.Substring(0,14), "yyyyMMddHHmmss", $null)) -gt (Get-Date).AddSeconds(-8)
        }

        foreach ($proc in $recentProcesses) {
            if ($proc.ExecutablePath -and $proc.ExecutablePath -like "*.exe") {
                $path = $proc.ExecutablePath

                # Only elevate if we haven't seen this exact path recently
                if (-not $seenProcesses.ContainsKey($path)) {
                    $seenProcesses[$path] = (Get-Date)
                    Elevate-Program $path
                }
            }
        }

        # Clean old entries from memory (older than 30 seconds)
        $seenProcesses = $seenProcesses.GetEnumerator() | 
            Where-Object { $_.Value -gt (Get-Date).AddSeconds(-30) } | 
            ForEach-Object { @{ $_.Key = $_.Value } }
    }
}

# === CLI Commands ===
if ($ToggleOn)  { Set-Toggle $true; exit }
if ($ToggleOff) { Set-Toggle $false; exit }
if ($Status)    { Get-Status; exit }

if ($Launch) {
    Start-GodMode
} else {
    Write-Host "`n=== GOD MODE (Elevate on Manual Start) ===" -ForegroundColor Cyan
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable (elevates programs you start)"
    Write-Host "  -ToggleOff    Disable"
    Write-Host "  -Status       Check status"
    Write-Host "  -Launch       Start monitoring"
    Write-Host ""
    Write-Host "When ON: Programs you manually open will be elevated to SYSTEM." -ForegroundColor Yellow
}