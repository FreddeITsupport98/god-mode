#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode with Background Auto-Detection + Auto Elevation (VM Testing)
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch
)

$ToggleFile       = "C:\Windows\GodMode_Enabled.flag"
$LastScanFile     = "C:\Windows\GodMode_LastScan.txt"
$LogFile          = "C:\Windows\GodMode_Log.txt"
$WatcherTaskName  = "GodMode_BackgroundWatcher"

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
        Write-Log "God Mode ENABLED" "OK"
        Start-BackgroundWatcher
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON" -ForegroundColor Green
    } else {
        Write-Host "God Mode: OFF" -ForegroundColor Yellow
    }
}

function Get-AllPrograms {
    $paths = @("\( env:ProgramFiles", " \){env:ProgramFiles(x86)}")
    $list = @()
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 100KB } |
                Select-Object -ExpandProperty FullName |
                ForEach-Object { $list += $_ }
        }
    }
    return $list | Sort-Object | Get-Unique
}

function Start-BackgroundWatcher {
    Unregister-ScheduledTask -TaskName $WatcherTaskName -Confirm:$false -ErrorAction SilentlyContinue

    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 365)
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $WatcherTaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
    Write-Log "Background watcher started (checks every 5 minutes)" "OK"
}

function Start-GodMode {
    if (-not (Test-Path $ToggleFile)) {
        Write-Log "God Mode is OFF. Enable it with -ToggleOn" "ERROR"
        return
    }

    Write-Log "Scanning for programs..." "INFO"
    $current = Get-AllPrograms

    # Detect new programs
    $newPrograms = @()
    if (Test-Path $LastScanFile) {
        $old = Get-Content $LastScanFile
        $newPrograms = $current | Where-Object { $_ -notin $old }
    }

    if ($newPrograms.Count -gt 0) {
        Write-Log "New programs detected: $($newPrograms.Count)" "WARN"
        foreach ($prog in $newPrograms) {
            Write-Log "Auto-elevating: $prog" "OK"
            $Action = New-ScheduledTaskAction -Execute $prog
            $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            \( tempTask = "GodMode_Auto_ \)([Guid]::NewGuid())"
            Register-ScheduledTask -TaskName $tempTask -Action $Action -Principal $Principal -Force | Out-Null
            Start-ScheduledTask -TaskName $tempTask
            Start-Sleep -Milliseconds 800
            Unregister-ScheduledTask -TaskName $tempTask -Confirm:$false
        }
    }

    $current | Out-File $LastScanFile -Force
}

# === Main CLI ===
if ($ToggleOn)  { Set-Toggle $true; exit }
if ($ToggleOff) { Set-Toggle $false; exit }
if ($Status)    { Get-Status; exit }

if ($Launch) {
    Start-GodMode
} else {
    Write-Host "`n=== GOD MODE CONTROLLER (Final) ===" -ForegroundColor Red
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable God Mode + Background Watcher"
    Write-Host "  -ToggleOff    Disable God Mode"
    Write-Host "  -Status       Check current status"
    Write-Host "  -Launch       Manual scan + auto elevation of new programs"
    Write-Host ""
    Write-Host "When God Mode is ON, new programs are automatically elevated to SYSTEM every 5 minutes." -ForegroundColor Yellow
}