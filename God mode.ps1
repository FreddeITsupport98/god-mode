#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode - Aggressive Auto Elevation (When Toggle is ON)
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch
)

$ToggleFile   = "C:\Windows\GodMode_Enabled.flag"
$LastScanFile = "C:\Windows\GodMode_LastScan.txt"
$LogFile      = "C:\Windows\GodMode_Log.txt"
$WatcherTask  = "GodMode_AggressiveWatcher"

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
        Write-Log "God Mode ENABLED (Aggressive Mode)" "OK"
        Start-AggressiveWatcher
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON (Aggressive)" -ForegroundColor Green
    } else {
        Write-Host "God Mode: OFF" -ForegroundColor Yellow
    }
}

function Start-AggressiveWatcher {
    Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue

    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 3) -RepetitionDuration (New-TimeSpan -Days 365)
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $WatcherTask -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
    Write-Log "Aggressive watcher started (checks every 3 minutes)" "OK"
}

function Get-Win32Programs {
    $paths = @("\( env:ProgramFiles", " \){env:ProgramFiles(x86)}")
    $list = @()
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem $p -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 100KB } |
                Select-Object -ExpandProperty FullName |
                ForEach-Object { $list += $_ }
        }
    }
    return $list | Sort-Object | Get-Unique
}

function Run-AsSystem {
    param([string]$Path, [string]$Type = "Win32")
    Write-Log "Auto-elevating as SYSTEM: $Path" "WARN"
    if ($Type -eq "UWP") {
        Start-Process explorer.exe -ArgumentList $Path
    } else {
        $Action = New-ScheduledTaskAction -Execute $Path
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        \( temp = "GodMode_Temp_ \)([Guid]::NewGuid())"
        Register-ScheduledTask -TaskName $temp -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $temp
        Start-Sleep -Seconds 1
        Unregister-ScheduledTask -TaskName $temp -Confirm:$false
    }
}

function Start-GodMode {
    if (-not (Test-Path $ToggleFile)) {
        Write-Log "God Mode is OFF" "ERROR"
        return
    }

    # === Aggressive Auto Elevation ===
    $programs = Get-Win32Programs

    # Elevate new programs
    if (Test-Path $LastScanFile) {
        $old = Get-Content $LastScanFile
        $new = $programs | Where-Object { $_ -notin $old }
        foreach ($prog in $new) {
            Run-AsSystem $prog "Win32"
        }
    }
    $programs | Out-File $LastScanFile -Force

    # Also try to elevate important system tools periodically
    $systemTools = @(
        "$env:SystemRoot\explorer.exe",
        "$env:SystemRoot\System32\cmd.exe",
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        "$env:SystemRoot\regedit.exe",
        "$env:SystemRoot\System32\taskmgr.exe"
    )

    foreach ($tool in $systemTools) {
        if (Test-Path $tool) {
            Run-AsSystem $tool "Win32"
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
    Write-Host "`n=== GOD MODE (Aggressive) ===" -ForegroundColor Red
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable aggressive auto-elevation"
    Write-Host "  -ToggleOff    Disable God Mode"
    Write-Host "  -Status       Check status"
    Write-Host "  -Launch       Manual trigger of aggressive elevation"
    Write-Host ""
    Write-Host "When ON: Auto-elevates new programs + important system tools every 3 minutes." -ForegroundColor Yellow
}