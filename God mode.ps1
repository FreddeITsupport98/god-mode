#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode - MAXIMUM Aggressive (Elevates All Programs + System Tools)
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch
)

$ToggleFile   = "C:\Windows\GodMode_Enabled.flag"
$LogFile      = "C:\Windows\GodMode_Log.txt"
$WatcherTask  = "GodMode_MaxAggressive"

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
        Write-Log "God Mode MAXIMUM AGGRESSIVE ENABLED" "WARN"
        Start-MaxAggressiveWatcher
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON (MAXIMUM AGGRESSIVE)" -ForegroundColor Red
    } else {
        Write-Host "God Mode: OFF" -ForegroundColor Yellow
    }
}

function Start-MaxAggressiveWatcher {
    Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue

    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2)
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $WatcherTask -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
    Write-Log "MAXIMUM Aggressive watcher started (every 2 minutes)" "WARN"
}

function Get-AllExecutables {
    $paths = @("\( env:ProgramFiles", " \){env:ProgramFiles(x86)}")
    $list = @()
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem $p -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 80KB } |
                Select-Object -ExpandProperty FullName |
                ForEach-Object { $list += $_ }
        }
    }
    return $list | Sort-Object | Get-Unique
}

function Run-AsSystem {
    param([string]$Path)
    Write-Log "MAX ELEVATE: $Path" "WARN"
    $Action = New-ScheduledTaskAction -Execute $Path
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    \( temp = "GodMode_Temp_ \)([Guid]::NewGuid())"
    Register-ScheduledTask -TaskName $temp -Action $Action -Principal $Principal -Force | Out-Null
    Start-ScheduledTask -TaskName $temp
    Start-Sleep -Milliseconds 600
    Unregister-ScheduledTask -TaskName $temp -Confirm:$false
}

function Start-GodMode {
    if (-not (Test-Path $ToggleFile)) {
        Write-Log "God Mode is OFF" "ERROR"
        return
    }

    Write-Log "MAX AGGRESSIVE SCAN - Elevating all programs + system tools..." "WARN"

    # Elevate ALL existing programs
    $allPrograms = Get-AllExecutables
    foreach ($prog in $allPrograms) {
        Run-AsSystem $prog
    }

    # Also elevate important system tools
    $systemTools = @(
        "$env:SystemRoot\explorer.exe",
        "$env:SystemRoot\System32\cmd.exe",
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        "$env:SystemRoot\regedit.exe",
        "$env:SystemRoot\System32\taskmgr.exe",
        "$env:SystemRoot\System32\services.msc"
    )

    foreach ($tool in $systemTools) {
        if (Test-Path $tool) {
            Run-AsSystem $tool
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
    Write-Host "`n=== GOD MODE - MAXIMUM AGGRESSIVE ===" -ForegroundColor Red
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable MAXIMUM aggressive mode"
    Write-Host "  -ToggleOff    Disable"
    Write-Host "  -Status       Check status"
    Write-Host "  -Launch       Manual aggressive elevation of ALL programs"
    Write-Host ""
    Write-Host "WARNING: This will try to elevate almost everything as SYSTEM every 2 minutes." -ForegroundColor Yellow
}