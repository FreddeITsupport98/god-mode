#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode - Optimized Aggressive (All Programs + System Tools)
    Frequency: Every 60 seconds | Optimized to reduce unnecessary load
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch
)

$ToggleFile   = "C:\Windows\GodMode_Enabled.flag"
$LogFile      = "C:\Windows\GodMode_Log.txt"
$LastElevated = "C:\Windows\GodMode_LastElevated.txt"
$WatcherTask  = "GodMode_OptimizedAggressive"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$Time] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8
    Write-Host $logEntry
}

function Set-Toggle {
    param([bool]$Enabled)
    if ($Enabled) {
        "ON" | Out-File $ToggleFile -Force
        Write-Log "God Mode ENABLED (Optimized Aggressive)" "WARN"
        Start-OptimizedWatcher
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON (Optimized Aggressive - Every 60s)" -ForegroundColor Red
    } else {
        Write-Host "God Mode: OFF" -ForegroundColor Yellow
    }
}

function Start-OptimizedWatcher {
    Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue

    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Seconds 60)
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $WatcherTask -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
    Write-Log "Optimized Aggressive Watcher started (every 60 seconds)" "OK"
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
    try {
        $Action = New-ScheduledTaskAction -Execute $Path
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        \( tempTask = "GodMode_Temp_ \)([Guid]::NewGuid())"
        Register-ScheduledTask -TaskName $tempTask -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $tempTask
        Start-Sleep -Milliseconds 400
        Unregister-ScheduledTask -TaskName $tempTask -Confirm:$false
        Write-Log "Elevated: $Path" "OK"
    } catch {
        Write-Log "Failed to elevate: $Path - $($_.Exception.Message)" "ERROR"
    }
}

function Start-GodMode {
    if (-not (Test-Path $ToggleFile)) {
        Write-Log "God Mode is OFF" "ERROR"
        return
    }

    Write-Log "=== AGGRESSIVE CYCLE START ===" "INFO"

    # Get all programs
    $allPrograms = Get-AllExecutables
    Write-Log "Found $($allPrograms.Count) programs to process" "INFO"

    # Elevate all programs (optimized - only new ones since last cycle)
    $alreadyElevated = @()
    if (Test-Path $LastElevated) {
        $alreadyElevated = Get-Content $LastElevated
    }

    $toElevate = $allPrograms | Where-Object { $_ -notin $alreadyElevated }
    Write-Log "Elevating $($toElevate.Count) new/remaining programs..." "WARN"

    foreach ($prog in $toElevate) {
        Run-AsSystem $prog
    }

    # Save what we just elevated
    $allPrograms | Out-File $LastElevated -Force

    # Elevate important system tools every cycle
    $systemTools = @(
        "$env:SystemRoot\explorer.exe",
        "$env:SystemRoot\System32\cmd.exe",
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        "$env:SystemRoot\regedit.exe",
        "$env:SystemRoot\System32\taskmgr.exe"
    )

    foreach ($tool in $systemTools) {
        if (Test-Path $tool) {
            Run-AsSystem $tool
        }
    }

    Write-Log "=== AGGRESSIVE CYCLE FINISHED ===" "INFO"
}

# === CLI Commands ===
if ($ToggleOn)  { Set-Toggle $true; exit }
if ($ToggleOff) { Set-Toggle $false; exit }
if ($Status)    { Get-Status; exit }

if ($Launch) {
    Start-GodMode
} else {
    Write-Host "`n=== GOD MODE - OPTIMIZED AGGRESSIVE ===" -ForegroundColor Red
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable aggressive mode (every 60s)"
    Write-Host "  -ToggleOff    Disable"
    Write-Host "  -Status       Check status"
    Write-Host "  -Launch       Manual aggressive elevation"
    Write-Host ""
    Write-Host "Elevates all programs + system tools. Optimized to reduce repeated work." -ForegroundColor Yellow
}