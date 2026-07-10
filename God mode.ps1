#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode - Clean Single List (All Programs + System Apps)
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
$WatcherTask  = "GodMode_Watcher"

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
        Start-Watcher
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON" -ForegroundColor Green
    } else {
        Write-Host "God Mode: OFF" -ForegroundColor Yellow
    }
}

function Start-Watcher {
    Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $WatcherTask -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
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

function Get-CommonSystemTools {
    return @(
        "$env:SystemRoot\explorer.exe",
        "$env:SystemRoot\System32\cmd.exe",
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        "$env:SystemRoot\regedit.exe",
        "$env:SystemRoot\System32\taskmgr.exe",
        "$env:SystemRoot\System32\services.msc"
    )
}

function Get-WindowsApps {
    try {
        return Get-AppxPackage | Where-Object { $_.InstallLocation } |
            Select-Object @{Name="DisplayName"; Expression={ $_.Name }},
                          @{Name="LaunchString"; Expression={ "shell:AppsFolder\$($_.PackageFamilyName)!App" }}
    } catch { return @() }
}

function Run-AsSystem {
    param([string]$Path, [string]$Type = "Win32")
    Write-Log "Running as SYSTEM: $Path" "OK"
    if ($Type -eq "UWP") {
        Start-Process explorer.exe -ArgumentList $Path
    } else {
        $Action = New-ScheduledTaskAction -Execute $Path
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        \( temp = "GodMode_Temp_ \)([Guid]::NewGuid())"
        Register-ScheduledTask -TaskName $temp -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $temp
        Start-Sleep -Seconds 1.5
        Unregister-ScheduledTask -TaskName $temp -Confirm:$false
    }
}

function Start-GodMode {
    if (-not (Test-Path $ToggleFile)) {
        Write-Log "God Mode is OFF. Enable it with -ToggleOn" "ERROR"
        return
    }

    # Auto elevate new Win32 programs
    $currentWin32 = Get-Win32Programs
    if (Test-Path $LastScanFile) {
        $old = Get-Content $LastScanFile
        $newPrograms = $currentWin32 | Where-Object { $_ -notin $old }
        foreach ($prog in $newPrograms) {
            Write-Log "New program detected → Auto elevating: $prog" "WARN"
            Run-AsSystem $prog "Win32"
        }
    }
    $currentWin32 | Out-File $LastScanFile -Force

    # Build combined clean list
    $systemTools = Get-CommonSystemTools
    $uwpApps = Get-WindowsApps | Select-Object -First 15
    $installedPrograms = Get-Win32Programs | Select-Object -First 25

    $allItems = @()

    # Add System Tools
    foreach ($tool in $systemTools) {
        $allItems += [PSCustomObject]@{
            Display = "[System] $(Split-Path $tool -Leaf)"
            Path    = $tool
            Type    = "Win32"
        }
    }

    # Add Windows Apps
    foreach ($app in $uwpApps) {
        $allItems += [PSCustomObject]@{
            Display = "[Windows App] $($app.DisplayName)"
            Path    = $app.LaunchString
            Type    = "UWP"
        }
    }

    # Add Installed Programs
    foreach ($prog in $installedPrograms) {
        $allItems += [PSCustomObject]@{
            Display = "[Program] $(Split-Path $prog -Leaf)"
            Path    = $prog
            Type    = "Win32"
        }
    }

    # Show clean single list
    Write-Host "`n=== GOD MODE - Select What to Run as SYSTEM ===" -ForegroundColor Cyan
    for ($i = 0; $i -lt $allItems.Count; $i++) {
        Write-Host "[$($i+1)] $($allItems[$i].Display)"
    }

    $choice = Read-Host "`nEnter number (or press Enter to exit)"
    if (\( choice -match '^\d+ \)') {
        $index = [int]$choice - 1
        if ($index -ge 0 -and $index -lt $allItems.Count) {
            $selected = $allItems[$index]
            Run-AsSystem $selected.Path $selected.Type
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
    Write-Host "`n=== GOD MODE CONTROLLER ===" -ForegroundColor Red
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable God Mode + Auto Watcher"
    Write-Host "  -ToggleOff    Disable God Mode"
    Write-Host "  -Status       Check status"
    Write-Host "  -Launch       Open clean list (System + Windows Apps + Programs)"
    Write-Host ""
    Write-Host "Shows everything in one clean list. No cluttered menu." -ForegroundColor Yellow
}