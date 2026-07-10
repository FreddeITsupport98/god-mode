#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v4 - Win32 + Windows Apps Auto Elevation + Easy Menu (VM Testing)
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

function Get-WindowsApps {
    try {
        return Get-AppxPackage | Where-Object { $_.InstallLocation } |
            Select-Object @{Name="Name"; Expression={$_.Name}}, 
                          @{Name="FullName"; Expression={"shell:AppsFolder\$($_.PackageFamilyName)!App"}}
    } catch { return @() }
}

function Run-AsSystem {
    param([string]$Path, [string]$Type = "Win32")
    Write-Log "Launching as SYSTEM ($Type): $Path" "OK"
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
        Write-Log "God Mode is OFF. Enable it first." "ERROR"
        return
    }

    # === Auto elevate new Win32 programs ===
    $currentWin32 = Get-Win32Programs
    if (Test-Path $LastScanFile) {
        $old = Get-Content $LastScanFile
        $newWin32 = $currentWin32 | Where-Object { $_ -notin $old }
        foreach ($prog in $newWin32) {
            Write-Log "New Win32 app detected → Elevating: $prog" "WARN"
            Run-AsSystem $prog "Win32"
        }
    }
    $currentWin32 | Out-File $LastScanFile -Force

    # === Try to auto elevate some Windows Apps ===
    $uwpApps = Get-WindowsApps
    $importantUWP = $uwpApps | Where-Object { 
        $_.Name -match "Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|Microsoft.Windows.Settings"
    }
    foreach ($app in $importantUWP) {
        Write-Log "Attempting to elevate Windows App: $($app.Name)" "INFO"
        Run-AsSystem $app.FullName "UWP"
    }

    # === Easy Menu ===
    Write-Host "`n=== GOD MODE MENU ===" -ForegroundColor Cyan
    Write-Host "[1] Windows Explorer as SYSTEM"
    Write-Host "[2] Command Prompt as SYSTEM"
    Write-Host "[3] PowerShell as SYSTEM"
    Write-Host "[4] Registry Editor as SYSTEM"
    Write-Host "[5] Task Manager as SYSTEM"
    Write-Host "[6] Windows Settings as SYSTEM"
    Write-Host "[7] Microsoft Store as SYSTEM"
    Write-Host "[8] Calculator as SYSTEM"
    Write-Host "[9] Photos as SYSTEM"
    Write-Host "[10] Scan & Elevate All Programs"
    Write-Host "[11] Exit"

    $choice = Read-Host "`nSelect option (1-11)"
    switch ($choice) {
        "1"  { Run-AsSystem "$env:SystemRoot\explorer.exe" }
        "2"  { Run-AsSystem "$env:SystemRoot\System32\cmd.exe" }
        "3"  { Run-AsSystem "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
        "4"  { Run-AsSystem "$env:SystemRoot\regedit.exe" }
        "5"  { Run-AsSystem "$env:SystemRoot\System32\taskmgr.exe" }
        "6"  { Run-AsSystem "shell:AppsFolder\Microsoft.Windows.Settings_8wekyb3d8bbwe!App" "UWP" }
        "7"  { Run-AsSystem "shell:AppsFolder\Microsoft.WindowsStore_8wekyb3d8bbwe!App" "UWP" }
        "8"  { Run-AsSystem "shell:AppsFolder\Microsoft.WindowsCalculator_8wekyb3d8bbwe!App" "UWP" }
        "9"  { Run-AsSystem "shell:AppsFolder\Microsoft.Windows.Photos_8wekyb3d8bbwe!App" "UWP" }
        "10" {
            $all = Get-Win32Programs
            for ($i = 0; $i -lt $all.Count; \( i++) { Write-Host "[ \)($i+1)] $($all[$i])" }
            $num = Read-Host "Enter number"
            if (\( num -match '^\d+ \)') { Run-AsSystem $all[[int]$num-1] }
        }
        default { Write-Host "Exiting..." }
    }
}

# === CLI ===
if ($ToggleOn)  { Set-Toggle $true; exit }
if ($ToggleOff) { Set-Toggle $false; exit }
if ($Status)    { Get-Status; exit }

if ($Launch) {
    Start-GodMode
} else {
    Write-Host "`n=== GOD MODE v4 (Win32 + Windows Apps) ===" -ForegroundColor Red
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable God Mode + Auto Watcher"
    Write-Host "  -ToggleOff    Disable God Mode"
    Write-Host "  -Status       Check status"
    Write-Host "  -Launch       Open menu + auto elevation"
    Write-Host ""
    Write-Host "Auto-elevates both traditional programs and some Windows Apps when ON." -ForegroundColor Yellow
}