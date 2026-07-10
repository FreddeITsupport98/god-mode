#Requires -RunAsAdministrator

<#
.SYNOPSIS
    God Mode v7 - Restricted to Built-in Administrator only
#>

param(
    [switch]$ToggleOn,
    [switch]$ToggleOff,
    [switch]$Status,
    [switch]$Launch
)

# ============================================================
#  SECURITY CHECK - Only allow Built-in Administrator
# ============================================================
function Test-BuiltInAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    
    # Built-in Administrator has SID ending with -500
    $isBuiltInAdmin = $currentUser.User.Value -like "*-500"
    
    if (-not $isBuiltInAdmin) {
        return $false
    }
    return $true
}

if (-not (Test-BuiltInAdmin) -and -not $Status) {
    Write-Host "`n[SECURITY] This tool can only be used by the Built-in Administrator account." -ForegroundColor Red
    Write-Host "Current user is not the built-in Administrator." -ForegroundColor Yellow
    Write-Host "Exiting for safety.`n" -ForegroundColor Red
    exit 1
}

# ============================================================
#  REST OF THE SCRIPT
# ============================================================

$ToggleFile  = "C:\Windows\GodMode_Enabled.flag"
$LogFile     = "C:\Windows\GodMode_Log.txt"
$WatcherTask = "GodMode_UserStartMonitor"
$RegPath     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Time] [$Level] $Message" | Out-File $LogFile -Append -Encoding UTF8
    Write-Host "[$Time] [$Level] $Message"
}

function Apply-StrongElevation {
    Write-Log "Applying strong elevation (UAC disabled)..." "WARN"

    if (-not (Test-Path "HKLM:\SOFTWARE\GodModeBackup")) {
        New-Item -Path "HKLM:\SOFTWARE\GodModeBackup" -Force | Out-Null
        try {
            $lua = (Get-ItemProperty -Path $RegPath -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
            $consent = (Get-ItemProperty -Path $RegPath -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
            Set-ItemProperty -Path "HKLM:\SOFTWARE\GodModeBackup" -Name EnableLUA -Value $lua
            Set-ItemProperty -Path "HKLM:\SOFTWARE\GodModeBackup" -Name ConsentPromptBehaviorAdmin -Value $consent
        } catch {}
    }

    Set-ItemProperty -Path $RegPath -Name EnableLUA -Value 0 -Force
    Set-ItemProperty -Path $RegPath -Name ConsentPromptBehaviorAdmin -Value 0 -Force
    Set-ItemProperty -Path $RegPath -Name PromptOnSecureDesktop -Value 0 -Force

    Write-Log "UAC fully disabled via registry." "OK"
}

function Revert-RegistryChanges {
    Write-Log "Reverting registry settings..." "WARN"
    try {
        if (Test-Path "HKLM:\SOFTWARE\GodModeBackup") {
            $lua = (Get-ItemProperty -Path "HKLM:\SOFTWARE\GodModeBackup" -Name EnableLUA).EnableLUA
            $consent = (Get-ItemProperty -Path "HKLM:\SOFTWARE\GodModeBackup" -Name ConsentPromptBehaviorAdmin).ConsentPromptBehaviorAdmin
            Set-ItemProperty -Path $RegPath -Name EnableLUA -Value $lua -Force
            Set-ItemProperty -Path $RegPath -Name ConsentPromptBehaviorAdmin -Value $consent -Force
            Remove-Item "HKLM:\SOFTWARE\GodModeBackup" -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log "Could not fully restore settings." "ERROR"
    }
}

function Set-Toggle {
    param([bool]$Enabled)
    if ($Enabled) {
        "ON" | Out-File $ToggleFile -Force
        Apply-StrongElevation
        Write-Log "God Mode ENABLED (Built-in Admin only)" "OK"
        Start-ProcessMonitor
    } else {
        Remove-Item $ToggleFile -Force -ErrorAction SilentlyContinue
        Revert-RegistryChanges
        Write-Log "God Mode DISABLED" "WARN"
        Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-Status {
    if (Test-Path $ToggleFile) {
        Write-Host "God Mode: ON (Built-in Admin + UAC Disabled)" -ForegroundColor Red
    } else {
        Write-Host "God Mode: OFF" -ForegroundColor Yellow
    }
}

function Start-ProcessMonitor {
    Unregister-ScheduledTask -TaskName $WatcherTask -Confirm:$false -ErrorAction SilentlyContinue
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Launch"
    $Trigger = New-ScheduledTaskTrigger -AtLogon
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $WatcherTask -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
}

function Elevate-Program {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Write-Log "Elevating: $Path" "OK"
    try {
        $Action = New-ScheduledTaskAction -Execute $Path
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        \( temp = "GodMode_Elev_ \)([Guid]::NewGuid())"
        Register-ScheduledTask -TaskName $temp -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $temp
        Start-Sleep -Milliseconds 500
        Unregister-ScheduledTask -TaskName $temp -Confirm:$false
    } catch {
        Write-Log "Failed to elevate $Path" "ERROR"
    }
}

function Start-GodMode {
    if (-not (Test-Path $ToggleFile)) {
        Write-Log "God Mode is OFF" "ERROR"
        return
    }

    Write-Log "God Mode active - Monitoring user-started programs..." "INFO"

    $seen = @{}
    while ($true) {
        Start-Sleep -Seconds 2
        $recent = Get-WmiObject Win32_Process | Where-Object {
            $_.CreationDate -and ([datetime]::ParseExact($_.CreationDate.Substring(0,14), "yyyyMMddHHmmss", $null)) -gt (Get-Date).AddSeconds(-8)
        }
        foreach ($p in $recent) {
            if ($p.ExecutablePath -like "*.exe" -and -not $seen.ContainsKey($p.ExecutablePath)) {
                $seen[$p.ExecutablePath] = $true
                Elevate-Program $p.ExecutablePath
            }
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
    Write-Host "`n=== GOD MODE v7 (Built-in Admin Only) ===" -ForegroundColor Red
    Write-Host "This tool can ONLY be used by the Built-in Administrator account."
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  -ToggleOn     Enable (applies strong elevation)"
    Write-Host "  -ToggleOff    Disable + restore settings"
    Write-Host "  -Status       Check status"
    Write-Host "  -Launch       Start monitoring"
}