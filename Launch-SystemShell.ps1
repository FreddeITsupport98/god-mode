#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Interactive SYSTEM Shell Launcher for Windows Security Testing
.DESCRIPTION
    Legitimate tool for security professionals to launch an explicit interactive
    shell as NT AUTHORITY\SYSTEM.

    METHODS (tried in order):
    1. PsExec (preferred) — launches a real interactive desktop window as SYSTEM.
    2. Temporary scheduled task (fallback) — runs as SYSTEM in Session 0.

    No persistence, no silent elevation, no permanent security boundary removal.

    IMPORTANT: This requires an explicit user action to launch. It does NOT
    automatically elevate every process or remove UAC.
.NOTES
    Run this script as Administrator. It will prompt before launching.
#>

param (
    [switch]$Launch,
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$TaskName = "SysShellLauncher_Explicit"

function Write-Status {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Color = switch ($Level) {
        "OK"     { "Green" }
        "WARN"   { "Yellow" }
        "ERROR"  { "Red" }
        default  { "White" }
    }
    Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color
}

function Invoke-Cleanup {
    Write-Status "Cleaning up temporary artifacts..." "WARN"
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {}
    $TempDir = $env:TEMP
    Get-ChildItem -Path $TempDir -Filter "SysShell_*_$PID.*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Status "Cleanup complete." "OK"
}

function Get-PsExecPath {
    $Candidates = @(
        "psexec.exe",
        "C:\Windows\System32\psexec.exe",
        "C:\Windows\psexec.exe",
        "C:\Sysinternals\psexec.exe",
        "C:\Tools\psexec.exe",
        (Join-Path $env:TEMP "psexec.exe")
    )
    foreach ($c in $Candidates) {
        if (Test-Path $c) { return $c }
    }
    return $null
}

function Install-PsExec {
    param([string]$Destination = (Join-Path $env:TEMP "psexec.exe"))
    Write-Status "PsExec not found. Downloading from Sysinternals..." "WARN"
    $ZipUrl = "https://download.sysinternals.com/files/PSTools.zip"
    $ZipPath = Join-Path $env:TEMP "PSTools.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $ZipUrl -OutFile $ZipPath -UseBasicParsing -ErrorAction Stop
        Write-Status "PSTools.zip downloaded. Extracting psexec.exe..." "OK"

        if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
            Expand-Archive -Path $ZipPath -DestinationPath $env:TEMP -Force -ErrorAction Stop
        } else {
            $Shell = New-Object -ComObject Shell.Application
            $Zip = $Shell.Namespace($ZipPath)
            $Dest = $Shell.Namespace($env:TEMP)
            foreach ($item in $Zip.Items()) {
                if ($item.Name -eq "psexec.exe") {
                    $Dest.CopyHere($item, 0x10)
                }
            }
        }

        $Extracted = Join-Path $env:TEMP "psexec.exe"
        if (Test-Path $Extracted) {
            Move-Item -Path $Extracted -Destination $Destination -Force -ErrorAction Stop
        } else {
            throw "psexec.exe not found in extracted archive."
        }
        Remove-Item -Path $ZipPath -Force -ErrorAction SilentlyContinue
        Write-Status "PsExec installed to $Destination" "OK"
        return $Destination
    } catch {
        Write-Status "Failed to download PsExec: $_" "ERROR"
        return $null
    }
}

function Invoke-SystemShell-PsExec {
    param([string]$PsExecPath)
    Write-Status "Launching interactive SYSTEM shell via PsExec..." "OK"
    Write-Status "A new PowerShell window will open as NT AUTHORITY\SYSTEM." "WARN"
    $Proc = Start-Process -FilePath $PsExecPath -ArgumentList "-accepteula -s -i -d powershell.exe -NoProfile -ExecutionPolicy Bypass" -PassThru
    Write-Status "SYSTEM shell launched. PID: $($Proc.Id)" "OK"
    Write-Status "Type 'whoami' in the new window to confirm it says 'nt authority\system'." "INFO"
}

function Invoke-SystemShell-ScheduledTask {
    Write-Status "Launching SYSTEM shell via temporary scheduled task..." "WARN"
    Write-Status "NOTE: This may run in Session 0 (background) and not show a window." "WARN"
    Write-Status "If no window appears, download PsExec for a fully interactive SYSTEM shell." "INFO"

    Invoke-Cleanup | Out-Null

    $TempDir = $env:TEMP
    $ReadyMarker = Join-Path $TempDir "SysShell_Ready_$PID.txt"
    $CleanupMarker = Join-Path $TempDir "SysShell_Cleanup_$PID.txt"

    $BootstrapScript = @"
`$host.ui.RawUI.WindowTitle = "SYSTEM Shell - PID: `$PID"
"SYSTEM Shell Active. Run 'whoami' to verify." | Out-File -FilePath "$ReadyMarker" -Force
Write-Host "You are running as SYSTEM. Type 'whoami' to verify." -ForegroundColor Green
while (-not (Test-Path "$CleanupMarker")) { Start-Sleep -Milliseconds 500 }
Remove-Item -Path "$ReadyMarker" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$CleanupMarker" -Force -ErrorAction SilentlyContinue
"@
    $BootstrapPath = Join-Path $TempDir "SysShell_Bootstrap_$PID.ps1"
    Set-Content -Path $BootstrapPath -Value $BootstrapScript -Encoding UTF8 -Force

    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$BootstrapPath`""
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName -Action $Action -Principal $Principal -Force | Out-Null
    Write-Status "Temporary SYSTEM task registered." "OK"

    Start-ScheduledTask -TaskName $TaskName
    Write-Status "Task started. Waiting for SYSTEM shell to initialize..." "INFO"

    $Timeout = 30
    $Elapsed = 0
    while (-not (Test-Path $ReadyMarker) -and $Elapsed -lt $Timeout) {
        Start-Sleep -Seconds 1
        $Elapsed++
    }

    if (Test-Path $ReadyMarker) {
        Write-Status "SYSTEM shell is running (Session 0 / background)." "OK"
        Write-Status "Use Task Manager or 'tasklist /fi `"USERNAME eq SYSTEM`"' to find powershell.exe." "INFO"
        Write-Status "Press Enter in THIS window to stop and clean up the SYSTEM shell." "WARN"
        $null = Read-Host
    } else {
        Write-Status "Timed out waiting for SYSTEM shell to start." "ERROR"
    }

    "cleanup" | Out-File -FilePath $CleanupMarker -Force
    Start-Sleep -Seconds 2
    Remove-Item -Path $BootstrapPath -Force -ErrorAction SilentlyContinue
    Invoke-Cleanup
    Write-Status "SYSTEM shell session ended and artifacts removed." "OK"
}

function Invoke-SystemShell {
    Write-Status "=====================================================" "INFO"
    Write-Status "  INTERACTIVE SYSTEM SHELL LAUNCHER                 " "INFO"
    Write-Status "=====================================================" "INFO"
    Write-Status "This will spawn an interactive shell as NT AUTHORITY\SYSTEM." "WARN"
    Write-Status "It does NOT auto-elevate future processes." "WARN"
    Write-Status "It does NOT create persistent startup triggers." "WARN"

    $Confirm = Read-Host "`nType 'SYSTEM' to confirm you want to launch a SYSTEM shell"
    if ($Confirm -ne "SYSTEM") {
        Write-Status "Launch cancelled by user." "WARN"
        return
    }

    $PsExec = Get-PsExecPath
    if ($PsExec) {
        Invoke-SystemShell-PsExec -PsExecPath $PsExec
    } else {
        Write-Status "PsExec not found in PATH or common locations." "WARN"
        $Choice = Read-Host "Download PsExec from Microsoft Sysinternals now? (y/N)"
        if ($Choice -eq "y" -or $Choice -eq "Y") {
            $PsExec = Install-PsExec
            if ($PsExec) {
                Invoke-SystemShell-PsExec -PsExecPath $PsExec
                return
            }
        }
        Write-Status "Falling back to scheduled task (may be non-interactive)." "WARN"
        Invoke-SystemShell-ScheduledTask
    }
}

# --- Main ---

if ($Cleanup) {
    Invoke-Cleanup
    exit
}

if ($Launch) {
    Invoke-SystemShell
} else {
    Write-Status "SYSTEM Shell Launcher (Explicit, Non-Persistent)" "INFO"
    Write-Status "Usage: .\Launch-SystemShell.ps1 -Launch" "INFO"
    Write-Status "       .\Launch-SystemShell.ps1 -Cleanup  (removes stale task)" "INFO"
    Write-Status "" "INFO"
    Write-Status "This tool requires you to explicitly type 'SYSTEM' to confirm." "WARN"
    Write-Status "It does NOT auto-elevate any other processes." "WARN"
    Write-Status "" "INFO"
    Write-Status "Recommended: Install PsExec for a fully interactive desktop shell." "INFO"
    Write-Status "  Download: https://docs.microsoft.com/sysinternals/downloads/psexec" "INFO"

    $Choice = Read-Host "`nLaunch SYSTEM shell now? (y/N)"
    if ($Choice -eq "y" -or $Choice -eq "Y") {
        Invoke-SystemShell
    } else {
        Write-Status "Cancelled." "INFO"
    }
}
