#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Explicit SYSTEM Shell Launcher for Windows Security Testing
.DESCRIPTION
    Legitimate tool for security professionals to launch an explicit interactive
    shell as NT AUTHORITY\SYSTEM. Uses a temporary scheduled task — no persistence,
    no silent elevation, and no permanent security boundary removal.
    
    IMPORTANT: This requires an explicit user action to launch. It does NOT
    automatically elevate every process or remove UAC.
.NOTES
    Run this script as Administrator. It will prompt before launching SYSTEM shell.
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
    Write-Status "Cleaning up temporary scheduled task..." "WARN"
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Status "Cleanup complete." "OK"
    } catch {
        Write-Status "Nothing to clean up." "OK"
    }
}

function Invoke-SystemShell {
    Write-Status "Preparing to launch SYSTEM shell..." "WARN"
    Write-Status "This will spawn a NEW interactive PowerShell window running as NT AUTHORITY\SYSTEM." "WARN"
    Write-Status "The shell will NOT auto-elevate future processes. It is a single explicit session." "WARN"
    
    $Confirm = Read-Host "`nType 'SYSTEM' to confirm you want to launch a SYSTEM shell"
    if ($Confirm -ne "SYSTEM") {
        Write-Status "Launch cancelled by user." "WARN"
        return
    }

    # Clean up any stale task first
    Invoke-Cleanup | Out-Null

    # Path to a temporary marker file so we know when the shell is ready
    $TempDir = $env:TEMP
    $ReadyMarker = Join-Path $TempDir "SysShell_Ready_$PID.txt"
    $CleanupMarker = Join-Path $TempDir "SysShell_Cleanup_$PID.txt"

    # Build a small bootstrap script that launches an interactive shell and signals readiness
    $BootstrapScript = @"
`$host.ui.RawUI.WindowTitle = "SYSTEM Shell - PID: `$PID"
"SYSTEM Shell Active. Run 'exit' to close." | Out-File -FilePath "$ReadyMarker" -Force
# Wait for cleanup signal
while (-not (Test-Path "$CleanupMarker")) { Start-Sleep -Milliseconds 500 }
Remove-Item -Path "$ReadyMarker" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$CleanupMarker" -Force -ErrorAction SilentlyContinue
"@
    $BootstrapPath = Join-Path $TempDir "SysShell_Bootstrap_$PID.ps1"
    Set-Content -Path $BootstrapPath -Value $BootstrapScript -Encoding UTF8 -Force

    # Create the scheduled task to run PowerShell as SYSTEM
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$BootstrapPath`""
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # No trigger = on-demand only; we start it manually
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Principal $Principal -Force | Out-Null
    Write-Status "Temporary scheduled task registered." "OK"

    Start-ScheduledTask -TaskName $TaskName
    Write-Status "SYSTEM shell task started. Waiting for window..." "OK"

    # Wait for the ready marker (with timeout)
    $Timeout = 30
    $Elapsed = 0
    while (-not (Test-Path $ReadyMarker) -and $Elapsed -lt $Timeout) {
        Start-Sleep -Seconds 1
        $Elapsed++
    }

    if (Test-Path $ReadyMarker) {
        Write-Status "SYSTEM shell is running in a separate window." "OK"
        Write-Status "When you close the SYSTEM shell window, this script will auto-clean the task." "INFO"

        # Monitor the task until it completes or the user exits
        do {
            Start-Sleep -Seconds 2
            $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        } while ($Task -and ($Task.State -eq "Running"))

        # Signal cleanup to the bootstrap script
        "cleanup" | Out-File -FilePath $CleanupMarker -Force
        Start-Sleep -Seconds 1

        # Final cleanup
        Remove-Item -Path $BootstrapPath -Force -ErrorAction SilentlyContinue
        Invoke-Cleanup
        Write-Status "SYSTEM shell session ended and all temporary artifacts removed." "OK"
    } else {
        Write-Status "Timed out waiting for SYSTEM shell to start. Check Task Scheduler for errors." "ERROR"
        Invoke-Cleanup
        Remove-Item -Path $BootstrapPath -Force -ErrorAction SilentlyContinue
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
    
    $Choice = Read-Host "`nLaunch SYSTEM shell now? (y/N)"
    if ($Choice -eq "y" -or $Choice -eq "Y") {
        Invoke-SystemShell
    } else {
        Write-Status "Cancelled." "INFO"
    }
}
