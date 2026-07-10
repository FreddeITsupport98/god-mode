@echo off
:: Launch-SystemShell.bat — Launcher wrapper for Launch-SystemShell.ps1
:: Automatically bypasses Execution Policy for this script only.

echo ========================================================
echo  SYSTEM Shell Launcher — Execution Policy Bypass        
echo ========================================================
echo.

:: Check if we are running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARN] Administrator privileges required.
    echo Right-click this file and select "Run as administrator".
    pause
    exit /b 1
)

:: Resolve directory where this .bat lives
set "SCRIPTDIR=%~dp0"
set "PSPATH=%SCRIPTDIR%Launch-SystemShell.ps1"

if not exist "%PSPATH%" (
    echo [ERROR] Launch-SystemShell.ps1 not found in: %SCRIPTDIR%
    pause
    exit /b 1
)

:: Launch with Bypass for this script only
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PSPATH%" -Launch %*

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Script exited with code %errorlevel%.
    pause
)
