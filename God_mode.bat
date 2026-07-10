@echo off
:: God_mode.bat — Launcher wrapper to bypass Execution Policy for God_mode.ps1
:: Run this file instead of the .ps1 directly if your system blocks scripts.
:: This does NOT change system-wide policy; it only bypasses for this script.

echo ================================================
echo  DNSGuard Launcher — Execution Policy Bypass    
echo ================================================
echo.

:: Check if we are running as admin (required for the script to work)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARN] Administrator privileges required.
    echo Right-click this file and select "Run as administrator".
    pause
    exit /b 1
)

:: Resolve the directory where this .bat file lives
set "SCRIPTDIR=%~dp0"
set "PSPATH=%SCRIPTDIR%God_mode.ps1"

if not exist "%PSPATH%" (
    echo [ERROR] God_mode.ps1 not found in: %SCRIPTDIR%
    pause
    exit /b 1
)

:: Launch PowerShell with Bypass for this script only
echo Launching God_mode.ps1 with ExecutionPolicy Bypass...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PSPATH%" %*

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Script exited with code %errorlevel%.
    pause
)
