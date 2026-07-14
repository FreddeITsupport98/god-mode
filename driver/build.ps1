# build.ps1 — God Mode Driver/Proxy Build Script
# Builds gmproxy.exe (IFEO proxy) and gmhook.dll (shell hook) from C sources.
# Requires either:
#   - Visual Studio (cl.exe / link.exe) in PATH, or
#   - MinGW-w64 cross-compiler (x86_64-w64-mingw32-gcc) on Linux, or
#   - mingw-w64 on Windows (gcc)
#
# Usage: pwsh -File driver\build.ps1  (or powershell -File driver\build.ps1 on older systems)

$DriverDir = $PSScriptRoot
$ErrorActionPreference = "Stop"

function Test-Tool {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Build-WithMSVC {
    param([string]$OutDir)
    Write-Host "[BUILD] Using MSVC (cl.exe)" -ForegroundColor Cyan

    # gmproxy.exe — IFEO proxy
    $proxySrc = Join-Path $DriverDir "gmproxy.c"
    $proxyOut = Join-Path $OutDir "gmproxy.exe"
    cl /nologo /O2 /W3 /Fe:"$proxyOut" "$proxySrc" kernel32.lib advapi32.lib ntdll.lib
    if ($LASTEXITCODE -ne 0) { throw "gmproxy.exe build failed" }
    Write-Host "[BUILD] gmproxy.exe -> $proxyOut" -ForegroundColor Green

    # gmhook.dll — shell hook
    $hookSrc = Join-Path $DriverDir "gmhook.c"
    $hookOut = Join-Path $OutDir "gmhook.dll"
    cl /nologo /O2 /W3 /LD /Fe:"$hookOut" "$hookSrc" kernel32.lib advapi32.lib ntdll.lib user32.lib
    if ($LASTEXITCODE -ne 0) { throw "gmhook.dll build failed" }
    Write-Host "[BUILD] gmhook.dll -> $hookOut" -ForegroundColor Green
}

function Build-WithMinGW {
    param([string]$OutDir, [string]$Prefix = "gcc")
    Write-Host "[BUILD] Using MinGW ($Prefix)" -ForegroundColor Cyan

    $proxySrc = Join-Path $DriverDir "gmproxy.c"
    $proxyOut = Join-Path $OutDir "gmproxy.exe"
    & $Prefix -O2 -Wall -o "$proxyOut" "$proxySrc" -ladvapi32 -lkernel32 -lntdll
    if ($LASTEXITCODE -ne 0) { throw "gmproxy.exe build failed" }
    Write-Host "[BUILD] gmproxy.exe -> $proxyOut" -ForegroundColor Green

    $hookSrc = Join-Path $DriverDir "gmhook.c"
    $hookOut = Join-Path $OutDir "gmhook.dll"
    & $Prefix -O2 -Wall -shared -o "$hookOut" "$hookSrc" -ladvapi32 -lkernel32 -lntdll -luser32
    if ($LASTEXITCODE -ne 0) { throw "gmhook.dll build failed" }
    Write-Host "[BUILD] gmhook.dll -> $hookOut" -ForegroundColor Green
}

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  God Mode C Component Builder" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

$OutDir = $DriverDir
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

if (Test-Tool "cl") {
    Build-WithMSVC -OutDir $OutDir
} elseif (Test-Tool "x86_64-w64-mingw32-gcc") {
    Build-WithMinGW -OutDir $OutDir -Prefix "x86_64-w64-mingw32-gcc"
} elseif (Test-Tool "gcc") {
    Build-WithMinGW -OutDir $OutDir -Prefix "gcc"
} else {
    Write-Host "[ERROR] No compiler found. Install Visual Studio or MinGW-w64." -ForegroundColor Red
    Write-Host "  Linux/Fedora: sudo dnf install mingw64-gcc" -ForegroundColor Yellow
    Write-Host "  Windows:      Install Visual Studio Build Tools or MSYS2 MinGW" -ForegroundColor Yellow
    exit 1
}

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  All builds succeeded." -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Cyan
