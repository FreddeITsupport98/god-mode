# Enterprise DNS Lockout Suite (DNSGuard)

A Zero-Trust Windows security tool for DNS hijack protection, browser DoH restriction, and registry-level network hardening.

## Table of Contents

- [Quick Links](#quick-links)
- [Features](#features)
- [Scripts](#scripts)
- [Usage](#usage)
- [System Shell Launcher](#system-shell-launcher)
- [Testing](#testing)
- [Changelog](#changelog)
- [Unreleased](#unreleased)

## Quick Links

- [God_mode.bat](God_mode.bat) — **Recommended launcher** (auto-bypasses Execution Policy, no system changes)
- [God_mode.ps1](God_mode.ps1) — Main DNS protection & installer suite
- [Launch-SystemShell.bat](Launch-SystemShell.bat) — **Recommended launcher** for SYSTEM shell
- [Launch-SystemShell.ps1](Launch-SystemShell.ps1) — Explicit SYSTEM shell launcher for security testing
- [tests/Test-Suite.ps1](tests/Test-Suite.ps1) — Regression test suite (no side-effects)
- [changelog.md](changelog.md) — Full change history

## Features

- **IPv4 & IPv6 DNS registry ACL locks** — Prevents tampering with interface DNS settings
- **Browser DoH GPO restrictions** — Disables DNS-over-HTTPS in Edge, Chrome, and Firefox
- **Self-healing persistence** — Scheduled tasks + WMI subscription auto-restore locks
- **NTFS self-defense** — Hardens installation directory against deletion/modification
- **Integrity checking** — SHA256 hash verification with registry + file backup
- **Explicit SYSTEM shell** — Legitimate, non-persistent SYSTEM shell for security testing
- **Regression test suite** — Validates syntax and structure without modifying the system

## Scripts

### God_mode.ps1

The main protection suite. Run as Administrator.

```powershell
# Interactive menu
.\God_mode.ps1

# CLI flags
.\God_mode.ps1 -Lock          # Deploy DNS locks
.\God_mode.ps1 -Unlock        # Remove DNS locks
.\God_mode.ps1 -Install       # Install persistence service
.\God_mode.ps1 -Uninstall     # Uninstall (requires SYSTEM shell)
```

### Launch-SystemShell.ps1

Explicit, non-persistent SYSTEM shell launcher for security testing. No silent elevation, no persistence, no UAC bypass.

```powershell
# Launch a SYSTEM shell (explicit confirmation required)
.\Launch-SystemShell.ps1 -Launch

# Cleanup any stale task
.\Launch-SystemShell.ps1 -Cleanup
```

## Usage

1. Right-click `God_mode.bat` and choose **Run as administrator**
2. Select `[1] DEPLOY LOCK` to secure adapters
3. Select `[3] INSTALL SERVICE` to enable auto-heal persistence
4. Right-click `Launch-SystemShell.bat` and choose **Run as administrator** when you need an explicit SYSTEM shell

> **Note:** The `.bat` wrappers use `-ExecutionPolicy Bypass` for **this script only** and do **not** change your system policy. If you prefer PowerShell directly, use `powershell -ExecutionPolicy Bypass -File .\God_mode.ps1`.

## System Shell Launcher

The `Launch-SystemShell.ps1` script creates a temporary scheduled task running as `NT AUTHORITY\SYSTEM`. It:
- Requires you to type `SYSTEM` to confirm
- Cleans up the task automatically after the shell closes
- Does NOT auto-elevate other processes
- Does NOT create persistent startup triggers
- Is intended for legitimate security testing and system administration only

## Testing

Run the regression test suite (no system changes):

```powershell
.\tests\Test-Suite.ps1
```

The suite validates:
- PowerShell syntax for all scripts
- Script structure and function definitions
- Installer/uninstaller logic coverage
- Menu integrity checks
- Integrity hash verification paths
- Explicit SYSTEM shell safety (no UAC bypass, no persistence)

## Changelog

See [changelog.md](changelog.md) for the full history.

## Unreleased

- Added `Launch-SystemShell.ps1` for explicit SYSTEM shell testing
- Added `tests/Test-Suite.ps1` regression suite
- Added `changelog.md` and `README.md`

---

**Use only on systems you own or have explicit authorization to test.**
