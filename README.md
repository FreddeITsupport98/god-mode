# Enterprise DNS Lockout Suite + God Mode / OS-Guard Security Suite

> ## 🔴 EXTREME DANGER NOTICE — READ THIS FIRST 🔴
>
> <span style="color:red">**STAGE 1 — AUTHORIZATION & SCOPE**</span>  
> This repository contains Windows PowerShell scripts designed for **AUTHORIZED SECURITY TESTING, SYSTEM ADMINISTRATION RESEARCH, AND CONTROLLED ENVIRONMENT AUDITING ONLY**. These scripts are **NOT** general-purpose utilities. They are specialized tools that deliberately manipulate core Windows security subsystems. If you are not the legal owner of the machine, **DO NOT RUN THESE SCRIPTS**. If you are in a production environment, **DO NOT RUN THESE SCRIPTS**.
>
> <span style="color:red">**STAGE 2 — SECURITY SUBSYSTEMS AFFECTED**</span>  
> Execution will deliberately bypass, disable, or subvert multiple layers of Windows built-in protection, including but not limited to: Windows Defender Antivirus, Windows Firewall, User Account Control (UAC), Windows Event Logging, Security Auditing, Early Launch Anti-Malware (ELAM), Credential Guard / Virtualization-Based Security (VBS), Windows Recovery Environment, Safe Mode boot policies, SmartScreen, Windows Script Host policies, and Remote UAC token filtering. If you do not understand exactly what each function does, **DO NOT RUN THESE SCRIPTS**.
>
> <span style="color:red">**STAGE 3 — SYSTEM CONTROL GRANTED**</span>  
> By executing these scripts, you are explicitly choosing to grant the user **COMPLETE CONTROL OVER THE PC AS SYSTEM** — equivalent to running with the highest possible privileges with all security gates removed. The intended purpose is to **TEST AND VALIDATE SYSTEM HARDENING, RESEARCH ADMINISTRATIVE PERSISTENCE MECHANISMS, AND PROVIDE THE BUILT-IN ADMINISTRATOR ACCOUNT WITH FULL, UNRESTRICTED SYSTEM-LEVEL CONTROL**. This is **INTENTIONAL BY DESIGN** for testing scenarios where an administrator needs unrestricted access to verify system behavior, test recovery procedures, or research security boundaries.
>
> <span style="color:red">**STAGE 4 — CONSEQUENCES & LIABILITY**</span>  
> Misuse can render your system unbootable, erase security audit trails, permanently weaken security posture, expose the machine to malware, or violate organizational security policies. You have been warned. Proceed only if you accept full responsibility for the outcome. The authors assume **no liability** for any damage, data loss, security compromise, or policy violation resulting from use or misuse.

---

## Table of Contents

- [Quick Links](#quick-links)
- [Project Overview](#project-overview)
- [Scripts Included](#scripts-included)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [God Mode Dangerous Features](#god-mode-dangerous-features)
- [OS-Guard Child Lockdown Features](#os-guard-child-lockdown-features)
- [Testing & Regression](#testing--regression)
- [Syntax Checking](#syntax-checking)
- [Changelog](#changelog)
- [Disclaimer](#disclaimer)

---

## Quick Links

| Section | Description |
|---------|-------------|
| [new2.ps1](#new2ps1--enterprise-dns--god-mode) | DNS Lockout + God Mode (dangerous admin control) |
| [security.ps1](#securityps1--os-guard-child-lockdown) | Parental control / child lockdown suite |
| [syntax_check.ps1](#syntax-checking) | Project-wide syntax checker script |
| [tests/](#testing--regression) | Regression test suite folder |
| [CHANGELOG](#changelog) | Version history and unreleased changes |

---

## Project Overview

This project is a dual-suite Windows PowerShell security toolkit consisting of two primary scripts:

1. **`new2.ps1`** — Enterprise DNS Hijack Protection + **God Mode** (dangerous admin override suite)
2. **`security.ps1`** — OS-Guard Child Lockdown Suite (parental control / kiosk mode)

Both scripts are designed for **testing, research, and full system control** scenarios where the built-in administrator needs to either lock down or unlock the operating system at the deepest levels.

---

## Scripts Included

### new2.ps1 — Enterprise DNS + God Mode

- **DNS Lockout**: Enforces static DNS on all network adapters (IPv4/IPv6) via registry ACLs
- **DoH Blocking**: Disables DNS-over-HTTPS in Edge, Chrome, and Firefox via GPO registry
- **God Mode**: A dangerous override suite that grants the Built-in Administrator (RID-500) unrestricted SYSTEM-level control by disabling Windows Defender, Firewall, UAC, Event Logging, Safe Mode, Recovery, ELAM, Credential Guard, SmartScreen, and more
- **Persistence**: Scheduled tasks, WMI event subscriptions, registry Run keys, and file-less fallback mechanisms
- **Auto-Elevation**: Automatically relaunches as Administrator if not already elevated
- **PowerShell 7 Preferred**: Automatically detects and relaunches in `pwsh` if available while maintaining PS5 compatibility
- **TUI Menu**: Interactive menu with category headers (DNS PROTECTION, SYSTEM, GOD MODE, SESSION)
- **Self-Destruct**: Can delete the original payload after persistence is installed

### security.ps1 — OS-Guard Child Lockdown

- **Child Account Lockdown**: Converts a standard user into a restricted child/kiosk account
- **Time-Based Restrictions**: Screen time limits, bedtime enforcement, weekday/weekend schedules
- **App Blocking**: Whitelist/blacklist application execution with process enforcement
- **Game Time Requests**: Child can request extra time; parent approves via admin dashboard
- **Network Restrictions**: SSID-based home network enforcement
- **Admin Dashboard**: Interactive TUI for managing all child policies
- **Tamper Detection**: Integrity checks and padlock verification
- **Password Policy**: Enforced password changes for child accounts

---

## Features

### DNS Protection Suite
- Zero-Trust registry padlock on all active network adapters
- IPv4 and IPv6 dual-stack enforcement
- Browser DoH (DNS-over-HTTPS) loophole closure via GPO
- Background service with auto-heal on boot/network change
- Global CLI command (`dnslock`) added to Windows PATH
- NTFS ACL hardening on installation directory

### God Mode Dangerous Features (Built-in Admin Only)
- **Windows Defender** — Disable real-time monitoring, behavior monitoring, tamper protection, and all core services
- **Windows Firewall** — Disable all profiles (Domain, Public, Private)
- **UAC** — Disable User Account Control and admin consent prompts entirely
- **Safe Mode / Recovery** — Block Safe Mode boot via BCD, disable Windows RE, disable Shift+Restart
- **Event Logging** — Stop EventLog service, clear all Windows event logs, disable WMI autologgers
- **ELAM** — Disable Early Launch Anti-Malware boot driver policy
- **Security Center Alerts** — Suppress "Windows Security is off" notifications
- **Credential Guard / VBS** — Disable virtualization-based security via registry
- **SmartScreen** — Disable application reputation filtering and phishing filters
- **Remote UAC** — Allow full admin tokens over network (disable token filtering)
- **Windows Script Host** — Disable `.js`/`.vbs` execution restrictions
- **Windows Update** — Block automatic updates to prevent Defender re-enabling
- **WMI Persistence** — File-less fallback using `__EventFilter` and `CommandLineEventConsumer`
- **Process Elevation** — Auto-elevate all new processes to SYSTEM in monitoring loop
- **Resurrection Killer** — Re-kill security services every 30 seconds if they respawn
- **Self-Whitelist** — Add payload paths to Defender exclusions before disabling it
- **Self-Destruct** — Delete original script after installation to achieve file-less persistence

### OS-Guard Child Lockdown Features
- Screen time scheduling with weekday/weekend splits
- Bedtime enforcement with lockout
- App whitelist / blacklist with real-time process enforcement
- Extra game time request system with admin approval
- Home network SSID enforcement
- Admin dashboard with integrity checks and tamper detection
- Password policy enforcement for child accounts
- Auto-elevation and persistent background monitoring

---

## Prerequisites

- Windows 10/11 (Pro or Enterprise recommended for full GPO features)
- PowerShell 5.1 or PowerShell 7 (`pwsh`)
- Built-in Administrator account (for God Mode features)
- Administrator privileges (for all installation and lockdown features)

---

## Usage

### DNS Lockout (new2.ps1)

```powershell
# Interactive TUI menu
.\new2.ps1

# CLI flags
.\new2.ps1 -Lock          # Deploy DNS lock immediately
.\new2.ps1 -Unlock        # Remove DNS lock
.\new2.ps1 -Install       # Install background service + auto-heal
.\new2.ps1 -Uninstall     # Remove service and unlock
.\new2.ps1 -SilentLock    # Background guardian mode (no UI)
```

### God Mode (new2.ps1)

```powershell
# Check God Mode status
.\new2.ps1 -GodModeStatus

# Enable God Mode (Built-in Admin ONLY — DANGEROUS)
.\new2.ps1 -Launch

# Install God Mode service persistence
.\new2.ps1 -InstallGodMode

# Uninstall God Mode service
.\new2.ps1 -UninstallGodMode
```

### OS-Guard (security.ps1)

```powershell
# Interactive admin dashboard
.\security.ps1

# Lock child account
.\security.ps1 -Lockdown -ChildUser "ChildName"

# Unlock child account
.\security.ps1 -Unlock -ChildUser "ChildName"
```

---

## Testing & Regression

All scripts are validated by the project's syntax checker (`syntax_check.ps1`) and regression test suite (`tests/Test-Suite.ps1`).

Run the syntax checker:
```powershell
.\syntax_check.ps1
```

Run the test suite:
```powershell
.\tests\Test-Suite.ps1
```

Tests cover:
- PowerShell syntax validation
- Auto-elevation loop detection
- Registry key creation verification
- Scheduled task registration/unregistration
- File integrity and hash checks

---

## Syntax Checking

The project includes a custom `syntax_check.ps1` script that scans all PowerShell files for:

- Alias usage (e.g., `dir`, `echo`, `write`)
- Trailing whitespace
- Redirection operator traps (`>>>`, `<<<`)
- Reserved operator misuse (`&`, `!`)
- Unescaped brackets in strings
- Quote mismatches
- Backtick end-of-line continuation issues
- Variable expansion in single-quoted strings
- Brace/parenthesis mismatches
- Duplicate script-scoped variable declarations
- Elevation loop detection (missing `UseShellExecute = $true`)
- UTF-8 BOM encoding issues
- Strict-mode null guard violations

---

## Changelog

### Unreleased

- **2026-07-10 18:29 UTC** — Added five new registry power functions to God Mode: `Disable-UACPrompts`, `Disable-SmartScreenRegistry`, `Disable-RemoteUAC`, `Disable-CredentialGuard`, `Disable-WindowsScriptHost`
- **2026-07-10 18:29 UTC** — Integrated all new registry functions into `Enable-DangerousMode` and `Disable-DangerousMode` flows
- **2026-07-10 18:29 UTC** — Updated `Show-GodModeStatus` TUI to display UAC Prompts, SmartScreen, Remote UAC, Credential Guard/VBS, and Windows Script Host states
- **2026-07-10 18:16 UTC** — Added PowerShell 7 preferred launcher with PS5 fallback compatibility
- **2026-07-10 18:16 UTC** — Auto-elevation now uses `(Get-Process -Id $PID).Path` instead of hardcoded `powershell.exe` to stay in the same host
- **2026-07-10 18:14 UTC** — Added automatic `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` at script start
- **2026-07-10 18:00 UTC** — Added God Mode dangerous enhancements: `Disable-RecoveryAndSafeMode`, `Disable-SecurityAlerts`, `Disable-ELAM`, `Disable-SecurityAuditing`, `Register-GodModeWMI`, `Invoke-SelfDestruct`
- **2026-07-10 18:00 UTC** — Added TUI category headers: DNS PROTECTION, SYSTEM, GOD MODE (DANGEROUS), SESSION
- **2026-07-10 18:00 UTC** — Added `InstallGodMode` and `UninstallGodMode` CLI flags with `Install-GodModePersistence` / `Uninstall-GodModePersistence` functions
- **2026-07-10 18:00 UTC** — Added global CLI at `C:\Windows\godmode.cmd`, NTFS hardening, PATH integration, scheduled tasks, guardians, integrity hash

### Earlier Releases

- Enterprise DNS Hijack Protection (IPv4 + IPv6 + DoH) with Zero-Trust registry padlock
- Background service with auto-heal on boot and network change
- Global `dnslock` CLI command in Windows PATH
- NTFS ACL hardening on installation directory
- God Mode base integration with Windows Defender disable, Firewall disable, UAC disable, and process elevation loop
- OS-Guard Child Lockdown Suite with screen time, app blocking, and admin dashboard
- Auto-elevation framework with SYSTEM-level task registration
- WMI file-less persistence fallback
- Self-destruct capability for file-less operation
- Syntax checker and regression test suite

---

## Disclaimer

This software is provided for **educational, research, and authorized testing purposes only**. The authors assume **no liability** for any damage, data loss, security compromise, or policy violation resulting from the use or misuse of these scripts. By using this software, you acknowledge that you understand the risks and accept full responsibility for your actions. These scripts are designed to give the **Built-in Administrator full SYSTEM control** by design — this is intentional for testing and research, not for production systems. Always use in a controlled, isolated environment. Never deploy on systems you do not own or have explicit written authorization to modify.
