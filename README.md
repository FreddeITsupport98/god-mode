# God-Mode-Windows

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
- [Jump List](#jump-list)
- [Project Overview](#project-overview)
- [Scripts Included](#scripts-included)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [God Mode Dangerous Features](#god-mode-dangerous-features)
- [OS-Guard Child Lockdown Features](#os-guard-child-lockdown-features)
- [Testing & Regression](#testing--regression)
- [Syntax Checking](#syntax-checking)
- [File Inventory](#file-inventory)
- [Architecture & How It Works](#architecture--how-it-works)
- [Parameter Reference](#parameter-reference)
- [Troubleshooting](#troubleshooting)
- [Legacy & Planned Components](#legacy--planned-components)
- [Changelog](#changelog)
- [Disclaimer](#disclaimer)

---

## Quick Links

| Section | Description |
|---------|-------------|
| [God-Mode-Windows.ps1](#god-mode-windowsps1--enterprise-dns--god-mode) | DNS Lockout + God Mode (dangerous admin control) |
| [syntax_check.ps1](#syntax-checking) | Project-wide syntax checker & auto-chmod script |
| [tests/](#testing--regression) | Regression test suite folder |
| [CHANGELOG](#changelog) | Version history and unreleased changes |

---

## Jump List

- [God-Mode-Windows.ps1 — Enterprise DNS + God Mode](#scripts-included)
- [DNS Lockout Usage](#dns-lockout-god-mode-windowsps1)
- [God Mode Usage](#god-mode-god-mode-windowsps1)
- [Syntax Checking](#syntax-checking)
- [Regression Tests](#testing--regression)
- [Changelog](#changelog)
- [Architecture & How It Works](#architecture--how-it-works)
- [Parameter Reference](#parameter-reference)
- [Troubleshooting](#troubleshooting)

---

## Project Overview

This project is a dual-suite Windows PowerShell security toolkit consisting of two primary scripts:

1. **`God-Mode-Windows.ps1`** — Enterprise DNS Hijack Protection + **God Mode** (dangerous admin override suite)
2. **`security.ps1`** — OS-Guard Child Lockdown Suite (parental control / kiosk mode — legacy / planned module)

Both scripts are designed for **testing, research, and full system control** scenarios where the built-in administrator needs to either lock down or unlock the operating system at the deepest levels.

---

## Scripts Included

### God-Mode-Windows.ps1 — Enterprise DNS + God Mode

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
|- **Process Elevation** — Auto-elevate all new processes to SYSTEM in monitoring loop
||- **Hybrid Token-Stealing Elevation** — `Invoke-HybridElevation` first attempts to duplicate a SYSTEM token from a running process (`lsass`, `services`, `winlogon`, `svchost`, etc.) and spawn the target process with it; if token stealing fails (e.g., desktop session mismatch), it falls back to the scheduled-task method. This dual-path approach adapts automatically to different Windows builds and makes post-reboot elevation more reliable.
||- **Session-1 Token Prioritization** — `Find-SystemProcessCandidate` now prioritizes interactive desktop SYSTEM processes in Session 1 (`winlogon.exe`, `dwm.exe`, `fontdrvhost.exe`) because their tokens carry the correct WindowStation (`WinSta0\Default`) and can spawn visible GUI apps. Session 0 or fallback processes are only used if Session 1 is unavailable.
||- **Protected-Process Access (`PROCESS_QUERY_LIMITED_INFORMATION`)** — The C# `TokenOps` class uses `0x1000` instead of `0x400` in `OpenProcess`, allowing it to query PPL-protected SYSTEM processes (e.g., `lsass.exe`) without access-denied errors.
||- **Pre-Flight Token Test (`TestOpenProcess`)** — A new C# method verifies the full open-token-duplicate chain on a candidate PID before returning it, so `Find-SystemProcessCandidate` only returns a process we can actually use.
||- **Monitoring-Loop Token-Only Elevation (`Monitor-ElevateProcess`)** — The post-reboot monitor loop uses a dedicated, lightweight elevation helper that only performs token-stealing (no `Stop-Process`, no scheduled-task fallback). This keeps existing single-instance apps (Chrome, Explorer, Edge) alive and avoids the Session 0 / WindowStation mismatch that made GUI apps invisible.
||- **Advanced Elevation Diagnostics** — `Get-Win32ErrorRootCause`, `Get-ElevationPrivilegeStatus`, `Get-ProcessElevationContext`, and `Export-ElevationDiagnostics` provide deep root-cause analysis for every token-stealing failure. Auto-dumps privilege tables, per-process accessibility scans (OpenProcess / OpenProcessToken / DuplicateTokenEx), and context-aware recommendations (e.g., "PPL active — pick winlogon.exe in Session 1").
||- **Resurrection Killer** — Re-kill security services every 30 seconds if they respawn
- **Self-Whitelist** — Add payload paths to Defender exclusions before disabling it
- **Self-Destruct** — Delete original script after installation to achieve file-less persistence
- **Registry ACL Hardening** — `Harden-RegistryKey` / `Restore-RegistryKey` helpers apply multi-layer `Deny` ACLs (`SetValue`, `CreateSubkey`, `Delete`, `WriteKey`) to `Administrators`, `Everyone`, and `Authenticated Users` on all DNS, DoH, and God Mode registry keys; removes inheritance and strips old deny rules before re-applying
- **Stealth Mode** — `Invoke-StealthMode` masks the PowerShell window title, suppresses script-block logging / transcription / module logging via registry, and hides from casual Task Manager inspection
- **Deep Persistence** — `Register-DeepPersistence` adds backup registry Run keys in `HKLM\WOW6432Node` and `HKCU`, additional scheduled tasks with randomized Microsoft-like names, and a boot-level WMI `Win32_ProcessStartupTrace` event filter that fires within 60 seconds of any boot
|- **Broader Security Disable** — `Disable-AppLocker`, `Disable-WindowsSandbox`, `Disable-LSAProtection`, `Disable-ASR`, `Disable-ControlledFolderAccess`, `Disable-ExploitGuard`, `Disable-BitLocker` expand the attack surface coverage beyond Defender/Firewall/UAC
|- **SYSTEM Watchdog Relauncher** — `Register-SystemWatchdog` creates a 30-second heartbeat task (`Windows-Defender-Engine-Update`) running as SYSTEM. If the stealth monitoring task is killed or crashes, the watchdog immediately relaunches it as SYSTEM. The watchdog itself has aggressive restart settings (99 restarts, 1-minute intervals) so it survives being killed too. If the stealth task is missing entirely, the watchdog dynamically recreates it from a hardened script in the install directory.
||- **Task Manager Unblocked + SYSTEM Elevation** — `Block-TaskManager` no longer blocks Task Manager. Instead, it removes any IFEO Debugger redirect and the `DisableTaskMgr` policy so `taskmgr.exe` can launch normally. The `Start-Monitoring` event watcher then detects `taskmgr.exe` on creation and elevates it to SYSTEM in-place via `ReplaceProcessTokenForPid` (Phase 0 of `Monitor-ElevateProcess`), so Task Manager opens instantly and runs as SYSTEM. This eliminates the previous problem where blocking Task Manager prevented it from opening at all.
|- **Stealth Task Restart-on-Kill** — `Register-StealthTask` now configures the monitoring task with `New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1)`, so Task Scheduler automatically relaunches the monitor as SYSTEM within 1 minute if it is killed or crashes, independent of the watchdog heartbeat.
- **Anti-Forensics** — `Clear-ShadowCopies`, `Clear-USNJournal`, `Clear-CrashDumps`, `Clear-PowerShellHistory`, `Clear-RecentTraces` remove Volume Shadow Copies, USN journals, crash dumps, PowerShell history, Recent files, Jump Lists, and thumbnail caches to hinder incident-response analysis.
||- **In-Place Token Replacement** — `ReplaceProcessTokenForPid` in the `TokenOps` C# class uses `NtSetInformationProcess(ProcessAccessToken, 0x09)` to replace a running process's token with a stolen SYSTEM token without killing it. This is Phase 0 inside `Monitor-ElevateProcess`: when a new process is detected via the event watcher, the monitor tries to elevate the existing PID in-place first, eliminating flicker and restart delay.
||- **C IFEO Proxy Elevation** — `driver/gmproxy.c` compiles to a tiny Win32 executable that intercepts launches via IFEO `Debugger` registry keys. It steals a SYSTEM token and calls `CreateProcessWithTokenW`/`CreateProcessAsUserW` to launch the intercepted app as SYSTEM on `WinSta0\Default` without kill-relaunch. Hooked apps: `chrome.exe`, `firefox.exe`, `msedge.exe`, `notepad.exe`, `cmd.exe`, `powershell.exe`.
||- **C Shell Hook DLL** — `driver/gmhook.c` is a DLL that injects into `explorer.exe` and hooks `CreateProcessW` with a 5-byte inline JMP. New processes are created `CREATE_SUSPENDED`, their token is replaced in-place via `NtSetInformationProcess`, then resumed as SYSTEM. Critical OS processes are filtered out so only user-facing apps are elevated.
|- **PowerShell Hook Installer** — `Install-ProcessHook` compiles the C components with `driver/build.ps1` (auto-detects MSVC or MinGW), copies binaries into the hardened install directory, registers IFEO `Debugger` keys, and injects `gmhook.dll` into `explorer.exe` via an inline C# `CreateRemoteThread` + `LoadLibraryW` injector. `Uninstall-ProcessHook` reverses all changes. Wired into `Enable-GodMode` / `Disable-GodMode` and `Show-GodModeStatus`. **Auto-build**: If the binaries are missing when option 7 is pressed, `Install-ProcessHook` automatically runs `driver/build.ps1`, captures all output to `GodMode_DriverBuild.log`, and logs errors to both the main and debug logs before retrying. **MSYS2 discovery**: If `gcc` is not in PATH but MSYS2 is installed in `C:\msys64\ucrt64\bin`, `C:\msys64\mingw64\bin`, or `C:\msys64\mingw32\bin`, the script temporarily adds that directory to PATH for the build so no manual PATH editing is required.
|- **Log Dump** — `Export-GodModeLogs` collects all accumulated logs and dumps them to the Desktop with a timestamped filename (`GodMode_Dump_YYYY-MM-DD_HH-mm-ss.log`); accessible via CLI `-DumpLogs` or interactive menu option [11]
|- **Rotating Raw Debug Dump** — `Export-RawDebugDump` captures full system state (environment variables, loaded modules, running processes, `$Error` stack, and all log files) into timestamped dumps under `%TEMP%\GodMode_RawDumps`. Automatically rotates to keep only the 5 most recent dumps. Triggered automatically on installation start/end and on any uncaught terminating error via a global `trap` handler.
|- **Event-Driven Process Elevation** — `Register-ProcessCreationWatcher` uses a WMI `__InstanceCreationEvent` watcher to detect new processes in near real time, pushing them into a synchronized queue that the monitor loop drains immediately. This eliminates the per-loop `Get-CimInstance` polling overhead and catches new apps faster than the 5-second window. Falls back to CIM polling automatically if WMI is unavailable.
|- **SYSTEM PID Cache** — `Find-SystemProcessCandidate` caches the first successfully validated SYSTEM PID for 60 seconds, avoiding repeated `GetOwner` + `OpenProcess` scans on every elevation call. Cache is invalidated on timeout or process exit.
|- **Conditional Polling** — When the event watcher is active, `Start-Monitoring` skips the `Get-CimInstance` new-process query entirely and trusts the queue, removing the last per-loop CIM overhead.
|- **Administrator-Safe Monitor** — If `Start-Monitoring` is accidentally started as Administrator (not SYSTEM), it logs a one-line warning and skips all elevation blocks (periodic and new-process) while keeping the resurrection-killer and stealth-mode active. This prevents the diagnostics-dump flood that occurred when `Enable-ElevationPrivileges` failed to enable `SeAssignPrimaryTokenPrivilege` in a filtered Administrator token.
||
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
- **Compiler (for C hook auto-build)** — One of:
  - Visual Studio / Build Tools (`cl.exe` in PATH)
  - MSYS2 MinGW-w64 (`gcc.exe` in PATH, or installed to `C:\msys64\ucrt64\bin`, `C:\msys64\mingw64\bin`, or `C:\msys64\mingw32\bin` — the script auto-detects these paths)
    - Download: https://github.com/msys2/msys2-installer/releases/latest
    - After install, open **MSYS2 UCRT64** terminal and run: `pacman -S mingw-w64-ucrt-x86_64-gcc`
  - Linux cross-compiler `x86_64-w64-mingw32-gcc` (for building on Linux)

---

## Usage

### Quick Tutorial — Install vs Enable

God Mode has two separate steps: **Install** (persistence) and **Enable** (activation).

| Step | Menu Option | What it does |
|------|-------------|--------------|
| **Install** | `[6]` | Copies the script to `C:\ProgramData\GodMode\`, creates the `godmode` CLI command, and registers scheduled tasks that auto-enable on every boot and logon. Does **not** turn God Mode on right now. |
| **Enable** | `[7]` | Immediately disables Windows Defender, Firewall, UAC, Safe Mode, logging, etc. and sets the active flag. This is the dangerous part. |
| **Status** | `[9]` | Shows whether God Mode is currently ACTIVE or INACTIVE. |
| **Disable** | `[8]` | Re-enables all security features and clears the active flag. The scheduled tasks from step 1 remain and will re-enable it on next reboot. |
| **Uninstall** | `[6]` (when already installed) | Removes the installed files, CLI command, and all scheduled tasks. |

**Correct workflow:**
1. Run `God-Mode-Windows.ps1` and press `[6]` to install.
2. Press `[7]` to enable God Mode right now.
3. Press `[9]` to verify it shows `ACTIVE`.
4. Press `[8]` to disable it temporarily (tasks will re-enable on next reboot).
5. Press `[6]` again to fully uninstall everything.

---

### DNS Lockout (God-Mode-Windows.ps1)

```powershell
# Interactive TUI menu
.\God-Mode-Windows.ps1

# CLI flags
.\God-Mode-Windows.ps1 -Lock          # Deploy DNS lock immediately
.\God-Mode-Windows.ps1 -Unlock        # Remove DNS lock
.\God-Mode-Windows.ps1 -Install       # Install background service + auto-heal
.\God-Mode-Windows.ps1 -Uninstall     # Remove service and unlock
.\God-Mode-Windows.ps1 -SilentLock    # Background guardian mode (no UI)
```

### God Mode (God-Mode-Windows.ps1)

```powershell
# Check God Mode status
.\God-Mode-Windows.ps1 -GodModeStatus

# Enable God Mode (Built-in Admin ONLY — DANGEROUS)
.\God-Mode-Windows.ps1 -Launch

# Install God Mode service persistence
.\God-Mode-Windows.ps1 -InstallGodMode

# Uninstall God Mode service
.\God-Mode-Windows.ps1 -UninstallGodMode
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
|- Strict-mode null guard violations
|- C/C++ syntax validation (`*.c`, `*.h`) — brace/bracket/parenthesis balance, unterminated strings/char literals, block comments, and preprocessor directive (`#if`/`#endif`) matching

---

## Changelog

### Unreleased

- **2026-07-10 20:08 UTC** — Added rotating raw debug/error dumper (`Export-RawDebugDump`) with automatic log rotation (keeps 5 most recent dumps) and global `trap` auto-capture; also hardened `Uninstall-GodModePersistence` and `Uninstall-Persistence` to explicitly delete payloads via `cmd /c del /f /q` before directory removal for reliable cleanup against hardened ACLs
- **2026-07-10 19:09 UTC** — Added `Harden-RegistryKey` and `Restore-RegistryKey` helpers; integrated multi-layer registry ACL hardening into DNS Lockout, DoH, and God Mode enable/disable flows
- **2026-07-10 19:01 UTC** — Updated README quick links, renamed all `new2.ps1` references to `God-Mode-Windows.ps1`, added Jump List, File Inventory, Architecture, Parameter Reference, Troubleshooting, and Legacy sections for improved documentation depth
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

## File Inventory

| File | Purpose |
|------|---------|
| `God-Mode-Windows.ps1` | Main dual-suite script (DNS Lockout + God Mode) |
| `syntax_check.ps1` | Enhanced multi-layer syntax checker, regression validator, and auto-chmod utility |
| `tests/Test-Suite.ps1` | Regression test suite for syntax, installer logic, and menu integrity |
| `changelog.md` | External project changelog |
| `driver/build.ps1` | Auto-detecting C component build script (MSVC / MinGW) |
| `driver/gmproxy.c` | IFEO proxy source — launches apps as SYSTEM via token theft |
| `driver/gmhook.c` | Shell hook DLL source — inline `CreateProcessW` hook with token replacement |
| `God mode.ps1.old` | Legacy archived payload (retained for reference) |

---

## Architecture & How It Works

### DNS Lockout Architecture
1. **Registry ACL Denial**: The script enumerates all active network adapters and applies `Deny SetValue` ACLs to both IPv4 (`Tcpip`) and IPv6 (`Tcpip6`) registry parameter subkeys for `S-1-5-32-544` (Administrators) and `S-1-5-18` (SYSTEM). This prevents any interactive user or service from modifying DNS settings.
2. **GPO UI Restrictions**: Sets `NC_LanProperties`, `NC_LanChangeProperties`, and `NC_AllowAdvancedTCPIPConfig` to `0` under `HKCU:\Software\Policies\Microsoft\Windows\Network Connections`, graying out the adapter properties UI.
3. **Browser DoH Closure**: Disables DNS-over-HTTPS via registry policies for Edge (`HKLM\SOFTWARE\Policies\Microsoft\Edge`), Chrome (`HKLM\SOFTWARE\Policies\Google\Chrome`), and Firefox (`HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`).
4. **Persistent Guardian**: Installs three scheduled tasks (startup, logon, network-change event ID 10000) plus two heartbeat guardians (5-minute and 10-minute intervals) and a WMI event subscription (`__EventFilter` + `CommandLineEventConsumer`) that re-applies locks if the Task Scheduler service is modified.
5. **NTFS Self-Defense**: Sets `C:\ProgramData\DNSGuard` owner to SYSTEM, strips inherited permissions, grants Admins `ReadAndExecute` only, and denies `Delete`, `ChangePermissions`, and `TakeOwnership` to prevent tampering.
6. **Integrity Verification**: Computes a SHA-256 hash of the installed payload and stores it both in a registry key (`PushConfigBackoffInterval` under `WpnPlatform\Settings`) and in a file (`integrity.sha256`) to detect tampering.

### God Mode Architecture
1. **Authorization Gate**: All God Mode commands check `Test-BuiltInAdmin` (RID-500) and exit with `ACCESS DENIED` if the caller is not the built-in Administrator.
2. **Exclusion First**: Before disabling Defender, the script adds `$GodModeInstallDir` and the current script path to Windows Defender exclusions to avoid self-flagging.
3. **Layered Disable**: Applies registry overrides, service-level disable, `MpPreference` disable, process termination, firewall disable, UAC disable, Safe Mode / Recovery BCD edits, ELAM disable, event log clearing, and SmartScreen / Credential Guard / Remote UAC / WSH registry locks.
4. **Resurrection Killer**: A persistent monitor loop (`Start-Monitoring`) checks every 30 seconds for security service respawns and re-kills them; it also auto-elevates any new process to SYSTEM within a 60-second cooldown.
5. **Hybrid Token-Stealing Elevation**: `Invoke-HybridElevation` centralizes all process elevation. It first attempts to steal a SYSTEM token from a known process (`lsass`, `services`, `winlogon`, `svchost`, etc.) via C# P/Invoke (`DuplicateTokenEx` + `CreateProcessWithTokenW`) and spawn the target app with that token. If the steal fails (common for desktop apps due to session/WindowStation mismatch), it immediately falls back to a temporary scheduled task running as `NT AUTHORITY\SYSTEM`. This dual-path design adapts to different Windows builds and makes post-reboot elevation robust.
5.1. **Monitoring-Loop Elevation (`Monitor-ElevateProcess`)**: The post-reboot monitor loop uses a dedicated token-only path (`Monitor-ElevateProcess`) that never kills existing processes and never uses the scheduled-task fallback. It only steals a Session 1 SYSTEM token (`winlogon.exe`, `dwm.exe`, `fontdrvhost.exe`) and spawns the new instance directly, so single-instance apps (Chrome, Explorer, Edge) stay alive and actually appear as SYSTEM on the interactive desktop. The periodic (60-second) and on-creation elevation blocks inside `Start-Monitoring` both call `Monitor-ElevateProcess` instead of the heavier `Invoke-HybridElevation` wrapper.
6. **Stealth Persistence**: Uses randomly named scheduled tasks (`MicrosoftEdgeUpdateTask_` prefix), registry Run/RunOnce keys, and WMI `__FilterToConsumerBinding` to maintain God Mode across reboots.
7. **Self-Destruct**: The `Invoke-SelfDestruct` function removes the original payload from disk after persistence is installed, achieving file-less operation.
8. **Registry ACL Hardening**: After all registry values are set, `Harden-RegistryKey` is called on every affected key. It disables inheritance, strips old deny rules, and applies comprehensive `Deny` ACLs (`SetValue`, `CreateSubkey`, `Delete`, `WriteKey`) to `Administrators`, `Everyone`, and `Authenticated Users`. This prevents tampering with DNS locks, DoH policies, and God Mode security overrides even by other elevated processes. When the script is disabled, `Restore-RegistryKey` removes the deny rules and re-enables inheritance before attempting to delete or modify values.
9. **Stealth Mode**: `Invoke-StealthMode` is called at the start of monitoring and after God Mode enable. It masks the window title to "Windows PowerShell (x86)", suppresses PowerShell script-block logging, transcription, and module logging via registry, making casual detection harder.
10. **Deep Persistence**: `Register-DeepPersistence` adds extra registry Run keys in `HKLM\WOW6432Node` and `HKCU`, additional scheduled tasks with randomized Microsoft-like names (`WindowsDefenderSigUpdates_`, `OneDriveStandaloneUpdater_`, `EdgeWebView2Updater_`), and a boot-level WMI `Win32_ProcessStartupTrace` event filter that fires within 60 seconds of any boot, making removal a multi-step process.
11. **Anti-Forensics**: `Clear-ShadowCopies`, `Clear-USNJournal`, `Clear-CrashDumps`, `Clear-PowerShellHistory`, and `Clear-RecentTraces` remove Volume Shadow Copies, USN journals, crash dumps, PowerShell history, Recent files, Jump Lists, and thumbnail caches to hinder incident-response analysis.
12. **SYSTEM Watchdog Relauncher**: A dedicated watchdog task (`Windows-Defender-Engine-Update`) runs every 30 seconds as SYSTEM, checking if the stealth monitoring task is alive. If the monitor is killed or crashes, the watchdog immediately relaunches it as SYSTEM. The watchdog itself has aggressive restart settings (99 restarts, 1-minute intervals) so it survives being killed too. If the stealth task is missing entirely, the watchdog dynamically recreates it from a hardened script in the install directory.
13. **Task Manager Unblocked + In-Place SYSTEM Elevation**: `Block-TaskManager` now removes the IFEO Debugger redirect and `DisableTaskMgr` policy so Task Manager can launch normally. The `Start-Monitoring` event watcher detects `taskmgr.exe` on creation and elevates it to SYSTEM in-place via `ReplaceProcessTokenForPid` (Phase 0 of `Monitor-ElevateProcess`). This replaces the old blocking design that prevented Task Manager from opening entirely, solving the "Task Manager won't open" problem while still running it as SYSTEM.
14. **Stealth Task Restart-on-Kill**: The monitoring task itself is configured with `New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1)`, so Task Scheduler automatically relaunches the monitor as SYSTEM within 1 minute if it is killed or crashes, independent of the watchdog heartbeat.
15. **In-Place Token Replacement (`NtSetInformationProcess`)**: When the event watcher detects a new process, `Monitor-ElevateProcess` first attempts `ReplaceProcessTokenForPid` (Phase 0) to swap the running process's token with a stolen SYSTEM token via `NtSetInformationProcess(ProcessAccessToken, 0x09)`. If the target is not protected (e.g., not PPL), the process becomes SYSTEM instantly without being killed or restarted, eliminating visible flicker. If Phase 0 fails, the function falls back to Phase 1 (`CreateProcessAsSystem` kill-relaunch) and Phase 2 (scheduled-task fallback).
16. **C IFEO Proxy (`gmproxy.exe`)**: A compiled Win32 executable registered under IFEO `Debugger` keys for common user apps (`chrome.exe`, `firefox.exe`, `msedge.exe`, `notepad.exe`, `cmd.exe`, `powershell.exe`). When the user launches one of these apps, `gmproxy.exe` intercepts the call, steals a SYSTEM token, and relaunches the original command line as SYSTEM on `WinSta0\Default`. This avoids the PowerShell kill-relaunch cycle entirely and works even before the monitor loop starts.
17. **C Shell Hook DLL (`gmhook.dll`)**: Injected into `explorer.exe` via `CreateRemoteThread` + `LoadLibraryW`. The DLL hooks `CreateProcessW` with a 5-byte inline JMP. Every user app launch is created `CREATE_SUSPENDED`, its token is replaced in-place via `NtSetInformationProcess`, and the process is resumed as SYSTEM. Critical OS processes are hardcoded in a filter list so the hook never touches system services.
18. **PowerShell Hook Installer (`Install-ProcessHook` / `Uninstall-ProcessHook`)**: `Install-ProcessHook` checks for `gmproxy.exe` and `gmhook.dll`; if either is missing, it auto-runs `driver/build.ps1` (auto-detects MSVC or MinGW), captures full build output to `%TEMP%\GodMode_DriverBuild.log`, and retries before proceeding. Once binaries exist, it copies them to the hardened install directory, registers IFEO `Debugger` keys, and injects the DLL into `explorer.exe`. `Uninstall-ProcessHook` removes the keys, deletes the binaries, and logs completion. Both are called automatically by `Enable-GodMode` and `Disable-GodMode`.

---

## Parameter Reference

| Parameter | Scope | Description |
|-----------|-------|-------------|
| `-Install` | DNS Lockout | Install background service, auto-heal, `dnslock` CLI, and NTFS hardening |
| `-Uninstall` | DNS Lockout | Remove service, unlock registry, clean PATH, and delete install directory |
| `-Lock` | DNS Lockout | Immediately apply DNS registry ACL locks and GPO restrictions |
| `-Unlock` | DNS Lockout | Remove all DNS locks and GPO restrictions |
| `-SilentLock` | DNS Lockout | Background guardian mode (no UI); used by scheduled tasks |
| `-ToggleOn` | God Mode | Enable God Mode (Built-in Admin only) |
| `-ToggleOff` | God Mode | Disable God Mode (Built-in Admin only) |
| `-GodModeStatus` | God Mode | Display detailed TUI status of all security subsystems |
| `-Launch` | God Mode | Launch the persistent monitor / resurrection killer (Built-in Admin only) |
| `-InstallGodMode` | God Mode | Install God Mode persistence, `godmode` CLI, and NTFS hardening |
| `-UninstallGodMode` | God Mode | Remove God Mode tasks, registry keys, WMI, and install directory |
| `-Verbose` | General | Enable verbose logging output |
| `-DumpLogs` | General | Collect and export all logs to Desktop with timestamped filename (`GodMode_Dump_YYYY-MM-DD_HH-mm-ss.log`) |
| `-ExportElevationDiagnostics` | General | Export a full elevation diagnostics dump (privilege table, per-process SYSTEM scan, root-cause analysis) to the Desktop |

---

## Troubleshooting

### DNS Lockout Issues
- **Cannot uninstall because "must run as SYSTEM"**: The uninstaller requires SYSTEM because the install directory is owned by SYSTEM. Use `psexec -s powershell.exe -File "C:\ProgramData\DNSGuard\DNS_Lockdown.ps1" -Uninstall` or run the original `God-Mode-Windows.ps1 -Uninstall` from an elevated admin shell (it will spawn a SYSTEM helper task automatically via `Invoke-AsSystem`).
- **GPO restrictions still active after uninstall**: The uninstaller removes `NC_LanProperties`, `NC_LanChangeProperties`, and `NC_AllowAdvancedTCPIPConfig` from `HKCU:\Software\Policies\Microsoft\Windows\Network Connections`. If these remain, run `gpupdate /force` or manually delete the keys.
- **Integrity mismatch warning**: If the SHA-256 hash of the installed script does not match the stored baseline, the script blocks lock/unlock operations. Reinstall from a clean source.

### God Mode Issues
|- **Access Denied**: God Mode commands are restricted to the Built-in Administrator (RID-500). Ensure you are logged in as the actual built-in admin, not a domain or local admin account.
|- **Defender keeps re-enabling**: Some Windows builds require a reboot for tamper-protection registry changes to take effect. If Defender respawns, run `God-Mode-Windows.ps1 -Launch` to start the resurrection killer, then reboot.
|- **Safe Mode blocked and cannot restore**: If you locked yourself out of Safe Mode, boot from Windows installation media and use `bcdedit /deletevalue {default} safeboot` from the repair command prompt.
|- **WMI persistence still active after uninstall**: WMI objects sometimes require a manual cleanup. Run `Get-WmiObject -Class __EventFilter -Namespace "root\subscription" | Where-Object Name -eq 'Win32ProviderHealthCheck' | Remove-WmiObject` as admin.
||- **Token steal fails with Access Denied (Win32 error 5)**: The script now uses `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000) to open protected SYSTEM processes. If you still see error 5 on `lsass.exe`, it means PPL (Protected Process Light) is active. The script will automatically fall back to other SYSTEM processes (`winlogon.exe`, `dwm.exe`, `fontdrvhost.exe`) in Session 1, which are usually accessible. Check `C:\Users\<User>\AppData\Local\Temp\GodMode_ElevationDiagnostics_*.log` for a full per-process breakdown.
||- **Chrome / Edge still shows Administrator instead of SYSTEM**: Make sure the monitor loop is running (`Start-Monitoring` or the scheduled task). If the loop was killed (flapping), idempotency checks now prevent re-registration from killing it. If the loop is alive but apps still show Administrator, the token steal was likely using a Session 0 process (e.g., `services.exe`). The monitor now prioritizes Session 1 processes, so a fresh reboot should fix this. Run `Export-ElevationDiagnostics` from the script or look for the auto-generated dump on the Desktop to see exactly which SYSTEM process was chosen and why.
||- **How to read the debug logs**: Every token-stealing attempt now writes a structured `ROOT_CAUSE:` line to `DNS_Lockdown_Enterprise.debug.log` in `%TEMP%`. The log format is `[timestamp] [DEBUG] [ACTION] [Function] [Line] Message | Exception: ... | ROOT_CAUSE: ...`. Look for `REJECTED:` and `SUCCESS:` entries from `Find-SystemProcessCandidate` to see why each process was skipped or picked.
||- **Privilege missing even as Administrator**: Windows removes `SeDebugPrivilege` from the filtered token when UAC is enabled. The new `Get-ElevationPrivilegeStatus` function logs which privileges are actually present. If it reports `SeDebugPrivilege: False`, run the script from a fully elevated shell ("Run as Administrator") or use a SYSTEM shell. The script will auto-dump diagnostics when it detects missing required privileges.

### General Issues
- **PowerShell 7 not detected**: The script checks `$PSVersionTable.PSVersion.Major` and relaunches in `pwsh` if available. If `pwsh` is not in PATH, it stays in Windows PowerShell 5.1.
- **Execution Policy blocked**: The script auto-sets `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` at startup. If GPO overrides this, sign the script or use `powershell.exe -ExecutionPolicy Bypass -File .\God-Mode-Windows.ps1`.

---

## Legacy & Planned Components

- **`new2.ps1`**: This was the original filename for the Enterprise DNS + God Mode script during early development. It has been renamed to `God-Mode-Windows.ps1` to reflect its purpose accurately. All legacy documentation references have been updated.
- **`security.ps1` / OS-Guard Child Lockdown**: The OS-Guard suite (parental control, screen time, app blocking, kiosk mode) is described as a planned or legacy module. The file is not present in the current repository but may be merged in a future release.
- **`God mode.ps1.old`**: Archived legacy payload retained for reference and historical comparison.

---

## Disclaimer

This software is provided for **educational, research, and authorized testing purposes only**. The authors assume **no liability** for any damage, data loss, security compromise, or policy violation resulting from the use or misuse of these scripts. By using this software, you acknowledge that you understand the risks and accept full responsibility for your actions. These scripts are designed to give the **Built-in Administrator full SYSTEM control** by design — this is intentional for testing and research, not for production systems. Always use in a controlled, isolated environment. Never deploy on systems you do not own or have explicit written authorization to modify.
