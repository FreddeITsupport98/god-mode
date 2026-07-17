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
||- **IFEO Elevation for Normal Programs (`Install-IfeoElevation`)** — Re-added the launcher-agnostic "born as SYSTEM" layer. `Enable-GodMode` now installs an IFEO `Debugger` redirect to `gmproxy.exe` for a curated list of ~60 normal user programs (browsers, editors, Office, comms, dev tools, media, PDF, archivers, net tools, `regedit`, `msconfig`, games) so ANY launch of those apps — from explorer, Start menu, cmd, Task Scheduler, or any launcher — is transparently relaunched as SYSTEM via a stolen token (`CreateProcessWithTokenW`), with no kill/relaunch delay. Each IFEO key is hardened (`Harden-RegistryKey`) so it cannot be removed by AV/user; `Disable-GodMode` calls `Uninstall-IfeoElevation` (`Restore-RegistryKey` + delete). Shells/terminals (`cmd`, `powershell`, `pwsh`, `wt`, `conhost`, `OpenConsole`, `WindowsTerminal`, `wsl`, `wslhost`) plus `explorer` (SystemDesktop) and `taskmgr` (Block-TaskManager watcher) are deliberately EXCLUDED — God Mode's own persistence invokes `powershell.exe`/`cmd.exe`, so IFEO-redirecting those would break the monitor loop (mirrors `IsShellLauncherProcess` in `gmhook.c`). IFEO keys persist across reboots and `gmproxy.exe` is re-copied each boot by `Install-ProcessHook`.
||- **C Shell Hook DLL** — `driver/gmhook.c` is a DLL that injects into `explorer.exe` and hooks `CreateProcessW` with a 5-byte inline JMP. New processes are created `CREATE_SUSPENDED`, their token is replaced in-place via `NtSetInformationProcess`, then resumed as SYSTEM. Critical OS processes are filtered out so only user-facing apps are elevated.
|- **PowerShell Hook Installer** — `Install-ProcessHook` compiles the C components with `driver/build.ps1` (auto-detects MSVC or MinGW), copies binaries into the hardened install directory, registers IFEO `Debugger` keys, and injects `gmhook.dll` into `explorer.exe` via an inline C# `CreateRemoteThread` + `LoadLibraryW` injector. `Uninstall-ProcessHook` reverses all changes. Wired into `Enable-GodMode` / `Disable-GodMode` and `Show-GodModeStatus`. **Auto-build**: If the binaries are missing when option 7 is pressed, `Install-ProcessHook` automatically runs `driver/build.ps1`, captures all output to `GodMode_DriverBuild.log`, and logs errors to both the main and debug logs before retrying. **MSYS2 discovery**: If `gcc` is not in PATH but MSYS2 is installed in `C:\msys64\ucrt64\bin`, `C:\msys64\mingw64\bin`, or `C:\msys64\mingw32\bin`, the script temporarily adds that directory to PATH for the build so no manual PATH editing is required.
|- **Shell/Launcher Host Exclusion (0xC0000005 fix)** — `gmhook.dll` and `Install-ProcessHook` NEVER inject into or IAT-hook shell/launcher hosts (`pwsh.exe`, `powershell.exe`, `cmd.exe`, `wt.exe`, `conhost.exe`, `OpenConsole.exe`, `WindowsTerminal.exe`). PowerShell and cmd launch native commands via `CreateProcessW` as their core job; in-process IAT hooking of those calls destabilizes the host and faults with `0xC0000005` (STATUS_ACCESS_VIOLATION) inside `Kernel32.CreateProcess` — a native access violation PowerShell `try/catch` cannot recover from (it kills `pwsh.exe`). `gmhook.c` adds `IsShellLauncherProcess()` gated at the `HookCreateProcessW` pass-through, `GetMsgProc`, and `DllMain` auto-install sites; `Install-ProcessHook` adds the same hosts to its `$CriticalProcs` injection skip-list. These hosts are still elevated to SYSTEM via `Invoke-HybridElevation` / `CreateProcessAsSystem`; they are simply not IAT-hooked in-process. Also fixed a `HookCreateProcessW` recursion-guard leak where one re-entry permanently left `inHook==1` and silently disabled elevation on every subsequent `CreateProcessW` call.
|- **Log Dump** — `Export-GodModeLogs` collects all accumulated logs and dumps them to the Desktop with a timestamped filename (`GodMode_Dump_YYYY-MM-DD_HH-mm-ss.log`); accessible via CLI `-DumpLogs` or interactive menu option [11]
|- **Rotating Raw Debug Dump** — `Export-RawDebugDump` captures full system state (environment variables, loaded modules, running processes, `$Error` stack, and all log files) into timestamped dumps under `%TEMP%\GodMode_RawDumps`. Automatically rotates to keep only the 5 most recent dumps. Triggered automatically on installation start/end and on any uncaught terminating error via a global `trap` handler.
|- **Event-Driven Process Elevation** — `Register-ProcessCreationWatcher` uses a WMI `__InstanceCreationEvent` watcher to detect new processes in near real time, pushing them into a synchronized queue that the monitor loop drains immediately. This eliminates the per-loop `Get-CimInstance` polling overhead and catches new apps faster than the 5-second window. Falls back to CIM polling automatically if WMI is unavailable.
|- **SYSTEM PID Cache** — `Find-SystemProcessCandidate` caches the first successfully validated SYSTEM PID for 60 seconds, avoiding repeated `GetOwner` + `OpenProcess` scans on every elevation call. Cache is invalidated on timeout or process exit.
|- **Conditional Polling** — When the event watcher is active, `Start-Monitoring` skips the `Get-CimInstance` new-process query entirely and trusts the queue, removing the last per-loop CIM overhead.
|- **Administrator-Safe Monitor** — If `Start-Monitoring` is accidentally started as Administrator (not SYSTEM), it logs a one-line warning and skips all elevation blocks (periodic and new-process) while keeping the resurrection-killer and stealth-mode active. This prevents the diagnostics-dump flood that occurred when `Enable-ElevationPrivileges` failed to enable `SeAssignPrimaryTokenPrivilege` in a filtered Administrator token.
|||- **Pre-flight Compiler Check in `Enable-GodMode`** — The very first thing `Enable-GodMode` (option 7) does is verify that `gmproxy.exe` and `gmhook.dll` exist. If either is missing and no compiler is available (after attempting MSYS2 auto-install), it **aborts before any system modifications** (Defender disable, registry changes, scheduled tasks, etc.) and writes a detailed `GodMode_CompilerError.log` to the **Desktop**. This prevents dangerous system changes from being applied when the C hooks cannot be built.
|||
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
    - **Auto-install**: If MSYS2 is detected but `gcc.exe` is missing, the TUI will show `MSYS2 FOUND (gcc missing)` and option `[7]` will automatically run `pacman -S mingw-w64-ucrt-x86_64-gcc --noconfirm` via MSYS2 bash before attempting the C component build.
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

### Regression Binder & wine Smoke Test

Run the full regression binder (shellcheck + MinGW/wine C test + PowerShell suites + the `gmhook.dll` wine smoke test) in one command:
```bash
bash tests/run-regressions.sh
```

`tests/test-shell-host-exclusion.sh` builds `gmhook.dll` with MinGW, loads it into `pwsh.exe` and `chrome.exe` stub hosts (built from `tests/Test-ShellHostExclusion.c`) under wine, and asserts via the exported `IsHookInstalled()` diagnostic that the `CreateProcessW` IAT hook is NOT installed in shell/launcher hosts (the `0xC0000005` fix) and IS installed in the `chrome.exe` control. This catches `IsShellLauncherProcess` regressions at the BINARY level before deploying to the Windows VM. It prints a FAIL SUMMARY (N) block and exits 1 on any failure. As of 2026-07-16 it also runs a RUNTIME wide-format (`%s`-vs-`%ls`) regression guard: it forces the wine CWD to a clean temp dir, pre-deletes the wine temp `gmhook.log`, and after the wine runs asserts NO `Cgmhook.log` CWD artifact + a FULL `[GM-HOOK] BUILD ... loaded in ...` stamp in the wine temp `gmhook.log` -- catching a MinGW wide-swprintf truncation regression at runtime, not just in source. As of 2026-07-16 23:22 UTC the smoke test also has a `--regression-mode` NEGATIVE direction (wired into `run-regressions.sh` step 4b) that builds a broken `%ls`->`%s` `gmhook.dll` (real source untouched) and asserts the two guards FAIL -- proving the guard catches a broken build, not just that a correct build passes.

`tests/test-gmproxy-refuse.sh` is a wine RUNTIME proof of gmproxy's ownerless-birth REFUSE (the source-level `Test-GmProxySession.ps1` section 17 + the `test-gmproxy-session.sh` build proof only check the invariants are written down + that gmproxy.c compiles). It builds `gmproxy.exe` twice (NORMAL + a FORCED build with `-DGMPROXY_TEST_FORCE_SESSION0=1`, a COMPILE-TIME test seam in `driver/gmproxy.c` that forces `mySession=0` -- the PRODUCTION build does NOT define it, so the shipped `gmproxy.exe` is byte-for-byte unaffected) plus a quickly-exiting dummy target (`tests/gmproxy-refuse-target.c`), runs both under wine, and asserts the NORMAL build takes the graceful current-user fallback (exit 0) while the FORCED build REFUSES ownerless birth (exit 1 + `[GM-PROXY] REFUSE` in `%TEMP%\gmproxy.log`). wine reports session 1 (not Session 0), so the seam is required to exercise the REFUSE branch under wine; it proves BOTH branches of the ownerless-birth fix behave at runtime, not just in source. Wired into `tests/run-regressions.sh` as step 5b; FAIL SUMMARY (N) + exit 1 on failure.

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
- Honest ERROR aggregation: the summary derives ERROR/WARN file lists from `$FileFailures` (single source of truth) so the exit code always reflects real `[ERROR]` findings (fixes a `$script:` scoping bug that always printed "Failed: 0"); `FAIL SUMMARY (N)` lists each ERROR file + message
- Heuristic scanners downgraded ERROR -> WARN: brace/bracket/parenthesis mismatch, try/catch/finally mismatch, and `>>>`/`<<<` redirect-trap inside double-quoted strings (string literals are NOT parsed as operators); AST + PSParser remain the authoritative ERROR parse checks
- String-aware elevation-loop detection: `Verb = runAs` without `UseShellExecute = $true` is only flagged in BARE code, not inside quoted string literals (test files mentioning the pattern in a `-notmatch` regex are no longer false-flagged)
- Best-effort toolchain checks (SKIP if the tool is not on PATH): C compile via `x86_64-w64-mingw32-gcc`/`gcc`/`cl.exe` (`-fsyntax-only`; `: error:` -> ERROR, `: warning:` -> WARN), `shellcheck -S warning` on `.sh`, `python -m py_compile` on `.py`, `node --check` on `.js`
- Auto-chmod extended to `.sh` / `.py` / `.js` (`chmod +x` on Unix, ACL `ReadAndExecute` on Windows) alongside the `.ps1` pass
- Per-language summary counts: `Total checked: N (PS: X, C: Y, SH: Z, PY: .., JS: ..)`

---

## Changelog

### Unreleased

- **2026-07-17 00:31 UTC** — Two residual edge cases from the 00:14 ownerless-birth fix closed, plus a deterministic RUNTIME proof of the gmproxy REFUSE under wine. (1) `Invoke-HybridElevation` Phase 2 (scheduled-task fallback) kill ordering reversed: kill-AFTER-success instead of kill-before-launch -- the old `Get-Process|Stop-Process` + 800ms settle BEFORE the task left the user with NO app if gmproxy-as-task refused or the SYSTEM child lost the single-instance race; Phase 2 now waits for a SYSTEM instance via `Test-SystemProcessExists` after the task enters Running and only THEN purges non-SYSTEM duplicates (gated on `$systemAlive`), keeping the user app if no SYSTEM child surfaces (graceful degradation). (2) New `tests/test-gmproxy-refuse.sh` + `tests/gmproxy-refuse-target.c` RUN `gmproxy.exe` under wine with a dummy target and prove BOTH branches at runtime: NORMAL build -> graceful current-user fallback (exit 0); FORCED build (`-DGMPROXY_TEST_FORCE_SESSION0=1`, a COMPILE-TIME test seam in `driver/gmproxy.c` that forces `mySession=0` -- the production build does NOT define it, so the shipped `gmproxy.exe` is byte-for-byte unaffected) -> ownerless-birth REFUSE (exit 1 + `[GM-PROXY] REFUSE` in `%TEMP%\gmproxy.log`). wine reports session 1 (not Session 0), so without the seam the REFUSE branch is never exercised under wine. Regression: `tests/Test-GmProxySession.ps1` +8 section-18 assertions (104/104, was 96/96); `tests/test-gmproxy-session.sh` +4 invariants; `tests/run-regressions.sh` +1 step (5b); `tests/test-gmproxy-refuse.sh` 16/16; full suite 17/17 (was 15/15), FAIL SUMMARY 0; `syntax_check.ps1` 18/18, 0 ERROR. No binary rebuild required (the gmproxy.c seam is compiled out of production; Phase 2 is PowerShell-side). NOT pushed.

- **2026-07-16 23:22 UTC** — Added a `--regression-mode` NEGATIVE direction to the wine smoke test `tests/test-shell-host-exclusion.sh` (wired into `tests/run-regressions.sh` as step 4b). It builds `gmhook.dll` from a BROKEN copy of `gmhook.c` (only the `%TEMP%\gmhook.log` PATH `swprintf` reverted `%ls`->`%s`, kept in the throwaway `$WORK` dir -- the real source is never modified) and INVERTS the two runtime wide-format guards: `Cgmhook.log` MUST appear in the wine CWD + the wine `%TEMP%` `gmhook.log` MUST have no full BUILD stamp, plus a characterization assertion that the CWD `Cgmhook.log` holds the FULL stamp (proving the regression is a PATH redirect, not content truncation). This PROVES the guard catches a broken build, not just that a correct build passes (positive 7/7 + negative 8/8; full suite 14/14, FAIL SUMMARY 0).

- **2026-07-16 23:05 UTC** — Runtime wide-format (`%s`-vs-`%ls`) regression guard added to the wine smoke test `tests/test-shell-host-exclusion.sh` (catches the regression at RUNTIME, not just in source). The smoke test now forces the wine CWD to the clean WORK dir (subshell) so a path-truncation regression drops a deterministic `Cgmhook.log` CWD artifact, pre-deletes the wine temp `gmhook.log` so the post-run check only sees THIS run's lines, and after the wine runs asserts (a) NO `Cgmhook.log` in the wine CWD and (b) the wine temp `gmhook.log` holds a FULL `[GM-HOOK] BUILD ... loaded in ...` stamp (`grep -qF` fixed strings). A negative test proved the guard catches the regression: an isolated broken `gmhook.c` (path `%ls`->`%s`, real source untouched) reproduced both symptoms (CWD `Cgmhook.log` + absent temp `gmhook.log`) so both assertions FAIL on a broken build; on the correct build both PASS. Existing pwsh/chrome assertions unchanged (additive). Smoke test 7/7; full suite 13/13, FAIL SUMMARY 0; `syntax_check.ps1` 0 ERROR (16 files); shellcheck clean.

- **2026-07-16 22:47 UTC** — Fixed the wine smoke-test `Cgmhook.log`/`Cgmproxy.log` repo-root artifact AND the garbled `[[` build stamps on MinGW-built binaries: `%s` in MinGW's wide `swprintf`/`fwprintf`/`vfwprintf` truncates a `wchar_t*` argument to its FIRST character (MSVC treats `%s` as wide, MinGW treats it as narrow and stops at the first `0x00` byte). A probe confirmed `GetTempPathW` returns the FULL `C:\...\Temp\` (WITH trailing backslash) under wine, but `swprintf(path, L"%sgmhook.log", tempDir)` produced `Cgmhook.log` (just `C` + `gmhook.log`), and `fwprintf(f, L"%s", line)` wrote only `[` per attach -- so the prior session's build-stamp feature was BROKEN on the MinGW binaries copied to the VM (logs landed in CWD, stamps truncated, option [11] showed `[not yet logged]`). The prior "missing backslash" diagnosis was wrong (wine DOES return the trailing backslash). Fix: `%s` -> `%ls` (wide, consistent across MSVC + MinGW) for every `wchar_t*` arg in both C files (gmproxy log path + BUILD stamp + hardlink path + Launched DiagLogs; gmhook log path + BUILD line wdate/wtime/baseName) + `fwprintf(f, L"%s", buf)` -> `fputws(buf, f)` for the two pre-built wide line writes. The `GmEnsureTrailingBackslash` helper added earlier this session is KEPT as harmless defensive belt-and-suspenders (a no-op in practice). End-to-end wine-verified: no repo-root artifact; wine temp `gmhook.log`/`gmproxy.log` now hold FULL `[GM-HOOK] BUILD Jul 17 2026 00:45:59 loaded in ...` / `[GM-PROXY] BUILD Jul 17 2026 00:45:58 (compiled)` stamps. Regression: `tests/Test-GmProxySession.ps1` section-14 regex fixed + new section 16 (+8 `%ls`/`fputws` assertions, 87/87); `tests/test-gmproxy-session.sh` +1 `grep -qF '%lsgmproxy.log'` invariant (21/21); full suite 13/13, FAIL SUMMARY 0; `syntax_check.ps1` honestly green (0 ERROR, 16 files). Binaries rebuilt (MinGW, PE32+, stamp `Jul 17 2026 00:45:58/59`) at `/tmp/GodModeBuild/` -- copy to the VM install dir so option [11] shows the real stamps.

- **2026-07-16 22:20 UTC** — Build-version stamps in the C binaries + at-a-glance deployment identification in Export-GodModeLogs (option [11]). `driver/gmproxy.c` writes `[GM-PROXY] BUILD <__DATE__ __TIME__> (compiled)` to `%TEMP%\gmproxy.log` on every launch (new `GmWidenAscii` widens the narrow `__DATE__`/`__TIME__` to `wchar_t` portably across MSVC/MinGW); `driver/gmhook.c` writes `[GM-HOOK] BUILD <date> <time> loaded in <host> (attach <ts>)` to `%TEMP%\gmhook.log` on every `DLL_PROCESS_ATTACH` via new `GmHookWriteBuildStamp` (named-mutex try-lock so `DllMain` never blocks under the loader lock, ~256KB size-capped, `OutputDebugStringW` for live DebugView). The stamp uses `__DATE__`/`__TIME__` so it changes on every recompile. `Export-GodModeLogs` (option [11]) adds a prominent `===== GM BUILD VERSIONS =====` section extracting the last `[GM-PROXY] BUILD` / `[GM-HOOK] BUILD` line + the installed binary `LastWriteTime` for each, so a stale vs. freshly-rebuilt binary is identifiable at a glance (no more guessing whether the VM is running the fixed or stale binary). `Uninstall-ProcessHook` now also removes `%TEMP%\gmhook.log`. Regression: `tests/Test-GmProxySession.ps1` +15 assertions (section 14, 75/75); `tests/test-gmproxy-session.sh` +4 invariants (19/19); full suite 13/13, FAIL SUMMARY 0; `syntax_check.ps1` honestly green (0 ERROR, 16 files). Binaries rebuilt (MinGW, PE32+, stamp baked in) at `/tmp/GodModeBuild/` -- copy to the VM install dir for the stamp to take effect.

- **2026-07-16 21:59 UTC** — Fixed the monitor's kill+relaunch path birthing Firefox/Chrome ownerless in Session 0 (empty User column, no visible window / no launch). The prior gmproxy.c session-correctness fix (2026-07-16 19:44) closed the IFEO/gmproxy ownerless-birth path, but `TokenOps.CreateProcessAsSystem` (the monitor's kill+relaunch) still had the same two bugs: (1) it called `SetTokenInformation(TokenSessionId, 1)` WITHOUT enabling `SeTcbPrivilege`, so session relocation silently failed; (2) `Find-SystemProcessCandidate` could source a Session-0 `services.exe` token when winlogon/dwm/fontdrvhost were PPL-protected. Fix: `CreateProcessAsSystem` now resolves the active session via `WTSGetActiveConsoleSessionId`, queries the token's session via `GetTokenInformation`, enables `SeTcbPrivilege`, and returns a new `SESSION0_REFUSED` sentinel (-1) instead of birthing an ownerless child (the caller falls through to the service path). `Find-SystemProcessCandidate` resolves `$activeSession` via `[TokenOps]::WTSGetActiveConsoleSessionId`, uses it in both the priority + fallback filters (`-and $_.SessionId -gt 0`), and excludes `services.exe`. `driver/gmhook.c` `FindSystemPid` is now session-aware too (new `GmHookGetActiveConsoleSessionId` dynamic wtsapi32 load + `ProcessIdToSessionId` filter). Binaries rebuilt (MinGW, PE32+ verified) -- copy to the VM install dir for the C-side fixes; the PowerShell fixes are live on reload. Regression: `tests/Test-GmProxySession.ps1` +17 assertions (sections 11/12/13); full suite 13/13, FAIL SUMMARY 0; `syntax_check.ps1` honestly green (0 ERROR, 16 files).

- **2026-07-16 21:33 UTC** — syntax_check.ps1 upgraded to be HONEST and to run real toolchains. Fixed a `$script:` scoping bug where `Add-Failure`'s `$FailedFiles`/`$ErrorFiles`/`$Warnings` never aggregated (the checker always printed "Failed: 0 / [SUCCESS]" regardless of real `[ERROR]` findings): the arrays are now `$script:`-scoped AND the summary derives ERROR/WARN file lists from `$FileFailures` (single source of truth), so the exit code honestly reflects `[ERROR]` findings and `FAIL SUMMARY (N)` lists each ERROR file + message. Heuristic scanners downgraded ERROR -> WARN (#18 brace/bracket/paren mismatch, #25.5 try/catch mismatch, #16 `>>>`/`<<<` inside double-quoted strings — string literals are not parsed as operators; `#16` self-skips the checker's own diagnostic lines); AST (#1) + PSParser (#2) remain the authoritative ERROR parse checks. `#21` elevation-loop (Verb=runAs without UseShellExecute) is now STRING-AWARE — only flags `Verb = runAs` in bare code, not inside quoted string literals (test files mentioning the pattern in a `-notmatch` regex are no longer false-flagged). New best-effort toolchain checks (SKIP if the tool is absent): C compile via `x86_64-w64-mingw32-gcc`/`gcc`/`cl.exe` (`-fsyntax-only`; `: error:` -> ERROR / `: warning:` -> WARN; `gmproxy.c` gets `-municode`), `shellcheck -S warning` on `.sh`, `python -m py_compile` on `.py`, `node --check` on `.js`. Auto-chmod extended to `.sh`/`.py`/`.js` (`chmod +x` on Unix, ACL `ReadAndExecute` fallback). Summary now shows per-language counts `Total checked: N (PS/C/SH/PY/JS)`. New regression `tests/test-syntax-check.sh` (shellcheck-clean) proves honesty: clean `.ps1` -> exit 0 + `[SUCCESS]`, broken `.ps1` -> exit 1 + `FAIL SUMMARY`, broken `.c` -> exit 1; wired into `tests/run-regressions.sh` as step 6. Full suite 13/13, FAIL SUMMARY 0; `syntax_check.ps1` honestly green on the project (0 ERROR, exit 0, 15 files = PS 8 / C 4 / SH 3); `gmproxy.c` MinGW `-fsyntax-only` clean.

- **2026-07-16 20:50 UTC** — gmproxy diagnostics are now durable and surfaced in Export-GodModeLogs (option [11]); graceful-fallback PIDs are handed to the monitor for in-place SYSTEM elevation (no kill+relaunch duplicate). `driver/gmproxy.c` mirrors every `[GM-PROXY]` line to `%TEMP%\gmproxy.log` via new `DiagLog()` (stderr preserved); `Export-GodModeLogs` adds a `===== GM-PROXY DIAGNOSTIC LOG =====` section reading that file (missing-file guarded). The graceful-fallback path signals the monitor over named pipe `\\.\pipe\GodMode-GmProxyFeedback` (new `SignalGmProxyFeedback`, non-blocking `CreateFileW`+`OPEN_EXISTING`) so new `Start-GmProxyFeedbackListener` (ThreadJob `NamedPipeServerStream` with explicit PipeSecurity ACL) + `Invoke-GmProxyFeedbackElevation` (Phase 0 `ReplaceProcessTokenForPid`, no kill-relaunch, shell/critical guard) elevate the PID in place instead of the 15s scan kill+relaunching a duplicate. `Stop-GmProxyFeedbackListener` wired into `Disable-GodMode`. Regression: `tests/Test-GmProxySession.ps1` + `tests/test-gmproxy-session.sh` extended; full suite 11/11, FAIL SUMMARY 0; `syntax_check.ps1` 12/12.
- **2026-07-16 19:44 UTC** — Fixed IFEO/gmproxy-launched apps coming up ownerless / blank User column / unusable / instant-killed (Firefox, Chrome, others). `driver/gmproxy.c` now requires the stolen SYSTEM token to come from the active interactive session (`GetActiveConsoleSessionId` via dynamic `wtsapi32` load + `ProcessIdToSessionId` filter; named `winlogon`/`dwm`/`fontdrvhost` priority with an any-openable-SYSTEM-in-session fallback), enables `SeTcbPrivilege` best-effort for a session-relocate path, and GRACEFULLY FALLS BACK to launching the target as the current user via the IFEO-bypass hardlink when no session-correct token + no `SeTcb` are available (instead of a broken ownerless Session-0 launch). `God-Mode-Windows.ps1` monitor (`Stop-NonSystemInstances` + both `Invoke-ParallelElevation` kill sites) no longer kills processes whose WMI `GetOwner` reads blank/unresolvable (the brief post-launch window that caused Chrome instant-kill). New regression tests `tests/Test-GmProxySession.ps1` (22 assertions) + `tests/test-gmproxy-session.sh` (MinGW compile proof); full suite 11/11, FAIL SUMMARY 0; `syntax_check.ps1` 12/12.
- **2026-07-16 19:10 UTC** — Auto-populate the IFEO elevation list so any installed normal program is caught at launch (born as SYSTEM via `gmproxy.exe`), while critical/shell/OS processes stay intact. New `Get-IfeoElevationCandidates` scans running processes, AppPaths registry, `Program Files` (x86/x64), and `%LOCALAPPDATA%\Programs`; a triple safety net (canonical name denylist `$GmCriticalIfeoExclude` = union of all existing critical lists incl. God Mode's own CLI deps `sc`/`schtasks`/`netsh`/`reg`; Windows/System32/SysWOW64 path-exclusion; dedup by base name) merges survivors with the curated seed. `Uninstall-IfeoElevation` rewritten to enumerate IFEO keys by `Debugger`-contains-`gmproxy` (robust cleanup of curated + auto-populated + legacy keys). Regression tests extended (76 assertions); full suite 8/8, FAIL SUMMARY 0; `syntax_check.ps1` 11/11.
- **2026-07-16 18:59 UTC** — Added an IFEO + gmproxy SYSTEM-elevation layer for normal user programs (chrome, notepad, regedit, mstsc, office, dev tools, archivers, games, etc.). Any launch of a curated list of normal apps is transparently redirected by an IFEO `Debugger` key to `gmproxy.exe`, which steals a SYSTEM token and launches the app BORN as SYSTEM via `CreateProcessWithTokenW` (gmproxy defeats IFEO recursion via a uniquely-named hardlink). New `Install-IfeoElevation` / `Uninstall-IfeoElevation` (wired into `Enable-GodMode`/`Disable-GodMode`); each IFEO key is hardened via `Harden-RegistryKey` and restored via `Restore-RegistryKey` on uninstall. Shells/terminals (`cmd`, `powershell`, `pwsh`, `wt`, `conhost`, `OpenConsole`, `WindowsTerminal`, `wsl`, `wslhost`) plus `explorer`/`taskmgr` are deliberately EXCLUDED — God Mode's own persistence invokes `powershell.exe`/`cmd.exe`, so IFEO-redirecting those would break the monitor loop (mirrors `IsShellLauncherProcess` in `gmhook.c`). `Export-GodModeLogs` IFEO diagnostic expanded to show `regedit`/`mstsc`. New regression test `tests/Test-IfeoElevation.ps1` (wired into `run-regressions.sh` + `Test-Suite.ps1`); full suite passes 8/8, FAIL SUMMARY 0.
- **2026-07-16 18:33 UTC** — Fixed Task Manager (and shell-launched apps) not elevating to SYSTEM. Two root causes: (1) `driver/gmhook.c` `TryCreateProcessWithSystemToken` bailed out unelevated whenever the caller passed a `STARTUPINFOEX` / `EXTENDED_STARTUPINFO_PRESENT` (`0x00080000`) structure — and `explorer.exe` launches Task Manager (and most shell apps) with `STARTUPINFOEX`, so the `CreateProcessW` IAT hook silently fell through to the real unelevated `CreateProcessW`. The old `cb > sizeof(STARTUPINFOW)` skip (which avoided the original `0xC0000005`) is now a **DOWNGRADE**: copy only the first `sizeof(STARTUPINFOW)` base bytes, clamp `cb` to `sizeof(STARTUPINFOW)`, and CLEAR the `EXTENDED_STARTUPINFO_PRESENT` bit, so the child is BORN as SYSTEM via `CreateProcessWithTokenW` (the `0xC0000005` root cause stays prevented by the `cb` clamp + bit clear; the unelevated fall-back still runs on any failure). (2) `God-Mode-Windows.ps1` `-LaunchTaskMgrAsSystem` always failed because it called `CreateProcessAsUser` (needs `SeAssignPrimaryTokenPrivilege` an interactive Administrator does NOT hold -> Win32 1314) and then fell back to an unelevated `Start-Process`; switched to `CreateProcessWithTokenW` (only needs `SeImpersonatePrivilege`), resolve the real `%WINDIR%\System32\taskmgr.exe` (the legacy `taskmgr_real.exe` copy is only ever deleted, never created), best-effort start the `seclogon` service first, and forward `-LaunchTaskMgrAsSystem` through auto-elevation. Regression coverage updated in `tests/Test-GmHookFix.c` and `tests/Test-GodModeCrashFix.ps1`; full suite passes 7/7, FAIL SUMMARY 0.
- **2026-07-16 18:05 UTC** — Added a wine smoke test that catches `gmhook.dll` shell-host-exclusion regressions BEFORE deploying to the Windows VM. `driver/gmhook.c` exports a read-only `IsHookInstalled()` diagnostic; `tests/Test-ShellHostExclusion.c` is a stub host built twice (as `pwsh.exe` and `chrome.exe`) that loads the real `gmhook.dll` under wine and asserts the `CreateProcessW` IAT hook is NOT installed in `pwsh.exe` and IS installed in the `chrome.exe` control. `tests/test-shell-host-exclusion.sh` runs it with a FAIL SUMMARY (N) + exit-1 contract and is wired into `tests/run-regressions.sh` as step 4; `Test-GodModeCrashFix.ps1` gained a source assertion guarding the new export.
- **2026-07-15 18:59 UTC** — Fixed PowerShell 7 (`pwsh.exe`) fatal crash `0xC0000005` (STATUS_ACCESS_VIOLATION) inside `Kernel32.CreateProcess`. Root cause: `gmhook.dll` was injected into shell/launcher hosts (PowerShell, cmd, terminals) and rerouted their `CreateProcessW` calls through the stolen-token `CreateProcessWithTokenW` path — a native access violation PowerShell `try/catch` cannot recover from (it kills `pwsh.exe`). Fix: `gmhook.c` adds `IsShellLauncherProcess()` (excludes `pwsh.exe`, `powershell.exe`, `cmd.exe`, `wt.exe`, `conhost.exe`, `OpenConsole.exe`, `WindowsTerminal.exe` from IAT hooking at the `HookCreateProcessW` pass-through, `GetMsgProc`, and `DllMain` sites); `Install-ProcessHook` adds the same hosts to its `$CriticalProcs` DLL-injection skip-list. These hosts are still elevated to SYSTEM via `Invoke-HybridElevation` / `CreateProcessAsSystem`; they are simply not IAT-hooked in-process. Also fixed a `HookCreateProcessW` recursion-guard leak (one re-entry permanently left `inHook==1`, silently disabling elevation) and documented why MinGW builds rely on deterministic STARTUPINFO validation instead of SEH (the `<excpt.h>` `__try1` macro emits invalid `.seh_endproc`/`.text.startup` directives under `-O2` on mingw-w64 16.x). Regression tests extended in `tests/Test-GmHookFix.c` and `tests/Test-GodModeCrashFix.ps1`.
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
| `tests/Test-ShellHostExclusion.c` | wine smoke-test stub host for gmhook.dll shell-host exclusion |
| `tests/test-shell-host-exclusion.sh` | wine smoke-test runner: builds gmhook.dll + pwsh.exe/chrome.exe stubs, runs under wine, FAIL SUMMARY (N) + exit-1 |
| `tests/Test-GmProxySession.ps1` | Regression test for gmproxy.c session-correct SYSTEM-token launch + monitor blank-owner kill guard (FAIL SUMMARY (N) + exit-1) |
| `tests/test-gmproxy-session.sh` | MinGW cross-compile proof for gmproxy.c session fix + source invariants (FAIL SUMMARY (N) + exit-1) |
| `tests/test-gmproxy-refuse.sh` | wine RUNTIME proof of gmproxy ownerless-birth REFUSE (NORMAL graceful fallback + FORCED `-DGMPROXY_TEST_FORCE_SESSION0=1` refuse) + dummy target (FAIL SUMMARY (N) + exit-1) |
| `tests/gmproxy-refuse-target.c` | Minimal quickly-exiting dummy target for the gmproxy REFUSE wine smoke test |

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
18. **PowerShell Hook Installer (`Install-ProcessHook` / `Uninstall-ProcessHook`)**: `Install-ProcessHook` checks for `gmproxy.exe` and `gmhook.dll`; if either is missing, it auto-runs `driver/build.ps1` (auto-detects MSVC or MinGW), captures full build output to the **Desktop** (`GodMode_DriverBuild.log`), and retries before proceeding. **MSYS2 auto-install**: If MSYS2 is present but `gcc.exe` is missing, `Install-ProcessHook` automatically invokes `pacman -S mingw-w64-ucrt-x86_64-gcc --noconfirm` via MSYS2 bash before the build, then refreshes PATH so the newly installed compiler is available. **Pre-flight compiler check**: Before attempting the build, `Install-ProcessHook` explicitly verifies that a compiler is available via `Get-CompilerStatus`. If no compiler is found and MSYS2 auto-install fails, it logs a red ERROR with the exact cause and **aborts** the process hook installation entirely — no IFEO keys or DLL injection are attempted. If the build script runs but exits with a non-zero code or throws an exception, it also aborts and logs the failure. A final binary verification ensures both `gmproxy.exe` and `gmhook.dll` exist before any installation steps proceed. `Uninstall-ProcessHook` removes the keys, deletes the binaries, and logs completion. Both are called automatically by `Enable-GodMode` and `Disable-GodMode`.

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
||- **Firefox / Chrome launches with an EMPTY User column (ownerless) or does not launch at all**: This is the Session-0 ownerless-birth symptom -- the process is born in the services session with no interactive desktop, so Task Manager shows a blank User column and no window appears. Root cause: the monitor's `CreateProcessAsSystem` called `SetTokenInformation(TokenSessionId)` without enabling `SeTcbPrivilege` (so relocation silently failed), AND `Find-SystemProcessCandidate` could fall back to a Session-0 `services.exe` token when `winlogon.exe`/`dwm.exe`/`fontdrvhost.exe` were PPL-protected. Fixed (2026-07-16 21:59 UTC): `CreateProcessAsSystem` now resolves the active session via `WTSGetActiveConsoleSessionId`, queries the token's session, enables `SeTcbPrivilege`, and returns a `SESSION0_REFUSED` sentinel instead of birthing an ownerless child (the caller falls through to the service-based path); `Find-SystemProcessCandidate` filters to the active session (`SessionId -gt 0`) and excludes `services.exe`; `driver/gmhook.c` `FindSystemPid` is session-aware too (new `GmHookGetActiveConsoleSessionId` dynamic wtsapi32 load + `ProcessIdToSessionId` filter). **To take effect**: reload `God-Mode-Windows.ps1` (the PowerShell fixes are live on reload via `Add-Type`), AND copy the freshly rebuilt `gmproxy.exe` + `gmhook.dll` to the VM install dir (the C-side session-awareness fixes need the new binaries). Check `%TEMP%\gmproxy.log` (surfaced via option [11] Export-GodModeLogs) for the `Acquired active-session SYSTEM token` / `WARN: no usable SYSTEM token` / `Launched ... as current user (graceful fallback)` lines to confirm which path was taken.
||- **How to read the debug logs**: Every token-stealing attempt now writes a structured `ROOT_CAUSE:` line to `DNS_Lockdown_Enterprise.debug.log` in `%TEMP%`. The log format is `[timestamp] [DEBUG] [ACTION] [Function] [Line] Message | Exception: ... | ROOT_CAUSE: ...`. Look for `REJECTED:` and `SUCCESS:` entries from `Find-SystemProcessCandidate` to see why each process was skipped or picked.
|||- **Privilege missing even as Administrator**: Windows removes `SeDebugPrivilege` from the filtered token when UAC is enabled. The new `Get-ElevationPrivilegeStatus` function logs which privileges are actually present. If it reports `SeDebugPrivilege: False`, run the script from a fully elevated shell ("Run as Administrator") or use a SYSTEM shell. The script will auto-dump diagnostics when it detects missing required privileges.
|||- **C component build failed / God Mode aborted on option 7**: If `Enable-GodMode` detects missing `gmproxy.exe` or `gmhook.dll` and no compiler is available, it aborts immediately before making any system changes. A detailed error log is saved to your **Desktop** as `GodMode_CompilerError.log`. The build output (when a build is attempted) is also saved to the Desktop as `GodMode_DriverBuild.log`. Install MSYS2 or Visual Studio Build Tools, then press `[7]` again.

|||- **PowerShell (pwsh.exe) crashes with `0xC0000005` inside `Kernel32.CreateProcess`**: This was caused by `gmhook.dll` being injected into PowerShell/cmd/terminals and rerouting their `CreateProcessW` calls through the stolen-token `CreateProcessWithTokenW` path — a native access violation PowerShell `try/catch` cannot recover from (it kills `pwsh.exe`). Fixed: shell/launcher hosts (`pwsh.exe`, `powershell.exe`, `cmd.exe`, `wt.exe`, `conhost.exe`, `OpenConsole.exe`, `WindowsTerminal.exe`) are now excluded from both the C IAT hook (`gmhook.c` `IsShellLauncherProcess`) and the PowerShell DLL-injection skip-list (`Install-ProcessHook` `$CriticalProcs`). PowerShell and cmd are still elevated to SYSTEM via the task/service path, just not IAT-hooked in-process. If the crash recurs after update, re-enable God Mode (option 7) so the new skip-list is applied, and verify with `tests/Test-GodModeCrashFix.ps1`.

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
