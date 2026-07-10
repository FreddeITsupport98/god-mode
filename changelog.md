# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added
- `God_mode.bat` — Batch launcher that automatically bypasses Execution Policy for this run only. Recommended way to start the suite when scripts are blocked.
- `Launch-SystemShell.bat` — Batch launcher for the SYSTEM shell tool with automatic Execution Policy bypass.
- `Launch-SystemShell.ps1` — Explicit, non-persistent SYSTEM shell launcher for security testing. Uses a temporary scheduled task. No auto-elevation, no silent UAC bypass, no persistence.
- `tests/Test-Suite.ps1` — Comprehensive regression test suite for `God_mode.ps1` and `Launch-SystemShell.ps1`. Validates syntax, script structure, installer/uninstaller logic, and menu integrity without making system changes.
- `changelog.md` — Project changelog initialized.
- Registry ACL hardening helpers: `Harden-RegistryKey` and `Restore-RegistryKey` — apply multi-layer `Deny` ACLs (`SetValue`, `CreateSubkey`, `Delete`, `WriteKey`) to `Administrators`, `Everyone`, and `Authenticated Users` on all DNS, DoH, and God Mode registry keys, plus disable inheritance and strip old deny rules before re-applying.
- `Invoke-StealthMode` — masks PowerShell window title and suppresses script-block logging / transcription / module logging via registry.
- `Register-DeepPersistence` — adds extra registry Run keys (`HKLM\WOW6432Node`, `HKCU`), additional scheduled tasks with randomized Microsoft-like names, and a boot-level WMI `Win32_ProcessStartupTrace` event filter.
- `Disable-AppLocker`, `Disable-WindowsSandbox`, `Disable-LSAProtection`, `Disable-ASR`, `Disable-ControlledFolderAccess`, `Disable-ExploitGuard`, `Disable-BitLocker` — broader security subsystem disable functions.
- `Clear-ShadowCopies`, `Clear-USNJournal`, `Clear-CrashDumps`, `Clear-PowerShellHistory`, `Clear-RecentTraces` — anti-forensics cleanup functions.
- `Export-GodModeLogs` / `-DumpLogs` — collects all accumulated logs and dumps them to Desktop with a timestamped filename (`GodMode_Dump_YYYY-MM-DD_HH-mm-ss.log`).
- `Get-QuickDNSLockStatus` — lightweight DNS lock probe used by the interactive menu header to show lock state without printing the full adapter report.
- Expanded `Show-GodModeStatus` TUI with real-time status checks for Stealth Mode, Deep Persistence, Broader Security Disable (AppLocker, HVCI, LSA, BitLocker, ASR, CFA, Exploit Guard), Anti-Forensics (Shadows, USN, Dumps, History, Recent), and Registry ACL Hardening.
- Interactive menu now shows a quick one-line status header (God Mode, DNS Lock, Integrity, Built-in Admin) on every redraw instead of dumping the full DNS adapter report.
- Menu option `[5] REFRESH SYSTEM STATUS` now invokes `Show-GodModeStatus` + `Get-DNSLockStatus` instead of doing nothing.
- Comprehensive debug and error tracking system added: `Write-DebugLog` function captures function ENTRY/EXIT, ERROR with full stack traces, line numbers, and exception details to a dedicated debug log (`DNS_Lockdown_Enterprise.debug.log`).
- `Invoke-WithDebug` wrapper for script blocks that auto-logs entry, exit, and exceptions with full stack traces.
- All major functions instrumented with `Write-DebugLog` (Harden-RegistryKey, Restore-RegistryKey, Enable-DNSLock, Disable-DNSLock, Install-Persistence, Install-GodModePersistence, Uninstall-GodModePersistence, Enable-DangerousMode, Disable-DangerousMode, Enable-GodMode, Disable-GodMode, Start-Monitoring, Export-GodModeLogs, Invoke-StealthMode, Register-DeepPersistence).
- `Export-GodModeLogs` now includes the debug log, auto-generated dump header (timestamp, user, machine, PS version), and an ERROR SUMMARY block counting all `[ERROR]` entries from the debug log.
- New CLI switch `-DebugMode` forwards debug verbosity to the main log and preserves detailed traces in the debug log.
- Auto-elevation and PS7 launcher now forward `-DebugMode` and `-Verbose` flags to the elevated child process.

### Improved
- Project structure reorganized with `tests/` folder for regression scripts.

---

## 2026-07-09 19:00:00 UTC — Initial review

### Notes
- Reviewed `God_mode.ps1` (Enterprise DNS Hijack Protection & Installer Suite).
- Identified existing features: IPv4/IPv6 registry ACL locks, browser DoH GPO restrictions, NTFS self-defense, scheduled task persistence, WMI subscription persistence, integrity checking, interactive menu.
- Identified missing: regression test suite, explicit SYSTEM shell tool, consolidated changelog.

---
