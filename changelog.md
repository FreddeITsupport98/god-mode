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

### Fixed
- `Invoke-SelfDestruct` now guards deletion so it only removes the script if it resides inside `$GodModeInstallDir`. Prevents accidental deletion of the original development source file when running from the GitHub repo.
- `Add-DefenderExclusion` now guards `Add-MpPreference` with `Get-Command` to avoid runtime errors when the Defender module is not available (e.g., PowerShell 7 without Windows Defender cmdlets).
- All `Set-MpPreference` calls in `Enable-DangerousMode`, `Disable-DangerousMode`, `Disable-ASR`, `Disable-ControlledFolderAccess`, and `Disable-ExploitGuard` are now wrapped with `Get-Command` guards, skipping gracefully when the cmdlet is unavailable.
- `Set-NetFirewallProfile` `-Enabled` parameter now uses string literals `"False"` and `"True"` instead of boolean `$false`/`$true`, resolving type-conversion runtime errors.
- `reagentc` calls replaced with `cmd /c "reagentc.exe /disable"` and `cmd /c "reagentc.exe /enable"` to fix "not recognized" errors in PowerShell 7.
- `Get-BitLockerVolume` call in `Disable-BitLocker` now guarded with `Get-Command` to skip suspension when the BitLocker module is not present.
- `Invoke-StealthMode` removed the read-only `$Proc.MainWindowTitle` assignment, which caused a runtime property-assignment error.
- `Invoke-AsSystem` completely rewritten for reliability: unique task/script/result IDs per invocation, result-file polling instead of fixed 30-second waits, explicit `[PSCustomObject]@{Success; Output}` return value, and robust cleanup of temp artifacts even on failure.
- All `Invoke-AsSystem` callers (`Uninstall-GodModePersistence`, `Uninstall-Persistence`) updated to check the returned success flag and log output on failure.
- Hardened-file cleanup commands switched from `Remove-Item` to `cmd /c del /f /q` (files) and `cmd /c rd /s /q` (directories) for better reliability when SYSTEM executes them.
- Added `Test-SystemContext` function and menu option `[13] VERIFY SYSTEM CONTEXT` — runs `whoami` and `whoami /groups` as SYSTEM via `Invoke-AsSystem` and displays the live output, proving SYSTEM execution works.
- Added `Get-CurrentUserSidInfo` helper that returns current SID, `IsAdmin`, and `IsBuiltInAdmin` flags.
- All `Test-BuiltInAdmin` access-denied messages (CLI handlers and interactive menu) now print the actual SID, admin status, and built-in admin status so users can see exactly why they are blocked.
- Menu prompt updated from `(1-12)` to `(1-13)` to reflect the new option.

### Improved
- Project structure reorganized with `tests/` folder for regression scripts.

---

## 2026-07-10 19:48:00 UTC — Self-destruct and runtime error fixes

### Fixed
- See "Fixed" section under Unreleased for detailed bug fixes applied during this build.

---

## 2026-07-09 19:00:00 UTC — Initial review

### Notes
- Reviewed `God_mode.ps1` (Enterprise DNS Hijack Protection & Installer Suite).
- Identified existing features: IPv4/IPv6 registry ACL locks, browser DoH GPO restrictions, NTFS self-defense, scheduled task persistence, WMI subscription persistence, integrity checking, interactive menu.
- Identified missing: regression test suite, explicit SYSTEM shell tool, consolidated changelog.

---
