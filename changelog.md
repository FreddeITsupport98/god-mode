# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added
- `Export-RawDebugDump` — Rotating raw debug/error dumper that captures full system state (environment variables, loaded modules, running processes, `$Error` stack, and all log files) into timestamped dumps under `%TEMP%\GodMode_RawDumps`. Automatically rotates to keep only the 5 most recent dumps.
- Global `trap` handler that auto-calls `Export-RawDebugDump` on any uncaught terminating error, ensuring a full snapshot is preserved before the script breaks.
- `Export-RawDebugDump` auto-triggered during `Install-GodModePersistence` (start/end) and `Install-Persistence` (start/end) so every installation produces a complete raw audit trail.
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
|- All `Test-BuiltInAdmin` access-denied messages (CLI handlers and interactive menu) now print the actual SID, admin status, and built-in admin status so users can see exactly why they are blocked.
|- Menu prompt updated from `(1-12)` to `(1-13)` to reflect the new option.

### Fixed (2026-07-10 20:08 UTC)
||- `Uninstall-GodModePersistence` now explicitly deletes `GodMode.ps1` via `cmd /c del /f /q` before attempting directory removal, and the SYSTEM fallback command was tightened to explicitly delete the file then remove the directory with `cmd /c rd /s /q`. This prevents the hardened install directory from leaving the payload behind.
||- `Uninstall-Persistence` hardened cleanup for the DNS-Guard install directory now follows the same explicit file-then-directory deletion pattern via `cmd /c del /f /q` and `cmd /c rd /s /q`, improving reliability against hardened ACLs.

### Fixed (2026-07-13 18:40:00 UTC)
|||- **Post-reboot elevation failure (monitoring-loop flapping):** After pressing menu 7 and rebooting, `Start-Monitoring` was constantly killed and restarted by competing persistence layers (startup task, guardian task, WMI `Win32_ProcessStartupTrace` subscription, and backup tasks). Each `-ToggleOn` run called `Register-StealthTask`, which unconditionally called `Unregister-StealthTask`, terminating the already-running monitoring loop before it could elevate any new process.
|||  - `Register-StealthTask` now checks if a stealth task is already `Running` and skips re-registration.
|||  - `Enable-GodMode` now checks if the God Mode flag is already set and the monitor is already running, and exits idempotently if so.
|||  - Deep-persistence WMI subscription changed from `Win32_ProcessStartupTrace` (fires on every process start, causing hundreds of `-ToggleOn` launches) to `__InstanceModificationEvent` with `WITHIN 300` polling on `Win32_Service` (sufficient periodic re-trigger without flapping).
||||- **Periodic elevation missing critical-process guard:** `$CriticalProcs` was defined only inside `Invoke-ExistingProcessElevation`, so the periodic re-elevation block inside `Start-Monitoring` silently referenced an undefined variable and would not skip critical processes. `$CriticalProcs` is now defined at the top of `Start-Monitoring` before the `while` loop.
||||  - `explorer.exe` also added to `$CriticalProcs` so it is never killed and restarted.
||||- **All processes failed elevation (single-instance detection):** `Elevate-Process` tried to spawn a new process via a temporary scheduled task, but single-instance apps (Chrome, Explorer, etc.) detected the existing running instance and immediately exited. This produced `Failed to elevate` for every single process and nothing appeared as SYSTEM in Task Manager.
||||  - `Elevate-Process` now kills the existing process first (`Stop-Process -Force`), waits 800ms, then launches the new instance as SYSTEM. Also skips if an instance is already running as SYSTEM (via `Test-SystemProcessExists`), so the loop doesn't repeatedly re-kill processes that have already been elevated.
||||  - `Test-SystemProcessExists` had a WMI `GetOwner` bug where `Invoke-CimMethod` returns a PSCustomObject with `User` property, not a direct `User` property — fixed.
|||||  - Wait time increased from 1 second to 3 seconds (30 x 100ms polls) for the scheduled task to enter the `Running` state.
||||||- **Periodic elevation indentation bug:** Inside `Start-Monitoring`, the `if` block that gates periodic re-elevation (de-dup via `$lastElevated`) was mis-indented, causing its condition to be evaluated incorrectly in some parses and the block to run unconditionally on every loop. The `if` is now correctly indented so it only fires when the 60-second cooldown has expired.
||||||- **Heart-beatless monitoring loop:** When the monitor runs silently after reboot, users had no way to know it was alive unless a process was elevated. Added a `$loopCount` heartbeat that logs `Monitor heartbeat: loop N, PIDs tracked: M` to the debug log every 30 iterations (roughly every 30 seconds), confirming the loop is still alive.

### Added (2026-07-13 19:32:00 UTC)
||||- **Hybrid Token-Stealing Elevation for Option 7 (God Mode):** Added a dual-path elevation engine that tries to steal a SYSTEM token from a running process before falling back to the scheduled-task method. This makes post-reboot elevation more robust across different Windows builds where SYSTEM processes vary.
||||  - New C# P/Invoke class `TokenOps` added via `Add-Type`: exposes `OpenProcess`, `OpenProcessToken`, `DuplicateTokenEx`, `CreateProcessWithTokenW`, `LookupPrivilegeValue`, `AdjustTokenPrivileges`, and `EnablePrivilege`/`CreateProcessFromToken` helpers.
||||  - `Enable-ElevationPrivileges` enables `SeDebugPrivilege`, `SeAssignPrimaryTokenPrivilege`, and `SeImpersonatePrivilege` in the current process token.
||||  - `Find-SystemProcessCandidate` dynamically searches for a suitable SYSTEM process to steal from. It tries a priority list of well-known stable processes (`lsass.exe`, `services.exe`, `winlogon.exe`, `svchost.exe`, `MsMpEng.exe`, `SearchIndexer.exe`) first, then falls back to scanning up to 30 non-critical processes via WMI `GetOwner`.
||||  - `Start-ProcessWithStolenToken` wraps the token duplication and `CreateProcessWithTokenW` call, passing `WinSta0\Default` as the desktop so GUI apps have a chance to start.
||||  - `Invoke-HybridElevation` orchestrates the two phases: Phase 1 attempts token stealing; Phase 2 falls back to the original scheduled-task elevation (kill existing instance, register temp task, start, wait, unregister). Returns `$true` on success.
||||  - `Elevate-Process` is now a thin wrapper around `Invoke-HybridElevation`, so both `Invoke-ExistingProcessElevation` (menu option 7) and `Start-Monitoring` (post-reboot monitor loop) automatically benefit from the hybrid approach without any caller changes.
||||||- **Token-Stealing Robustness Improvements (2026-07-13 19:50:00 UTC):**
||||||  - `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000) is now used in C# `OpenProcess` instead of `PROCESS_QUERY_INFORMATION` (0x400), allowing the script to query protected SYSTEM processes (e.g., PPL-protected `lsass.exe`) without access-denied errors.
||||||  - New C# `TestOpenProcess` method verifies the full open-token-duplicate chain on a candidate PID before returning it, so `Find-SystemProcessCandidate` only returns a process we can actually use.
||||||  - `Find-SystemProcessCandidate` rewritten to prioritize **Session 1** interactive desktop SYSTEM processes (`winlogon.exe`, `dwm.exe`, `fontdrvhost.exe`) first, because tokens from Session 1 have the correct WindowStation and Desktop (`WinSta0\Default`) and can actually spawn visible GUI apps. Falls back to Session 0 or any accessible non-critical SYSTEM process only if Session 1 fails.
||||||  - `Monitor-ElevateProcess` added: a dedicated monitoring-loop elevation helper that only performs token-stealing (no `Stop-Process`, no scheduled-task fallback). This keeps existing Chrome/Explorer instances alive and avoids the Session 0 / WindowStation mismatch that made GUI apps invisible.
||||||  - Both periodic (60-second) and new-process (on-creation) elevation blocks inside `Start-Monitoring` now call `Monitor-ElevateProcess` instead of `Elevate-Process`, eliminating the kill-and-relaunch cycle that destroyed single-instance apps.

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
