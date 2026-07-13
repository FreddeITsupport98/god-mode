# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added (2026-07-13 21:18:00 UTC)
- `Invoke-AsSystem` multi-method elevation engine: attempts direct token duplication first (stealing a SYSTEM token from `winlogon.exe` / `csrss.exe` via `CreateProcessWithTokenW`), falls back to a temporary `sc.exe` service launch, and finally falls back to the original Task Scheduler helper. This eliminates the previous failure mode where the Task Scheduler helper killed the target process but never actually elevated it.
- `sc.exe` temporary service elevation path: creates a demand-start service running as SYSTEM, executes the command, deletes the service, and reads the result from a temp file. Useful when token privileges are missing or Task Scheduler is unavailable.

### Fixed (2026-07-13 21:18:00 UTC)
- `TokenOps.CreateProcessFromToken` C# P/Invoke bug: `CreateProcessWithTokenW` was called with `dwLogonFlags = 0` (invalid), causing `ERROR_INVALID_PARAMETER` (87) on every token-stealing attempt. Changed to `LOGON_WITH_PROFILE` (1) as required by the Win32 API.
- `TokenOps.CreateProcessFromToken` C# P/Invoke improvement: `lpApplicationName` is now passed to `CreateProcessWithTokenW` when `appName` is provided, preventing failures when `lpCommandLine` does not start with the executable path (e.g., `/c ...` without `cmd.exe`).

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
||- Menu prompt updated from `(1-12)` to `(1-14)` to reflect the new options [13] VERIFY SYSTEM CONTEXT and [14] EXPORT ELEVATION DIAGNOSTICS.
||- New CLI flag `-ExportElevationDiagnostics` exports the full elevation diagnostics dump without opening the interactive menu.

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
|||||||- **Token-Stealing Robustness Improvements (2026-07-13 19:50:00 UTC):**
|||||||  - `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000) is now used in C# `OpenProcess` instead of `PROCESS_QUERY_INFORMATION` (0x400), allowing the script to query protected SYSTEM processes (e.g., PPL-protected `lsass.exe`) without access-denied errors.
|||||||  - New C# `TestOpenProcess` method verifies the full open-token-duplicate chain on a candidate PID before returning it, so `Find-SystemProcessCandidate` only returns a process we can actually use.
|||||||  - `Find-SystemProcessCandidate` rewritten to prioritize **Session 1** interactive desktop SYSTEM processes (`winlogon.exe`, `dwm.exe`, `fontdrvhost.exe`) first, because tokens from Session 1 have the correct WindowStation (`WinSta0\Default`) and can spawn visible GUI apps. Falls back to Session 0 or any accessible non-critical SYSTEM process only if Session 1 fails.
|||||||  - `Monitor-ElevateProcess` added: a dedicated monitoring-loop elevation helper that only performs token-stealing (no `Stop-Process`, no scheduled-task fallback). This keeps existing Chrome/Explorer instances alive and avoids the Session 0 / WindowStation mismatch that made GUI apps invisible.
|||||||  - Both periodic (60-second) and new-process (on-creation) elevation blocks inside `Start-Monitoring` now call `Monitor-ElevateProcess` instead of `Elevate-Process`, eliminating the kill-and-relaunch cycle that destroyed single-instance apps.
||||||||- **Advanced Elevation Diagnostics & Root-Cause Error Mapping (2026-07-13 19:55:00 UTC):**
||||||||  - `Get-Win32ErrorRootCause` — maps every Win32 API error code (5, 87, 6, 1314, 1307, 2, 8, 998, 122) to a human-readable root-cause explanation with context-aware recommendations (e.g., "PPL protection active — pick winlogon.exe in Session 1").
||||||||  - `Get-ElevationPrivilegeStatus` — programmatically checks which token privileges are held (`SeDebugPrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeImpersonatePrivilege`, etc.) and logs whether each is present or missing, with a clear "MISSING REQUIRED PRIVILEGES" warning if any mandatory privilege is absent.
||||||||  - `Get-ProcessElevationContext` — returns a rich diagnostic object for any PID: name, session ID, owner, whether it is SYSTEM, whether `OpenProcess`/`OpenProcessToken`/`DuplicateTokenEx` succeeded, and the exact root-cause string for the first failure stage.
||||||||  - `Export-ElevationDiagnostics` — generates a dedicated `GodMode_ElevationDiagnostics_*.log` dump file containing: current user/SID/admin status, privilege status table, a full scan of the top 40 SYSTEM processes with per-process `CanOpen`/`CanQuery`/`CanDuplicate` flags and root-cause explanations, and the last Win32 error in the thread. This dump is auto-triggered when `Find-SystemProcessCandidate` fails or when `Enable-ElevationPrivileges` detects missing required privileges.
||||||||  - `Write-DebugLog` upgraded with an optional `RootCause` parameter and automatic root-cause detection: if an `ErrorRecord` is passed and `RootCause` is not provided, the function auto-detects common error strings ("Access is denied", "0x5", "invalid parameter", "privilege") and appends a `ROOT_CAUSE:` line to the debug log.
||||||||  - `Enable-ElevationPrivileges` now logs per-privilege success/failure, reports the Win32 error and root cause for each failed privilege, and auto-calls `Export-ElevationDiagnostics` if any required privilege is missing.
||||||||  - `Find-SystemProcessCandidate` now logs every rejection reason (e.g., "REJECTED: lsass.exe PID=892 Session=0 Owner=SYSTEM | TestOpenProcess failed | ERROR_ACCESS_DENIED..."), reports the total scan count, and auto-dumps diagnostics when no candidate is found.
||||||||  - `Start-ProcessWithStolenToken` now logs the exact target and source PID before attempting creation, and if `CreateProcessWithTokenW` fails it logs the root-cause error, the source process context (Session/Name/CanDup), and a recommendation about Session 1 vs Session 0.
|||||||||  - `Invoke-HybridElevation` and `Monitor-ElevateProcess` now log structured Phase 1 / Phase 2 transitions and explicit root-cause messages when paths are missing or token-stealing fails.
||||||||||- **Invoke-ExistingProcessElevation no longer kills apps on token-steal failure (2026-07-13 20:10:00 UTC):**
||||||||||  - `Invoke-ExistingProcessElevation` (called by menu option 7) was using `Elevate-Process` which includes the scheduled-task fallback. When token stealing failed (missing `SeAssignPrimaryTokenPrivilege` in interactive admin session), the fallback killed Chrome/Explorer and restarted them in Session 0, making them invisible.
||||||||||  - Fixed by switching `Invoke-ExistingProcessElevation` to use `Monitor-ElevateProcess` (token-only, no kill, no scheduled-task fallback). This preserves existing desktop apps during the initial enable. After reboot, the monitor loop runs as SYSTEM with full privileges and correctly elevates new processes.
|||||||||||  - Added clarifying comment explaining the design: existing apps stay alive at their current privilege level during menu 7 enable; true SYSTEM elevation happens after reboot via the monitor loop.

|### Fixed (2026-07-13 20:33:00 UTC)
|||||||||||||  - **Duplicate Administrator + SYSTEM processes (Chrome, etc.):** After reboot, the monitor loop successfully elevated new processes to SYSTEM, but existing Administrator instances of single-instance apps (Chrome, Edge, Firefox) remained alive. This produced duplicate processes — some running as SYSTEM and some as Administrator.
|||||||||||||  - New function `Stop-NonSystemInstances` scans all processes by name, checks ownership via WMI `GetOwner`, and force-kills every instance whose owner is **not** `SYSTEM`. This is called aggressively in two places:
|||||||||||||    1. `Monitor-ElevateProcess` — whenever a SYSTEM instance already exists, all non-SYSTEM duplicates are purged before returning. This prevents the new-process detector from leaving Administrator Chrome children alive.
|||||||||||||    2. After `Start-ProcessWithStolenToken` successfully spawns a SYSTEM instance, it waits 500ms then calls `Stop-NonSystemInstances` to purge any Administrator/user duplicates that existed before the elevation. This ensures the app is 100% SYSTEM-only immediately after elevation.
|||||||||||||  - The periodic existing-process elevation block (60-second) inside `Start-Monitoring` now also checks: if a SYSTEM instance exists, it calls `Stop-NonSystemInstances` instead of skipping. Previously it skipped when `Test-SystemProcessExists` returned `$true`, leaving Administrator duplicates untouched.
|||||||||||||  - **TrustedInstaller ruled out as token source:** The user asked about using `TrustedInstaller` as a token source. The diagnostic dump shows `TrustedInstaller` is PPL-protected (`CanOpen=True` but `CanQuery=False`), so `OpenProcessToken` is denied with `ERROR_ACCESS_DENIED`. Even if accessible, TrustedInstaller runs in Session 0 with a non-interactive token lacking `WinSta0\Default`, making it unsuitable for spawning visible desktop apps. The correct token sources remain `winlogon.exe` / `csrss.exe` SYSTEM tokens in Session 1.

|### Fixed (2026-07-13 20:41:00 UTC)
||||||||||||||  - **Error flood during menu option 7 (Administrator session):** When running `Invoke-ExistingProcessElevation` as Administrator (not SYSTEM), `Enable-ElevationPrivileges` was called for every single process, failed to enable `SeAssignPrimaryTokenPrivilege` (Win32 error 1300), and exported a full `ElevationDiagnostics` dump each time. This produced a wall of CRITICAL errors and diagnostic dumps for every single process.
||||||||||||||  - **Added root-cause mapping for Win32 error 1300 (`ERROR_NOT_ALL_ASSIGNED`):** Now correctly explains that this occurs when running as Administrator (filtered token) rather than SYSTEM, and that `SeAssignPrimaryTokenPrivilege` may be missing due to UAC token filtering.
||||||||||||||  - **Cached `Enable-ElevationPrivileges` warning:** Added `$script:__ElevPrivWarned` flag so the CRITICAL privilege-missing warning and diagnostic dump are emitted **only once per session**. Subsequent calls log a single INFO line instead of repeating the error.
||||||||||||||  - **`Invoke-ExistingProcessElevation` now exits early when not SYSTEM:** Added a guard at the top of the function that detects if the current user is not `SYSTEM` (via `[Environment]::UserName` and SID check). If not SYSTEM, it logs a clear one-line explanation and returns immediately. This prevents hundreds of failed token-steal attempts during menu option 7, eliminates the error flood, and makes the design explicit: existing apps stay at their current privilege level during menu 7; full elevation happens after reboot via the monitor loop running as SYSTEM.

|### Improved
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
