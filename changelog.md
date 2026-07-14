# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added (2026-07-14 01:23:00 UTC)
- **Auto-build C components in `Install-ProcessHook`.** When `gmproxy.exe` or `gmhook.dll` are missing in `driver\`, `Install-ProcessHook` (called by `Enable-GodMode` / option 7) now automatically runs `driver\build.ps1` via `pwsh` before installing. The full build output is captured to `$env:TEMP\GodMode_DriverBuild.log`. If the build fails, detailed error logs are written to both the main log and the debug log via `Write-DebugLog`. If the build succeeds but binaries are still missing, the function gracefully skips the IFEO proxy and DLL injection steps without crashing. This makes option 7 fully self-contained: press `[7]` and the C components compile, install, and activate automatically.
- **`Export-GodModeLogs` (option 11) now reports driver/hook status.** The log dump includes a new `===== DRIVER / HOOK STATUS =====` section that records: existence of source and installed binaries (`gmproxy.exe`, `gmhook.dll`), IFEO `Debugger` keys for all hooked apps (chrome, firefox, edge, notepad, cmd, powershell), `explorer.exe` running state, and the **full last driver build log** (`GodMode_DriverBuild.log`). Build errors and runtime failures are therefore captured by both the live debug log and the static dump file.
- **C/C++ syntax checker added to `syntax_check.ps1`.** The checker now scans all `.c` and `.h` files in the project tree using a stack-based parser that validates: matched braces `{}`, brackets `[]`, and parentheses `()`; unterminated string literals (`"..."`) and character literals (`'...'`); unterminated block comments (`/* ... */`); and unmatched preprocessor directives (`#if`/`#ifdef`/`#ifndef` vs `#endif`, plus `#else`/`#elif` balance). Errors are reported with `[C-...]` prefixed tags and counted in the final summary. The summary now shows `Total checked: N (PS: X, C: Y)` so both PowerShell and C coverage are visible.

### Changed (2026-07-13 21:58:00 UTC)
- **Replaced token-stealing elevation with service-based elevation.** The `CreateProcessWithTokenW` / `DuplicateTokenEx` token-stealing path (Method 1) has been removed entirely from `Invoke-AsSystem`. The primary elevation mechanism is now a temporary `sc.exe` service that runs as SYSTEM. This avoids the `SeAssignPrimaryTokenPrivilege` dependency that was failing on the user's machine (Win32 error 1008 / 1300).
- New `Start-ProcessWithService` helper: creates a demand-start `sc.exe` service, starts it, waits 2 seconds, stops and deletes it. This is used by `Monitor-ElevateProcess` and `Invoke-HybridElevation` to spawn individual processes as SYSTEM.
- `Invoke-ExistingProcessElevation` (SYSTEM branch) now batches all target processes into a **single** temporary service instead of spawning one service per process. It builds one batch file containing `start` commands for every process that needs elevation, then launches the batch via one `sc.exe` service. This is far more efficient and avoids service-name collisions.
- `explorer.exe` added to the `$CriticalProcs` list in `Invoke-ExistingProcessElevation` so it is never killed or restarted by the aggressive bulk elevation logic.

### Added (2026-07-13 22:17:00 UTC)
- **Menu option [15] IMPERSONATE SYSTEM TOKEN (Toggle).** Administrator can now attach a live SYSTEM token to the current thread via `SetThreadToken`, making the entire PowerShell session operate as SYSTEM without spawning a new process or rebooting.
  - `Enable-SystemImpersonation`: Finds a suitable SYSTEM process (e.g., `winlogon.exe`), opens its token, duplicates it as an impersonation token, and calls `SetThreadToken` on the current thread. Uses the existing `Find-SystemProcessCandidate` and `TokenOps` P/Invoke infrastructure. Does not require `SeAssignPrimaryTokenPrivilege` (which is missing in the user's filtered Administrator token); only requires `SeDebugPrivilege` and `SeImpersonatePrivilege`, both of which are already enabled.
  - `Disable-SystemImpersonation`: Reverts the thread token via `SetThreadToken(0, 0)` and closes the stored handle.
  - New `SetThreadToken` P/Invoke added to the `TokenOps` C# class.
  - Menu label dynamically shows `[15] IMPERSONATE SYSTEM TOKEN (Enable)` when inactive, or `[15] DISABLE SYSTEM IMPERSONATION (Active)` when active. Guarded by `Test-BuiltInAdmin` so only the built-in Administrator can use it.

### Added (2026-07-13 22:25:00 UTC)
- **Menu option [16] PERSISTENT SYSTEM IMPERSONATION (Toggle).** Automatically re-enables SYSTEM token impersonation on every new PowerShell window via a profile hook in `$PROFILE.CurrentUserAllHosts`, AND immediately launches system-wide God Mode elevation so all programs and services run as SYSTEM without waiting for a reboot.
  - `Install-PersistentSystemImpersonation`: Writes a self-contained profile hook (no external file dependencies) that bakes a lightweight `TokenOpsMini` C# class, enables `SeDebugPrivilege`/`SeImpersonatePrivilege`, finds a suitable SYSTEM process, and calls `SetThreadToken` on the current thread. The hook is idempotent — it skips installation if already present. After installing the hook, it immediately calls `Enable-GodMode` to start the system-wide monitor in the current session so all processes elevate immediately.
  - `Uninstall-PersistentSystemImpersonation`: Removes the profile hook by detecting `# <GODMODE_PERSISTENT_IMPERSONATION>` / `# </GODMODE_PERSISTENT_IMPERSONATION>` markers and removing the block. If the profile becomes empty, it deletes the file entirely.
  - `Test-PersistentSystemImpersonation`: Returns `$true` if the profile hook markers are present.
  - Menu label dynamically shows `[16] UNINSTALL PERSISTENT SYSTEM IMPERSONATION (Active)` when installed, or `[16] INSTALL PERSISTENT SYSTEM IMPERSONATION (System-Wide + All PowerShell sessions)` when not. Guarded by `Test-BuiltInAdmin`.
  - Prompt updated from `(1-15)` to `(1-16)`.

### Added (2026-07-13 22:43:00 UTC)
- **Menu option [17] SYSTEM DESKTOP SESSION (Toggle).** Makes the entire Windows desktop (Explorer, Start Menu, Taskbar, Desktop) run as SYSTEM at every logon by using `CreateProcessAsUser` with a stolen `winlogon.exe` SYSTEM token modified for Session 1.
  - New C# P/Invoke additions to `TokenOps`: `SetTokenInformation`, `CreateProcessAsUser`, `TokenSessionId` constant, and `CreateProcessAsSystem` helper method. `CreateProcessAsSystem` opens a SYSTEM process, duplicates its token to primary, explicitly sets `TokenSessionId` to 1, and calls `CreateProcessAsUser` to spawn `explorer.exe` on the interactive desktop (`WinSta0\Default`).
  - `Start-SystemDesktopExplorer`: Finds `winlogon.exe` in Session 1, enables `SeIncreaseQuotaPrivilege`, kills the existing user `explorer.exe`, and calls `CreateProcessAsSystem` to start a SYSTEM-owned `explorer.exe` in the user's desktop session.
  - `Install-SystemDesktopSession`: Registers a scheduled task `Windows-Session-Manager` triggered at both `AtStartup` and `AtLogOn`, running as `S-1-5-18` ServiceAccount. If the current process is not SYSTEM, it uses `Invoke-AsSystem` to immediately elevate and start the desktop session. After installation, `explorer` restarts as SYSTEM at every boot and logon.
  - `Uninstall-SystemDesktopSession`: Unregisters the `Windows-Session-Manager` scheduled task.
  - `Test-SystemDesktopSession`: Returns `$true` if the scheduled task exists.
  - Menu label dynamically shows `[17] UNINSTALL SYSTEM DESKTOP SESSION (Active)` when installed, or `[17] INSTALL SYSTEM DESKTOP SESSION (Run Explorer as SYSTEM)` when not. Guarded by `Test-BuiltInAdmin`.
  - New CLI flag `-SystemDesktop` triggers `Start-SystemDesktopExplorer` directly for non-interactive use.
  - New CLI flags `-InstallSystemDesktop` and `-UninstallSystemDesktop` for non-interactive system desktop session installation/removal.
  - Prompt updated from `(1-16)` to `(1-17)`.

### Changed (2026-07-13 22:45:00 UTC)
- **Removed buggy `Invoke-AsSystem` wrappers from menu options [6], [7], [8], [17].** These wrappers were copied from the CLI handler approach but caused a 3-minute hang because `Invoke-AsSystem` waits for a result file from a child process that calls `Enable-GodMode` -> `Start-Monitoring` (infinite loop). The parent process would sit waiting for a result file that never appeared.
  - Menu options [6], [7], [8], [17] now call their respective functions directly (same as the original code). The functions themselves handle SYSTEM elevation internally where needed, using fire-and-forget `Start-ProcessWithService` for background elevation rather than blocking `Invoke-AsSystem`.
- **Replaced `Invoke-AsSystem` with `Start-ProcessWithService` in `Invoke-ExistingProcessElevation`.** The old `Invoke-ExistingProcessElevation` would call `Invoke-AsSystem` to relaunch the entire script as SYSTEM, which hung because the child process ran `Start-Monitoring` (infinite loop). Now it uses `Start-ProcessWithService` (fire-and-forget) to spawn the script as SYSTEM, waits only 3 seconds to confirm the service started, and immediately returns with a success message. The SYSTEM-elevated process runs in the background without blocking the parent.
- **CLI flags `-InstallSystemDesktop` and `-UninstallSystemDesktop` preserved.** These flags allow non-interactive installation/removal of the SYSTEM desktop session when the script is already running as SYSTEM (e.g., via `psexec -s` or a SYSTEM shell).

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

||### Changed (2026-07-13 23:16:00 UTC)
||- **Rewrote `Invoke-ExistingProcessElevation` for direct Session 1 SYSTEM elevation.** When running as SYSTEM, the function now uses `CreateProcessAsSystem` with a stolen `winlogon.exe` token to launch each elevated process directly into Session 1 (`WinSta0\Default`). This replaces the old batch-file approach that created processes in Session 0, making them invisible to the user desktop.
||- **Administrator branch of `Invoke-ExistingProcessElevation` switched from `Start-ProcessWithService` to scheduled task.** The old `sc.exe` service approach was unreliable because the service was killed after only 2 seconds, often before the PowerShell script could finish enumerating processes. The new approach registers a temporary scheduled task as `S-1-5-18` with `RunLevel Highest`, starts it immediately, and **waits synchronously for the task to finish** (up to 120 seconds) before returning to the menu. This ensures that when the menu comes back, Chrome and other processes are already running as SYSTEM, not still Administrator.
||- **`Monitor-ElevateProcess` now uses `CreateProcessAsSystem` when running as SYSTEM.** When the monitoring loop is running in a SYSTEM context, it bypasses `Start-ProcessWithService` (which creates Session 0 processes) and instead uses `CreateProcessAsSystem` to launch new processes directly in Session 1.
||- **`Invoke-HybridElevation` now attempts `CreateProcessAsSystem` first when running as SYSTEM.** Phase 0 is a direct `CreateProcessAsSystem` call before falling back to `Start-ProcessWithService` (Phase 1) and scheduled task (Phase 2).
||- **`Start-ProcessWithService` service lifetime fixed.** Instead of a hard-coded 2-second `Start-Sleep`, the function now polls `sc.exe query` every 500ms until the service reports `STOPPED`, with a 30-second timeout. This ensures the service stays alive long enough for the batch file to complete its `start` commands.
|- **Monitoring loop speed increased.** Main loop sleep reduced from 2 seconds to 500ms, new process detection window reduced from 10 seconds to 5 seconds, and periodic existing-process elevation interval reduced from 60 seconds to 15 seconds. This catches newly launched applications much faster.
|  |- **PID cleanup interval reduced from 5 minutes to 2 minutes** to keep the tracking dictionary smaller and more responsive.

|||### Added (2026-07-14 00:20:00 UTC)
||- **SYSTEM watchdog relauncher (`Register-SystemWatchdog`).** A dedicated watchdog task (`Windows-Defender-Engine-Update`) runs every 30 seconds as SYSTEM, checking if the stealth monitoring task is alive. If the monitor is killed or crashes, the watchdog immediately relaunches it as SYSTEM. The watchdog itself has aggressive restart settings (99 restarts, 1-minute intervals) so it survives being killed too. A companion `.ps1` watchdog script is written to the hardened install directory and dynamically recreates the stealth task if it is missing entirely.
||- **Task Manager kill-block (`Block-TaskManager`).** Uses two simultaneous mechanisms to prevent Task Manager from launching:
|  1. **IFEO Debugger redirect** — `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe` is set with a `Debugger` value pointing to a non-existent executable (`C:\Windows\System32\notaskmgr.exe`), causing Task Manager to silently fail on launch.
|  2. **Registry policy disable** — `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr` is set to `1`.
|  3. **IFEO registry key hardening** — The `taskmgr.exe` IFEO key ACLs are hardened to SYSTEM FullControl and Admins ReadKey-only, preventing tampering.
|  Both `Block-TaskManager` and `Unblock-TaskManager` are wired into `Enable-GodMode` and `Disable-GodMode` respectively, so Task Manager is automatically blocked when God Mode is enabled and restored when disabled.
||- **Stealth task restart-on-kill.** `Register-StealthTask` now passes `New-ScheduledTaskSettingsSet` with `-RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1)` to the monitoring task itself. If the stealth task is killed or crashes, Task Scheduler automatically relaunches it as SYSTEM within 1 minute, independent of the watchdog heartbeat.
||- **Status display for watchdog and Task Manager block.** `Show-GodModeStatus` now shows:
|  - `Watchdog` — installed/running state of the `Windows-Defender-Engine-Update` task.
|  - `Task Manager` — `BLOCKED` (red) if IFEO Debugger or `DisableTaskMgr` policy is active, or `UNBLOCKED` (green) otherwise.

|||---
|- **`NtSetInformationProcess` token replacement (experimental).** Added `NtSetInformationProcess` P/Invoke from `ntdll.dll` to `TokenOps`, along with a `PROCESS_ACCESS_TOKEN` structure and a `ReplaceProcessToken` helper method. This allows in-place replacement of the current process token with a stolen SYSTEM token via `ProcessAccessToken` (0x09). A new PowerShell function `Invoke-ProcessTokenReplacement` wraps this method and is available for manual use. This is an undocumented API and may cause instability; it is provided as an additional elevation method to increase success chances.

||### Improved
||- Project structure reorganized with `tests/` folder for regression scripts.

|||### Added (2026-07-13 23:51:00 UTC)
||||- **Parallel hyperthreaded elevation (`Invoke-ParallelElevation`).** Added a new `Invoke-ParallelElevation` helper that distributes process elevation across dynamically-detected concurrent `Start-ThreadJob` threads (PowerShell 7). The thread count is determined at runtime by the actual CPU logical processor count, not a hardcoded value. This replaces the old sequential `foreach` loop in `Invoke-ExistingProcessElevation` (menu option 7) and dramatically reduces the time needed to elevate all running user processes to SYSTEM.
||  - Each worker thread performs the full "detect first, then set" cycle per process: checks if a SYSTEM instance already exists via WMI `GetOwner`, skips if already SYSTEM, kills all non-SYSTEM instances of the same process name, extracts the original command-line arguments, and calls `TokenOps::CreateProcessAsSystem` to launch the process directly into Session 1 (`WinSta0\Default`).
||  - Automatic fallback to sequential execution when `Start-ThreadJob` is unavailable (PowerShell 5.1), so the script remains compatible with older environments.
|||  - **Monitoring loop periodic scan also parallelized.** The 15-second periodic re-elevation block inside `Start-Monitoring` now builds a "due list" of processes that need elevation, then delegates the elevation work to `Invoke-ParallelElevation` with dynamically-detected threads instead of looping sequentially. This prevents the monitor loop from spending seconds per process and missing newly launched applications.
||- **Deduplication before parallel elevation.** `Invoke-ExistingProcessElevation` now deduplicates the target process list by executable name before spawning threads, so only one elevation attempt per unique process is launched. This avoids race conditions where multiple threads might try to elevate the same app simultaneously.
||- **Removed per-process `Start-Sleep -Milliseconds 300` bottleneck.** The old sequential loop paused 300ms between each process; the parallel path removes all sleeps, with threads running concurrently.
||- **Parallel process ownership scan (`Get-NonSystemProcessesParallel`).** The ownership scan inside `Invoke-ExistingProcessElevation` was the last sequential bottleneck. The new `Get-NonSystemProcessesParallel` helper:
||  - Fast-filters by PID, path, and critical name (no WMI calls).
||  - Splits remaining candidates into PID chunks of 25.
|||  - Launches dynamically-detected `Start-ThreadJob` threads (one per CPU logical processor), each querying its batch via `Get-CimInstance -Filter "ProcessId=... OR ProcessId=..."` and checking `GetOwner` per process.
||  - Collects all non-SYSTEM PIDs, maps them back to the original CIM instances, and returns the deduplicated target list.
||  - Sequential fallback with CIM/WMI compatibility for environments without `ThreadJob`.
|||  - This eliminates the 200+ sequential `GetOwner` WMI calls that were the slowest part of menu option 7.
||||- **Dynamic CPU thread detection (`Get-OptimalThreadCount`).** All hardcoded thread counts (8, 4) removed. New `Get-OptimalThreadCount` helper detects the actual logical processor count at runtime via `[System.Environment]::ProcessorCount` (cross-platform, works in PS 7 and PS 5.1 on .NET 4.6+), with fallback to `$env:NUMBER_OF_PROCESSORS` and ultimate fallback to 4.
|||||  - `Invoke-ParallelElevation` default `MaxThreads` now uses `Get-OptimalThreadCount`.
|||||  - `Get-NonSystemProcessesParallel` default `MaxThreads` now uses `Get-OptimalThreadCount`; `ChunkSize` is dynamically calculated as `max(10, ceil(50 / CPU count))` so smaller machines get larger batches and larger machines get smaller batches for better parallelism.
|||||  - `Invoke-ExistingProcessElevation` log message now reports the actual detected CPU count and the number of threads being spawned.
|||||  - Monitoring loop periodic elevation also inherits the dynamic thread count instead of the hardcoded 4.

|---
||---

||||### Added (2026-07-14 00:50:00 UTC)
||||- **Event-driven process creation watcher (`Register-ProcessCreationWatcher`).** Replaces the expensive 500ms `Get-CimInstance Win32_Process` polling in `Start-Monitoring` with a lightweight WMI `__InstanceCreationEvent` watcher. New processes are detected in near real time and pushed into a synchronized queue (`$script:ProcessCreationQueue`), which the monitor loop drains at the top of every iteration. This eliminates the ~100-200ms CIM query overhead per loop and catches new processes immediately instead of only every 5-second window.
||||  - `Register-ProcessCreationWatcher` — creates a `ManagementEventWatcher` with `WITHIN 5` polling on `Win32_Process` creation events, filters for user-session (`SessionId > 0`) and `.exe` executables, and parses command-line arguments into the queue.
||||  - `Unregister-ProcessCreationWatcher` — stops and disposes the watcher, clears the queue, and sets `$script:ProcessCreationWatcherActive = $false`.
||||  - Watcher is auto-registered by `Enable-GodMode` and unregistered by `Disable-GodMode`.
||||  - If the watcher fails to register (e.g., WMI unavailable), the monitor loop falls back transparently to the original `Get-CimInstance` polling path.
||||- **SYSTEM PID cache (`Find-SystemProcessCandidate`).** Caches the first successfully validated SYSTEM PID and reuses it for up to 60 seconds, avoiding repeated WMI `GetOwner` + `OpenProcess` token-test scans on every elevation call. The cache is invalidated automatically after the timeout or when the cached process exits.
||||  - Cache write occurs on both the Session 1 priority path and the fallback path, so whichever succeeds first becomes the cached source.
||||- **Conditional polling in `Start-Monitoring`.** When the event watcher is active, the monitor loop skips the `Get-CimInstance` new-process query entirely and trusts the queue. This removes the last remaining per-loop CIM overhead when the watcher is healthy.
||||- **Guard elevation blocks in `Start-Monitoring` when running as Administrator.** Previously the periodic existing-process elevation block and the new-process CIM polling block ran unconditionally, calling `Enable-ElevationPrivileges` which failed to enable `SeAssignPrimaryTokenPrivilege` in a filtered Administrator token and auto-generated a full `ElevationDiagnostics` dump every 15 seconds, flooding the log. Added a `$isSystem` guard at the top of the loop; if the monitor is not SYSTEM, it logs a one-line warning and skips all elevation blocks while keeping the resurrection-killer and stealth-mode active. `Invoke-ExistingProcessElevation` already exits early when not SYSTEM, so the startup call is unaffected.
|
|||||-

|||||### Added (2026-07-14 01:13:00 UTC)
|||||- **In-place token replacement via `NtSetInformationProcess`.** Added `ReplaceProcessTokenForPid` to the `TokenOps` C# class. Opens the target process with `PROCESS_SET_INFORMATION`, steals a SYSTEM token from a source process, and calls `NtSetInformationProcess` with `ProcessAccessToken (0x09)` to replace the target's token in-place without killing it. This is the Phase 0 elevation path inside `Monitor-ElevateProcess`.
|||||  - `Monitor-ElevateProcess` now accepts an optional `ProcessId` parameter. When a new process is detected via the event watcher (or CIM polling), Phase 0 attempts `ReplaceProcessTokenForPid` on the existing PID first. If the replacement succeeds, the process is already running as SYSTEM with no visible flicker or restart.
|||||  - If Phase 0 fails (e.g., PPL-protected target, access denied), the function falls back to Phase 1 (kill-relaunch via `CreateProcessAsSystem`) and Phase 2 (scheduled-task fallback).
|||||  - Task Manager is now **unblocked** (IFEO Debugger redirect removed) so it can open normally; the watcher then elevates it to SYSTEM in-place via Phase 0 instead of blocking it entirely.
|||||- **C IFEO proxy (`gmproxy.exe`).** New Win32 executable `driver/gmproxy.c` intercepts process launches via the Image File Execution Options `Debugger` key. It steals a SYSTEM token from a running process via `Toolhelp32Snapshot`, duplicates it to a primary token, and calls `CreateProcessWithTokenW` or `CreateProcessAsUserW` to launch the intercepted application as SYSTEM on the `WinSta0\Default` desktop. The original command line is passed through as arguments so the user sees the intended application. This avoids the kill-relaunch cycle entirely for hooked apps.
|||||- **C shell hook DLL (`gmhook.dll`).** New DLL `driver/gmhook.c` injects into `explorer.exe` and hooks `CreateProcessW` via a 5-byte inline JMP. Every time a hooked process is created, the DLL:
|||||  1. Creates the process `CREATE_SUSPENDED`.
|||||  2. Replaces the new process token via `NtSetInformationProcess(ProcessAccessToken, 0x09)` with a stolen SYSTEM token.
|||||  3. Resumes the process.
|||||  Critical OS processes (e.g., `svchost.exe`, `lsass.exe`, `csrss.exe`, `smss.exe`, `services.exe`, `wininit.exe`, `conhost.exe`, `SearchIndexer.exe`, `fontdrvhost.exe`, `dwm.exe`, `winlogon.exe`) are filtered out so only user-facing applications are elevated.
|||||- **PowerShell build script (`driver/build.ps1`).** Auto-detects MSVC (`cl.exe`) or MinGW (`x86_64-w64-mingw32-gcc` / `gcc`) and compiles both `gmproxy.exe` and `gmhook.dll`. Exits with a clear error if no compiler is found.
|||||- **PowerShell installer functions (`Install-ProcessHook`, `Uninstall-ProcessHook`).**
|||||  - `Install-ProcessHook` copies `gmproxy.exe` and `gmhook.dll` into the hardened install directory (`C:\ProgramData\GodMode`), registers IFEO `Debugger` keys for a curated set of user apps (`chrome.exe`, `firefox.exe`, `msedge.exe`, `notepad.exe`, `cmd.exe`, `powershell.exe`), and injects `gmhook.dll` into `explorer.exe` via a lightweight `CreateRemoteThread` + `LoadLibraryW` injector written in inline C# (`GmInjector`). Logs success/failure for each step.
|||||  - `Uninstall-ProcessHook` removes all IFEO `Debugger` keys for the curated app list, deletes the copied binaries from the install directory, and logs completion.
|||||- **Wired into God Mode lifecycle.** `Enable-GodMode` calls `Install-ProcessHook` after `Block-TaskManager`. `Disable-GodMode` calls `Uninstall-ProcessHook` after `Unblock-TaskManager`. `Show-GodModeStatus` displays `Process Hook` status as `INSTALLED (IFEO + DLL)`, `PARTIAL`, or `NOT INSTALLED`.
|||||- **Event watcher speedup.** `Register-ProcessCreationWatcher` polling interval reduced from `WITHIN 5` to `WITHIN 1` for faster detection of new processes.
|||||---
|
|### Fixed
- See "Fixed" section under Unreleased for detailed bug fixes applied during this build.

---

## 2026-07-09 19:00:00 UTC — Initial review

### Notes
- Reviewed `God_mode.ps1` (Enterprise DNS Hijack Protection & Installer Suite).
- Identified existing features: IPv4/IPv6 registry ACL locks, browser DoH GPO restrictions, NTFS self-defense, scheduled task persistence, WMI subscription persistence, integrity checking, interactive menu.
- Identified missing: regression test suite, explicit SYSTEM shell tool, consolidated changelog.

---
