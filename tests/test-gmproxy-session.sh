#!/usr/bin/env bash
# test-gmproxy-session.sh -- prove driver/gmproxy.c still BUILDS after the
# session-correctness + graceful-fallback fix, and that the key invariants are
# present in source.
#
# The source-level pwsh test (Test-GmProxySession.ps1) checks the invariants are
# written down; THIS test proves the new C (dynamic wtsapi32 load of
# WTSGetActiveConsoleSessionId, ProcessIdToSessionId session filter, StealSystemToken,
# CreateProcessW graceful fallback) actually COMPILES with the MinGW cross-compiler
# and produces a valid PE binary. A regression that breaks the build (undeclared
# symbol, wrong typedef, missing prototype) is caught here before deploying to the VM.
#
# Prints a FAIL SUMMARY (N) block and exits 1 on any failure, 0 if all pass.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$SCRIPT_DIR/.." && pwd)/driver/gmproxy.c"
GMHOOK_SRC="$(cd "$SCRIPT_DIR/.." && pwd)/driver/gmhook.c"

pass_count=0
fail_count=0
fail_names=()

record() {  # record <name> <0|1> [detail]
    local name="$1" ok="$2" detail="${3:-}"
    if [ "$ok" = "1" ]; then
        pass_count=$((pass_count + 1))
        printf '  [PASS] %s\n' "$name"
    else
        fail_count=$((fail_count + 1))
        fail_names+=("$name")
        printf '  [FAIL] %s : %s\n' "$name" "$detail"
    fi
}

printf '=====================================================\n'
printf '  gmproxy.c session-fix BUILD + invariant test\n'
printf '=====================================================\n'

if [ ! -f "$SRC" ]; then
    record "gmproxy.c present" 0 "missing: $SRC"
    printf '\n  FAIL SUMMARY (%s)\n    - gmproxy.c present\n' "$fail_count"
    exit 1
fi
record "gmproxy.c present" 1

# Source invariant greps (the fix must be present in source before we trust a build).
grep -q 'GetActiveConsoleSessionId' "$SRC" && record "src: GetActiveConsoleSessionId present" 1 || record "src: GetActiveConsoleSessionId present" 0 "not found"
grep -q 'ProcessIdToSessionId' "$SRC" && record "src: ProcessIdToSessionId present" 1 || record "src: ProcessIdToSessionId present" 0 "not found"
grep -q 'SeTcbPrivilege' "$SRC" && record "src: SeTcbPrivilege present" 1 || record "src: SeTcbPrivilege present" 0 "not found"
grep -q 'FindAnySystemProcessPid' "$SRC" && record "src: FindAnySystemProcessPid present" 1 || record "src: FindAnySystemProcessPid present" 0 "not found"
grep -q 'haveToken' "$SRC" && record "src: haveToken gate present" 1 || record "src: haveToken gate present" 0 "not found"
grep -q 'CreateProcessW(hardlinkPath' "$SRC" && record "src: graceful fallback CreateProcessW(hardlinkPath) present" 1 || record "src: graceful fallback CreateProcessW(hardlinkPath) present" 0 "not found"
grep -q 'DiagLog' "$SRC" && record "src: DiagLog helper present" 1 || record "src: DiagLog helper present" 0 "not found"
grep -q 'GmProxyDiagLogOpen' "$SRC" && record "src: GmProxyDiagLogOpen present" 1 || record "src: GmProxyDiagLogOpen present" 0 "not found"
grep -q 'gmproxy.log' "$SRC" && record "src: durable gmproxy.log path present" 1 || record "src: durable gmproxy.log path present" 0 "not found"
grep -q 'SignalGmProxyFeedback' "$SRC" && record "src: SignalGmProxyFeedback present" 1 || record "src: SignalGmProxyFeedback present" 0 "not found"
grep -q 'GodMode-GmProxyFeedback' "$SRC" && record "src: feedback pipe name present" 1 || record "src: feedback pipe name present" 0 "not found"
grep -q 'OPEN_EXISTING' "$SRC" && record "src: feedback pipe non-blocking OPEN_EXISTING present" 1 || record "src: feedback pipe non-blocking OPEN_EXISTING present" 0 "not found"

# Build-version stamp invariants (baked in via __DATE__/__TIME__, changes every
# recompile; surfaced in Export-GodModeLogs option [11] so a stale vs. freshly
# rebuilt gmproxy.exe is identifiable at a glance).
grep -qF '__DATE__' "$SRC" && record "src: __DATE__ build-stamp present" 1 || record "src: __DATE__ build-stamp present" 0 "not found"
grep -qF '__TIME__' "$SRC" && record "src: __TIME__ build-stamp present" 1 || record "src: __TIME__ build-stamp present" 0 "not found"
grep -qF 'GmWidenAscii' "$SRC" && record "src: GmWidenAscii helper present" 1 || record "src: GmWidenAscii helper present" 0 "not found"
grep -qF '[GM-PROXY] BUILD' "$SRC" && record "src: [GM-PROXY] BUILD stamp present" 1 || record "src: [GM-PROXY] BUILD stamp present" 0 "not found"

# Ownerless-birth REFUSE + compile-time test seam (wine runtime proof in
# test-gmproxy-refuse.sh). The seam lets the REFUSE branch be exercised under
# wine (which does not model Session 0); the PRODUCTION build must NOT define it.
grep -qF '#ifdef GMPROXY_TEST_FORCE_SESSION0' "$SRC" && record "src: GMPROXY_TEST_FORCE_SESSION0 compile-time seam present (#ifdef, wine REFUSE runtime proof)" 1 || record "src: GMPROXY_TEST_FORCE_SESSION0 compile-time seam present (#ifdef, wine REFUSE runtime proof)" 0 "not found -- ownerless-birth REFUSE cannot be exercised under wine"
grep -qF 'mySessionIsZero' "$SRC" && record "src: mySessionIsZero ownerless-birth guard present" 1 || record "src: mySessionIsZero ownerless-birth guard present" 0 "not found"
grep -qF '[GM-PROXY] REFUSE' "$SRC" && record "src: [GM-PROXY] REFUSE ownerless-birth refusal diag present" 1 || record "src: [GM-PROXY] REFUSE ownerless-birth refusal diag present" 0 "not found"
BUILD_PS1="$(cd "$SCRIPT_DIR/.." && pwd)/driver/build.ps1"
if [ -f "$BUILD_PS1" ] && grep -qF 'GMPROXY_TEST_FORCE_SESSION0' "$BUILD_PS1"; then
    record "build.ps1 does NOT define the test seam (production binary unaffected)" 0 "driver/build.ps1 references GMPROXY_TEST_FORCE_SESSION0 -- production build would force-refuse in the field"
elif [ -f "$BUILD_PS1" ]; then
    record "build.ps1 does NOT define the test seam (production binary unaffected)" 1
else
    record "build.ps1 does NOT define the test seam (production binary unaffected)" 0 "driver/build.ps1 missing"
fi

# GetTempPathW trailing-backslash hardening: wine smoke tests can return a temp
# path WITHOUT a trailing '\', which would concatenate tempDir+filename
# (Cgmhook.log artifact). GmEnsureTrailingBackslash normalizes it.
grep -qF 'GmEnsureTrailingBackslash' "$SRC" && record "src: GmEnsureTrailingBackslash trailing-backslash hardening present" 1 || record "src: GmEnsureTrailingBackslash trailing-backslash hardening present" 0 "not found"

# Wide-format %ls fix: MinGW's wide swprintf %s truncates a wchar_t* arg to its
# first character (reads it as narrow, stops at the 0x00 high byte), which was the
# REAL root cause of the Cgmhook.log/Cgmproxy.log wine artifact + garbled stamps.
# %ls (wide) is consistent across MSVC and MinGW.
grep -qF '%lsgmproxy.log' "$SRC" && record "src: %ls wide-format log path present (MinGW %s truncation fix)" 1 || record "src: %ls wide-format log path present (MinGW %s truncation fix)" 0 "not found"

# Layer 1 (token-consistent env block) + Layer 2 (browser launch flags) fix:
# gmproxy now builds the SYSTEM child's env from the stolen token via
# CreateEnvironmentBlock (so USERPROFILE/APPDATA point at systemprofile, not
# the invoking user's AppData -> no profile-lock conflict / sandbox failure),
# and injects --no-sandbox (Chromium/Electron) / -no-remote (Firefox) so the
# SYSTEM child renders and doesn't IPC-exit. userenv is linked for the env API.
grep -qF 'userenv.h' "$SRC" && record "src: #include <userenv.h> present (Layer 1 env block)" 1 || record "src: #include <userenv.h> present (Layer 1 env block)" 0 "not found -- CreateEnvironmentBlock undeclared"
grep -qF 'CreateEnvironmentBlock' "$SRC" && record "src: CreateEnvironmentBlock present (token-consistent env)" 1 || record "src: CreateEnvironmentBlock present (token-consistent env)" 0 "not found -- SYSTEM child inherits user APPDATA"
grep -qF 'DestroyEnvironmentBlock' "$SRC" && record "src: DestroyEnvironmentBlock present (env block freed)" 1 || record "src: DestroyEnvironmentBlock present (env block freed)" 0 "not found -- env block leak"
grep -qF 'GmProxyLaunchFlagForTarget' "$SRC" && record "src: GmProxyLaunchFlagForTarget helper present (Layer 2 flag injection)" 1 || record "src: GmProxyLaunchFlagForTarget helper present (Layer 2 flag injection)" 0 "not found"
grep -qF -- '--no-sandbox' "$SRC" && record "src: --no-sandbox flag present (Chromium/Electron render under SYSTEM)" 1 || record "src: --no-sandbox flag present (Chromium/Electron render under SYSTEM)" 0 "not found"
grep -qF -- '-no-remote' "$SRC" && record "src: -no-remote flag present (Firefox no IPC-exit)" 1 || record "src: -no-remote flag present (Firefox no IPC-exit)" 0 "not found"
grep -qF 'envBlock' "$SRC" && record "src: envBlock variable present (passed to token launch sites)" 1 || record "src: envBlock variable present (passed to token launch sites)" 0 "not found"

# Per-app launch telemetry (big debug): gmproxy emits structured [GM-PROXY]
# LAUNCH: / [GM-PROXY] CHILD-STATUS: lines per invocation so Export-GodModeLogs
# (option [11]) can aggregate a PER-APP LAUNCH REPORT (which apps launched as
# SYSTEM vs fell back vs refused vs failed, and which EXITED within the grace
# window = the "launched but instantly died / won't render" crash signal). The
# MinGW build below must still compile with this new code.
grep -qF 'GmProxyLogLaunchReport' "$SRC" && record "src: GmProxyLogLaunchReport per-app telemetry helper present" 1 || record "src: GmProxyLogLaunchReport per-app telemetry helper present" 0 "not found"
grep -qF '[GM-PROXY] LAUNCH:' "$SRC" && record "src: [GM-PROXY] LAUNCH: structured telemetry line present" 1 || record "src: [GM-PROXY] LAUNCH: structured telemetry line present" 0 "not found"
grep -qF '[GM-PROXY] CHILD-STATUS:' "$SRC" && record "src: [GM-PROXY] CHILD-STATUS: child-survival observation line present" 1 || record "src: [GM-PROXY] CHILD-STATUS: child-survival observation line present" 0 "not found"
grep -qF 'WaitForSingleObject' "$SRC" && record "src: WaitForSingleObject child-survival wait present" 1 || record "src: WaitForSingleObject child-survival wait present" 0 "not found"

# Grandchild-tree Job observation + elevation-context logging (root-cause debug):
# gmproxy now creates the child CREATE_SUSPENDED, assigns it to a Job Object
# (BREAKAWAY_OK, NO KILL_ON_JOB_CLOSE so the user's real app is never killed),
# resumes it, and walks the job tree after the wait to classify a launcher/stub
# that DELEGATED to a surviving grandchild (NOT a failure) vs a genuine EXIT
# (class=CLEAN exitcode 0 = graceful refusal as SYSTEM / class=CRASH non-zero).
# Elevation-context logging (ELEVATE/TOKEN/CMDLINE/ENV + per-attempt CREATEPROC
# result=OK/FAIL gle) catches the ELEVATION-side root cause. The MinGW build
# below must still compile with all this new code.
grep -qF 'sddl.h' "$SRC" && record "src: #include <sddl.h> present (ConvertSidToStringSidW token SID logging)" 1 || record "src: #include <sddl.h> present (ConvertSidToStringSidW token SID logging)" 0 "not found"
grep -qF 'GmProxyImageNameForPid' "$SRC" && record "src: GmProxyImageNameForPid helper present (resolve a PID's image base name)" 1 || record "src: GmProxyImageNameForPid helper present (resolve a PID's image base name)" 0 "not found"
grep -qF 'QueryFullProcessImageNameW' "$SRC" && record "src: QueryFullProcessImageNameW dynamic load present" 1 || record "src: QueryFullProcessImageNameW dynamic load present" 0 "not found"
grep -qF 'GmProxyEnumerateJobTree' "$SRC" && record "src: GmProxyEnumerateJobTree helper present (walk the job process list)" 1 || record "src: GmProxyEnumerateJobTree helper present (walk the job process list)" 0 "not found"
grep -qF 'JobObjectBasicProcessIdList' "$SRC" && record "src: JobObjectBasicProcessIdList query present (job tree enumeration)" 1 || record "src: JobObjectBasicProcessIdList query present (job tree enumeration)" 0 "not found"
grep -qF 'GmProxyLogElevationContext' "$SRC" && record "src: GmProxyLogElevationContext helper present (token/cmdline/env context log)" 1 || record "src: GmProxyLogElevationContext helper present (token/cmdline/env context log)" 0 "not found"
grep -qF 'ConvertSidToStringSidW' "$SRC" && record "src: ConvertSidToStringSidW present (token SID -> S-1-5-18 confirm)" 1 || record "src: ConvertSidToStringSidW present (token SID -> S-1-5-18 confirm)" 0 "not found"
grep -qF '[GM-PROXY] ELEVATE:' "$SRC" && record "src: [GM-PROXY] ELEVATE: token-source context line present" 1 || record "src: [GM-PROXY] ELEVATE: token-source context line present" 0 "not found"
grep -qF '[GM-PROXY] TOKEN:' "$SRC" && record "src: [GM-PROXY] TOKEN: sid/type/elevated/session context line present" 1 || record "src: [GM-PROXY] TOKEN: sid/type/elevated/session context line present" 0 "not found"
grep -qF '[GM-PROXY] CMDLINE:' "$SRC" && record "src: [GM-PROXY] CMDLINE: rebuilt command line context line present" 1 || record "src: [GM-PROXY] CMDLINE: rebuilt command line context line present" 0 "not found"
grep -qF '[GM-PROXY] ENV:' "$SRC" && record "src: [GM-PROXY] ENV: env-block state+bytes context line present" 1 || record "src: [GM-PROXY] ENV: env-block state+bytes context line present" 0 "not found"
grep -qF '[GM-PROXY] CREATEPROC:' "$SRC" && record "src: [GM-PROXY] CREATEPROC: per-attempt outcome line present (method/result/gle)" 1 || record "src: [GM-PROXY] CREATEPROC: per-attempt outcome line present (method/result/gle)" 0 "not found"
grep -qF 'CREATE_SUSPENDED' "$SRC" && record "src: CREATE_SUSPENDED present (child suspended before job assign)" 1 || record "src: CREATE_SUSPENDED present (child suspended before job assign)" 0 "not found"
grep -qF 'CreateJobObjectW' "$SRC" && record "src: CreateJobObjectW present (observational job)" 1 || record "src: CreateJobObjectW present (observational job)" 0 "not found"
grep -qF 'AssignProcessToJobObject' "$SRC" && record "src: AssignProcessToJobObject present (child -> job)" 1 || record "src: AssignProcessToJobObject present (child -> job)" 0 "not found"
grep -qF 'JOB_OBJECT_LIMIT_BREAKAWAY_OK' "$SRC" && record "src: JOB_OBJECT_LIMIT_BREAKAWAY_OK present (no breakaway failure)" 1 || record "src: JOB_OBJECT_LIMIT_BREAKAWAY_OK present (no breakaway failure)" 0 "not found"
grep -qF 'ResumeThread' "$SRC" && record "src: ResumeThread present (resume suspended child after job assign)" 1 || record "src: ResumeThread present (resume suspended child after job assign)" 0 "not found"
grep -qF 'result=DELEGATED' "$SRC" && record "src: result=DELEGATED classification present (launcher/stub -> grandchild)" 1 || record "src: result=DELEGATED classification present (launcher/stub -> grandchild)" 0 "not found"
grep -qF 'class=%ls' "$SRC" && record "src: class=CLEAN/CRASH classification present (exit-code class)" 1 || record "src: class=CLEAN/CRASH classification present (exit-code class)" 0 "not found"
grep -qF 'L"CLEAN"' "$SRC" && record "src: L\"CLEAN\" literal present (exitcode 0 = graceful)" 1 || record "src: L\"CLEAN\" literal present (exitcode 0 = graceful)" 0 "not found"
grep -qF 'L"CRASH"' "$SRC" && record "src: L\"CRASH\" literal present (exitcode != 0 = crash)" 1 || record "src: L\"CRASH\" literal present (exitcode != 0 = crash)" 0 "not found"

# IFEO re-entry recur tag (root-cause debug): a launcher/stub child that spawns an
# IFEO-hooked image births a NESTED gmproxy.exe as the grandchild (recur=yes), not the
# real app. recur=no = genuine delegation. The MinGW build below must still compile
# with this new code.
grep -qF 'recur=%ls' "$SRC" && record "src: recur=%ls tag present on DELEGATED line (IFEO re-entry detection)" 1 || record "src: recur=%ls tag present on DELEGATED line (IFEO re-entry detection)" 0 "not found"
grep -qF '_wcsicmp(firstImg, L"gmproxy.exe")' "$SRC" && record "src: recur detects survivor is gmproxy.exe (exact base-name match)" 1 || record "src: recur detects survivor is gmproxy.exe (exact base-name match)" 0 "not found"

# Concurrent gmproxy.log write serialization (root-cause debug): concurrent gmproxy.exe instances
# (GoogleUpdater spawning many updater.exe at once as SYSTEM) all write the SAME gmproxy.log via
# _wfopen append + vfwprintf + fflush; the C runtime append mode is seek-then-write, which races
# across processes and interleaves PARTIAL lines (the 'dater.exe' / 'YSTEM session=...' garbage in
# the SYSTEM-temp log). A Global named mutex (NULL DACL so admin + SYSTEM both open it; bounded
# 2000ms wait; WAIT_ABANDONED tolerated) serializes each write so every line lands atomically at
# the true end-of-file. The MinGW build below must still compile with this new code.
grep -qF 'GmProxyDiagMutexAcquire' "$SRC" && record "src: GmProxyDiagMutexAcquire helper present (cross-process log serializer)" 1 || record "src: GmProxyDiagMutexAcquire helper present (cross-process log serializer)" 0 "not found"
grep -qF 'GmProxyDiagMutexRelease' "$SRC" && record "src: GmProxyDiagMutexRelease helper present" 1 || record "src: GmProxyDiagMutexRelease helper present" 0 "not found"
grep -qF 'GmProxyDiagLogMutex' "$SRC" && record "src: Global GmProxyDiagLogMutex name present (shared admin + SYSTEM)" 1 || record "src: Global GmProxyDiagLogMutex name present (shared admin + SYSTEM)" 0 "not found"
grep -qF 'SetSecurityDescriptorDacl' "$SRC" && record "src: SetSecurityDescriptorDacl NULL DACL present (admin + SYSTEM both open)" 1 || record "src: SetSecurityDescriptorDacl NULL DACL present (admin + SYSTEM both open)" 0 "not found"
grep -qF 'GM_DIAG_LOG_MUTEX_TIMEOUT_MS' "$SRC" && record "src: GM_DIAG_LOG_MUTEX_TIMEOUT_MS bounded wait present (never stall a launch)" 1 || record "src: GM_DIAG_LOG_MUTEX_TIMEOUT_MS bounded wait present (never stall a launch)" 0 "not found"
grep -qF 'WAIT_ABANDONED' "$SRC" && record "src: WAIT_ABANDONED tolerated (crashed holder does not block logging)" 1 || record "src: WAIT_ABANDONED tolerated (crashed holder does not block logging)" 0 "not found"

# Runtime SYSTEM-crash auto-exclude store (Detector B): gmproxy records every base
# name that CRASHED as SYSTEM (EXITED class=CRASH tree=0, SYSTEM mode) in a persistent
# store; at >= threshold crashes the NEXT launch skips the SYSTEM token and reuses the
# current-user fallback (MODE=USER-AUTOEXCLUDE). Fail-open; 256-cap + 30-day stale;
# atomic temp+rename; Global NULL-DACL mutex; reset via --gm-reset-autoexclude.
grep -qF 'GM_AUTOEXCLUDE_THRESHOLD' "$SRC" && record "src: GM_AUTOEXCLUDE_THRESHOLD present (crash threshold)" 1 || record "src: GM_AUTOEXCLUDE_THRESHOLD present (crash threshold)" 0 "not found"
grep -qF 'GM_AUTOEXCLUDE_STALE_DAYS' "$SRC" && record "src: GM_AUTOEXCLUDE_STALE_DAYS present (30-day stale drop)" 1 || record "src: GM_AUTOEXCLUDE_STALE_DAYS present (30-day stale drop)" 0 "not found"
grep -qF 'GM_AUTOEXCLUDE_MAX_ENTRIES' "$SRC" && record "src: GM_AUTOEXCLUDE_MAX_ENTRIES present (256 cap)" 1 || record "src: GM_AUTOEXCLUDE_MAX_ENTRIES present (256 cap)" 0 "not found"
grep -qF 'GM_AUTOEXCLUDE_MUTEX_TIMEOUT_MS' "$SRC" && record "src: GM_AUTOEXCLUDE_MUTEX_TIMEOUT_MS present (bounded wait)" 1 || record "src: GM_AUTOEXCLUDE_MUTEX_TIMEOUT_MS present (bounded wait)" 0 "not found"
grep -qF 'GmProxyAutoExcludeLoad' "$SRC" && record "src: GmProxyAutoExcludeLoad present (store parse+prune)" 1 || record "src: GmProxyAutoExcludeLoad present (store parse+prune)" 0 "not found"
grep -qF 'GmProxyAutoExcludeQuery' "$SRC" && record "src: GmProxyAutoExcludeQuery present (excluded lookup)" 1 || record "src: GmProxyAutoExcludeQuery present (excluded lookup)" 0 "not found"
grep -qF 'GmProxyAutoExcludeRecord' "$SRC" && record "src: GmProxyAutoExcludeRecord present (increment+threshold)" 1 || record "src: GmProxyAutoExcludeRecord present (increment+threshold)" 0 "not found"
grep -qF 'GmProxyAutoExcludeReset' "$SRC" && record "src: GmProxyAutoExcludeReset present (delete store)" 1 || record "src: GmProxyAutoExcludeReset present (delete store)" 0 "not found"
grep -qF 'GmProxyAutoExcludeWrite' "$SRC" && record "src: GmProxyAutoExcludeWrite present (atomic write)" 1 || record "src: GmProxyAutoExcludeWrite present (atomic write)" 0 "not found"
grep -qF 'GmProxyAutoExcludeMutex' "$SRC" && record "src: Global GmProxyAutoExcludeMutex present (cross-privilege serializer)" 1 || record "src: Global GmProxyAutoExcludeMutex present (cross-privilege serializer)" 0 "not found"
grep -qF 'USER-AUTOEXCLUDE' "$SRC" && record "src: USER-AUTOEXCLUDE launch mode present" 1 || record "src: USER-AUTOEXCLUDE launch mode present" 0 "not found"
grep -qF 'MoveFileExW' "$SRC" && record "src: MoveFileExW present (atomic store write)" 1 || record "src: MoveFileExW present (atomic store write)" 0 "not found"
grep -qF -- '--gm-reset-autoexclude' "$SRC" && record "src: --gm-reset-autoexclude CLI hook present (mutex-safe reset)" 1 || record "src: --gm-reset-autoexclude CLI hook present (mutex-safe reset)" 0 "not found"
grep -qF 'GodModeAutoExclude' "$SRC" && record "src: GodModeAutoExclude store path present" 1 || record "src: GodModeAutoExclude store path present" 0 "not found"

# CLEAN-GUI refusal recording (Part A): gmproxy now records a SYSTEM-mode CLEAN
# exit (exitcode 0, tree=0) WHEN the target is a GUI PE (IMAGE_SUBSYSTEM_WINDOWS_GUI),
# not just CRASH (non-zero exit). This is the fix for Win11 Notepad -- it exits
# CLEAN as SYSTEM (WinUI stub cannot init under SYSTEM) but is a GUI app, so the
# widened guard records it and Detector B auto-excludes after 2 refusals. The
# PE-subsystem gate avoids false-excluding console apps (nslookup/ftp/7z exit 0
# as SYSTEM legitimately -- they are CUI, not GUI).
grep -qF 'GmProxyIsGuiSubsystem' "$SRC" && record "src: GmProxyIsGuiSubsystem present (PE subsystem gate for CLEAN-GUI recording)" 1 || record "src: GmProxyIsGuiSubsystem present (PE subsystem gate for CLEAN-GUI recording)" 0 "not found -- CLEAN-GUI refusals (notepad) would never be recorded"
grep -qF 'IMAGE_SUBSYSTEM_WINDOWS_GUI' "$SRC" && record "src: IMAGE_SUBSYSTEM_WINDOWS_GUI constant present (GUI subsystem check)" 1 || record "src: IMAGE_SUBSYSTEM_WINDOWS_GUI constant present (GUI subsystem check)" 0 "not found -- the PE-subsystem gate has no target value"
grep -qF 'IMAGE_FILE_HEADER' "$SRC" && record "src: IMAGE_FILE_HEADER read before OptionalHeader (PE parse correctness)" 1 || record "src: IMAGE_FILE_HEADER read before OptionalHeader (PE parse correctness)" 0 "not found -- OptionalHeader.Subsystem would read from the wrong offset"
grep -qF 'GmProxyIsGuiSubsystem(targetPath)' "$SRC" && record "src: widened record guard references GmProxyIsGuiSubsystem(targetPath)" 1 || record "src: widened record guard references GmProxyIsGuiSubsystem(targetPath)" 0 "not found -- CLEAN-GUI refusals not gated on the PE subsystem"
grep -qF 'if (!autoExcluded)' "$SRC" && record "src: A3 -- SignalGmProxyFeedback gated on !autoExcluded" 1 || record "src: A3 -- SignalGmProxyFeedback gated on !autoExcluded" 0 "not found"
# Detector B alias-stub guard (2026-07-19): a CLEAN-GUI exit for a Win11 App
# Execution Alias stub (notepad/mspaint/calc) is NOT a SYSTEM refusal -- it is
# the IFEO-bypass RENAME breaking the stub's Store redirect + .mui lookup. The
# guard skips recording it + logs the real cause. CRASH is still recorded.
grep -qF 'GmProxyIsAppExecutionAliasStub' "$SRC" && record "src: GmProxyIsAppExecutionAliasStub helper present (Detector B alias-stub guard)" 1 || record "src: GmProxyIsAppExecutionAliasStub helper present (Detector B alias-stub guard)" 0 "not found -- CLEAN-GUI refusals for Store stubs would pollute the store"
grep -qF 'is an App Execution Alias stub' "$SRC" && record "src: alias guard skip-record DiagLog present (App Execution Alias stub)" 1 || record "src: alias guard skip-record DiagLog present" 0 "not found -- the rename-breaks-stub cause would not be logged"
grep -qF 'code == 0 && GmProxyIsAppExecutionAliasStub(base)' "$SRC" && record "src: alias guard wraps the CLEAN-GUI record (code == 0 && GmProxyIsAppExecutionAliasStub(base))" 1 || record "src: alias guard wraps the CLEAN-GUI record" 0 "not found -- a stub CLEAN exit would still be recorded"

# IFEO-bypass same-directory copy fallback (2026-07-19, Suggestion 3): when the
# same-dir hardlink fails, gmproxy now tries a same-dir CopyFileW under its
# current token, then under the stolen SYSTEM token (ImpersonateLoggedOnUser +
# RevertToSelf) so ACL-protected dirs (C:\Windows/System32) the admin can't write
# stay in-context, then falls back to Temp. Keeps canonical-directory context
# for path-relative targets. The MinGW build below must still compile with this.
grep -qF 'CopyFileW(argv[1], hardlinkPath, FALSE)' "$SRC" && record "src: same-dir copy fallback present (CopyFileW to hardlinkPath before Temp)" 1 || record "src: same-dir copy fallback present" 0 "not found -- a hardlink failure jumps straight to Temp (loses canonical-directory context)"
grep -qF 'ImpersonateLoggedOnUser' "$SRC" && record "src: same-dir copy SYSTEM impersonation present (ImpersonateLoggedOnUser)" 1 || record "src: same-dir copy SYSTEM impersonation present" 0 "not found -- C:\Windows/System32 targets the admin can't write stay broken"
grep -qF 'RevertToSelf' "$SRC" && record "src: impersonation always reverts (RevertToSelf)" 1 || record "src: impersonation always reverts (RevertToSelf)" 0 "not found -- gmproxy would keep running as SYSTEM after the copy"
grep -qF 'TokenImpersonation' "$SRC" && record "src: SYSTEM token duplicated as impersonation (TokenImpersonation for ImpersonateLoggedOnUser)" 1 || record "src: SYSTEM token duplicated as impersonation (TokenImpersonation)" 0 "not found -- ImpersonateLoggedOnUser needs an impersonation token, not the TokenPrimary used for CreateProcess"
# gmproxy GmProxyAutoExcludeRecord preserves an install-time 'A' reason (2026-
# 07-19 belt-and-suspenders): a stub that slips past Detector A must not lose
# its 'A' classification to a runtime G/C. The MinGW build below must still compile.
grep -qF "if (entries[idx].reason != L'A')" "$SRC" && record "src: GmProxyAutoExcludeRecord preserves reason 'A' (if reason != L'A')" 1 || record "src: GmProxyAutoExcludeRecord preserves reason 'A' (if reason != L'A')" 0 "not found -- an install-time 'A' is downgraded to a runtime G/C for a stub that slips past Detector A"

# gmhook.c store consult (Part B): gmhook reads the auto-exclude store before
# birthing a child as SYSTEM; a store-excluded base name falls through to the
# real CreateProcessW (born as the host's normal user token, not SYSTEM). 2s
# in-process cache so the CreateProcess hot path does at most one file read
# per 2s per process. Fail-open.
if [ -f "$GMHOOK_SRC" ]; then
    grep -qF 'GmHookIsAutoExcluded' "$GMHOOK_SRC" && record "src: gmhook GmHookIsAutoExcluded present (store consult before SYSTEM birth)" 1 || record "src: gmhook GmHookIsAutoExcluded present (store consult before SYSTEM birth)" 0 "not found -- gmhook cannot consult the store"
    grep -qF 'GmHookIsAutoExcluded(baseName)' "$GMHOOK_SRC" && record "src: gmhook HookCreateProcessW consults GmHookIsAutoExcluded(baseName)" 1 || record "src: gmhook HookCreateProcessW consults GmHookIsAutoExcluded(baseName)" 0 "not found -- excluded apps still born as SYSTEM from hooked hosts"
    grep -qF 'GMHOOK_AUTOEXCLUDE_CACHE_TTL_MS' "$GMHOOK_SRC" && record "src: gmhook 2s TTL cache constant present (hot-path throttle)" 1 || record "src: gmhook 2s TTL cache constant present (hot-path throttle)" 0 "not found -- CreateProcess hot path would read the store file every call"
    grep -qF 'GetFileAttributesExW' "$GMHOOK_SRC" && record "src: gmhook mtime invalidation (GetFileAttributesExW) present -- newly-excluded app respected on next CreateProcessW" 1 || record "src: gmhook mtime invalidation (GetFileAttributesExW) present" 0 "not found -- a fresh exclusion waits up to the 2s TTL"
    grep -qF 'cacheLoadMtime' "$GMHOOK_SRC" && record "src: gmhook tracks the store LastWriteTime (cacheLoadMtime) for mtime invalidation" 1 || record "src: gmhook tracks the store LastWriteTime (cacheLoadMtime)" 0 "not found -- mtime change cannot trigger a reload"
    # gmhook host-process-token invalidation (2026-07-19): reload the store when
    # the host's process token changes (monitor in-place elevation / token swap).
    grep -qF 'cacheLoadTokenSid' "$GMHOOK_SRC" && record "src: gmhook captures the host token SID (cacheLoadTokenSid) for token-change invalidation" 1 || record "src: gmhook captures the host token SID (cacheLoadTokenSid)" 0 "not found -- a host-token change cannot trigger a reload"
    grep -qF 'tokenChanged' "$GMHOOK_SRC" && record "src: gmhook reloads on a host-token change (tokenChanged)" 1 || record "src: gmhook reloads on a host-token change (tokenChanged)" 0 "not found -- the 'always fresh' guarantee is incomplete"
    grep -qF 'EqualSid' "$GMHOOK_SRC" && record "src: gmhook token SID compare uses EqualSid (fail-open)" 1 || record "src: gmhook token SID compare uses EqualSid" 0 "not found"
    # gmhook alias-stub skip (2026-07-20, S1): a direct reparse-point check
    # (mirrors gmproxy.c GmProxyIsAppExecutionAliasStub) in HookCreateProcessW
    # -- belt-and-suspenders for a stub whose store entry was pruned by
    # reconcile or never written (Detector A miss). Fail-open.
    grep -qF 'GmHookIsAppExecutionAliasStub' "$GMHOOK_SRC" && record "src: gmhook GmHookIsAppExecutionAliasStub helper present (alias-stub skip)" 1 || record "src: gmhook GmHookIsAppExecutionAliasStub helper present (alias-stub skip)" 0 "not found -- a stub whose store entry was pruned/never-written would still be born as SYSTEM"
    grep -qF 'GmHookIsAppExecutionAliasStub(baseName)' "$GMHOOK_SRC" && record "src: gmhook HookCreateProcessW consults GmHookIsAppExecutionAliasStub(baseName)" 1 || record "src: gmhook HookCreateProcessW consults GmHookIsAppExecutionAliasStub(baseName)" 0 "not found -- the belt-and-suspenders alias-stub skip is not wired"
    # gmhook ISE hardening (2026-07-20): powershell_ise.exe is a shell host that
    # launches commands via CreateProcessW -- IAT-hooking it in-process faults
    # with the same 0xC0000005 as powershell/pwsh/cmd. IsShellLauncherProcess now
    # excludes it (never IAT-hooked); the monitor auto-elevates ISE in place.
    grep -qF 'L"powershell_ise.exe"' "$GMHOOK_SRC" && record "src: gmhook IsShellLauncherProcess excludes powershell_ise.exe (ISE hardening)" 1 || record "src: gmhook IsShellLauncherProcess excludes powershell_ise.exe (ISE hardening)" 0 "not found -- ISE would be IAT-hooked (0xC0000005 crash risk)"
    grep -qF 'L"explorer.exe"' "$GMHOOK_SRC" && record "src: gmhook IsShellLauncherProcess excludes explorer.exe (STARTUPINFOEX downgrade crash/restart loop)" 1 || record "src: gmhook IsShellLauncherProcess excludes explorer.exe (STARTUPINFOEX downgrade crash/restart loop)" 0 "not found -- explorer would be IAT-hooked -> STARTUPINFOEX->STARTUPINFOW downgrade drops the extended attribute list -> explorer crash/restart loop (blank User column)"
    grep -qF 'Microsoft\\WindowsApps' "$GMHOOK_SRC" && record "src: gmhook alias check uses the WindowsApps reparse path (Microsoft\\WindowsApps)" 1 || record "src: gmhook alias check uses the WindowsApps reparse path (Microsoft\\WindowsApps)" 0 "not found -- the alias-stub check does not look at the WindowsApps reparse point"
    # gmhook instant shell birth-signal (2026-07-22): gmhook does NOT elevate a
    # shell child itself (no SeTcb; rerouting its CreateProcessW crashes it with
    # 0xC0000005). Instead it signals the new shell PID to the SYSTEM monitor
    # (SHELLPID=<n> over the GodMode-GmProxyFeedback pipe) the moment the real
    # CreateProcessW succeeds, so the monitor in-place swaps it to SYSTEM within
    # the loop tick (~<=500ms) instead of waiting for the 3s/15s scan. Only the 4
    # interactive shells (cmd/powershell/pwsh/ise) -- NOT explorer/wt/conhost
    # (swapping those to SYSTEM breaks the desktop). Fail-open + non-blocking.
    grep -qF 'IsInteractiveShell' "$GMHOOK_SRC" && record "src: gmhook IsInteractiveShell helper present (gates the shell birth-signal to cmd/powershell/pwsh/ise only)" 1 || record "src: gmhook IsInteractiveShell helper present" 0 "not found -- gmhook cannot gate the shell birth-signal"
    grep -qF 'SignalShellBirth' "$GMHOOK_SRC" && record "src: gmhook SignalShellBirth helper present (notifies the monitor of a shell birth)" 1 || record "src: gmhook SignalShellBirth helper present" 0 "not found -- gmhook cannot hand the shell PID to the monitor"
    grep -qF 'SHELLPID=%lu' "$GMHOOK_SRC" && record "src: gmhook SignalShellBirth writes a SHELLPID= payload (distinct from gmproxy's PID=)" 1 || record "src: gmhook SHELLPID= payload present" 0 "not found -- the monitor listener cannot route shell signals to the shell-elevation path"
    grep -qF 'SignalShellBirth(lpProcessInformation->dwProcessId)' "$GMHOOK_SRC" && record "src: gmhook shell pass-through calls SignalShellBirth with the new shell PID" 1 || record "src: gmhook shell pass-through calls SignalShellBirth with the new shell PID" 0 "not found -- the instant-elevation fast path is not wired in HookCreateProcessW"
else
    record "src: gmhook.c present" 0 "missing: $GMHOOK_SRC"
fi

# Detector B reason field (5th, additive): the store line is now
# base|count|ts|excluded|reason (C=crash, G=clean-gui, P=pre-drop, ?=old line).
# The reason is informational (Export-GodModeLogs debuggability); the parser
# defaults to '?' so old 4-field lines still parse. The MinGW build below must
# still compile with the new field + the reason-threaded record call.
grep -qF "GmProxyAutoExcludeRecord(base, (code != 0) ? L'C' : L'G')" "$SRC" && record "src: record call threads the reason flavor ('C' crash / 'G' clean-gui)" 1 || record "src: record call threads the reason flavor ('C' / 'G')" 0 "not found -- the refusal flavor is not recorded"
grep -qF '|%lc' "$SRC" && record "src: store write emits the 5th reason field (%lc)" 1 || record "src: store write emits the 5th reason field (%lc)" 0 "not found -- reason not persisted to the store"
grep -qF "if (reason) *reason = L'?';" "$SRC" && record "src: parser defaults reason to '?' (old 4-field lines backward compat)" 1 || record "src: parser defaults reason to '?' (old 4-field lines backward compat)" 0 "not found -- old 4-field store lines would not parse"

# GMPROXY_TEST_FORCE_SYSTEM_MODE compile-time seam: mirrors the
# GMPROXY_TEST_FORCE_SESSION0 seam. Lets the wine runtime test
# (test-gmproxy-force-system.sh) exercise the RECORDING path (the production
# _wcsicmp(mode,L"SYSTEM") guard never fires under wine, since wine has no
# real SYSTEM token). The PRODUCTION build does NOT define it; the #else branch
# is the byte-for-byte original guard. driver/build.ps1 must NOT reference it.
grep -qF '#ifdef GMPROXY_TEST_FORCE_SYSTEM_MODE' "$SRC" && record "src: GMPROXY_TEST_FORCE_SYSTEM_MODE compile-time seam present (#ifdef)" 1 || record "src: GMPROXY_TEST_FORCE_SYSTEM_MODE compile-time seam present (#ifdef)" 0 "not found -- recording cannot be exercised under wine"
grep -qF 'BOOL recordAsSystem = TRUE;' "$SRC" && record "src: seam forces recordAsSystem=TRUE (test build records even under wine FALLBACK)" 1 || record "src: seam forces recordAsSystem=TRUE" 0 "not found"
grep -qF 'BOOL recordAsSystem = (_wcsicmp(mode, L"SYSTEM") == 0);' "$SRC" && record "src: production #else branch keeps the original _wcsicmp(mode,L\"SYSTEM\") guard (byte-for-byte)" 1 || record "src: production #else branch keeps the original _wcsicmp(mode,L\"SYSTEM\") guard" 0 "not found -- production recording guard regressed"

# Build: MinGW cross-compile (mirrors driver/build.ps1 Build-WithMinGW for gmproxy).
if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    record "MinGW (x86_64-w64-mingw32-gcc) available" 0 "not installed; compile skipped"
else
    out="$SCRIPT_DIR/gmproxy_session_test.exe"
    build_log="$(mktemp)"
    if x86_64-w64-mingw32-gcc -O2 -Wall -municode -o "$out" "$SRC" -ladvapi32 -lkernel32 -lntdll -luserenv >"$build_log" 2>&1; then
        record "gmproxy.c compiles (MinGW, session-fix)" 1
        # Verify the output is a valid PE binary.
        if command -v file >/dev/null 2>&1; then
            if file "$out" 2>/dev/null | grep -q 'PE32'; then
                record "gmproxy.exe is a PE32 binary" 1
            else
                record "gmproxy.exe is a PE32 binary" 0 "file did not report PE32"
            fi
        else
            # Fallback: check the MZ DOS header magic.
            if head -c 2 "$out" 2>/dev/null | grep -q 'MZ'; then
                record "gmproxy.exe has MZ PE header" 1
            else
                record "gmproxy.exe has MZ PE header" 0 "no MZ magic"
            fi
        fi
    else
        record "gmproxy.c compiles (MinGW, session-fix)" 0 "gcc failed; build log: $build_log"
        cat "$build_log" 2>/dev/null
        rm -f "$build_log"
    fi
    rm -f "$out" "$build_log"
fi

# Final summary with FAIL SUMMARY (N).
printf '\n=====================================================\n'
printf '  gmproxy SESSION-FIX TEST SUMMARY\n'
printf '=====================================================\n'
printf '  Passed: %s\n' "$pass_count"
printf '  Failed: %s\n' "$fail_count"
if [ "$fail_count" -gt 0 ]; then
    printf '\n  FAIL SUMMARY (%s)\n' "$fail_count"
    for n in "${fail_names[@]}"; do
        printf '    - %s\n' "$n"
    done
    exit 1
fi
printf '\n  ALL gmproxy SESSION-FIX TESTS PASSED!\n'
exit 0
