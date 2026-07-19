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
grep -qF 'if (!autoExcluded)' "$SRC" && record "src: A3 -- SignalGmProxyFeedback gated on !autoExcluded" 1 || record "src: A3 -- SignalGmProxyFeedback gated on !autoExcluded" 0 "not found -- auto-excluded PIDs would be re-elevated by the monitor"

# gmhook.c store consult (Part B): gmhook reads the auto-exclude store before
# birthing a child as SYSTEM; a store-excluded base name falls through to the
# real CreateProcessW (born as the host's normal user token, not SYSTEM). 2s
# in-process cache so the CreateProcess hot path does at most one file read
# per 2s per process. Fail-open.
if [ -f "$GMHOOK_SRC" ]; then
    grep -qF 'GmHookIsAutoExcluded' "$GMHOOK_SRC" && record "src: gmhook GmHookIsAutoExcluded present (store consult before SYSTEM birth)" 1 || record "src: gmhook GmHookIsAutoExcluded present (store consult before SYSTEM birth)" 0 "not found -- gmhook cannot consult the store"
    grep -qF 'GmHookIsAutoExcluded(baseName)' "$GMHOOK_SRC" && record "src: gmhook HookCreateProcessW consults GmHookIsAutoExcluded(baseName)" 1 || record "src: gmhook HookCreateProcessW consults GmHookIsAutoExcluded(baseName)" 0 "not found -- excluded apps still born as SYSTEM from hooked hosts"
    grep -qF 'GMHOOK_AUTOEXCLUDE_CACHE_TTL_MS' "$GMHOOK_SRC" && record "src: gmhook 2s TTL cache constant present (hot-path throttle)" 1 || record "src: gmhook 2s TTL cache constant present (hot-path throttle)" 0 "not found -- CreateProcess hot path would read the store file every call"
else
    record "src: gmhook.c present" 0 "missing: $GMHOOK_SRC"
fi

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
