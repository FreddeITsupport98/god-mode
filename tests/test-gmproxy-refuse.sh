#!/usr/bin/env bash
# test-gmproxy-refuse.sh -- wine RUNTIME proof of gmproxy's ownerless Session-0
# birth REFUSE (driver/gmproxy.c) + the graceful current-user fallback preservation.
#
# The source-level pwsh test (Test-GmProxySession.ps1 section 17) checks the
# refusal invariants are WRITTEN DOWN; the build test (test-gmproxy-session.sh)
# proves gmproxy.c still COMPILES. THIS test goes one step further: it RUNS the
# freshly-built gmproxy.exe under wine with a real (quickly-exiting) dummy
# target (gmproxy-refuse-target.c) and asserts the OBSERVED runtime behavior of
# BOTH branches of the ownerless-birth fix:
#   1. NORMAL build (no test macro): wine reports the interactive session (1),
#      so gmproxy's mySessionIsZero is FALSE -> the graceful current-user
#      fallback fires -> gmproxy launches the dummy as the current user and
#      exits 0 ("Launched ... as current user (graceful fallback, ...)" in
#      %TEMP%\gmproxy.log). Proves the non-Session-0 IFEO fallback is preserved
#      at runtime -- the path an interactive admin user actually hits via IFEO.
#   2. FORCED build (-DGMPROXY_TEST_FORCE_SESSION0=1): a COMPILE-TIME test seam
#      forces mySession=0 / mySessionIsZero=TRUE (wine does NOT model Windows
#      Session 0 isolation -- ProcessIdToSessionId returns 1 there -- so without
#      the seam the REFUSE branch is never exercised under wine). gmproxy then
#      REFUSES ownerless birth -> exits 1 with "[GM-PROXY] REFUSE" in
#      %TEMP%\gmproxy.log and does NOT reach the graceful-fallback launch.
#      Proves the Session-0 refusal fires at runtime.
#
# The PRODUCTION build (driver/build.ps1) does NOT define
# GMPROXY_TEST_FORCE_SESSION0, so the shipped gmproxy.exe is byte-for-byte
# unaffected -- this is a compile-time test double, NOT a runtime env-var hook
# (no behavior change unless the macro is defined at build time). This test
# asserts that invariant too (build.ps1 must NOT reference the macro).
#
# Prints a FAIL SUMMARY (N) block and exits 1 on any failure, 0 if all pass.
# Usage: bash tests/test-gmproxy-refuse.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="$PROJECT_ROOT/driver/gmproxy.c"
DUMMY_SRC="$SCRIPT_DIR/gmproxy-refuse-target.c"
BUILD_PS1="$PROJECT_ROOT/driver/build.ps1"

GCC=x86_64-w64-mingw32-gcc
WINE=wine

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
printf '  gmproxy ownerless-birth REFUSE (wine runtime test)\n'
printf '=====================================================\n'

# --- Tool checks (hard-fail if the toolchain the VM build also needs is
#     missing, so this never silently passes by skipping). ---
if ! command -v "$GCC" >/dev/null 2>&1; then
    record "MinGW ($GCC) available" 0 "not installed; cannot build gmproxy.exe / dummy"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi
if ! command -v "$WINE" >/dev/null 2>&1; then
    record "wine available" 0 "not installed; cannot run gmproxy.exe"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi

# --- Source invariants (the refusal + seam must be present in source before we
#     trust a build / run). ---
if [ ! -f "$SRC" ]; then
    record "driver/gmproxy.c present" 0 "missing: $SRC"
else
    record "driver/gmproxy.c present" 1
fi
grep -q 'ProcessIdToSessionId' "$SRC" && record "src: ProcessIdToSessionId own-session detect present" 1 || record "src: ProcessIdToSessionId own-session detect present" 0 "not found"
grep -q 'mySessionIsZero' "$SRC" && record "src: mySessionIsZero guard present" 1 || record "src: mySessionIsZero guard present" 0 "not found"
grep -qF '[GM-PROXY] REFUSE' "$SRC" && record "src: [GM-PROXY] REFUSE diag present" 1 || record "src: [GM-PROXY] REFUSE diag present" 0 "not found"
grep -qF '#ifdef GMPROXY_TEST_FORCE_SESSION0' "$SRC" && record "src: GMPROXY_TEST_FORCE_SESSION0 compile-time seam present (#ifdef)" 1 || record "src: GMPROXY_TEST_FORCE_SESSION0 compile-time seam present (#ifdef)" 0 "not found -- forced REFUSE run cannot be exercised under wine"
# Layer 1 (env block) + Layer 2 (launch flags) fix invariants: gmproxy now
# builds the SYSTEM child's env from the stolen token (CreateEnvironmentBlock)
# and injects --no-sandbox / -no-remote for browser/Electron targets. The
# NORMAL + FORCED builds below must link -luserenv for CreateEnvironmentBlock.
grep -qF 'userenv.h' "$SRC" && record "src: #include <userenv.h> present (Layer 1 env block)" 1 || record "src: #include <userenv.h> present (Layer 1 env block)" 0 "not found"
grep -qF 'CreateEnvironmentBlock' "$SRC" && record "src: CreateEnvironmentBlock present (token-consistent env)" 1 || record "src: CreateEnvironmentBlock present (token-consistent env)" 0 "not found"
grep -qF -- '--no-sandbox' "$SRC" && record "src: --no-sandbox flag present (Chromium/Electron)" 1 || record "src: --no-sandbox flag present (Chromium/Electron)" 0 "not found"
grep -qF -- '-no-remote' "$SRC" && record "src: -no-remote flag present (Firefox)" 1 || record "src: -no-remote flag present (Firefox)" 0 "not found"
# Per-app launch telemetry (big debug): gmproxy emits structured [GM-PROXY]
# LAUNCH: / [GM-PROXY] CHILD-STATUS: lines per invocation (app, pid, mode, flag,
# env) + a child-survival observation, so Export-GodModeLogs (option [11]) can
# aggregate a PER-APP LAUNCH REPORT (which apps EXITED within the grace window
# = the "launched but instantly died / won't render" crash signal).
grep -qF 'GmProxyLogLaunchReport' "$SRC" && record "src: GmProxyLogLaunchReport per-app telemetry helper present" 1 || record "src: GmProxyLogLaunchReport per-app telemetry helper present" 0 "not found"
grep -qF '[GM-PROXY] LAUNCH:' "$SRC" && record "src: [GM-PROXY] LAUNCH: structured telemetry line present" 1 || record "src: [GM-PROXY] LAUNCH: structured telemetry line present" 0 "not found"
grep -qF '[GM-PROXY] CHILD-STATUS:' "$SRC" && record "src: [GM-PROXY] CHILD-STATUS: child-survival observation line present" 1 || record "src: [GM-PROXY] CHILD-STATUS: child-survival observation line present" 0 "not found"
# Grandchild-tree Job observation + elevation-context logging (root-cause debug):
# gmproxy now captures the child's whole process tree in a Job Object (CREATE_
# SUSPENDED -> AssignProcessToJobObject -> ResumeThread, BREAKAWAY_OK, NO
# KILL_ON_JOB_CLOSE) and classifies a clean exit with a surviving grandchild as
# result=DELEGATED (launcher/stub, NOT a failure) vs result=EXITED class=CLEAN
# (exitcode 0, graceful refusal) / class=CRASH (non-zero). Elevation-context
# logging (ELEVATE/TOKEN/CMDLINE/ENV + CREATEPROC result=OK/FAIL gle) catches the
# ELEVATION-side root cause. The NORMAL + FORCED builds below must link + run.
grep -qF 'sddl.h' "$SRC" && record "src: #include <sddl.h> present (token SID logging)" 1 || record "src: #include <sddl.h> present (token SID logging)" 0 "not found"
grep -qF 'GmProxyImageNameForPid' "$SRC" && record "src: GmProxyImageNameForPid helper present" 1 || record "src: GmProxyImageNameForPid helper present" 0 "not found"
grep -qF 'GmProxyEnumerateJobTree' "$SRC" && record "src: GmProxyEnumerateJobTree helper present (job tree walk)" 1 || record "src: GmProxyEnumerateJobTree helper present (job tree walk)" 0 "not found"
grep -qF 'GmProxyLogElevationContext' "$SRC" && record "src: GmProxyLogElevationContext helper present (elevation context log)" 1 || record "src: GmProxyLogElevationContext helper present (elevation context log)" 0 "not found"
grep -qF 'CreateJobObjectW' "$SRC" && record "src: CreateJobObjectW present (observational job)" 1 || record "src: CreateJobObjectW present (observational job)" 0 "not found"
grep -qF 'AssignProcessToJobObject' "$SRC" && record "src: AssignProcessToJobObject present (child -> job)" 1 || record "src: AssignProcessToJobObject present (child -> job)" 0 "not found"
grep -qF 'CREATE_SUSPENDED' "$SRC" && record "src: CREATE_SUSPENDED present (child suspended before job assign)" 1 || record "src: CREATE_SUSPENDED present (child suspended before job assign)" 0 "not found"
grep -qF 'ResumeThread' "$SRC" && record "src: ResumeThread present (resume after job assign)" 1 || record "src: ResumeThread present (resume after job assign)" 0 "not found"
grep -qF '[GM-PROXY] ELEVATE:' "$SRC" && record "src: [GM-PROXY] ELEVATE: token-source context line present" 1 || record "src: [GM-PROXY] ELEVATE: token-source context line present" 0 "not found"
grep -qF '[GM-PROXY] CREATEPROC:' "$SRC" && record "src: [GM-PROXY] CREATEPROC: per-attempt outcome line present" 1 || record "src: [GM-PROXY] CREATEPROC: per-attempt outcome line present" 0 "not found"
grep -qF 'result=DELEGATED' "$SRC" && record "src: result=DELEGATED classification present (launcher/stub -> grandchild)" 1 || record "src: result=DELEGATED classification present (launcher/stub -> grandchild)" 0 "not found"
grep -qF 'class=%ls' "$SRC" && record "src: class=CLEAN/CRASH classification present (exit-code class)" 1 || record "src: class=CLEAN/CRASH classification present (exit-code class)" 0 "not found"
# CRITICAL invariant: the PRODUCTION build must NOT define the test seam (else
# the shipped gmproxy.exe would force-refuse ownerless birth in the field).
# Negative assertion on driver/build.ps1.
if [ -f "$BUILD_PS1" ]; then
    if grep -qF 'GMPROXY_TEST_FORCE_SESSION0' "$BUILD_PS1"; then
        record "build.ps1 does NOT define the test seam (production binary unaffected)" 0 "driver/build.ps1 references GMPROXY_TEST_FORCE_SESSION0 -- production build would force-refuse in the field"
    else
        record "build.ps1 does NOT define the test seam (production binary unaffected)" 1
    fi
else
    record "driver/build.ps1 present" 0 "missing"
fi
if [ ! -f "$DUMMY_SRC" ]; then
    record "gmproxy-refuse-target.c dummy target present" 0 "missing: $DUMMY_SRC"
else
    record "gmproxy-refuse-target.c dummy target present" 1
fi

WORK="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$WORK'" EXIT

# --- Build the dummy target (quick exit so it never hangs a test run). ---
DUMMY="$WORK/dummy.exe"
if "$GCC" -O2 -Wall -o "$DUMMY" "$DUMMY_SRC" >/dev/null 2>&1; then
    record "build dummy.exe (MinGW)" 1
else
    record "build dummy.exe (MinGW)" 0 "gcc failed"
    DUMMY=""
fi

# --- Build gmproxy.exe: NORMAL (production-equivalent, no test macro). ---
NORMAL="$WORK/gmproxy_normal.exe"
if "$GCC" -O2 -Wall -municode -o "$NORMAL" "$SRC" -ladvapi32 -lkernel32 -lntdll -luserenv >/dev/null 2>&1; then
    record "build gmproxy.exe NORMAL (MinGW, production-equivalent)" 1
else
    record "build gmproxy.exe NORMAL (MinGW, production-equivalent)" 0 "gcc failed"
    NORMAL=""
fi

# --- Build gmproxy.exe: FORCED (-DGMPROXY_TEST_FORCE_SESSION0=1 -> mySession=0). ---
FORCED="$WORK/gmproxy_forced.exe"
if "$GCC" -O2 -Wall -municode -DGMPROXY_TEST_FORCE_SESSION0=1 -o "$FORCED" "$SRC" -ladvapi32 -lkernel32 -lntdll -luserenv >/dev/null 2>&1; then
    record "build gmproxy.exe FORCED (MinGW, -DGMPROXY_TEST_FORCE_SESSION0=1)" 1
else
    record "build gmproxy.exe FORCED (MinGW, -DGMPROXY_TEST_FORCE_SESSION0=1)" 0 "gcc failed"
    FORCED=""
fi

# --- Locate wine %TEMP% (where gmproxy writes gmproxy.log) so each run's
#     assertions only see THIS run's lines. gmproxy.log is this project's own
#     log artifact (not user data), safe to remove here for deterministic guards.
WINEPREFIX_DIR="${WINEPREFIX:-$HOME/.wine}"
WINE_USER="${USER:-${LOGNAME:-}}"
WINE_TEMP="$WINEPREFIX_DIR/drive_c/users/$WINE_USER/AppData/Local/Temp"
if [ ! -d "$WINE_TEMP" ]; then
    WINE_TEMP="$(find "$WINEPREFIX_DIR/drive_c/users" -maxdepth 4 -type d -path '*/AppData/Local/Temp' 2>/dev/null | head -n1)"
fi
GMPROXY_LOG="$WINE_TEMP/gmproxy.log"

# run_gmproxy <exe> <dummy_rel> -> sets RUN_OUT, RUN_RC, RUN_LOG. Clears
# gmproxy.log first so the guard only sees this run's lines. The dummy is passed
# as a RELATIVE name so gmproxy's CreateHardLinkW resolves it against the wine
# CWD ($WORK), matching how the real IFEO path hands gmproxy a target name.
run_gmproxy() {
    local exe="$1" dummy="$2"
    if [ -n "$WINE_TEMP" ] && [ -d "$WINE_TEMP" ]; then rm -f "$GMPROXY_LOG"; fi
    RUN_OUT="$(cd "$WORK" && "$WINE" "$exe" "$dummy" 2>&1)"
    RUN_RC=$?
    if [ -f "$GMPROXY_LOG" ]; then
        RUN_LOG="$(cat "$GMPROXY_LOG")"
    else
        RUN_LOG=""
    fi
}

# --- Run 1: NORMAL build -> graceful current-user fallback (wine session 1). ---
if [ -n "$NORMAL" ] && [ -n "$DUMMY" ]; then
    run_gmproxy "$NORMAL" "dummy.exe"
    printf '  [wine] NORMAL build (expect graceful fallback, exit 0):\n%s\n' "$RUN_OUT" | sed 's/^/    /'
    record "NORMAL: gmproxy exits 0 (graceful fallback, not a launch failure)" "$([ "$RUN_RC" -eq 0 ] && echo 1 || echo 0)" "wine exit=$RUN_RC (expected 0)"
    # "graceful fallback" uniquely identifies the current-user LAUNCH line
    # (L519). The no-token WARN line also says "as current user" but does NOT
    # contain "graceful fallback", so this needle proves the launch happened.
    case "$RUN_LOG" in
        *"graceful fallback"*) record "NORMAL: gmproxy.log shows graceful-fallback launch line" 1 ;;
        *) record "NORMAL: gmproxy.log shows graceful-fallback launch line" 0 "gmproxy.log missing the graceful-fallback launch line" ;;
    esac
    case "$RUN_LOG" in
        *"[GM-PROXY] REFUSE"*) record "NORMAL: gmproxy.log does NOT REFUSE (non-Session-0 path preserved)" 0 "REFUSE appeared in the NORMAL build log -- graceful fallback regressed" ;;
        *) record "NORMAL: gmproxy.log does NOT REFUSE (non-Session-0 path preserved)" 1 ;;
    esac
    # Per-app launch telemetry (big debug): the NORMAL build takes the graceful
    # fallback and launches the dummy, which exits immediately -> gmproxy's
    # child-survival observation must fire and report result=EXITED. Proves the
    # new telemetry actually emits at runtime under wine, not just in source.
    case "$RUN_LOG" in
        *"[GM-PROXY] LAUNCH:"*) record "NORMAL: gmproxy.log shows [GM-PROXY] LAUNCH: telemetry line" 1 ;;
        *) record "NORMAL: gmproxy.log shows [GM-PROXY] LAUNCH: telemetry line" 0 "gmproxy.log missing the LAUNCH telemetry line" ;;
    esac
    case "$RUN_LOG" in
        *"[GM-PROXY] CHILD-STATUS:"*) record "NORMAL: gmproxy.log shows [GM-PROXY] CHILD-STATUS: child-survival observation" 1 ;;
        *) record "NORMAL: gmproxy.log shows [GM-PROXY] CHILD-STATUS: child-survival observation" 0 "gmproxy.log missing the CHILD-STATUS line -- child observation did not fire" ;;
    esac
    case "$RUN_LOG" in
        *"result=EXITED"*) record "NORMAL: gmproxy.log shows result=EXITED (dummy exited fast, crash-signal path exercised)" 1 ;;
        *) record "NORMAL: gmproxy.log shows result=EXITED (dummy exited fast, crash-signal path exercised)" 0 "gmproxy.log missing result=EXITED" ;;
    esac
    # New root-cause classification: the dummy exits with exitcode 0 -> the
    # CHILD-STATUS line must carry class=CLEAN (graceful, not a crash). Proves the
    # new CLEAN/CRASH exit-code classification fires at runtime under wine.
    case "$RUN_LOG" in
        *"class=CLEAN"*) record "NORMAL: gmproxy.log shows class=CLEAN (exitcode 0 = graceful, not a crash)" 1 ;;
        *) record "NORMAL: gmproxy.log shows class=CLEAN (exitcode 0 = graceful, not a crash)" 0 "gmproxy.log missing class=CLEAN -- new exit-code classification did not fire" ;;
    esac
    # Per-attempt CreateProcess outcome logging + elevation-context logging must
    # fire at runtime (the NORMAL build takes the current-user fallback, so a
    # CREATEPROC method=currentuser result=OK line + ELEVATE context line appear).
    case "$RUN_LOG" in
        *"[GM-PROXY] CREATEPROC:"*) record "NORMAL: gmproxy.log shows [GM-PROXY] CREATEPROC: per-attempt outcome line" 1 ;;
        *) record "NORMAL: gmproxy.log shows [GM-PROXY] CREATEPROC: per-attempt outcome line" 0 "gmproxy.log missing the CREATEPROC line -- per-attempt outcome logging did not fire" ;;
    esac
    case "$RUN_LOG" in
        *"[GM-PROXY] ELEVATE:"*) record "NORMAL: gmproxy.log shows [GM-PROXY] ELEVATE: elevation-context line" 1 ;;
        *) record "NORMAL: gmproxy.log shows [GM-PROXY] ELEVATE: elevation-context line" 0 "gmproxy.log missing the ELEVATE context line -- elevation-context logging did not fire" ;;
    esac
fi

# --- Run 2: FORCED build -> ownerless-birth REFUSE (forced Session 0). ---
if [ -n "$FORCED" ] && [ -n "$DUMMY" ]; then
    run_gmproxy "$FORCED" "dummy.exe"
    printf '  [wine] FORCED build (expect REFUSE, exit 1):\n%s\n' "$RUN_OUT" | sed 's/^/    /'
    record "FORCED: gmproxy exits 1 (ownerless-birth REFUSE)" "$([ "$RUN_RC" -eq 1 ] && echo 1 || echo 0)" "wine exit=$RUN_RC (expected 1)"
    case "$RUN_LOG" in
        *"[GM-PROXY] REFUSE"*) record "FORCED: gmproxy.log shows [GM-PROXY] REFUSE (ownerless birth refused)" 1 ;;
        *) record "FORCED: gmproxy.log shows [GM-PROXY] REFUSE (ownerless birth refused)" 0 "gmproxy.log missing the REFUSE line" ;;
    esac
    case "$RUN_LOG" in
        *"graceful fallback"*) record "FORCED: gmproxy.log does NOT reach the graceful-fallback launch (REFUSE short-circuited)" 0 "graceful-fallback launch line appeared in the FORCED build -- REFUSE did not short-circuit" ;;
        *) record "FORCED: gmproxy.log does NOT reach the graceful-fallback launch (REFUSE short-circuited)" 1 ;;
    esac
    # The FORCED build REFUSEs before any child is born -> it emits a LAUNCH
    # telemetry line (mode=REFUSE) but NO CHILD-STATUS (no child to observe).
    case "$RUN_LOG" in
        *"[GM-PROXY] LAUNCH:"*) record "FORCED: gmproxy.log shows [GM-PROXY] LAUNCH: telemetry line (mode=REFUSE)" 1 ;;
        *) record "FORCED: gmproxy.log shows [GM-PROXY] LAUNCH: telemetry line (mode=REFUSE)" 0 "gmproxy.log missing the LAUNCH telemetry line" ;;
    esac
    case "$RUN_LOG" in
        *"[GM-PROXY] CHILD-STATUS:"*) record "FORCED: gmproxy.log does NOT show CHILD-STATUS (REFUSE short-circuited, no child)" 0 "CHILD-STATUS appeared in the FORCED build -- REFUSE did not short-circuit before the child observation" ;;
        *) record "FORCED: gmproxy.log does NOT show CHILD-STATUS (REFUSE short-circuited, no child)" 1 ;;
    esac
fi

# Final summary with FAIL SUMMARY (N).
printf '\n=====================================================\n'
printf '  GMPROXY REFUSE RUNTIME TEST SUMMARY\n'
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
printf '\n  ALL GMPROXY REFUSE RUNTIME TESTS PASSED!\n'
exit 0
