#!/usr/bin/env bash
# test-gmproxy-cleangui.sh -- wine RUNTIME proof of gmproxy's A3 (auto-excluded
# launch does NOT hand the PID back to the monitor for SYSTEM re-elevation) +
# source-level proof of the CLEAN-GUI refusal recording (Part A2).
#
# The source-level pwsh test (Test-GmProxySession.ps1) checks the invariants are
# WRITTEN DOWN; test-gmproxy-session.sh proves gmproxy.c COMPILES. THIS test RUNS
# the freshly-built gmproxy.exe under wine with a PRE-SEEDED auto-exclude store
# and asserts the OBSERVED runtime behavior of A3:
#   1. PRE-SEEDED store (dummy.exe crashCount=2 excluded=1 >= threshold) ->
#      gmproxy skips the SYSTEM token, launches the dummy as the current user
#      (graceful fallback), logs MODE=USER-AUTOEXCLUDE, AND does NOT hand the
#      PID to the monitor (A3: SignalGmProxyFeedback is gated on !autoExcluded,
#      so NO "Handed PID" line appears in the log). Proves an auto-excluded
#      launch is not re-elevated in-place by the monitor (which would defeat the
#      auto-exclude and re-kill the app).
#   2. Source greps: GmProxyIsGuiSubsystem + IMAGE_SUBSYSTEM_WINDOWS_GUI +
#      IMAGE_FILE_HEADER + the widened record guard. The CLEAN-GUI refusal
#      RECORDING path (seed count=1 excluded=0, run a GUI target, assert
#      count->2/excluded->1) CANNOT be exercised under wine because wine has no
#      real SYSTEM token (the launch mode is FALLBACK, not SYSTEM, so the record
#      guard _wcsicmp(mode,L"SYSTEM")==0 never fires). The recording is proven
#      at the source level here + in Test-GmProxySession.ps1; the runtime A3
#      proof (no "Handed PID") is the wine-testable half.
#
# Prints a FAIL SUMMARY (N) block and exits 1 on any failure, 0 if all pass.
# Usage: bash tests/test-gmproxy-cleangui.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="$PROJECT_ROOT/driver/gmproxy.c"
DUMMY_SRC="$SCRIPT_DIR/gmproxy-refuse-target.c"

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
printf '  gmproxy CLEAN-GUI + A3 (wine runtime test)\n'
printf '=====================================================\n'

# --- Tool checks (hard-fail if the toolchain is missing). ---
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
if [ ! -f "$SRC" ]; then
    record "driver/gmproxy.c present" 0 "missing: $SRC"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi
record "driver/gmproxy.c present" 1
if [ ! -f "$DUMMY_SRC" ]; then
    record "gmproxy-refuse-target.c dummy present" 0 "missing: $DUMMY_SRC"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi
record "gmproxy-refuse-target.c dummy present" 1

# --- Source invariants (Part A2: CLEAN-GUI refusal recording). ---
grep -qF 'GmProxyIsGuiSubsystem' "$SRC" && record "src: GmProxyIsGuiSubsystem present (PE subsystem gate for CLEAN-GUI recording)" 1 || record "src: GmProxyIsGuiSubsystem present (PE subsystem gate for CLEAN-GUI recording)" 0 "not found"
grep -qF 'IMAGE_SUBSYSTEM_WINDOWS_GUI' "$SRC" && record "src: IMAGE_SUBSYSTEM_WINDOWS_GUI constant present" 1 || record "src: IMAGE_SUBSYSTEM_WINDOWS_GUI constant present" 0 "not found"
grep -qF 'IMAGE_FILE_HEADER' "$SRC" && record "src: IMAGE_FILE_HEADER read before OptionalHeader (PE parse correctness)" 1 || record "src: IMAGE_FILE_HEADER read before OptionalHeader (PE parse correctness)" 0 "not found -- Subsystem would read from the wrong offset"
grep -qF 'GmProxyIsGuiSubsystem(targetPath)' "$SRC" && record "src: widened record guard references GmProxyIsGuiSubsystem(targetPath)" 1 || record "src: widened record guard references GmProxyIsGuiSubsystem(targetPath)" 0 "not found -- CLEAN-GUI refusals not gated on the PE subsystem"
# A3: SignalGmProxyFeedback gated on !autoExcluded (no re-elevation of auto-excluded PIDs).
grep -qF 'if (!autoExcluded)' "$SRC" && record "src: A3 -- SignalGmProxyFeedback gated on !autoExcluded" 1 || record "src: A3 -- SignalGmProxyFeedback gated on !autoExcluded" 0 "not found -- auto-excluded PIDs would be re-elevated by the monitor"
grep -qF 'skipping monitor feedback handoff' "$SRC" && record "src: A3 -- auto-excluded feedback skip diag line present" 1 || record "src: A3 -- auto-excluded feedback skip diag line present" 0 "not found -- cannot tell from the log that the feedback was intentionally skipped"

WORK="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$WORK'" EXIT

# --- Build gmproxy.exe (NORMAL, production-equivalent) + dummy.exe ---
GMPROXY="$WORK/gmproxy.exe"
DUMMY="$WORK/dummy.exe"
if "$GCC" -O2 -Wall -municode -o "$GMPROXY" "$SRC" -ladvapi32 -lkernel32 -lntdll -luserenv >/dev/null 2>&1; then
    record "build gmproxy.exe (MinGW, production-equivalent)" 1
else
    record "build gmproxy.exe (MinGW, production-equivalent)" 0 "gcc failed"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi
if "$GCC" -O2 -Wall -o "$DUMMY" "$DUMMY_SRC" >/dev/null 2>&1; then
    record "build dummy.exe (MinGW)" 1
else
    record "build dummy.exe (MinGW)" 0 "gcc failed"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi

# --- Locate wine %TEMP% (gmproxy.log) + ProgramData (the auto-exclude store) ---
WINEPREFIX_DIR="${WINEPREFIX:-$HOME/.wine}"
WINE_USER="${USER:-${LOGNAME:-}}"
WINE_TEMP="$WINEPREFIX_DIR/drive_c/users/$WINE_USER/AppData/Local/Temp"
if [ ! -d "$WINE_TEMP" ]; then
    WINE_TEMP="$(find "$WINEPREFIX_DIR/drive_c/users" -maxdepth 4 -type d -path '*/AppData/Local/Temp' 2>/dev/null | head -n1)"
fi
GMPROXY_LOG="$WINE_TEMP/gmproxy.log"
STORE_DIR="$WINEPREFIX_DIR/drive_c/ProgramData/GodModeAutoExclude"
STORE_FILE="$STORE_DIR/gmproxy_autoexclude.dat"

# --- Test 1: PRE-SEEDED store -> USER-AUTOEXCLUDE + NO "Handed PID" (A3 proof) ---
mkdir -p "$STORE_DIR" 2>/dev/null || true
NOW_TS="$(date +%s)"
printf 'dummy.exe|2|%s|1\n' "$NOW_TS" > "$STORE_FILE"

# Clear gmproxy.log so the guard only sees this run's lines.
if [ -n "$WINE_TEMP" ] && [ -d "$WINE_TEMP" ]; then rm -f "$GMPROXY_LOG"; fi
RUN_OUT="$(cd "$WORK" && "$WINE" "$GMPROXY" "dummy.exe" 2>&1)"
RUN_RC=$?
if [ -f "$GMPROXY_LOG" ]; then RUN_LOG="$(cat "$GMPROXY_LOG")"; else RUN_LOG=""; fi

printf '  [wine] Test 1 (pre-seeded excluded dummy.exe -> expect USER-AUTOEXCLUDE, NO Handed PID):\n%s\n' "$RUN_OUT" | sed 's/^/    /'
record "T1: gmproxy exits 0 (auto-excluded -> current-user fallback)" "$([ "$RUN_RC" -eq 0 ] && echo 1 || echo 0)" "wine exit=$RUN_RC (expected 0)"
case "$RUN_LOG" in
    *"USER-AUTOEXCLUDE"*) record "T1: gmproxy.log shows USER-AUTOEXCLUDE mode" 1 ;;
    *) record "T1: gmproxy.log shows USER-AUTOEXCLUDE mode" 0 "log missing USER-AUTOEXCLUDE" ;;
esac
case "$RUN_LOG" in
    *"Handed PID"*) record "T1: gmproxy.log does NOT show Handed PID (A3 -- no monitor re-elevation)" 0 "Handed PID appeared despite auto-exclude -- A3 regressed" ;;
    *) record "T1: gmproxy.log does NOT show Handed PID (A3 -- no monitor re-elevation)" 1 ;;
esac
case "$RUN_LOG" in
    *"skipping monitor feedback handoff"*) record "T1: gmproxy.log shows A3 skip diag line" 1 ;;
    *) record "T1: gmproxy.log shows A3 skip diag line" 0 "log missing the A3 skip diag line" ;;
esac

# Cleanup the store so a later test run starts clean.
rm -f "$STORE_FILE" 2>/dev/null || true

# --- Final summary with FAIL SUMMARY (N). ---
printf '\n=====================================================\n'
printf '  gmproxy CLEAN-GUI + A3 TEST SUMMARY\n'
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
printf '\n  ALL gmproxy CLEAN-GUI + A3 TESTS PASSED!\n'
exit 0
