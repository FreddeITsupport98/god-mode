#!/usr/bin/env bash
# test-gmproxy-autoexclude.sh -- wine RUNTIME proof of gmproxy's Detector B
# runtime SYSTEM-crash auto-exclude store (driver/gmproxy.c).
#
# The source-level pwsh test (Test-GmProxySession.ps1 section 24) checks the
# store symbols are WRITTEN DOWN; test-gmproxy-session.sh proves gmproxy.c still
# COMPILES. THIS test RUNS the freshly-built gmproxy.exe under wine and asserts
# the OBSERVED runtime behavior of the auto-exclude layer:
#   1. PRE-SEEDED store (dummy.exe crashCount=2 excluded=1 >= threshold) ->
#      gmproxy skips the SYSTEM token, launches the dummy as the current user
#      (graceful fallback), and logs MODE=USER-AUTOEXCLUDE. Exit 0. Proves a
#      known-SYSTEM-crashing base name is auto-de-elevated on the next launch.
#   2. CORRUPT store (garbage lines) -> gmproxy fail-opens (skips bad lines,
#      no exclusions), launches normally as the current user, NO USER-AUTOEXCLUDE
#      in the log. Exit 0. Proves a corrupt/ACL-denied store never blocks a launch.
#   3. --gm-reset-autoexclude CLI hook -> the store file is deleted (mutex-safe
#      reset). Proves menu [18]'s backing hook works at runtime.
#
# The store path is hardcoded C:\ProgramData\GodModeAutoExclude\gmproxy_autoexclude.dat
# in gmproxy.c; under wine C: maps to $WINEPREFIX/drive_c, so the bash-side path is
# $WINEPREFIX/drive_c/ProgramData/GodModeAutoExclude/gmproxy_autoexclude.dat.
#
# Prints a FAIL SUMMARY (N) block and exits 1 on any failure, 0 if all pass.
# Usage: bash tests/test-gmproxy-autoexclude.sh
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
printf '  gmproxy AUTO-EXCLUDE store (wine runtime test)\n'
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

# Source invariants (the auto-exclude machinery must be present before we trust a run).
grep -qF 'GmProxyAutoExcludeQuery' "$SRC" && record "src: GmProxyAutoExcludeQuery present" 1 || record "src: GmProxyAutoExcludeQuery present" 0 "not found"
grep -qF 'USER-AUTOEXCLUDE' "$SRC" && record "src: USER-AUTOEXCLUDE mode present" 1 || record "src: USER-AUTOEXCLUDE mode present" 0 "not found"
grep -qF -- '--gm-reset-autoexclude' "$SRC" && record "src: --gm-reset-autoexclude hook present" 1 || record "src: --gm-reset-autoexclude hook present" 0 "not found"

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

run_gmproxy() {  # <dummy_rel> -> sets RUN_OUT, RUN_RC, RUN_LOG. Clears gmproxy.log first.
    if [ -n "$WINE_TEMP" ] && [ -d "$WINE_TEMP" ]; then rm -f "$GMPROXY_LOG"; fi
    RUN_OUT="$(cd "$WORK" && "$WINE" "$GMPROXY" "$1" 2>&1)"
    RUN_RC=$?
    if [ -f "$GMPROXY_LOG" ]; then RUN_LOG="$(cat "$GMPROXY_LOG")"; else RUN_LOG=""; fi
}

# --- Test 1: PRE-SEEDED store -> USER-AUTOEXCLUDE (auto-de-elevate) ---
mkdir -p "$STORE_DIR" 2>/dev/null || true
NOW_TS="$(date +%s)"
printf 'dummy.exe|2|%s|1\n' "$NOW_TS" > "$STORE_FILE"
run_gmproxy "dummy.exe"
printf '  [wine] Test 1 (pre-seeded excluded dummy.exe -> expect USER-AUTOEXCLUDE, exit 0):\n%s\n' "$RUN_OUT" | sed 's/^/    /'
record "T1: gmproxy exits 0 (auto-excluded -> current-user fallback)" "$([ "$RUN_RC" -eq 0 ] && echo 1 || echo 0)" "wine exit=$RUN_RC (expected 0)"
case "$RUN_LOG" in
    *"USER-AUTOEXCLUDE"*) record "T1: gmproxy.log shows USER-AUTOEXCLUDE mode" 1 ;;
    *) record "T1: gmproxy.log shows USER-AUTOEXCLUDE mode" 0 "log missing USER-AUTOEXCLUDE" ;;
esac
case "$RUN_LOG" in
    *"[GM-PROXY] AUTO-EXCLUDE:"*) record "T1: gmproxy.log shows AUTO-EXCLUDE diag line" 1 ;;
    *) record "T1: gmproxy.log shows AUTO-EXCLUDE diag line" 0 "log missing AUTO-EXCLUDE diag" ;;
esac

# --- Test 2: CORRUPT store -> fail-open (no exclusion, normal launch, NO USER-AUTOEXCLUDE) ---
printf 'this is garbage\n!!!not a valid line!!!\n|||\n' > "$STORE_FILE"
run_gmproxy "dummy.exe"
printf '  [wine] Test 2 (corrupt store -> expect fail-open normal launch, exit 0, NO USER-AUTOEXCLUDE):\n%s\n' "$RUN_OUT" | sed 's/^/    /'
record "T2: gmproxy exits 0 (corrupt store fail-open)" "$([ "$RUN_RC" -eq 0 ] && echo 1 || echo 0)" "wine exit=$RUN_RC (expected 0)"
case "$RUN_LOG" in
    *"USER-AUTOEXCLUDE"*) record "T2: gmproxy.log does NOT show USER-AUTOEXCLUDE (corrupt store fail-open)" 0 "USER-AUTOEXCLUDE appeared despite a corrupt store -- fail-open regressed" ;;
    *) record "T2: gmproxy.log does NOT show USER-AUTOEXCLUDE (corrupt store fail-open)" 1 ;;
esac

# --- Test 3: --gm-reset-autoexclude -> store file deleted ---
printf 'dummy.exe|2|%s|1\n' "$NOW_TS" > "$STORE_FILE"
[ -f "$STORE_FILE" ] && record "T3: store file present before reset" 1 || record "T3: store file present before reset" 0 "store file not created"
RESET_OUT="$(cd "$WORK" && "$WINE" "$GMPROXY" "--gm-reset-autoexclude" 2>&1)"
RESET_RC=$?
printf '  [wine] Test 3 (--gm-reset-autoexclude -> expect store deleted, exit 0):\n%s\n' "$RESET_OUT" | sed 's/^/    /'
record "T3: gmproxy --gm-reset-autoexclude exits 0" "$([ "$RESET_RC" -eq 0 ] && echo 1 || echo 0)" "wine exit=$RESET_RC (expected 0)"
case "$RESET_OUT" in
    *"AUTO-EXCLUDE store reset"*) record "T3: reset diag line present" 1 ;;
    *) record "T3: reset diag line present" 0 "reset diag missing" ;;
esac
if [ -f "$STORE_FILE" ]; then
    record "T3: store file deleted by --gm-reset-autoexclude" 0 "store file still present after reset"
else
    record "T3: store file deleted by --gm-reset-autoexclude" 1
fi

# Cleanup the store so a later test run starts clean.
rm -f "$STORE_FILE" 2>/dev/null || true

# --- Final summary with FAIL SUMMARY (N). ---
printf '\n=====================================================\n'
printf '  gmproxy AUTO-EXCLUDE TEST SUMMARY\n'
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
printf '\n  ALL gmproxy AUTO-EXCLUDE TESTS PASSED!\n'
exit 0
