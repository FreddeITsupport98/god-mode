#!/usr/bin/env bash
# test-gmproxy-force-system.sh -- wine RUNTIME proof of gmproxy's Detector B
# RECORDING path (count -> threshold -> excluded -> reason) for BOTH refusal
# flavors (CLEAN-GUI = Win11 notepad case, and CRASH), plus the end-to-end
# USER-AUTOEXCLUDE handoff on the NEXT (production) launch.
#
# Why a seam is needed: wine has NO real SYSTEM token, so a gmproxy launch
# under wine takes the graceful current-user fallback (launchMode=FALLBACK, not
# SYSTEM). The production recording guard is _wcsicmp(mode,L"SYSTEM")==0, which
# NEVER fires under wine -- so the count->threshold->excluded transition was
# only source-level proven (Test-GmProxySession.ps1) and the runtime A3 proof
# (test-gmproxy-cleangui.sh) could only assert USER-AUTOEXCLUDE on a PRE-SEEDED
# store, not the recording that POPULATES it. This test closes that gap.
#
# GMPROXY_TEST_FORCE_SYSTEM_MODE is a COMPILE-TIME test double (mirrors
# GMPROXY_TEST_FORCE_SESSION0): when defined, recordAsSystem=TRUE so the
# recording path fires under wine regardless of the real (FALLBACK) launch mode.
# The PRODUCTION build (driver/build.ps1) does NOT define it, so the shipped
# gmproxy.exe is byte-for-byte unaffected. This test also asserts that
# invariant (build.ps1 must NOT reference the macro).
#
# Test matrix (one GUI-subsystem dummy, exit code selects the flavor):
#   T1 CLEAN-GUI: pre-seed cleangui.exe|1|now|0 -> run FORCED gmproxy with the
#      GUI dummy (exit 0) -> store becomes cleangui.exe|2|now|1|G  (count 1->2,
#      excluded 0->1, reason 'G'). Proves CLEAN-GUI recording at runtime.
#   T2 END-TO-END: run the PRODUCTION (NORMAL) gmproxy with the now-excluded
#      store + cleangui.exe -> logs USER-AUTOEXCLUDE (the production build
#      honors the store the FORCED build wrote) AND does NOT re-record (mode
#      USER-AUTOEXCLUDE != SYSTEM -> store count stays 2). Proves the
#      force-system-recorded store is read correctly by the production binary
#      (5-field format backward/forward compatible) and A3 holds (no Handed PID).
#   T3 CRASH: reset store -> pre-seed crashgui.exe|1|now|0 -> run FORCED gmproxy
#      with "crashgui.exe 1" (exit 1) -> store becomes crashgui.exe|2|now|1|C
#      (reason 'C'). Proves CRASH recording at runtime.
#
# The GUI dummy (gmproxy-cleangui-target.c) is compiled with -Wl,--subsystem,
# windows so GmProxyIsGuiSubsystem reads IMAGE_SUBSYSTEM_WINDOWS_GUI -> the
# CLEAN-GUI guard (code==0 && GUI) fires. The store mutation to reason 'G' is
# itself the proof the dummy is a GUI PE (GmProxyIsGuiSubsystem returned TRUE).
#
# Prints a FAIL SUMMARY (N) block and exits 1 on any failure, 0 if all pass.
# Usage: bash tests/test-gmproxy-force-system.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="$PROJECT_ROOT/driver/gmproxy.c"
DUMMY_SRC="$SCRIPT_DIR/gmproxy-cleangui-target.c"
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
printf '  gmproxy RECORDING (force-system seam, wine runtime)\n'
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
if [ ! -f "$SRC" ]; then
    record "driver/gmproxy.c present" 0 "missing: $SRC"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi
record "driver/gmproxy.c present" 1
if [ ! -f "$DUMMY_SRC" ]; then
    record "gmproxy-cleangui-target.c dummy present" 0 "missing: $DUMMY_SRC"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi
record "gmproxy-cleangui-target.c dummy present" 1

# --- Source invariants (the seam + reason field must be present before we
#     trust a build / run). ---
grep -qF '#ifdef GMPROXY_TEST_FORCE_SYSTEM_MODE' "$SRC" && record "src: GMPROXY_TEST_FORCE_SYSTEM_MODE compile-time seam present (#ifdef)" 1 || record "src: GMPROXY_TEST_FORCE_SYSTEM_MODE compile-time seam present (#ifdef)" 0 "not found -- recording cannot be exercised under wine"
grep -qF 'BOOL recordAsSystem = TRUE;' "$SRC" && record "src: seam forces recordAsSystem=TRUE" 1 || record "src: seam forces recordAsSystem=TRUE" 0 "not found"
grep -qF 'BOOL recordAsSystem = (_wcsicmp(mode, L"SYSTEM") == 0);' "$SRC" && record "src: production #else branch keeps _wcsicmp(mode,L\"SYSTEM\") guard (byte-for-byte original)" 1 || record "src: production #else branch keeps _wcsicmp(mode,L\"SYSTEM\") guard (byte-for-byte original)" 0 "not found -- production recording guard regressed"
# Reason field: the record call passes 'C' or 'G', and the write format emits it.
grep -qF "GmProxyAutoExcludeRecord(base, (code != 0) ? L'C' : L'G')" "$SRC" && record "src: record call passes reason 'C' (crash) / 'G' (clean-gui)" 1 || record "src: record call passes reason 'C' / 'G'" 0 "not found -- reason flavor not threaded into the record"
grep -qF '|%lc' "$SRC" && record "src: store write emits the 5th reason field (%lc)" 1 || record "src: store write emits the 5th reason field (%lc)" 0 "not found -- reason not persisted"
grep -qF "if (reason) *reason = L'?';" "$SRC" && record "src: parser defaults reason to '?' (old 4-field lines backward compat)" 1 || record "src: parser defaults reason to '?' (old 4-field lines backward compat)" 0 "not found -- old 4-field store lines would not parse"
# job=disabled branch records ONLY under the seam (production never records there).
grep -qF '#ifdef GMPROXY_TEST_FORCE_SYSTEM_MODE' "$SRC" && grep -qF 'job=disabled' "$SRC" && record "src: job=disabled branch guarded by the force-system seam (production never records there)" 1 || record "src: job=disabled branch guarded by the force-system seam" 0 "not found -- wine job stubs would make recording unreachable"
# CRITICAL invariant: the PRODUCTION build must NOT define either test seam.
if [ -f "$BUILD_PS1" ]; then
    if grep -qF 'GMPROXY_TEST_FORCE_SYSTEM_MODE' "$BUILD_PS1"; then
        record "build.ps1 does NOT define the force-system seam (production binary unaffected)" 0 "driver/build.ps1 references GMPROXY_TEST_FORCE_SYSTEM_MODE -- production build would force-record in the field"
    else
        record "build.ps1 does NOT define the force-system seam (production binary unaffected)" 1
    fi
else
    record "driver/build.ps1 present" 0 "missing"
fi

WORK="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$WORK'" EXIT

# --- Build gmproxy.exe: FORCED (-DGMPROXY_TEST_FORCE_SYSTEM_MODE=1 -> record). ---
FORCED="$WORK/gmproxy_forced.exe"
if "$GCC" -O2 -Wall -municode -DGMPROXY_TEST_FORCE_SYSTEM_MODE=1 -o "$FORCED" "$SRC" -ladvapi32 -lkernel32 -lntdll -luserenv >/dev/null 2>&1; then
    record "build gmproxy.exe FORCED (MinGW, -DGMPROXY_TEST_FORCE_SYSTEM_MODE=1)" 1
else
    record "build gmproxy.exe FORCED (MinGW, -DGMPROXY_TEST_FORCE_SYSTEM_MODE=1)" 0 "gcc failed"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi

# --- Build gmproxy.exe: NORMAL (production-equivalent, no test macro). ---
NORMAL="$WORK/gmproxy_normal.exe"
if "$GCC" -O2 -Wall -municode -o "$NORMAL" "$SRC" -ladvapi32 -lkernel32 -lntdll -luserenv >/dev/null 2>&1; then
    record "build gmproxy.exe NORMAL (MinGW, production-equivalent)" 1
else
    record "build gmproxy.exe NORMAL (MinGW, production-equivalent)" 0 "gcc failed"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi

# --- Build the GUI-subsystem dummy (cleangui.exe) + a copy (crashgui.exe). ---
DUMMY_GUI="$WORK/cleangui.exe"
DUMMY_CRASH="$WORK/crashgui.exe"
if "$GCC" -O2 -Wall -Wl,--subsystem,windows -o "$DUMMY_GUI" "$DUMMY_SRC" >/dev/null 2>&1; then
    record "build GUI dummy cleangui.exe (MinGW, --subsystem,windows)" 1
else
    record "build GUI dummy cleangui.exe (MinGW, --subsystem,windows)" 0 "gcc failed"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi
cp "$DUMMY_GUI" "$DUMMY_CRASH" 2>/dev/null
[ -f "$DUMMY_CRASH" ] && record "copy GUI dummy -> crashgui.exe (same PE, distinct base name)" 1 || record "copy GUI dummy -> crashgui.exe (same PE, distinct base name)" 0 "cp failed"
# Subsystem detection (informational; the hard GUI proof is T1's reason='G' store
# mutation -- GmProxyIsGuiSubsystem returned TRUE -> the dummy IS a GUI PE).
sub_hint="(unknown)"
if file "$DUMMY_GUI" 2>/dev/null | grep -qi '(GUI)'; then sub_hint="file:(GUI)"
elif objdump -x "$DUMMY_GUI" 2>/dev/null | grep -qi 'Windows GUI'; then sub_hint="objdump:Windows GUI"
elif objdump -x "$DUMMY_GUI" 2>/dev/null | grep -qi 'Subsystem.*[[:space:]]2\b'; then sub_hint="objdump:Subsystem 2"
fi
printf '  [info] GUI dummy subsystem detection: %s\n' "$sub_hint"

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

# run_gmproxy <exe> <args...> -> sets RUN_OUT, RUN_RC, RUN_LOG. Clears gmproxy.log
# first so the guard only sees this run's lines. The dummy is passed as a
# RELATIVE name so gmproxy's CreateHardLinkW resolves it against the wine CWD
# ($WORK), matching how the real IFEO path hands gmproxy a target name.
run_gmproxy() {
    local exe="$1"; shift
    if [ -n "$WINE_TEMP" ] && [ -d "$WINE_TEMP" ]; then rm -f "$GMPROXY_LOG"; fi
    RUN_OUT="$(cd "$WORK" && "$WINE" "$exe" "$@" 2>&1)"
    RUN_RC=$?
    if [ -f "$GMPROXY_LOG" ]; then RUN_LOG="$(cat "$GMPROXY_LOG")"; else RUN_LOG=""; fi
}

store_line() {  # store_line <base> <count> <excluded> <reason> -> 1 if a matching line exists
    [ -f "$STORE_FILE" ] || return 1
    local base="$1" count="$2" excluded="$3" reason="$4"
    # The store is written by gmproxy's fwprintf in TEXT mode -> CRLF line endings
    # (\r\n) under MinGW. Strip CR before grepping so the trailing $ anchor
    # matches (G$ / C$) regardless of LF vs CRLF. The production parsers (gmproxy
    # _wtoi/wcstoul stop at '|'; the reason reader excludes \r/\n; gmhook _wtoi;
    # PS -split '\|' -> parts[3]) all handle CRLF correctly already.
    tr -d '\r' < "$STORE_FILE" | grep -Eq "^${base}\|${count}\|[0-9]+\|${excluded}\|${reason}\$"
}

mkdir -p "$STORE_DIR" 2>/dev/null || true
NOW_TS="$(date +%s)"

# --- T1: CLEAN-GUI recording (pre-seed count=1 excluded=0 -> run FORCED -> count=2 excluded=1 reason=G) ---
rm -f "$STORE_FILE" 2>/dev/null || true
printf 'cleangui.exe|1|%s|0\n' "$NOW_TS" > "$STORE_FILE"
store_line 'cleangui\.exe' 1 0 '...' >/dev/null 2>&1
run_gmproxy "$FORCED" cleangui.exe
printf '  [wine] T1 (FORCED + GUI dummy exit 0 -> expect store cleangui.exe|2|..|1|G):\n%s\n' "$RUN_OUT" | sed 's/^/    /'
record "T1: FORCED gmproxy exits 0 (current-user fallback launch)" "$([ "$RUN_RC" -eq 0 ] && echo 1 || echo 0)" "wine exit=$RUN_RC (expected 0)"
record "T1: store became cleangui.exe|2|<ts>|1|G (CLEAN-GUI recorded, count 1->2, excluded, reason G)" "$(store_line 'cleangui\.exe' 2 1 'G' && echo 1 || echo 0)" "store did not become |2|..|1|G -- CLEAN-GUI recording did not fire (store: $(cat "$STORE_FILE" 2>/dev/null))"

# --- T2: END-TO-END -- production NORMAL build honors the FORCED-recorded store ---
run_gmproxy "$NORMAL" cleangui.exe
printf '  [wine] T2 (NORMAL + excluded store -> expect USER-AUTOEXCLUDE, NO Handed PID, store unchanged):\n%s\n' "$RUN_OUT" | sed 's/^/    /'
record "T2: NORMAL gmproxy exits 0 (auto-excluded -> current-user fallback)" "$([ "$RUN_RC" -eq 0 ] && echo 1 || echo 0)" "wine exit=$RUN_RC (expected 0)"
case "$RUN_LOG" in
    *"USER-AUTOEXCLUDE"*) record "T2: NORMAL gmproxy.log shows USER-AUTOEXCLUDE (production build honors the force-system-recorded store)" 1 ;;
    *) record "T2: NORMAL gmproxy.log shows USER-AUTOEXCLUDE (production build honors the force-system-recorded store)" 0 "log missing USER-AUTOEXCLUDE -- the 5-field store from the FORCED build was not read correctly by the production binary" ;;
esac
case "$RUN_LOG" in
    *"Handed PID"*) record "T2: NORMAL gmproxy.log does NOT show Handed PID (A3 -- auto-excluded launch not re-elevated)" 0 "Handed PID appeared despite auto-exclude -- A3 regressed" ;;
    *) record "T2: NORMAL gmproxy.log does NOT show Handed PID (A3 -- auto-excluded launch not re-elevated)" 1 ;;
esac
record "T2: store unchanged by the NORMAL run (count stays 2, reason G -- production does not re-record USER-AUTOEXCLUDE)" "$(store_line 'cleangui\.exe' 2 1 'G' && echo 1 || echo 0)" "store changed or lost the |2|..|1|G line -- production build re-recorded or corrupted the store (store: $(cat "$STORE_FILE" 2>/dev/null))"

# --- T3: CRASH recording (reset -> pre-seed crashgui.exe|1|..|0 -> run FORCED with exit 1 -> reason C) ---
rm -f "$STORE_FILE" 2>/dev/null || true
printf 'crashgui.exe|1|%s|0\n' "$NOW_TS" > "$STORE_FILE"
run_gmproxy "$FORCED" crashgui.exe 1
printf '  [wine] T3 (FORCED + GUI dummy exit 1 -> expect store crashgui.exe|2|..|1|C):\n%s\n' "$RUN_OUT" | sed 's/^/    /'
record "T3: FORCED gmproxy exits 0 (launcher itself exits 0; the dummy child exited 1)" "$([ "$RUN_RC" -eq 0 ] && echo 1 || echo 0)" "wine exit=$RUN_RC (expected 0 -- gmproxy observes the child, its own exit is 0)"
record "T3: store became crashgui.exe|2|<ts>|1|C (CRASH recorded, count 1->2, excluded, reason C)" "$(store_line 'crashgui\.exe' 2 1 'C' && echo 1 || echo 0)" "store did not become |2|..|1|C -- CRASH recording did not fire (store: $(cat "$STORE_FILE" 2>/dev/null))"

# Cleanup the store so a later test run starts clean.
rm -f "$STORE_FILE" 2>/dev/null || true

# --- Final summary with FAIL SUMMARY (N). ---
printf '\n=====================================================\n'
printf '  gmproxy RECORDING (force-system) TEST SUMMARY\n'
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
printf '\n  ALL gmproxy RECORDING (force-system) TESTS PASSED!\n'
exit 0
