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

# Build: MinGW cross-compile (mirrors driver/build.ps1 Build-WithMinGW for gmproxy).
if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    record "MinGW (x86_64-w64-mingw32-gcc) available" 0 "not installed; compile skipped"
else
    out="$SCRIPT_DIR/gmproxy_session_test.exe"
    build_log="$(mktemp)"
    if x86_64-w64-mingw32-gcc -O2 -Wall -municode -o "$out" "$SRC" -ladvapi32 -lkernel32 -lntdll >"$build_log" 2>&1; then
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
