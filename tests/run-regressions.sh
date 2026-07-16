#!/usr/bin/env bash
# run-regressions.sh -- bind all God-Mode regression tests into one run.
#
# Runs, in order:
#   1. shellcheck on every .sh in tests/ (including this binder)
#   2. MinGW compile + wine run of the C guard-logic test (Test-GmHookFix.c)
#   3. PowerShell regression suites via pwsh:
#        - Test-GodModeCrashFix.ps1  (the 0xC0000005 crash-fix regression)
#        - Test-IfeoElevation.ps1    (IFEO + gmproxy normal-program elevation regression)
#        - Test-Suite.ps1            (DNSGuard / God-Mode structure suite)
#        - Test-GmProxySession.ps1   (gmproxy session-correct SYSTEM-token launch +
#                                    monitor blank-owner kill guard regression +
#                                    durable gmproxy.log diagnostics + gmproxy<->monitor
#                                    named-pipe PID handoff for in-place elevation)
#   4. wine smoke test: loads the built gmhook.dll into pwsh.exe + chrome.exe
#      stubs and asserts the CreateProcessW IAT hook is NOT installed in shell
#      hosts (tests/test-shell-host-exclusion.sh) -- binary-level check that
#      catches IsShellLauncherProcess regressions BEFORE deploying to the VM.
#   4b. wine smoke test --regression-mode (negative direction): builds a BROKEN
#      gmhook.dll (%ls->%s path) and asserts the runtime wide-format guards FAIL
#      on it -- proves the guard catches a broken build, not just that a correct
#      build passes (tests/test-shell-host-exclusion.sh --regression-mode).
#   5. gmproxy session-fix build + invariant test (tests/test-gmproxy-session.sh):
#      MinGW cross-compile of gmproxy.c proves the session-correctness + graceful-
#      fallback code BUILDS and yields a PE binary (catches undeclared symbols /
#      wrong typedefs before deploying to the VM). Also grep-proves the durable
#      gmproxy.log diagnostics + SignalGmProxyFeedback named-pipe handoff symbols.
#   6. syntax_check.ps1 honesty test (tests/test-syntax-check.sh): proves the upgraded
#      checker exits 0 on a clean .ps1 and exits 1 + prints a FAIL SUMMARY (N) block on
#      a broken .ps1 (unterminated function) and a broken .c (int main({) -- guarding
#      against the old $script: scoping bug that always printed "Failed: 0".
#
# Prints a FAIL SUMMARY (N) block and exits 1 on any failure, 0 if all pass.
# Usage: bash tests/run-regressions.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Auto-chmod executable all scripts in tests/ for convenience.
find "$SCRIPT_DIR" -maxdepth 1 -type f \( -name '*.sh' -o -name '*.ps1' \) -exec chmod +x {} + 2>/dev/null || true

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

# 1. shellcheck on shell scripts.
if command -v shellcheck >/dev/null 2>&1; then
    while IFS= read -r f; do
        if shellcheck -S warning "$f" >/dev/null 2>&1; then
            record "shellcheck $(basename "$f")" 1
        else
            record "shellcheck $(basename "$f")" 0 "run: shellcheck $f"
        fi
    done < <(find "$SCRIPT_DIR" -maxdepth 1 -type f -name '*.sh')
else
    record "shellcheck available" 0 "shellcheck not installed"
fi

# 2. C guard-logic test: MinGW compile + wine run.
ctest_src="$SCRIPT_DIR/Test-GmHookFix.c"
ctest_exe="$SCRIPT_DIR/Test-GmHookFix.exe"
if [ ! -f "$ctest_src" ]; then
    record "Test-GmHookFix.c present" 0 "missing"
elif ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    record "MinGW (x86_64-w64-mingw32-gcc) available" 0 "not installed; C compile/run skipped"
else
    if x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -o "$ctest_exe" "$ctest_src" >/dev/null 2>&1; then
        record "C: Test-GmHookFix.c compiles (MinGW)" 1
        if command -v wine >/dev/null 2>&1; then
            ctest_out="$(wine "$ctest_exe" 2>&1)"
            ctest_rc=$?
            if [ "$ctest_rc" -eq 0 ] && printf '%s' "$ctest_out" | grep -q 'ALL ASSERTIONS PASSED'; then
                record "C: Test-GmHookFix.exe passes (wine)" 1
            else
                record "C: Test-GmHookFix.exe passes (wine)" 0 "wine exit=$ctest_rc"
            fi
        else
            record "wine available" 0 "wine not installed; C run skipped"
        fi
    else
        record "C: Test-GmHookFix.c compiles (MinGW)" 0 "gcc failed"
    fi
    rm -f "$ctest_exe"
fi

# 3. PowerShell regression suites via pwsh.
if ! command -v pwsh >/dev/null 2>&1; then
    record "pwsh available" 0 "pwsh not installed"
else
    for suite in Test-GodModeCrashFix.ps1 Test-IfeoElevation.ps1 Test-Suite.ps1 Test-GmProxySession.ps1; do
        f="$SCRIPT_DIR/$suite"
        if [ ! -f "$f" ]; then
            record "pwsh $suite" 0 "missing"
            continue
        fi
        log="$(mktemp)"
        if pwsh -NoProfile -File "$f" >"$log" 2>&1; then
            record "pwsh $suite" 1
            rm -f "$log"
        else
            rc=$?
            record "pwsh $suite" 0 "exit=$rc (log: $log)"
        fi
    done
fi

# 4. wine smoke test: gmhook.dll shell-host exclusion (binary-level).
smoke="$SCRIPT_DIR/test-shell-host-exclusion.sh"
if [ ! -f "$smoke" ]; then
    record "test-shell-host-exclusion.sh present" 0 "missing"
else
    log="$(mktemp)"
    if bash "$smoke" >"$log" 2>&1; then
        record "wine smoke: gmhook.dll not hooked in pwsh.exe (chrome.exe control hooked)" 1
        rm -f "$log"
    else
        rc=$?
        record "wine smoke: gmhook.dll not hooked in pwsh.exe (chrome.exe control hooked)" 0 "exit=$rc (log: $log)"
    fi
fi

# 4b. wine smoke test --regression-mode (negative direction): broken %ls->%s
#     build must FAIL the runtime wide-format guards (proves the guard catches a
#     broken build, not just that a correct build passes).
if [ ! -f "$smoke" ]; then
    record "wine smoke --regression-mode present" 0 "test-shell-host-exclusion.sh missing"
else
    log="$(mktemp)"
    if bash "$smoke" --regression-mode >"$log" 2>&1; then
        record "wine smoke --regression-mode: broken %ls->%s build FAILS the guards" 1
        rm -f "$log"
    else
        rc=$?
        record "wine smoke --regression-mode: broken %ls->%s build FAILS the guards" 0 "exit=$rc (log: $log)"
    fi
fi

# 5. gmproxy session-fix build + invariant test (MinGW cross-compile proof).
gmsess="$SCRIPT_DIR/test-gmproxy-session.sh"
if [ ! -f "$gmsess" ]; then
    record "test-gmproxy-session.sh present" 0 "missing"
else
    log="$(mktemp)"
    if bash "$gmsess" >"$log" 2>&1; then
        record "gmproxy session-fix: compiles + invariants (MinGW)" 1
        rm -f "$log"
    else
        rc=$?
        record "gmproxy session-fix: compiles + invariants (MinGW)" 0 "exit=$rc (log: $log)"
    fi
fi

# 6. syntax_check.ps1 honesty test (clean -> exit 0; broken .ps1/.c -> exit 1 + FAIL SUMMARY).
synhonest="$SCRIPT_DIR/test-syntax-check.sh"
if [ ! -f "$synhonest" ]; then
    record "test-syntax-check.sh present" 0 "missing"
else
    log="$(mktemp)"
    if bash "$synhonest" >"$log" 2>&1; then
        record "syntax_check.ps1 honesty (clean=exit0, broken=exit1+FAIL SUMMARY)" 1
        rm -f "$log"
    else
        rc=$?
        record "syntax_check.ps1 honesty (clean=exit0, broken=exit1+FAIL SUMMARY)" 0 "exit=$rc (log: $log)"
    fi
fi

# Final summary with FAIL SUMMARY (N).
printf '\n=====================================================\n'
printf '  REGRESSION RUN SUMMARY\n'
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
printf '\n  ALL REGRESSION TESTS PASSED!\n'
exit 0
