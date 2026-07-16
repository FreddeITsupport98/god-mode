#!/usr/bin/env bash
# run-regressions.sh -- bind all God-Mode regression tests into one run.
#
# Runs, in order:
#   1. shellcheck on every .sh in tests/ (including this binder)
#   2. MinGW compile + wine run of the C guard-logic test (Test-GmHookFix.c)
#   3. PowerShell regression suites via pwsh:
#        - Test-GodModeCrashFix.ps1  (the 0xC0000005 crash-fix regression)
#        - Test-Suite.ps1            (DNSGuard / God-Mode structure suite)
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
    for suite in Test-GodModeCrashFix.ps1 Test-Suite.ps1; do
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
