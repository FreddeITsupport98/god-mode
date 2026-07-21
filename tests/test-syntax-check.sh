#!/usr/bin/env bash
# test-syntax-check.sh -- prove the upgraded syntax_check.ps1 is HONEST: it exits 0 on
# clean input and exits 1 + prints a FAIL SUMMARY (N) block on broken input (a broken
# .ps1 with an unterminated function and a broken .c with "int main({").
#
# This guards against the old $script: scoping bug where Add-Failure's arrays never
# aggregated and the checker ALWAYS printed "Failed: 0 / [SUCCESS]" regardless of real
# [ERROR] findings. With honest aggregation (summary derives from $FileFailures) + the
# new C-compile check, a broken file MUST flip the exit code to 1 and emit a FAIL SUMMARY.
#
# Prints a FAIL SUMMARY (N) block and exits 1 on any failure, 0 if all pass.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/../syntax_check.ps1"

pass_count=0
fail_count=0
fail_names=()
RUN_LOG=""
RUN_RC=0

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

if [ ! -f "$CHECK" ]; then
    record "syntax_check.ps1 present" 0 "missing: $CHECK"
    printf '\n  FAIL SUMMARY (%s)\n    - syntax_check.ps1 present\n' "$fail_count"
    exit 1
fi
record "syntax_check.ps1 present" 1

if ! command -v pwsh >/dev/null 2>&1; then
    record "pwsh available" 0 "pwsh not installed; cannot run syntax_check.ps1"
    printf '\n  FAIL SUMMARY (%s)\n    - pwsh available\n' "$fail_count"
    exit 1
fi
record "pwsh available" 1

# run_check <scandir>: run syntax_check.ps1 against scandir; sets RUN_LOG + RUN_RC.
run_check() {
    RUN_LOG="$(mktemp)"
    if pwsh -NoProfile -File "$CHECK" -ScanDir "$1" >"$RUN_LOG" 2>&1; then
        RUN_RC=0
    else
        RUN_RC=$?
    fi
}

# Scenario 1: a clean .ps1 -> exit 0 + [SUCCESS].
d1="$(mktemp -d)"
cat >"$d1/clean.ps1" <<'PS_EOF'
function Invoke-CleanTest {
    param([string]$Message)
    Write-Output $Message
}
PS_EOF
run_check "$d1"
if [ "$RUN_RC" -eq 0 ] && grep -Fq '[SUCCESS]' "$RUN_LOG"; then
    record "clean .ps1 -> exit 0 + [SUCCESS]" 1
else
    record "clean .ps1 -> exit 0 + [SUCCESS]" 0 "exit=$RUN_RC (log: $RUN_LOG)"
fi
rm -rf "$d1"; rm -f "$RUN_LOG"

# Scenario 2: a broken .ps1 (unterminated function) -> exit 1 + FAIL SUMMARY.
d2="$(mktemp -d)"
cat >"$d2/broken.ps1" <<'PS_EOF'
function Invoke-BrokenTest {
    # missing closing brace on purpose
PS_EOF
run_check "$d2"
if [ "$RUN_RC" -ne 0 ] && grep -Fq 'FAIL SUMMARY' "$RUN_LOG"; then
    record "broken .ps1 -> exit 1 + FAIL SUMMARY" 1
else
    record "broken .ps1 -> exit 1 + FAIL SUMMARY" 0 "exit=$RUN_RC (log: $RUN_LOG)"
fi
rm -rf "$d2"; rm -f "$RUN_LOG"

# Scenario 3: a broken .c (int main({) -> exit 1 (C-brace heuristic and/or C-compile check).
d3="$(mktemp -d)"
cat >"$d3/broken.c" <<'C_EOF'
int main({
C_EOF
run_check "$d3"
if [ "$RUN_RC" -ne 0 ]; then
    record "broken .c -> exit 1" 1
else
    record "broken .c -> exit 1" 0 "exit=$RUN_RC (log: $RUN_LOG)"
fi
rm -rf "$d3"; rm -f "$RUN_LOG"

# Scenario 4: the parallelization symbols are present (auto thread count +
# Start-ThreadJob in syntax_check.ps1; nproc + GODMODE_JOBS + background jobs in
# run-regressions.sh). Additive source-invariant guards so a future edit cannot
# silently revert the speedup. The honesty scenarios above remain authoritative
# for exit-code behavior; this just guards the parallel plumbing is wired in.
SC="$SCRIPT_DIR/../syntax_check.ps1"
RR="$SCRIPT_DIR/run-regressions.sh"
if grep -qF 'function Get-OptimalThreadCount' "$SC" 2>/dev/null; then
    record "syntax_check.ps1: Get-OptimalThreadCount defined (auto thread count)" 1
else
    record "syntax_check.ps1: Get-OptimalThreadCount defined (auto thread count)" 0 "missing"
fi
if grep -qF 'Start-ThreadJob' "$SC" 2>/dev/null; then
    record "syntax_check.ps1: Start-ThreadJob used (parallel toolchain)" 1
else
    record "syntax_check.ps1: Start-ThreadJob used (parallel toolchain)" 0 "missing"
fi
if grep -qF 'GODMODE_JOBS' "$SC" 2>/dev/null; then
    record 'syntax_check.ps1: honors $GODMODE_JOBS override' 1
else
    record 'syntax_check.ps1: honors $GODMODE_JOBS override' 0 "missing"
fi
if grep -qF 'Invoke-ParallelToolChecks' "$SC" 2>/dev/null; then
    record "syntax_check.ps1: Invoke-ParallelToolChecks helper defined" 1
else
    record "syntax_check.ps1: Invoke-ParallelToolChecks helper defined" 0 "missing"
fi
if grep -qE 'nproc|GODMODE_JOBS' "$RR" 2>/dev/null; then
    record "run-regressions.sh: auto job count (nproc + GODMODE_JOBS)" 1
else
    record "run-regressions.sh: auto job count (nproc + GODMODE_JOBS)" 0 "missing"
fi
if grep -qF 'sh_pids+=("$!")' "$RR" 2>/dev/null && grep -qF 'ps_pids+=("$!")' "$RR" 2>/dev/null; then
    record "run-regressions.sh: background jobs spawned (shellcheck + pwsh suites)" 1
else
    record "run-regressions.sh: background jobs spawned (shellcheck + pwsh suites)" 0 "missing sh_pids/ps_pids append"
fi
if grep -qF 'wait "${sh_pids[$idx]}"' "$RR" 2>/dev/null && grep -qF 'wait "${ps_pids[$idx]}"' "$RR" 2>/dev/null; then
    record "run-regressions.sh: per-pid wait + record after (parallel safe)" 1
else
    record "run-regressions.sh: per-pid wait + record after (parallel safe)" 0 "missing per-pid wait"
fi

# Final summary with FAIL SUMMARY (N).
printf '\n=====================================================\n'
printf '  SYNTAX-CHECK HONESTY TEST SUMMARY\n'
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
printf '\n  ALL SYNTAX-CHECK HONESTY TESTS PASSED!\n'
exit 0
