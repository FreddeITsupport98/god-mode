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
#   4b. wine smoke test --regression-mode (negative direction, PATH): builds a
#      BROKEN gmhook.dll (%ls->%s path) and asserts the runtime wide-format
#      guards FAIL on it -- proves the guard catches a broken build, not just
#      that a correct build passes (tests/test-shell-host-exclusion.sh
#      --regression-mode).
#   4c. wine smoke test --regression-mode=line (negative direction, LINE/CONTENT):
#      builds a BROKEN gmhook.dll with only the stamp-LINE %ls->%s reverted (path
#      left intact) and asserts the content guards FAIL on it -- proves a LINE
#      content-truncation regression (full host "loaded in chrome.exe" missing
#      while the [GM-HOOK] BUILD/loaded in literals stay) is caught, covering the
#      other half of the wide-format surface the path guards do not reach
#      (tests/test-shell-host-exclusion.sh --regression-mode=line).
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

# Auto-detect the parallel job count for the independent shellcheck + pwsh-suite
# steps (overridable via GODMODE_JOBS). The wine tests (steps 4/4b/4c + 5/5b-5e)
# stay SERIAL by design -- see the step-4 comment for why (shared WINEPREFIX +
# shared gmproxy.log/gmhook.log + the auto-exclude store would race/corrupt under
# concurrency). nproc -> 4 fallback; GODMODE_JOBS=1 forces fully serial.
if [ -n "${GODMODE_JOBS:-}" ] && [ "${GODMODE_JOBS:-}" -gt 0 ] 2>/dev/null; then
    JOBS="$GODMODE_JOBS"
elif command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc)"
else
    JOBS=4
fi
case "$JOBS" in ''|*[!0-9]*) JOBS=4 ;; esac
[ "$JOBS" -lt 1 ] && JOBS=1
printf '[REGRESSION] parallel jobs: %s (override: GODMODE_JOBS=<n>; wine tests stay serial)\n' "$JOBS"

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

# 1. shellcheck on shell scripts (parallel: one background job per file).
if command -v shellcheck >/dev/null 2>&1; then
    sh_pids=(); sh_logs=(); sh_names=(); sh_paths=()
    while IFS= read -r f; do
        log="$(mktemp)"; nm="$(basename "$f")"
        # Background subshell writes the log + exit code to <log>.rc; the main
        # shell waits per-PID and records AFTER (so the record counters/arrays
        # are never touched concurrently -- safe under set -u, no locking).
        ( shellcheck -S warning "$f" >"$log" 2>&1; echo $? > "$log.rc" ) &
        sh_pids+=("$!"); sh_logs+=("$log"); sh_names+=("$nm"); sh_paths+=("$f")
    done < <(find "$SCRIPT_DIR" -maxdepth 1 -type f -name '*.sh')
    for idx in "${!sh_pids[@]}"; do
        wait "${sh_pids[$idx]}" 2>/dev/null
        rc="$(cat "${sh_logs[$idx]}.rc" 2>/dev/null)"
        [ -z "$rc" ] && rc=1
        if [ "$rc" -eq 0 ]; then
            record "shellcheck ${sh_names[$idx]}" 1
        else
            record "shellcheck ${sh_names[$idx]}" 0 "run: shellcheck ${sh_paths[$idx]}"
        fi
        rm -f "${sh_logs[$idx]}" "${sh_logs[$idx]}.rc"
    done
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

# 3. PowerShell regression suites via pwsh (parallel: one background job per suite).
if ! command -v pwsh >/dev/null 2>&1; then
    record "pwsh available" 0 "pwsh not installed"
else
    ps_pids=(); ps_logs=(); ps_names=()
    for suite in Test-GodModeCrashFix.ps1 Test-IfeoElevation.ps1 Test-Suite.ps1 Test-GmProxySession.ps1; do
        f="$SCRIPT_DIR/$suite"
        if [ ! -f "$f" ]; then
            record "pwsh $suite" 0 "missing"
            continue
        fi
        log="$(mktemp)"
        # Background subshell: each suite is an independent pwsh process reading
        # source files (read-only), so concurrent runs are safe. The main shell
        # waits per-PID + records after, keeping the counters/arrays single-threaded.
        ( pwsh -NoProfile -File "$f" >"$log" 2>&1; echo $? > "$log.rc" ) &
        ps_pids+=("$!"); ps_logs+=("$log"); ps_names+=("$suite")
    done
    for idx in "${!ps_pids[@]}"; do
        wait "${ps_pids[$idx]}" 2>/dev/null
        rc="$(cat "${ps_logs[$idx]}.rc" 2>/dev/null)"
        [ -z "$rc" ] && rc=1
        if [ "$rc" -eq 0 ]; then
            record "pwsh ${ps_names[$idx]}" 1
            rm -f "${ps_logs[$idx]}" "${ps_logs[$idx]}.rc"
        else
            record "pwsh ${ps_names[$idx]}" 0 "exit=$rc (log: ${ps_logs[$idx]})"
            rm -f "${ps_logs[$idx]}.rc"
        fi
    done
fi

# 4. wine smoke test: gmhook.dll shell-host exclusion (binary-level).
# NOTE: the wine tests (4/4b/4c + 5/5b-5e) run SERIALLY by design -- they all share
# WINEPREFIX="${WINEPREFIX:-$HOME/.wine}" and the same wine %TEMP% gmproxy.log /
# gmhook.log + the C:\ProgramData\GodModeAutoExclude store, so concurrent runs
# would race on those files and corrupt each other's assertions. Parallelizing
# them would need a per-job isolated WINEPREFIX (mktemp -d) + a wineboot per
# prefix, which is a larger future enhancement (concurrent wineboot across
# separate prefixes is itself flaky). The shellcheck + pwsh-suite steps above
# ARE parallel (independent processes, no shared writable state).
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

# 4b. wine smoke test --regression-mode (negative direction, PATH): broken
#     %ls->%s PATH build must FAIL the runtime wide-format guards (proves the
#     guard catches a broken build, not just that a correct build passes).
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

# 4c. wine smoke test --regression-mode=line (negative direction, LINE/CONTENT):
#     broken stamp-LINE %ls->%s build (path left intact) must FAIL the content
#     guards (full host "loaded in chrome.exe" missing while literals stay).
if [ ! -f "$smoke" ]; then
    record "wine smoke --regression-mode=line present" 0 "test-shell-host-exclusion.sh missing"
else
    log="$(mktemp)"
    if bash "$smoke" --regression-mode=line >"$log" 2>&1; then
        record "wine smoke --regression-mode=line: broken LINE %ls->%s build FAILS the content guards" 1
        rm -f "$log"
    else
        rc=$?
        record "wine smoke --regression-mode=line: broken LINE %ls->%s build FAILS the content guards" 0 "exit=$rc (log: $log)"
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

# 5b. gmproxy ownerless-birth REFUSE wine runtime test: RUNS the freshly-built
#     gmproxy.exe under wine with a dummy target -- NORMAL build -> graceful
#     current-user fallback (exit 0); FORCED build (-DGMPROXY_TEST_FORCE_SESSION0=1)
#     -> ownerless-birth REFUSE (exit 1 + [GM-PROXY] REFUSE in %TEMP%\gmproxy.log).
#     Runtime analogue of the source-level section 17/18 invariants: proves BOTH
#     branches of the ownerless-birth fix behave at runtime, not just in source
#     (tests/test-gmproxy-refuse.sh).
gmrefuse="$SCRIPT_DIR/test-gmproxy-refuse.sh"
if [ ! -f "$gmrefuse" ]; then
    record "test-gmproxy-refuse.sh present" 0 "missing"
else
    log="$(mktemp)"
    if bash "$gmrefuse" >"$log" 2>&1; then
        record "gmproxy REFUSE: wine runtime (NORMAL fallback + FORCED refuse)" 1
        rm -f "$log"
    else
        rc=$?
        record "gmproxy REFUSE: wine runtime (NORMAL fallback + FORCED refuse)" 0 "exit=$rc (log: $log)"
    fi
fi

# 5c. gmproxy Detector B auto-exclude store wine runtime test: RUNS the freshly-
#     built gmproxy.exe under wine with a PRE-SEEDED crash store -> asserts the
#     app auto-de-elevates to the current user (USER-AUTOEXCLUDE mode), a CORRUPT
#     store fail-opens, and --gm-reset-autoexclude deletes the store. Runtime
#     analogue of the source-level section 24 invariants (tests/test-gmproxy-
#     autoexclude.sh).
gmautoex="$SCRIPT_DIR/test-gmproxy-autoexclude.sh"
if [ ! -f "$gmautoex" ]; then
    record "test-gmproxy-autoexclude.sh present" 0 "missing"
else
    log="$(mktemp)"
    if bash "$gmautoex" >"$log" 2>&1; then
        record "gmproxy AUTO-EXCLUDE: wine runtime (pre-seeded + corrupt + reset)" 1
        rm -f "$log"
    else
        rc=$?
        record "gmproxy AUTO-EXCLUDE: wine runtime (pre-seeded + corrupt + reset)" 0 "exit=$rc (log: $log)"
    fi
fi

# 5d. gmproxy CLEAN-GUI + A3 wine runtime test: RUNS the freshly-built gmproxy.exe
#     under wine with a PRE-SEEDED auto-exclude store -> asserts USER-AUTOEXCLUDE
#     mode AND that the PID is NOT handed to the monitor (A3: no "Handed PID" line
#     in the log -- auto-excluded launches are not re-elevated in-place). Also
#     grep-proves the CLEAN-GUI refusal recording source invariants (Part A2:
#     GmProxyIsGuiSubsystem + IMAGE_SUBSYSTEM_WINDOWS_GUI + the widened record
#     guard). The CLEAN-GUI RECORDING path itself cannot be exercised under wine
#     (no real SYSTEM token -> mode=FALLBACK, not SYSTEM -> record guard never
#     fires); the recording is proven at the source level here + in
#     Test-GmProxySession.ps1 (tests/test-gmproxy-cleangui.sh).
gmcleangui="$SCRIPT_DIR/test-gmproxy-cleangui.sh"
if [ ! -f "$gmcleangui" ]; then
    record "test-gmproxy-cleangui.sh present" 0 "missing"
else
    log="$(mktemp)"
    if bash "$gmcleangui" >"$log" 2>&1; then
        record "gmproxy CLEAN-GUI + A3: wine runtime (USER-AUTOEXCLUDE + no Handed PID)" 1
        rm -f "$log"
    else
        rc=$?
        record "gmproxy CLEAN-GUI + A3: wine runtime (USER-AUTOEXCLUDE + no Handed PID)" 0 "exit=$rc (log: $log)"
    fi
fi

# 5e. gmproxy RECORDING (force-system seam) wine runtime test: RUNS the freshly-
#     built gmproxy.exe (FORCED build, -DGMPROXY_TEST_FORCE_SYSTEM_MODE=1) under
#     wine with a GUI-subsystem dummy + a PRE-SEEDED count=1 store -> asserts the
#     recording path fires (store becomes count=2 excluded=1 reason 'G' for a
#     CLEAN-GUI exit, reason 'C' for a CRASH exit), AND that the PRODUCTION
#     (NORMAL) build then launches USER-AUTOEXCLUDE on the next run (end-to-end:
#     the force-system-recorded store is read correctly by the production binary,
#     5-field format backward/forward compatible). The recording path was
#     previously only source-level proven (the production _wcsicmp(mode,L"SYSTEM")
#     guard never fires under wine -- no real SYSTEM token); this test closes
#     that gap (tests/test-gmproxy-force-system.sh).
gmforce="$SCRIPT_DIR/test-gmproxy-force-system.sh"
if [ ! -f "$gmforce" ]; then
    record "test-gmproxy-force-system.sh present" 0 "missing"
else
    log="$(mktemp)"
    if bash "$gmforce" >"$log" 2>&1; then
        record "gmproxy RECORDING (force-system): wine runtime (CLEAN-GUI + CRASH + end-to-end USER-AUTOEXCLUDE)" 1
        rm -f "$log"
    else
        rc=$?
        record "gmproxy RECORDING (force-system): wine runtime (CLEAN-GUI + CRASH + end-to-end USER-AUTOEXCLUDE)" 0 "exit=$rc (log: $log)"
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
