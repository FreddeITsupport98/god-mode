#!/usr/bin/env bash
# test-shell-host-exclusion.sh -- wine smoke test for the gmhook.dll 0xC0000005 fix.
#
# Binary-level check that catches IsShellLauncherProcess() regressions BEFORE
# deploying to the Windows VM. Builds gmhook.dll (MinGW cross-compile, same
# flags as driver/build.ps1), builds two stub host exes from the SAME source
# (named pwsh.exe and chrome.exe), loads gmhook.dll into each under wine, and
# asserts via the exported IsHookInstalled() diagnostic:
#   - pwsh.exe    (shell/launcher host) -> CreateProcessW IAT hook NOT installed
#   - chrome.exe  (user app)            -> CreateProcessW IAT hook IS installed
# The chrome.exe control proves the test actually detects hooking (it is not
# trivially always-false): if gmhook stopped hooking EVERYTHING, chrome.exe
# would fail and surface here.
#
# Prints a FAIL SUMMARY (N) block and exits 1 on any failure, 0 if all pass.
# Usage: bash tests/test-shell-host-exclusion.sh
#        bash tests/test-shell-host-exclusion.sh --regression-mode
#        bash tests/test-shell-host-exclusion.sh --regression-mode=line
#          --regression-mode:      NEGATIVE direction (PATH). Builds a BROKEN
#          copy of gmhook.c with only the %TEMP%\gmhook.log path swprintf
#          reverted %ls->%s (the exact wide-format regression the runtime guard
#          catches) -- the real source is never modified -- then asserts the
#          two build-stamp guards FAIL (Cgmhook.log CWD artifact appears +
#          %TEMP% gmhook.log has no full BUILD stamp). Proves the guard catches
#          a broken build, not just that a correct build passes.
#          --regression-mode=line: NEGATIVE direction (LINE / CONTENT). Builds a
#          BROKEN copy of gmhook.c with only the stamp-LINE swprintf reverted
#          %ls->%s (the wdate/wtime/baseName wide args) while the PATH %ls is
#          left INTACT -- the real source is never modified. MinGW wide swprintf
#          %s reads a wchar_t* as narrow and stops at the first 0x00 high byte,
#          so each arg collapses to its first char (baseName "chrome.exe" ->
#          "c"): the path is still correct (log at %TEMP%, NO CWD Cgmhook.log)
#          but the stamp CONTENT is truncated. Asserts the full host
#          "loaded in chrome.exe" is MISSING from %TEMP% gmhook.log while the
#          [GM-HOOK] BUILD / loaded in LITERALS still appear -- proving the
#          path-mode guard (b) substring check ALONE false-passes on a content-
#          truncation regression, so a dedicated full-host content guard (the
#          positive (f-pos) below) is needed for the LINE half.
set -uo pipefail

# --regression-mode[=line]: negative direction (see Usage above). Builds a
#    known-broken gmhook.dll and asserts the runtime wide-format guards FAIL on
#    it. "path" reverts the %TEMP%\gmhook.log path swprintf; "line" reverts only
#    the stamp-LINE swprintf (content truncation, path left intact).
REGRESSION_MODE=""   # "" = positive; "path" = %ls->%s path revert; "line" = %ls->%s line revert
if [ "${1:-}" = "--regression-mode" ]; then
    REGRESSION_MODE="path"
elif [ "${1:-}" = "--regression-mode=line" ]; then
    REGRESSION_MODE="line"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DRIVER_DIR="$PROJECT_ROOT/driver"

GCC=x86_64-w64-mingw32-gcc
NM=x86_64-w64-mingw32-nm
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
printf '  gmhook.dll shell-host exclusion (wine smoke test)\n'
printf '=====================================================\n'
case "$REGRESSION_MODE" in
    path) printf '  mode: REGRESSION-PATH (negative direction -- broken %%ls->%%s PATH build; path guards must FAIL)\n' ;;
    line) printf '  mode: REGRESSION-LINE (negative direction -- broken %%ls->%%s LINE build; content guards must FAIL)\n' ;;
    *)    printf '  mode: POSITIVE (correct %%ls build; guards must PASS)\n' ;;
esac

# --- Tool checks (hard-fail if the toolchain that the VM build also needs
#     is missing, so this never silently passes by skipping). ---
if ! command -v "$GCC" >/dev/null 2>&1; then
    record "MinGW ($GCC) available" 0 "not installed; cannot build gmhook.dll / stubs"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi
if ! command -v "$WINE" >/dev/null 2>&1; then
    record "wine available" 0 "not installed; cannot load gmhook.dll under wine"
    printf '\n  FAIL SUMMARY (%s)\n    - %s\n' "$fail_count" "${fail_names[0]}"
    exit 1
fi

STUB_SRC="$SCRIPT_DIR/Test-ShellHostExclusion.c"
HOOK_SRC="$DRIVER_DIR/gmhook.c"

if [ ! -f "$STUB_SRC" ]; then
    record "Test-ShellHostExclusion.c present" 0 "missing"
elif [ ! -f "$HOOK_SRC" ]; then
    record "driver/gmhook.c present" 0 "missing"
else
    WORK="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$WORK'" EXIT

    # 1. Build gmhook.dll (same flags as driver/build.ps1 MinGW path). In a
    #    regression mode, build from a BROKEN copy of gmhook.c with one wide-
    #    format swprintf reverted %ls->%s (the exact regression the runtime guard
    #    below catches). The REAL source is never modified -- the broken copy
    #    lives in $WORK and is rm -rf'd on exit. We assert the reversion happened
    #    so a future source change cannot make this silently build an unbroken
    #    DLL and false-pass the negative direction.
    #      path: revert the %TEMP%\gmhook.log PATH swprintf (%lsgmhook.log ->
    #            %sgmhook.log). Truncates the path to "C"+"gmhook.log" -> a
    #            relative CWD artifact + no %TEMP% stamp (a LOCATION redirect).
    #      line: revert ONLY the stamp-LINE swprintf (the three wdate/wtime/
    #            baseName wide args) via a targeted sed 's/%ls /%s /g'. The PATH
    #            %lsgmhook.log has NO trailing space after %ls, so it is NOT
    #            matched and stays %ls (log still opens at %TEMP%\gmhook.log).
    #            MinGW %s reads each wchar_t* arg as narrow and stops at the
    #            first 0x00 high byte -> each arg collapses to its first char
    #            (baseName "chrome.exe" -> "c"), so the stamp CONTENT is
    #            truncated while the path/location stays correct.
    HOOK_BUILD_SRC="$HOOK_SRC"
    build_name="build gmhook.dll (MinGW)"
    if [ "$REGRESSION_MODE" = "path" ]; then
        src_occ=$(grep -cF -- '%lsgmhook.log' "$HOOK_SRC" 2>/dev/null || true)
        [ -z "$src_occ" ] && src_occ=0
        sed 's/%lsgmhook\.log/%sgmhook.log/' "$HOOK_SRC" > "$WORK/gmhook_broken.c"
        brok_occ=$(grep -cF -- '%sgmhook.log' "$WORK/gmhook_broken.c" 2>/dev/null || true)
        [ -z "$brok_occ" ] && brok_occ=0
        kept_occ=$(grep -cF -- '%lsgmhook.log' "$WORK/gmhook_broken.c" 2>/dev/null || true)
        [ -z "$kept_occ" ] && kept_occ=0
        if [ "$src_occ" -ge 1 ] && [ "$brok_occ" -ge 1 ] && [ "$kept_occ" -eq 0 ]; then
            HOOK_BUILD_SRC="$WORK/gmhook_broken.c"
            build_name="build broken gmhook.dll (%ls->%s path, MinGW)"
        else
            record "build broken gmhook.c variant (%ls->%s path)" 0 \
                "could not construct broken variant (src=$src_occ brok=$brok_occ kept=$kept_occ)"
            HOOK_BUILD_SRC=""
        fi
    elif [ "$REGRESSION_MODE" = "line" ]; then
        # Targeted revert of ONLY the stamp-LINE %ls (the three wide args). The
        # distinctive substring 'BUILD %ls %ls loaded in %ls' pins the line
        # format; '%lsgmhook.log' pins the path (must stay intact). sed matches
        # '%ls ' (trailing space) so the path '%lsgmhook.log' (%ls + 'g', no
        # space) is untouched.
        if grep -qF 'BUILD %ls %ls loaded in %ls' "$HOOK_SRC" 2>/dev/null \
           && grep -qF '%lsgmhook.log' "$HOOK_SRC" 2>/dev/null; then
            sed 's/%ls /%s /g' "$HOOK_SRC" > "$WORK/gmhook_broken_line.c"
            if grep -qF 'BUILD %s %s loaded in %s' "$WORK/gmhook_broken_line.c" 2>/dev/null \
               && grep -qF '%lsgmhook.log' "$WORK/gmhook_broken_line.c" 2>/dev/null \
               && ! grep -qF 'BUILD %ls %ls loaded in %ls' "$WORK/gmhook_broken_line.c" 2>/dev/null; then
                HOOK_BUILD_SRC="$WORK/gmhook_broken_line.c"
                build_name="build broken gmhook.dll (line %ls->%s, MinGW)"
            else
                record "build broken gmhook.c variant (line %ls->%s)" 0 \
                    "could not construct broken line variant (path or line format not as expected)"
                HOOK_BUILD_SRC=""
            fi
        else
            record "build broken gmhook.c variant (line %ls->%s)" 0 \
                "source line format not found (BUILD %ls %ls loaded in %ls or %lsgmhook.log missing)"
            HOOK_BUILD_SRC=""
        fi
    fi
    if [ -n "$HOOK_BUILD_SRC" ]; then
        if "$GCC" -O2 -Wall -shared -o "$WORK/gmhook.dll" "$HOOK_BUILD_SRC" \
                -ladvapi32 -lkernel32 -lntdll -luser32 >/dev/null 2>&1; then
            record "$build_name" 1
        else
            record "$build_name" 0 "gcc failed"
        fi
    fi

    # 2. Verify IsHookInstalled is exported (static guard; the runtime
    #    GetProcAddress in the stub below is authoritative). Captured into a
    #    variable and matched with `case` so `set -o pipefail` cannot turn a
    #    SIGPIPE on `nm | grep -q` into a false negative.
    if [ ! -f "$WORK/gmhook.dll" ]; then
        :  # build already failed above; nothing to inspect
    elif command -v "$NM" >/dev/null 2>&1; then
        nm_out="$("$NM" "$WORK/gmhook.dll" 2>/dev/null || true)"
        case "$nm_out" in
            *IsHookInstalled*) record "gmhook.dll exports IsHookInstalled" 1 ;;
            *) record "gmhook.dll exports IsHookInstalled" 0 "symbol not found in nm output" ;;
        esac
    else
        record "gmhook.dll exports IsHookInstalled (nm skip)" 1 "$NM unavailable; runtime GetProcAddress is authoritative"
    fi

    # 3. Build stub hosts: same source, two filenames (the filename is what
    #    gmhook's DllMain reads to decide shell-host exclusion).
    build_stub=0
    if [ -f "$WORK/gmhook.dll" ]; then
        if "$GCC" -O2 -Wall -o "$WORK/pwsh.exe" "$STUB_SRC" -lkernel32 >/dev/null 2>&1 && \
           "$GCC" -O2 -Wall -o "$WORK/chrome.exe" "$STUB_SRC" -lkernel32 >/dev/null 2>&1; then
            build_stub=1
            record "build stub hosts pwsh.exe + chrome.exe (MinGW)" 1
        else
            record "build stub hosts pwsh.exe + chrome.exe (MinGW)" 0 "gcc failed"
        fi
    fi

    # 4. Run under wine. pwsh.exe -> expect NOT hooked (0); chrome.exe -> expect
    #    hooked (1). The stub exits 0 when the expectation is met. The wine CWD
    #    is forced to the clean WORK dir (subshell) so a wide-format regression
    #    that truncates the %TEMP%\gmhook.log path to a relative "Cgmhook.log"
    #    drops a deterministic CWD artifact we assert on below -- independent of
    #    where this script was invoked from. (Loading gmhook.dll is unaffected:
    #    the stub loads it via an absolute beside-the-exe path, not via CWD.)
    if [ "$build_stub" = "1" ]; then
        # Locate wine's %TEMP% (where a correct %ls build writes gmhook.log) and
        # clear any stale gmhook.log so the post-run content guard only sees
        # lines written by THIS run's freshly built gmhook.dll. gmhook.log is
        # this project's own log artifact (not user data), so removing it here
        # is safe and keeps the guard deterministic.
        WINEPREFIX_DIR="${WINEPREFIX:-$HOME/.wine}"
        WINE_USER="${USER:-${LOGNAME:-}}"
        WINE_TEMP="$WINEPREFIX_DIR/drive_c/users/$WINE_USER/AppData/Local/Temp"
        if [ ! -d "$WINE_TEMP" ]; then
            WINE_TEMP="$(find "$WINEPREFIX_DIR/drive_c/users" -maxdepth 4 -type d -path '*/AppData/Local/Temp' 2>/dev/null | head -n1)"
        fi
        GMHOOK_LOG="$WINE_TEMP/gmhook.log"
        if [ -n "$WINE_TEMP" ] && [ -d "$WINE_TEMP" ]; then
            rm -f "$GMHOOK_LOG"
        fi

        out_pwsh="$(cd "$WORK" && "$WINE" "$WORK/pwsh.exe" 0 2>&1)"; rc_pwsh=$?
        printf '  [wine] pwsh.exe (expect NOT hooked):\n%s\n' "$out_pwsh" | sed 's/^/    /'
        if [ "$rc_pwsh" -eq 0 ]; then
            record "pwsh.exe NOT hooked (shell-host exclusion works)" 1
        else
            record "pwsh.exe NOT hooked (shell-host exclusion works)" 0 "wine exit=$rc_pwsh (expected IsHookInstalled=0)"
        fi

        out_chr="$(cd "$WORK" && "$WINE" "$WORK/chrome.exe" 1 2>&1)"; rc_chr=$?
        printf '  [wine] chrome.exe (expect IS hooked, control):\n%s\n' "$out_chr" | sed 's/^/    /'
        if [ "$rc_chr" -eq 0 ]; then
            record "chrome.exe IS hooked (negative control)" 1
        else
            record "chrome.exe IS hooked (negative control)" 0 "wine exit=$rc_chr (expected IsHookInstalled=1)"
        fi

        # 5. Runtime wide-format regression guard (catches %s-vs-%ls at runtime,
        #    not just in source). A correct %ls build writes a FULL
        #    "[GM-HOOK] BUILD <date> <time> loaded in <host> (attach ...)" line
        #    to %TEMP%\gmhook.log and leaves NO Cgmhook.log in the wine CWD. A
        #    %s PATH regression (MinGW wide swprintf truncating the wchar_t* path
        #    arg to its first char) instead truncates the path to "Cgmhook.log"
        #    in the CWD and writes the full stamp there (LOCATION redirect). A
        #    %s LINE regression leaves the path correct (log at %TEMP%, NO CWD
        #    artifact) but truncates each stamp-LINE wide arg to its first char
        #    (CONTENT truncation): "loaded in chrome.exe" -> "loaded in c". The
        #    [GM-HOOK] BUILD / loaded in LITERALS are format-string constants,
        #    so they survive a LINE regression -- the substring-only guard (b)
        #    ALONE would false-pass on it, which is why a dedicated full-host
        #    content guard ((f-pos) positive / (e) line) is needed for the LINE
        #    half. In a regression mode the expectations are INVERTED for the
        #    half being tested, proving the guard catches a broken build (not
        #    just that a correct build passes).
        if [ -z "$WINE_TEMP" ] || [ ! -d "$WINE_TEMP" ]; then
            record "locate wine %TEMP% for content guard" 0 "no <wineprefix>/drive_c/users/*/AppData/Local/Temp found"
        else
            # (a) CWD artifact. POSITIVE: a correct %ls path drops NO Cgmhook.log
            #     into the wine CWD (the WORK dir). REGRESSION-PATH: a broken %s
            #     path MUST drop Cgmhook.log (the truncated path is "C" +
            #     "gmhook.log"). REGRESSION-LINE: the path is still %ls so NO
            #     CWD artifact must appear (the line revert isolates content, not
            #     location) -- handled by guard (d) below.
            if [ "$REGRESSION_MODE" = "path" ]; then
                if [ -e "$WORK/Cgmhook.log" ]; then
                    record "broken build DROPS Cgmhook.log CWD artifact (guard catches %s)" 1
                else
                    record "broken build DROPS Cgmhook.log CWD artifact (guard catches %s)" 0 \
                        "no Cgmhook.log -> broken build did not reproduce the %s path-truncation regression"
                fi
            elif [ -z "$REGRESSION_MODE" ]; then
                if [ -e "$WORK/Cgmhook.log" ]; then
                    record "no Cgmhook.log CWD artifact (wide-format path OK)" 0 "Cgmhook.log in wine CWD -> %s path-truncation regression"
                else
                    record "no Cgmhook.log CWD artifact (wide-format path OK)" 1
                fi
            fi

            # (b) %TEMP%\gmhook.log stamp LITERALS. The fixed strings
            #     '[GM-HOOK] BUILD ' and 'loaded in' only co-occur on a stamp
            #     line that swprintf actually formatted (they are format-string
            #     constants, so they survive a LINE %s regression too). grep -qF
            #     (fixed-string) avoids regex-mangling the brackets. POSITIVE:
            #     literals MUST be present. REGRESSION-PATH: the broken %s PATH
            #     redirects the full stamp to the CWD Cgmhook.log, so %TEMP%
            #     gmhook.log is never written -> literals MUST be absent (see
            #     guard (c)). REGRESSION-LINE: the path is correct so %TEMP%
            #     gmhook.log IS written and the literals ARE present -- guard (b)
            #     alone false-passes here, which is exactly the gap guard (e)
            #     closes (full host missing).
            full_stamp=0
            if [ -f "$GMHOOK_LOG" ] && grep -qF '[GM-HOOK] BUILD ' "$GMHOOK_LOG" && grep -qF 'loaded in' "$GMHOOK_LOG"; then
                full_stamp=1
            fi
            if [ "$REGRESSION_MODE" = "path" ]; then
                if [ "$full_stamp" = "1" ]; then
                    record "broken build leaves %TEMP% gmhook.log without a full BUILD stamp (guard catches %s)" 0 \
                        "full stamp present in %TEMP% gmhook.log -> broken build did not redirect the stamp away from %TEMP%"
                else
                    record "broken build leaves %TEMP% gmhook.log without a full BUILD stamp (guard catches %s)" 1
                fi
            elif [ -z "$REGRESSION_MODE" ]; then
                if [ "$full_stamp" = "1" ]; then
                    record "wine %TEMP% gmhook.log has full BUILD ... loaded in stamp" 1
                else
                    record "wine %TEMP% gmhook.log has full BUILD ... loaded in stamp" 0 "gmhook.log missing/truncated -> %s wide-format regression"
                fi
            fi

            # (c) REGRESSION-PATH-only characterization: the broken build redirects
            #     the FULL stamp to the CWD -- the path swprintf is %s so the log
            #     opens "Cgmhook.log" in the CWD, but the stamp LINE still uses
            #     %ls (only the PATH was reverted) so its content is intact and
            #     fputws writes the full line to the CWD file. So the CWD
            #     Cgmhook.log artifact MUST hold a full [GM-HOOK] BUILD stamp --
            #     proving the regression is a PATH redirect (wrong location), not
            #     a content truncation, and tying (a)+(b) together: the full stamp
            #     MISSING from %TEMP% (b) is present in the CWD (a).
            if [ "$REGRESSION_MODE" = "path" ] && [ -e "$WORK/Cgmhook.log" ]; then
                if [ -f "$WORK/Cgmhook.log" ] && grep -qF '[GM-HOOK] BUILD ' "$WORK/Cgmhook.log"; then
                    record "broken build redirects FULL stamp to CWD Cgmhook.log (path %s, line %ls)" 1
                else
                    record "broken build redirects FULL stamp to CWD Cgmhook.log (path %s, line %ls)" 0 \
                        "no full stamp in CWD Cgmhook.log -> broken build did not redirect the full stamp to the CWD"
                fi
            fi

            # (d) REGRESSION-LINE: path is still correct (PATH %ls intact) so NO
            #     CWD Cgmhook.log artifact appears -- the line revert isolates
            #     CONTENT, not LOCATION (contrast with path mode guard (a)). If a
            #     CWD artifact DOES appear, the line sed accidentally also broke
            #     the path (a test bug, not the intended regression).
            if [ "$REGRESSION_MODE" = "line" ]; then
                if [ -e "$WORK/Cgmhook.log" ]; then
                    record "line build keeps path correct (no CWD Cgmhook.log artifact)" 0 \
                        "Cgmhook.log in wine CWD -> line revert also broke the path (unexpected)"
                else
                    record "line build keeps path correct (no CWD Cgmhook.log artifact)" 1
                fi
            fi

            # (e) REGRESSION-LINE: %TEMP%\gmhook.log IS written (path correct) but
            #     the stamp CONTENT is truncated -- MinGW %s collapses each
            #     wchar_t* arg to its first char, so the full host basename
            #     ("chrome.exe") is MISSING from the "loaded in <host>" field (it
            #     reads "loaded in c"). This is the content-truncation half the
            #     path guards do not cover. A correct %ls build writes the full
            #     "loaded in chrome.exe" (see positive guard (f-pos)).
            if [ "$REGRESSION_MODE" = "line" ]; then
                if [ -f "$GMHOOK_LOG" ] && grep -qF 'loaded in chrome.exe' "$GMHOOK_LOG"; then
                    record "line build truncates stamp content (full host MISSING from %TEMP% gmhook.log)" 0 \
                        "full host 'loaded in chrome.exe' present -> line revert did not truncate content"
                else
                    record "line build truncates stamp content (full host MISSING from %TEMP% gmhook.log)" 1
                fi
            fi

            # (f) REGRESSION-LINE characterization: the [GM-HOOK] BUILD ... loaded
            #     in LITERALS are still present in the truncated %TEMP% stamp (they
            #     are format-string constants, not wchar_t args), so the path-mode
            #     guard (b) substring check ALONE false-passes on a content-
            #     truncation regression -- proving why a dedicated full-host
            #     content guard (e) is needed for the LINE half.
            if [ "$REGRESSION_MODE" = "line" ] && [ -f "$GMHOOK_LOG" ]; then
                if grep -qF '[GM-HOOK] BUILD ' "$GMHOOK_LOG" && grep -qF 'loaded in' "$GMHOOK_LOG"; then
                    record "line build still has [GM-HOOK] BUILD/loaded in literals (guard (b) alone false-passes)" 1
                else
                    record "line build still has [GM-HOOK] BUILD/loaded in literals (guard (b) alone false-passes)" 0 \
                        "literals missing -> line revert also dropped the format literals (unexpected)"
                fi
            fi

            # (f-pos) POSITIVE: the full host basename IS present in the %TEMP%
            #     stamp ("loaded in chrome.exe") -- the content-truncation
            #     counterpart to guard (e). A %s LINE regression collapses the
            #     host to its first char, so this guard catches a LINE wide-format
            #     regression that the substring-only guard (b) would false-pass on.
            if [ -z "$REGRESSION_MODE" ] && [ -f "$GMHOOK_LOG" ]; then
                if grep -qF 'loaded in chrome.exe' "$GMHOOK_LOG"; then
                    record "wine %TEMP% gmhook.log stamp has full host (loaded in chrome.exe)" 1
                else
                    record "wine %TEMP% gmhook.log stamp has full host (loaded in chrome.exe)" 0 \
                        "full host missing -> %s line content-truncation regression"
                fi
            fi
        fi
    fi
fi

printf '\n=====================================================\n'
printf '  SHELL-HOST EXCLUSION TEST SUMMARY\n'
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
printf '\n  ALL SHELL-HOST EXCLUSION TESTS PASSED!\n'
exit 0
