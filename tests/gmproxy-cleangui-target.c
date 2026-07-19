/*
 * gmproxy-cleangui-target.c -- GUI-subsystem dummy target for the gmproxy
 * CLEAN-GUI refusal RECORDING wine runtime test
 * (tests/test-gmproxy-force-system.sh).
 *
 * Compiled with -Wl,--subsystem,windows so its PE OptionalHeader.Subsystem is
 * IMAGE_SUBSYSTEM_WINDOWS_GUI. gmproxy's GmProxyIsGuiSubsystem reads that field
 * and returns TRUE, so an exit-0 run of this dummy is classified as a CLEAN-GUI
 * refusal (exit 0 + GUI PE = the Win11 Notepad silent-refusal case) and recorded
 * with reason 'G' under the GMPROXY_TEST_FORCE_SYSTEM_MODE compile-time seam.
 *
 * Behavior:
 *   - No argv[1] (or a zero/empty argv[1])  -> return 0  (CLEAN-GUI, reason 'G')
 *   - A non-zero integer argv[1]            -> return it (CRASH,      reason 'C')
 * One binary therefore exercises BOTH recording flavors:
 *     wine gmproxy.exe cleangui.exe        -> exit 0 -> CLEAN-GUI -> reason 'G'
 *     wine gmproxy.exe crashgui.exe 1      -> exit 1 -> CRASH     -> reason 'C'
 *
 * Plain main() + the --subsystem,windows LINKER flag (NOT -mwindows): MinGW-w64's
 * default entry mainCRTStartup still calls main -- the subsystem flag only
 * suppresses the console (no console is allocated); it does NOT switch the entry
 * to WinMainCRTStartup (only -mwindows does that). So main is invoked and the PE
 * is GUI. The dummy calls no GUI API, so no window is ever created/flashed.
 */
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc > 1 && argv[1] && argv[1][0]) {
        int code = atoi(argv[1]);
        if (code != 0) return code;   /* CRASH path: non-zero exit as "SYSTEM" */
    }
    return 0;                         /* CLEAN-GUI path: exit 0 + GUI PE */
}
