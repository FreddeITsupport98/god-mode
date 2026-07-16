/*
 * Test-GmHookFix.c -- Regression test for the 0xC0000005 fix in gmhook.c.
 *
 * It mirrors the STARTUPINFO guard logic of TryCreateProcessWithSystemToken():
 *   - NEVER take the CreateProcessWithTokenW path for an EXTENDED STARTUPINFOEX
 *     (cb > sizeof(STARTUPINFOW)) or when EXTENDED_STARTUPINFO_PRESENT is set,
 *     because the kernel would read the lpAttributeList pointer at offset
 *     sizeof(STARTUPINFOW) -- past our stack STARTUPINFOW -- and dereference
 *     garbage (STATUS_ACCESS_VIOLATION / 0xC0000005).
 *   - require a non-NULL PROCESS_INFORMATION and a non-NULL SYSTEM token.
 *   - clamp cb to sizeof(STARTUPINFOW) when building the local copy.
 *
 * Build (MinGW, Linux cross-compile):
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -o Test-GmHookFix.exe Test-GmHookFix.c
 * Run (Linux via wine):
 *   wine Test-GmHookFix.exe
 *
 * Exits 0 when all assertions pass, 1 with a FAIL SUMMARY (N) block otherwise.
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 /* STARTUPINFOEXW requires >= 0x0600 (Vista) */
#endif

#include <windows.h>
#include <stdio.h>
#include <string.h>

#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

static const char* g_fails[64];
static int g_failCount = 0;

static void check(const char* name, int pass) {
    if (pass) {
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s\n", name);
        if (g_failCount < 64) g_fails[g_failCount++] = name;
    }
}

/* Pure decision mirroring TryCreateProcessWithSystemToken()'s guards.
   Returns 1 if the token path would be taken, 0 if it falls back to the
   real CreateProcessW. outClampedCb receives the cb we would pass on. */
static int shouldTakeTokenPath(const STARTUPINFOW* si, const void* pi,
                               DWORD flags, int haveToken, DWORD* outClampedCb) {
    if (!haveToken) return 0;
    if (!pi) return 0;
    if (flags & EXTENDED_STARTUPINFO_PRESENT) return 0;
    if (si) {
        if (si->cb > sizeof(STARTUPINFOW)) return 0; /* extended SI -> fall back */
        if (outClampedCb) *outClampedCb = sizeof(STARTUPINFOW);
    } else {
        if (outClampedCb) *outClampedCb = sizeof(STARTUPINFOW);
    }
    return 1;
}

/* Mirror of gmhook.c's IsCriticalProcess() || IsShellLauncherProcess() decision.
   Returns 1 if the host SHOULD be IAT-hooked (neither critical nor a shell/
   launcher host), 0 if it must be skipped. Shell/launcher hosts (pwsh,
   powershell, cmd, terminals) are excluded because they launch native commands
   via CreateProcessW as their core job and in-process IAT hooking destabilizes
   them with 0xC0000005 inside Kernel32.CreateProcess. */
static int shouldHookHost(const char* baseName) {
    if (!baseName) return 0; /* NULL -> unhookable (mirrors IsCriticalProcess TRUE on NULL) */
    static const char* critical[] = {
        "csrss.exe","lsass.exe","services.exe","smss.exe","winlogon.exe","wininit.exe",
        "svchost.exe","dwm.exe","fontdrvhost.exe","System","Registry","Memory Compression",
        "Secure System","Idle", NULL
    };
    static const char* shells[] = {
        "pwsh.exe","powershell.exe","cmd.exe","wt.exe","conhost.exe","OpenConsole.exe",
        "WindowsTerminal.exe", NULL
    };
    for (int i = 0; critical[i]; i++) if (_stricmp(baseName, critical[i]) == 0) return 0;
    for (int i = 0; shells[i]; i++) if (_stricmp(baseName, shells[i]) == 0) return 0;
    return 1;
}

int main(void) {
    printf("===== gmhook 0xC0000005 fix regression =====\n");

    /* Premise of the bug: STARTUPINFOEXW is larger than STARTUPINFOW, so a
       truncated local STARTUPINFOW that still carries the EX cb lets the kernel
       read past it as a STARTUPINFOEX. */
    check("sizeof(STARTUPINFOEXW) > sizeof(STARTUPINFOW)",
          (int)sizeof(STARTUPINFOEXW) > (int)sizeof(STARTUPINFOW));

    STARTUPINFOW plainSi;
    memset(&plainSi, 0, sizeof(plainSi));
    plainSi.cb = sizeof(STARTUPINFOW);

    STARTUPINFOEXW exSi;
    memset(&exSi, 0, sizeof(exSi));
    exSi.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    int dummyPi = 1;
    void* pi = &dummyPi;
    DWORD clamped = 0;

    /* Plain STARTUPINFO, non-NULL PI, token present, no EXTENDED -> take path. */
    check("plain STARTUPINFO takes token path",
          shouldTakeTokenPath(&plainSi, pi, 0, 1, &clamped) == 1);
    check("plain SI cb clamped to sizeof(STARTUPINFOW)",
          clamped == (DWORD)sizeof(STARTUPINFOW));

    /* Extended STARTUPINFOEX (cb > sizeof STARTUPINFOW) -> MUST fall back (the bug). */
    check("extended STARTUPINFOEX falls back (no token path)",
          shouldTakeTokenPath((STARTUPINFOW*)&exSi, pi, 0, 1, &clamped) == 0);

    /* EXTENDED_STARTUPINFO_PRESENT flag set -> fall back. */
    check("EXTENDED flag falls back",
          shouldTakeTokenPath(&plainSi, pi, EXTENDED_STARTUPINFO_PRESENT, 1, &clamped) == 0);

    /* NULL PROCESS_INFORMATION -> fall back (CreateProcessWithTokenW needs it). */
    check("NULL PROCESS_INFORMATION falls back",
          shouldTakeTokenPath(&plainSi, NULL, 0, 1, &clamped) == 0);

    /* No SYSTEM token -> fall back. */
    check("NULL token falls back",
          shouldTakeTokenPath(&plainSi, pi, 0, 0, &clamped) == 0);

    /* NULL STARTUPINFO -> take path with clamped cb. */
    check("NULL STARTUPINFO takes token path",
          shouldTakeTokenPath(NULL, pi, 0, 1, &clamped) == 1);
    check("NULL SI cb clamped to sizeof(STARTUPINFOW)",
          clamped == (DWORD)sizeof(STARTUPINFOW));

    /* --- Host exclusion regression: shell/launcher hosts must NOT be hooked
           (the actual cause of the 0xC0000005 was hooking these in-process) --- */
    printf("  -- shell/launcher host exclusion --\n");
    check("pwsh.exe NOT hooked (shell launcher)",
          shouldHookHost("pwsh.exe") == 0);
    check("powershell.exe NOT hooked (shell launcher)",
          shouldHookHost("powershell.exe") == 0);
    check("cmd.exe NOT hooked (shell launcher)",
          shouldHookHost("cmd.exe") == 0);
    check("wt.exe NOT hooked (terminal host)",
          shouldHookHost("wt.exe") == 0);
    check("conhost.exe NOT hooked (terminal host)",
          shouldHookHost("conhost.exe") == 0);
    check("WindowsTerminal.exe NOT hooked (terminal host)",
          shouldHookHost("WindowsTerminal.exe") == 0);
    check("csrss.exe NOT hooked (critical OS)",
          shouldHookHost("csrss.exe") == 0);
    check("explorer.exe IS hooked (user app, not shell/critical)",
          shouldHookHost("explorer.exe") == 1);
    check("chrome.exe IS hooked (user app, not shell/critical)",
          shouldHookHost("chrome.exe") == 1);
    check("NULL base name NOT hooked (safe default)",
          shouldHookHost(NULL) == 0);

    printf("\n===== FAIL SUMMARY (%d) =====\n", g_failCount);
    for (int i = 0; i < g_failCount; i++) {
        printf("  - %s\n", g_fails[i]);
    }
    if (g_failCount > 0) {
        printf("[RESULT] FAIL\n");
        return 1;
    }
    printf("[RESULT] ALL ASSERTIONS PASSED\n");
    return 0;
}
