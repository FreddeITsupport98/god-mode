/*
 * Test-ShellHostExclusion.c -- wine smoke-test stub host for gmhook.dll.
 *
 * Built TWICE from the same source with different output filenames so that
 * gmhook.dll's DllMain sees a different host base name in each run:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o pwsh.exe   Test-ShellHostExclusion.c -lkernel32
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o chrome.exe Test-ShellHostExclusion.c -lkernel32
 *
 * gmhook.dll's DllMain derives the host base name from GetModuleFileNameW(NULL)
 * and SKIPS InstallIATHook() for shell/launcher hosts (IsShellLauncherProcess:
 * pwsh/powershell/cmd/wt/conhost/OpenConsole/WindowsTerminal) -- the 0xC0000005
 * fix. This stub:
 *   1. Forces a static CreateProcessW import (harmless empty-app-name call) so
 *      the stub's IAT has an entry gmhook could patch -- proving the chrome.exe
 *      control can actually detect hooking, not trivially always-false.
 *   2. Loads gmhook.dll from beside this exe (robust regardless of CWD / DLL
 *      search path).
 *   3. Queries the exported IsHookInstalled() diagnostic.
 *   4. Compares against the expected value passed as argv[1]:
 *        0 = hook must NOT be installed (shell host, e.g. pwsh.exe)
 *        1 = hook must BE installed (user-app control, e.g. chrome.exe)
 *
 * Exit 0 = expectation met; 1 = not met or infrastructure error.
 * Run (Linux via wine):  wine pwsh.exe 0   |   wine chrome.exe 1
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef BOOL (WINAPI *IsHookInstalled_t)(void);

int main(int argc, char* argv[]) {
    int expected = (argc > 1) ? atoi(argv[1]) : -1;

    /* Force a static CreateProcessW import so the stub's IAT has an entry that
       gmhook.dll's InstallIATHook() can patch. Harmless: an empty application
       name fails immediately (no process is launched); the call only exists to
       guarantee the import survives linking. */
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    (void)CreateProcessW(L"", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    /* Report which host we are (the filename drives gmhook's decision). */
    wchar_t modName[MAX_PATH];
    if (!GetModuleFileNameW(NULL, modName, MAX_PATH)) {
        printf("FAIL: GetModuleFileNameW failed (GLE=%lu)\n", GetLastError());
        return 1;
    }
    const wchar_t* base = wcsrchr(modName, L'\\');
    base = base ? base + 1 : modName;

    if (expected < 0 || expected > 1) {
        printf("FAIL: %ls invalid expected value (usage: %ls <0|1>)\n", base, base);
        return 1;
    }

    /* Load gmhook.dll from beside this exe. dllDir = directory of this exe,
       trailing backslash kept so concatenation yields a valid path. */
    wchar_t dllDir[MAX_PATH];
    wcscpy(dllDir, modName);
    wchar_t* slash = wcsrchr(dllDir, L'\\');
    if (slash) slash[1] = 0; else dllDir[0] = 0;
    wchar_t dllPath[MAX_PATH];
    wcscpy(dllPath, dllDir);
    wcscat(dllPath, L"gmhook.dll");

    HMODULE hHook = LoadLibraryW(dllPath);
    if (!hHook) {
        printf("FAIL: %ls LoadLibraryW(gmhook.dll) failed (GLE=%lu)\n", base, GetLastError());
        return 1;
    }

    IsHookInstalled_t pIsHook = (IsHookInstalled_t)GetProcAddress(hHook, "IsHookInstalled");
    if (!pIsHook) {
        printf("FAIL: %ls gmhook.dll does not export IsHookInstalled\n", base);
        return 1;
    }

    BOOL installed = pIsHook();
    int actual = installed ? 1 : 0;
    printf("host=%ls expected=%d actual=%d\n", base, expected, actual);

    if (actual != expected) {
        printf("FAIL: %ls expected IsHookInstalled=%d but got %d\n", base, expected, actual);
        return 1;
    }
    printf("PASS: %ls IsHookInstalled=%d\n", base, actual);
    return 0;
}
