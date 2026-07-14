/*
 * gmhook.c — God Mode Shell Hook DLL
 * Injects into explorer.exe and hooks CreateProcessW to intercept every
 * process launch before it starts executing.  The intercepted process is created
 * suspended, its primary token is replaced with a stolen SYSTEM token via
 * NtSetInformationProcess, and then the process is resumed.
 *
 * Build: cl /LD /O2 gmhook.c /link /EXPORT:InstallHook /EXPORT:UninstallHook user32.lib ntdll.lib advapi32.lib kernel32.lib
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")

#define TOKEN_ALL_ACCESS           0xF01FF
#define TOKEN_DUPLICATE            0x0002
#define TOKEN_QUERY                0x0008
#define SecurityImpersonation      2
#define TokenPrimary               1
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define PROCESS_SET_INFORMATION    0x0200

/* NtSetInformationProcess and ProcessAccessToken */
#define ProcessAccessToken 9

typedef NTSTATUS (NTAPI *NtSetInformationProcess_t)(
    HANDLE ProcessHandle,
    int ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength);

typedef BOOL (WINAPI *CreateProcessW_t)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

static NtSetInformationProcess_t pNtSetInfo = NULL;
static CreateProcessW_t pOrigCreateProcessW = NULL;
static BYTE origBytes[5] = {0};
static BOOL hookInstalled = FALSE;
static DWORD gSystemPid = 0;
static HANDLE gSystemToken = NULL;

static BOOL EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privName, &luid)) { CloseHandle(hToken); return FALSE; }
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && GetLastError() == 0;
}

static DWORD FindSystemPid(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    const wchar_t* names[] = { L"winlogon.exe", L"dwm.exe", L"fontdrvhost.exe", L"csrss.exe" };
    for (int i = 0; i < 4; i++) {
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, names[i]) == 0) {
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (hProc) {
                        HANDLE hTok;
                        if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
                            BYTE buf[256];
                            DWORD len;
                            if (GetTokenInformation(hTok, TokenUser, buf, sizeof(buf), &len)) {
                                TOKEN_USER* tu = (TOKEN_USER*)buf;
                                WCHAR* sidStr = NULL;
                                if (ConvertSidToStringSidW(tu->User.Sid, &sidStr)) {
                                    if (wcscmp(sidStr, L"S-1-5-18") == 0) {
                                        LocalFree(sidStr);
                                        CloseHandle(hTok);
                                        CloseHandle(hProc);
                                        CloseHandle(hSnap);
                                        return pe.th32ProcessID;
                                    }
                                    LocalFree(sidStr);
                                }
                            }
                            CloseHandle(hTok);
                        }
                        CloseHandle(hProc);
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }
    }
    CloseHandle(hSnap);
    return 0;
}

static BOOL PrepareSystemToken(void) {
    if (gSystemToken) return TRUE;
    gSystemPid = FindSystemPid();
    if (!gSystemPid) return FALSE;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, gSystemPid);
    if (!hProc) return FALSE;
    HANDLE hTok;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
        CloseHandle(hProc);
        return FALSE;
    }
    if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &gSystemToken)) {
        CloseHandle(hTok);
        CloseHandle(hProc);
        gSystemToken = NULL;
        return FALSE;
    }
    CloseHandle(hTok);
    CloseHandle(hProc);
    return TRUE;
}

/* Intercepted CreateProcessW */
static BOOL WINAPI HookCreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    /* Only intercept user-session processes (not SYSTEM services) */
    /* Check if the process is being created by a non-SYSTEM user */
    /* For simplicity, we intercept all processes and skip critical ones by name */
    if (!lpApplicationName && !lpCommandLine) {
        return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    /* Determine executable name for filtering */
    const wchar_t* exePath = lpApplicationName;
    wchar_t parsedPath[MAX_PATH] = {0};
    if (!exePath && lpCommandLine) {
        /* Parse first quoted or unquoted token from command line */
        const wchar_t* p = lpCommandLine;
        while (*p == L' ') p++;
        if (*p == L'"') {
            p++;
            int i = 0;
            while (*p && *p != L'"' && i < MAX_PATH - 1) parsedPath[i++] = *p++;
            parsedPath[i] = 0;
            exePath = parsedPath;
        } else {
            int i = 0;
            while (*p && *p != L' ' && i < MAX_PATH - 1) parsedPath[i++] = *p++;
            parsedPath[i] = 0;
            exePath = parsedPath;
        }
    }

    const wchar_t* baseName = exePath;
    if (baseName) {
        const wchar_t* slash = wcsrchr(baseName, L'\\');
        if (slash) baseName = slash + 1;
        const wchar_t* critical[] = {
            L"csrss.exe", L"lsass.exe", L"services.exe", L"smss.exe",
            L"winlogon.exe", L"wininit.exe", L"svchost.exe", L"dwm.exe",
            L"fontdrvhost.exe", L"powershell.exe", L"pwsh.exe", L"cmd.exe",
            L"conhost.exe", L"explorer.exe", L"godmode.exe", NULL
        };
        for (int i = 0; critical[i]; i++) {
            if (baseName && _wcsicmp(baseName, critical[i]) == 0) {
                return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                    lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                    lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
            }
        }
    }

    /* Ensure token is ready */
    if (!gSystemToken) {
        EnablePrivilege(L"SeDebugPrivilege");
        EnablePrivilege(L"SeImpersonatePrivilege");
        EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");
        if (!PrepareSystemToken()) {
            /* Fallback: original behavior */
            return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }
    }

    /* Create suspended */
    DWORD flags = dwCreationFlags | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    BOOL ret = pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, flags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if (!ret) return FALSE;

    /* Replace token on the newly created process */
    if (pNtSetInfo) {
        struct _PROCESS_ACCESS_TOKEN {
            HANDLE Token;
            HANDLE Thread;
        } pat = { gSystemToken, NULL };
        NTSTATUS status = pNtSetInfo(lpProcessInformation->hProcess, ProcessAccessToken, &pat, sizeof(pat));
        if (status != 0) {
            /* Token replacement failed — terminate the suspended process so the user doesn't run un-elevated */
            TerminateProcess(lpProcessInformation->hProcess, 1);
            CloseHandle(lpProcessInformation->hProcess);
            CloseHandle(lpProcessInformation->hThread);
            return FALSE;
        }
    }

    /* Resume the process now running as SYSTEM */
    ResumeThread(lpProcessInformation->hThread);
    return TRUE;
}

/* Inline hook: overwrite first 5 bytes of CreateProcessW with a JMP to our hook */
static BOOL InstallInlineHook(void) {
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel) return FALSE;
    pOrigCreateProcessW = (CreateProcessW_t)GetProcAddress(hKernel, "CreateProcessW");
    if (!pOrigCreateProcessW) return FALSE;

    /* Save original bytes */
    memcpy(origBytes, pOrigCreateProcessW, 5);

    DWORD oldProtect;
    if (!VirtualProtect(pOrigCreateProcessW, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) return FALSE;

    /* Write JMP rel32 */
    BYTE jmp[5];
    jmp[0] = 0xE9;
    DWORD offset = (DWORD)HookCreateProcessW - (DWORD)pOrigCreateProcessW - 5;
    memcpy(&jmp[1], &offset, 4);
    memcpy(pOrigCreateProcessW, jmp, 5);

    VirtualProtect(pOrigCreateProcessW, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), pOrigCreateProcessW, 5);
    return TRUE;
}

static void RemoveInlineHook(void) {
    if (!pOrigCreateProcessW) return;
    DWORD oldProtect;
    if (VirtualProtect(pOrigCreateProcessW, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(pOrigCreateProcessW, origBytes, 5);
        VirtualProtect(pOrigCreateProcessW, 5, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), pOrigCreateProcessW, 5);
    }
}

/* DLL Entry */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        pNtSetInfo = (NtSetInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess");
        if (pNtSetInfo) {
            hookInstalled = InstallInlineHook();
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (hookInstalled) RemoveInlineHook();
        if (gSystemToken) CloseHandle(gSystemToken);
    }
    return TRUE;
}

/* Exported install/uninstall for manual injection */
__declspec(dllexport) void InstallHook(void) {
    if (!hookInstalled) hookInstalled = InstallInlineHook();
}

__declspec(dllexport) void UninstallHook(void) {
    if (hookInstalled) { RemoveInlineHook(); hookInstalled = FALSE; }
}
