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
static CRITICAL_SECTION gHookLock;

/* Lazy-resolve CreateProcessWithTokenW from advapi32.dll.
   DllMain might run before advapi32.dll is loaded in the target process.
   We resolve on first use instead of failing silently. */
static CreateProcessWithTokenW_t ResolveCreateProcessWithTokenW(void) {
    if (pCreateWithToken) return pCreateWithToken;
    HMODULE hAdvapi = GetModuleHandleW(L"advapi32.dll");
    if (!hAdvapi) hAdvapi = LoadLibraryW(L"advapi32.dll");
    if (hAdvapi) {
        pCreateWithToken = (CreateProcessWithTokenW_t)GetProcAddress(hAdvapi, "CreateProcessWithTokenW");
    }
    return pCreateWithToken;
}

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
    char buf[1024];
    sprintf(buf, "[GMHOOK] CreateProcessW hook: app=%S cmd=%S\n",
            lpApplicationName ? lpApplicationName : L"(null)",
            lpCommandLine ? lpCommandLine : L"(null)");
    OutputDebugStringA(buf);

    if (!pOrigCreateProcessW) {
        HMODULE hKb = GetModuleHandleW(L"kernelbase.dll");
        HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
        if (hKb) pOrigCreateProcessW = (CreateProcessW_t)GetProcAddress(hKb, "CreateProcessW");
        if (!pOrigCreateProcessW && hK32) pOrigCreateProcessW = (CreateProcessW_t)GetProcAddress(hK32, "CreateProcessW");
    }

    if (!lpApplicationName && !lpCommandLine) {
        OutputDebugStringA("[GMHOOK] Both app and cmd are NULL, passing through.\n");
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

    sprintf(buf, "[GMHOOK] baseName=%S\n", baseName ? baseName : L"(null)");
    OutputDebugStringA(buf);

    /* Pass through critical OS processes untouched */
    if (IsCriticalProcess(baseName)) {
        OutputDebugStringA("[GMHOOK] Critical process, passing through.\n");
        return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    /* Ensure token is ready */
    if (!gSystemToken) {
        OutputDebugStringA("[GMHOOK] gSystemToken missing, preparing...\n");
        EnablePrivilege(L"SeDebugPrivilege");
        EnablePrivilege(L"SeImpersonatePrivilege");
        if (!PrepareSystemToken()) {
            OutputDebugStringA("[GMHOOK] PrepareSystemToken failed, falling back.\n");
            return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }
        OutputDebugStringA("[GMHOOK] gSystemToken prepared OK.\n");
    }

    /* Ensure CreateProcessWithTokenW is resolved (advapi32 may not be loaded at DllMain time). */
    CreateProcessWithTokenW_t pCpwt = ResolveCreateProcessWithTokenW();
    if (pCpwt) {
        /* CreateProcessWithTokenW requires lpDesktop to be specified for cross-session
           tokens. If the caller passed NULL, we must copy STARTUPINFO and set it. */
        STARTUPINFOW siCopy = {0};
        LPSTARTUPINFOW pSi;
        if (lpStartupInfo) {
            if (lpStartupInfo->cb >= sizeof(STARTUPINFOW)) {
                siCopy = *lpStartupInfo;
            } else {
                memcpy(&siCopy, lpStartupInfo, lpStartupInfo->cb);
            }
            if (!siCopy.lpDesktop) siCopy.lpDesktop = L"Winsta0\\Default";
            pSi = &siCopy;
        } else {
            siCopy.cb = sizeof(siCopy);
            siCopy.lpDesktop = L"Winsta0\\Default";
            pSi = &siCopy;
        }

        /* CreateProcessWithTokenW does not support EXTENDED_STARTUPINFO_PRESENT.
           If the caller used it, fall back to the original path. */
        if (!(dwCreationFlags & 0x00080000)) { /* EXTENDED_STARTUPINFO_PRESENT = 0x00080000 */
            OutputDebugStringA("[GMHOOK] Calling CreateProcessWithTokenW...\n");
            BOOL ret = pCpwt(gSystemToken, 0, lpApplicationName, lpCommandLine,
                dwCreationFlags, lpEnvironment, lpCurrentDirectory, pSi,
                lpProcessInformation);
            if (ret) {
                OutputDebugStringA("[GMHOOK] CreateProcessWithTokenW SUCCEEDED.\n");
                return TRUE;
            }
            sprintf(buf, "[GMHOOK] CreateProcessWithTokenW FAILED: GLE=%lu\n", GetLastError());
            OutputDebugStringA(buf);
        } else {
            OutputDebugStringA("[GMHOOK] EXTENDED_STARTUPINFO_PRESENT set, falling back.\n");
        }
    } else {
        OutputDebugStringA("[GMHOOK] CreateProcessWithTokenW not resolved, falling back.\n");
    }

    OutputDebugStringA("[GMHOOK] Falling back to original CreateProcessW.\n");
    return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

/* IAT hook helper: patch a single module's IAT for CreateProcessW. */
static BOOL HookModuleIAT(HMODULE hMod) {
    if (!hMod) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)
        ((BYTE*)hMod + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) return FALSE;

    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    void* realAddr = NULL;
    void* realAddrBase = NULL;
    if (hKernel) realAddr = GetProcAddress(hKernel, "CreateProcessW");
    if (hKernelBase) realAddrBase = GetProcAddress(hKernelBase, "CreateProcessW");
    if (!realAddr && !realAddrBase) return FALSE;

    BOOL hooked = FALSE;
    for (; importDesc->Name; importDesc++) {
        PIMAGE_THUNK_DATA origThunk = NULL;
        if (importDesc->OriginalFirstThunk) {
            origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hMod + importDesc->OriginalFirstThunk);
        }
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
                    if (!pOrigCreateProcessW) {
                        pOrigCreateProcessW = (CreateProcessW_t)thunk->u1.Function;
                    }
                    thunk->u1.Function = (ULONG_PTR)HookCreateProcessW;
                    VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                                   oldProtect, &oldProtect);
                    hooked = TRUE;
                }
            }
        } else {
            for (; thunk->u1.Function; thunk++) {
                if (thunk->u1.Function == (ULONG_PTR)realAddr || thunk->u1.Function == (ULONG_PTR)realAddrBase) {
                    DWORD oldProtect;
                    if (VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                                       PAGE_READWRITE, &oldProtect)) {
                        if (!pOrigCreateProcessW) {
                            pOrigCreateProcessW = (CreateProcessW_t)thunk->u1.Function;
                        }
                        thunk->u1.Function = (ULONG_PTR)HookCreateProcessW;
                        VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                                       oldProtect, &oldProtect);
                        hooked = TRUE;
                    }
                }
            }
        }
    }
    return hooked;
}

/* Enumerate all loaded modules and hook each one's IAT.
   Modern browsers (Firefox, Chrome, Edge) and explorer call CreateProcessW
   from their loaded DLLs, not the main executable. */
static BOOL InstallIATHook(void) {
    BOOL hooked = FALSE;

    /* Hook the main executable first */
    hooked |= HookModuleIAT(GetModuleHandle(NULL));

    /* Enumerate all loaded modules and hook each one */
    HMODULE hMods[1024];
    DWORD cbNeeded;
    HMODULE hPsapi = GetModuleHandleW(L"psapi.dll");
    if (!hPsapi) hPsapi = LoadLibraryW(L"psapi.dll");
    if (hPsapi) {
        typedef BOOL (WINAPI *EnumProcessModules_t)(HANDLE, HMODULE*, DWORD, LPDWORD);
        EnumProcessModules_t pEnum = (EnumProcessModules_t)GetProcAddress(hPsapi, "EnumProcessModules");
        if (pEnum && pEnum(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
            DWORD count = cbNeeded / sizeof(HMODULE);
            for (DWORD i = 0; i < count; i++) {
                if (hMods[i] != GetModuleHandle(NULL)) {
                    hooked |= HookModuleIAT(hMods[i]);
                }
            }
        }
    }
    return hooked;
}

static void RemoveIATHook(void) {
    if (!pOrigCreateProcessW) return;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    HMODULE hPsapi = GetModuleHandleW(L"psapi.dll");
    if (!hPsapi) hPsapi = LoadLibraryW(L"psapi.dll");
    if (hPsapi) {
        typedef BOOL (WINAPI *EnumProcessModules_t)(HANDLE, HMODULE*, DWORD, LPDWORD);
        EnumProcessModules_t pEnum = (EnumProcessModules_t)GetProcAddress(hPsapi, "EnumProcessModules");
        if (pEnum && pEnum(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
            DWORD count = cbNeeded / sizeof(HMODULE);
            for (DWORD i = 0; i < count; i++) {
                HMODULE hMod = hMods[i];
                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
                PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)
                    ((BYTE*)hMod + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
                if (!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) continue;
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
            }
        }
    }
    pOrigCreateProcessW = NULL;
}


/* GetMsgProc for SetWindowsHookEx global injection */
__declspec(dllexport) LRESULT CALLBACK GetMsgProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && !hookInstalled) {
        EnterCriticalSection(&gHookLock);
        if (!hookInstalled) {
            wchar_t modName[MAX_PATH];
            GetModuleFileNameW(NULL, modName, MAX_PATH);
            wchar_t* baseName = wcsrchr(modName, L'\\');
            if (baseName) baseName++; else baseName = modName;
            if (!IsCriticalProcess(baseName)) {
                EnablePrivilege(L"SeDebugPrivilege");
                EnablePrivilege(L"SeImpersonatePrivilege");
                if (!gSystemToken) PrepareSystemToken();
                hookInstalled = InstallIATHook();
                char buf[512];
                sprintf(buf, "[GMHOOK] GetMsgProc installed hook in %S: %d\n", modName, hookInstalled);
                OutputDebugStringA(buf);
            }
        }
        LeaveCriticalSection(&gHookLock);
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
        InitializeCriticalSection(&gHookLock);
        pNtSetInfo = (NtSetInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess");
        /* Resolve pCreateWithToken eagerly if advapi32.dll is already loaded;
           if not, ResolveCreateProcessWithTokenW() will lazy-load it on first use. */
        pCreateWithToken = (CreateProcessWithTokenW_t)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "CreateProcessWithTokenW");
        /* Only install hook if this process is not critical */
        wchar_t modName[MAX_PATH];
        GetModuleFileNameW(NULL, modName, MAX_PATH);
        wchar_t* baseName = wcsrchr(modName, L'\\');
        if (baseName) baseName++; else baseName = modName;
        if (!IsCriticalProcess(baseName)) {
            EnablePrivilege(L"SeDebugPrivilege");
            EnablePrivilege(L"SeImpersonatePrivilege");
            if (!gSystemToken) PrepareSystemToken();
            EnterCriticalSection(&gHookLock);
            hookInstalled = InstallIATHook();
            LeaveCriticalSection(&gHookLock);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (hookInstalled) {
            EnterCriticalSection(&gHookLock);
            RemoveIATHook();
            hookInstalled = FALSE;
            LeaveCriticalSection(&gHookLock);
        }
        if (gSystemToken) CloseHandle(gSystemToken);
        DeleteCriticalSection(&gHookLock);
    }
    return TRUE;
}
