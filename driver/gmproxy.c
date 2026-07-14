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

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif

/* TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY, SecurityImpersonation,
   TokenPrimary, PROCESS_QUERY_LIMITED_INFORMATION, and LOGON_WITH_PROFILE
   are all defined in standard Windows headers (winnt.h / winbase.h). */

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
                                    if (IsSystemSid(tu->User.Sid)) {
                                        CloseHandle(hToken);
                                        CloseHandle(hProcess);
                                        CloseHandle(hSnap);
                                        return pe.th32ProcessID;
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
                        if (IsSystemSid(tu->User.Sid)) {
                            CloseHandle(hToken);
                            CloseHandle(hProcess);
                            CloseHandle(hSnap);
                            return pe.th32ProcessID;
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

    // --- IFEO infinite-loop bypass ---
    // When we launch the original executable via CreateProcess*, Windows kernel
    // checks IFEO again and launches gmproxy.exe recursively. To prevent this,
    // create a hardlink with a unique name in the same directory. IFEO keys are
    // matched by exact filename, so chrome.exe.gmproxy won't trigger IFEO.
    // If hardlink fails (different volume), fall back to CopyFile in TEMP.
    const wchar_t* baseName = wcsrchr(argv[1], L'\\');
    if (baseName) baseName++; else baseName = argv[1];

    wchar_t hardlinkPath[MAX_PATH] = {0};
    wchar_t dirPath[MAX_PATH] = {0};
    wcscpy(dirPath, argv[1]);
    wchar_t* lastSlash = wcsrchr(dirPath, L'\\');
    if (lastSlash) lastSlash[1] = 0; /* keep trailing backslash */

    swprintf(hardlinkPath, MAX_PATH, L"%sgmproxy_%lu_%s", dirPath, GetCurrentProcessId(), baseName);

    BOOL usedHardlink = CreateHardLinkW(hardlinkPath, argv[1], NULL);
    if (!usedHardlink) {
        wchar_t tempDir[MAX_PATH] = {0};
        GetTempPathW(MAX_PATH, tempDir);
        swprintf(hardlinkPath, MAX_PATH, L"%s\\gmproxy_%lu_%s", tempDir, GetCurrentProcessId(), baseName);
        usedHardlink = CopyFileW(argv[1], hardlinkPath, FALSE);
    }

    if (!usedHardlink) {
        fwprintf(stderr, L"[GM-PROXY] ERROR: Failed to create hardlink/copy for IFEO bypass. GLE=%lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, cmdLine);
        CloseHandle(hPrimary);
        CloseHandle(hSrcToken);
        CloseHandle(hSrc);
        return 1;
    }

    // Try CreateProcessWithTokenW (requires Vista+)
    HMODULE hAdv = GetModuleHandleW(L"advapi32.dll");
    CreateProcessWithTokenW_t cpwt = NULL;
    if (hAdv) {
        cpwt = (CreateProcessWithTokenW_t)GetProcAddress(hAdv, "CreateProcessWithTokenW");
    }

    BOOL ok = FALSE;
    if (cpwt) {
        ok = cpwt(hPrimary, LOGON_WITH_PROFILE, hardlinkPath, cmdLine, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);
    }

    // Fallback: CreateProcessAsUser
    if (!ok) {
        ok = CreateProcessAsUserW(hPrimary, hardlinkPath, cmdLine, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);
    }

    // Best-effort cleanup of the hardlink/copy (may fail if process is still starting)
    DeleteFileW(hardlinkPath);

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
