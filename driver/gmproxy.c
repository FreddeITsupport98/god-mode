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
#include <stdarg.h>   /* va_list for DiagLog() */

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

/* ------------------------------------------------------------------ */
/* Diagnostics: mirror stderr diagnostic lines to a durable log file   */
/* (%TEMP%\gmproxy.log) so they survive even when IFEO launches        */
/* gmproxy.exe detached (no console). Surfaced in Export-GodModeLogs   */
/* (menu option [11]) via the "===== GM-PROXY DIAGNOSTIC LOG ====="    */
/* section. Best-effort: if the file cannot be opened, stderr still    */
/* receives every line and the launch is never affected.               */
/* ------------------------------------------------------------------ */
/* Widen an ASCII (char) string to wchar_t in-place. __DATE__/__TIME__ are
   narrow char literals; this widens them (ASCII, direct char->wchar_t) so they
   can be logged via the wide DiagLog without relying on %hs/%S (whose meaning
   differs between MSVC and MinGW wprintf modes). */
static void GmWidenAscii(const char* src, wchar_t* dst, size_t cap) {
    if (!dst || cap == 0) return;
    size_t i = 0;
    if (src) {
        for (; src[i] && i + 1 < cap; i++) dst[i] = (wchar_t)(unsigned char)src[i];
    }
    dst[i] = 0;
}

/* Ensure a wide path buffer ends with a single trailing backslash. GetTempPathW
   is documented to return a path ending in '\', and on real Windows AND wine it
   does -- this is a defensive belt-and-suspenders that appends a backslash only
   if some non-conforming environment ever omitted one (a no-op in practice;
   callers already guard the length). NOTE: the wine smoke-test Cgmproxy.log
   artifact was NOT a missing backslash -- it was %s in MinGW's wide
   swprintf/fwprintf truncating wchar_t arguments to their first character; that
   is fixed by using %ls (wide) in the format strings below. Mirrored in gmhook.c. */
static void GmEnsureTrailingBackslash(wchar_t* path, size_t cap) {
    if (!path || cap == 0) return;
    size_t n = wcslen(path);
    if (n == 0) return;
    if (path[n - 1] == L'\\') return;       /* already ends with a backslash */
    if (n + 1 < cap) {
        path[n] = L'\\';
        path[n + 1] = 0;
    }
}

static FILE* g_GmProxyDiagLog = NULL;

static FILE* GmProxyDiagLogOpen(void) {
    if (g_GmProxyDiagLog) return g_GmProxyDiagLog;
    wchar_t tempDir[MAX_PATH] = {0};
    DWORD len = GetTempPathW(MAX_PATH, tempDir);
    if (len == 0 || len >= MAX_PATH) return NULL;
    GmEnsureTrailingBackslash(tempDir, MAX_PATH);   /* harden: wine may omit the trailing '\' */
    /* Leave room for the "gmproxy.log" suffix + a session header line. */
    if (wcslen(tempDir) > (MAX_PATH - 24)) return NULL;
    wchar_t path[MAX_PATH] = {0};
    swprintf(path, MAX_PATH, L"%lsgmproxy.log", tempDir);   /* %ls: wide (MinGW swprintf %s reads wchar_t as narrow -> truncates) */
    g_GmProxyDiagLog = _wfopen(path, L"a");
    if (g_GmProxyDiagLog) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t header[80] = {0};
        swprintf(header, 80, L"=== gmproxy diag session %04u-%02u-%02u %02u:%02u:%02u ===\n",
                 (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
                 (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);
        fputws(header, g_GmProxyDiagLog);   /* fputws: write the wide header without %s truncation */
        fflush(g_GmProxyDiagLog);
    }
    return g_GmProxyDiagLog;
}

/* Write a diagnostic line to BOTH stderr and the durable gmproxy.log. */
static void DiagLog(const wchar_t* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfwprintf(stderr, fmt, ap);
    va_end(ap);
    FILE* f = GmProxyDiagLogOpen();
    if (f) {
        va_start(ap, fmt);
        vfwprintf(f, fmt, ap);
        va_end(ap);
        fflush(f);
    }
}

/* ------------------------------------------------------------------ */
/* Monitor feedback: hand a gracefully-launched PID to the God Mode    */
/* monitor via named pipe \\.\pipe\GodMode-GmProxyFeedback so the       */
/* monitor can elevate it IN PLACE (ReplaceProcessTokenForPid) instead */
/* of the 15s periodic scan kill+relaunching it (which would spawn a   */
/* duplicate). Non-blocking: if no monitor is listening, CreateFile    */
/* fails immediately (ERROR_FILE_NOT_FOUND) and we skip -- the         */
/* periodic scan remains a fallback. Never affects the launch.         */
/* ------------------------------------------------------------------ */
static void SignalGmProxyFeedback(DWORD pid) {
    if (pid == 0) return;
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GodMode-GmProxyFeedback",
                               GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) return; /* monitor not running / not SYSTEM yet */
    char buf[40];
    int n = snprintf(buf, sizeof(buf), "PID=%lu\n", (unsigned long)pid);
    if (n > 0) {
        if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
        DWORD written = 0;
        WriteFile(hPipe, buf, (DWORD)n, &written, NULL);
    }
    CloseHandle(hPipe);
}

/* Resolve the active interactive (console) session id. WTSGetActiveConsoleSessionId
   lives in wtsapi32.dll; load it dynamically so no extra link dependency is added
   and the build stays identical across MSVC/MinGW. Returns 1 (the typical
   interactive session) if the API is missing or no console session is attached. */
static DWORD GetActiveConsoleSessionId(void) {
    HMODULE hWts = LoadLibraryW(L"wtsapi32.dll");
    if (!hWts) return 1;
    typedef DWORD (WINAPI *WTSGetActiveConsoleSessionId_t)(void);
    WTSGetActiveConsoleSessionId_t pfn =
        (WTSGetActiveConsoleSessionId_t)GetProcAddress(hWts, "WTSGetActiveConsoleSessionId");
    if (!pfn) return 1;
    DWORD sid = pfn();
    return (sid == 0xFFFFFFFF) ? 1 : sid;
}

/* TRUE if pid runs in wantSid. ProcessIdToSessionId is exported by kernel32
   (already linked), so no extra dependency is needed. */
static BOOL IsProcessSessionId(DWORD pid, DWORD wantSid) {
    DWORD sid = 0;
    if (!ProcessIdToSessionId(pid, &sid)) return FALSE;
    return sid == wantSid;
}

/* TRUE if pid can be opened with PROCESS_QUERY_LIMITED_INFORMATION AND its token
   owner is Local System (S-1-5-18). PPL-protected SYSTEM processes (winlogon /
   lsass on modern builds) fail the OpenProcess and return FALSE -- which is the
   exact reason the old code silently fell back to a Session 0 SYSTEM token. */
static BOOL IsOpenableSystemProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;
    HANDLE hTok = NULL;
    BOOL isSys = FALSE;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hTok)) {
        BYTE userBuf[256]; DWORD len = 0;
        if (GetTokenInformation(hTok, TokenUser, userBuf, sizeof(userBuf), &len)) {
            TOKEN_USER* tu = (TOKEN_USER*)userBuf;
            isSys = IsSystemSid(tu->User.Sid);
        }
        CloseHandle(hTok);
    }
    CloseHandle(hProcess);
    return isSys;
}

/* Open pid, duplicate a primary SYSTEM token (TOKEN_ALL_ACCESS), and return it
   (caller closes) or NULL. The source process + source token handles are closed
   here, so the caller only owns the returned primary token. */
static HANDLE StealSystemToken(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return NULL;
    HANDLE hTok = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
        CloseHandle(hProcess);
        return NULL;
    }
    BYTE userBuf[256]; DWORD len = 0;
    BOOL isSys = FALSE;
    if (GetTokenInformation(hTok, TokenUser, userBuf, sizeof(userBuf), &len)) {
        TOKEN_USER* tu = (TOKEN_USER*)userBuf;
        isSys = IsSystemSid(tu->User.Sid);
    }
    if (!isSys) { CloseHandle(hTok); CloseHandle(hProcess); return NULL; }
    HANDLE hPrimary = NULL;
    if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimary)) {
        CloseHandle(hTok);
        CloseHandle(hProcess);
        return NULL;
    }
    CloseHandle(hTok);
    CloseHandle(hProcess);
    return hPrimary;
}

/* Find a SYSTEM process whose token ALREADY lives in the active interactive
   session (wantSession). Named interactive SYSTEM processes (winlogon / dwm /
   fontdrvhost) are preferred and returned immediately; if none is openable
   (PPL), the first openable SYSTEM process in wantSession is returned. This
   guarantees the stolen token carries the right session so the child is born on
   the interactive desktop instead of ownerless in Session 0. Returns a PID or 0. */
static DWORD FindSystemProcessForToken(DWORD wantSession) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    const wchar_t* priorityNames[] = { L"winlogon.exe", L"dwm.exe", L"fontdrvhost.exe", NULL };
    const DWORD selfPid = GetCurrentProcessId();
    DWORD anyHit = 0;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == selfPid) continue;
            if (!IsProcessSessionId(pe.th32ProcessID, wantSession)) continue;
            if (!IsOpenableSystemProcess(pe.th32ProcessID)) continue;
            /* Named interactive SYSTEM process -> best candidate, return now. */
            for (int i = 0; priorityNames[i] != NULL; i++) {
                if (_wcsicmp(pe.szExeFile, priorityNames[i]) == 0) {
                    CloseHandle(hSnap);
                    return pe.th32ProcessID;
                }
            }
            /* Otherwise remember the first session-correct SYSTEM pid as a
               fallback (covers the case where winlogon/dwm/fontdrvhost are all
               PPL-protected but another session-1 SYSTEM process is openable). */
            if (anyHit == 0) anyHit = pe.th32ProcessID;
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return anyHit; /* 0 if no session-correct SYSTEM process was openable */
}

/* Find ANY openable SYSTEM process regardless of session. Used to try
   relocating a Session 0 SYSTEM token into the active session via
   SetTokenInformation(TokenSessionId), which requires SeTcbPrivilege (only held
   when gmproxy itself runs as SYSTEM). Returns a PID or 0. */
static DWORD FindAnySystemProcessPid(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    const DWORD selfPid = GetCurrentProcessId();
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == selfPid) continue;
            if (IsOpenableSystemProcess(pe.th32ProcessID)) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        DiagLog(L"[GM-PROXY] Usage: gmproxy.exe <path_to_original.exe> [args...]\n");
        return 1;
    }

    /* Reject over-long target paths up front: several stack buffers below are
       MAX_PATH wide and wcscpy/swprintf would otherwise overflow them. */
    if (wcslen(argv[1]) >= MAX_PATH) {
        DiagLog(L"[GM-PROXY] ERROR: target path too long (>= MAX_PATH).\n");
        return 1;
    }

    /* Build-version stamp (baked in at compile time via __DATE__/__TIME__):
       changes on every recompile, so Export-GodModeLogs (menu option [11]) can
       confirm at a glance which gmproxy.exe build is actually deployed on the
       VM (stale vs. freshly rebuilt). First line of every diag session. */
    {
        wchar_t wdate[16] = {0}, wtime[16] = {0};
        GmWidenAscii(__DATE__, wdate, 16);
        GmWidenAscii(__TIME__, wtime, 16);
        DiagLog(L"[GM-PROXY] BUILD %ls %ls (compiled)\n", wdate, wtime);   /* %ls: wide wdate/wtime (MinGW %s truncates wchar_t) */
    }

    EnablePrivilege(L"SeDebugPrivilege");
    EnablePrivilege(L"SeImpersonatePrivilege");
    EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");
    /* SeTcbPrivilege ("Act as part of the operating system") is required to
       relocate a token to a different session via SetTokenInformation(
       TokenSessionId). IFEO launches gmproxy as the invoking (admin) user,
       which does NOT hold SeTcb, so enabling it is a no-op there -- but it lets
       the relocate path below succeed if gmproxy ever runs as SYSTEM. */
    EnablePrivilege(L"SeTcbPrivilege");

    DWORD activeSession = GetActiveConsoleSessionId();

    /* Detect whether gmproxy itself was born in Session 0 (the isolated services
       session). This happens when a Windows service or a "run whether logged on or
       not" scheduled task invokes gmproxy (Start-ProcessWithService /
       Invoke-HybridElevation Phase 2). In that case a current-user fallback launch
       below would inherit Session 0 -> an ownerless child (blank User column, no
       interactive desktop) -- the reported unusable symptom. We use this to REFUSE
       ownerless birth instead of degrading when no session-correct SYSTEM token is
       obtainable. In the normal IFEO path gmproxy runs in the user's interactive
       session (mySession != 0), so the current-user fallback stays available. */
    DWORD mySession = 0;
    BOOL mySessionIsZero = FALSE;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &mySession)) {
        mySessionIsZero = (mySession == 0);
    }

    /* Prefer a SYSTEM token that ALREADY lives in the active interactive
       session (winlogon/dwm/fontdrvhost, or any session-correct SYSTEM process).
       A token sourced from Session 0 (services/lsass) produces an ownerless
       child with no interactive desktop -- the reported "blank user id /
       unusable / instant-kill" symptom. */
    DWORD srcPid = FindSystemProcessForToken(activeSession);
    HANDLE hPrimary = NULL;
    if (srcPid != 0) {
        hPrimary = StealSystemToken(srcPid);
        if (hPrimary) {
            /* Belt-and-suspenders: the source already carries activeSession, but
               reassert it in case the duplicate's session drifted. Best-effort. */
            DWORD sid = activeSession;
            if (!SetTokenInformation(hPrimary, TokenSessionId, &sid, sizeof(sid))) {
                DiagLog(L"[GM-PROXY] INFO: SetTokenInformation(session=%lu) not applied (source already in session).\n", activeSession);
            }
            DiagLog(L"[GM-PROXY] Acquired active-session SYSTEM token from PID %lu (session %lu).\n", srcPid, activeSession);
        }
    }

    /* If no active-session SYSTEM token is openable (e.g. all PPL-protected),
       try to steal ANY SYSTEM token and relocate it to the active session. This
       only succeeds when SeTcb is held (gmproxy running as SYSTEM); otherwise it
       fails and we degrade gracefully (launch as the current user) below. */
    if (!hPrimary) {
        DWORD anyPid = FindAnySystemProcessPid();
        if (anyPid != 0) {
            HANDLE hTmp = StealSystemToken(anyPid);
            if (hTmp) {
                DWORD sid = activeSession;
                if (SetTokenInformation(hTmp, TokenSessionId, &sid, sizeof(sid))) {
                    hPrimary = hTmp;
                    DiagLog(L"[GM-PROXY] Relocated SYSTEM token from PID %lu to session %lu.\n", anyPid, activeSession);
                } else {
                    CloseHandle(hTmp);
                    DiagLog(L"[GM-PROXY] WARN: cannot relocate SYSTEM token to session %lu (no SeTcb). Will degrade to normal launch.\n", activeSession);
                }
            }
        }
    }

    const BOOL haveToken = (hPrimary != NULL);
    if (!haveToken) {
        DiagLog(L"[GM-PROXY] WARN: no usable SYSTEM token in session %lu; will launch target as current user (not SYSTEM).\n", activeSession);
    }

    // Build command line from argv
    size_t cmdLen = 0;
    for (int i = 1; i < argc; i++) {
        cmdLen += wcslen(argv[i]) + 3; // quotes + space
    }
    wchar_t* cmdLine = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cmdLen + 1) * sizeof(wchar_t));
    if (!cmdLine) {
        if (hPrimary) CloseHandle(hPrimary);
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

    swprintf(hardlinkPath, MAX_PATH, L"%lsgmproxy_%lu_%ls", dirPath, GetCurrentProcessId(), baseName);   /* %ls: wide dirPath + baseName */

    BOOL usedHardlink = CreateHardLinkW(hardlinkPath, argv[1], NULL);
    if (!usedHardlink) {
        wchar_t tempDir[MAX_PATH] = {0};
        GetTempPathW(MAX_PATH, tempDir);
        swprintf(hardlinkPath, MAX_PATH, L"%ls\\gmproxy_%lu_%ls", tempDir, GetCurrentProcessId(), baseName);   /* %ls: wide tempDir + baseName */
        usedHardlink = CopyFileW(argv[1], hardlinkPath, FALSE);
    }

    if (!usedHardlink) {
        DiagLog(L"[GM-PROXY] ERROR: Failed to create hardlink/copy for IFEO bypass. GLE=%lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, cmdLine);
        if (hPrimary) CloseHandle(hPrimary);
        return 1;
    }

    // Try CreateProcessWithTokenW (requires Vista+)
    HMODULE hAdv = GetModuleHandleW(L"advapi32.dll");
    CreateProcessWithTokenW_t cpwt = NULL;
    if (hAdv) {
        cpwt = (CreateProcessWithTokenW_t)GetProcAddress(hAdv, "CreateProcessWithTokenW");
    }

    BOOL ok = FALSE;
#ifdef _MSC_VER
    __try {
#endif
        if (haveToken && cpwt) {
            ok = cpwt(hPrimary, LOGON_WITH_PROFILE, hardlinkPath, cmdLine, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);
        }
        /* Fallback with the same (session-correct) SYSTEM token. */
        if (!ok && haveToken) {
            ok = CreateProcessAsUserW(hPrimary, hardlinkPath, cmdLine, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);
        }
#ifdef _MSC_VER
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
#endif

    /* Graceful degradation: if we never had a session-correct SYSTEM token (all
       SYSTEM processes PPL-protected and gmproxy lacks SeTcb to relocate one),
       OR the token launch failed, launch the target as the CURRENT user via the
       IFEO-bypass hardlink. The app then runs normally (not SYSTEM) instead of
       being born ownerless in Session 0 with no interactive desktop. The God
       Mode monitor will still elevate it to SYSTEM via its normal kill+relaunch
       path, so this is strictly better than a broken ownerless launch. */
    if (!ok) {
        /* Belt-and-suspenders ownerless-birth refusal: if gmproxy itself is
           running in Session 0 (invoked by a SYSTEM service / Session-0 scheduled
           task), a current-user CreateProcessW launch here would inherit
           Session 0 -> an ownerless child (blank User column, no desktop). We
           only reach this fallback when the session-correct SYSTEM token launch
           above also failed, so the only honest outcome is to REFUSE rather than
           birth an unusable ownerless process. The caller (Start-ProcessWithService
           / scheduled task) sees no child; the user can relaunch the app normally.
           In the normal IFEO path gmproxy runs in the interactive session
           (mySession != 0), so the graceful current-user fallback below stays
           available there. */
        if (mySessionIsZero) {
            DiagLog(L"[GM-PROXY] REFUSE: gmproxy is in Session %lu with no session-correct SYSTEM token; aborting to avoid ownerless Session-0 birth (would inherit Session 0, blank User column).\n", mySession);
            DeleteFileW(hardlinkPath);
            HeapFree(GetProcessHeap(), 0, cmdLine);
            if (hPrimary) CloseHandle(hPrimary);
            return 1;
        }
        ok = CreateProcessW(hardlinkPath, cmdLine, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);
        if (ok) {
            DiagLog(L"[GM-PROXY] Launched %ls as current user (graceful fallback, PID=%lu, session=%lu).\n", argv[1], pi.dwProcessId, activeSession);   /* %ls: wide argv[1] */
            /* Hand the PID to the God Mode monitor so it can elevate this process
               IN PLACE (token replacement) instead of the 15s periodic scan
               kill+relaunching it (which would spawn a duplicate). Best-effort:
               if no monitor is listening, the periodic scan remains a fallback. */
            SignalGmProxyFeedback(pi.dwProcessId);
            DiagLog(L"[GM-PROXY] Handed PID %lu to monitor via GodMode-GmProxyFeedback for in-place elevation.\n", pi.dwProcessId);
        }
    }

    // Best-effort cleanup of the hardlink/copy (may fail if process is still starting)
    DeleteFileW(hardlinkPath);

    if (!ok) {
        DiagLog(L"[GM-PROXY] ERROR: launch failed (token path + current-user fallback). GLE=%lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, cmdLine);
        if (hPrimary) CloseHandle(hPrimary);
        return 1;
    }

    if (haveToken) {
        DiagLog(L"[GM-PROXY] SUCCESS: Launched %ls as SYSTEM (PID=%lu, session=%lu).\n", argv[1], pi.dwProcessId, activeSession);   /* %ls: wide argv[1] */
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    HeapFree(GetProcessHeap(), 0, cmdLine);
    if (hPrimary) CloseHandle(hPrimary);
    return 0;
}
