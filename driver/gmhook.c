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

/* Widen an ASCII (char) string to wchar_t in-place (ASCII, direct char->wchar_t).
   __DATE__/__TIME__ are narrow char literals; this widens them so they can be
   logged via the wide fwprintf without relying on %hs/%S (whose meaning differs
   between MSVC and MinGW wprintf modes). Mirrors gmproxy.c's GmWidenAscii. */
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
   callers already guard the length). NOTE: the wine smoke-test Cgmhook.log
   artifact was NOT a missing backslash -- it was %s in MinGW's wide
   swprintf/fwprintf truncating wchar_t arguments to their first character; that
   is fixed by using %ls (wide) in the format strings below. Mirrors gmproxy.c. */
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

/* Build-version stamp: baked in at compile time via __DATE__/__TIME__, so it
   changes on every recompile. Written to %TEMP%\gmhook.log on every
   DLL_PROCESS_ATTACH (best-effort, mutex try-locked so DllMain never blocks
   under the loader lock, size-capped at ~256KB so it cannot grow unbounded
   across thousands of attaches) and mirrored to OutputDebugStringW for live
   DebugView tracing. Export-GodModeLogs (menu option [11]) extracts the last
   `[GM-HOOK] BUILD` line so a stale vs. freshly-rebuilt gmhook.dll is
   identifiable at a glance; the host process base name is included so the dump
   also shows which processes actually loaded the new DLL. Never affects the
   hook: every step is best-effort and errors are ignored. */
static void GmHookWriteBuildStamp(void) {
    wchar_t tempDir[MAX_PATH] = {0};
    DWORD len = GetTempPathW(MAX_PATH, tempDir);
    if (len == 0 || len >= MAX_PATH) return;
    GmEnsureTrailingBackslash(tempDir, MAX_PATH);   /* harden: wine may omit the trailing '\' */
    if (wcslen(tempDir) > (MAX_PATH - 24)) return;
    wchar_t path[MAX_PATH] = {0};
    swprintf(path, MAX_PATH, L"%lsgmhook.log", tempDir);   /* %ls: wide (MinGW swprintf %s reads wchar_t as narrow -> truncates) */

    /* Host process base name (so the stamp shows who loaded this DLL). */
    wchar_t modName[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, modName, MAX_PATH);
    wchar_t* baseName = wcsrchr(modName, L'\\');
    if (baseName) baseName++; else baseName = modName;

    wchar_t wdate[16] = {0}, wtime[16] = {0};
    GmWidenAscii(__DATE__, wdate, 16);
    GmWidenAscii(__TIME__, wtime, 16);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t line[256] = {0};
    swprintf(line, 256,
        L"[GM-HOOK] BUILD %ls %ls loaded in %ls (attach %04u-%02u-%02u %02u:%02u:%02u)\n",   /* %ls: wide wdate/wtime/baseName (MinGW %s truncates wchar_t) */
        wdate, wtime, baseName,
        (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
        (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);

    /* Live debug trace (DebugView) -- no file needed. */
    OutputDebugStringW(line);

    /* Serialize appends across the many processes that load this DLL. Use a
       try-lock (zero timeout) so DllMain never blocks under the loader lock. */
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"GodMode_GmHookLog");
    if (hMutex) {
        if (WaitForSingleObject(hMutex, 0) == WAIT_OBJECT_0) {
            /* Size cap: if the log exceeds 256KB, truncate it (rewrite fresh)
               so it cannot grow unbounded across thousands of attaches. */
            WIN32_FILE_ATTRIBUTE_DATA fad;
            BOOL truncate = FALSE;
            if (GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) {
                ULONGLONG sz = ((ULONGLONG)fad.nFileSizeHigh << 32) | (ULONGLONG)fad.nFileSizeLow;
                if (sz > (256 * 1024)) truncate = TRUE;
            }
            FILE* f = _wfopen(path, truncate ? L"w" : L"a");
            if (f) {
                fputws(line, f);   /* fputws: write the wide line without %s truncation */
                fflush(f);
                fclose(f);
            }
            ReleaseMutex(hMutex);
        }
        CloseHandle(hMutex);
    }
}

/* Resolve the active interactive (console) session id. WTSGetActiveConsoleSessionId
   lives in wtsapi32.dll; load it dynamically so no extra link dependency is added
   (gmhook.dll is not linked against wtsapi32). Returns 1 (the typical interactive
   session) if the API is missing or no console session is attached (0xFFFFFFFF).
   Mirrors gmproxy.c's GetActiveConsoleSessionId so the hook selects a SYSTEM
   token that already lives in the active session -- a Session-0 SYSTEM token
   (e.g. a Session-0 csrss) would birth children ownerless (empty User column,
   no visible window). */
static DWORD GmHookGetActiveConsoleSessionId(void) {
    HMODULE hWts = GetModuleHandleW(L"wtsapi32.dll");
    if (!hWts) hWts = LoadLibraryW(L"wtsapi32.dll");
    if (!hWts) return 1;
    typedef DWORD (WINAPI *WTSGetActiveConsoleSessionId_t)(void);
    WTSGetActiveConsoleSessionId_t pfn =
        (WTSGetActiveConsoleSessionId_t)GetProcAddress(hWts, "WTSGetActiveConsoleSessionId");
    if (!pfn) return 1;
    DWORD sid = pfn();
    return (sid == 0xFFFFFFFF) ? 1 : sid;
}

static DWORD FindSystemPid(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD activeSession = GmHookGetActiveConsoleSessionId();
    const wchar_t* names[] = { L"winlogon.exe", L"dwm.exe", L"fontdrvhost.exe", L"csrss.exe" };
    for (int i = 0; i < 4; i++) {
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, names[i]) == 0) {
                    /* Session filter: only accept a SYSTEM process in the active
                       interactive session. A Session-0 SYSTEM token (e.g. the
                       Session-0 csrss) births children ownerless (empty User
                       column, no visible window). ProcessIdToSessionId is
                       exported by kernel32 (already linked). Skip if the session
                       cannot be resolved or is not the active session. */
                    DWORD procSession = 0;
                    if (!ProcessIdToSessionId(pe.th32ProcessID, &procSession) || procSession != activeSession) {
                        continue;
                    }
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

/* Shell / launcher hosts are NEVER IAT-hooked in-process. PowerShell
   (pwsh.exe / powershell.exe) and cmd.exe launch native commands via
   CreateProcessW as their core job; rerouting those calls through the
   stolen-token CreateProcessWithTokenW path destabilizes the host and
   faults with STATUS_ACCESS_VIOLATION (0xC0000005) inside
   Kernel32.CreateProcess -- a native AV that PowerShell try/catch cannot
   recover from (it kills pwsh.exe, exactly the crash being fixed).
   Terminals (wt / conhost / OpenConsole / WindowsTerminal) host those
   shells, so they are excluded too. explorer.exe is ALSO excluded: it
   launches Task Manager and most modern shell apps with a
   STARTUPINFOEX (EXTENDED_STARTUPINFO_PRESENT) structure, and the
   TryCreateProcessWithSystemToken STARTUPINFOEX -> plain STARTUPINFOW
   DOWNGRADE (cb clamp + EXTENDED bit clear) drops the caller's attribute
   list (inherited-handle list / mitigation policies) -- explorer then
   crashes on the next CreateProcessW it issues expecting those extended
   attributes, and the shell restarts it, producing the repeated
   explorer.exe crash/restart loop (blank User column alongside the live
   monitor loop missing). explorer is still elevated to SYSTEM by the
   task / service path in God-Mode-Windows.ps1 (Invoke-HybridElevation /
   CreateProcessAsSystem) and managed by the SystemDesktop session path;
   it is simply not IAT-hooked in-process. These hosts are still elevated
   to SYSTEM by the task / service path; they are simply not IAT-hooked
   in-process. */
static BOOL IsShellLauncherProcess(const wchar_t* baseName) {
    if (!baseName) return FALSE;
    const wchar_t* shells[] = {
        L"pwsh.exe", L"powershell.exe", L"powershell_ise.exe", L"cmd.exe", L"wt.exe",
        L"conhost.exe", L"OpenConsole.exe", L"WindowsTerminal.exe", L"explorer.exe", NULL
    };
    for (int i = 0; shells[i]; i++) {
        if (_wcsicmp(baseName, shells[i]) == 0) return TRUE;
    }
    return FALSE;
}

/* Interactive shells ONLY -- the strict subset of IsShellLauncherProcess that
   the user actually types into: cmd / powershell / pwsh / powershell_ise.
   Excludes the launcher hosts (explorer / wt / conhost / OpenConsole /
   WindowsTerminal): those host shells and render the desktop/taskbar, and an
   in-place SYSTEM token swap on them breaks the desktop (the monitor's
   CriticalProcs guard skips them for the same reason). This predicate gates
   the SHELLPID birth-signal below -- only a real interactive shell is worth
   signaling the monitor to in-place elevate. */
static BOOL IsInteractiveShell(const wchar_t* baseName) {
    if (!baseName) return FALSE;
    const wchar_t* shells[] = {
        L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"powershell_ise.exe", NULL
    };
    for (int i = 0; shells[i]; i++) {
        if (_wcsicmp(baseName, shells[i]) == 0) return TRUE;
    }
    return FALSE;
}

/* Instant shell elevation -- the birth-signal. When a hooked host (typically
   explorer.exe, which IS injected with gmhook) launches an interactive shell,
   the shell is born as the host's normal user token (the real CreateProcessW
   above) -- visible, correct session/cwd/history. This hands the new shell's
   PID to the God Mode SYSTEM monitor over the SAME named pipe gmproxy uses
   (\\.\pipe\GodMode-GmProxyFeedback) with a SHELLPID=<n> payload so the
   monitor can in-place swap its token to SYSTEM (ReplaceProcessTokenForPid,
   which needs SeTcbPrivilege -- only the SYSTEM monitor holds it) within ~ms,
   instead of waiting for the 3s/5s/15s scan to catch it.
   gmhook does NOT elevate the shell itself: it holds no SeTcb here, and
   rerouting the shell's own CreateProcessW through the stolen-token
   CreateProcessWithTokenW path crashes it with 0xC0000005 (see
   IsShellLauncherProcess comment). It only NOTIFIES the monitor, which does
   the safe in-place swap. Non-blocking + fail-open: CreateFileW(OPEN_EXISTING)
   returns immediately (ERROR_FILE_NOT_FOUND) if no monitor is listening yet,
   and any write error is swallowed -- the 3s/15s periodic scan remains the
   fallback. The real CreateProcessW already succeeded before this is called,
   so a signal failure never affects the launch. Mirrors gmproxy.c's
   SignalGmProxyFeedback (same pipe, same connect/write pattern, distinct
   SHELLPID= prefix so the monitor listener routes shell signals to the
   shell-elevation path, not the normal-app feedback path). */
static void SignalShellBirth(DWORD pid) {
    if (pid == 0) return;
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GodMode-GmProxyFeedback",
                               GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) return; /* monitor not running / not listening yet */
    char buf[40];
    int n = snprintf(buf, sizeof(buf), "SHELLPID=%lu\n", (unsigned long)pid);
    if (n > 0) {
        if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
        DWORD written = 0;
        WriteFile(hPipe, buf, (DWORD)n, &written, NULL);
    }
    CloseHandle(hPipe);
}

/* Attempt to launch the child directly as SYSTEM via CreateProcessWithTokenW.
   Returns TRUE on success, FALSE on failure (caller falls back to the real
   CreateProcessW). Isolated into its own function so an MSVC __try/__except
   guard around the call can convert any fault into a plain FALSE instead of
   crashing the host process (the 0xC0000005 seen after "Defender processes
   terminated."). The deterministic normalization below is the actual fix and
   works on every toolchain; the SEH guard is defense-in-depth on MSVC builds. */
static BOOL TryCreateProcessWithSystemToken(
    CreateProcessWithTokenW_t pCpwt,
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    /* CreateProcessWithTokenW cannot consume an EXTENDED_STARTUPINFO attribute
       list, needs a non-NULL PROCESS_INFORMATION, and needs the stolen SYSTEM
       token. The NULL/guard checks below stay hard requirements; everything
       else is normalized so we can still take the token path. */
    if (!pCpwt || !gSystemToken || !lpProcessInformation) return FALSE;

    /* Build a PLAIN STARTUPINFOW copy. If the caller passed a STARTUPINFOEX
       (cb > sizeof(STARTUPINFOW) and/or EXTENDED_STARTUPINFO_PRESENT set) -- which
       is how explorer.exe launches Task Manager and most modern shell apps -- we
       DOWNGRADE to a plain STARTUPINFOW instead of bailing out unelevated:
         - copy only the first sizeof(STARTUPINFOW) bytes (STARTUPINFOEX begins
           with an embedded STARTUPINFOW, so those bytes are always valid),
         - clamp cb to sizeof(STARTUPINFOW) so the kernel never reads an
           lpAttributeList pointer past our local (the original 0xC0000005 was
           caused by leaving cb == sizeof(STARTUPINFOEX) on a truncated local),
         - CLEAR the EXTENDED_STARTUPINFO_PRESENT (0x00080000) bit from the
           creation flags we pass on, so the kernel does not treat our plain
           STARTUPINFOW as a STARTUPINFOEX and try to dereference an attribute
           list that is not there.
       The caller's attribute list (inherited handle list / mitigation policies)
       is intentionally dropped so the child can be BORN as SYSTEM; on any
       failure we still fall back to the real CreateProcessW (which preserves
       the attribute list but runs unelevated), so there is no regression. */
    STARTUPINFOW siCopy = {0};
    LPSTARTUPINFOW pSi;
    if (lpStartupInfo) {
        if (lpStartupInfo->cb >= sizeof(STARTUPINFOW)) {
            memcpy(&siCopy, lpStartupInfo, sizeof(STARTUPINFOW)); /* base fields (plain OR EX) */
        } else if (lpStartupInfo->cb > 0) {
            memcpy(&siCopy, lpStartupInfo, lpStartupInfo->cb);
        }
        /* Clamp cb to the real size of our local STARTUPINFOW so the kernel
           never reads past it as a STARTUPINFOEX. */
        siCopy.cb = sizeof(siCopy);
        if (!siCopy.lpDesktop) siCopy.lpDesktop = L"Winsta0\\Default";
        pSi = &siCopy;
    } else {
        siCopy.cb = sizeof(siCopy);
        siCopy.lpDesktop = L"Winsta0\\Default";
        pSi = &siCopy;
    }

    /* Strip EXTENDED_STARTUPINFO_PRESENT: we now pass a plain STARTUPINFOW. */
    DWORD flagsOut = dwCreationFlags & ~0x00080000u;

    return pCpwt(gSystemToken, 0, lpApplicationName, lpCommandLine,
        flagsOut, lpEnvironment, lpCurrentDirectory, pSi, lpProcessInformation);
}

/* Detector B store consult: read the auto-exclude store (written by
   gmproxy.c) to decide whether a base name should be born as the host's
   normal user token instead of SYSTEM. gmproxy records a base name here
   after it refuses/crashes >= GM_AUTOEXCLUDE_THRESHOLD times as SYSTEM;
   gmhook then SKIPS the SYSTEM-token birth for that base so the app is
   not force-elevated (and re-killed) on every child launch from a hooked
   host. No mutex (gmproxy's atomic temp+MoveFileExW rename guarantees a
   consistent read); 2s in-process cache (GetTickCount64) so the
   CreateProcess hot path does at most one tiny file read per 2s per
   process. Fail-open: any read/parse error -> FALSE -> current SYSTEM-
   birth behavior (never blocks elevation). No hardcoded app names --
   the store is populated purely by runtime observation in gmproxy.c. */
#define GMHOOK_AUTOEXCLUDE_CACHE_TTL_MS 2000
#define GMHOOK_AUTOEXCLUDE_MAX_ENTRIES 256
#define GMHOOK_AUTOEXCLUDE_BASE_CAP    64

typedef struct {
    wchar_t base[GMHOOK_AUTOEXCLUDE_BASE_CAP];
    BOOL    excluded;
} GmHookAutoExcludeEntry;

static BOOL GmHookIsAutoExcluded(const wchar_t* baseName) {
    if (!baseName || !baseName[0]) return FALSE;  /* fail-open */
    static GmHookAutoExcludeEntry cache[GMHOOK_AUTOEXCLUDE_MAX_ENTRIES];
    static int cacheCount = -1;  /* -1 = not loaded yet */
    static ULONGLONG cacheLoadTick = 0;
    static FILETIME cacheLoadMtime;   /* store LastWriteTime captured at last load */
    /* host-process-token invalidation: if the host's process token changed
       since the last load (e.g. the monitor elevated this host to SYSTEM
       in-place via ReplaceProcessTokenForPid / NtSetInformationProcess, or a
       token swap mid-session), reload the store so a freshly-excluded app is
       respected immediately under the new token context. Captured at cache-
       load time into cacheLoadTokenSid; on consult the current token SID is
       re-queried and compared (EqualSid). Fail-open: any token query failure
       -> tokenChanged stays FALSE -> the mtime + TTL invalidations still
       govern (the store path is token-independent, so this is a belt-and-
       suspenders "always fresh" guarantee, not a correctness requirement). */
    static BYTE cacheLoadTokenSid[256];  /* SECURITY_MAX_SID_SIZE */
    static BOOL cacheLoadTokenSidValid = FALSE;
    const wchar_t kPath[] = L"C:\\ProgramData\\GodModeAutoExclude\\gmproxy_autoexclude.dat";
    ULONGLONG now = GetTickCount64();
    /* mtime invalidation: a newly-excluded app (just crashed as SYSTEM and
       recorded by gmproxy) is respected on the NEXT CreateProcessW instead of
       waiting up to the TTL. Read the store file's LastWriteTime; if it changed
       since the last load, reload immediately. The TTL stays a secondary
       invalidation so a long-idle host still refreshes. Fail-open: if
       GetFileAttributesExW fails (file missing/ACL-denied), curMtime is zeroed
       and the reload decision falls back to the TTL check (and a missing file
       loads zero entries = no exclusions = normal SYSTEM-birth behavior). */
    WIN32_FILE_ATTRIBUTE_DATA fa;
    BOOL haveMtime = GetFileAttributesExW(kPath, GetFileExInfoStandard, &fa);
    FILETIME curMtime;
    if (haveMtime) curMtime = fa.ftLastWriteTime;
    else { curMtime.dwLowDateTime = 0; curMtime.dwHighDateTime = 0; }
    BOOL mtimeChanged = (cacheCount < 0) ||
        (curMtime.dwLowDateTime  != cacheLoadMtime.dwLowDateTime) ||
        (curMtime.dwHighDateTime != cacheLoadMtime.dwHighDateTime);
    /* Query the current host-process token SID once per consult (mirrors the
       mtime GetFileAttributesExW per-call pattern); if it differs from the SID
       captured at the last load, force a reload. One OpenProcessToken +
       GetTokenInformation + CopySid + EqualSid per call (~microseconds; the
       CreateProcessW it gates is ~1ms). Fail-open: any failure -> haveCurSid
       stays FALSE -> tokenChanged FALSE -> mtime/TTL govern. */
    BYTE curSid[256]; BOOL haveCurSid = FALSE;
    HANDLE hTok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
        BYTE tub[256]; DWORD tlen = 0;
        if (GetTokenInformation(hTok, TokenUser, tub, sizeof(tub), &tlen)) {
            TOKEN_USER* tu = (TOKEN_USER*)tub;
            if (tu && IsValidSid(tu->User.Sid)) {
                DWORD sidLen = GetLengthSid(tu->User.Sid);
                if (sidLen > 0 && sidLen <= sizeof(cacheLoadTokenSid) &&
                    CopySid(sizeof(curSid), curSid, tu->User.Sid)) {
                    haveCurSid = TRUE;
                }
            }
        }
        CloseHandle(hTok);
    }
    BOOL tokenChanged = haveCurSid &&
        (!cacheLoadTokenSidValid || !EqualSid(cacheLoadTokenSid, curSid));
    if (mtimeChanged || tokenChanged || (now - cacheLoadTick) > GMHOOK_AUTOEXCLUDE_CACHE_TTL_MS) {
        cacheCount = 0;
        cacheLoadTick = now;
        cacheLoadMtime = curMtime;
        /* capture the current host-process token SID so the next consult can
           detect a host-token change (the tokenChanged reload trigger above).
           Uses the curSid already queried this consult (no second token query).
           Fail-open: if haveCurSid is FALSE, leave cacheLoadTokenSidValid
           FALSE so the next consult re-attempts (no stale SID captured). */
        if (haveCurSid) {
            if (CopySid(sizeof(cacheLoadTokenSid), cacheLoadTokenSid, curSid)) {
                cacheLoadTokenSidValid = TRUE;
            }
        }
        FILE* f = _wfopen(kPath, L"r");
        if (f) {
            wchar_t line[256];
            while (cacheCount < GMHOOK_AUTOEXCLUDE_MAX_ENTRIES && fgetws(line, 256, f)) {
                /* Parse "base|count|ts|excluded[|reason]" manually (no swscanf).
                   The 5th 'reason' field (C/G/P, added for Export-GodModeLogs
                   debuggability) is IGNORED here -- gmhook only needs base +
                   excluded. The int parser stops at '|' so a 5-field line still
                   yields the correct excluded flag (forward-compatible). */
                const wchar_t* p1 = wcschr(line, L'|'); if (!p1) continue;
                const wchar_t* p2 = wcschr(p1 + 1, L'|'); if (!p2) continue;
                const wchar_t* p3 = wcschr(p2 + 1, L'|'); if (!p3) continue;
                size_t baseLen = (size_t)(p1 - line);
                if (baseLen == 0 || baseLen >= GMHOOK_AUTOEXCLUDE_BASE_CAP) continue;
                wcsncpy(cache[cacheCount].base, line, baseLen);
                cache[cacheCount].base[baseLen] = 0;
                cache[cacheCount].excluded = (_wtoi(p3 + 1) != 0);
                cacheCount++;
            }
            fclose(f);
        }
        /* If the file is absent/corrupt, cacheCount stays 0 (no exclusions)
           for the TTL window -> fail-open -> normal SYSTEM-birth behavior. */
    }
    for (int i = 0; i < cacheCount; i++) {
        if (_wcsicmp(cache[i].base, baseName) == 0) return cache[i].excluded;
    }
    return FALSE;  /* fail-open: not found -> not excluded */
}

/* TRUE if baseName has an App Execution Alias reparse point at
   %LOCALAPPDATA%\Microsoft\WindowsApps\<base> -- i.e. it is a Win11
   Store-redirector stub (notepad, mspaint, calc, photos, ...). Mirrors
   gmproxy.c's GmProxyIsAppExecutionAliasStub: a stub cannot run as SYSTEM
   (AppX package activation needs user identity) AND birthing it as SYSTEM
   here would break its Store redirect, so HookCreateProcessW falls through
   to the real CreateProcessW (native user launch) for a stub. This is the
   belt-and-suspenders for a stub whose auto-exclude store entry was pruned
   by Invoke-GmAutoExcludeReconcile between the 2s cache TTL + mtime
   invalidation (Store app uninstalled then reinstalled), or whose store
   entry was never written (Detector A missed it) -- the install-time
   Detector A drop + the GmHookIsAutoExcluded store consult above are the
   primary gates; this direct reparse-point check is the no-hardcode,
   always-fresh safety net. Fail-open: any error / missing alias file ->
   FALSE (normal SYSTEM-birth behavior). LOCALAPPDATA is the host
   process's; a SYSTEM-elevated host gets systemprofile's LOCALAPPDATA (no
   user aliases) -> FALSE -> normal SYSTEM birth, which is correct (the
   user-session stub case is covered by Detector A + the IFEO layer; a
   SYSTEM host birthing a child uses the token path). */
static BOOL GmHookIsAppExecutionAliasStub(const wchar_t* baseName) {
    if (!baseName || !baseName[0]) return FALSE;
    wchar_t localAppData[MAX_PATH] = {0};
    DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return FALSE;  /* fail-open */
    wchar_t path[MAX_PATH] = {0};
    /* %ls: wide (MinGW %s truncates wchar_t). Build
       %LOCALAPPDATA%\Microsoft\WindowsApps\<base>. */
    int n = swprintf(path, MAX_PATH, L"%ls\\Microsoft\\WindowsApps\\%ls", localAppData, baseName);
    if (n <= 0 || (size_t)n >= MAX_PATH) return FALSE;
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fa)) return FALSE;  /* no alias file -> not a stub */
    return (fa.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ? TRUE : FALSE;
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
    /* Recursion guard: if the hook is called recursively (e.g., pOrigCreateProcessW points back here),
       fall through immediately to avoid stack overflow / crash. */
    static volatile LONG inHook = 0;
    if (InterlockedExchange(&inHook, 1) == 1) {
        /* Already inside the hook — call the real function directly to break recursion. */
        if (!pOrigCreateProcessW) {
            HMODULE hKb = GetModuleHandleW(L"kernelbase.dll");
            if (hKb) pOrigCreateProcessW = (CreateProcessW_t)GetProcAddress(hKb, "CreateProcessW");
            if (!pOrigCreateProcessW) {
                HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
                if (hK32) pOrigCreateProcessW = (CreateProcessW_t)GetProcAddress(hK32, "CreateProcessW");
            }
        }
        if (pOrigCreateProcessW && pOrigCreateProcessW != HookCreateProcessW) {
            /* Reset the recursion guard before returning so a single re-entry
               does not permanently leave inHook==1 (which would silently bypass
               elevation on every subsequent CreateProcessW call). */
            InterlockedExchange(&inHook, 0);
            return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }
        SetLastError(ERROR_PROC_NOT_FOUND);
        InterlockedExchange(&inHook, 0);
        return FALSE;
    }

    BOOL result = FALSE;

    /* Ensure we have the real original function pointer. */
    if (!pOrigCreateProcessW || pOrigCreateProcessW == HookCreateProcessW) {
        HMODULE hKb = GetModuleHandleW(L"kernelbase.dll");
        if (hKb) pOrigCreateProcessW = (CreateProcessW_t)GetProcAddress(hKb, "CreateProcessW");
        if (!pOrigCreateProcessW) {
            HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
            if (hK32) pOrigCreateProcessW = (CreateProcessW_t)GetProcAddress(hK32, "CreateProcessW");
        }
    }

    if (!lpApplicationName && !lpCommandLine) {
        if (pOrigCreateProcessW && pOrigCreateProcessW != HookCreateProcessW) {
            result = pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }
        InterlockedExchange(&inHook, 0);
        return result;
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

    /* Critical OS processes are NEVER touched (passthrough to the real
       CreateProcessW). Shell/launcher HOSTS and interactive shells are split
       below: interactive shells (cmd/powershell/pwsh/ISE) are now BORN AS
       SYSTEM directly in THIS session (see the IsInteractiveShell branch),
       while the remaining launcher hosts (wt/conhost/explorer) still
       passthrough (birthing those as SYSTEM breaks the desktop/taskbar).
       Hooking a shell IN-PROCESS (gmhook injected into pwsh.exe and rerouting
       ITS CreateProcessW) caused the 0xC0000005 inside Kernel32.CreateProcess
       -- but gmhook is never injected into shells (IsShellLauncherProcess is
       excluded from injection), so the host here is always a non-shell
       (explorer / GUI app) and birthing a shell TARGET as SYSTEM from it is
       safe. */
    if (IsCriticalProcess(baseName)) {
        if (pOrigCreateProcessW && pOrigCreateProcessW != HookCreateProcessW) {
            result = pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }
        InterlockedExchange(&inHook, 0);
        return result;
    }

    /* Interactive shells (cmd/powershell/pwsh/ISE) -> BORN AS SYSTEM directly
       in THIS session. The hooked host (explorer / a GUI app) runs in the
       interactive Session 1, so CreateProcessWithTokenW births the shell in
       Session 1 -> VISIBLE + SYSTEM (whoami -> nt authority\system). This
       replaces the monitor's born-as-SYSTEM fallback, which is INVISIBLE on
       Win11 26100 because the monitor runs in Session 0 and
       CreateProcessWithTokenW births in the CALLER's session (proven by the
       VM dump: 5 SYSTEM powershell.exe born Session 0, killed as invisible).
       The host's lpCurrentDirectory flows through so the SYSTEM shell opens in
       the folder the user chose. Env parity: when the host did not pass an
       explicit env block, use the host's env (explorer's env = the USER's env)
       via GetEnvironmentStringsW so the SYSTEM shell inherits %USERPROFILE%/
       %PATH% instead of SYSTEM's System32 profile. Falls back to the real
       CreateProcessW (normal USER shell -- visible, correct cwd) +
       SignalShellBirth if the SYSTEM birth fails (no SYSTEM donor / seclogon
       down / token-path fault) so the shell is at least launched and the
       monitor retries in-place. Never kills the visible user shell. */
    if (IsInteractiveShell(baseName)) {
        CreateProcessWithTokenW_t pCpwt = ResolveCreateProcessWithTokenW();
        if (pCpwt && pOrigCreateProcessW && pOrigCreateProcessW != HookCreateProcessW) {
            if (!gSystemToken) {
                EnablePrivilege(L"SeDebugPrivilege");
                EnablePrivilege(L"SeImpersonatePrivilege");
                PrepareSystemToken();
            }
            if (gSystemToken) {
                /* Env parity: inherit the host's (user's) env when the caller
                   passed none. GetEnvironmentStringsW is unicode -> set
                   CREATE_UNICODE_ENVIRONMENT. Freed after the birth. */
                LPVOID envToPass = lpEnvironment;
                BOOL freeEnv = FALSE;
                DWORD shellFlags = dwCreationFlags;
                if (!envToPass) {
                    envToPass = (LPVOID)GetEnvironmentStringsW();
                    if (envToPass) { freeEnv = TRUE; shellFlags |= 0x00000400u; /* CREATE_UNICODE_ENVIRONMENT */ }
                }
                BOOL tokOk = FALSE;
#ifdef _MSC_VER
                __try {
                    tokOk = TryCreateProcessWithSystemToken(pCpwt, lpApplicationName, lpCommandLine,
                        shellFlags, envToPass, lpCurrentDirectory, lpStartupInfo,
                        lpProcessInformation);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    tokOk = FALSE;
                }
#else
                /* MinGW: no portable __try/__except (see the general-app path
                   below for the rationale). The deterministic STARTUPINFO
                   validation inside TryCreateProcessWithSystemToken is the
                   actual 0xC0000005 fix; the SEH above is defense-in-depth. */
                tokOk = TryCreateProcessWithSystemToken(pCpwt, lpApplicationName, lpCommandLine,
                    shellFlags, envToPass, lpCurrentDirectory, lpStartupInfo,
                    lpProcessInformation);
#endif
                if (freeEnv) FreeEnvironmentStringsW((LPWCH)envToPass);
                if (tokOk) {
                    /* Born as SYSTEM, visible, Session 1, correct cwd. Signal
                       so the monitor sees it is already SYSTEM (it skips the
                       redundant in-place swap via Test-PidIsSystem). */
                    if (lpProcessInformation && lpProcessInformation->dwProcessId != 0) {
                        SignalShellBirth(lpProcessInformation->dwProcessId);
                    }
                    InterlockedExchange(&inHook, 0);
                    return TRUE;
                }
            }
        }
        /* SYSTEM birth failed -> normal USER birth (visible, correct cwd) +
           signal so the monitor retries in-place. The shell is launched
           regardless; never vanishes. */
        if (pOrigCreateProcessW && pOrigCreateProcessW != HookCreateProcessW) {
            result = pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }
        if (result && lpProcessInformation && lpProcessInformation->dwProcessId != 0) {
            SignalShellBirth(lpProcessInformation->dwProcessId);
        }
        InterlockedExchange(&inHook, 0);
        return result;
    }

    /* Other launcher hosts (wt/conhost/OpenConsole/WindowsTerminal/explorer)
       passthrough untouched: birthing these as SYSTEM breaks the desktop /
       taskbar / console association. They are still elevated to SYSTEM by the
       task / service path in God-Mode-Windows.ps1; they are simply not
       IAT-hooked in-process. */
    if (IsShellLauncherProcess(baseName)) {
        if (pOrigCreateProcessW && pOrigCreateProcessW != HookCreateProcessW) {
            result = pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }
        InterlockedExchange(&inHook, 0);
        return result;
    }

    /* Detector B store consult: if this base name was auto-excluded by
       gmproxy (it refused/crashed as SYSTEM >= threshold times), do NOT
       birth it as SYSTEM -- fall through to the real CreateProcessW so the
       child is born as the host's normal user token. This prevents gmhook
       from re-elevating (and re-killing) an app the runtime store already
       learned is SYSTEM-incompatible. The store is the SAME file gmproxy.c
       writes (C:\ProgramData\GodModeAutoExclude\gmproxy_autoexclude.dat);
       gmhook reads it with a 2s in-process cache. Fail-open: a
       missing/corrupt/ACL-denied store -> GmHookIsAutoExcluded returns FALSE
       -> normal SYSTEM-birth behavior (never blocks elevation). */
    if (baseName && GmHookIsAutoExcluded(baseName)) {
        if (pOrigCreateProcessW && pOrigCreateProcessW != HookCreateProcessW) {
            result = pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }
        InterlockedExchange(&inHook, 0);
        return result;
    }

    /* Belt-and-suspenders alias-stub skip (mirrors gmproxy.c's
       GmProxyIsAppExecutionAliasStub): a Win11 App Execution Alias stub
       (notepad/mspaint/calc/...) at %LOCALAPPDATA%\Microsoft\WindowsApps\<base>
       (a reparse point) is a Store-redirector that cannot run as SYSTEM (AppX
       activation needs user identity) AND a stolen-token birth would break
       its Store redirect. The Detector A install-time drop + the
       GmHookIsAutoExcluded store consult above already make gmhook skip
       these, but a stub whose store entry was pruned by
       Invoke-GmAutoExcludeReconcile (Store app uninstalled then reinstalled)
       between the 2s cache TTL + mtime invalidation, or whose store entry
       has not been written yet (Detector A missed it), would otherwise be
       born as SYSTEM here. This direct reparse-point check is the no-hardcode,
       always-fresh safety net. Fail-open: any error / missing alias -> FALSE
       -> normal SYSTEM-birth behavior. */
    if (baseName && GmHookIsAppExecutionAliasStub(baseName)) {
        if (pOrigCreateProcessW && pOrigCreateProcessW != HookCreateProcessW) {
            result = pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }
        InterlockedExchange(&inHook, 0);
        return result;
    }

    /* Ensure token is ready */
    if (!gSystemToken) {
        EnablePrivilege(L"SeDebugPrivilege");
        EnablePrivilege(L"SeImpersonatePrivilege");
        if (!PrepareSystemToken()) {
            if (pOrigCreateProcessW && pOrigCreateProcessW != HookCreateProcessW) {
                result = pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                    lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                    lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
            }
            InterlockedExchange(&inHook, 0);
            return result;
        }
    }

    /* Try to launch the child "born as SYSTEM" via CreateProcessWithTokenW. The
       helper validates the STARTUPINFO shape so we never pass a truncated /
       extended structure that would make CreateProcessWithTokenW read past our
       stack — the exact cause of the 0xC0000005 after "Defender processes
       terminated.". */
    CreateProcessWithTokenW_t pCpwt = ResolveCreateProcessWithTokenW();
    if (pCpwt && pOrigCreateProcessW && pOrigCreateProcessW != HookCreateProcessW) {
        BOOL tokOk = FALSE;
#ifdef _MSC_VER
        __try {
            tokOk = TryCreateProcessWithSystemToken(pCpwt, lpApplicationName, lpCommandLine,
                dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo,
                lpProcessInformation);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            tokOk = FALSE;
        }
#else
        /* MinGW: no portable __try/__except. The MinGW <excpt.h> __try1 macro
           emits invalid .seh_endproc / .text.startup segment directives under
           -O2 on mingw-w64 16.x (verified by compile test: 'Assembler Error:
           .seh_endproc used in segment .text instead of expected .text.startup'),
           so an SEH guard here would break the build. The deterministic input
           validation inside TryCreateProcessWithSystemToken
           (EXTENDED_STARTUPINFO_PRESENT bypass, cb clamp to sizeof(STARTUPINFOW),
           NULL PROCESS_INFORMATION / token guards) is the actual fix for the
           0xC0000005 and works on every toolchain; the MSVC __try/__except
           above is defense-in-depth only. */
        tokOk = TryCreateProcessWithSystemToken(pCpwt, lpApplicationName, lpCommandLine,
            dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo,
            lpProcessInformation);
#endif
        if (tokOk) {
            InterlockedExchange(&inHook, 0);
            return TRUE;
        }
        /* On failure (or a guarded fault) fall through to the real CreateProcessW
           so the app still launches unelevated instead of vanishing — no flashing,
           no silent close, and never a host crash. */
    }

    if (pOrigCreateProcessW && pOrigCreateProcessW != HookCreateProcessW) {
        result = pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    InterlockedExchange(&inHook, 0);
    return result;
}

/* IAT hook helper: patch a single module's IAT for CreateProcessW. */
static BOOL HookModuleIAT(HMODULE hMod) {
    if (!hMod) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    /* Sanity-check e_lfanew so a stale / partially-unloaded module does not make
       us dereference a bogus NT header (which would fault the install thread). */
    if (dos->e_lfanew <= 0 || (DWORD)dos->e_lfanew < (DWORD)sizeof(IMAGE_DOS_HEADER)) return FALSE;
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
            if (!IsCriticalProcess(baseName) && !IsShellLauncherProcess(baseName)) {
                EnablePrivilege(L"SeDebugPrivilege");
                EnablePrivilege(L"SeImpersonatePrivilege");
                if (!gSystemToken) PrepareSystemToken();
                hookInstalled = InstallIATHook();
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

/* Read-only diagnostic export: returns TRUE if the CreateProcessW IAT hook has
   been installed in this host process, FALSE otherwise. Used by the wine smoke
   test (tests/test-shell-host-exclusion.sh -> Test-ShellHostExclusion.c) to
   verify that shell/launcher hosts (pwsh/powershell/cmd/terminals) are NOT
   IAT-hooked in-process -- the 0xC0000005 fix -- BEFORE deploying to the
   Windows VM. Safe to call from any thread: it only reads the hookInstalled
   flag set by DllMain / GetMsgProc. */
__declspec(dllexport) BOOL IsHookInstalled(void) {
    return hookInstalled;
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
        /* Build-version stamp to %TEMP%\gmhook.log + OutputDebugStringW (see
           GmHookWriteBuildStamp). Best-effort, never affects the hook. */
        GmHookWriteBuildStamp();
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
        if (!IsCriticalProcess(baseName) && !IsShellLauncherProcess(baseName)) {
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
