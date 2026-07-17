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
#include <userenv.h>  /* CreateEnvironmentBlock/DestroyEnvironmentBlock (Layer 1 env fix) */
#include <sddl.h>    /* ConvertSidToStringSidW (elevation-context token SID logging) */

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")
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

/* Resolve the full image path of a PID into buf (wide), then truncate to the
   base name. Used by the elevation-context log (which SYSTEM process donated
   the token) and the grandchild-delegation log (what a launcher stub spawned).
   QueryFullProcessImageNameW is loaded dynamically (kernel32, already linked)
   so the build stays identical across MSVC/MinGW header versions. Best-effort:
   returns FALSE + buf="" on any failure (never affects the launch). */
static BOOL GmProxyImageNameForPid(DWORD pid, wchar_t* buf, size_t cap) {
    if (!buf || cap == 0) return FALSE;
    buf[0] = 0;
    typedef BOOL (WINAPI *QueryFullProcessImageNameW_t)(HANDLE, DWORD, LPWSTR, PDWORD);
    static QueryFullProcessImageNameW_t pfn = NULL;
    if (!pfn) {
        HMODULE hk = GetModuleHandleW(L"kernel32.dll");
        if (hk) pfn = (QueryFullProcessImageNameW_t)GetProcAddress(hk, "QueryFullProcessImageNameW");
    }
    if (!pfn) return FALSE;
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return FALSE;
    DWORD len = (DWORD)cap;
    BOOL ok = pfn(hp, 0, buf, &len);
    CloseHandle(hp);
    if (ok) {
        const wchar_t* b = wcsrchr(buf, L'\\');
        if (b && b != buf) {
            memmove(buf, b + 1, (wcslen(b + 1) + 1) * sizeof(wchar_t));  /* base name only */
        }
    } else {
        buf[0] = 0;
    }
    return ok;
}

/* Enumerate the processes currently in a Job Object (the child + any descendants
   it spawned). Used after the child-survival wait to distinguish a launcher/stub
   that DELEGATED to a surviving grandchild (the real app -- NOT a failure) from a
   genuine EXIT with no descendant (graceful refusal as SYSTEM, or a crash if the
   exit code is non-zero). Returns the total process count in the job; *outSurvivors
   excludes childPid (so after the child exits, *outSurvivors = living grandchildren).
   *outFirstPid / firstImg capture the first surviving descendant's PID + base name.
   Best-effort: returns 0 on any failure (caller falls back to exit-code-only class). */
static DWORD GmProxyEnumerateJobTree(HANDLE hJob, DWORD childPid,
                                     DWORD* outSurvivors, DWORD* outFirstPid,
                                     wchar_t* firstImg, size_t imgCap) {
    if (outSurvivors) *outSurvivors = 0;
    if (outFirstPid) *outFirstPid = 0;
    if (firstImg && imgCap) firstImg[0] = 0;
    if (!hJob) return 0;
    enum { GM_JOB_MAX_PIDS = 512 };
    BYTE buf[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + GM_JOB_MAX_PIDS * sizeof(ULONG_PTR)];
    ZeroMemory(&buf, sizeof(buf));
    JOBOBJECT_BASIC_PROCESS_ID_LIST* plist = (JOBOBJECT_BASIC_PROCESS_ID_LIST*)buf;
    DWORD retLen = 0;
    BOOL ok = QueryInformationJobObject(hJob, JobObjectBasicProcessIdList, plist, (DWORD)sizeof(buf), &retLen);
    if (!ok && plist->NumberOfAssignedProcesses == 0) return 0;  /* query failed, no info */
    DWORD total = plist->NumberOfProcessIdsInList;
    DWORD survivors = 0;
    DWORD firstPid = 0;
    for (DWORD i = 0; i < total; i++) {
        DWORD pid = (DWORD)plist->ProcessIdList[i];
        if (pid == 0 || pid == childPid) continue;
        survivors++;
        if (firstPid == 0) firstPid = pid;
    }
    if (outSurvivors) *outSurvivors = survivors;
    if (outFirstPid) *outFirstPid = firstPid;
    if (firstPid && firstImg && imgCap) GmProxyImageNameForPid(firstPid, firstImg, imgCap);
    return total;
}

/* Elevation-context logging ("big debug" for the elevator): emit the token
   source identity (which SYSTEM process donated the token + its session), the
   token's user SID (confirm S-1-5-18 Local System), token type (primary vs
   impersonation), elevation, and session, plus the rebuilt command line, the
   env-block state + byte size, and the IFEO-bypass hardlink target. This catches
   the ELEVATION-side root cause (wrong token source, non-SYSTEM SID, missing env,
   bad cmdline) that the child-survival observation alone cannot. Best-effort:
   every sub-query is guarded so a missing API/permission never affects the
   launch. Called once after the env block is built, before the CreateProcess
   attempts. */
static void GmProxyLogElevationContext(HANDLE hPrimary, DWORD srcPid, DWORD activeSession,
                                       const wchar_t* cmdLine, const wchar_t* hardlinkPath,
                                       LPVOID envBlock) {
    wchar_t srcImg[MAX_PATH] = {0};
    DWORD srcSess = 0;
    const wchar_t* srckind = L"none";
    if (srcPid != 0) {
        srckind = L"system";
        GmProxyImageNameForPid(srcPid, srcImg, MAX_PATH);
        if (!ProcessIdToSessionId(srcPid, &srcSess)) srcSess = 0xFFFFFFFF;
    }
    DiagLog(L"[GM-PROXY] ELEVATE: srckind=%ls srcpid=%lu srcsess=%lu srcimg=%ls tgtsess=%lu\n",
            srckind, (unsigned long)srcPid, (unsigned long)srcSess,
            srcImg[0] ? srcImg : L"(unknown)", (unsigned long)activeSession);
    if (hPrimary) {
        wchar_t sidStr[128] = {0};
        BYTE tub[256]; DWORD tlen = 0;
        if (GetTokenInformation(hPrimary, TokenUser, tub, sizeof(tub), &tlen)) {
            TOKEN_USER* tu = (TOKEN_USER*)tub;
            LPWSTR sidAlloc = NULL;
            if (ConvertSidToStringSidW(tu->User.Sid, &sidAlloc) && sidAlloc) {
                wcsncpy(sidStr, sidAlloc, 127); sidStr[127] = 0;
                LocalFree(sidAlloc);
            }
        }
        DWORD ttype = 0; DWORD tlen2 = sizeof(ttype);
        BOOL isPrimary = GetTokenInformation(hPrimary, TokenType, &ttype, sizeof(ttype), &tlen2) && ttype == TokenPrimary;
        TOKEN_ELEVATION elev = {0}; DWORD elen = sizeof(elev);
        BOOL isElevated = GetTokenInformation(hPrimary, TokenElevation, &elev, sizeof(elev), &elen) && elev.TokenIsElevated;
        DWORD tksess = 0; DWORD slen = sizeof(tksess);
        BOOL tokSessOk = GetTokenInformation(hPrimary, TokenSessionId, &tksess, sizeof(tksess), &slen);
        DiagLog(L"[GM-PROXY] TOKEN: sid=%ls type=%ls elevated=%lu tksess=%lu\n",
                sidStr[0] ? sidStr : L"(?)", isPrimary ? L"primary" : L"impersonation",
                (unsigned long)(isElevated ? 1 : 0), (unsigned long)(tokSessOk ? tksess : 0xFFFFFFFF));
    } else {
        DiagLog(L"[GM-PROXY] TOKEN: sid=(none) no SYSTEM token acquired (will degrade to current-user launch)\n");
    }
    DiagLog(L"[GM-PROXY] CMDLINE: %ls\n", cmdLine ? cmdLine : L"(null)");
    DWORD envBytes = 0;
    if (envBlock) {
        const wchar_t* p = (const wchar_t*)envBlock;
        while (*p) { p += wcslen(p) + 1; }
        envBytes = (DWORD)((p - (const wchar_t*)envBlock + 1) * sizeof(wchar_t));
    }
    DiagLog(L"[GM-PROXY] ENV: block=%ls bytes=%lu\n", envBlock ? L"built" : L"null", (unsigned long)envBytes);
    DiagLog(L"[GM-PROXY] TARGET: hardlink=%ls\n", hardlinkPath ? hardlinkPath : L"(null)");
}

#define GM_CHILD_OBSERVE_MS 1500  /* child-survival grace window for the per-app launch report */

/* ------------------------------------------------------------------ */
/* Per-app launch telemetry ("big debug"): emit a structured LAUNCH    */
/* line for every gmproxy invocation (app, pid, mode, session, token-  */
/* source pid, injected launch flag, env-block state) so Export-       */
/* GodModeLogs (menu option [11]) can aggregate a PER-APP LAUNCH       */
/* REPORT. When a child was actually born (childOk), also observe      */
/* whether it survived a short grace window via WaitForSingleObject +  */
/* a Job-Object tree walk: a child that exits within the window is     */
/* classified as DELEGATED (it spawned a surviving grandchild -- a     */
/* launcher/stub like a Desktop Firefox copy or the Win11 notepad      */
/* stub; the real app opened, NOT a failure) vs EXITED (no surviving   */
/* descendant -- genuine early exit: exitcode 0 = graceful refusal as  */
/* SYSTEM, non-zero = class CRASH). ALIVE = the child itself is still  */
/* running after the window (healthy; tree= counts its descendants).   */
/* The wait returns immediately when the child exits, so a fast-dying  */
/* app adds ~0 latency; a healthy app keeps gmproxy alive for the      */
/* window (acceptable for a diagnostic phase). Never blocks the child  */
/* (the child runs independently; we only hold its handle + job).      */
/* Best-effort: logging/observation never affects the launch outcome.  */
/* hJob is NULL on the REFUSE/FAILED paths (no child) and when the job */
/* could not be created/assigned (e.g. wine stubs jobs) -- in that     */
/* case classification falls back to exit-code-only (job=disabled).    */
/* The caller transfers hJob ownership to this helper on the success   */
/* path; it is closed exactly once here.                               */
/* ------------------------------------------------------------------ */
static void GmProxyLogLaunchReport(const wchar_t* targetPath, const wchar_t* mode,
                                   const wchar_t* injectFlag, BOOL childOk,
                                   LPPROCESS_INFORMATION ppi, LPVOID envBlock,
                                   DWORD srcPid, DWORD activeSession, HANDLE hJob) {
    if (!targetPath) { if (hJob) CloseHandle(hJob); return; }
    const wchar_t* base = wcsrchr(targetPath, L'\\');
    if (base) base++; else base = targetPath;
    const wchar_t* flag = injectFlag ? injectFlag : L"none";
    const wchar_t* env  = envBlock ? L"built" : L"null";
    DWORD pid = (childOk && ppi) ? ppi->dwProcessId : 0;
    DiagLog(L"[GM-PROXY] LAUNCH: app=%ls pid=%lu mode=%ls session=%lu srcpid=%lu flag=%ls env=%ls\n",
            base, (unsigned long)pid, mode, (unsigned long)activeSession,
            (unsigned long)srcPid, flag, env);
    if (!childOk || !ppi || !ppi->hProcess) {  /* no child to observe (REFUSE / FAILED) */
        if (hJob) CloseHandle(hJob);
        return;
    }
    DWORD w = WaitForSingleObject(ppi->hProcess, GM_CHILD_OBSERVE_MS);
    if (w == WAIT_TIMEOUT) {
        DWORD total = 0, survivors = 0, firstPid = 0;
        wchar_t firstImg[MAX_PATH] = {0};
        if (hJob) total = GmProxyEnumerateJobTree(hJob, ppi->dwProcessId, &survivors, &firstPid, firstImg, MAX_PATH);
        DiagLog(L"[GM-PROXY] CHILD-STATUS: app=%ls pid=%lu result=ALIVE waited_ms=%lu tree=%lu (mode=%ls)\n",
                base, (unsigned long)ppi->dwProcessId, (unsigned long)GM_CHILD_OBSERVE_MS,
                (unsigned long)total, mode);
    } else if (w == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeProcess(ppi->hProcess, &code);
        const wchar_t* cls = (code == 0) ? L"CLEAN" : L"CRASH";  /* exitcode 0 = graceful; non-zero = crash */
        DWORD survivors = 0, firstPid = 0;
        wchar_t firstImg[MAX_PATH] = {0};
        if (hJob) (void)GmProxyEnumerateJobTree(hJob, ppi->dwProcessId, &survivors, &firstPid, firstImg, MAX_PATH);
        if (survivors > 0) {
            /* The child exited cleanly but left a LIVING descendant: it was a
               launcher/stub that DELEGATED. recur=yes means the survivor is
               gmproxy.exe itself -- the stub spawned an IFEO-hooked image (e.g.
               a Desktop Firefox copy spawning the real firefox.exe) and Windows
               birthed a NESTED gmproxy as the grandchild (IFEO re-entry); the
               real app's fate is logged by that nested gmproxy (running as SYSTEM
               -> a different %TEMP%, which Export-GodModeLogs now also collects).
               recur=no means the survivor IS the real app (genuine delegation --
               NOT a failure). The exact base-name match avoids a false positive on
               a gmproxy_<pid>_<app>.exe hardlink (which is the real app under a
               bypass name, not the debugger). */
            BOOL recur = (_wcsicmp(firstImg, L"gmproxy.exe") == 0);
            DiagLog(L"[GM-PROXY] CHILD-STATUS: app=%ls pid=%lu result=DELEGATED exitcode=%lu treepids=%lu firstgchild=%ls gchildpid=%lu recur=%ls (mode=%ls)\n",
                    base, (unsigned long)ppi->dwProcessId, (unsigned long)code,
                    (unsigned long)survivors, firstImg[0] ? firstImg : L"(unknown)",
                    (unsigned long)firstPid, recur ? L"yes" : L"no", mode);
        } else if (hJob) {
            DiagLog(L"[GM-PROXY] CHILD-STATUS: app=%ls pid=%lu result=EXITED exitcode=%lu class=%ls tree=0 (mode=%ls)\n",
                    base, (unsigned long)ppi->dwProcessId, (unsigned long)code, cls, mode);
        } else {
            DiagLog(L"[GM-PROXY] CHILD-STATUS: app=%ls pid=%lu result=EXITED exitcode=%lu class=%ls job=disabled (mode=%ls)\n",
                    base, (unsigned long)ppi->dwProcessId, (unsigned long)code, cls, mode);
        }
    } else {
        DiagLog(L"[GM-PROXY] CHILD-STATUS: app=%ls pid=%lu result=UNKNOWN waiterr=%lu (mode=%ls)\n",
                base, (unsigned long)ppi->dwProcessId, (unsigned long)GetLastError(), mode);
    }
    if (hJob) CloseHandle(hJob);
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

/* Layer 2: return a launch flag to inject for sandboxed/single-instance apps
   so they render and don't IPC-exit when born as SYSTEM. Returns NULL (no
   injection) for apps that Layer 1's env block alone fixes. The flag is
   inserted immediately AFTER argv[1] in the rebuilt command line, preserving
   any existing caller arguments. Scoped by exact base-name match (case-
   insensitive) so non-matching apps are unaffected. iexplore.exe is NOT
   Chromium and is deliberately excluded from the --no-sandbox set. */
static const wchar_t* GmProxyLaunchFlagForTarget(const wchar_t* targetPath) {
    if (!targetPath) return NULL;
    const wchar_t* base = wcsrchr(targetPath, L'\\');
    if (base) base++; else base = targetPath;
    /* Chromium family + Electron (all share the Chromium sandbox + single-
       instance lock). --no-sandbox is the standard, reliable way to make
       Chromium render under SYSTEM; in a red-team tool whose purpose is "run
       as SYSTEM" the sandbox threat model is already moot (process IS SYSTEM). */
    if (_wcsicmp(base, L"chrome.exe") == 0 ||
        _wcsicmp(base, L"msedge.exe") == 0 ||
        _wcsicmp(base, L"brave.exe") == 0 ||
        _wcsicmp(base, L"opera.exe") == 0 ||
        _wcsicmp(base, L"vivaldi.exe") == 0 ||
        _wcsicmp(base, L"discord.exe") == 0 ||
        _wcsicmp(base, L"slack.exe") == 0 ||
        _wcsicmp(base, L"teams.exe") == 0 ||
        _wcsicmp(base, L"code.exe") == 0 ||
        _wcsicmp(base, L"zoom.exe") == 0 ||
        _wcsicmp(base, L"telegram.exe") == 0 ||
        _wcsicmp(base, L"spotify.exe") == 0) {
        return L"--no-sandbox";
    }
    /* Firefox: -no-remote so the SYSTEM Firefox doesn't IPC to an existing
       user Firefox and exit (belt-and-suspenders on Layer 1's separate
       systemprofile). */
    if (_wcsicmp(base, L"firefox.exe") == 0) {
        return L"-no-remote";
    }
    return NULL;
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
#ifdef GMPROXY_TEST_FORCE_SESSION0
    /* Test-only COMPILE-TIME seam (see tests/test-gmproxy-refuse.sh): wine does
       NOT model Windows Session 0 isolation -- ProcessIdToSessionId returns the
       interactive session (1) there, so the ownerless-birth REFUSE branch below
       is never exercised at runtime under wine. Defining
       GMPROXY_TEST_FORCE_SESSION0 at compile time forces mySession=0 /
       mySessionIsZero=TRUE so the REFUSE path is deterministically exercised by
       the wine smoke test. The PRODUCTION build (driver/build.ps1) does NOT
       define this macro, so this block is compiled out and the shipped
       gmproxy.exe is byte-for-byte unaffected -- this is a compile-time test
       double, NOT a runtime env-var hook (no behavior change unless the macro
       is defined at build time). */
    mySession = 0;
    mySessionIsZero = TRUE;
#endif

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

    // Layer 2: detect sandboxed/single-instance apps and inject a launch flag
    // (Chromium/Electron --no-sandbox, Firefox -no-remote) immediately after
    // argv[1] so the SYSTEM child renders and doesn't IPC-exit. NULL = no
    // injection (Layer 1's env block alone fixes that app).
    const wchar_t* injectFlag = GmProxyLaunchFlagForTarget(argv[1]);

    // Build command line from argv
    size_t cmdLen = 0;
    for (int i = 1; i < argc; i++) {
        cmdLen += wcslen(argv[i]) + 3; // quotes + space
    }
    if (injectFlag) {
        cmdLen += wcslen(injectFlag) + 3; // injected flag + space
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
        // Inject the launch flag right after argv[1] (before argv[2..]).
        // The flag has no spaces (--no-sandbox / -no-remote) so no quoting.
        if (i == 1 && injectFlag) {
            wcscat(cmdLine, L" ");
            wcscat(cmdLine, injectFlag);
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

    // Layer 1: build a token-consistent environment block from the stolen
    // SYSTEM token so the SYSTEM child gets systemprofile\AppData (its own
    // profile dir) instead of inheriting the invoking user's APPDATA via
    // gmproxy's env. Without this, single-instance + profile-lock apps
    // (Chrome, Firefox, Electron) either IPC-exit to the user's running
    // instance or fail to init the content sandbox -> unusable as SYSTEM.
    // bInheritExistingEnvironment=TRUE inherits the current process's system
    // vars (PATH, SystemRoot, ...) and replaces the user-specific vars
    // (USERPROFILE, APPDATA, LOCALAPPDATA) with the SYSTEM token's values.
    // Three-tier: if CreateEnvironmentBlock fails, fall back to NULL (the
    // previous behavior) so this never regresses the launch.
    LPVOID envBlock = NULL;
    if (haveToken) {
        if (!CreateEnvironmentBlock(&envBlock, hPrimary, TRUE)) {
            envBlock = NULL;
            DiagLog(L"[GM-PROXY] WARN: CreateEnvironmentBlock failed (GLE=%lu); inheriting gmproxy env.\n", GetLastError());
        }
    }

    /* Elevation-context logging (big debug for the elevator): token source
       identity, token SID/type/elevation/session, rebuilt command line, env
       block state+size, and the IFEO-bypass hardlink target. Catches the
       ELEVATION-side root cause the child-survival observation cannot. */
    GmProxyLogElevationContext(hPrimary, srcPid, activeSession, cmdLine, hardlinkPath, envBlock);

    BOOL ok = FALSE;
#ifdef _MSC_VER
    __try {
#endif
        if (haveToken && cpwt) {
            ok = cpwt(hPrimary, LOGON_WITH_PROFILE, hardlinkPath, cmdLine, CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, envBlock, NULL, &si, &pi);
            if (ok) DiagLog(L"[GM-PROXY] CREATEPROC: method=cpwt result=OK pid=%lu\n", (unsigned long)pi.dwProcessId);
            else { DWORD e = GetLastError(); DiagLog(L"[GM-PROXY] CREATEPROC: method=cpwt result=FAIL gle=%lu\n", (unsigned long)e); }
        }
        /* Fallback with the same (session-correct) SYSTEM token. */
        if (!ok && haveToken) {
            ok = CreateProcessAsUserW(hPrimary, hardlinkPath, cmdLine, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, envBlock, NULL, &si, &pi);
            if (ok) DiagLog(L"[GM-PROXY] CREATEPROC: method=asuser result=OK pid=%lu\n", (unsigned long)pi.dwProcessId);
            else { DWORD e = GetLastError(); DiagLog(L"[GM-PROXY] CREATEPROC: method=asuser result=FAIL gle=%lu\n", (unsigned long)e); }
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
            GmProxyLogLaunchReport(argv[1], L"REFUSE", injectFlag, FALSE, NULL, envBlock, srcPid, activeSession, NULL);
            DeleteFileW(hardlinkPath);
            HeapFree(GetProcessHeap(), 0, cmdLine);
            if (envBlock) DestroyEnvironmentBlock(envBlock);
            if (hPrimary) CloseHandle(hPrimary);
            return 1;
        }
        ok = CreateProcessW(hardlinkPath, cmdLine, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, NULL, NULL, &si, &pi);
        if (ok) {
            DiagLog(L"[GM-PROXY] CREATEPROC: method=currentuser result=OK pid=%lu\n", (unsigned long)pi.dwProcessId);
            DiagLog(L"[GM-PROXY] Launched %ls as current user (graceful fallback, PID=%lu, session=%lu).\n", argv[1], pi.dwProcessId, activeSession);   /* %ls: wide argv[1] */
            /* Hand the PID to the God Mode monitor so it can elevate this process
               IN PLACE (token replacement) instead of the 15s periodic scan
               kill+relaunching it (which would spawn a duplicate). Best-effort:
               if no monitor is listening, the periodic scan remains a fallback. */
            SignalGmProxyFeedback(pi.dwProcessId);
            DiagLog(L"[GM-PROXY] Handed PID %lu to monitor via GodMode-GmProxyFeedback for in-place elevation.\n", pi.dwProcessId);
        } else {
            DWORD e = GetLastError();
            DiagLog(L"[GM-PROXY] CREATEPROC: method=currentuser result=FAIL gle=%lu\n", (unsigned long)e);
        }
    }

    // Best-effort cleanup of the hardlink/copy (may fail if process is still starting)
    DeleteFileW(hardlinkPath);

    if (!ok) {
        DiagLog(L"[GM-PROXY] ERROR: launch failed (token path + current-user fallback). GLE=%lu\n", GetLastError());
        GmProxyLogLaunchReport(argv[1], L"FAILED", injectFlag, FALSE, NULL, envBlock, srcPid, activeSession, NULL);
        HeapFree(GetProcessHeap(), 0, cmdLine);
        if (envBlock) DestroyEnvironmentBlock(envBlock);
        if (hPrimary) CloseHandle(hPrimary);
        return 1;
    }

    if (haveToken) {
        DiagLog(L"[GM-PROXY] SUCCESS: Launched %ls as SYSTEM (PID=%lu, session=%lu).\n", argv[1], pi.dwProcessId, activeSession);   /* %ls: wide argv[1] */
    }

    /* Root-cause observation: capture the child's whole process tree in a Job
       Object so that when a launcher/stub child (a Desktop Firefox copy, the
       Win11 notepad stub) exits cleanly (exitcode 0) the launch report can tell
       whether it DELEGATED to a surviving grandchild (the real app -- NOT a
       failure) vs genuinely EXITED with no descendant (graceful refusal as
       SYSTEM, or a crash if exitcode != 0). CREATE_SUSPENDED (set on every
       CreateProcess above) lets us assign the child to the job BEFORE it runs so
       no grandchild escapes the tree. JOB_OBJECT_LIMIT_BREAKAWAY_OK keeps the job
       from breaking a child that spawns with CREATE_BREAKAWAY_FROM_JOB. No
       KILL_ON_JOB_CLOSE: we NEVER want to kill the user's real app when gmproxy
       exits -- the job is purely observational. If job creation/assignment fails
       (e.g. wine stubs jobs, or gmproxy is already in a non-breakaway job),
       hJob is set NULL and classification falls back to exit-code-only. The job
       handle is transferred to GmProxyLogLaunchReport (closed exactly once
       there). The child was CREATE_SUSPENDED, so resume its main thread now. */
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (hJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli = {0};
        eli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &eli, sizeof(eli));  /* best-effort */
        if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
            DiagLog(L"[GM-PROXY] INFO: AssignProcessToJobObject failed (GLE=%lu); grandchild tree observation disabled (exit-code-only classification).\n", (unsigned long)GetLastError());
            CloseHandle(hJob);
            hJob = NULL;
        }
    } else {
        DiagLog(L"[GM-PROXY] INFO: CreateJobObjectW failed (GLE=%lu); grandchild tree observation disabled.\n", (unsigned long)GetLastError());
    }
    ResumeThread(pi.hThread);  /* child was CREATE_SUSPENDED so the job captured it before it ran */

    /* Per-app launch telemetry + child-survival observation (big debug for the
       Export-GodModeLogs option [11] PER-APP LAUNCH REPORT). Must run BEFORE
       CloseHandle(pi.hProcess) -- the observation WaitForSingleObject's the
       child handle. The wait returns immediately when the child exits (crash),
       so a fast-dying app adds ~0 latency; a healthy app keeps gmproxy alive
       for the grace window (acceptable for a diagnostic phase). */
    GmProxyLogLaunchReport(argv[1], haveToken ? L"SYSTEM" : L"FALLBACK", injectFlag, TRUE, &pi, envBlock, srcPid, activeSession, hJob);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    HeapFree(GetProcessHeap(), 0, cmdLine);
    if (envBlock) DestroyEnvironmentBlock(envBlock);
    if (hPrimary) CloseHandle(hPrimary);
    return 0;
}
