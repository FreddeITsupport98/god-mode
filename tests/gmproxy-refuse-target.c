/*
 * gmproxy-refuse-target.c -- minimal quickly-exiting target for the gmproxy
 * ownerless-birth REFUSE wine smoke test (tests/test-gmproxy-refuse.sh).
 *
 * gmproxy.exe takes argv[1] = target exe, creates an IFEO-bypass hardlink to
 * it, then either launches it (graceful current-user fallback, when gmproxy is
 * NOT in Session 0) or REFUSES and returns 1 (when gmproxy IS in Session 0 with
 * no session-correct SYSTEM token). This dummy prints a unique marker and exits
 * 0 immediately so it NEVER hangs a test run, and so the test can prove the
 * child actually launched when gmproxy takes the graceful fallback path.
 *
 * Plain main() (no -municode needed) -- gmproxy launches it via
 * CreateProcessW which calls the normal entry point.
 */
#include <stdio.h>

int main(void) {
    /* Unique marker so the test can prove the child actually launched when
       gmproxy takes the graceful current-user fallback (non-Session-0 path).
       Absent when gmproxy REFUSES (Session-0 path) -- the test asserts on
       gmproxy's own [GM-PROXY] REFUSE log line + exit 1 in that case. */
    fputs("GMREFUSE_TARGET_RAN\n", stdout);
    fflush(stdout);
    return 0;
}
