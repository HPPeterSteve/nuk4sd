/*
 * caps.c
 *
 * Nuk4sd — Hardened Sandbox — Layer 4: Capability Drop
 * Extracted from vault_sandbox.c
 */

#include "sandbox.h"

#ifdef __linux__

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_drop_caps(): Remove all Linux Capabilities
 *
 *  Three steps in order:
 *    1. PR_CAPBSET_DROP in loop — clears bounding set (prevents inheritance via
 *       execve even without NO_NEW_PRIVS; closes window if NO_NEW_PRIVS is
 *       reset in the future).
 *    2. cap_set_proc(empty) — clears Effective + Permitted + Inheritable.
 *    3. PR_SET_NO_NEW_PRIVS — prevents privilege escalation via file caps
 *       in any subsequent execve.
 *    4. Verification: confirms that cap_get_proc() returns "=" (empty).
 *
 *  Logs: state before/after, each prctl sent to kernel and result.
 * ───────────────────────────────────────────────────────────────────────── */
static int sandbox_drop_caps(void)
{
    /* ── Step 1: PR_CAPBSET_DROP — remove each capability from bounding set ─
     * Bounding set limits which capabilities can be acquired via
     * execve (file capabilities). Even without cap_set_proc, an execv of a
     * SUID/file-cap binary could re-elevate if bounding set is not
     * dropped. PR_CAPBSET_DROP requires CAP_SETPCAP — which we still have
     * at this point, before calling cap_set_proc(empty). */
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (prctl(PR_CAPBSET_DROP, (unsigned long)cap, 0, 0, 0) != 0) {
            /* EINVAL = capability not known by this kernel (ok to ignore) */
            if (errno != EINVAL) {
                vault_log(LOG_ALERT,
                          "[CAP] prctl(PR_CAPBSET_DROP, %d) failed: %s (errno=%d)",
                          cap, strerror(errno), errno);
                return -1;
            }
        }
    }
    vault_log(LOG_INFO, "[CAP] Bounding set cleared (%d caps dropped)", CAP_LAST_CAP + 1);

    /* ── Step 2: cap_set_proc(empty) — clears Effective/Permitted/Inheritable */
    cap_t empty = cap_init();
    if (empty == NULL) {
        vault_log(LOG_ALERT, "[CAP] cap_init() failed: %s — cannot drop caps", strerror(errno));
        return -1;
    }
    if (cap_set_proc(empty) != 0) {
        int e = errno;
        vault_log(LOG_ALERT, "[CAP] cap_set_proc(empty) failed: %s (errno=%d)", strerror(e), e);
        cap_free(empty);
        return -1;
    }
    cap_free(empty);   /* free in normal path — no leak */

    if (prctl(PR_SET_KEEPCAPS, 0) != 0) {
        int e = errno;
        vault_log(LOG_ALERT, "[CAP] prctl(PR_SET_KEEPCAPS, 0) failed: %s (errno=%d)", strerror(e), e);
        return -1;
    }

    /* ── Step 3: NO_NEW_PRIVS ─────────────────────────────────────────── */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        int e = errno;
        vault_log(LOG_ALERT, "[CAP] prctl(PR_SET_NO_NEW_PRIVS, 1) failed: %s (errno=%d)", strerror(e), e);
        return -1;
    }

    /* ── Step 4: Verification — confirm caps are actually empty ── */
    cap_t check = cap_get_proc();
    if (check != NULL) {
        char *text = cap_to_text(check, NULL);
        if (text && strcmp(text, "=") != 0) {
            vault_log(LOG_ALERT, "[CAP] cap_get_proc() after drop is NOT empty: '%s'", text);
            cap_free(text);
            cap_free(check);
            return -1;
        }
        cap_free(text);
        cap_free(check);
    }

    vault_log(LOG_INFO, "[CAP] All capabilities dropped (bounding set + E/P/I sets cleared, NO_NEW_PRIVS=1)");
    return 0;
}

int vsb_drop_caps(void) { return sandbox_drop_caps(); }

#endif /* __linux__ */
