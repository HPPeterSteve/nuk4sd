/*
 * caps.c
 *
 * Nuk4sd — Hardened Sandbox — Layer 4: Capability Drop
 * Extraído de vault_sandbox.c (split modular, estilo Firejail).
 */

#include "sandbox.h"

#ifdef __linux__

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_drop_caps(): Remove all Linux Capabilities
 *  Logs: estado antes/depois, cada prctl enviado ao kernel e o resultado,
 *        implicações de segurança de cada passo.
 * ───────────── */
static int sandbox_drop_caps(void)
{
    /* ── Passo 1: cap_set_proc(empty) — zera as 3 listas de capabilities ─ */
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

    if (prctl(PR_SET_KEEPCAPS, 0) != 0) {
        int e = errno;
        vault_log(LOG_ALERT, "[CAP] prctl(PR_SET_KEEPCAPS, 0) failed: %s (errno=%d)", strerror(e), e);
        return -1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        int e = errno;
        vault_log(LOG_ALERT, "[CAP] prctl(PR_SET_NO_NEW_PRIVS, 1) failed: %s (errno=%d)", strerror(e), e);
        return -1;
    }


    /* ── Verificação: confirma que caps estão realmente vazios ───────────  */

    cap_t check = cap_get_proc();
    if (check != NULL) {
        char *text = cap_to_text(check, NULL);
        if (text && strcmp(text, "=") != 0) {
            cap_free(text);
            cap_free(check);
            return -1;
        }
        cap_free(text);
        cap_free(check);
    }

    return 0;
}

int vsb_drop_caps(void) { return sandbox_drop_caps(); }

#endif /* __linux__ */
