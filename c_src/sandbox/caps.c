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
    const char *L = "CAP";

    /* ── Passo 1: cap_set_proc(empty) — zera as 3 listas de capabilities ─ */
    cap_t empty = cap_init();
    if (empty == NULL) {
        SBX_ALERT(L, "cap_init() failed: %s — cannot drop caps, aborting", strerror(errno));
        perror("[SANDBOX] cap_init");
        return -1;
    }
    if (cap_set_proc(empty) != 0) {
        int e = errno;
        SBX_ALERT(L, "cap_set_proc(empty) FAILED: %s (errno=%d) — sandbox INSECURE", strerror(e), e);
        perror("[SANDBOX] cap_set_proc");
        cap_free(empty);
        return -1;
    }


    /* ── Passo 2: PR_SET_KEEPCAPS = 0 ────────────────────────────────────
     *  Controla se o kernel preserva as caps quando o processo executa um
     *  novo binário via execve(). Com flag=0, QUALQUER execve() limpa as
     *  caps — mesmo que o binário seja setuid-root.
     * ─────── */

    if (prctl(PR_SET_KEEPCAPS, 0) != 0) {
        int e = errno;
        SBX_ALERT(L, "prctl(PR_SET_KEEPCAPS, 0) FAILED: %s (errno=%d)", strerror(e), e);
        perror("[SANDBOX] PR_SET_KEEPCAPS");
        return -1;
    }


    /* ── Passo 3: PR_SET_NO_NEW_PRIVS = 1 ────────────────────────────────
     *  Bit IRREVERSÍVEL no process descriptor do kernel.
     *  Efeito: execve() de binários setuid/setcap não eleva privilégios.
     *  Todo filho herdará este bit — impossível remover via prctl ou fork.
     * ─────── */

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        int e = errno;
        SBX_ALERT(L, "prctl(PR_SET_NO_NEW_PRIVS, 1) FAILED: %s (errno=%d)", strerror(e), e);
        perror("[SANDBOX] PR_SET_NO_NEW_PRIVS");
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
