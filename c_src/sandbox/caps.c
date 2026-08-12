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
    SBX_SEP(L);
    SBX_LOG(L, "━━ Layer 4: DROP ALL LINUX CAPABILITIES ━━");

    /* ── Estado ANTES ────────────────────────────────────────────────────── */
    cap_t before = cap_get_proc();
    char *before_text = before ? cap_to_text(before, NULL) : NULL;
    SBX_DBG(L, "▶ State BEFORE drop:");
    SBX_DBG(L, "  capabilities   = '%s'", before_text ? before_text : "(read failed)");
    SBX_DBG(L, "  euid=%d  egid=%d  pid=%d", (int)geteuid(), (int)getegid(), (int)getpid());
    SBX_DBG(L, "  NOTE: inside user namespace, UID 0 maps to host UID %d", (int)getuid());
    if (before_text) cap_free(before_text);
    if (before)      cap_free(before);

    /* ── Passo 1: cap_set_proc(empty) — zera as 3 listas de capabilities ─ */
    SBX_DBG(L, "▶ Step 1/3 — Kernel call: cap_set_proc(empty_set)");
    SBX_DBG(L, "  Erases: permitted, effective AND inheritable capability sets");
    SBX_DBG(L, "  Effect: process loses CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_CHOWN, etc.");
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
    cap_free(empty);
    SBX_DBG(L, "  Kernel result: 0 (SUCCESS)");
    SBX_DBG(L, "  ✔ permitted=∅  effective=∅  inheritable=∅");

    /* ── Passo 2: PR_SET_KEEPCAPS = 0 ────────────────────────────────────
     *  Controla se o kernel preserva as caps quando o processo executa um
     *  novo binário via execve(). Com flag=0, QUALQUER execve() limpa as
     *  caps — mesmo que o binário seja setuid-root.
     * ─────── */
    SBX_DBG(L, "▶ Step 2/3 — Kernel call: prctl(PR_SET_KEEPCAPS, 0)");
    SBX_DBG(L, "  Without this: execve() could restore caps from ambient set");
    SBX_DBG(L, "  With flag=0 : caps cleared on every execve(), unconditionally");
    if (prctl(PR_SET_KEEPCAPS, 0) != 0) {
        int e = errno;
        SBX_ALERT(L, "prctl(PR_SET_KEEPCAPS, 0) FAILED: %s (errno=%d)", strerror(e), e);
        perror("[SANDBOX] PR_SET_KEEPCAPS");
        return -1;
    }
    SBX_DBG(L, "  Kernel result: 0 (SUCCESS)");
    SBX_DBG(L, "  ✔ PR_SET_KEEPCAPS=0 — caps will NOT survive next execve()");

    /* ── Passo 3: PR_SET_NO_NEW_PRIVS = 1 ────────────────────────────────
     *  Bit IRREVERSÍVEL no process descriptor do kernel.
     *  Efeito: execve() de binários setuid/setcap não eleva privilégios.
     *  Todo filho herdará este bit — impossível remover via prctl ou fork.
     * ─────── */
    SBX_DBG(L, "▶ Step 3/3 — Kernel call: prctl(PR_SET_NO_NEW_PRIVS, 1)");
    SBX_DBG(L, "  This bit is IRREVERSIBLE for this process and ALL children");
    SBX_DBG(L, "  Effect: setuid(0) binaries inside jail cannot gain root privs");
    SBX_DBG(L, "  Effect: seccomp filter cannot be bypassed via privilege escalation");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        int e = errno;
        SBX_ALERT(L, "prctl(PR_SET_NO_NEW_PRIVS, 1) FAILED: %s (errno=%d)", strerror(e), e);
        perror("[SANDBOX] PR_SET_NO_NEW_PRIVS");
        return -1;
    }
    SBX_DBG(L, "  Kernel result: 0 (SUCCESS)");
    SBX_DBG(L, "  ✔ NO_NEW_PRIVS=1 — IRREVOCABLE, inherited by all descendants");

    /* ── Verificação: confirma que caps estão realmente vazios ───────────  */
    SBX_DBG(L, "▶ Verification — Reading post-drop capability state from kernel:");
    cap_t check = cap_get_proc();
    if (check != NULL) {
        char *text = cap_to_text(check, NULL);
        SBX_DBG(L, "  post-drop caps = '%s'  (expected '=')", text ? text : "(null)");
        if (text && strcmp(text, "=") != 0) {
            SBX_ALERT(L, "RESIDUAL CAPS DETECTED: '%s' — sandbox privilege isolation INCOMPLETE!", text);
            cap_free(text);
            cap_free(check);
            return -1;
        }
        cap_free(text);
        cap_free(check);
    }

    SBX_OK(L, "All capabilities dropped. NO_NEW_PRIVS=1. Privilege level: ZERO.");
    SBX_DBG(L, "  Security: no kernel privilege escalation vector remains via capabilities");
    SBX_DBG(L, "  Next: Seccomp-BPF will enforce syscall allowlist as final layer");
    SBX_SEP(L);
    return 0;
}

int vsb_drop_caps(void) { return sandbox_drop_caps(); }

#endif /* __linux__ */
