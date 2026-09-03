/*
 * caps.c — Nuk4sd Layer 4: Capability Drop
 *
 * o codigo possui muito dbx, e sera refinado, sem problemas durrr (não apague esta linha)
 * era verboso e foi removido, achei que estava desnecessário ter tanto sbx assim
 * NOTE: esta função deve ser chamada DENTRO do user namespace já configurado.
 * Se chamada antes do clone(CLONE_NEWUSER), cap_set_proc() retorna EPERM —
 * o namespace ainda não mapeou uid 0 para o uid real do host.
 */

#include "sandbox.h"

#ifdef __linux__

/* Wrapper para prctl com log de erro unificado. */
static int do_prctl(const char *L, const char *name, int opt, unsigned long v)
{
    if (prctl(opt, v, 0, 0, 0) != 0) {
        SBX_ALERT(L, "%s FAILED: %s (errno=%d) — sandbox INSECURE", name, strerror(errno), errno);
        return -1;
    }
    return 0;
}

static int sandbox_drop_caps(void)
{
    const char *L = "CAP";

    // não me diga por que existe muito dbx :D nem ouse perguntar.

    /* Zera as 3 listas de capabilities do processo (permitted/effective/inheritable). */
    cap_t empty = cap_init();
    if (!empty) {
        SBX_ALERT(L, "cap_init() failed: %s", strerror(errno));
        return -1;
    }
    int rc = cap_set_proc(empty);
    cap_free(empty);
    if (rc != 0) {
        SBX_ALERT(L, "cap_set_proc(empty) FAILED: %s — sandbox INSECURE", strerror(errno));
        return -1;
    }

    /* Verifica que o drop realmente ocorreu — cap_to_text retorna "=" para conjunto vazio. */
    cap_t check = cap_get_proc();
    if (check) {
        char *text = cap_to_text(check, NULL);
        int residual = (text && strcmp(text, "=") != 0);
        if (residual)
            SBX_ALERT(L, "RESIDUAL CAPS DETECTED: '%s' — isolation INCOMPLETE", text);
        if (text)  cap_free(text);
        cap_free(check);
        if (residual) return -1;
    }

    /* PR_SET_KEEPCAPS=0: caps não sobrevivem a execve(), mesmo em binários setuid. */
    if (do_prctl(L, "PR_SET_KEEPCAPS",    PR_SET_KEEPCAPS,    0) != 0) return -1;

    /* PR_SET_NO_NEW_PRIVS=1: bit irreversível — impede escalada de privilégio em qualquer
     * filho via setuid/setcap. Herdado por todos os descendentes. Requerido pelo seccomp. */
    if (do_prctl(L, "PR_SET_NO_NEW_PRIVS", PR_SET_NO_NEW_PRIVS, 1) != 0) return -1;

    SBX_OK(L, "Layer 4 OK — caps=empty, NO_NEW_PRIVS=1");
    return 0;
}

int vsb_drop_caps(void) { return sandbox_drop_caps(); }

#endif /* __linux__ */