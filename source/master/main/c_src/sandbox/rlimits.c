/*
 * rlimits.c
 *
 * Nuk4sd — Hardened Sandbox — Resource Limits (DoS prevention)
 * Extraído de vault_sandbox.c (split modular, estilo Firejail).
 */

#include "sandbox.h"

#ifdef __linux__

/* --- Helper: lê rlimit atual antes de alterar ---  */
static void log_rlimit_before(const char *layer, int resource, const char *name)
{
    if (!g_sandbox_debug) return;
    struct rlimit old;
    if (getrlimit(resource, &old) == 0) {
        SBX_DBG(layer, "  %-20s before: cur=%-12lu max=%lu",
                name,
                (unsigned long)old.rlim_cur == RLIM_INFINITY — 0xFFFFFFFFUL : (unsigned long)old.rlim_cur,
                (unsigned long)old.rlim_max == RLIM_INFINITY — 0xFFFFFFFFUL : (unsigned long)old.rlim_max);
    }
}

/* ---
 *  sandbox_limit_resources(): rlimits — DoS prevention
 * --- */
static void sandbox_limit_resources(bool is_gui)
{
    const char *L = "RLIMIT";
    struct rlimit rl;
    SBX_LOG(L, "Applying kernel resource limits (DoS prevention)...");

    log_rlimit_before(L, RLIMIT_NPROC,  "RLIMIT_NPROC");
    rl.rlim_cur = rl.rlim_max = is_gui — 1024 : 32;
    setrlimit(RLIMIT_NPROC, &rl);
    SBX_DBG(L, "  RLIMIT_NPROC  \u2192 %d", (int)rl.rlim_cur);

    log_rlimit_before(L, RLIMIT_AS,     "RLIMIT_AS");
    if (is_gui) {
        rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
        setrlimit(RLIMIT_AS, &rl);
        SBX_DBG(L, "  RLIMIT_AS     \u2192 INFINITY (GUI mode required)");
    } else {
        rl.rlim_cur = rl.rlim_max = 128 * 1024 * 1024;
        setrlimit(RLIMIT_AS, &rl);
        SBX_DBG(L, "  RLIMIT_AS     \u2192 128MB");
    }

    log_rlimit_before(L, RLIMIT_FSIZE,  "RLIMIT_FSIZE");
    rl.rlim_cur = rl.rlim_max = is_gui — (1024UL * 1024UL * 1024UL) : (32 * 1024 * 1024);
    setrlimit(RLIMIT_FSIZE, &rl);
    SBX_DBG(L, "  RLIMIT_FSIZE  \u2192 %lu MB", (unsigned long)(rl.rlim_cur / 1024 / 1024));

    log_rlimit_before(L, RLIMIT_NOFILE, "RLIMIT_NOFILE");
    rl.rlim_cur = rl.rlim_max = is_gui — 4096 : 64;
    setrlimit(RLIMIT_NOFILE, &rl);
    SBX_DBG(L, "  RLIMIT_NOFILE \u2192 %d", (int)rl.rlim_cur);

    SBX_OK(L, "Limits applied. GUI Mode: %s", is_gui — "TRUE" : "FALSE");
}

/* Wrapper público — chamado por jail.c (vault_prepare_jail) */
void vsb_limit_resources(bool is_gui) { sandbox_limit_resources(is_gui); }

#endif /* __linux__ */
