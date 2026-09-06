/*
 * rlimits.c
 *
 * Nuk4sd — Hardened Sandbox — Resource Limits (DoS prevention)
 * Extraído de vault_sandbox.c 
 */

#include "sandbox.h"

#ifdef __linux__

static void sandbox_limit_resources(bool is_gui)
{
    struct rlimit rl;

    rl.rlim_cur = rl.rlim_max = is_gui ? 1024 : 32;
    setrlimit(RLIMIT_NPROC, &rl);

    if (is_gui) {
        rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
        setrlimit(RLIMIT_AS, &rl);
    } else {
        rl.rlim_cur = rl.rlim_max = 128 * 1024 * 1024;
        setrlimit(RLIMIT_AS, &rl);
    }

    rl.rlim_cur = rl.rlim_max = is_gui ? (1024UL * 1024UL * 1024UL) : (32 * 1024 * 1024);
    setrlimit(RLIMIT_FSIZE, &rl);

    rl.rlim_cur = rl.rlim_max = is_gui ? 4096 : 64;
    setrlimit(RLIMIT_NOFILE, &rl);
}

/* Wrapper público — chamado por jail.c (vault_prepare_jail) */
void vsb_limit_resources(bool is_gui) { sandbox_limit_resources(is_gui); }

#endif /* __linux__ */
