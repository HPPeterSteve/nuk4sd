/*
 * landlock.c
 *
 * Nuk4sd — Sandbox — Landlock LSM (Linux 5.13+)
 *
 * Terceira camada de MAC (Mandatory Access Control) além do Seccomp-BPF.
 * Enquanto o Seccomp bloqueia syscalls pelo número, o Landlock bloqueia
 * acesso a paths específicos no VFS — complementares e independentes.
 *
 * Estratégia: nega tudo por padrão, depois abre exatamente os paths
 * que o processo precisa (derivados dos bind mounts do CliConfig).
 *
 * Compatibilidade:
 *   - Kernel >= 5.13: Landlock ABI v1 (básico)
 *   - Kernel >= 5.19: Landlock ABI v2 (+ LANDLOCK_ACCESS_FS_REFER)
 *   - Kernel >= 6.2 : Landlock ABI v3 (+ LANDLOCK_ACCESS_FS_TRUNCATE)
 *   - Kernel <  5.13: fallback silencioso — sandbox continua via Seccomp
 */

#define _GNU_SOURCE
#include "sandbox.h"
#include "preset.h"
#include "vault_core.h"

#ifdef __linux__
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

/* ── Syscall wrappers (landlock não tem wrapper na glibc ainda) ───────── */
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule       445
#define __NR_landlock_restrict_self  446
#endif

#define ll_create_ruleset(attr, size, flags) \
    syscall(__NR_landlock_create_ruleset, attr, size, flags)
#define ll_add_rule(fd, type, attr, flags) \
    syscall(__NR_landlock_add_rule, fd, type, attr, flags)
#define ll_restrict_self(fd, flags) \
    syscall(__NR_landlock_restrict_self, fd, flags)

/* ── Detecção de ABI disponível ──────────────────────────────────────── */
static int landlock_abi_version(void)
{
    struct landlock_ruleset_attr probe = { .handled_access_fs = 0 };
    int fd = ll_create_ruleset(&probe, sizeof(probe),
                               LANDLOCK_CREATE_RULESET_VERSION);
    if (fd < 0) return -1; /* kernel sem suporte */
    close(fd);
    /* fd retornado é a versão ABI quando flag=VERSION */
    return (int)(long)fd;
}

/* ── Acesso FS completo suportado por ABI ─────────────────────────────── */
static __u64 landlock_fs_access_all(int abi)
{
    __u64 access =
        LANDLOCK_ACCESS_FS_EXECUTE        |
        LANDLOCK_ACCESS_FS_WRITE_FILE     |
        LANDLOCK_ACCESS_FS_READ_FILE      |
        LANDLOCK_ACCESS_FS_READ_DIR       |
        LANDLOCK_ACCESS_FS_REMOVE_DIR     |
        LANDLOCK_ACCESS_FS_REMOVE_FILE    |
        LANDLOCK_ACCESS_FS_MAKE_CHAR      |
        LANDLOCK_ACCESS_FS_MAKE_DIR       |
        LANDLOCK_ACCESS_FS_MAKE_REG       |
        LANDLOCK_ACCESS_FS_MAKE_SOCK      |
        LANDLOCK_ACCESS_FS_MAKE_FIFO      |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK     |
        LANDLOCK_ACCESS_FS_MAKE_SYM;

    if (abi >= 2)
        access |= LANDLOCK_ACCESS_FS_REFER;       /* hardlinks entre dirs */
    if (abi >= 3)
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;    /* truncate(2) */

    return access;
}

/* ── Adiciona uma regra para um path com os acessos permitidos ────────── */
static int ll_allow_path(int ruleset_fd, const char *path, __u64 allowed)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        /* path pode não existir (bind mount ainda não feito) — não é fatal */
        vault_log(LOG_WARN, "[LANDLOCK] open(O_PATH) falhou para '%s': %s",
                  path, strerror(errno));
        return 0;
    }

    struct landlock_path_beneath_attr attr = {
        .allowed_access = allowed,
        .parent_fd      = fd,
    };

    int ret = ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    close(fd);

    if (ret < 0) {
        vault_log(LOG_WARN, "[LANDLOCK] add_rule falhou para '%s': %s",
                  path, strerror(errno));
    }
    return ret;
}

/*════
 *  landlock_apply — entry point principal
 *
 *  Constrói o ruleset com base nos bind mounts declarados no CliConfig:
 *    BIND_RO      → READ_FILE | READ_DIR | EXECUTE
 *    BIND_RW      → acesso completo (escrita, criação, etc.)
 *    BIND_BLACKLIST → nada — path não aparece no ruleset → acesso negado
 *
 *  Além dos binds do usuário, sempre permite:
 *    /proc/self   → getpid, /proc/self/fd, etc.
 *    /dev         → /dev/null, /dev/urandom, /dev/fuse — já montados
 *    /tmp         → alguns apps precisam de /tmp
 *    vault_root   → o diretório raiz do jail (pivot_root já feito antes)
 *
 *  Retorna 0 em sucesso, -1 se Landlock não suportado (kernel antigo).
 *  Fallback silencioso: sandbox continua sem Landlock — Seccomp permanece.
 *════ */
int landlock_apply(const CliConfig *cfg, const char *vault_root)
{
    if (!cfg) return -1;

    int abi = landlock_abi_version();
    if (abi < 0) {
        vault_log(LOG_INFO, "[LANDLOCK] kernel sem suporte (ABI < 1) — skipped");
        return -1; /* não fatal */
    }

    vault_log(LOG_INFO, "[LANDLOCK] ABI v%d detectada", abi);

    __u64 all_access = landlock_fs_access_all(abi);
    __u64 ro_access  = LANDLOCK_ACCESS_FS_EXECUTE |
                       LANDLOCK_ACCESS_FS_READ_FILE |
                       LANDLOCK_ACCESS_FS_READ_DIR;

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = all_access,
    };

    int ruleset_fd = ll_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        vault_log(LOG_WARN, "[LANDLOCK] create_ruleset falhou: %s", strerror(errno));
        return -1;
    }

    /* ── Paths sempre permitidos (base do sistema dentro do jail) ─────── */
    /* FIX #6: /tmp NÃO tem all_access aqui — o mount namespace cria um tmpfs
     * isolado via vsb_prepare_mounts() DEPOIS do pivot_root. Dar all_access a
     * /tmp ANTES do pivot_root permitiria escrita no /tmp do HOST.
     * Aplicamos apenas ro_access em /tmp host (leitura temporária pré-pivot),
     * e após o pivot o Landlock ruleset já está ancorado nos inodes do jail. */
    static const struct { const char *path; int rw; } base_paths[] = {
        { "/proc/self",   0 },
        { "/proc/self/fd",0 },
        { "/dev",         0 },
        { "/tmp",         0 }, /* FIX #6: apenas leitura — escrita é do tmpfs isolado */
        { "/run",         0 },
    };
    for (size_t i = 0; i < sizeof(base_paths)/sizeof(base_paths[0]); i++) {
        ll_allow_path(ruleset_fd, base_paths[i].path,
                      base_paths[i].rw ? all_access : ro_access);
    }

    /* ── Vault root (jail root onde pivot_root aterrou) ──────────────── */
    if (vault_root && *vault_root)
        ll_allow_path(ruleset_fd, vault_root, all_access);

    /* ── Bind mounts declarados pelo usuário ─────────────────────────── */
    for (int i = 0; i < cfg->bind_count; i++) {
        const BindEntry *b = &cfg->binds[i];
        switch (b->type) {
        case BIND_RO:
            ll_allow_path(ruleset_fd, b->path, ro_access);
            break;
        case BIND_RW:
            ll_allow_path(ruleset_fd, b->path, all_access);
            break;
        case BIND_BLACKLIST:
            /* sem regra → acesso negado automaticamente */
            break;
        }
    }

    /* ── Home mounts ─────────────────────────────────────────────────── */
    const char *home = getenv("HOME");
    if (home) {
        if (cfg->iso_ro_home)
            ll_allow_path(ruleset_fd, home, ro_access);
        else if (cfg->iso_rw_home || cfg->iso_tmp_home)
            ll_allow_path(ruleset_fd, home, all_access);
    }

    /* ── Aplicar o ruleset ao thread atual (e todos os filhos) ─────── */
    /* PR_SET_NO_NEW_PRIVS já foi setado em caps.c — verificar de qualquer forma */
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    if (ll_restrict_self(ruleset_fd, 0) < 0) {
        vault_log(LOG_ERROR, "[LANDLOCK] restrict_self falhou: %s", strerror(errno));
        close(ruleset_fd);
        return -1;
    }

    close(ruleset_fd);
    vault_log(LOG_INFO, "[LANDLOCK] ruleset aplicado com %d bind(s)", cfg->bind_count);
    return 0;
}

#else /* !__linux__ */

int landlock_apply(const CliConfig *cfg, const char *vault_root)
{
    (void)cfg; (void)vault_root;
    return -1; /* não suportado fora do Linux */
}

#endif /* __linux__ */
