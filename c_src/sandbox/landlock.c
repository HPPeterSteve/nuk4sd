/*
 * landlock.c
 *
 * Nuk4sd — Sandbox — Landlock LSM (Linux 5.13+)
 *
 * Third layer of MAC (Mandatory Access Control) alongside Seccomp-BPF.
 * While Seccomp blocks syscalls by number, Landlock blocks
 * access to specific paths in VFS — complementary and independent.
 *
 * Strategy: deny everything by default, then open exactly the paths
 * that the process needs (derived from CliConfig bind mounts).
 *
 * Compatibility:
 *   - Kernel >= 5.13: Landlock ABI v1 (basic)
 *   - Kernel >= 5.19: Landlock ABI v2 (+ LANDLOCK_ACCESS_FS_REFER)
 *   - Kernel >= 6.2 : Landlock ABI v3 (+ LANDLOCK_ACCESS_FS_TRUNCATE)
 *   - Kernel <  5.13: silent fallback — sandbox continues via Seccomp
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

/* ── Syscall wrappers (landlock has no glibc wrapper yet) ───────── */
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

/* ── Available ABI detection ──────────────────────────────────────── */
static int landlock_abi_version(void)
{
    struct landlock_ruleset_attr probe = { .handled_access_fs = 0 };
    int fd = ll_create_ruleset(&probe, sizeof(probe),
                               LANDLOCK_CREATE_RULESET_VERSION);
    if (fd < 0) return -1; /* kernel unsupported */
    close(fd);
    /* returned fd is the ABI version when flag=VERSION */
    return (int)(long)fd;
}

/* ── Full FS access supported by ABI ─────────────────────────────── */
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
        access |= LANDLOCK_ACCESS_FS_REFER;       /* hardlinks between dirs */
    if (abi >= 3)
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;    /* truncate(2) */

    return access;
}

/* ── Adds a rule for a path with allowed access permissions ────────── */
static int ll_allow_path(int ruleset_fd, const char *path, __u64 allowed)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        /* path might not exist (bind mount not performed yet) — non-fatal */
        vault_log(LOG_WARN, "[LANDLOCK] open(O_PATH) failed for '%s': %s",
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
        vault_log(LOG_WARN, "[LANDLOCK] add_rule failed for '%s': %s",
                  path, strerror(errno));
    }
    return ret;
}

/*════
 *  landlock_apply — main entry point
 *
 *  Builds ruleset based on bind mounts declared in CliConfig:
 *    BIND_RO      → READ_FILE | READ_DIR | EXECUTE
 *    BIND_RW      → full access (write, create, etc.)
 *    BIND_BLACKLIST → nothing — path doesn't appear in ruleset → access denied
 *
 *  In addition to user binds, always allows:
 *    /proc/self   → getpid, /proc/self/fd, etc.
 *    /dev         → /dev/null, /dev/urandom, /dev/fuse — already mounted
 *    /tmp         → some apps need /tmp
 *    vault_root   → jail root directory (pivot_root performed beforehand)
 *
 *  Returns:
 *     0  → success, Landlock active
 *    -1  → kernel does not support Landlock (ABI < 1) — silent fallback OK
 *    -2  → kernel SUPPORTS Landlock but unexpected error (LOG_ALERT emitted)
 *
 *  Caller MUST distinguish -1 from -2: -1 is silent, -2 must be
 *  signaled to the user as the process runs WITHOUT VFS restrictions.
 *════ */
int landlock_apply(const CliConfig *cfg, const char *vault_root)
{
    if (!cfg) return -1;

    int abi = landlock_abi_version();
    if (abi < 0) {
        vault_log(LOG_INFO, "[LANDLOCK] kernel unsupported (ABI < 1) — Seccomp remains active");
        return -1; /* non-fatal: old kernel, silent fallback */
    }

    vault_log(LOG_INFO, "[LANDLOCK] ABI v%d detected", abi);

    __u64 all_access = landlock_fs_access_all(abi);
    __u64 ro_access  = LANDLOCK_ACCESS_FS_EXECUTE |
                       LANDLOCK_ACCESS_FS_READ_FILE |
                       LANDLOCK_ACCESS_FS_READ_DIR;

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = all_access,
    };

    int ruleset_fd = ll_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        /* Kernel supports Landlock (abi >= 1) but create_ruleset failed — unexpected */
        vault_log(LOG_ALERT,
                  "[LANDLOCK][ALERT] kernel supports Landlock (ABI v%d) but "
                  "create_ruleset failed: %s — VFS unrestricted!", abi, strerror(errno));
        return -2;
    }

    /* ── Always allowed paths (base system inside jail) ─────── */
    /* FIX #6: /tmp does NOT have all_access here — mount namespace creates an isolated tmpfs
     * via vsb_prepare_mounts() AFTER pivot_root. Giving all_access to /tmp BEFORE
     * pivot_root would allow writing to HOST /tmp.
     * We apply only ro_access to host /tmp (pre-pivot temporary reading),
     * and after pivot the Landlock ruleset is already anchored to jail inodes. */
    static const struct { const char *path; int rw; } base_paths[] = {
        { "/proc/self",   0 },
        { "/proc/self/fd",0 },
        { "/dev",         0 },
        { "/tmp",         0 }, /* FIX #6: read-only — write goes to isolated tmpfs */
        { "/run",         0 },
    };
    for (size_t i = 0; i < sizeof(base_paths)/sizeof(base_paths[0]); i++) {
        ll_allow_path(ruleset_fd, base_paths[i].path,
                      base_paths[i].rw ? all_access : ro_access);
    }

    /* ── Vault root (jail root where pivot_root landed) ──────────────── */
    if (vault_root && *vault_root)
        ll_allow_path(ruleset_fd, vault_root, all_access);

    /* ── User-declared bind mounts ─────────────────────────── */
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
            /* no rule → access automatically denied */
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

    /* ── Apply ruleset to current thread (and all children) ─────── */
    /* PR_SET_NO_NEW_PRIVS was already set in caps.c — check anyway */
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    if (ll_restrict_self(ruleset_fd, 0) < 0) {
        /* Kernel supports Landlock but restrict_self failed — process runs without VFS restriction */
        vault_log(LOG_ALERT,
                  "[LANDLOCK][ALERT] kernel supports Landlock (ABI v%d) but "
                  "restrict_self failed: %s — process running WITHOUT VFS restriction!",
                  abi, strerror(errno));
        close(ruleset_fd);
        return -2;
    }

    close(ruleset_fd);
    vault_log(LOG_INFO, "[LANDLOCK] ruleset applied with %d bind(s)", cfg->bind_count);
    return 0;
}

#else /* !__linux__ */

int landlock_apply(const CliConfig *cfg, const char *vault_root)
{
    (void)cfg; (void)vault_root;
    return -1; /* unsupported outside Linux */
}

#endif /* __linux__ */
