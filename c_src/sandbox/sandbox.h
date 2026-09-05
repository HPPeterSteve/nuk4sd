#ifndef NUK4SD_SANDBOX_H
#define NUK4SD_SANDBOX_H

/*
 * sandbox.h
 *
 * Nuk4sd — Hardened Sandbox — header único compartilhado
 *
 * Segue o padrão do Firejail (src/firejail/firejail.h): um header só
 * pra todo o subsistema, em vez de um .h por .c. Cada seção abaixo é
 * marcada com um comentário "// arquivo.c" indicando onde a função
 * correspondente é definida — igual ao firejail.h faz.
 *
 * 5-layer defense-in-depth sandbox (Linux-only):
 *   1. User Namespace  — userns.c    — root no sandbox → nobody no host
 *   2. Mount Namespace  — mounts.c    — /proc + /tmp virtuais
 *   3. Pivot Root       — userns.c    — substitui chroot (mais seguro)
 *   4. Capability Drop  — caps.c      — remove todas as Linux Caps + NO_NEW_PRIVS
 *   5. Seccomp-BPF      — seccomp.c   — allowlist mínima, KILL como padrão
 *
 * Outros módulos:
 *   jail.c     — monta a estrutura de diretórios do jail + shell/busybox
 *   rlimits.c  — rlimits (DoS prevention)
 *   common.c   — flag de debug compartilhada entre todos os módulos
 */

#include "vault_core.h"

#ifdef __linux__
#include <sys/sysmacros.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════
 *  common.c — estado de debug compartilhado
 * ═══════════════════════════════════════════════════════════════════════ */
extern bool g_sandbox_debug;

#define SBX_LOG(layer, fmt, ...) \
    fprintf(stderr, "\033[36m[SANDBOX][%s]\033[0m " fmt "\n", (layer), ##__VA_ARGS__)

#define SBX_DBG(layer, fmt, ...) \
    do { if (g_sandbox_debug) \
        fprintf(stderr, "\033[90m[SANDBOX][DBG][%s]\033[0m " fmt "\n", (layer), ##__VA_ARGS__); \
    } while(0)

#define SBX_ALERT(layer, fmt, ...) \
    fprintf(stderr, "\033[31m[SANDBOX][ALERT][%s]\033[0m " fmt "\n", (layer), ##__VA_ARGS__)

#define SBX_OK(layer, fmt, ...) \
    fprintf(stderr, "\033[32m[SANDBOX][OK][%s]\033[0m " fmt "\n", (layer), ##__VA_ARGS__)

#define SBX_SEP(layer) \
    do { if (g_sandbox_debug) \
        fprintf(stderr, "\033[90m[SANDBOX][DBG][%s] ──────────────────────────────────────────────\033[0m\n", (layer)); \
    } while(0)

void vsb_set_debug(bool debug);

/* ═══════════════════════════════════════════════════════════════════════
 *  Helper compartilhado entre userns.c (pivot_root) e mounts.c
 *  (era a única função não-estática de fato usada em mais de um lugar —
 *  as outras "decode_ns_flags"/"log_ns_link"/"mount_bind" originais do
 *  vault_sandbox.c nunca eram chamadas em lugar nenhum e foram removidas
 *  nesse split, não fazia sentido carregar código morto pros arquivos novos)
 * ═══════════════════════════════════════════════════════════════════════ */
static inline const char *decode_mount_flags(unsigned long fl, char *buf, size_t sz)
{
    buf[0] = '\0';
    static const struct { unsigned long v; const char *n; } bits[] = {
        {MS_RDONLY,     "RDONLY"},  {MS_NOSUID,  "NOSUID"}, {MS_NODEV,  "NODEV"},
        {MS_NOEXEC,     "NOEXEC"},  {MS_REMOUNT, "REMOUNT"},{MS_BIND,   "BIND"},
        {MS_REC,        "REC"},     {MS_PRIVATE, "PRIVATE"},{MS_SLAVE,  "SLAVE"},
        {MS_SHARED,     "SHARED"},  {MS_MOVE,    "MOVE"},   {0, NULL}
    };
    int first = 1;
    for (int i = 0; bits[i].n; i++) {
        if (fl & bits[i].v) {
            if (!first) strncat(buf, "|", sz - strlen(buf) - 1);
            strncat(buf, bits[i].n, sz - strlen(buf) - 1);
            first = 0;
        }
    }
    if (first) strncat(buf, "(none)", sz - 1);
    return buf;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  caps.c — Layer 4: Capability Drop
 * ═══════════════════════════════════════════════════════════════════════ */
int vsb_drop_caps(void);
int vsb_caps_drop(const CliConfig *cfg);

/* ═══════════════════════════════════════════════════════════════════════
 *  landlock.c
 * ═══════════════════════════════════════════════════════════════════════ */
int landlock_apply(const CliConfig *cfg, const char *vault_root);

/* ═══════════════════════════════════════════════════════════════════════
 *  userns.c — Layer 1+3: User Namespace + Pivot Root
 * ═══════════════════════════════════════════════════════════════════════ */
int  vsb_pivot_root(const char *new_root, bool mount_proc);
int vsb_write_uid_gid_map(pid_t child_pid, uid_t ruid, gid_t rgid);

/* ═══════════════════════════════════════════════════════════════════════
 *  mounts.c — Layer 2: Mount Namespace
 * ═══════════════════════════════════════════════════════════════════════ */
void vsb_prepare_mounts(void);

/* ═══════════════════════════════════════════════════════════════════════
 *  rlimits.c — Resource Limits
 * ═══════════════════════════════════════════════════════════════════════ */
void vsb_limit_resources(bool is_gui);

/* ═══════════════════════════════════════════════════════════════════════
 *  seccomp.c — Layer 5: Seccomp-BPF
 * ═══════════════════════════════════════════════════════════════════════ */
int  vsb_apply_seccomp(void);
void vsb_set_seccomp_mode(int strict, int allow_c3, int friendly, int permissive);

/* ═══════════════════════════════════════════════════════════════════════
 *  jail.c — estrutura de diretórios do jail + shell/busybox
 * ═══════════════════════════════════════════════════════════════════════ */
void vsb_prepare_jail(const char *path, bool gui);
void vsb_bind_gui_deps(const char *jail_path);

#endif /* NUK4SD_SANDBOX_H */