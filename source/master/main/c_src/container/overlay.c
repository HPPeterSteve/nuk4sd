/*
 * overlay.c
 *
 * Nuk4sd — Container OverlayFS
 *
 * Monta overlayfs para VaultContainer com verificação de regras WORM
 * via Vault.worm_flags antes de qualquer operação de escrita.
 *
 * Localização: c_src/container/overlay.c
 * Header:      c_src/container/overlay.h
 *
 * Dependências:
 *   vault_core.h  — VaultContainer, Vault, WORM_PROTECT_*, vault_log()
 */

#include "overlay.h"
#include "vault_core.h"

#include <limits.h>
#include <string.h>
#ifndef SYMLOOP_MAX
#define SYMLOOP_MAX 40
#endif
#include <errno.h>
#include <sys/stat.h>

#ifdef __linux__
#include <sys/mount.h>
#include <unistd.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  overlay_path_is_safe — verifica que 'path' está contido dentro de
 *  'vault_root', prevenindo ataques de path traversal em upper/work/merged/lower.
 *
 *  Usa realpath() subindo no path até achar um componente existente no disco,
 *  já que os diretórios podem ainda não existir na primeira chamada.
 *
 *  Guards:
 *    - vault_root ou path NULL -> retorna 0 (inseguro) imediatamente.
 *    - path maior que PATH_MAX -> retorna 0.
 *    - probe colapsado até "/" sem achar componente existente -> retorna 0.
 * ═══════════════════════════════════════════════════════════════════════════ */
static int overlay_path_is_safe(const char *vault_root, const char *path) {
    if (!vault_root || !path) return 0;

    char resolved_root[PATH_MAX];
    if (!realpath(vault_root, resolved_root)) return 0;

    char probe[PATH_MAX];
    if (snprintf(probe, sizeof(probe), "%s", path) >= (int)sizeof(probe))
        return 0; /* path too long — trunc silenciosa seria perigosa */

    char resolved_probe[PATH_MAX];

    /* Guard de profundidade: previne loop infinito com symlinks circulares.
     * SYMLOOP_MAX (POSIX) é o limite de redirecionamentos de symlink que o
     * kernel tolera — usar o mesmo valor aqui é consistente com o comportamento
     * do próprio realpath() interno. */
    int depth = 0;
    while (!realpath(probe, resolved_probe)) {
        if (++depth > SYMLOOP_MAX) {
            vault_log(LOG_WARN, "[OVERLAY] path_is_safe: limite de profundidade atingido — possível loop de symlink em '%s'", path);
            return 0;
        }
        char *slash = strrchr(probe, '/');
        /* Chegou na raiz (slash == probe -> "/") ou sem barra -> para */
        if (!slash || slash == probe) return 0;
        *slash = '\0';
    }

    size_t rlen = strlen(resolved_root);
    return strncmp(resolved_probe, resolved_root, rlen) == 0 &&
           (resolved_probe[rlen] == '/' || resolved_probe[rlen] == '\0');
}

/* --------------------------------------------------------------------------- */

static int ensure_dir(const char *path) {
    if (!path) {
        vault_log(LOG_ERROR, "[OVERLAY] ensure_dir: NULL path");
        return -1;
    }
    if (access(path, F_OK) == 0) return 0;
    if (mkdir(path, 0755) == -1) {
        vault_log(LOG_ERROR, "[OVERLAY] mkdir '%s': %s", path, strerror(errno));
        return -1;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  mount_overlay — monta lower+upper+work em merged.
 *
 *  vault_root: raiz que upper/work/merged/lower DEVEM ter como prefixo
 *  (via overlay_path_is_safe). Passe NULL só se os quatro paths já vierem
 *  de uma fonte confiável e pré-validada — nunca com paths vindos de flag
 *  de usuário ou config carregada de disco.
 * ═══════════════════════════════════════════════════════════════════════════ */
int mount_overlay(const char *upper, const char *work, const char *lower,
                  const char *merged, const char *vault_root) {
#ifndef __linux__
    (void)upper; (void)work; (void)lower; (void)merged; (void)vault_root;
    return -1; /* Not implemented on this platform */
#else
    if (!upper || !work || !lower || !merged) {
        vault_log(LOG_ERROR, "[OVERLAY] mount_overlay: argumento NULL");
        return -1;
    }

    if (vault_root) {
        const char *dirs[]  = { lower, upper, work, merged };
        const char *names[] = { "lowerdir", "upperdir", "workdir", "merged" };
        for (int i = 0; i < 4; i++) {
            if (!overlay_path_is_safe(vault_root, dirs[i])) {
                vault_log(LOG_ERROR,
                    "[OVERLAY] %s '%s': path escapes vault jail — recusando",
                    names[i], dirs[i]);
                return -1;
            }
        }
    }

    if (ensure_dir(lower)  == -1) return -1;
    if (ensure_dir(upper)  == -1) return -1;
    if (ensure_dir(work)   == -1) return -1;
    if (ensure_dir(merged) == -1) return -1;

    /* Tamanho dinmico: 4 paths de até VAULT_PATH_MAX + prefixos de chaves.
     * Truncamento checado explicitamente — snprintf silencioso passaria
     * opções corrompidas direto para mount(). */
    char opts[4 * VAULT_PATH_MAX + 128];

    /* "userxattr" é obrigatório para montar overlayfs dentro de um user
     * namespace sem privilégio (kernel >= 5.11 — exatamente o caso do
     * Nuk4sd após unshare(CLONE_NEWUSER)). Tentamos com ela primeiro; se
     * o kernel for antigo (<5.11) e não reconhecer a opção, EINVAL -> fallback
     * sem ela. Cobre as duas famílias de kernel sem detectar versão. */
    int n = snprintf(opts, sizeof(opts),
                     "lowerdir=%s,upperdir=%s,workdir=%s,userxattr",
                     lower, upper, work);
    if (n < 0 || (size_t)n >= sizeof(opts)) {
        vault_log(LOG_ERROR, "[OVERLAY] mount options truncadas — paths muito longos");
        return -1;
    }

    if (mount("overlay", merged, "overlay", 0, opts) == 0) {
        vault_log(LOG_INFO, "[OVERLAY] montado com userxattr (kernel >= 5.11) em '%s'", merged);
        return 0;
    }

    if (errno == EINVAL) {
        /* Kernel < 5.11: "userxattr" não reconhecida — tenta sem ela.
         * Nota: kernels 5.11–5.12 tinham bugs com SELinux no overlayfs
         * não-privilegiado (corrigido no 5.13). Nesta família, a montagem
         * pode falhar com outros erros mesmo sem userxattr — o chamador
         * deve verificar o resultado. */
        n = snprintf(opts, sizeof(opts),
                     "lowerdir=%s,upperdir=%s,workdir=%s",
                     lower, upper, work);
        if (n < 0 || (size_t)n >= sizeof(opts)) {
            vault_log(LOG_ERROR, "[OVERLAY] mount options truncadas — paths muito longos");
            return -1;
        }
        if (mount("overlay", merged, "overlay", 0, opts) == 0) {
            vault_log(LOG_WARN, "[OVERLAY] montado SEM userxattr (kernel < 5.11) em '%s' — xattrs de overlay não disponíveis", merged);
            return 0;
        }
    }

    vault_log(LOG_ERROR, "[OVERLAY] mount falhou: %s", strerror(errno));
    return -1;
#endif
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  umount_overlay — lazy-unmount (MNT_DETACH) do ponto de montagem merged.
 *
 *  MNT_DETACH garante que o umount não trava se ainda houver fds abertos
 *  dentro do merged (mesmo padrão do teardown FUSE do vault).
 * ═══════════════════════════════════════════════════════════════════════════ */
int umount_overlay(const char *merged) {
#ifndef __linux__
    (void)merged;
    return -1;
#else
    if (!merged) {
        vault_log(LOG_ERROR, "[OVERLAY] umount_overlay: path NULL");
        return -1;
    }
    /* sync() antes do MNT_DETACH: garante que dados em cache sejam
     * escritos antes de desanexar o mount. MNT_DETACH desvincula o ponto
     * de montagem imediatamente mas deixa o filesystem ativo enquanto
     * houver fds abertos — sem sync, gravações pendentes podem ser perdidas
     * se o storage for removido logo após. */
    sync();
    if (umount2(merged, MNT_DETACH) == -1) {
        vault_log(LOG_ERROR, "[OVERLAY] umount2 '%s': %s", merged, strerror(errno));
        return -1;
    }
    vault_log(LOG_INFO, "[OVERLAY] desmontado (lazy) '%s'", merged);
    return 0;
#endif
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  overlay_fs_init — entry point de alto nível para VaultContainer.
 *
 *  Checa regras WORM via vault->worm_flags ANTES de qualquer operação de
 *  escrita. Se WORM_PROTECT_WRITE ou o super-flag WORM_PROTECT_SCAN estiver
 *  ativo, a montagem com upperdir é recusada — o container é somente-leitura.
 *
 *  Layout derivado de container->path:
 *    lower  -> <path>/lower
 *    upper  -> <path>/upper   (camada de escrita — bloqueada por WORM)
 *    work   -> <path>/work
 *    merged -> <path>/merged  (ponto de montagem final)
 * ═══════════════════════════════════════════════════════════════════════════ */
int overlay_fs_init(const VaultContainer *container, const Vault *vault) {
    if (!container || !vault) {
        vault_log(LOG_ERROR, "[OVERLAY] overlay_fs_init: argumento NULL");
        return -1;
    }

    /* -- Checagem Sealed + Whitelist ---------------------------------------
     * Se o container está selado (sealed=1), a montagem do overlayfs consta
     * na whitelist padrão e é permitida (whitelist_excluded=0).
     * Se o usuário executou --white-list -e, whitelist_excluded=1 e a
     * montagem é bloqueada mesmo que o container esteja apenas selado.
     *
     * Para restaurar: --white-list -r -> whitelist_excluded = 0. */
    if (container->sealed && container->whitelist_excluded) {
        vault_log(LOG_ERROR,
            "[OVERLAY] container '%s' selado com whitelist excluída (--white-list -e)"
            " — montagem recusada",
            container->path);
        return -1;
    }

    /* -- Checagem WORM ------------------------------------------------------
     * WORM_PROTECT_WRITE -> escrita em arquivos existentes bloqueada.
     * WORM_PROTECT_SCAN  -> super-flag: imutabilidade total, sem upperdir. */
    if (worm_check(vault, WORM_PROTECT_WRITE)) {
        vault_log(LOG_WARN,
            "[OVERLAY] WORM ativo (flags=0x%x): container '%s' é somente-leitura"
            " — montagem com upperdir recusada",
            vault->worm_flags, container->path);
        return -1;
    }

    /* -- Derivação dos paths ---------------------------------------------- */
    char lower[VAULT_PATH_MAX];
    char upper[VAULT_PATH_MAX];
    char work[VAULT_PATH_MAX];
    char merged[VAULT_PATH_MAX];

    int r;
    r = snprintf(lower,  sizeof(lower),  "%s/lower",  container->path);
    if (r < 0 || r >= (int)sizeof(lower))  goto path_too_long;

    r = snprintf(upper,  sizeof(upper),  "%s/upper",  container->path);
    if (r < 0 || r >= (int)sizeof(upper))  goto path_too_long;

    r = snprintf(work,   sizeof(work),   "%s/work",   container->path);
    if (r < 0 || r >= (int)sizeof(work))   goto path_too_long;

    r = snprintf(merged, sizeof(merged), "%s/merged", container->path);
    if (r < 0 || r >= (int)sizeof(merged)) goto path_too_long;

    return mount_overlay(upper, work, lower, merged, container->path);

path_too_long:
    vault_log(LOG_ERROR,
        "[OVERLAY] container path muito longo para derivar subpaths: '%s'",
        container->path);
    return -1;
}
