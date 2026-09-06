/*
 * userns.c
 *
 * Nuk4sd — Hardened Sandbox — Layer 1+3: User Namespace + Pivot Root
 * Extraído de vault_sandbox.c (split modular, estilo Firejail).
 */

#include "sandbox.h"

#ifdef __linux__

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_pivot_root(): Layer 3 — Pivot root to vault path
 * ───────────── */
static int sandbox_pivot_root(const char *new_root, bool mount_proc)
{
    const char *L = "PIVOT";
    SBX_LOG(L, "\u2501\u2501 Layer 3: PIVOT ROOT \u2192 '%s' \u2501\u2501", new_root);
    if (new_root == NULL || new_root[0] == '\0') {
        SBX_ALERT(L, "new_root is NULL/empty");
        return -1;
    }

    int ret = -1;
    char oldroot[64] = ".sandbox_oldroot_XXXXXX";

    /* Step 1: MS_PRIVATE — prevent mount propagation to host */
    mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);

    /* Step 2: self-bind new_root (pivot_root requires a mountpoint) */
    if (mount(new_root, new_root, NULL, MS_BIND | MS_REC, NULL) != 0) {
        int e = errno;
        SBX_ALERT(L, "Self-bind '%s' FAILED: %s (errno=%d)", new_root, strerror(e), e);
        return -1;
    }

    /* Step 3: chdir to new_root */
    if (chdir(new_root) != 0) {
        SBX_ALERT(L, "chdir('%s') FAILED: %s", new_root, strerror(errno));
        goto cleanup_bind;
    }

    /* Step 4: tmp dir for old root anchor */
    if (mkdtemp(oldroot) == NULL) {
        SBX_ALERT(L, "mkdtemp FAILED: %s", strerror(errno));
        goto cleanup_bind;
    }
    struct stat st;
    if (lstat(oldroot, &st) != 0 || !S_ISDIR(st.st_mode)) {
        SBX_ALERT(L, "TOCTOU check: '%s' is not a real dir!", oldroot);
        rmdir(oldroot);
        goto cleanup_bind;
    }

    /* Step 5: THE pivot_root(2) syscall */
    if (syscall(SYS_pivot_root, ".", oldroot) != 0) {
        int e = errno;
        SBX_ALERT(L, "pivot_root FAILED: %s (errno=%d) — try --chroot as fallback", strerror(e), e);
        rmdir(oldroot);
        goto cleanup_bind;
    }

    /* Step 6: detach old root */
    char oldroot_abs[80];
    snprintf(oldroot_abs, sizeof(oldroot_abs), "/%s", oldroot);

    /* BUGFIX: O Kernel proíbe montar um novo procfs se a raiz do host
     * for desmontada antes. Precisamos montar o /proc novo AQUI, enquanto
     * o /proc do host ainda está tecnicamente visível na árvore antiga. */
    if (mount_proc) {
        mkdir("/proc", 0555);
        if (mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) != 0) {
            SBX_ALERT(L, "mount /proc falhou ANTES do detach: %s", strerror(errno));
        }
    }

    umount2(oldroot_abs, MNT_DETACH);
    rmdir(oldroot_abs);

    if (chdir("/") != 0) {
        SBX_ALERT(L, "chdir('/') after pivot FAILED: %s", strerror(errno));
        goto cleanup_bind;
    }
    SBX_OK(L, "Root pivoted. Jail '/' = vault. Host filesystem: DETACHED.");
    ret = 0;
    goto done;

cleanup_bind:
    umount2(new_root, MNT_DETACH);
done:
    return ret;
}

/* [REMOVIDO] run_id_helper()/newuidmap/newgidmap — não são mais necessários.
 * Ver comentário em sandbox_write_uid_gid_map() abaixo: o kernel rejeita o
 * mapa de 2 linhas que exigia esse helper, então o design mudou pra mapa de
 * 1 linha só, que já é escrevível sem privilégio nenhum. */


/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_write_uid_gid_map(): Write UID/GID maps for user namespace
 *
 *  [REDESIGN] O mapa original tentava DUAS linhas — "0 -> 0" (ou "0 -> ruid")
 *  E "ruid -> ruid" — pra depois dar setresuid() e "soltar" o root fake pro
 *  UID real, já que apps GUI (Firefox etc) recusam/estranham getuid()==0.
 *
 *  Só que o KERNEL REJEITA (EINVAL) qualquer uid_map com o mesmo
 *  ID-outside-ns repetido em duas linhas — confirmado testando direto via
 *  write(2) em /proc/[pid]/uid_map. "0 -> 1000" + "1000 -> 1000" tem
 *  outside-id=1000 nas duas linhas → sempre falha, com ou sem newuidmap,
 *  com ou sem CAP_SETUID. Não é bug do newuidmap, é o kernel mesmo.
 *
 *  Fix: mapa de UMA linha só, "0 -> ruid". Isso é EXATAMENTE o formato que
 *  o kernel permite escrever SEM NENHUM PRIVILÉGIO (regra: processo sem
 *  CAP_SETUID só pode escrever 1 linha, e o outside-id tem que ser o
 *  próprio UID real de quem escreve) — então newuidmap/newgidmap deixam de
 *  ser necessários pro caso comum. O processo fica como ns-uid 0 o tempo
 *  todo, mapeado direto pro UID real — o que já resolve sozinho o
 *  descasamento de permissão com o mount FUSE/socket Wayland/etc, porque o
 *  kernel resolve esse ns-uid 0 pro UID real em QUALQUER checagem de
 *  permissão contra arquivos do host.
 *
 *  Consequência: não existe mais um segundo ns-uid pra "dropar" via
 *  setresuid() depois do pivot_root — o chamador (vault_cli.c) não deve
 *  mais tentar isso. Ver comentário lá.
 * ───────────── */
static int sandbox_write_uid_gid_map(pid_t child_pid, uid_t ruid, gid_t rgid)
{
    char path[256];
    char map[128];
    int fd;
    ssize_t n;
    int map_len;
    bool uid_ok = false;
    bool gid_ok = false;

    /* setgroups deny — precisa vir ANTES de gid_map em kernels que exigem isso */
    snprintf(path, sizeof(path), "/proc/%d/setgroups", (int)child_pid);
    fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        fprintf(stderr, "[SANDBOX][WARN] open(%s): %s\n", path, strerror(errno));
    }
    else
    {
        n = write(fd, "deny", 4);
        if (n != 4)
            fprintf(stderr, "[SANDBOX][WARN] write(%s) falhou: %s\n", path, strerror(errno));
        close(fd);
    }

    /* uid_map: linha única, IDENTIDADE "ruid -> ruid" (não mais "0 -> ruid").
     *
     * [REDESIGN 2] Testado e confirmado empiricamente: o kuid real do
     * processo NUNCA muda com unshare(CLONE_NEWUSER) — só a TRADUÇÃO de
     * exibição (getuid()) muda, de acordo com o mapa. Com "0 -> ruid",
     * getuid() mostra 0 (reverse-lookup do kuid=ruid encontra a entrada
     * ns-id=0) — e é exatamente isso que fazia o Firefox recusar rodar
     * ("Running Firefox as root... is not supported"). Com "ruid -> ruid"
     * (identidade), getuid() já mostra o UID real direto, SEM precisar de
     * setresuid() nenhum depois. E como a capability de criar o jail
     * (mount()/pivot_root()) vem de SER O PROCESSO QUE CRIOU o namespace —
     * não do valor numérico do uid mapeado — ela continua de pé igual.
     * Confirmado via teste direto (fork+unshare+mount como usuário sem
     * privilégio nenhum, com esse exato formato de mapa). */
    snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)child_pid);
    map_len = snprintf(map, sizeof(map), "%d %d 1\n", (int)ruid, (int)ruid);

    fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        fprintf(stderr, "[SANDBOX][FATAL] open(%s): %s\n", path, strerror(errno));
    }
    else
    {
        n = write(fd, map, (size_t)map_len);
        if (n != map_len)
            fprintf(stderr, "[SANDBOX][FATAL] write(%s) falhou: %s (escrito %zd de %d bytes)\n",
                    path, strerror(errno), n, map_len);
        else {
            fprintf(stderr, "[SANDBOX][OK] uid_map escrito (identidade): \"%s\"", map);
            uid_ok = true;
        }
        close(fd);
    }

    /* gid_map: mesma lógica, identidade "rgid -> rgid". */
    snprintf(path, sizeof(path), "/proc/%d/gid_map", (int)child_pid);
    map_len = snprintf(map, sizeof(map), "%d %d 1\n", (int)rgid, (int)rgid);

    fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        fprintf(stderr, "[SANDBOX][FATAL] open(%s): %s\n", path, strerror(errno));
    }
    else
    {
        n = write(fd, map, (size_t)map_len);
        if (n != map_len)
            fprintf(stderr, "[SANDBOX][FATAL] write(%s) falhou: %s (escrito %zd de %d bytes)\n",
                    path, strerror(errno), n, map_len);
        else {
            fprintf(stderr, "[SANDBOX][OK] gid_map escrito (identidade): \"%s\"", map);
            gid_ok = true;
        }
        close(fd);
    }

    if (!uid_ok || !gid_ok) {
        fprintf(stderr,
                "[SANDBOX][FATAL] uid_map/gid_map não foram escritos — o processo ficaria "
                "preso como UID/GID de overflow (65534, 'nobody') dentro do namespace, sem "
                "bater com o dono de nada no host (vault FUSE, sockets, /dev/*). Abortando em "
                "vez de continuar num estado quebrado.\n");
        return -1;
    }
    return 0;
}

int vsb_pivot_root(const char *new_root, bool mount_proc) { return sandbox_pivot_root(new_root, mount_proc); }
int vsb_write_uid_gid_map(pid_t child_pid, uid_t ruid, gid_t rgid) { return sandbox_write_uid_gid_map(child_pid, ruid, rgid); }

#endif /* __linux__ */
