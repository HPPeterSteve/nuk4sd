/*
 * mount_dev.c
 *
 * Nuk4sd — Hardened Sandbox
 * Cria um /dev mínimo e isolado dentro do jail (tmpfs + mknod).
 * Nenhum device do host é exposto ao processo sandboxado.
 */

#include "sandbox.h"
#include <sys/sysmacros.h>

#ifdef __linux__

/* ─── Nodes mínimos para um shell funcional ───────────────────────────────  */

static const struct {
    const char *path;
    mode_t      mode;    /* S_IFCHR | permissões */
    unsigned    maj;
    unsigned    min;
} dev_nodes[] = {
    { "/dev/null",    S_IFCHR | 0666, 1, 3 },
    { "/dev/zero",    S_IFCHR | 0666, 1, 5 },
    { "/dev/random",  S_IFCHR | 0444, 1, 8 },
    { "/dev/urandom", S_IFCHR | 0444, 1, 9 },
    { "/dev/tty",     S_IFCHR | 0666, 5, 0 },
    { "/dev/console", S_IFCHR | 0600, 5, 1 },
    { NULL, 0, 0, 0 }  /* sentinela */
};

/* ─── Estado do módulo ───────────────────────────────────────────────────  */

static bool g_mount_dev = false;

void vsb_set_mount_dev(bool enabled) { g_mount_dev = enabled; }

/* ─── Implementação ───────────────────────────────────────────────────────  */

void vsb_mount_dev(void)
{
    if (!g_mount_dev)
        return;

    const char *Log = "MOUNT_DEV";

    /* Passo 1: tmpfs em /dev — isola completamente do /dev do host */
    if (mount("tmpfs", "/dev", "tmpfs",
              MS_NOSUID | MS_STRICTATIME,
              "mode=0755,size=65536k") != 0) {
        vault_log(LOG_ALERT, "[%s] tmpfs on /dev failed: %s", Log, strerror(errno));
        return;
    }
    vault_log(LOG_INFO, "[%s] /dev: tmpfs montado (isolado do host)", Log);

    /* Passo 2: cria apenas os device nodes essenciais via mknod */
    for (int i = 0; dev_nodes[i].path != NULL; i++) {
        dev_t dev = makedev(dev_nodes[i].maj, dev_nodes[i].min);
        if (mknod(dev_nodes[i].path, dev_nodes[i].mode, dev) != 0)
            vault_log(LOG_WARN, "[%s] mknod '%s' (%u:%u) failed: %s",
                      Log, dev_nodes[i].path,
                      dev_nodes[i].maj, dev_nodes[i].min, strerror(errno));
        else
            vault_log(LOG_INFO, "[%s] criado %s (%u:%u)",
                      Log, dev_nodes[i].path,
                      dev_nodes[i].maj, dev_nodes[i].min);
    }

    /* Passo 3: devpts — pseudoterminals para shell interativo */
    if (mkdir("/dev/pts", 0755) != 0 && errno != EEXIST) {
        vault_log(LOG_WARN, "[%s] mkdir /dev/pts failed: %s", Log, strerror(errno));
    } else if (mount("devpts", "/dev/pts", "devpts",
                     MS_NOSUID | MS_NOEXEC,
                     "newinstance,ptmxmode=0666,mode=0620") != 0) {
        vault_log(LOG_WARN, "[%s] devpts on /dev/pts failed: %s", Log, strerror(errno));
    } else {
        vault_log(LOG_INFO, "[%s] /dev/pts: devpts montado", Log);
    }

    /* Passo 4: symlinks padrão esperados por programas POSIX */
    symlink("/proc/self/fd",   "/dev/fd");
    symlink("/proc/self/fd/0", "/dev/stdin");
    symlink("/proc/self/fd/1", "/dev/stdout");
    symlink("/proc/self/fd/2", "/dev/stderr");
}

#endif /* __linux__ */
