/*
 * mounts.c
 *
 * Nuk4sd — Hardened Sandbox — Layer 2: Mount Namespace (/proc, /tmp)
 * Extraído de vault_sandbox.c (split modular, estilo Firejail).
 */

#include "sandbox.h"

#ifdef __linux__

/* ---
 *  sandbox_prepare_mounts(): /proc + /tmp virtuais dentro do jail
 * --- */
static void sandbox_prepare_mounts(void)
{
    const char *L = "MOUNTS";
    char fl_buf[256];
    SBX_LOG(L, "Mounting virtual filesystems inside jail...");

    int rp = mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
    if (rp != 0) {
        int err = errno;
        fprintf(stderr, "[KERNEL ERROR] Function: %s | Syscall: mount(\"none\", \"/\") | Error: %s (%d)\n", __func__, strerror(err), err);
        _exit(-ERR_SYSTEM_MOUNT_FAILED);
    }
    SBX_DBG(L, "\u25b6 mount(none,/,NULL,%s): result=%d OK",
            decode_mount_flags(MS_REC|MS_PRIVATE, fl_buf, sizeof(fl_buf)), rp);

    if (mkdir("/proc", 0555) != 0 && errno != EEXIST)
        SBX_DBG(L, "  mkdir(/proc): %s (non-fatal)", strerror(errno));

    unsigned long pfl = MS_NOSUID | MS_NOEXEC | MS_NODEV;
    int rr = mount("proc", "/proc", "proc", pfl, NULL);
    if (rr != 0) {
        int err = errno;
        fprintf(stderr, "[KERNEL ERROR] Function: %s | Syscall: mount(\"proc\", \"/proc\") | Error: %s (%d)\n", __func__, strerror(err), err);
        _exit(-ERR_SYSTEM_MOUNT_FAILED);
    }
    SBX_DBG(L, "\u25b6 mount(proc,/proc,proc,%s): result=%d OK",
            decode_mount_flags(pfl, fl_buf, sizeof(fl_buf)), rr);
    SBX_DBG(L, "  NOSUID: suid inside /proc is inert | NOEXEC: no exec from procfs | NODEV: no devs");

    if (mkdir("/tmp", 01777) != 0 && errno != EEXIST)
        SBX_DBG(L, "  mkdir(/tmp): %s (non-fatal)", strerror(errno));

    unsigned long tfl = MS_NOSUID | MS_NODEV;
    char tmp_opts[128];
    snprintf(tmp_opts, sizeof(tmp_opts),
             "uid=%u,gid=%u,mode=1777,size=64m",
             (unsigned)geteuid(), (unsigned)getegid());
    int rt = mount("tmpfs", "/tmp", "tmpfs", tfl, tmp_opts);
    SBX_DBG(L, "\u25b6 mount(tmpfs,/tmp,tmpfs,%s,'%s'): result=%d %s",
            decode_mount_flags(tfl, fl_buf, sizeof(fl_buf)),
            tmp_opts, rt, rt — strerror(errno) : "OK");
    SBX_DBG(L, "  tmpfs: RAM-backed, ephemeral — destroyed when namespace exits");

    if (mkdir("/dev/shm", 01777) != 0 && errno != EEXIST)
        SBX_DBG(L, "  mkdir(/dev/shm): %s (non-fatal)", strerror(errno));

    unsigned long shm_fl = MS_NOSUID | MS_NODEV;
    char shm_opts[128];
    snprintf(shm_opts, sizeof(shm_opts),
             "uid=%u,gid=%u,mode=1777,size=256m",
             (unsigned)geteuid(), (unsigned)getegid());
    int rshm = mount("tmpfs", "/dev/shm", "tmpfs", shm_fl, shm_opts);
    SBX_DBG(L, "\u25b6 mount(tmpfs,/dev/shm,tmpfs,%s,'%s'): result=%d %s",
            decode_mount_flags(shm_fl, fl_buf, sizeof(fl_buf)), shm_opts, rshm, rshm — strerror(errno) : "OK");
    SBX_OK(L, "/proc, /tmp, and /dev/shm ready inside jail.");
}

void vsb_prepare_mounts(void) { sandbox_prepare_mounts(); }

#endif /* __linux__ */
