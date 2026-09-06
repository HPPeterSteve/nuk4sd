/*
 * mounts.c
 *
 * Nuk4sd — Hardened Sandbox — Layer 2: Mount Namespace (/proc, /tmp)
 * Extraído de vault_sandbox.c 
 */

#include "sandbox.h"

#ifdef __linux__

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_prepare_mounts(): /proc + /tmp virtuais dentro do jail
 * ───────────── */
static void sandbox_prepare_mounts(void)
{
    int rp = mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
    if (rp != 0) {
        int err = errno;
        vault_log(LOG_ERROR, "[MOUNTS] mount(\"none\", \"/\") failed: %s (%d)", strerror(err), err);
        _exit(-ERR_SYSTEM_MOUNT_FAILED);
    }

    (void)mkdir("/proc", 0555);

    unsigned long pfl = MS_NOSUID | MS_NOEXEC | MS_NODEV;
    int rr = mount("proc", "/proc", "proc", pfl, NULL);
    if (rr != 0) {
        int err = errno;
        vault_log(LOG_ERROR, "[MOUNTS] mount(\"proc\", \"/proc\") failed: %s (%d)", strerror(err), err);
        _exit(-ERR_SYSTEM_MOUNT_FAILED);
    }

    (void)mkdir("/tmp", 01777);

    unsigned long tfl = MS_NOSUID | MS_NODEV;
    mount("tmpfs", "/tmp", "tmpfs", tfl, SANDBOX_TMP_SIZE);

    (void)mkdir("/dev/shm", 01777);

    unsigned long shm_fl = MS_NOSUID | MS_NODEV;
    mount("tmpfs", "/dev/shm", "tmpfs", shm_fl, "mode=1777,size=256m");
}

void vsb_prepare_mounts(void) { sandbox_prepare_mounts(); }

#endif /* __linux__ */
