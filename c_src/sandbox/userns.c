/*
 * userns.c
 *
 * Nuk4sd — Hardened Sandbox — Layer 1+3: User Namespace + Pivot Root
 * Extraído de vault_sandbox.c 
 */

#include "sandbox.h"

#ifdef __linux__

static inline void pivot_fatal(const char *step) {
    vault_log(LOG_ALERT, "[PIVOT] Critical failure during '%s' — aborting to prevent escape", step);
    _exit(EXIT_FAILURE);
}

static int sandbox_pivot_root(const char *new_root, bool mount_proc)
{
    if (new_root == NULL || new_root[0] == '\0') {
        return -1;
    }

    int ret = -1;
    char oldroot[64] = ".sandbox_oldroot_XXXXXX";

    /* Step 1: MS_PRIVATE — prevent mount propagation to host */
    mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);

    /* Step 2: self-bind new_root (pivot_root requires a mountpoint) */
    if (mount(new_root, new_root, NULL, MS_BIND | MS_REC, NULL) != 0) {
        vault_log(LOG_ERROR, "[PIVOT] Self-bind '%s' failed: %s", new_root, strerror(errno));
        return -1;
    }

    /* Step 3: chdir to new_root */
    if (chdir(new_root) != 0) {
        vault_log(LOG_ERROR, "[PIVOT] chdir('%s') failed: %s", new_root, strerror(errno));
        goto cleanup_bind;
    }

    /* Step 4: tmp dir for old root anchor */
    if (mkdtemp(oldroot) == NULL) {
        vault_log(LOG_ERROR, "[PIVOT] mkdtemp failed: %s", strerror(errno));
        goto cleanup_bind;
    }
    struct stat st;
    if (lstat(oldroot, &st) != 0 || !S_ISDIR(st.st_mode)) {
        vault_log(LOG_ALERT, "[PIVOT] TOCTOU check failed: '%s' is not a directory", oldroot);
        rmdir(oldroot);
        goto cleanup_bind;
    }

    /* Step 5: THE pivot_root(2) syscall */
    if (syscall(SYS_pivot_root, ".", oldroot) != 0) {
        vault_log(LOG_ERROR, "[PIVOT] pivot_root failed: %s", strerror(errno));
        rmdir(oldroot);
        goto cleanup_bind;
    }

    /* Step 6: detach old root */
    char oldroot_abs[80];
    snprintf(oldroot_abs, sizeof(oldroot_abs), "/%s", oldroot);

    if (mount_proc) {
        mkdir("/proc", 0555);
        if (mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) != 0) {
            vault_log(LOG_WARN, "[PIVOT] mount /proc failed: %s", strerror(errno));
        }
    }

    if (umount2(oldroot_abs, MNT_DETACH) != 0) {
        vault_log(LOG_ERROR,
              "[PIVOT] umount2('%s') failed: %s",
              oldroot_abs, strerror(errno));
        pivot_fatal("oldroot detach");
    }

    if (rmdir(oldroot_abs) != 0) {
        vault_log(LOG_ERROR,
                  "[PIVOT] rmdir('%s') failed: %s",
                  oldroot_abs, strerror(errno));
        pivot_fatal("oldroot removal");
    }

    if (chdir("/") != 0) {
        vault_log(LOG_ALERT,
                  "[PIVOT] chdir('/') failed: %s",
                  strerror(errno));
        pivot_fatal("return to root");
    }

    ret = 0;
    goto done;

cleanup_bind:
    umount2(new_root, MNT_DETACH);
done:
    return ret;
}


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
        vault_log(LOG_WARN, "[USERNS] open(%s) failed: %s", path, strerror(errno));
    }
    else
    {
        n = write(fd, "deny", 4);
        if (n != 4)
            vault_log(LOG_WARN, "[USERNS] write(%s) failed: %s", path, strerror(errno));
        close(fd);
    }

    snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)child_pid);
    map_len = snprintf(map, sizeof(map), "%d %d 1\n", (int)ruid, (int)ruid);

    fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        vault_log(LOG_ERROR, "[USERNS] open(%s) failed: %s", path, strerror(errno));
    }
    else
    {
        n = write(fd, map, (size_t)map_len);
        if (n != map_len)
            vault_log(LOG_ERROR, "[USERNS] write(%s) failed: %s (%zd/%d bytes)", path, strerror(errno), n, map_len);
        else {
            vault_log(LOG_INFO, "[USERNS] uid_map set: %s", map);
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
        vault_log(LOG_ERROR, "[USERNS] open(%s) failed: %s", path, strerror(errno));
    }
    else
    {
        n = write(fd, map, (size_t)map_len);
        if (n != map_len)
            vault_log(LOG_ERROR, "[USERNS] write(%s) failed: %s (%zd/%d bytes)", path, strerror(errno), n, map_len);
        else {
            vault_log(LOG_INFO, "[USERNS] gid_map set: %s", map);
            gid_ok = true;
        }
        close(fd);
    }

    if (!uid_ok || !gid_ok) {
        vault_log(LOG_ALERT, "[USERNS] uid_map/gid_map write failed — aborting namespace setup");
        return -1;
    }
    return 0;
}

int vsb_pivot_root(const char *new_root, bool mount_proc) { return sandbox_pivot_root(new_root, mount_proc); }
int vsb_write_uid_gid_map(pid_t child_pid, uid_t ruid, gid_t rgid) { return sandbox_write_uid_gid_map(child_pid, ruid, rgid); }

#endif /* __linux__ */
