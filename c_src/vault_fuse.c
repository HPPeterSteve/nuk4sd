/*
 * vault_fuse.c
 *
 * FUSE filesystem layer for Nuk4sd.
 *
 * WORM Protection Model
 * ─────────────────────
 * Each mounted vault carries a worm_flags bitmask (uint32_t) that is
 * evaluated on every mutating FUSE call before the real syscall:
 *
 *   WORM_PROTECT_DELETE  →  vfuse_unlink / vfuse_rmdir  return -EPERM
 *   WORM_PROTECT_RENAME  →  vfuse_rename                returns -EPERM
 *   WORM_PROTECT_WRITE   →  vfuse_write on an *existing* file returns -EPERM
 *   WORM_PROTECT_READ    →  vfuse_read on an *existing* file returns -EPERM
 *                           (vfuse_create of a NEW file is allowed so the
 *                            vault can still be populated; only overwrites
 *                            of existing data are blocked)
 *   WORM_PROTECT_SCAN    →  super-flag; forces all three protections above
 *                           and makes the bitmask immutable at runtime.
 *                           The only sanctioned egress path is mount-export.
 *
 * Granularity note:
 *   Flags are per-vault, not per-file.  Per-file granularity would require
 *   extended attributes; that is left as a future enhancement.
 *
 * Thread safety:
 *   All FUSE callbacks run inside fuse_loop_mt.  They access the Vault
 *   pointer through fuse_get_context()->private_data.  The worm_flags
 *   field is read-only during a mounted session (write-barrier in
 *   vault_worm_set_flags / vault_worm_clear_flags acquires g_monitor.lock
 *   on the caller side), so a plain read is safe.
 */

#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>

#include "vault_core.h"

#include <time.h>

/* ─────────────────────────────────────────────────────────────────────────
 *  Atexit safety net: re-seal any cipher_dirs left at mode 700 if the
 *  process exits while a FUSE session is still running (e.g. the user
 *  sends SIGTERM or the CLI finishes while the FUSE thread is detached).
 *
 *  We walk the global catalog and chmod(0000) every vault whose
 *  cipher_path is currently accessible (i.e. we can stat() it with
 *  mode != 0000).  This is a best-effort defense-in-depth measure; the
 *  FUSE thread itself will also do the chmod on clean exit.
 * ───────────────────────────────────────────────────────────────────────── */
static void vault_fuse_seal_all_on_exit(void)
{
    for (uint32_t i = 0; i < g_catalog.count; i++) {
        Vault *v = &g_catalog.vaults[i];
        if (!v->cipher_path[0]) continue;

        struct stat st;
        /* If stat succeeds the directory is accessible (mode > 0000) */
        if (stat(v->cipher_path, &st) == 0) {
            if ((st.st_mode & 0777) != 0) {
                if (chmod(v->cipher_path, 0000) == 0) {
                    /* Write directly to stderr — log subsystem may already be down */
                    fprintf(stderr,
                            "[PHYSICAL_LOCK][atexit] Re-sealed cipher_dir='%s' "
                            "vault_id=%u (was mode 0%03o). State: SEALED.\n",
                            v->cipher_path, v->id, (unsigned)(st.st_mode & 0777));
                } else {
                    fprintf(stderr,
                            "[PHYSICAL_LOCK][atexit] WARNING: chmod 0000 FAILED on "
                            "cipher_dir='%s' vault_id=%u: %s\n",
                            v->cipher_path, v->id, strerror(errno));
                }
            }
        }
        v->is_mounted = false;
    }
}

/* Register the atexit handler exactly once. */
static pthread_once_t g_fuse_atexit_once = PTHREAD_ONCE_INIT;
static void register_fuse_atexit(void)
{
    atexit(vault_fuse_seal_all_on_exit);
}

#define FUSE_LOG_START(op) \
    struct timespec _ts_start, _ts_end; \
    clock_gettime(CLOCK_MONOTONIC, &_ts_start); \
    Vault *_v_log = (Vault *)fuse_get_context()->private_data;

#define FUSE_LOG_END(op, path, res) \
    clock_gettime(CLOCK_MONOTONIC, &_ts_end); \
    double _elapsed = (_ts_end.tv_sec - _ts_start.tv_sec) * 1000.0 + \
                      (_ts_end.tv_nsec - _ts_start.tv_nsec) / 1e6; \
    if ((res) < 0) { \
        vault_log(LOG_ERROR, "[FUSE] %s '%s' failed: %d (%.3fms) [vault=%s]", op, path, (res), _elapsed, _v_log ? _v_log->name : "?"); \
    } else { \
        vault_log(LOG_INFO, "[FUSE] %s '%s' OK (%.3fms) [vault=%s]", op, path, _elapsed, _v_log ? _v_log->name : "?"); \
    }



/* ─────────────────────────────────────────────────────────────────────────
 *  Internal helpers
 * ───────────────────────────────────────────────────────────────────────── */

/* Map the virtual FUSE path to the real cipher_path on disk. */
static void get_cipher_path(char *out_path, const char *path)
{
    Vault *v = (Vault *)fuse_get_context()->private_data;
    if (v) {
        snprintf(out_path, VAULT_PATH_MAX, "%s%s", v->cipher_path, path);
    } else {
        out_path[0] = '\0';
    }
}

/* Evaluate a single WORM flag against the vault.
 * WORM_PROTECT_SCAN forces ALL protection bits regardless of the stored mask. */
static inline bool worm_check(const Vault *v, uint32_t flag)
{
    if (!v) return false;
    /* SCAN super-flag: treat every protection bit as set */
    if (v->worm_flags & WORM_PROTECT_SCAN)
        return (flag & WORM_PROTECT_ALL) != 0;
    return (v->worm_flags & flag) != 0;
}

/* Log a WORM denial with full forensic context: timestamp, pid, op, path, flags. */
static void worm_deny_log(const Vault *v, const char *op, const char *path)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    const char *reason =
        (v->worm_flags & WORM_PROTECT_SCAN) ? "PROTECTED-SCAN" : "WORM";
    vault_log(LOG_AUDIT,
              "[WORM] %s DENIED │ op=%-10s │ path=%-40s │ vault='%s' │ "
              "flags=0x%08x │ pid=%d │ uid=%d │ ts=%ld.%09ld │ errno=EPERM",
              reason, op, path,
              v ? v->name : "<null>",
              v ? v->worm_flags : 0,
              (int)getpid(), (int)getuid(),
              (long)ts.tv_sec, ts.tv_nsec);
}

/* ─────────────────────────────────────────────────────────────────────────
 *  FUSE operation handlers
 * ───────────────────────────────────────────────────────────────────────── */

static int vfuse_getattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi)
{
    FUSE_LOG_START("getattr");
    (void) fi;
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    int res = lstat(full_path, stbuf);
    if (res == -1)
        { int err = -errno; FUSE_LOG_END("getattr", path, err); return err; }

    /* When WORM_PROTECT_SCAN is active, advertise all files as read-only
     * so that tools like cp or rsync do not attempt to overwrite them. */
    Vault *v = (Vault *)fuse_get_context()->private_data;
    if (v && (v->worm_flags & WORM_PROTECT_SCAN)) {
        stbuf->st_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
    }
    return 0;
}

static int vfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags)
{
    FUSE_LOG_START("readdir");
    (void) offset;
    (void) fi;
    (void) flags;

    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    DIR *dp = opendir(full_path);
    if (dp == NULL)
        { int err = -errno; FUSE_LOG_END("readdir", path, err); return err; }

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino  = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0))
            break;
    }
    closedir(dp);
    int res = 0;
    FUSE_LOG_END("readdir", path, res);
    return res;
}

static int vfuse_open(const char *path, struct fuse_file_info *fi)
{
    FUSE_LOG_START("open");
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    /* If WORM_PROTECT_WRITE (or SCAN) is active, deny any open that
     * carries a write flag — even O_RDWR.  This prevents silent
     * truncation via open(O_WRONLY|O_TRUNC) without going through write(). */
    Vault *v = (Vault *)fuse_get_context()->private_data;
    if (v && worm_check(v, WORM_PROTECT_WRITE)) {
        if (fi->flags & (O_WRONLY | O_RDWR | O_TRUNC | O_APPEND)) {
            worm_deny_log(v, "open-write", path);
            { int err = -EPERM; FUSE_LOG_END("open", path, err); return err; }
        }
    }

    int res = open(full_path, fi->flags);
    if (res == -1)
        { int err = -errno; FUSE_LOG_END("open", path, err); return err; }

    close(res);
    int res_ok = 0;
    FUSE_LOG_END("open", path, res_ok);
    return res_ok;
}

static int vfuse_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    FUSE_LOG_START("read");
    (void) fi;
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    Vault *v = (Vault *)fuse_get_context()->private_data;
    if (v && worm_check(v, WORM_PROTECT_READ)) {
        worm_deny_log(v, "read", path);
        { int err = -EPERM; FUSE_LOG_END("read", path, err); return err; }
    }

    int fd = open(full_path, O_RDONLY);
    if (fd == -1)
        { int err = -errno; FUSE_LOG_END("read", path, err); return err; }

    int res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    /* TODO: On-the-fly decryption should happen here using vault_crypto.c primitives */

    close(fd);
    FUSE_LOG_END("read", path, res);
    return res;
}

static int vfuse_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
    FUSE_LOG_START("write");
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    Vault *v = (Vault *)fuse_get_context()->private_data;

    /* ── WORM_PROTECT_WRITE / SCAN ───────────────────────────────────────
     * Block writes to existing files.  A new file (created in the same
     * session via vfuse_create) does not yet exist on disk when vfuse_write
     * is first called, so lstat() will fail with ENOENT — we allow those
     * writes through so that initial population still works.             */

    if (v && worm_check(v, WORM_PROTECT_WRITE)) {
        struct stat st;
        if (lstat(full_path, &st) == 0) {
            /* File already exists → deny overwrite */
            worm_deny_log(v, "write", path);
            { int err = -EPERM; FUSE_LOG_END("write", path, err); return err; }
        }
        /* ENOENT → new file being written for the first time → allow */
    }

    (void) fi;
    int fd = open(full_path, O_WRONLY | O_CREAT, 0600);
    if (fd == -1)
        { int err = -errno; FUSE_LOG_END("write", path, err); return err; }

    /* TODO: On-the-fly encryption should happen here using vault_crypto.c primitives */

    int res = pwrite(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    FUSE_LOG_END("write", path, res);
    return res;
}

static int vfuse_mkdir(const char *path, mode_t mode)
{
    FUSE_LOG_START("mkdir");
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    /* Directory creation is only blocked under SCAN (full immutability).
     * Plain --protect-delete / --no-write still allow mkdir so the user
     * can organise new content. */
    Vault *v = (Vault *)fuse_get_context()->private_data;
    if (v && (v->worm_flags & WORM_PROTECT_SCAN)) {
        worm_deny_log(v, "mkdir", path);
        { int err = -EPERM; FUSE_LOG_END("mkdir", path, err); return err; }
    }

    int res = mkdir(full_path, mode);
    if (res == -1)
        { int err = -errno; FUSE_LOG_END("mkdir", path, err); return err; }
    int res_ok = 0;
    FUSE_LOG_END("mkdir", path, res_ok);
    return res_ok;
}

static int vfuse_unlink(const char *path)
{
    FUSE_LOG_START("unlink");
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    Vault *v = (Vault *)fuse_get_context()->private_data;
    if (v && worm_check(v, WORM_PROTECT_DELETE)) {
        worm_deny_log(v, "unlink", path);
        { int err = -EPERM; FUSE_LOG_END("unlink", path, err); return err; }
    }

    if (unlink(full_path) == -1) { int err = -errno; FUSE_LOG_END("unlink", path, err); return err; }
    int res_ok = 0;
    FUSE_LOG_END("unlink", path, res_ok);
    return res_ok;
}

static int vfuse_rmdir(const char *path)
{
    FUSE_LOG_START("rmdir");
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);
    /*
    * Block rmdir if WORM_PROTECT_DELETE is active. This prevents
    * users from deleting directories that contain protected files.
    * Note: This check is performed *before* attempting the actual deletion.
    */

    Vault *v = (Vault *)fuse_get_context()->private_data;
    if (v && worm_check(v, WORM_PROTECT_DELETE)) {
        worm_deny_log(v, "rmdir", path);
        { int err = -EPERM; FUSE_LOG_END("rmdir", path, err); return err; }
    }

    if (rmdir(full_path) == -1) { int err = -errno; FUSE_LOG_END("rmdir", path, err); return err; }
    int res_ok = 0;
    FUSE_LOG_END("rmdir", path, res_ok);
    return res_ok;
}

static int vfuse_rename(const char *from, const char *to, unsigned int flags)
{
    FUSE_LOG_START("rename");
    (void) flags;
    char full_from[VAULT_PATH_MAX], full_to[VAULT_PATH_MAX];
    get_cipher_path(full_from, from);
    get_cipher_path(full_to, to);


    Vault *v = (Vault *)fuse_get_context()->private_data;
    if (v && worm_check(v, WORM_PROTECT_RENAME)) {
        worm_deny_log(v, "rename", from);
        { int err = -EPERM; FUSE_LOG_END("rename", from, err); return err; }
    }

    if (rename(full_from, full_to) == -1) { int err = -errno; FUSE_LOG_END("rename", from, err); return err; }
    int res_ok = 0;
    FUSE_LOG_END("rename", from, res_ok);
    return res_ok;
}

static int vfuse_create(const char *path, mode_t mode,
                        struct fuse_file_info *fi)
{
    FUSE_LOG_START("create");
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    /* Under SCAN mode even creation of new files is blocked (full freeze). */
    Vault *v = (Vault *)fuse_get_context()->private_data;
    if (v && (v->worm_flags & WORM_PROTECT_SCAN)) {
        worm_deny_log(v, "create", path);
        { int err = -EPERM; FUSE_LOG_END("create", path, err); return err; }
    }

    int res = open(full_path, fi->flags | O_CREAT, mode);
    if (res == -1)
        { int err = -errno; FUSE_LOG_END("create", path, err); return err; }
    close(res);
    int res_ok = 0;
    FUSE_LOG_END("create", path, res_ok);
    return res_ok;
}


/* ─────────────────────────────────────────────────────────────────────────
 *  FUSE operations table
 * ───────────────────────────────────────────────────────────────────────── */

static struct fuse_operations vault_oper = {
    .getattr = vfuse_getattr,
    .readdir = vfuse_readdir,
    .open    = vfuse_open,
    .read    = vfuse_read,
    .write   = vfuse_write,
    .mkdir   = vfuse_mkdir,
    .unlink  = vfuse_unlink,   /* WORM_PROTECT_DELETE guard */
    .rmdir   = vfuse_rmdir,    /* WORM_PROTECT_DELETE guard */
    .rename  = vfuse_rename,   /* WORM_PROTECT_RENAME guard */
    .create  = vfuse_create,   /* WORM_PROTECT_SCAN   guard */
};

/* ─────────────────────────────────────────────────────────────────────────
 *  FUSE mount / unmount
 * ───────────────────────────────────────────────────────────────────────── */
struct fuse_thread_data {
    /* Vault structure reused across most of the project.
     * Core of the vault subsystem interlinks. */
    Vault       *v;
    struct fuse *f;
    pthread_t    tid;  /* thread handle stored so unmount can join it */
};


static void *vault_fuse_loop(void *arg)
{
    /* Rename the thread so it appears distinctly in htop/task managers */
    prctl(PR_SET_NAME, "Nuk4sd-FUSE", 0, 0, 0);

    struct fuse_thread_data *td = (struct fuse_thread_data *)arg;
    Vault *v = td->v;
    

    vault_log(LOG_INFO,
              "[FUSE_LIFECYCLE] Thread STARTED │ vault_id=%u │ name='%s' │ "
              "mount_point='%s' │ cipher_dir='%s' │ worm_flags=0x%08x │ pid=%d │ uid=%d",
              v->id, v->name, v->path, v->cipher_path,
              v->worm_flags, (int)getpid(), (int)getuid());

    vault_log(LOG_AUDIT,
              "[PHYSICAL_LOCK] Temporary bypass granted: chmod 000 → 700 on cipher_dir='%s' "
              "to allow FUSE VFS projection. WORM guard active.",
              v->cipher_path);
    chmod(v->cipher_path, 0700);

    int res = fuse_loop_mt(td->f, 1); /* multi-threaded FUSE loop */

    vault_log(LOG_INFO,
              "[FUSE_LIFECYCLE] Loop EXITED │ vault_id=%u │ name='%s' │ exit_code=%d",
              v->id, v->name, res);

    /* Re-seal the physical directory immediately after FUSE tears down */
    chmod(v->cipher_path, 0000);
    vault_log(LOG_AUDIT,
              "[PHYSICAL_LOCK] FUSE session TERMINATED cleanly. Restoring permanent 000 "
              "immutable lock on cipher_dir='%s'. State: SEALED.",
              v->cipher_path);

    fuse_unmount(td->f);
    fuse_destroy(td->f);
    v->is_mounted = false;
    free(td);
    return NULL;
}

VaultErrorr vault_fuse_mount(Vault *v)
{
    if (v->is_mounted) {
        vault_log(LOG_WARN,
                  "[FUSE_MOUNT] Mount requested for vault_id=%u name='%s' but it is ALREADY MOUNTED at '%s'. Skipping.",
                  v->id, v->name, v->path);
        return ERR_OK;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    vault_log(LOG_AUDIT,
              "[FUSE_MOUNT] MOUNT INITIATED │ vault_id=%u │ name='%s' │ "
              "mount_point='%s' │ cipher_dir='%s' │ ts=%ld.%09ld │ pid=%d │ uid=%d",
              v->id, v->name, v->path, v->cipher_path,
              (long)ts.tv_sec, ts.tv_nsec, (int)getpid(), (int)getuid());

    /* Log active WORM protections at mount time */
    if (v->worm_flags & WORM_PROTECT_SCAN) {
        vault_log(LOG_AUDIT,
                  "[WORM] Vault %u '%s' mounting in PROTECTED-SCAN mode "
                  "(immutable — export only via mount-export). All WORM bits forced ON.",
                  v->id, v->name);
    } else if (v->worm_flags) {
        vault_log(LOG_AUDIT,
                  "[WORM] Vault %u '%s' mounting with active flags=0x%08x: "
                  "WRITE=%s DELETE=%s RENAME=%s READ=%s",
                  v->id, v->name, v->worm_flags,
                  (v->worm_flags & WORM_PROTECT_WRITE)  ? "BLOCK" : "allow",
                  (v->worm_flags & WORM_PROTECT_DELETE) ? "BLOCK" : "allow",
                  (v->worm_flags & WORM_PROTECT_RENAME) ? "BLOCK" : "allow",
                  (v->worm_flags & WORM_PROTECT_READ)   ? "BLOCK" : "allow");
    } else {
        vault_log(LOG_INFO,
                  "[WORM] Vault %u '%s' mounting with NO active protections (all WORM flags=0x00000000).",
                  v->id, v->name);
    }

    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args, "Nuk4sd");
    fuse_opt_add_arg(&args, "-o");
    fuse_opt_add_arg(&args, "auto_unmount");

    struct fuse *f = fuse_new(&args, &vault_oper, sizeof(vault_oper), v);
    fuse_opt_free_args(&args);
    if (!f) {
        vault_log(LOG_ERROR,
                  "[FUSE_MOUNT] FAILED to create FUSE struct for vault_id=%u name='%s'. "
                  "Kernel may have rejected the FUSE session.",
                  v->id, v->name);
        return ERR_IO;
    }

    if (fuse_mount(f, v->path) != 0) {
        fuse_destroy(f);
        vault_log(LOG_ERROR,
                  "[FUSE_MOUNT] FAILED to bind FUSE at mount_point='%s' for vault_id=%u. "
                  "errno=%d (%s). Ensure /dev/fuse is accessible and the mount point exists.",
                  v->path, v->id, errno, strerror(errno));
        return ERR_IO;
    }

    vault_log(LOG_INFO,
              "[FUSE_MOUNT] FUSE session bound to kernel VFS at mount_point='%s'. "
              "Spawning FUSE I/O thread for vault_id=%u.",
              v->path, v->id);

    struct fuse_thread_data *td = calloc(1, sizeof(struct fuse_thread_data));
    if (!td) {
        fuse_unmount(f);
        fuse_destroy(f);
        vault_log(LOG_ERROR,
                  "[FUSE_MOUNT] Out of memory allocating FUSE thread context for vault_id=%u.",
                  v->id);
        return ERR_NO_MEMORY;
    }
    td->v = v;
    td->f = f;
    v->is_mounted = true;

    /* Register the atexit handler (once) so that if this process exits
     * before the FUSE thread has a chance to re-seal the cipher_dir,
     * we still ensure the lock is restored. */
    pthread_once(&g_fuse_atexit_once, register_fuse_atexit);

    if (pthread_create(&td->tid, NULL, vault_fuse_loop, td) != 0) {
        fuse_unmount(f);
        fuse_destroy(f);
        free(td);
        v->is_mounted = false;
        vault_log(LOG_ERROR,
                  "[FUSE_MOUNT] pthread_create FAILED for vault_id=%u: errno=%d (%s). "
                  "FUSE session aborted. Physical lock NOT applied.",
                  v->id, errno, strerror(errno));
        return ERR_IO;
    }

    /* ── Validate that the mount actually appeared in /proc/mounts ──────
     * Give the FUSE thread up to 2 s to bind (kernel VFS registration is
     * nearly instant, but we add a small grace window for slow machines). */
    bool mount_confirmed = false;
    for (int attempt = 0; attempt < 20 && !mount_confirmed; attempt++) {
        struct timespec delay = { 0, 100 * 1000 * 1000 }; /* 100 ms */
        nanosleep(&delay, NULL);

        FILE *mf = fopen("/proc/mounts", "r");
        if (mf) {
            char line[512];
            while (fgets(line, sizeof(line), mf)) {
                /* Each line: device mountpoint fstype options ... */
                char dev[128], mp[VAULT_PATH_MAX];
                if (sscanf(line, "%127s %511s", dev, mp) == 2 &&
                    strcmp(mp, v->path) == 0) {
                    mount_confirmed = true;
                    break;
                }
            }
            fclose(mf);
        }
    }

    if (!mount_confirmed) {
        /* FUSE session did not materialise — the thread will clean up
         * the FUSE objects, but WE must immediately re-seal the
         * cipher_dir because the thread may have already unlocked it
         * or the atexit handler might run too late. */
        vault_log(LOG_ERROR,
                  "[FUSE_MOUNT] VALIDATION FAILED: mount_point='%s' not found in "
                  "/proc/mounts after 2 s. Reporting failure. "
                  "Re-sealing cipher_dir='%s' immediately.",
                  v->path, v->cipher_path);

        /* Signal the FUSE thread to stop by unmounting */
        {
            char *const args[] = { "fusermount", "-u", v->path, NULL };
            pid_t up = fork();
            if (up == 0) { execvp("fusermount", args); _exit(127); }
            if (up > 0) { int st; waitpid(up, &st, 0); }
        }
        pthread_join(td->tid, NULL); /* wait for thread to finish cleanup */

        /* Ensure cipher_dir is sealed regardless of thread outcome */
        if (chmod(v->cipher_path, 0000) != 0) {
            vault_log(LOG_ERROR,
                      "[PHYSICAL_LOCK] chmod 0000 FAILED on cipher_dir='%s': %s",
                      v->cipher_path, strerror(errno));
        } else {
            vault_log(LOG_AUDIT,
                      "[PHYSICAL_LOCK] Emergency re-seal applied on cipher_dir='%s'. "
                      "State: SEALED.", v->cipher_path);
        }
        v->is_mounted = false;
        return ERR_IO;
    }

    /* Thread is detached from join responsibility — atexit covers the exit path. */
    pthread_detach(td->tid);

    vault_log(LOG_AUDIT,
              "[FUSE_MOUNT] SUCCESS │ vault_id=%u │ name='%s' │ mount_point='%s' │ "
              "mount confirmed in /proc/mounts │ FUSE thread running.",
              v->id, v->name, v->path);
    return ERR_OK;
}

VaultErrorr vault_fuse_unmount(Vault *v)
{
    if (!v->is_mounted) {
        vault_log(LOG_WARN,
                  "[FUSE_UNMOUNT] Unmount requested for vault_id=%u name='%s' but it is NOT MOUNTED. No-op.",
                  v->id, v->name);
        return ERR_OK;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    vault_log(LOG_AUDIT,
              "[FUSE_UNMOUNT] UNMOUNT INITIATED │ vault_id=%u │ name='%s' │ "
              "mount_point='%s' │ ts=%ld.%09ld │ pid=%d",
              v->id, v->name, v->path, (long)ts.tv_sec, ts.tv_nsec, (int)getpid());

    /* PROTECTED-SCAN vaults cannot be unmounted via this path. */
    if (v->worm_flags & WORM_PROTECT_SCAN) {
        vault_log(LOG_AUDIT,
                  "[WORM] UNMOUNT DENIED │ vault_id=%u │ name='%s' │ reason=PROTECTED-SCAN active │ "
                  "flags=0x%08x │ pid=%d │ Action: use 'mount-export' to retrieve files.",
                  v->id, v->name, v->worm_flags, (int)getpid());
        return ERR_PERM_DENIED;
    }

    vault_log(LOG_INFO,
              "[FUSE_UNMOUNT] Sending fusermount -u signal to mount_point='%s' "
              "for vault_id=%u. Forking child process...",
              v->path, v->id);

    /* Use fork()+execvp() to avoid shell command injection. */
    pid_t pid = fork();
    if (pid < 0) {
        vault_log(LOG_ERROR,
                  "[FUSE_UNMOUNT] fork() FAILED for vault_id=%u: errno=%d (%s).",
                  v->id, errno, strerror(errno));
        return ERR_IO;
    }

    if (pid == 0) {
        char *const args[] = { "fusermount", "-u", v->path, NULL };
        execvp("fusermount", args);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0 ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        vault_log(LOG_ERROR,
                  "[FUSE_UNMOUNT] fusermount -u FAILED for mount_point='%s' vault_id=%u. "
                  "exit_status=%d. The physical lock may not have been restored.",
                  v->path, v->id, WEXITSTATUS(status));
        return ERR_IO;
    }

    /* Physical re-lock is applied inside vault_fuse_loop after fuse_loop_mt returns.
     * Log here for confirmation that the signal was accepted by the kernel. */
    vault_log(LOG_AUDIT,
              "[FUSE_UNMOUNT] SUCCESS │ vault_id=%u │ name='%s' │ "
              "fusermount -u accepted by kernel. FUSE thread will apply 000 re-seal on cipher_dir='%s'.",
              v->id, v->name, v->cipher_path);

    return ERR_OK;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  WORM flag management (called from FFI / Rust)
 * ───────────────────────────────────────────────────────────────────────── */

bool vault_worm_is_scan_locked(const Vault *v)
{
    return v && (v->worm_flags & WORM_PROTECT_SCAN);
}

VaultErrorr vault_worm_set_flags(Vault *v, uint32_t flags)
{
    if (!v) return ERR_INVALID_ARGS;
    /* SCAN mode is set-only through vault_worm_set_scan(); prevent direct
     * manipulation of the super-flag via this path. */
    if (flags & WORM_PROTECT_SCAN) return ERR_INVALID_ARGS;
    /* Once SCAN is active the individual flags are irrelevant (all are forced
     * on), but we still allow SET so metadata stays consistent. */
    v->worm_flags |= (flags & WORM_PROTECT_ALL);
    vault_log(LOG_AUDIT,
              "[WORM] vault '%s' flags SET 0x%x → current=0x%x",
              v->name, flags, v->worm_flags);
    return catalog_save();
}

VaultErrorr vault_worm_clear_flags(Vault *v, uint32_t flags)
{
    if (!v) return ERR_INVALID_ARGS;
    /* Cannot clear flags while SCAN super-lock is active */
    if (v->worm_flags & WORM_PROTECT_SCAN) {
        vault_log(LOG_AUDIT,
                  "[WORM] CLEAR DENIED for vault '%s': PROTECTED-SCAN active",
                  v->name);
        return ERR_PERM_DENIED;
    }
    /* Prevent clearing SCAN via this path */
    flags &= ~WORM_PROTECT_SCAN;
    v->worm_flags &= ~flags;
    vault_log(LOG_AUDIT,
              "[WORM] vault '%s' flags CLEARED 0x%x → current=0x%x",
              v->name, flags, v->worm_flags);
    return catalog_save();
}

VaultErrorr vault_worm_set_scan(Vault *v)
{
    if (!v) return ERR_INVALID_ARGS;
    v->worm_flags |= (WORM_PROTECT_SCAN | WORM_PROTECT_ALL);
    vault_log(LOG_AUDIT,
              "[WORM] vault '%s' PROTECTED-SCAN ENGAGED (flags=0x%x) — "
              "immutable; use mount-export to retrieve files.",
              v->name, v->worm_flags);
    return catalog_save();
}