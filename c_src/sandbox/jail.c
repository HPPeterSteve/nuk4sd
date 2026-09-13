/*
 * jail.c
 *
 * Nuk4sd — Hardened Sandbox — Jail structure (dirs, /dev, shell, GUI binds)
 * Extracted from vault_sandbox.c
 *
 * Calls vsb_limit_resources() (rlimits.c) during jail preparation.
 */

#include "sandbox.h"

#ifdef __linux__

/* ─────────────────────────────────────────────────────────────────────────
 *  jail_run_installer(): Fork + exec package manager to install busybox-static
 *
 *  Tries known package managers in order. Returns 0 if installer process
 *  exited with success, -1 otherwise.
 *  Does not guarantee package existence — caller must re-check path.
 * ───────────────────────────────────────────────────────────────────────── */

/* Classic Levenshtein algorithm */
int levenshtein(const char *s1, const char *s2) {
    int len1 = strlen(s1), len2 = strlen(s2);
    int matrix[len1 + 1][len2 + 1];

    for (int i = 0; i <= len1; i++) matrix[i][0] = i;
    for (int j = 0; j <= len2; j++) matrix[0][j] = j;

    for (int i = 1; i <= len1; i++) {
        for (int j = 1; j <= len2; j++) {
            int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            int min = matrix[i - 1][j] + 1;
            if (matrix[i][j - 1] + 1 < min) min = matrix[i][j - 1] + 1;
            if (matrix[i - 1][j - 1] + cost < min) min = matrix[i - 1][j - 1] + cost;
            matrix[i][j] = min;
        }
    }
    return matrix[len1][len2];
}

/* Searches for closest binary executable in PATH directories */
char *find_closest_binary(const char *target, int max_distance) {
    const char *paths[] = {        
        "/usr/bin/apt-get",
        "/usr/bin/dnf",
        "/usr/bin/pacman",
        "/sbin/apk",
        "/usr/bin/zypper",
        NULL
    };
    
    char *best_match_path = NULL;
    int min_dist = max_distance + 1;

    for (int p = 0; paths[p] != NULL; p++) {
        DIR *dir = opendir(paths[p]);
        if (!dir) continue;

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            /* Ignore . and .. */
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            int dist = levenshtein(target, entry->d_name);
            if (dist < min_dist) {
                char full_path[1024];
                snprintf(full_path, sizeof(full_path), "%s/%s", paths[p], entry->d_name);

                /* Check if it is a valid executable file */
                if (access(full_path, X_OK) == 0) {
                    min_dist = dist;
                    free(best_match_path);
                    best_match_path = strdup(full_path);
                }
            }
        }
        closedir(dir);
    }
    return best_match_path; /* Returns path or NULL if nothing is close */
}

static int jail_run_installer(void)
{
    /* Each entry: { argv[0..n], NULL } */
    const char *installers[][6] = {
        /* Debian / Ubuntu */
        { "apt-get", "install", "-y", "--no-install-recommends", "busybox-static", NULL },
        /* Fedora / RHEL 10+ */
        { "dnf",     "install", "-y", "busybox",                 NULL,             NULL },
        /* Arch */
        { "pacman",  "-Sy",     "--noconfirm", "busybox",        NULL,             NULL },
        /* Alpine */
        { "apk",     "add",     "--no-cache",  "busybox-static", NULL,             NULL },
        /* openSUSE */
        { "zypper",  "install", "-y",          "busybox-static", NULL,             NULL },
        { NULL }
    };

    /* Search paths for package manager binaries */
    const char *pm_paths[] = paths;
    free(paths);


    for (int i = 0; installers[i][0] != NULL; i++) {
        /* Check if pm exists before forking */
        struct stat st;
        if (stat(pm_paths[i], &st) != 0)
            continue;

        vault_log(LOG_INFO,
                  "[SANDBOX] Detected package manager '%s' — invoking to install busybox-static...",
                  pm_paths[i]);

        pid_t pid = fork();
        if (pid < 0) {
            vault_log(LOG_WARN, "[SANDBOX] fork for installer failed: %s", strerror(errno));
            continue;
        }

        if (pid == 0) {
            /* Child: redirect stdout/stderr to /dev/null if non-root
             * to avoid cluttering terminal with apt output */
            if (geteuid() != 0) {
                int devnull = open("/dev/null", O_WRONLY);
                if (devnull >= 0) {
                    dup2(devnull, STDOUT_FILENO);
                    dup2(devnull, STDERR_FILENO);
                    close(devnull);
                }
            }
            /* execvp searches PATH automatically */
            /* TODO: Implement Levenshtein algorithm to detect correct package manager */
            if (execvp(installers[i][0], (char *const *)installers[i]) < 0) {
                char *fallback = find_closest_binary(installers[i][0], 2);
            if (fallback) {
                execv(fallback, (char *const *)installers[i]);
                free(fallback);
                }
             _exit(127);
            }
        }

        int status;
        if (waitpid(pid, &status, 0) < 0) {
            vault_log(LOG_WARN, "[SANDBOX] waitpid installer: %s", strerror(errno));
            continue;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            vault_log(LOG_INFO, "[SANDBOX] Package manager exited successfully.");
            return 0;
        }

        vault_log(LOG_WARN,
                  "[SANDBOX] Installer '%s' exited with code %d — trying next...",
                  pm_paths[i], WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }

    return -1; /* no installer succeeded */
}

/* ─────────────────────────────────────────────────────────────────────────
 *  jail_install_shell(): Ensures /bin/sh exists inside the jail
 *
 *  Attempt order:
 *    1. Copy static busybox already present on host (fastest)
 *    2. Call package manager to install busybox-static and retry
 *    3. Give up and log warning — sandbox will launch but without shell
 *
 *  busybox MUST be static: after pivot_root, host /lib does not exist.
 * ───────────────────────────────────────────────────────────────────────── */
static int jail_install_shell(const char *vault_path)
{
    static const char *candidates[] = {
        "/usr/bin/busybox-static",
        "/usr/bin/busybox",
        "/bin/busybox",
        "/usr/local/bin/busybox",
        NULL
    };

    char dst[VAULT_PATH_MAX];
    snprintf(dst, sizeof(dst), "%s/bin/sh", vault_path);

    /* ── Already exists and non-empty? Do not touch. ─────────────────── */
    {
        struct stat st;
        if (stat(dst, &st) == 0 && st.st_size > 0) {
            vault_log(LOG_INFO, "[SANDBOX] Shell already present at jail/bin/sh (%ld bytes) — skipping install.",
                      (long)st.st_size);
            return 0;
        }
    }

    /* ── Attempt 1: copy from host ──────────────────────────────────── */
    for (int i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) != 0)
            continue;

        /* Open source */
        int src = open(candidates[i], O_RDONLY | O_CLOEXEC);
        if (src < 0) continue;

        /* Open destination */
        int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
        if (dst_fd < 0) { close(src); continue; }

        /* Copy in 64 KB blocks */
        char buf[65536];
        ssize_t n;
        int ok = 1;
        while ((n = read(src, buf, sizeof(buf))) > 0) {
            if (write(dst_fd, buf, (size_t)n) != n) { ok = 0; break; }
        }
        close(src);
        close(dst_fd);

        if (!ok) {
            unlink(dst);
            vault_log(LOG_WARN, "[SANDBOX] Copy from '%s' failed mid-transfer — removing partial file.",
                      candidates[i]);
            continue;
        }

        /* Check if truly static to warn user */
        int is_static = 0;
        {
            /* Quick heuristic: dynamic ELF has PT_INTERP; open and search
             * for string "/lib" in first 4 KB of file */
            int probe = open(candidates[i], O_RDONLY | O_CLOEXEC);
            if (probe >= 0) {
                char head[4096];
                ssize_t r = read(probe, head, sizeof(head));
                close(probe);
                /* If no interpreter path found, it is static */
                is_static = (r > 0 && memmem(head, (size_t)r, "/lib", 4) == NULL);
            }
        }

        if (!is_static) {
            unlink(dst);
            vault_log(LOG_WARN, "[SANDBOX] Shell candidate '%s' is dynamically linked — skipping for static shell", candidates[i]);
            continue;
        }

        vault_log(LOG_INFO,
                  "[SANDBOX] Shell installed: '%s' → jail/bin/sh (%ld bytes, %s)",
                  candidates[i], (long)st.st_size,
                  is_static ? "static" : "dynamic — may fail");
        return 0;
    }

    vault_log(LOG_WARN, "[SANDBOX] No busybox found on host — attempting auto-install via package manager.");

    if (geteuid() != 0) {
        vault_log(LOG_WARN, "[SANDBOX] Auto-install requires root privileges (euid=%d).", geteuid());
    }

    int installed = jail_run_installer();

    if (installed == 0) {
        /* Retry copy after installation */
        for (int i = 0; candidates[i]; i++) {
            struct stat st;
            if (stat(candidates[i], &st) != 0)
                continue;

            int src = open(candidates[i], O_RDONLY | O_CLOEXEC);
            if (src < 0) continue;

            int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
            if (dst_fd < 0) { close(src); continue; }

            char buf[65536];
            ssize_t n;
            int ok = 1;
            while ((n = read(src, buf, sizeof(buf))) > 0) {
                if (write(dst_fd, buf, (size_t)n) != n) { ok = 0; break; }
            }
            close(src);
            close(dst_fd);

            if (!ok) { unlink(dst); continue; }

            vault_log(LOG_AUDIT,
                      "[SANDBOX] Shell auto-installed and deployed: '%s' → jail/bin/sh (%ld bytes)",
                      candidates[i], (long)st.st_size);
            return 0;
        }
    }

    vault_log(LOG_WARN, "[SANDBOX] Shell binary not found for jail.");
    errno = ENOENT;
    return -1;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  vault_mkdir_p — creates all intermediate path components
 *  (mirrors cli_mkdir_p of vault_cli.c — necessary because a newly created
 *  vault has NO default directory such as /etc inside it. A single-level
 *  mkdir() fails with ENOENT if parent does not exist yet).
 * ───────────────────────────────────────────────────────────────────────── */
static int vault_mkdir_p(const char *path, mode_t mode) {
    char tmp[VAULT_PATH_MAX];
    size_t len = (size_t)snprintf(tmp, sizeof(tmp), "%s", path);
    if (len == 0 || len >= sizeof(tmp)) { errno = ENAMETOOLONG; return -1; }

    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  vault_prepare_jail(): Prepare jail structure inside vault path
 * ───────────────────────────────────────────────────────────────────────── */
static void vault_prepare_jail(const char *vault_path, bool gui_mode)
{
    char marker[VAULT_PATH_MAX];
    snprintf(marker, sizeof(marker), "%s/%s", vault_path, SANDBOX_JAIL_MARKER);

    struct stat st;

    /* Always ensure critical dirs and device stubs exist, even if marker present */
    char dev_dir[VAULT_PATH_MAX];
    snprintf(dev_dir, sizeof(dev_dir), "%s/dev", vault_path);
    if (mkdir(dev_dir, 0755) != 0 && errno != EEXIST)
        vault_log(LOG_WARN, "[SANDBOX] mkdir dev: %s", strerror(errno));

    {
        char p_null[VAULT_PATH_MAX], p_zero[VAULT_PATH_MAX], p_tty[VAULT_PATH_MAX];
        snprintf(p_null, sizeof(p_null), "%s/dev/null", vault_path);
        snprintf(p_zero, sizeof(p_zero), "%s/dev/zero", vault_path);
        snprintf(p_tty,  sizeof(p_tty),  "%s/dev/tty",  vault_path);
        struct stat ds;
        if (stat(p_null, &ds) != 0) {
            int fd = open(p_null, O_CREAT | O_WRONLY, 0666);
            if (fd >= 0) close(fd);
        }
        if (stat(p_zero, &ds) != 0) {
            int fd = open(p_zero, O_CREAT | O_WRONLY, 0666);
            if (fd >= 0) close(fd);
        }
        if (stat(p_tty, &ds) != 0) {
            int fd = open(p_tty, O_CREAT | O_WRONLY, 0666);
            if (fd >= 0) close(fd);
        }
    }

    /* Same "always ensure" block, but for real device nodes (mknod).
     * Must be BEFORE "if (stat(marker...)) return;" below — otherwise
     * vaults that ran previously (marker present) never reach this code. */
    if (geteuid() == 0)
    {
        char dev_null[VAULT_PATH_MAX], dev_zero[VAULT_PATH_MAX], dev_tty[VAULT_PATH_MAX];
        snprintf(dev_null, sizeof(dev_null), "%s/dev/null", vault_path);
        snprintf(dev_zero, sizeof(dev_zero), "%s/dev/zero", vault_path);
        snprintf(dev_tty,  sizeof(dev_tty),  "%s/dev/tty",  vault_path);

        /* Block above creates these three paths as EMPTY REGULAR FILES
         * (placeholder meant for bind-mount in geteuid()!=0 path).
         * Explicitly check S_ISCHR and remove placeholder before mknod(). */
        struct stat dst;
        if (stat(dev_null, &dst) != 0 || !S_ISCHR(dst.st_mode)) {
            unlink(dev_null);
            mknod(dev_null, S_IFCHR | 0666, makedev(1, 3));
        }
        if (stat(dev_zero, &dst) != 0 || !S_ISCHR(dst.st_mode)) {
            unlink(dev_zero);
            mknod(dev_zero, S_IFCHR | 0666, makedev(1, 5));
        }
        /* /dev/tty (major 5, minor 0) */
        if (stat(dev_tty, &dst) != 0 || !S_ISCHR(dst.st_mode)) {
            unlink(dev_tty);
            mknod(dev_tty, S_IFCHR | 0666, makedev(5, 0));
        }
    }

    if (stat(marker, &st) == 0)
        return;

    vault_log(LOG_INFO, "[SANDBOX] Preparing jail at '%s'", vault_path);

    char dir[VAULT_PATH_MAX];
    const char *subdirs_cli[] = {"proc", "tmp", "dev", "bin", "lib", "lib64", NULL};
    const char *subdirs_gui[] = {"proc", "tmp", "dev", "bin", "lib", "lib64", "usr", "etc", "etc/fonts", "etc/alternatives", "run", "run/user", "sys", "sys/dev", "sys/dev/char", NULL};
    const char **subdirs = gui_mode ? subdirs_gui : subdirs_cli;

    for (int i = 0; subdirs[i]; i++)
    {
        snprintf(dir, sizeof(dir), "%s/%s", vault_path, subdirs[i]);
        if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
            /* Create parent if needed for nested dirs like etc/fonts */
            char parent[VAULT_PATH_MAX];
            snprintf(parent, sizeof(parent), "%s", dir);
            char *last_dir = strrchr(parent, '/');
            if (last_dir) { 
                /* remove last directory to create parent directory */
                *last_dir = '\0'; 
                mkdir(parent, 0755); 
            }
            if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
                vault_log(LOG_WARN, "[SANDBOX] mkdir %s: %s", dir, strerror(errno));
            }
        }
    }

    /* ── Ensures /bin/sh inside jail (auto-installs if needed) ── */
    jail_install_shell(vault_path);

    int fd = open(marker, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0400);
    if (fd >= 0)
    {
        write(fd, "Nuk4sd Jail v2\n", 18);
        close(fd);
    }
    else
    {
        if (errno == ELOOP)
        {
            vault_log(LOG_ALERT, "[SANDBOX] Detected symlink on jail marker '%s' (ELOOP)", marker);
        }
        else
        {
            vault_log(LOG_WARN, "[SANDBOX] open(marker '%s'): %s", marker, strerror(errno));
        }
    }

    vault_log(LOG_AUDIT, "[SANDBOX] Jail prepared at '%s'", vault_path);
}

/* ─────────────────────────────────────────────────────────────────────────
 *  vault_bind_gui_deps(): bind-mounts /usr, /lib, /lib64, fontconfig, DRI,
 *  X11 socket etc. (read-only) from HOST into the jail.
 * ───────────────────────────────────────────────────────────────────────── */
void vsb_bind_gui_deps(const char *jail_path)
{
    printf("[SANDBOX] [Layer 2.5] GUI Mode: Bind mounting host GUI dependencies...\n");
    const char *gui_binds[] = {
        "/usr", "/lib", "/lib64", "/etc/fonts", "/etc/alternatives",
        "/sys/dev/char", "/dev/dri", "/dev/null", "/dev/zero", "/dev/urandom",
        "/dev/random", "/dev/shm", "/dev/pts", "/tmp/.X11-unix",
        "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/ssl/certs", "/etc/machine-id", NULL
    };
    for (int i = 0; gui_binds[i]; i++) {
        char dst[VAULT_PATH_MAX];
        snprintf(dst, sizeof(dst), "%s%s", jail_path, gui_binds[i]);

        struct stat st;
        if (stat(gui_binds[i], &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            if (vault_mkdir_p(dst, 0755) != 0) {
                vault_log(LOG_WARN, "[SANDBOX] gui-bind mkdir_p '%s': %s", dst, strerror(errno));
                continue;
            }
        } else {
            int fd = open(dst, O_CREAT | O_WRONLY, 0666);
            if (fd >= 0) close(fd);
        }

        if (mount(gui_binds[i], dst, NULL, MS_BIND | MS_REC, NULL) == 0) {
            // Keep /dev/ nodes read-write (e.g. /dev/null, /dev/shm, /dev/dri, /dev/pts)
            if (strncmp(gui_binds[i], "/dev/", 5) != 0) {
                mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
            }
        } else {
            vault_log(LOG_WARN, "[SANDBOX] gui-bind mount '%s': %s", gui_binds[i], strerror(errno));
        }
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  vault_sandbox_open() — Nuk4sd Hardened Sandbox v2
 * ───────────────────────────────────────────────────────────────────────── */
VaultErrorr vault_sandbox_open(Vault *v, const char *password, bool gui_mode, const char *app_cmd)
{
    if (!v)
        return ERR_INVALID_ARGS;
        
    uid_t host_uid = getuid();
    gid_t host_gid = getgid();

    /* Authentication */
    if (v->type == VAULT_TYPE_PROTECTED)
    {
        if (!password || !*password)
            return ERR_PASS_REQUIRED;
        VaultErrorr err = auth_verify_password(v, password);
        if (err != ERR_OK)
            return err;
    }

    if (v->path[0] == '\0') {
        vault_log(LOG_ERROR, "[SANDBOX] vault path empty");
        return ERR_PATH_INVALID;
    }

    struct timespec _ts_sb;
    clock_gettime(CLOCK_REALTIME, &_ts_sb);
    vault_log(LOG_AUDIT,
              "[SANDBOX] INITIATE \u2502 vault_id=%u \u2502 name='%s' \u2502 "
              "type=%s \u2502 pid=%d \u2502 uid=%d \u2502 ts=%ld.%09ld",
              v->id, v->name,
              v->type == VAULT_TYPE_PROTECTED ? "PROTECTED" : "NORMAL",
              (int)getpid(), (int)getuid(),
              (long)_ts_sb.tv_sec, 
              _ts_sb.tv_nsec
            );


    /* Temporarily unlock cipher_path so the jail can access vault data */
    vault_log(LOG_AUDIT,
              "[PHYSICAL_LOCK] Temporary bypass granted: chmod 000 \u2192 700 on cipher_dir='%s' "
              "to allow Sandbox jail access. Session-scoped unlock.",
              "check status: ls -ld %s",
              v->cipher_path);
    chmod(v->cipher_path, 0700);

    vault_prepare_jail(v->path, gui_mode);

    int sync_pipe[2];   /* parent -> child: "mapping already written" */
    int ready_pipe[2];  /* child -> parent: "unshare(CLONE_NEWUSER) already called" */
    if (pipe(sync_pipe) != 0 || pipe(ready_pipe) != 0)
    {
        vault_log(LOG_ERROR, "[SANDBOX] pipe failed: %s", strerror(errno));
        return ERR_SYSTEM;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        vault_log(LOG_ERROR, "[SANDBOX] fork failed: %s", strerror(errno));
        return ERR_SYSTEM;
    }

    /* PARENT */
    if (pid > 0)
    {
        vault_auth_pid_add_ffi(pid);

        close(ready_pipe[1]);
        close(sync_pipe[0]);

        /* Wait for child to signal unshare(CLONE_NEWUSER) completed */
        {
            char c;
            ssize_t r = read(ready_pipe[0], &c, 1);
            if (r != 1)
                vault_log(LOG_ERROR, "[SANDBOX] ready_pipe read failed: %s", strerror(errno));
        }
        close(ready_pipe[0]);

        if (vsb_write_uid_gid_map(pid, host_uid, host_gid) != 0) {
            vault_log(LOG_ERROR, "[SANDBOX] uid_map/gid_map failed — aborting sandbox.");
            kill(pid, SIGKILL);
            close(sync_pipe[1]);
            int status;
            waitpid(pid, &status, 0);
            vault_auth_pid_remove_ffi(pid);
            return ERR_PERM_DENIED;
        }
        close(sync_pipe[1]);

        int status;
        waitpid(pid, &status, 0);

        vault_auth_pid_remove_ffi(pid);

        VaultErrorr session_err = ERR_OK;
        if (WIFSIGNALED(status))
        {
            vault_log(LOG_ALERT,
                      "[SANDBOX] Session of vault '%s' (id=%u) TERMINATED BY SIGNAL %d "
                      "(possible seccomp/namespace violation). exit_code=N/A.",
                      v->name, v->id, WTERMSIG(status));
            session_err = ERR_SYSTEM;
        }
        else
        {
            int exit_code = WEXITSTATUS(status);
            vault_log(LOG_AUDIT,
                      "[SANDBOX] Session of vault '%s' (id=%u) ended cleanly. "
                      "exit_code=%d. Namespace teardown complete.",
                      v->name, v->id, exit_code);
                      
            if (exit_code == -ERR_SYSTEM_UNSHARE_FAILED) session_err = ERR_SYSTEM_UNSHARE_FAILED;
            else if (exit_code == -ERR_SYSTEM_CLONE_FAILED) session_err = ERR_SYSTEM_CLONE_FAILED;
            else if (exit_code == -ERR_SYSTEM_PIVOT_ROOT_FAILED) session_err = ERR_SYSTEM_PIVOT_ROOT_FAILED;
            else if (exit_code == -ERR_SYSTEM_MOUNT_FAILED) session_err = ERR_SYSTEM_MOUNT_FAILED;
        }

        /* Re-seal cipher_path immediately after sandbox session ends */

        if (chmod(v->cipher_path, 0000) != 0) {
            vault_log(LOG_WARN,
                      "[PHYSICAL_LOCK] WARNING: chmod 0000 FAILED on cipher_dir='%s' post-sandbox: "
                      "errno=%d (%s). Physical isolation NOT restored.",
                      v->cipher_path, errno, strerror(errno));
        } else {
            struct timespec _ts_seal;
            clock_gettime(CLOCK_REALTIME, &_ts_seal);
            vault_log(LOG_AUDIT,
                      "[PHYSICAL_LOCK] Sandbox session terminated. Restoring permanent 000 immutable lock: "
                      "cipher_dir='%s' \u2502 vault_id=%u \u2502 ts=%ld.%09ld \u2502 State: SEALED.",
                      v->cipher_path, 
                      v->id,
                      (long)_ts_seal.tv_sec, 
                      _ts_seal.tv_nsec
                    );
        }

        return session_err;
    }

    /* CHILD — SANDBOX */

    /* Rename process for task managers */
    prctl(PR_SET_NAME, "Nuk4sd-Jail", 0, 0, 0);

    close(sync_pipe[1]);
    close(ready_pipe[0]);

    /* [Layer 1] User Namespace */
    printf("[SANDBOX] [Layer 1/5] Invoking unshare(CLONE_NEWUSER) syscall to dissociate user/group database from host...\n");
    if (unshare(CLONE_NEWUSER) != 0)
    {
        int err = errno;
        fprintf(stderr, "[KERNEL ERROR] Function: %s | Syscall: unshare(CLONE_NEWUSER) | Error: %s (%d)\n", __func__, strerror(err), err);
        _exit(-ERR_SYSTEM_UNSHARE_FAILED);
    }
    printf("[SANDBOX] [Layer 1/5] User Namespace unshared. Signaling host to assign UID/GID mappings...\n");

    /* Signal parent NOW that user namespace exists */
    {
        char c = 'r';
        if (write(ready_pipe[1], &c, 1) != 1)
            fprintf(stderr, "[SANDBOX][WARN] ready_pipe write failed: %s\n", strerror(errno));
        close(ready_pipe[1]);
    }

    /* Wait for parent to write uid_map/gid_map */
    {
        char c;
        read(sync_pipe[0], &c, 1);
        close(sync_pipe[0]);
    }
    printf("[SANDBOX] [Layer 1/5] UID/GID mapping initialized (identity): ns-%d -> host-%d "
           "(your real UID on both sides — no UID 0, GUI apps will not reject).\n",
           (int)host_uid, (int)host_uid);

    /* [Layer 2] Mount + PID Namespace */
    printf("[SANDBOX] [Layer 2/5] Invoking unshare(CLONE_NEWNS | CLONE_NEWPID) to isolate mount points and process trees...\n");
    if (unshare(CLONE_NEWNS | CLONE_NEWPID) != 0)
    {
        int err = errno;
        fprintf(stderr, "[KERNEL ERROR] Function: %s | Syscall: unshare(CLONE_NEWNS | CLONE_NEWPID) | Error: %s (%d)\n", __func__, strerror(err), err);
        _exit(-ERR_SYSTEM_UNSHARE_FAILED);
    }

    printf("[SANDBOX] [Layer 2/5] Namespaces created. Forking inside new PID namespace to gain PID 1...\n");
    pid_t ns_pid = fork();
    if (ns_pid < 0)
    {
        int err = errno;
        fprintf(stderr, "[KERNEL ERROR] Function: %s | Syscall: fork() | Error: %s (%d)\n", __func__, strerror(err), err);
        _exit(-ERR_SYSTEM_CLONE_FAILED);
    }
    if (ns_pid > 0)
    {
        int st;
        waitpid(ns_pid, &st, 0);
        if (WIFSIGNALED(st)) {
            int sig = WTERMSIG(st);
            fprintf(stderr,
                "[SANDBOX][FATAL] child process (PID 1 of namespace) killed by signal %d (%s)"
                " — possible seccomp/allowlist violation if sig=31 (SIGSYS). "
                "Check 'dmesg' for 'audit: type=1326 ... comm=\"<process>\" syscall=N'.\n",
                sig, strsignal(sig));
            _exit(128 + sig);
        }
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
    }

    printf("[SANDBOX] [Layer 2/5] Fork successful. Subprocess running as PID 1 inside isolated PID namespace.\n");

    // Bind-mount host /dev/null and /dev/zero onto jail's /dev/null and /dev/zero
    if (geteuid() != 0)
    {
        char jail_null[VAULT_PATH_MAX], jail_zero[VAULT_PATH_MAX], jail_tty[VAULT_PATH_MAX];
        snprintf(jail_null, sizeof(jail_null), "%s/dev/null", v->path);
        snprintf(jail_zero, sizeof(jail_zero), "%s/dev/zero", v->path);
        snprintf(jail_tty,  sizeof(jail_tty),  "%s/dev/tty",  v->path);

        if (mount("/dev/null", jail_null, NULL, MS_BIND, NULL) != 0)
            perror("[SANDBOX] mount bind /dev/null");
        if (mount("/dev/zero", jail_zero, NULL, MS_BIND, NULL) != 0)
            perror("[SANDBOX] mount bind /dev/zero");
        /* /dev/tty is needed for busybox sh interactive mode */
        if (mount("/dev/tty", jail_tty, NULL, MS_BIND, NULL) != 0)
            perror("[SANDBOX] mount bind /dev/tty (non-fatal)");
    }

    /* ── GUI Mode: Bind mount host libraries and Wayland/X11 sockets ── */
    if (gui_mode) {
        vsb_bind_gui_deps(v->path);

        /* Wayland and PulseAudio Sockets */
        char wayland_sock[256];
        snprintf(wayland_sock, sizeof(wayland_sock), "/run/user/%d", host_uid);
        char dst_wayland[VAULT_PATH_MAX];
        snprintf(dst_wayland, sizeof(dst_wayland), "%s%s", v->path, wayland_sock);
        vault_mkdir_p(dst_wayland, 0700);
        
        if (mount(wayland_sock, dst_wayland, NULL, MS_BIND | MS_REC, NULL) == 0) {
            mount(NULL, dst_wayland, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        }

        /* Set GUI Environment Variables */
        const char *h_wayland = getenv("WAYLAND_DISPLAY");
        setenv("WAYLAND_DISPLAY", (h_wayland && *h_wayland) ? h_wayland : "wayland-0", 1);

        const char *h_disp = getenv("DISPLAY");
        setenv("DISPLAY", (h_disp && *h_disp) ? h_disp : ":0", 1);

        char xdg_run[256];
        snprintf(xdg_run, sizeof(xdg_run), "/run/user/%d", host_uid);
        setenv("XDG_RUNTIME_DIR", xdg_run, 1);
        setenv("QT_QPA_PLATFORM", "wayland;xcb", 1);
        setenv("GDK_BACKEND", "wayland,x11", 1);
    }

    /* [Layer 3] Pivot Root */
    if (vsb_pivot_root(v->path, true) != 0)
    {
        int err = errno;
        fprintf(stderr, "[KERNEL ERROR] Function: %s | Syscall: pivot_root('%s') | Error: %s (%d)\n", __func__, v->path, strerror(err), err);
        _exit(-ERR_SYSTEM_PIVOT_ROOT_FAILED);
    }
    /* Synthetic /dev — isolates from host immediately post-pivot */
    vsb_mount_dev();
    vsb_prepare_mounts();

    /* [Layer 4] Drop capabilities */
    if (vsb_drop_caps() != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] drop capabilities failed: %s (Kernel code %d)\n", strerror(err), err);
        _exit(1);
    }
    vsb_limit_resources(gui_mode);

    /* [Layer 5] Seccomp-BPF — LAST STEP */
    if (vsb_apply_seccomp() != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] seccomp policy activation failed: %s (Kernel code %d)\n", strerror(err), err);
        _exit(1);
    }


    if (gui_mode && app_cmd && app_cmd[0] != '\0') {
        vault_log(LOG_INFO, "[SANDBOX] Launching GUI App: %s", app_cmd);
        
        /* Parse simple args */
        execl("/bin/sh", "sh", "-c", app_cmd, NULL);
        
        int err = errno;
        vault_log(LOG_ERROR, "[SANDBOX] execl(/bin/sh -c %s) failed: %s (%d)", app_cmd, strerror(err), err);
        _exit(127);
    } else {
        vault_log(LOG_INFO, "[SANDBOX] Launching shell via execl(\"/bin/sh\")");
        execl("/bin/sh", "sh", NULL);

        int err = errno;
        vault_log(LOG_ERROR, "[SANDBOX] execl(/bin/sh) failed: %s (%d)", strerror(err), err);
        _exit(127);
    }
}


/* ─────────────────────────────────────────────────────────────────────────
 * vault_isolate_path_readonly — bind-mount + remount readonly
 *
 * Isolates an arbitrary path making it read-only at kernel level via
 * bind mount.
 *
 * Requires CAP_SYS_ADMIN. Returns 0 on success, -1 on failure.
 * ───────────────────────────────────────────────────────────────────────── */
int vault_isolate_path_readonly(const char *path)
{
    if (path == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    if (mount(path, path, NULL, MS_BIND, NULL) != 0)
    {
        return -1;
    }

    if (mount(path, path, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) != 0)
    {
        int saved_errno = errno;
        umount(path); /* undo bind if remount readonly fails */
        errno = saved_errno;
        return -1;
    }

    return 0;
}

void vsb_prepare_jail(const char *path, bool gui) { vault_prepare_jail(path, gui); }

#endif /* __linux__ */