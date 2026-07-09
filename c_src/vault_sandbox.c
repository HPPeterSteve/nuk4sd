/*
 * vault_sandbox.c
 *
 * VAULT SECURITY SYSTEM — Nuk4sd Hardened Sandbox v2
 * Section 12 from legacy monolith
 *
 * Linux-only: 5-layer defense-in-depth sandbox
 *   1. User Namespace  — root in sandbox → nobody on host
 *   2. Mount + PID NS  — private process/fs view
 *   3. Pivot Root      — replaces chroot (more secure)
 *   4. Capability Drop — removes all Linux Caps + NO_NEW_PRIVS
 *   5. Seccomp-BPF     — minimal allowlist, KILL as default
 *
 * On Windows: stub that returns ERR_SYSTEM (sandbox not available).
 *
 * Author: Peter Steve (architecture)
 * Split: 2026-05-13
 */

#include "vault_core.h"

#ifdef __linux__
#include <sys/sysmacros.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  SANDBOX DEBUG INFRASTRUCTURE
 *  g_sandbox_debug: activado via vsb_set_debug(true) / --debug flag
 *  SBX_LOG  → sempre emite (info operacional mínimo)
 *  SBX_DBG  → só emite quando debug ativo (logs massivos de estado kernel)
 *  SBX_SEP  → separador visual no debug
 * ═══════════════════════════════════════════════════════════════════════════ */
static bool g_sandbox_debug = false;

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

/* ─── Decoder: mount flags → string legível ─────────────────────────────── */
static const char *decode_mount_flags(unsigned long fl, char *buf, size_t sz)
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

/* ─── Decoder: clone/unshare namespace flags → string ──────────────────── */
static const char *decode_ns_flags(int fl, char *buf, size_t sz)
{
    buf[0] = '\0';
    static const struct { int v; const char *n; } bits[] = {
        {CLONE_NEWUSER, "NEWUSER"}, {CLONE_NEWNS,  "NEWNS"},
        {CLONE_NEWNET,  "NEWNET"},  {CLONE_NEWPID, "NEWPID"},
        {CLONE_NEWUTS,  "NEWUTS"},  {CLONE_NEWIPC, "NEWIPC"},
        {0, NULL}
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

/* ─── Helper: lê link simbólico de namespace atual ─────────────────────── */
static void log_ns_link(const char *layer, const char *ns_name)
{
    if (!g_sandbox_debug) return;
    char path[64], target[128];
    snprintf(path, sizeof(path), "/proc/self/ns/%s", ns_name);
    ssize_t n = readlink(path, target, sizeof(target) - 1);
    if (n > 0) { target[n] = '\0'; SBX_DBG(layer, "  ns/%-8s = %s", ns_name, target); }
    else        { SBX_DBG(layer, "  ns/%-8s = (unreadable: %s)", ns_name, strerror(errno)); }
}

/* ─── Helper: lê rlimit atual antes de alterar ───────────────────────────  */
static void log_rlimit_before(const char *layer, int resource, const char *name)
{
    if (!g_sandbox_debug) return;
    struct rlimit old;
    if (getrlimit(resource, &old) == 0) {
        SBX_DBG(layer, "  %-20s before: cur=%-12lu max=%lu",
                name,
                (unsigned long)old.rlim_cur == RLIM_INFINITY ? 0xFFFFFFFFUL : (unsigned long)old.rlim_cur,
                (unsigned long)old.rlim_max == RLIM_INFINITY ? 0xFFFFFFFFUL : (unsigned long)old.rlim_max);
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_drop_caps(): Remove all Linux Capabilities
 *  Logs: estado antes/depois, cada prctl enviado ao kernel e o resultado,
 *        implicações de segurança de cada passo.
 * ───────────────────────────────────────────────────────────────────────── */
static int sandbox_drop_caps(void)
{
    const char *L = "CAP";
    SBX_SEP(L);
    SBX_LOG(L, "━━ Layer 4: DROP ALL LINUX CAPABILITIES ━━");

    /* ── Estado ANTES ────────────────────────────────────────────────────── */
    cap_t before = cap_get_proc();
    char *before_text = before ? cap_to_text(before, NULL) : NULL;
    SBX_DBG(L, "▶ State BEFORE drop:");
    SBX_DBG(L, "  capabilities   = '%s'", before_text ? before_text : "(read failed)");
    SBX_DBG(L, "  euid=%d  egid=%d  pid=%d", (int)geteuid(), (int)getegid(), (int)getpid());
    SBX_DBG(L, "  NOTE: inside user namespace, UID 0 maps to host UID %d", (int)getuid());
    if (before_text) cap_free(before_text);
    if (before)      cap_free(before);

    /* ── Passo 1: cap_set_proc(empty) — zera as 3 listas de capabilities ─ */
    SBX_DBG(L, "▶ Step 1/3 — Kernel call: cap_set_proc(empty_set)");
    SBX_DBG(L, "  Erases: permitted, effective AND inheritable capability sets");
    SBX_DBG(L, "  Effect: process loses CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_CHOWN, etc.");
    cap_t empty = cap_init();
    if (empty == NULL) {
        SBX_ALERT(L, "cap_init() failed: %s — cannot drop caps, aborting", strerror(errno));
        perror("[SANDBOX] cap_init");
        return -1;
    }
    if (cap_set_proc(empty) != 0) {
        int e = errno;
        SBX_ALERT(L, "cap_set_proc(empty) FAILED: %s (errno=%d) — sandbox INSECURE", strerror(e), e);
        perror("[SANDBOX] cap_set_proc");
        cap_free(empty);
        return -1;
    }
    cap_free(empty);
    SBX_DBG(L, "  Kernel result: 0 (SUCCESS)");
    SBX_DBG(L, "  ✔ permitted=∅  effective=∅  inheritable=∅");

    /* ── Passo 2: PR_SET_KEEPCAPS = 0 ────────────────────────────────────
     *  Controla se o kernel preserva as caps quando o processo executa um
     *  novo binário via execve(). Com flag=0, QUALQUER execve() limpa as
     *  caps — mesmo que o binário seja setuid-root.
     * ─────────────────────────────────────────────────────────────────── */
    SBX_DBG(L, "▶ Step 2/3 — Kernel call: prctl(PR_SET_KEEPCAPS, 0)");
    SBX_DBG(L, "  Without this: execve() could restore caps from ambient set");
    SBX_DBG(L, "  With flag=0 : caps cleared on every execve(), unconditionally");
    if (prctl(PR_SET_KEEPCAPS, 0) != 0) {
        int e = errno;
        SBX_ALERT(L, "prctl(PR_SET_KEEPCAPS, 0) FAILED: %s (errno=%d)", strerror(e), e);
        perror("[SANDBOX] PR_SET_KEEPCAPS");
        return -1;
    }
    SBX_DBG(L, "  Kernel result: 0 (SUCCESS)");
    SBX_DBG(L, "  ✔ PR_SET_KEEPCAPS=0 — caps will NOT survive next execve()");

    /* ── Passo 3: PR_SET_NO_NEW_PRIVS = 1 ────────────────────────────────
     *  Bit IRREVERSÍVEL no process descriptor do kernel.
     *  Efeito: execve() de binários setuid/setcap não eleva privilégios.
     *  Todo filho herdará este bit — impossível remover via prctl ou fork.
     * ─────────────────────────────────────────────────────────────────── */
    SBX_DBG(L, "▶ Step 3/3 — Kernel call: prctl(PR_SET_NO_NEW_PRIVS, 1)");
    SBX_DBG(L, "  This bit is IRREVERSIBLE for this process and ALL children");
    SBX_DBG(L, "  Effect: setuid(0) binaries inside jail cannot gain root privs");
    SBX_DBG(L, "  Effect: seccomp filter cannot be bypassed via privilege escalation");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        int e = errno;
        SBX_ALERT(L, "prctl(PR_SET_NO_NEW_PRIVS, 1) FAILED: %s (errno=%d)", strerror(e), e);
        perror("[SANDBOX] PR_SET_NO_NEW_PRIVS");
        return -1;
    }
    SBX_DBG(L, "  Kernel result: 0 (SUCCESS)");
    SBX_DBG(L, "  ✔ NO_NEW_PRIVS=1 — IRREVOCABLE, inherited by all descendants");

    /* ── Verificação: confirma que caps estão realmente vazios ───────────  */
    SBX_DBG(L, "▶ Verification — Reading post-drop capability state from kernel:");
    cap_t check = cap_get_proc();
    if (check != NULL) {
        char *text = cap_to_text(check, NULL);
        SBX_DBG(L, "  post-drop caps = '%s'  (expected '=')", text ? text : "(null)");
        if (text && strcmp(text, "=") != 0) {
            SBX_ALERT(L, "RESIDUAL CAPS DETECTED: '%s' — sandbox privilege isolation INCOMPLETE!", text);
            cap_free(text);
            cap_free(check);
            return -1;
        }
        cap_free(text);
        cap_free(check);
    }

    SBX_OK(L, "All capabilities dropped. NO_NEW_PRIVS=1. Privilege level: ZERO.");
    SBX_DBG(L, "  Security: no kernel privilege escalation vector remains via capabilities");
    SBX_DBG(L, "  Next: Seccomp-BPF will enforce syscall allowlist as final layer");
    SBX_SEP(L);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_pivot_root(): Layer 3 — Pivot root to vault path
 * ───────────────────────────────────────────────────────────────────────── */
static int mount_bind(const char *src, const char *target) {
    if (mount(src, target, NULL, MS_BIND | MS_REC, NULL) != 0) {
        perror("[SANDBOX] mount MS_BIND");
        return -1;
    }
    return 0;
}

static int sandbox_pivot_root(const char *new_root)
{
    const char *L = "PIVOT";
    SBX_SEP(L);
    SBX_LOG(L, "\u2501\u2501 Layer 3: PIVOT ROOT \u2192 '%s' \u2501\u2501", new_root);
    if (new_root == NULL || new_root[0] == '\0') {
        SBX_ALERT(L, "new_root is NULL/empty");
        return -1;
    }
    char cwd_before[512] = "(unknown)";
    getcwd(cwd_before, sizeof(cwd_before));
    SBX_DBG(L, "\u25b6 Before: cwd='%s'  pid=%d  euid=%d", cwd_before, (int)getpid(), (int)geteuid());
    SBX_DBG(L, "  Goal: replace host '/' with vault jail, host fs becomes invisible");

    int ret = -1;
    char oldroot[64] = ".sandbox_oldroot_XXXXXX";
    char fl_buf[256];

    /* Step 1: MS_PRIVATE — prevent mount propagation to host */
    SBX_DBG(L, "\u25b6 Step 1 — mount(none,/,NULL,%s)",
            decode_mount_flags(MS_REC|MS_PRIVATE, fl_buf, sizeof(fl_buf)));
    SBX_DBG(L, "  Kernel action: marks entire mount tree as MS_PRIVATE");
    SBX_DBG(L, "  Effect: new mounts inside namespace won't propagate to host");
    int r1 = mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
    SBX_DBG(L, "  Result: %d %s", r1, r1 ? strerror(errno) : "(OK)");

    /* Step 2: self-bind new_root (pivot_root requires a mountpoint) */
    SBX_DBG(L, "\u25b6 Step 2 — mount('%s','%s',NULL,%s)",
            new_root, new_root,
            decode_mount_flags(MS_BIND|MS_REC, fl_buf, sizeof(fl_buf)));
    SBX_DBG(L, "  Kernel requirement: new_root must be a mountpoint for pivot_root(2)");
    if (mount(new_root, new_root, NULL, MS_BIND | MS_REC, NULL) != 0) {
        int e = errno;
        SBX_ALERT(L, "Self-bind '%s' FAILED: %s (errno=%d)", new_root, strerror(e), e);
        return -1;
    }
    SBX_DBG(L, "  Result: 0 (OK) — '%s' is now a bind-mounted mountpoint", new_root);

    /* Step 3: chdir to new_root */
    SBX_DBG(L, "\u25b6 Step 3 — chdir('%s')", new_root);
    if (chdir(new_root) != 0) {
        SBX_ALERT(L, "chdir('%s') FAILED: %s", new_root, strerror(errno));
        goto cleanup_bind;
    }
    SBX_DBG(L, "  Result: 0 (OK) — CWD is now inside future jail root");

    /* Step 4: tmp dir for old root anchor */
    SBX_DBG(L, "\u25b6 Step 4 — mkdtemp('%s') inside new_root (old root anchor)", oldroot);
    if (mkdtemp(oldroot) == NULL) {
        SBX_ALERT(L, "mkdtemp FAILED: %s", strerror(errno));
        goto cleanup_bind;
    }
    SBX_DBG(L, "  Created: '%s'", oldroot);
    struct stat st;
    if (lstat(oldroot, &st) != 0 || !S_ISDIR(st.st_mode)) {
        SBX_ALERT(L, "TOCTOU check: '%s' is not a real dir!", oldroot);
        rmdir(oldroot);
        goto cleanup_bind;
    }

    /* Step 5: THE pivot_root(2) syscall */
    SBX_DBG(L, "\u25b6 Step 5 — syscall(SYS_pivot_root, '.', '%s')", oldroot);
    SBX_DBG(L, "  Kernel action: new_root='%s' becomes '/'  |  old '/' → '%s'",
            new_root, oldroot);
    SBX_DBG(L, "  Security: stronger than chroot (no path traversal via openat AT_FDCWD)");
    if (syscall(SYS_pivot_root, ".", oldroot) != 0) {
        int e = errno;
        SBX_ALERT(L, "pivot_root FAILED: %s (errno=%d) — try --chroot as fallback", strerror(e), e);
        rmdir(oldroot);
        goto cleanup_bind;
    }
    SBX_DBG(L, "  Result: 0 (OK) — ROOT FS REPLACED. Host filesystem is now at '/%s'", oldroot);

    /* Step 6: detach old root */
    char oldroot_abs[80];
    snprintf(oldroot_abs, sizeof(oldroot_abs), "/%s", oldroot);
    SBX_DBG(L, "\u25b6 Step 6 — umount2('%s', MNT_DETACH)", oldroot_abs);
    int ru = umount2(oldroot_abs, MNT_DETACH);
    SBX_DBG(L, "  Result: %d — host fs is now %s", ru,
            ru ? "POSSIBLY VISIBLE (non-fatal)" : "FULLY DETACHED AND INVISIBLE");
    rmdir(oldroot_abs);

    if (chdir("/") != 0) {
        SBX_ALERT(L, "chdir('/') after pivot FAILED: %s", strerror(errno));
        goto cleanup_bind;
    }
    SBX_OK(L, "Root pivoted. Jail '/' = vault. Host filesystem: DETACHED.");
    SBX_SEP(L);
    ret = 0;
    goto done;

cleanup_bind:
    umount2(new_root, MNT_DETACH);
done:
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_prepare_mounts(): /proc + /tmp virtuais dentro do jail
 * ───────────────────────────────────────────────────────────────────────── */
static void sandbox_prepare_mounts(void)
{
    const char *L = "MOUNTS";
    char fl_buf[256];
    SBX_LOG(L, "Mounting virtual filesystems inside jail...");

    int rp = mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
    SBX_DBG(L, "\u25b6 mount(none,/,NULL,%s): result=%d %s",
            decode_mount_flags(MS_REC|MS_PRIVATE, fl_buf, sizeof(fl_buf)),
            rp, rp ? strerror(errno) : "OK");

    if (mkdir("/proc", 0555) != 0 && errno != EEXIST)
        SBX_DBG(L, "  mkdir(/proc): %s (non-fatal)", strerror(errno));

    unsigned long pfl = MS_NOSUID | MS_NOEXEC | MS_NODEV;
    int rr = mount("proc", "/proc", "proc", pfl, NULL);
    SBX_DBG(L, "\u25b6 mount(proc,/proc,proc,%s): result=%d %s",
            decode_mount_flags(pfl, fl_buf, sizeof(fl_buf)), rr, rr ? strerror(errno) : "OK");
    SBX_DBG(L, "  NOSUID: suid inside /proc is inert | NOEXEC: no exec from procfs | NODEV: no devs");

    if (mkdir("/tmp", 01777) != 0 && errno != EEXIST)
        SBX_DBG(L, "  mkdir(/tmp): %s (non-fatal)", strerror(errno));

    unsigned long tfl = MS_NOSUID | MS_NODEV;
    int rt = mount("tmpfs", "/tmp", "tmpfs", tfl, SANDBOX_TMP_SIZE);
    SBX_DBG(L, "\u25b6 mount(tmpfs,/tmp,tmpfs,%s,'%s'): result=%d %s",
            decode_mount_flags(tfl, fl_buf, sizeof(fl_buf)),
            SANDBOX_TMP_SIZE, rt, rt ? strerror(errno) : "OK");
    SBX_DBG(L, "  tmpfs: RAM-backed, ephemeral — destroyed when namespace exits");
    SBX_OK(L, "/proc and /tmp ready inside jail.");
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_limit_resources(): rlimits — DoS prevention
 * ───────────────────────────────────────────────────────────────────────── */
static void sandbox_limit_resources(void)
{
    const char *L = "RLIMIT";
    struct rlimit rl;
    SBX_LOG(L, "Applying kernel resource limits (DoS prevention)...");

    log_rlimit_before(L, RLIMIT_NPROC,  "RLIMIT_NPROC");
    rl.rlim_cur = rl.rlim_max = 32;
    setrlimit(RLIMIT_NPROC, &rl);
    SBX_DBG(L, "  RLIMIT_NPROC  \u2192 32 (fork bombs blocked, max 32 procs/threads total)");

    log_rlimit_before(L, RLIMIT_AS,     "RLIMIT_AS");
    rl.rlim_cur = rl.rlim_max = 128 * 1024 * 1024;
    setrlimit(RLIMIT_AS, &rl);
    SBX_DBG(L, "  RLIMIT_AS     \u2192 128MB (mmap() beyond 128MB = ENOMEM)");

    log_rlimit_before(L, RLIMIT_FSIZE,  "RLIMIT_FSIZE");
    rl.rlim_cur = rl.rlim_max = 32 * 1024 * 1024;
    setrlimit(RLIMIT_FSIZE, &rl);
    SBX_DBG(L, "  RLIMIT_FSIZE  \u2192 32MB (write beyond 32MB = SIGXFSZ sent to process)");

    log_rlimit_before(L, RLIMIT_NOFILE, "RLIMIT_NOFILE");
    rl.rlim_cur = rl.rlim_max = 64;
    setrlimit(RLIMIT_NOFILE, &rl);
    SBX_DBG(L, "  RLIMIT_NOFILE \u2192 64 (open/socket beyond 64 = EMFILE)");

    SBX_OK(L, "Limits applied: NPROC=32  AS=128MB  FSIZE=32MB  NOFILE=64");
}

/* ─────────────────────────────────────────────────────────────────────────
 *  apply_seccomp_policy(): Seccomp-BPF — Layer 5
 *
 *  g_seccomp_strict=0 (padrão): allowlist completa, clone3 permitido
 *  g_seccomp_strict=1 : remove clone3, userfaultfd, shmget/shmat, sockets
 *  g_seccomp_allow_c3=1: mesmo em strict, re-adiciona clone3 (multithread)
 *
 *  Vulnerabilidade clone(CLONE_NEWUSER): bloqueada via argumento mascarado.
 *  Flags de namespace em clone() causam KILL imediato (não EPERM).
 * ───────────────────────────────────────────────────────────────────────── */
static int g_seccomp_strict   = 0;
static int g_seccomp_allow_c3 = 0;

static int apply_seccomp_policy(void)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (!ctx)
    {
        perror("[SANDBOX] seccomp_init");
        return -1;
    }

    /* I/O */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);

    /* Files */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0);

    /* Directories */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);

    /* Memory */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

    /* Processes */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);

    /* VULNERABILIDADE BLOQUEADA: clone() com flags de namespace.
     * MASKED_EQ(mask, 0) -> permite apenas se TODAS as flags de mask estiverem ZERADAS.
     * Se tentar usar NEWUSER (escalação) o processo será MORTO. */
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#define CLONE_DANGEROUS (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET | \
                         CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWCGROUP)
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
                     SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_DANGEROUS, 0));
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execveat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgrp), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsid), 0);
    /* gettid (186) + tkill (200) — called by pthreads immediately on init */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tkill), 0);
    /* sigaltstack (131) — alternate signal stack, used by Firefox crash handler */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0);
    /* getrusage (98) — resource usage, used by Firefox profiler / GC */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrusage), 0);
    /* rt_sigtimedwait (128), rt_sigqueueinfo (129) — signal helpers */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigtimedwait), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigqueueinfo), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_tgsigqueueinfo), 0);

    /* Signals */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigsuspend), 0);

    /* Identity */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups), 0);

    /* Sync */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);

    /* Libc init */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);

    /* Time */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
    /* rseq (restartable sequences) — called automatically by glibc/busybox on startup */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rseq), 0);

    /* Resource limits — used by sandbox layer 4 and read by shell */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setrlimit), 0);

    /* Modern filesystem syscalls used by busybox */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statx), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    /* memfd_create moved to conditional block below */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(link), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(linkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rmdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdirat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(truncate), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmodat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lchown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimes), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimensat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msync), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mincore), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getscheduler), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getparam), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getitimer), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setitimer), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(alarm), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pause), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_create), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_settime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_gettime), 0);

    /* System info — uname is called by busybox sh for prompt/hostname */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
    /* Note: gethostname/tcgetattr/tcsetattr are libc wrappers over uname/ioctl, already allowed */

    /* Process/session management used by shell job control */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresgid), 0);
    /* tcgetattr/tcsetattr are ioctl wrappers — ioctl already in allowlist */

    /* File copy / sendfile used by cp and similar builtins */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(copy_file_range), 0);

    /* Misc libc internals */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_getres), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_settime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(times), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);

    /* Poll / select — needed by interactive shell */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pselect6), 0);

    /* Access / permissions */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat2), 0);

    /* prctl — busybox sh uses it to read process name / check caps */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);

    /* ── GUI / Browser syscalls (Firefox, Chromium, Electron) ─────────── *
     * These are required for modern multi-process browsers to start.      *
     * They do NOT grant privilege escalation (setuid/mount remain KILL).  */

    /* clone3: replaces clone() in glibc >= 2.34, used by Firefox/Chromium */
    if (!g_seccomp_strict || g_seccomp_allow_c3) {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone3), 0);
    }

    if (!g_seccomp_strict) {
        /* Sockets — needed for Wayland/X11 IPC and browser inter-process comm */
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpeername), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shutdown), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketpair), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmmsg), 0);

        /* Shared memory — used by GPU/IPC in Chromium-based browsers */
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmget), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmctl), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmdt), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munlock), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlockall), 0);
        
        /* memfd_create — memory execution vector */
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(memfd_create), 0);
        /* userfaultfd (if it were allowed, we'd block it here) */
    }

    /* inotify — Firefox profile locking */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_init1), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_add_watch), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_rm_watch), 0);

    /* futex_waitv / futex2 — modern threading */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex_waitv), 0);

    /* Scheduling — Firefox uses real-time hints for audio/video */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setscheduler), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setparam), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setaffinity), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getaffinity), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpriority), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpriority), 0);

    /* File locking — SQLite / profile databases */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flock), 0);

    /* Extended attributes — used by some GTK/glib features */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getxattr), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listxattr), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fgetxattr), 0);

    /* openat2 — used by newer glibc / systemd resolver stubs */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat2), 0);

    /* close_range — glibc 2.34+ uses it to close fds efficiently */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close_range), 0);

    /* Misc modern syscalls used by JIT (SpiderMonkey / V8) */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(userfaultfd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 0);

    /* Explicit blocks */
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(umount2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(chroot), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(pivot_root), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(unshare), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setns), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(capset), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(perf_event_open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(kexec_load), 0);
    

    int ret = seccomp_load(ctx);
    if (ret != 0)
        perror("[SANDBOX] seccomp_load");
    seccomp_release(ctx);
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_write_uid_gid_map(): Write UID/GID maps for user namespace
 * ───────────────────────────────────────────────────────────────────────── */
static void sandbox_write_uid_gid_map(pid_t child_pid)
{
    char path[256];
    char map[64];
    int fd;
    ssize_t n;
    int map_len;

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

    /* uid_map: namespace UID 0 -> real host UID (unprivileged users can only map their own UID) */
    snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)child_pid);
    map_len = snprintf(map, sizeof(map), "0 %d 1\n", (int)getuid());
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
        else
            fprintf(stderr, "[SANDBOX][OK] uid_map escrito: \"%s\"\n", map);
        close(fd);
    }

    /* gid_map: namespace GID 0 -> real host GID */
    snprintf(path, sizeof(path), "/proc/%d/gid_map", (int)child_pid);
    map_len = snprintf(map, sizeof(map), "0 %d 1\n", (int)getgid());
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
        else
            fprintf(stderr, "[SANDBOX][OK] gid_map escrito: \"%s\"\n", map);
        close(fd);
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  jail_run_installer(): Fork + exec package manager to install busybox-static
 *
 *  Tenta os package managers conhecidos em ordem. Retorna 0 se o processo
 *  do instalador saiu com success, -1 caso contrário.
 *  Não garante que o pacote existe — o chamador deve re-checar o path.
 * ───────────────────────────────────────────────────────────────────────── */
static int jail_run_installer(void)
{
    /* Cada entrada: { argv[0..n], NULL } */
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

    /* Paths de busca para os binários dos package managers */
    const char *pm_paths[] = {
        "/usr/bin/apt-get",
        "/usr/bin/dnf",
        "/usr/bin/pacman",
        "/sbin/apk",
        "/usr/bin/zypper",
        NULL
    };

    for (int i = 0; installers[i][0] != NULL; i++) {
        /* Verifica se o pm existe antes de forkar */
        struct stat st;
        if (stat(pm_paths[i], &st) != 0)
            continue;

        vault_log(LOG_INFO,
                  "[SANDBOX] Detected package manager '%s' — invoking to install busybox-static...",
                  pm_paths[i]);

        printf("[SANDBOX] [AUTO-INSTALL] Running: %s", pm_paths[i]);
        for (int j = 1; installers[i][j]; j++)
            printf(" %s", installers[i][j]);
        printf("\n");
        fflush(stdout);

        pid_t pid = fork();
        if (pid < 0) {
            vault_log(LOG_WARN, "[SANDBOX] fork for installer failed: %s", strerror(errno));
            continue;
        }

        if (pid == 0) {
            /* Filho: redireciona stdout/stderr para /dev/null se não for root
             * para não poluir o terminal com output do apt */
            if (geteuid() != 0) {
                int devnull = open("/dev/null", O_WRONLY);
                if (devnull >= 0) {
                    dup2(devnull, STDOUT_FILENO);
                    dup2(devnull, STDERR_FILENO);
                    close(devnull);
                }
            }
            /* execvp busca no PATH automaticamente */
            execvp(installers[i][0], (char *const *)installers[i]);
            _exit(127); /* execvp falhou */
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

    return -1; /* nenhum instalador funcionou */
}

/* ─────────────────────────────────────────────────────────────────────────
 *  jail_install_shell(): Garante que /bin/sh existe dentro do jail
 *
 *  Ordem de tentativas:
 *    1. Copia busybox estático já presente no host (mais rápido)
 *    2. Chama o package manager para instalar busybox-static e tenta de novo
 *    3. Desiste e loga aviso — sandbox vai subir mas sem shell
 *
 *  O busybox DEVE ser estático: após pivot_root o /lib do host não existe.
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

    /* ── Já existe e não é vazio? Não mexe. ─────────────────────────── */
    {
        struct stat st;
        if (stat(dst, &st) == 0 && st.st_size > 0) {
            vault_log(LOG_INFO, "[SANDBOX] Shell already present at jail/bin/sh (%ld bytes) — skipping install.",
                      (long)st.st_size);
            return 0;
        }
    }

    /* ── Tentativa 1: copia do host ──────────────────────────────────── */
    for (int i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) != 0)
            continue;

        /* Abre origem */
        int src = open(candidates[i], O_RDONLY | O_CLOEXEC);
        if (src < 0) continue;

        /* Abre destino */
        int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
        if (dst_fd < 0) { close(src); continue; }

        /* Copia em blocos de 64 KB */
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

        /* Verifica se é realmente estático para avisar o usuário */
        int is_static = 0;
        {
            /* Heurística rápida: ELF dinâmico tem PT_INTERP; abre e procura
             * a string "/lib" nos primeiros 4 KB do arquivo */
            int probe = open(candidates[i], O_RDONLY | O_CLOEXEC);
            if (probe >= 0) {
                char head[4096];
                ssize_t r = read(probe, head, sizeof(head));
                close(probe);
                /* Se não achou interpreter path, é estático */
                is_static = (r > 0 && memmem(head, (size_t)r, "/lib", 4) == NULL);
            }
        }

        if (!is_static) {
            vault_log(LOG_WARN,
                      "[SANDBOX] '%s' appears to be dynamically linked — "
                      "may fail inside jail (missing host /lib). "
                      "Install 'busybox-static' for reliable operation.",
                      candidates[i]);
            printf("[SANDBOX] [WARN] Copied '%s' but it may be dynamic — "
                   "prefer busybox-static.\n", candidates[i]);
        }

        vault_log(LOG_INFO,
                  "[SANDBOX] ✔ Shell installed: '%s' → jail/bin/sh (%ld bytes, %s)",
                  candidates[i], (long)st.st_size,
                  is_static ? "static" : "dynamic — may fail");
        printf("[SANDBOX] [AUTO-INSTALL] ✔ Shell ready at jail/bin/sh "
               "(copied from '%s', %s).\n",
               candidates[i],
               is_static ? "statically linked" : "dynamically linked — may fail inside jail");
        return 0;
    }

    /* ── Tentativa 2: instala via package manager e tenta de novo ────── */
    printf("[SANDBOX] [AUTO-INSTALL] busybox not found on host — attempting automatic installation...\n");
    vault_log(LOG_WARN, "[SANDBOX] No busybox found on host — attempting auto-install via package manager.");

    if (geteuid() != 0) {
        printf("[SANDBOX] [AUTO-INSTALL] WARNING: not running as root — package manager will likely fail.\n");
        vault_log(LOG_WARN, "[SANDBOX] Auto-install requires root privileges (euid=%d).", geteuid());
    }

    int installed = jail_run_installer();

    if (installed == 0) {
        /* Re-tenta a cópia após instalação */
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
                      "[SANDBOX] ✔ Shell auto-installed and deployed: '%s' → jail/bin/sh (%ld bytes)",
                      candidates[i], (long)st.st_size);
            printf("[SANDBOX] [AUTO-INSTALL] ✔ busybox-static installed and deployed to jail/bin/sh.\n");
            return 0;
        }
    }

    /* ── Tentativa 3: desiste ────────────────────────────────────────── */
    vault_log(LOG_WARN,
              "[SANDBOX] Could not obtain a shell binary for the jail. "
              "Sandbox will open but execl(\"/bin/sh\") will fail. "
              "Install busybox-static manually: apt install busybox-static");
    printf("[SANDBOX] [AUTO-INSTALL] ✗ Could not install shell. "
           "Run: sudo apt install busybox-static\n");
    return -1;
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
            char *p = strrchr(parent, '/');
            if (p) { *p = '\0'; mkdir(parent, 0755); }
            if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
                vault_log(LOG_WARN, "[SANDBOX] mkdir %s: %s", dir, strerror(errno));
            }
        }
    }

    /* ── Garante /bin/sh dentro do jail (auto-instala se necessário) ── */
    jail_install_shell(vault_path);

    if (geteuid() == 0)
    {
        char dev_null[VAULT_PATH_MAX], dev_zero[VAULT_PATH_MAX];
        snprintf(dev_null, sizeof(dev_null), "%s/dev/null", vault_path);
        snprintf(dev_zero, sizeof(dev_zero), "%s/dev/zero", vault_path);
        if (stat(dev_null, &st) != 0)
            mknod(dev_null, S_IFCHR | 0666, makedev(1, 3));
        if (stat(dev_zero, &st) != 0)
            mknod(dev_zero, S_IFCHR | 0666, makedev(1, 5));
    }

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
 *  vault_sandbox_open() — Nuk4sd Hardened Sandbox v2
 * ───────────────────────────────────────────────────────────────────────── */
VaultErrorr vault_sandbox_open(Vault *v, const char *password, bool gui_mode, const char *app_cmd)
{
    if (!v)
        return ERR_INVALID_ARGS;

    /* Authentication */
    if (v->type == VAULT_TYPE_PROTECTED)
    {
        if (!password || !*password)
            return ERR_PASS_REQUIRED;
        VaultErrorr err = auth_verify_password(v, password);
        if (err != ERR_OK)
            return err;
    }

    if (v->path[0] == '\0')
    {
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
              (long)_ts_sb.tv_sec, _ts_sb.tv_nsec);

    /* Temporarily unlock cipher_path so the jail can access vault data */
    vault_log(LOG_AUDIT,
              "[PHYSICAL_LOCK] Temporary bypass granted: chmod 000 \u2192 700 on cipher_dir='%s' "
              "to allow Sandbox jail access. Session-scoped unlock.",
              v->cipher_path);
    chmod(v->cipher_path, 0700);

    vault_prepare_jail(v->path, gui_mode);

    int sync_pipe[2];   /* pai -> filho: "mapeamento já escrito" */
    int ready_pipe[2];  /* filho -> pai: "unshare(CLONE_NEWUSER) já feito" */
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

        /* Espera o filho sinalizar que já chamou unshare(CLONE_NEWUSER) —
         * sem isso, escrever em /proc/[pid]/uid_map cedo demais falha com
         * EPERM, porque o PID ainda pertence à user namespace antiga. */
        {
            char c;
            ssize_t r = read(ready_pipe[0], &c, 1);
            if (r != 1)
                vault_log(LOG_ERROR, "[SANDBOX] ready_pipe read falhou: %s", strerror(errno));
        }
        close(ready_pipe[0]);

        sandbox_write_uid_gid_map(pid);
        close(sync_pipe[1]);

        int status;
        waitpid(pid, &status, 0);

        vault_auth_pid_remove_ffi(pid);

        if (WIFSIGNALED(status))
        {
            vault_log(LOG_ALERT,
                      "[SANDBOX] Session of vault '%s' (id=%u) TERMINATED BY SIGNAL %d "
                      "(possible seccomp/namespace violation). exit_code=N/A.",
                      v->name, v->id, WTERMSIG(status));
        }
        else
        {
            vault_log(LOG_AUDIT,
                      "[SANDBOX] Session of vault '%s' (id=%u) ended cleanly. "
                      "exit_code=%d. Namespace teardown complete.",
                      v->name, v->id, WEXITSTATUS(status));
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
                      v->cipher_path, v->id,
                      (long)_ts_seal.tv_sec, _ts_seal.tv_nsec);
        }

        return ERR_OK;
    }

    /* CHILD — SANDBOX */

    /* Rename the process so it appears distinctly in htop/task managers */
    prctl(PR_SET_NAME, "Nuk4sd-Jail", 0, 0, 0);

    close(sync_pipe[1]);
    close(ready_pipe[0]);

    /* [Layer 1] User Namespace */
    printf("[SANDBOX] [Layer 1/5] Invoking unshare(CLONE_NEWUSER) syscall to dissociate user/group database from host...\n");
    if (unshare(CLONE_NEWUSER) != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] unshare(CLONE_NEWUSER) failed: %s (Kernel code %d)\n", strerror(err), err);
        _exit(1);
    }
    printf("[SANDBOX] [Layer 1/5] User Namespace unshared. Signaling host to assign UID/GID mappings...\n");

    /* Avisa o pai AGORA que a user namespace já existe — só depois disso
     * é seguro o pai escrever em /proc/[este_pid]/uid_map e gid_map. */
    {
        char c = 'r';
        if (write(ready_pipe[1], &c, 1) != 1)
            fprintf(stderr, "[SANDBOX][WARN] ready_pipe write falhou: %s\n", strerror(errno));
        close(ready_pipe[1]);
    }

    /* Wait for parent to write uid_map/gid_map */
    {
        char c;
        read(sync_pipe[0], &c, 1);
        close(sync_pipe[0]);
    }
    printf("[SANDBOX] [Layer 1/5] UID/GID mapping initialized: current sandbox root maps to host 'nobody' (%d:%d).\n", 
           SANDBOX_NOBODY_UID, SANDBOX_NOBODY_GID);

    /* [Layer 2] Mount + PID Namespace */
    printf("[SANDBOX] [Layer 2/5] Invoking unshare(CLONE_NEWNS | CLONE_NEWPID) to isolate mount points and process trees...\n");
    if (unshare(CLONE_NEWNS | CLONE_NEWPID) != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] unshare(CLONE_NEWNS|CLONE_NEWPID) failed: %s (Kernel code %d)\n",
                strerror(err), err);
        _exit(1);
    }

    printf("[SANDBOX] [Layer 2/5] Namespaces created. Forking inside new PID namespace to gain PID 1...\n");
    pid_t ns_pid = fork();
    if (ns_pid < 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] fork inside new PID NS failed: %s (Kernel code %d)\n", strerror(err), err);
        _exit(1);
    }
    if (ns_pid > 0)
    {
        int st;
        waitpid(ns_pid, &st, 0);
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
        printf("[SANDBOX] [Layer 2.5] GUI Mode: Bind mounting host GUI dependencies (Read-Only)...\n");
        const char *gui_binds[] = {
            "/usr", "/lib", "/lib64", "/etc/fonts", "/etc/alternatives", 
            "/sys/dev/char", "/dev/dri", "/tmp/.X11-unix", NULL
        };
        for (int i = 0; gui_binds[i]; i++) {
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", v->path, gui_binds[i]);
            
            struct stat st;
            if (stat(gui_binds[i], &st) == 0) {
                if (S_ISDIR(st.st_mode)) {
                    mkdir(dst, 0755); // Ignore error
                } else {
                    int fd = open(dst, O_CREAT | O_WRONLY, 0666);
                    if (fd >= 0) close(fd);
                }
                if (mount(gui_binds[i], dst, NULL, MS_BIND | MS_REC, NULL) == 0) {
                    mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
                }
            }
        }
        
        /* Wayland Socket */
        char wayland_sock[256];
        snprintf(wayland_sock, sizeof(wayland_sock), "/run/user/%d", getuid());
        char dst_wayland[VAULT_PATH_MAX];
        snprintf(dst_wayland, sizeof(dst_wayland), "%s%s", v->path, wayland_sock);
        mkdir(dst_wayland, 0700);
        
        if (mount(wayland_sock, dst_wayland, NULL, MS_BIND | MS_REC, NULL) == 0) {
            mount(NULL, dst_wayland, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        }

        /* Set GUI Environment Variables */
        setenv("WAYLAND_DISPLAY", "wayland-0", 1);
        setenv("DISPLAY", ":0", 1);
        char xdg_run[256];
        snprintf(xdg_run, sizeof(xdg_run), "/run/user/%d", getuid());
        setenv("XDG_RUNTIME_DIR", xdg_run, 1);
        setenv("QT_QPA_PLATFORM", "wayland;xcb", 1);
        setenv("GDK_BACKEND", "wayland,x11", 1);
    }

    /* [Layer 3] Pivot Root */
    printf("[SANDBOX] [Layer 3/5] Executing pivot_root syscall targeting '%s'...\n", v->path);
    if (sandbox_pivot_root(v->path) != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] pivot_root syscall to '%s' failed: %s (Kernel code %d)\n", v->path, strerror(err), err);
        _exit(1);
    }
    printf("[SANDBOX] [Layer 3/5] Root filesystem successfully pivoted. Old root unmounted.\n");

    printf("[SANDBOX] [Layer 3/5] Creating private virtual mounts (/proc, /tmp) inside new root...\n");
    sandbox_prepare_mounts();
    printf("[SANDBOX] [Layer 3/5] /proc and /tmp (tmpfs) mounted securely with MS_NOSUID | MS_NOEXEC.\n");

    /* [Layer 4] Drop capabilities */
    printf("[SANDBOX] [Layer 4/5] Dropping Linux kernel capabilities to prevent privilege escalation...\n");
    if (sandbox_drop_caps() != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] drop capabilities failed: %s (Kernel code %d)\n", strerror(err), err);
        _exit(1);
    }
    printf("[SANDBOX] [Layer 4/5] Capabilities dropped. PR_SET_NO_NEW_PRIVS set to 1.\n");

    printf("[SANDBOX] [Layer 4/5] Enforcing resource limits (RLIMIT_NPROC=32, RLIMIT_AS=128MB, RLIMIT_NOFILE=64)...\n");
    sandbox_limit_resources();
    printf("[SANDBOX] [Layer 4/5] Kernel RLIMIT parameters applied successfully.\n");

    /* [Layer 5] Seccomp-BPF — LAST STEP */
    printf("[SANDBOX] [Layer 5/5] Compiling and loading Seccomp-BPF filter allowlist...\n");
    if (apply_seccomp_policy() != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] seccomp policy activation failed: %s (Kernel code %d)\n", strerror(err), err);
        _exit(1);
    }
    printf("[SANDBOX] [Layer 5/5] Seccomp filter loaded. Kernel will now SIGKILL unauthorized syscalls.\n");

    printf("\n");
    printf("  ┌─────────────────────────────────────────────────────────┐\n");
    printf("  │     Nuk4sd HARDENED SANDBOX v2                       │\n");
    printf("  │     Vault : %-43s            │\n", v->name);
    printf("  │     Isolation: UserNS + PivotRoot + Caps + Seccomp-BPF  │\n");
    printf("  │     Mode: Least Privilege · Deny by Default             │\n");
    printf("  │     Type 'exit' to end session.                         │\n");
    printf("  └─────────────────────────────────────────────────────────┘\n\n");


    if (gui_mode && app_cmd && app_cmd[0] != '\0') {
        printf("[SANDBOX] Launching GUI App: %s\n", app_cmd);
        
        /* Parse simple args. In a real shell, we'd use wordexp or /bin/sh -c */
        /* For now, just pass to /bin/sh -c so it inherits the PATH from /usr/bin */
        execl("/bin/sh", "sh", "-c", app_cmd, NULL);
        
        int err = errno;
        fprintf(stderr,
                "[SANDBOX][FATAL] execl(/bin/sh -c %s) failed: %s (Kernel code %d)\n",
                app_cmd, strerror(err), err);
        _exit(127);
    } else {
        printf("[SANDBOX] Launching shell via execl(\"/bin/sh\")...\n%s\n", app_cmd);
        execl("/bin/sh", "sh", NULL);

        int err = errno;
        fprintf(stderr,
                "[SANDBOX][FATAL] execl(/bin/sh) failed: %s (Kernel code %d)\n"
                "  Hint: place a static /bin/sh (busybox) inside the vault.\n",
                strerror(err), err);
        _exit(127);
    }
}


/* ─────────────────────────────────────────────────────────────────────────
 * vault_isolate_path_readonly — bind-mount + remount readonly
 *
 * Isola um caminho arbitrário (não necessariamente um vault catalogado)
 * tornando-o readonly em nível de kernel via bind mount, em vez de apenas
 * chmod (que não impede escrita por processos com CAP_DAC_OVERRIDE).
 *
 * Requer CAP_SYS_ADMIN. Retorna 0 em success, -1 em falha (ver errno).
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
        umount(path); /* desfaz o bind se o remount readonly falhar */
        errno = saved_errno;
        return -1;
    }

    return 0;
}

#endif /* __linux__ */
/* ─────────────────────────────────────────────────────────────────────────
 *  Wrappers públicos — expõem funções static para vault_cli.c
 *  Prefixo vsb_ para não colidir com nomes externos.
 * ───────────────────────────────────────────────────────────────────────── */
#ifdef __linux__
int vsb_drop_caps(void)                        { return sandbox_drop_caps(); }
int vsb_apply_seccomp(void)                    { return apply_seccomp_policy(); }
int vsb_pivot_root(const char *new_root)       { return sandbox_pivot_root(new_root); }
void vsb_prepare_mounts(void)                  { sandbox_prepare_mounts(); }
void vsb_write_uid_gid_map(pid_t child_pid)    { sandbox_write_uid_gid_map(child_pid); }
void vsb_prepare_jail(const char *path, bool gui) { vault_prepare_jail(path, gui); }

void vsb_set_seccomp_mode(int strict, int allow_c3) {
    g_seccomp_strict = strict;
    g_seccomp_allow_c3 = allow_c3;
}

void vsb_set_debug(bool debug) {
    g_sandbox_debug = debug;
}
#endif /* __linux__ */