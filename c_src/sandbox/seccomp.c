/*
 * seccomp.c
 *
 * Nuk4sd — Hardened Sandbox — Layer 5: Seccomp-BPF
 * Extracted from vault_sandbox.c
 */

#include "sandbox.h"

#ifdef __linux__

/* ─────────────────────────────────────────────────────────────────────────
 *  apply_seccomp_policy(): Seccomp-BPF — Layer 5 — ALLOWLIST
 *
 *  Model: default DENY (SCMP_ACT_ERRNO(EPERM)).
 *  Only explicitly enumerated system calls below are permitted.
 *  Any unlisted system call — including new ones added in future kernels —
 *  is automatically blocked with EPERM.
 *
 *  Available modes (orthogonal to each other):
 *
 *  g_seccomp_strict=0 (default):
 *    Full allowlist for general usage: includes clone3, userfaultfd,
 *    shmget/shmat (shared memory), socket/connect/bind (network).
 *    Suitable for applications requiring threading and networking.
 *
 *  g_seccomp_strict=1 (--strict):
 *    Removes clone3, sockets, shmget/shmat, and memfd_create from allowlist.
 *    Maximum isolation for processes requiring neither network nor
 *    shared memory. g_seccomp_allow_c3 re-adds clone3
 *    for multithreading support even in strict mode.
 *
 *  g_seccomp_permissive=1 (--permissive):
 *    Adds chroot/capset/setuid/setgid to allowlist — required for
 *    GUI applications (Firefox, Chromium) constructing internal sandboxes.
 *    mount/pivot_root/ptrace/bpf/kexec_load remain denied
 *    regardless of this flag.
 *
 *  g_seccomp_friendly=1 (--friendly-sandbox):
 *    Adds file I/O housekeeping syscalls to allowlist:
 *    fsync, fdatasync, renameat2, sync_file_range, fallocate,
 *    name_to_handle_at. Useful for applications persisting disk state safely
 *    (e.g., Firefox/Glean "Could not write...").
 *    Orthogonal to g_seccomp_strict.
 *
 *  clone(CLONE_NEWUSER) vulnerability: blocked via masked arguments.
 *  Namespace flags in clone() trigger EPERM.
 * ───────────────────────────────────────────────────────────────────────── */
#include <strings.h>
#include <ctype.h>

static int g_seccomp_strict     = 0;
static int g_seccomp_allow_c3   = 0;
static int g_seccomp_friendly   = 0;
static int g_seccomp_permissive = 0;
static const char *g_seccomp_adapter = NULL;

static void apply_adapter_rules(scmp_filter_ctx ctx, const char *adapter_str)
{
    if (!adapter_str || !*adapter_str) return;

    char buf[1024];
    strncpy(buf, adapter_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *accept_pos = strstr(buf, "accept:");
    char *decline_pos = strstr(buf, "decline:");

    char *accept_block = NULL;
    char *decline_block = NULL;

    if (accept_pos) {
        accept_block = accept_pos + 7;
    }
    if (decline_pos) {
        decline_block = decline_pos + 8;
    }

    if (accept_pos && decline_pos) {
        if (accept_pos < decline_pos) {
            *decline_pos = '\0';
        } else {
            *accept_pos = '\0';
        }
    }

    if (accept_block) {
        char *saveptr = NULL;
        char *tok = strtok_r(accept_block, ",; \t\r\n", &saveptr);
        while (tok) {
            if (*tok && strcasecmp(tok, "empty") != 0) {
                int sc = seccomp_syscall_resolve_name(tok);
                if (sc != __NR_SCMP_ERROR && sc >= 0) {
                    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, sc, 0);
                    vault_log(LOG_INFO, "[SECCOMP] adapter: allowed syscall '%s' (nr=%d)", tok, sc);
                } else {
                    vault_log(LOG_WARN, "[SECCOMP] adapter: unknown syscall '%s' (ignored)", tok);
                    fprintf(stderr, "\033[33m⚠ [SECCOMP] adapter: unknown syscall '%s' ignored\033[0m\n", tok);
                }
            }
            tok = strtok_r(NULL, ",; \t\r\n", &saveptr);
        }
    }

    if (decline_block) {
        char *saveptr = NULL;
        char *tok = strtok_r(decline_block, ",; \t\r\n", &saveptr);
        while (tok) {
            if (*tok && strcasecmp(tok, "empty") != 0) {
                int sc = seccomp_syscall_resolve_name(tok);
                if (sc != __NR_SCMP_ERROR && sc >= 0) {
                    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), sc, 0);
                    vault_log(LOG_INFO, "[SECCOMP] adapter: declined syscall '%s' (nr=%d)", tok, sc);
                } else {
                    vault_log(LOG_WARN, "[SECCOMP] adapter: unknown syscall '%s' (ignored)", tok);
                    fprintf(stderr, "\033[33m⚠ [SECCOMP] adapter: unknown syscall '%s' ignored\033[0m\n", tok);
                }
            }
            tok = strtok_r(NULL, ",; \t\r\n", &saveptr);
        }
    }
}

/* ── Macro helper: adds syscall to allowlist, silently ignoring syscalls
 * that do not exist on the current architecture (SCMP_SYS returns -1). */
#define ALLOW(ctx, sc) \
    do { \
        int _nr = (int)(sc); \
        if (_nr >= 0) seccomp_rule_add((ctx), SCMP_ACT_ALLOW, (uint32_t)_nr, 0); \
    } while (0)

static int apply_seccomp_policy(void)
{
    /*
     * Allowlist: default DENY — only explicitly listed system calls
     * below are permitted. Any unlisted syscall -> EPERM.
     */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx)
    {
        perror("[SANDBOX] seccomp_init");
        return -1;
    }

    /* ── File and descriptor I/O ──────────────────────────────────── */
    ALLOW(ctx, SCMP_SYS(read));
    ALLOW(ctx, SCMP_SYS(write));
    ALLOW(ctx, SCMP_SYS(readv));
    ALLOW(ctx, SCMP_SYS(writev));
    ALLOW(ctx, SCMP_SYS(pread64));
    ALLOW(ctx, SCMP_SYS(pwrite64));
    ALLOW(ctx, SCMP_SYS(preadv));
    ALLOW(ctx, SCMP_SYS(pwritev));
    ALLOW(ctx, SCMP_SYS(preadv2));
    ALLOW(ctx, SCMP_SYS(pwritev2));
    ALLOW(ctx, SCMP_SYS(lseek));
    ALLOW(ctx, SCMP_SYS(open));
    ALLOW(ctx, SCMP_SYS(openat));
    ALLOW(ctx, SCMP_SYS(openat2));
    ALLOW(ctx, SCMP_SYS(close));
    ALLOW(ctx, SCMP_SYS(close_range));
    ALLOW(ctx, SCMP_SYS(dup));
    ALLOW(ctx, SCMP_SYS(dup2));
    ALLOW(ctx, SCMP_SYS(dup3));
    ALLOW(ctx, SCMP_SYS(pipe));
    ALLOW(ctx, SCMP_SYS(pipe2));
    ALLOW(ctx, SCMP_SYS(read));
    ALLOW(ctx, SCMP_SYS(fstat));
    ALLOW(ctx, SCMP_SYS(stat));
    ALLOW(ctx, SCMP_SYS(lstat));
    ALLOW(ctx, SCMP_SYS(newfstatat));
    ALLOW(ctx, SCMP_SYS(statx));
    ALLOW(ctx, SCMP_SYS(access));
    ALLOW(ctx, SCMP_SYS(faccessat));
    ALLOW(ctx, SCMP_SYS(faccessat2));
    ALLOW(ctx, SCMP_SYS(ioctl));
    ALLOW(ctx, SCMP_SYS(fcntl));
    ALLOW(ctx, SCMP_SYS(flock));
    ALLOW(ctx, SCMP_SYS(truncate));
    ALLOW(ctx, SCMP_SYS(ftruncate));

    /* ── Directories and filesystem ───────────────────────────────── */
    ALLOW(ctx, SCMP_SYS(getcwd));
    ALLOW(ctx, SCMP_SYS(chdir));
    ALLOW(ctx, SCMP_SYS(fchdir));
    ALLOW(ctx, SCMP_SYS(mkdir));
    ALLOW(ctx, SCMP_SYS(mkdirat));
    ALLOW(ctx, SCMP_SYS(rmdir));
    ALLOW(ctx, SCMP_SYS(rename));
    ALLOW(ctx, SCMP_SYS(renameat));
    ALLOW(ctx, SCMP_SYS(renameat2));
    ALLOW(ctx, SCMP_SYS(unlink));
    ALLOW(ctx, SCMP_SYS(unlinkat));
    ALLOW(ctx, SCMP_SYS(link));
    ALLOW(ctx, SCMP_SYS(linkat));
    ALLOW(ctx, SCMP_SYS(symlink));
    ALLOW(ctx, SCMP_SYS(symlinkat));
    ALLOW(ctx, SCMP_SYS(readlink));
    ALLOW(ctx, SCMP_SYS(readlinkat));
    ALLOW(ctx, SCMP_SYS(chmod));
    ALLOW(ctx, SCMP_SYS(fchmod));
    ALLOW(ctx, SCMP_SYS(fchmodat));
    ALLOW(ctx, SCMP_SYS(chown));
    ALLOW(ctx, SCMP_SYS(fchown));
    ALLOW(ctx, SCMP_SYS(lchown));
    ALLOW(ctx, SCMP_SYS(fchownat));
    ALLOW(ctx, SCMP_SYS(getdents));
    ALLOW(ctx, SCMP_SYS(getdents64));
    ALLOW(ctx, SCMP_SYS(utimes));
    ALLOW(ctx, SCMP_SYS(utimensat));
    ALLOW(ctx, SCMP_SYS(futimesat));
    ALLOW(ctx, SCMP_SYS(inotify_init));
    ALLOW(ctx, SCMP_SYS(inotify_init1));
    ALLOW(ctx, SCMP_SYS(inotify_add_watch));
    ALLOW(ctx, SCMP_SYS(inotify_rm_watch));
    ALLOW(ctx, SCMP_SYS(statfs));
    ALLOW(ctx, SCMP_SYS(fstatfs));

    /* ── Process and threading ────────────────────────────────────────────── */
    ALLOW(ctx, SCMP_SYS(getpid));
    ALLOW(ctx, SCMP_SYS(getppid));
    ALLOW(ctx, SCMP_SYS(gettid));
    ALLOW(ctx, SCMP_SYS(getuid));
    ALLOW(ctx, SCMP_SYS(geteuid));
    ALLOW(ctx, SCMP_SYS(getgid));
    ALLOW(ctx, SCMP_SYS(getegid));
    ALLOW(ctx, SCMP_SYS(getgroups));
    ALLOW(ctx, SCMP_SYS(getresuid));
    ALLOW(ctx, SCMP_SYS(getresgid));
    ALLOW(ctx, SCMP_SYS(getpgrp));
    ALLOW(ctx, SCMP_SYS(getpgid));
    ALLOW(ctx, SCMP_SYS(getsid));
    ALLOW(ctx, SCMP_SYS(setpgid));
    ALLOW(ctx, SCMP_SYS(setsid));
    ALLOW(ctx, SCMP_SYS(exit));
    ALLOW(ctx, SCMP_SYS(exit_group));
    ALLOW(ctx, SCMP_SYS(wait4));
    ALLOW(ctx, SCMP_SYS(waitid));
    ALLOW(ctx, SCMP_SYS(fork));
    ALLOW(ctx, SCMP_SYS(vfork));
    ALLOW(ctx, SCMP_SYS(clone));
    ALLOW(ctx, SCMP_SYS(execve));
    ALLOW(ctx, SCMP_SYS(execveat));
    ALLOW(ctx, SCMP_SYS(kill));
    ALLOW(ctx, SCMP_SYS(tgkill));
    ALLOW(ctx, SCMP_SYS(tkill));
    ALLOW(ctx, SCMP_SYS(sigaltstack));
    ALLOW(ctx, SCMP_SYS(rt_sigaction));
    ALLOW(ctx, SCMP_SYS(rt_sigprocmask));
    ALLOW(ctx, SCMP_SYS(rt_sigreturn));
    ALLOW(ctx, SCMP_SYS(rt_sigpending));
    ALLOW(ctx, SCMP_SYS(rt_sigsuspend));
    ALLOW(ctx, SCMP_SYS(rt_sigtimedwait));
    ALLOW(ctx, SCMP_SYS(pause));
    ALLOW(ctx, SCMP_SYS(alarm));
    ALLOW(ctx, SCMP_SYS(setitimer));
    ALLOW(ctx, SCMP_SYS(getitimer));
    ALLOW(ctx, SCMP_SYS(prctl));

    /* ── Memory ─────────────────────────────────────────────────────────── */
    ALLOW(ctx, SCMP_SYS(mmap));
    ALLOW(ctx, SCMP_SYS(munmap));
    ALLOW(ctx, SCMP_SYS(mprotect));
    ALLOW(ctx, SCMP_SYS(mremap));
    ALLOW(ctx, SCMP_SYS(madvise));
    ALLOW(ctx, SCMP_SYS(mlock));
    ALLOW(ctx, SCMP_SYS(munlock));
    ALLOW(ctx, SCMP_SYS(mlockall));
    ALLOW(ctx, SCMP_SYS(munlockall));
    ALLOW(ctx, SCMP_SYS(brk));
    ALLOW(ctx, SCMP_SYS(mincore));

    /* ── Polling and events ───────────────────────────────────────────────── */
    ALLOW(ctx, SCMP_SYS(select));
    ALLOW(ctx, SCMP_SYS(pselect6));
    ALLOW(ctx, SCMP_SYS(poll));
    ALLOW(ctx, SCMP_SYS(ppoll));
    ALLOW(ctx, SCMP_SYS(epoll_create));
    ALLOW(ctx, SCMP_SYS(epoll_create1));
    ALLOW(ctx, SCMP_SYS(epoll_ctl));
    ALLOW(ctx, SCMP_SYS(epoll_wait));
    ALLOW(ctx, SCMP_SYS(epoll_pwait));
    ALLOW(ctx, SCMP_SYS(epoll_pwait2));
    ALLOW(ctx, SCMP_SYS(eventfd));
    ALLOW(ctx, SCMP_SYS(eventfd2));
    ALLOW(ctx, SCMP_SYS(signalfd));
    ALLOW(ctx, SCMP_SYS(signalfd4));
    ALLOW(ctx, SCMP_SYS(timerfd_create));
    ALLOW(ctx, SCMP_SYS(timerfd_settime));
    ALLOW(ctx, SCMP_SYS(timerfd_gettime));

    /* ── Timing ───────────────────────────────────────────────────── */
    ALLOW(ctx, SCMP_SYS(nanosleep));
    ALLOW(ctx, SCMP_SYS(clock_nanosleep));
    ALLOW(ctx, SCMP_SYS(clock_gettime));
    ALLOW(ctx, SCMP_SYS(clock_getres));
    ALLOW(ctx, SCMP_SYS(clock_settime));
    ALLOW(ctx, SCMP_SYS(gettimeofday));
    ALLOW(ctx, SCMP_SYS(times));
    ALLOW(ctx, SCMP_SYS(time));
    ALLOW(ctx, SCMP_SYS(timer_create));
    ALLOW(ctx, SCMP_SYS(timer_settime));
    ALLOW(ctx, SCMP_SYS(timer_gettime));
    ALLOW(ctx, SCMP_SYS(timer_getoverrun));
    ALLOW(ctx, SCMP_SYS(timer_delete));

    /* ── Resources and limits ─────────────────────────────────────────────── */
    ALLOW(ctx, SCMP_SYS(getrlimit));
    ALLOW(ctx, SCMP_SYS(setrlimit));
    ALLOW(ctx, SCMP_SYS(prlimit64));
    ALLOW(ctx, SCMP_SYS(getrusage));
    ALLOW(ctx, SCMP_SYS(sched_getaffinity));
    ALLOW(ctx, SCMP_SYS(sched_setaffinity));
    ALLOW(ctx, SCMP_SYS(sched_getparam));
    ALLOW(ctx, SCMP_SYS(sched_setparam));
    ALLOW(ctx, SCMP_SYS(sched_getscheduler));
    ALLOW(ctx, SCMP_SYS(sched_setscheduler));
    ALLOW(ctx, SCMP_SYS(sched_yield));
    ALLOW(ctx, SCMP_SYS(nice));
    ALLOW(ctx, SCMP_SYS(getpriority));
    ALLOW(ctx, SCMP_SYS(setpriority));

    /* ── Basic IPC: futex, sem ─────────────────────────────────────────── */
    ALLOW(ctx, SCMP_SYS(futex));
    ALLOW(ctx, SCMP_SYS(futex_waitv));
    ALLOW(ctx, SCMP_SYS(semget));
    ALLOW(ctx, SCMP_SYS(semop));
    ALLOW(ctx, SCMP_SYS(semtimedop));
    ALLOW(ctx, SCMP_SYS(semctl));

    /* ── Entropy ────────────────────────────────────────────────────────── */
    ALLOW(ctx, SCMP_SYS(getrandom));

    /* ── Safe miscellaneous ───────────────────────────────────────────────── */
    ALLOW(ctx, SCMP_SYS(uname));
    ALLOW(ctx, SCMP_SYS(sysinfo));
    ALLOW(ctx, SCMP_SYS(getdents));
    ALLOW(ctx, SCMP_SYS(sendfile));
    ALLOW(ctx, SCMP_SYS(copy_file_range));
    ALLOW(ctx, SCMP_SYS(splice));
    ALLOW(ctx, SCMP_SYS(tee));
    ALLOW(ctx, SCMP_SYS(vmsplice));
    ALLOW(ctx, SCMP_SYS(mq_open));
    ALLOW(ctx, SCMP_SYS(mq_unlink));
    ALLOW(ctx, SCMP_SYS(mq_timedsend));
    ALLOW(ctx, SCMP_SYS(mq_timedreceive));
    ALLOW(ctx, SCMP_SYS(mq_notify));
    ALLOW(ctx, SCMP_SYS(mq_getsetattr));
    ALLOW(ctx, SCMP_SYS(syslog));       /* for apps logging via syslog(3) */
    ALLOW(ctx, SCMP_SYS(restart_syscall));

    /* ── Sensitive syscalls conditioned on g_seccomp_permissive ─────────── */
    if (g_seccomp_permissive) {
        /* Required for GUIs (Firefox, Chromium) constructing internal sandbox */
        ALLOW(ctx, SCMP_SYS(chroot));
        ALLOW(ctx, SCMP_SYS(capset));
        ALLOW(ctx, SCMP_SYS(capget));
        ALLOW(ctx, SCMP_SYS(setuid));
        ALLOW(ctx, SCMP_SYS(setgid));
        ALLOW(ctx, SCMP_SYS(setreuid));
        ALLOW(ctx, SCMP_SYS(setregid));
        ALLOW(ctx, SCMP_SYS(setresuid));
        ALLOW(ctx, SCMP_SYS(setresgid));
        ALLOW(ctx, SCMP_SYS(setgroups));
        /* mount/pivot_root/ptrace/bpf/kexec_load remain denied */
    }

    /* ── Network: only in non-strict mode ──────────────────────────────────────
     * In strict mode, sockets are excluded from allowlist -> automatic EPERM. */
    if (!g_seccomp_strict) {
        ALLOW(ctx, SCMP_SYS(socket));
        ALLOW(ctx, SCMP_SYS(connect));
        ALLOW(ctx, SCMP_SYS(bind));
        ALLOW(ctx, SCMP_SYS(listen));
        ALLOW(ctx, SCMP_SYS(accept));
        ALLOW(ctx, SCMP_SYS(accept4));
        ALLOW(ctx, SCMP_SYS(sendmsg));
        ALLOW(ctx, SCMP_SYS(recvmsg));
        ALLOW(ctx, SCMP_SYS(sendto));
        ALLOW(ctx, SCMP_SYS(recvfrom));
        ALLOW(ctx, SCMP_SYS(socketpair));
        ALLOW(ctx, SCMP_SYS(getsockopt));
        ALLOW(ctx, SCMP_SYS(setsockopt));
        ALLOW(ctx, SCMP_SYS(getsockname));
        ALLOW(ctx, SCMP_SYS(getpeername));
        ALLOW(ctx, SCMP_SYS(shutdown));
        ALLOW(ctx, SCMP_SYS(sendmmsg));
        ALLOW(ctx, SCMP_SYS(recvmmsg));

        /* Shared memory POSIX and SysV */
        ALLOW(ctx, SCMP_SYS(shmget));
        ALLOW(ctx, SCMP_SYS(shmat));
        ALLOW(ctx, SCMP_SYS(shmctl));
        ALLOW(ctx, SCMP_SYS(shmdt));
        ALLOW(ctx, SCMP_SYS(memfd_create));

        /* clone3 — modern multithreading */
        ALLOW(ctx, SCMP_SYS(clone3));
        ALLOW(ctx, SCMP_SYS(userfaultfd));
    } else {
        /* Strict mode: re-allow clone3 only if --allow-clone3 */
        if (g_seccomp_allow_c3) {
            ALLOW(ctx, SCMP_SYS(clone3));
        }
    }

    /* ── --friendly-sandbox: housekeeping file I/O ────────
     * Safe persistence syscalls required by some apps
     * (e.g., Firefox/Glean "Could not write...").
     * Orthogonal to strict/permissive mode. */
    if (g_seccomp_friendly) {
        ALLOW(ctx, SCMP_SYS(fsync));
        ALLOW(ctx, SCMP_SYS(fdatasync));
        ALLOW(ctx, SCMP_SYS(sync));
        ALLOW(ctx, SCMP_SYS(syncfs));
        ALLOW(ctx, SCMP_SYS(sync_file_range));
        ALLOW(ctx, SCMP_SYS(fallocate));
        ALLOW(ctx, SCMP_SYS(name_to_handle_at));
        ALLOW(ctx, SCMP_SYS(open_by_handle_at));
    }

    /* ── Always denied — immediate KILL for high risk ──────────── */
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(kexec_load), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_writev), 0);

    /* ── Apply granular adapter rules from --adapter ─────────────────── */
    apply_adapter_rules(ctx, g_seccomp_adapter);

    int ret = seccomp_load(ctx);
    if (ret != 0)
        perror("[SANDBOX] seccomp_load");
    seccomp_release(ctx);
    return ret;
}

int vsb_apply_seccomp(void) { return apply_seccomp_policy(); }

void vsb_set_seccomp_mode(int strict, int allow_c3, int friendly, int permissive) {
    g_seccomp_strict     = strict;
    g_seccomp_allow_c3   = allow_c3;
    g_seccomp_friendly   = friendly;
    g_seccomp_permissive = permissive;
}

void vsb_set_seccomp_adapter(const char *adapter) {
    g_seccomp_adapter = adapter;
}

#else

int vsb_apply_seccomp(void) { return 0; }
void vsb_set_seccomp_mode(int strict, int allow_c3, int friendly, int permissive) {
    (void)strict; (void)allow_c3; (void)friendly; (void)permissive;
}
void vsb_set_seccomp_adapter(const char *adapter) { (void)adapter; }

#endif /* __linux__ */
