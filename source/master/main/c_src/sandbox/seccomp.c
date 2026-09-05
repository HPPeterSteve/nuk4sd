/*
 * seccomp.c
 *
 * Nuk4sd - Hardened Sandbox - Layer 5: Seccomp-BPF
 * Extraído de vault_sandbox.c (split modular, estilo Firejail).
 */

#include "sandbox.h"

#ifdef __linux__
#include <errno.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>

static uint32_t g_seccomp_allow = 0;

static int apply_seccomp_policy(void) {
    /* Denylist approach: default allow, block only dangerous syscalls. */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        perror("[SANDBOX] seccomp_init");
        return -1;
    }

    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(kexec_load), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_writev), 0);

    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 1,
                     SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER));
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
                     SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER));
#ifdef CLONE_NEWCGROUP
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 1,
                     SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWCGROUP, CLONE_NEWCGROUP));
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
                     SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWCGROUP, CLONE_NEWCGROUP));
#endif

    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(perf_event_open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_readv), 0);

    if (!(g_seccomp_allow & SALLOW_SOCKET))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 0);
    if (!(g_seccomp_allow & SALLOW_BIND))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bind), 0);
    if (!(g_seccomp_allow & SALLOW_LISTEN))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(listen), 0);
    if (!(g_seccomp_allow & SALLOW_ACCEPT)) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(accept), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(accept4), 0);
    }
    if (!(g_seccomp_allow & SALLOW_CONNECT))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(connect), 0);
    if (!(g_seccomp_allow & SALLOW_SENÃO))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendto), 0);
    if (!(g_seccomp_allow & SALLOW_RECVFROM))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvfrom), 0);
    if (!(g_seccomp_allow & SALLOW_SENDMSG))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendmsg), 0);
    if (!(g_seccomp_allow & SALLOW_RECVMSG))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvmsg), 0);
    if (!(g_seccomp_allow & SALLOW_SOCKETPAIR))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socketpair), 0);
    if (!(g_seccomp_allow & SALLOW_GETSOCKOPT))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(getsockopt), 0);
    if (!(g_seccomp_allow & SALLOW_SETSOCKOPT))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setsockopt), 0);
    if (!(g_seccomp_allow & SALLOW_SHMGET))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(shmget), 0);
    if (!(g_seccomp_allow & SALLOW_SHMAT)) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(shmat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(shmdt), 0);
    }
    if (!(g_seccomp_allow & SALLOW_SHMCTL))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(shmctl), 0);
    if (!(g_seccomp_allow & SALLOW_MEMFD))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(memfd_create), 0);
    if (!(g_seccomp_allow & SALLOW_CLONE3))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone3), 0);

    if (!(g_seccomp_allow & SALLOW_FUTEX)) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(futex), 0);
#ifdef __NR_futex_waitv
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(futex_waitv), 0);
#endif
    }

    if (!(g_seccomp_allow & SALLOW_FSYNC)) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fsync), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fdatasync), 0);
    }
    if (!(g_seccomp_allow & SALLOW_RENAMEAT2))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(renameat2), 0);
    if (!(g_seccomp_allow & SALLOW_INOTIFY)) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(inotify_add_watch), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(inotify_rm_watch), 0);
    }
    if (!(g_seccomp_allow & SALLOW_SPLICE)) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(splice), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(tee), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendfile), 0);
    }
    if (!(g_seccomp_allow & SALLOW_TIMERFD)) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(timerfd_create), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(timerfd_settime), 0);
    }
    if (!(g_seccomp_allow & SALLOW_SIGNALFD)) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(signalfd), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(signalfd4), 0);
    }

    if (!(g_seccomp_allow & SALLOW_USERFAULTFD))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(userfaultfd), 0);
    if (!(g_seccomp_allow & SALLOW_PTRACE))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0);
    if (!(g_seccomp_allow & SALLOW_BPF))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0);

    if (!(g_seccomp_allow & SALLOW_MOUNT)) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount2), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(pivot_root), 0);
    }
    if (!(g_seccomp_allow & SALLOW_CHROOT))
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chroot), 0);
    if (!(g_seccomp_allow & SALLOW_SETUID)) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setuid), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setgid), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(capset), 0);
    }

    int ret = seccomp_load(ctx);
    if (ret != 0)
        perror("[SANDBOX] seccomp_load");
    seccomp_release(ctx);
    return ret;
}

int vsb_apply_seccomp(void) {
    return apply_seccomp_policy();
}

void vsb_set_seccomp_mode(uint32_t seccomp_allow) {
    g_seccomp_allow = seccomp_allow;
}

#endif /* __linux__ */
