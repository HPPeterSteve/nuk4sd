/*
 * seccomp.c
 *
 * Nuk4sd — Hardened Sandbox — Layer 5: Seccomp-BPF
 * Extraído de vault_sandbox.c 
 */

#include "sandbox.h"

#ifdef __linux__

/* ─────────────────────────────────────────────────────────────────────────
 *  apply_seccomp_policy(): Seccomp-BPF — Layer 5
 *
 *  g_seccomp_strict=0 (padrão): allowlist completa, clone3 permitido
 *  g_seccomp_strict=1 : remove clone3, userfaultfd, shmget/shmat, sockets
 *  g_seccomp_allow_c3=1: mesmo em strict, re-adiciona clone3 (multithread)
 *
 *  g_seccomp_friendly=1 (--friendly-sandbox): libera SÓ um punhado de
 *  syscalls de "housekeeping" de arquivo (fsync/fdatasync/renameat2) que
 *  a allowlist padrão não tinha e que programas comuns usam pra gravar
 *  estado em disco com segurança (ex.: o erro do Glean/Firefox — "Could
 *  not write ... privileges to complete"). NÃO mexe em chroot/capset/
 *  mount/setuid/setgid — essas continuam EPERM independente desta flag.
 *  Ortogonal a g_seccomp_strict: pode ligar as duas ao mesmo tempo.
 *
 *  g_seccomp_permissive=1 (--permissive): libera chroot/capset/setuid/
 *  setgid no filtro — o mesmo caminho que o Firejail escolhe pra deixar
 *  o app GUI (Firefox, Chromium, etc.) montar o PRÓPRIO sandbox interno
 *  em vez de sempre falhar com EPERM. mount/pivot_root/ptrace continuam
 *  bloqueados independente desta flag — só o necessário pro sandbox do
 *  app em si é liberado. Ortogonal às outras duas flags.
 *
 *  Vulnerabilidade clone(CLONE_NEWUSER): bloqueada via argumento mascarado.
 *  Flags de namespace em clone() causam KILL imediato (não EPERM).
 * ───────────── */
static int g_seccomp_strict     = 0;
static int g_seccomp_allow_c3   = 0;
static int g_seccomp_friendly   = 0;
static int g_seccomp_permissive = 0;

static int apply_seccomp_policy(void)
{
    /* Denylist approach: default allow, block only dangerous syscalls. */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx)
    {
        perror("[SANDBOX] seccomp_init");
        return -1;
    }

    /* As duas syscalls mais perigosas (Kill imediato) */
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(kexec_load), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_writev), 0);

    /* Fronteira do Sandbox (EPERM) */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(pivot_root), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(perf_event_open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(userfaultfd), 0);

    /* Syscalls sensíveis (condicionadas a g_seccomp_permissive) */
    if (!g_seccomp_permissive) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chroot), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(capset), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setuid), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setgid), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount2), 0);
    }

    /* Sandbox Strict: bloqueia sockets, mem compartilhada e etc */
    if (g_seccomp_strict) {
        if (!g_seccomp_allow_c3) {
            seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone3), 0);
        }
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(connect), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bind), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(listen), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(accept), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(accept4), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendto), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvfrom), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socketpair), 0);
        
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(shmget), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(shmat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(shmctl), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(shmdt), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(memfd_create), 0);
    }

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

#endif /* __linux__ */
