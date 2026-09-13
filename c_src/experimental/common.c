/*
 * common.c [EXPERIMENTAL]
 *
 * Nuk4sd — Mini-Init Supervisor (--init) & Utilidades Compartilhadas
 *
 * Resolve o clássico PID 1 problem para daemons (sshd, bancos de dados, servidores):
 *   - Previne acúmulo de processos zumbis / fantasmas através de reaper loop (waitpid)
 *   - Encaminha sinais de término (SIGTERM, SIGINT, SIGHUP) para o processo payload
 *   - Encerra processos órfãos remanescentes quando o aplicativo principal encerra
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "common.h"
#include "vault_core.h"
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/wait.h>

static volatile sig_atomic_t g_target_pid = 0;

static void sig_forward_handler(int sig) {
    if (g_target_pid > 0) {
        kill(g_target_pid, sig);
    }
}

int nuk_mini_init(const char *exec_path, char **argv) {
    if (!exec_path || !argv)
        return -1;

    /* Configura handlers para repassar sinais ao processo payload */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_forward_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    pid_t child = fork();
    if (child < 0) {
        perror("[INIT] fork failed");
        return 1;
    }

    if (child == 0) {
        /* Restaura handlers padrão no processo filho */
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGHUP, SIG_DFL);

        execvp(exec_path, argv);
        fprintf(stderr, "[INIT] execvp '%s': %s\n", exec_path, strerror(errno));
        _exit(127);
    }

    /* Processo PID 1: Mini-Init Supervisor */
    g_target_pid = child;
    prctl(PR_SET_NAME, "nuk-init", 0, 0, 0);
    vault_log(LOG_INFO, "[INIT] Mini-init PID 1 ativo, supervisionando payload PID %d ('%s')",
              (int)child, exec_path);

    int app_exit_code = 0;
    bool app_exited = false;

    while (1) {
        int st;
        pid_t p = waitpid(-1, &st, 0);
        if (p < 0) {
            if (errno == EINTR)
                continue;
            break; /* Não restam mais processos vivos no namespace */
        }

        /* Se o processo principal (sshd, etc.) encerrou */
        if (p == child) {
            app_exit_code = WIFEXITED(st) ? WEXITSTATUS(st)
                                          : (WIFSIGNALED(st) ? 128 + WTERMSIG(st) : 1);
            app_exited = true;
            vault_log(LOG_INFO, "[INIT] Processo payload %d encerrou com código %d — encerrando processos órfãos",
                      (int)child, app_exit_code);

            /* Envia SIGTERM para todos os outros processos remanescentes no namespace */
            kill(-1, SIGTERM);
        }
    }

    return app_exited ? app_exit_code : 1;
}

#else /* !__linux__ */

int nuk_mini_init(const char *exec_path, char **argv) {
    (void)exec_path;
    (void)argv;
    return -1;
}

#endif /* __linux__ */
