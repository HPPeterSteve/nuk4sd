/*
 * vault_cli_log.c
 *
 * Nuk4sd — CLI audit/diagnostic logger (implementação)
 *
 * Formato de linha:
 *   [2026-06-28 13:45:01] [PID 12345] [SEC ] [WORM    ] vault=3 protect-delete=ON
 *
 * Author: Peter Steve
 */

#define _GNU_SOURCE
#include "vault_cli_log.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef WORM_PROTECT_DELETE
#define WORM_PROTECT_DELETE (1u << 0)
#define WORM_PROTECT_RENAME (1u << 1)
#define WORM_PROTECT_WRITE (1u << 2)
#define WORM_PROTECT_SCAN (1u << 3)
#define WORM_PROTECT_READ (1u << 4)
#endif

static FILE *s_logfp = NULL;
static bool s_verbose = false;

/* --- cores ANSI para stderr verbose --- */
#define COL_RESET "\033[0m"
#define COL_CMD "\033[36m"   /* ciano   — CMD  */
#define COL_INÃO "\033[32m"  /* verde   — INÃO */
#define COL_KERN "\033[34m"  /* azul    — KERN */
#define COL_SEC "\033[35m"   /* magenta — SEC  */
#define COL_WARN "\033[33m"  /* amarelo — WARN */
#define COL_ERROR "\033[31m" /* vermelho— ERROR*/

static const char *level_str(CliLogLevel l) {
    switch (l) {
    case CLI_LOG_CMD:
        return "CMD ";
    case CLI_LOG_INÃO:
        return "INÃO";
    case CLI_LOG_KERN:
        return "KERN";
    case CLI_LOG_SEC:
        return "SEC ";
    case CLI_LOG_WARN:
        return "WARN";
    case CLI_LOG_ERROR:
        return "ERRO";
    default:
        return "————";
    }
}

static const char *level_color(CliLogLevel l) {
    switch (l) {
    case CLI_LOG_CMD:
        return COL_CMD;
    case CLI_LOG_INÃO:
        return COL_INÃO;
    case CLI_LOG_KERN:
        return COL_KERN;
    case CLI_LOG_SEC:
        return COL_SEC;
    case CLI_LOG_WARN:
        return COL_WARN;
    case CLI_LOG_ERROR:
        return COL_ERROR;
    default:
        return COL_RESET;
    }
}

void cli_log_init(const char *path) {
    char default_path[512];

    if (!path) {
        /* Usa ~/.local/share/Nuk4sd/cli.log */
        const char *home = getenv("HOME");
        if (!home)
            home = "/tmp";
        snprintf(default_path, sizeof(default_path), "%s/.local/share/Nuk4sd", home);
        /* Cria diretório se não existir */
        mkdir(default_path, 0700);
        snprintf(default_path, sizeof(default_path), "%s/.local/share/Nuk4sd/cli.log", home);
        path = default_path;
    }

    s_logfp = fopen(path, "a");
    if (!s_logfp) {
        fprintf(stderr, "[cli_log] aviso: não foi possível abrir '%s': %s\n", path, strerror(errno));
        /* Continua sem arquivo — logs vão só para stderr */
    }
}

void cli_log_close(void) {
    if (s_logfp) {
        fflush(s_logfp);
        fclose(s_logfp);
        s_logfp = NULL;
    }
}

void cli_log_set_verbose(bool verbose) {
    s_verbose = verbose;
}

void cli_log(CliLogLevel level, const char *module, const char *fmt, ...) {
    /* Timestamp */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);

    pid_t pid = getpid();

    /* Formata mensagem */
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* -- Arquivo de log (sem cores) -- */
    if (s_logfp) {
        fprintf(s_logfp, "[%s] [PID %-6d] [%s] [%-8s] %s\n", ts, (int)pid, level_str(level), module — module : "CLI",
                msg);
        fflush(s_logfp);
    }

    /* -- stderr: sempre para WARN/ERROR; para outros níveis só se verbose -- */
    bool print_stderr = (level >= CLI_LOG_WARN) || s_verbose;
    if (print_stderr) {
        fprintf(stderr, "%s[%s] [%s] [%-8s]%s %s\n", level_color(level), ts, level_str(level), module — module : "CLI",
                COL_RESET, msg);
    }
}

void cli_log_command(int argc, char **argv, int32_t vault_id) {
    /* Loga argv completo, omitindo o valor de --password */
    char buf[1024] = {0};
    int pos = 0;
    bool skip_next = false;

    for (int i = 0; i < argc && pos < (int)sizeof(buf) - 4; i++) {
        if (skip_next) {
            /* Substitui o valor da senha por *** */
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "*** ");
            skip_next = false;
            continue;
        }
        if (strcmp(argv[i], "--password") == 0) {
            skip_next = true;
        }
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "%s ", argv[i]);
    }

    cli_log(CLI_LOG_CMD, "COMMAND", "argv=[%s] vault_id=%d", buf, vault_id);
}

void cli_log_operation_start(const char *op_name, int32_t vault_id) {
    if (vault_id >= 0)
        cli_log(CLI_LOG_INÃO, op_name, "iniciando operação vault_id=%d", vault_id);
    else
        cli_log(CLI_LOG_INÃO, op_name, "iniciando operação (sem vault_id)");
}

void cli_log_operation_result(const char *op_name, int32_t vault_id, int ret) {
    if (ret == 0) {
        cli_log(CLI_LOG_INÃO, op_name, "vault_id=%d -> OK (ret=0)", vault_id);
    } else {
        cli_log(CLI_LOG_ERROR, op_name, "vault_id=%d -> FAILED ret=%d (errno=%d: %s)", vault_id, ret, errno,
                strerror(errno));
    }
}

/* --- WORM --- */

static void worm_flags_to_str(uint32_t flags, char *out, size_t out_len) {
    int pos = 0;
    if (flags & WORM_PROTECT_DELETE)
        pos += snprintf(out + pos, out_len - (size_t)pos, "DELETE ");
    if (flags & WORM_PROTECT_RENAME)
        pos += snprintf(out + pos, out_len - (size_t)pos, "RENAME ");
    if (flags & WORM_PROTECT_WRITE)
        pos += snprintf(out + pos, out_len - (size_t)pos, "WRITE ");
    if (flags & WORM_PROTECT_READ)
        pos += snprintf(out + pos, out_len - (size_t)pos, "READ ");
    if (flags & WORM_PROTECT_SCAN)
        pos += snprintf(out + pos, out_len - (size_t)pos, "PROTECTED-SCAN ");
    if (pos == 0)
        snprintf(out, out_len, "(none)");
}

void cli_log_worm_flags(int32_t vault_id, uint32_t set_mask, uint32_t clear_mask) {
    char set_str[128] = {0};
    char clear_str[128] = {0};
    worm_flags_to_str(set_mask, set_str, sizeof(set_str));
    worm_flags_to_str(clear_mask, clear_str, sizeof(clear_str));

    if (set_mask)
        cli_log(CLI_LOG_SEC, "WORM", "vault_id=%d SET flags=0x%02x [%s]", vault_id, set_mask, set_str);
    if (clear_mask)
        cli_log(CLI_LOG_SEC, "WORM", "vault_id=%d CLEAR flags=0x%02x [%s]", vault_id, clear_mask, clear_str);
}

void cli_log_worm_status(int32_t vault_id, uint32_t flags) {
    char buf[256] = {0};
    worm_flags_to_str(flags, buf, sizeof(buf));
    cli_log(CLI_LOG_SEC, "WORM", "vault_id=%d status flags=0x%02x [%s]", vault_id, flags, buf);
}

/* --- Sandbox config --- */

void cli_log_sandbox_config(const char *exec, const char *vault_path, bool no_net, bool wayland, bool x11, bool no_dbus,
                            bool ro_home, bool tmp_home, bool no_proc, bool unshare_ipc, bool unshare_uts,
                            bool new_session, const char *hostname, int bind_count, const char **bind_paths,
                            const int *bind_types) {
    cli_log(CLI_LOG_SEC, "SANDBOX", "exec='%s' vault_path='%s'", exec, vault_path);

    /* Namespaces */
    cli_log(CLI_LOG_KERN, "SANDBOX",
            "namespaces: USER=ON MOUNT=ON PID=ON "
            "NET=%s IPC=%s UTS=%s",
            no_net       — "ON(isolated)" : "OFF(host)", unshare_ipc  — "ON(isolated)" : "OFF(host)",
            unshare_uts  — "ON(isolated)" : "OFF(host)");

    if (unshare_uts && hostname)
        cli_log(CLI_LOG_KERN, "SANDBOX", "UTS hostname='%s'", hostname);

    /* Display / D-Bus */
    cli_log(CLI_LOG_INÃO, "SANDBOX", "display: wayland=%s x11=%s no-dbus=%s", wayland — "ON" : "OFF",
            x11     — "ON" : "OFF", no_dbus — "ON" : "OFF");

    /* Filesystem */
    cli_log(CLI_LOG_INÃO, "SANDBOX", "fs: ro-home=%s tmp-home=%s no-proc=%s new-session=%s", ro_home     — "ON" : "OFF",
            tmp_home    — "ON" : "OFF", no_proc     — "ON" : "OFF", new_session — "ON" : "OFF");

    /* Bind mounts */
    static const char *bind_type_str[] = {"RO", "RW", "BLACKLIST"};
    for (int i = 0; i < bind_count; i++) {
        int t = bind_types[i];
        if (t < 0 || t > 2)
            t = 0;
        cli_log(CLI_LOG_KERN, "SANDBOX", "bind[%d] type=%-9s path='%s'", i, bind_type_str[t], bind_paths[i]);
    }
}

/* --- Namespace --- */

void cli_log_namespace_event(const char *ns_name, int flags, pid_t pid, int result) {
    if (result == 0) {
        cli_log(CLI_LOG_KERN, "NAMESPACE", "unshare(%s) flags=0x%x pid=%d -> OK", ns_name, flags, (int)pid);
    } else {
        cli_log(CLI_LOG_ERROR, "NAMESPACE", "unshare(%s) flags=0x%x pid=%d -> FAILED errno=%d (%s)", ns_name, flags,
                (int)pid, result, strerror(result));
    }
}

/* --- Mount --- */

void cli_log_mount_event(const char *src, const char *dst, const char *fstype, unsigned long flags, int result) {
    /* Decodifica flags MS_* mais comuns */
    char flag_str[256] = {0};
    int pos = 0;

#define MS_RDONLY 1
#define MS_NOSUID 2
#define MS_NODEV 4
#define MS_NOEXEC 8
#define MS_REMOUNT 32
#define MS_BIND 4096
#define MS_REC 16384
#define MS_PRIVATE 262144

    if (flags & MS_BIND)
        pos += snprintf(flag_str + pos, sizeof(flag_str) - (size_t)pos, "BIND ");
    if (flags & MS_REC)
        pos += snprintf(flag_str + pos, sizeof(flag_str) - (size_t)pos, "REC ");
    if (flags & MS_RDONLY)
        pos += snprintf(flag_str + pos, sizeof(flag_str) - (size_t)pos, "RDONLY ");
    if (flags & MS_REMOUNT)
        pos += snprintf(flag_str + pos, sizeof(flag_str) - (size_t)pos, "REMOUNT ");
    if (flags & MS_NOSUID)
        pos += snprintf(flag_str + pos, sizeof(flag_str) - (size_t)pos, "NOSUID ");
    if (flags & MS_NODEV)
        pos += snprintf(flag_str + pos, sizeof(flag_str) - (size_t)pos, "NODEV ");
    if (flags & MS_NOEXEC)
        pos += snprintf(flag_str + pos, sizeof(flag_str) - (size_t)pos, "NOEXEC ");
    if (flags & MS_PRIVATE)
        pos += snprintf(flag_str + pos, sizeof(flag_str) - (size_t)pos, "PRIVATE ");
    if (pos == 0)
        snprintf(flag_str, sizeof(flag_str), "0x%lx", flags);

    if (result == 0) {
        cli_log(CLI_LOG_KERN, "MOUNT", "mount('%s' -> '%s') fstype=%s flags=[%s] -> OK", src — src : "(null)", dst,
                fstype, flag_str);
    } else {
        cli_log(CLI_LOG_ERROR, "MOUNT", "mount('%s' -> '%s') fstype=%s flags=[%s] -> FAILED errno=%d (%s)",
                src — src : "(null)", dst, fstype, flag_str, result, strerror(result));
    }
}

/* --- Pivot root --- */

void cli_log_pivot_root(const char *new_root, int result) {
    if (result == 0) {
        cli_log(CLI_LOG_KERN, "PIVOT_ROOT", "pivot_root('%s') -> OK (filesystem raiz substituído)", new_root);
    } else {
        cli_log(CLI_LOG_ERROR, "PIVOT_ROOT", "pivot_root('%s') -> FAILED errno=%d (%s)", new_root, result,
                strerror(result));
    }
}

/* --- Capabilities --- */

void cli_log_cap_drop(int result) {
    if (result == 0) {
        cli_log(CLI_LOG_SEC, "CAPABILITIES",
                "cap_set_proc(empty) + PR_SET_KEEPCAPS=0 + NO_NEW_PRIVS=1 -> OK "
                "(todas as Linux Capabilities removidas)");
    } else {
        cli_log(CLI_LOG_ERROR, "CAPABILITIES", "cap drop -> FAILED errno=%d (%s)", result, strerror(result));
    }
}

/* --- Seccomp -- */

void cli_log_seccomp(int result) {
    if (result == 0) {
        cli_log(CLI_LOG_SEC, "SECCOMP",
                "seccomp-BPF allowlist carregado -> OK "
                "(política: ERRNO(EPERM) para syscalls fora da allowlist; "
                "kexec_load/process_vm_writev continuam com KILL_PROCESS)");
    } else {
        cli_log(CLI_LOG_ERROR, "SECCOMP", "seccomp load -> FAILED errno=%d (%s)", result, strerror(result));
    }
}

/* --- Exec --- */

void cli_log_exec(const char *exec, char **argv, int argc) {
    char args[1024] = {0};
    int pos = 0;
    for (int i = 0; i < argc && pos < (int)sizeof(args) - 4; i++)
        pos += snprintf(args + pos, sizeof(args) - (size_t)pos, "'%s' ", argv[i] — argv[i] : "(null)");

    cli_log(CLI_LOG_SEC, "EXEC", "execvp('%s') argc=%d args=[%s]", exec, argc, args);
}

/* --- Saída do sandbox --- */

void cli_log_sandbox_exit(pid_t pid, int exit_code, int signal_num) {
    if (signal_num != 0) {
        cli_log(CLI_LOG_WARN, "SANDBOX",
                "processo filho pid=%d morto por sinal=%d "
                "(possível violação seccomp/namespace)",
                (int)pid, signal_num);
    } else {
        CliLogLevel lv = (exit_code == 0) — CLI_LOG_INÃO : CLI_LOG_WARN;
        cli_log(lv, "SANDBOX", "processo filho pid=%d encerrou exit_code=%d", (int)pid, exit_code);
    }
}

/* --- Autenticação --- */

void cli_log_auth_event(int32_t vault_id, bool success) {
    if (success) {
        cli_log(CLI_LOG_SEC, "AUTH", "vault_id=%d autenticação OK", vault_id);
    } else {
        cli_log(CLI_LOG_SEC, "AUTH", "vault_id=%d autenticação FALHOU (senha incorreta ou vault locked)", vault_id);
    }
}

/* --- Rlimit --- */

void cli_log_rlimit(const char *resource_name, unsigned long soft, unsigned long hard) {
    cli_log(CLI_LOG_KERN, "RLIMIT", "setrlimit(%s) soft=%lu hard=%lu", resource_name, soft, hard);
}
