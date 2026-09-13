/*
 * vault_cli_log.h
 *
 * Nuk4sd — CLI audit/diagnostic logger
 *
 * Comprehensive logging of all CLI operations: commands, flags, results,
 * kernel calls, namespaces, seccomp, bind mounts, permissions.
 *
 * Log format:
 *   [YYYY-MM-DD HH:MM:SS] [PID xxxxx] [LEVEL] [MODULE] message
 *
 * Levels:
 *   CLI_LOG_CMD   — command received and flags parsed
 *   CLI_LOG_INFO  — normal operation progress
 *   CLI_LOG_KERN  — kernel interactions (syscalls, namespaces, mounts)
 *   CLI_LOG_SEC   — security events (caps, seccomp, WORM, auth)
 *   CLI_LOG_WARN  — non-fatal warnings
 *   CLI_LOG_ERROR — failures
 *
 * Author: Peter Steve
 */

#ifndef VAULT_CLI_LOG_H
#define VAULT_CLI_LOG_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

typedef enum {
    CLI_LOG_CMD   = 0,   /* command + flags received                 */
    CLI_LOG_INFO  = 1,   /* operation progress                       */
    CLI_LOG_KERN  = 2,   /* kernel interaction (mount, ns, prctl)    */
    CLI_LOG_SEC   = 3,   /* security (auth, caps, seccomp, WORM)     */
    CLI_LOG_WARN  = 4,   /* non-fatal warning                        */
    CLI_LOG_ERROR = 5,   /* failure                                  */
} CliLogLevel;



/*
 * cli_log_init()
 *
 * Opens log file in append mode. Must be called once at the start of
 * vault_cli_parse_and_exec(). If file cannot be opened, logs go
 * to stderr only (non-fatal).
 *
 * Default path is ~/.local/share/Nuk4sd/cli.log (same directory as catalog).
 * If path == NULL, uses default path.
 */
void cli_log_init(const char *path);

/*
 * cli_log_close()
 *
 * Closes log file. Call at application shutdown.
 */
void cli_log_close(void);



/*
 * cli_log(level, module, fmt, ...)
 *
 * Logs a formatted line. Sent to file + stderr (only WARN/ERROR
 * go to stderr when not in verbose mode).
 *
 * Example:
 *   cli_log(CLI_LOG_KERN, "NAMESPACE", "unshare(CLONE_NEWUSER) → pid=%d", pid);
 */
void cli_log(CliLogLevel level, const char *module, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/*
 * cli_log_set_verbose(bool)
 *
 * If verbose=true, all levels print to stderr.
 * By default, only WARN and ERROR go to stderr.
 */
void cli_log_set_verbose(bool verbose);



/*
 * cli_log_command()
 *
 * Logs received command (complete argc/argv) and selected vault_id.
 * Called right after parse_flags(), before dispatch().
 * Never logs value of --password to avoid exposing passwords.
 */
void cli_log_command(int argc, char **argv, int32_t vault_id);

/*
 * cli_log_operation_start(op_name, vault_id)
 *
 * Logs start of a specific operation (e.g., "ENCRYPT", "MOUNT", "SCAN").
 */
void cli_log_operation_start(const char *op_name, int32_t vault_id);

/*
 * cli_log_operation_result(op_name, vault_id, ret)
 *
 * Logs result of an operation: OK if ret==0, FAILED(ret) otherwise.
 */
void cli_log_operation_result(const char *op_name, int32_t vault_id, int ret);

/*
 * cli_log_worm_flags(vault_id, set_mask, clear_mask)
 *
 * Logs which WORM flags were activated/deactivated and what each bit means.
 */
void cli_log_worm_flags(int32_t vault_id, uint32_t set_mask, uint32_t clear_mask);

/*
 * cli_log_worm_status(vault_id, flags)
 *
 * Logs current state of all WORM bits for a vault.
 */
void cli_log_worm_status(int32_t vault_id, uint32_t flags);

/*
 * cli_log_sandbox_config()
 *
 * Logs full isolation configuration prior to fork():
 *   - target exec
 *   - vault_path
 *   - namespace flags (net, ipc, uts, pid, user, mount)
 *   - display flags (wayland, x11, no-dbus)
 *   - filesystem flags (ro-home, tmp-home, no-proc)
 *   - bind mounts (ro/rw/blacklist) with paths
 *   - configured rlimits
 */
void cli_log_sandbox_config(
    const char  *exec,
    const char  *vault_path,
    bool         no_net,
    bool         wayland,
    bool         x11,
    bool         no_dbus,
    bool         ro_home,
    bool         tmp_home,
    bool         no_proc,
    bool         unshare_ipc,
    bool         unshare_uts,
    bool         new_session,
    const char  *hostname,
    int          bind_count,
    const char **bind_paths,    /* array of paths */
    const int   *bind_types     /* 0=RO 1=RW 2=BLACKLIST */
);

/*
 * cli_log_namespace_event(ns_name, flags, pid, result)
 *
 * Logs result of an unshare() or clone() namespace operation.
 *   ns_name: "CLONE_NEWUSER", "CLONE_NEWNET", etc.
 *   flags:   numeric value passed to unshare()
 *   pid:     child process PID (0 if not applicable)
 *   result:  0 = success, != 0 = errno
 */
void cli_log_namespace_event(const char *ns_name, int flags, pid_t pid, int result);

/*
 * cli_log_mount_event(src, dst, fstype, flags, result)
 *
 * Logs a mount() performed by the sandbox:
 *   src:    source (e.g. "/home/pedro", "tmpfs", "proc")
 *   dst:    destination inside jail
 *   fstype: "bind", "tmpfs", "proc", "null", etc.
 *   flags:  MS_BIND | MS_RDONLY | ... (numeric value)
 *   result: 0 = success, != 0 = errno
 */
void cli_log_mount_event(const char *src, const char *dst,
                         const char *fstype, unsigned long flags, int result);

/*
 * cli_log_pivot_root(new_root, result)
 *
 * Logs pivot_root() replacing chroot.
 */
void cli_log_pivot_root(const char *new_root, int result);

/*
 * cli_log_cap_drop(result)
 *
 * Logs drop of all Linux Capabilities + NO_NEW_PRIVS.
 */
void cli_log_cap_drop(int result);

/*
 * cli_log_seccomp(result)
 *
 * Logs application of seccomp-BPF filter (full allowlist).
 */
void cli_log_seccomp(int result);

/*
 * cli_log_exec(exec, argv, argc)
 *
 * Logs final execvp() inside sandbox (complete args).
 * Called immediately before execvp().
 */
void cli_log_exec(const char *exec, char **argv, int argc);

/*
 * cli_log_sandbox_exit(pid, exit_code, signal_num)
 *
 * Logs return of child process after waitpid().
 *   exit_code:  exit code (if exited normally)
 *   signal_num: signal that killed process (0 if not signal)
 */
void cli_log_sandbox_exit(pid_t pid, int exit_code, int signal_num);

/*
 * cli_log_auth_event(vault_id, success)
 *
 * Logs authentication attempt (without logging password).
 */
void cli_log_auth_event(int32_t vault_id, bool success);

/*
 * cli_log_rlimit(resource_name, soft, hard)
 *
 * Logs a setrlimit() applied to child process.
 */
void cli_log_rlimit(const char *resource_name,
                    unsigned long soft, unsigned long hard);

#endif /* VAULT_CLI_LOG_H */