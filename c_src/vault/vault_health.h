/*
 * vault_health.h
 *
 * Nuk4sd — Sandbox Health Inspector — public header
 */

#ifndef VAULT_HEALTH_H
#define VAULT_HEALTH_H

#include <sys/types.h>

/*
 * sandbox_health_check(pid)
 *
 * Inspects process <pid> via /proc and outputs a JSON report to stdout
 * containing the following fields:
 *   - caps_dropped       : bool  (CapEff == 0)
 *   - no_new_privs       : bool  (NoNewPrivs == 1)
 *   - seccomp            : int   (0=off, 1=strict, 2=filter)
 *   - ns_user_isolated   : bool  (user namespace ≠ host)
 *   - ns_mnt_isolated    : bool  (mount namespace ≠ host)
 *   - ns_net_isolated    : bool  (network namespace ≠ host)
 *   - ns_pid_isolated    : bool  (PID namespace ≠ host)
 *   - verdict            : "isolated" | "partial" | "exposed"
 *   - issues             : list of strings detailing issues
 *
 * Returns 0 on success, 1 if PID does not exist.
 */
int sandbox_health_check(pid_t pid);

#endif /* VAULT_HEALTH_H */
