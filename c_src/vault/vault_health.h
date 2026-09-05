/*
 * vault_health.h
 *
 * Nuk4sd — Sandbox Health Inspector — header público
 */

#ifndef VAULT_HEALTH_H
#define VAULT_HEALTH_H

#include <sys/types.h>

/*
 * sandbox_health_check(pid)
 *
 * Inspeciona o processo <pid> via /proc e emite um relatório JSON
 * para stdout com os seguintes campos:
 *   - caps_dropped       : bool  (CapEff == 0)
 *   - no_new_privs       : bool  (NoNewPrivs == 1)
 *   - seccomp            : int   (0=off, 1=strict, 2=filter)
 *   - ns_user_isolated   : bool  (namespace de usuário ≠ host)
 *   - ns_mnt_isolated    : bool  (namespace de mount ≠ host)
 *   - ns_net_isolated    : bool  (namespace de rede ≠ host)
 *   - ns_pid_isolated    : bool  (namespace de PID ≠ host)
 *   - verdict            : "isolated" | "partial" | "exposed"
 *   - issues             : lista de strings descrevendo problemas
 *
 * Retorna 0 em sucesso, 1 se o PID não existe.
 */
int sandbox_health_check(pid_t pid);

#endif /* VAULT_HEALTH_H */
