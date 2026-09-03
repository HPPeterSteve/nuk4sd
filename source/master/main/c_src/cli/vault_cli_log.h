/*
 * vault_cli_log.h
 *
 * Nuk4sd — CLI audit/diagnostic logger
 *
 * Log massivo de todas as operações do CLI: comandos, flags, resultados,
 * chamadas ao kernel, namespaces, seccomp, bind mounts, permissões.
 *
 * Formato de log:
 *   [YYYY-MM-DD HH:MM:SS] [PID xxxxx] [LEVEL] [MODULE] mensagem
 *
 * Níveis:
 *   CLI_LOG_CMD   — comando recebido e flags parseadas
 *   CLI_LOG_INFO  — progresso normal de operação
 *   CLI_LOG_KERN  — interações com o kernel (syscalls, namespaces, mounts)
 *   CLI_LOG_SEC   — eventos de segurança (caps, seccomp, WORM, auth)
 *   CLI_LOG_WARN  — avisos não fatais
 *   CLI_LOG_ERROR — falhas
 *
 * Author: Peter Steve
 */

#ifndef VAULT_CLI_LOG_H
#define VAULT_CLI_LOG_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

typedef enum {
    CLI_LOG_CMD   = 0,   /* comando + flags recebidos                */
    CLI_LOG_INFO  = 1,   /* progresso da operação                    */
    CLI_LOG_KERN  = 2,   /* interação com kernel (mount, ns, prctl)  */
    CLI_LOG_SEC   = 3,   /* segurança (auth, caps, seccomp, WORM)    */
    CLI_LOG_WARN  = 4,   /* aviso não fatal                          */
    CLI_LOG_ERROR = 5,   /* falha                                    */
} CliLogLevel;



/*
 * cli_log_init()
 *
 * Abre o arquivo de log em append. Deve ser chamado uma vez no início de
 * vault_cli_parse_and_exec(). Se o arquivo não puder ser aberto, os logs
 * vão apenas para stderr (não é fatal).
 *
 * O caminho padrão é ~/.local/share/Nuk4sd/cli.log  (mesmo diretório
 * do catalog). Se path == NULL, usa o padrão.
 */
void cli_log_init(const char *path);

/*
 * cli_log_close()
 *
 * Fecha o arquivo de log. Chamar no encerramento da aplicação.
 */
void cli_log_close(void);



/*
 * cli_log(level, module, fmt, ...)
 *
 * Loga uma linha formatada. Vai para arquivo + stderr (apenas WARN/ERROR
 * vão para stderr quando não em modo verbose).
 *
 * Exemplo:
 *   cli_log(CLI_LOG_KERN, "NAMESPACE", "unshare(CLONE_NEWUSER) -> pid=%d", pid);
 */
void cli_log(CliLogLevel level, const char *module, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/*
 * cli_log_set_verbose(bool)
 *
 * Se verbose=true, todos os níveis também imprimem no stderr.
 * Por padrão só WARN e ERROR vão para stderr.
 */
void cli_log_set_verbose(bool verbose);



/*
 * cli_log_command()
 *
 * Loga o comando recebido (argc/argv completo) e o vault_id selecionado.
 * Chamado logo após parse_flags(), antes de dispatch().
 * Nunca loga o valor de --password para não expor senhas.
 */
void cli_log_command(int argc, char **argv, int32_t vault_id);

/*
 * cli_log_operation_start(op_name, vault_id)
 *
 * Loga o início de uma operação específica (ex: "ENCRYPT", "MOUNT", "SCAN").
 */
void cli_log_operation_start(const char *op_name, int32_t vault_id);

/*
 * cli_log_operation_result(op_name, vault_id, ret)
 *
 * Loga o resultado de uma operação: OK se ret==0, FAILED(ret) caso contrário.
 */
void cli_log_operation_result(const char *op_name, int32_t vault_id, int ret);

/*
 * cli_log_worm_flags(vault_id, set_mask, clear_mask)
 *
 * Loga quais flags WORM foram ativadas/desativadas e o que cada bit significa.
 */
void cli_log_worm_flags(int32_t vault_id, uint32_t set_mask, uint32_t clear_mask);

/*
 * cli_log_worm_status(vault_id, flags)
 *
 * Loga o estado atual de todos os bits WORM de um vault.
 */
void cli_log_worm_status(int32_t vault_id, uint32_t flags);

/*
 * cli_log_sandbox_config()
 *
 * Loga toda a configuração de isolamento antes do fork():
 *   - exec alvo
 *   - vault_path
 *   - flags de namespace (net, ipc, uts, pid, user, mount)
 *   - flags de display (wayland, x11, no-dbus)
 *   - flags de filesystem (ro-home, tmp-home, no-proc)
 *   - bind mounts (ro/rw/blacklist) com paths
 *   - rlimits configurados
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
    const char **bind_paths,    /* array de paths */
    const int   *bind_types     /* 0=RO 1=RW 2=BLACKLIST */
);

/*
 * cli_log_namespace_event(ns_name, flags, pid, result)
 *
 * Loga o resultado de um unshare() ou clone() de namespace.
 *   ns_name: "CLONE_NEWUSER", "CLONE_NEWNET", etc.
 *   flags:   valor numérico passado ao unshare()
 *   pid:     PID do processo filho (0 se não aplicável)
 *   result:  0 = sucesso, != 0 = errno
 */
void cli_log_namespace_event(const char *ns_name, int flags, pid_t pid, int result);

/*
 * cli_log_mount_event(src, dst, fstype, flags, result)
 *
 * Loga um mount() realizado pelo sandbox:
 *   src:    source (ex: "/home/<user>", "tmpfs", "proc")
 *   dst:    destino dentro do jail
 *   fstype: "bind", "tmpfs", "proc", "null", etc.
 *   flags:  MS_BIND | MS_RDONLY | ... (valor numérico)
 *   result: 0 = sucesso, != 0 = errno
 */
void cli_log_mount_event(const char *src, const char *dst,
                         const char *fstype, unsigned long flags, int result);

/*
 * cli_log_pivot_root(new_root, result)
 *
 * Loga o pivot_root() que substitui o chroot.
 */
void cli_log_pivot_root(const char *new_root, int result);

/*
 * cli_log_cap_drop(result)
 *
 * Loga o drop de todas as Linux Capabilities + NO_NEW_PRIVS.
 */
void cli_log_cap_drop(int result);

/*
 * cli_log_seccomp(result)
 *
 * Loga a aplicação do filtro seccomp-BPF (allowlist completa).
 */
void cli_log_seccomp(int result);

/*
 * cli_log_exec(exec, argv, argc)
 *
 * Loga o execvp() final dentro do sandbox (args completos).
 * Chamado imediatamente antes de execvp().
 */
void cli_log_exec(const char *exec, char **argv, int argc);

/*
 * cli_log_sandbox_exit(pid, exit_code, signal_num)
 *
 * Loga o retorno do processo filho após waitpid().
 *   exit_code:  código de saída (se saiu normalmente)
 *   signal_num: sinal que matou o processo (0 se não foi sinal)
 */
void cli_log_sandbox_exit(pid_t pid, int exit_code, int signal_num);

/*
 * cli_log_auth_event(vault_id, success)
 *
 * Loga tentativa de autenticação (sem logar a senha).
 */
void cli_log_auth_event(int32_t vault_id, bool success);

/*
 * cli_log_rlimit(resource_name, soft, hard)
 *
 * Loga um setrlimit() aplicado ao processo filho.
 */
void cli_log_rlimit(const char *resource_name,
                    unsigned long soft, unsigned long hard);

#endif /* VAULT_CLI_LOG_H */