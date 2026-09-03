/*
 * nuk_sandbox.h [EXPERIMENTAL]
 *
 * API C da biblioteca de criação e gerenciamento de sandbox + leitor de Nukfile.
 */

#ifndef NUK4SD_EXPERIMENTAL_NUK_SANDBOX_H
#define NUK4SD_EXPERIMENTAL_NUK_SANDBOX_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NukSandbox NukSandbox;

typedef enum {
    NUK_BIND_READ_ONLY  = 0,
    NUK_BIND_READ_WRITE = 1,
    NUK_BIND_BLACKLIST  = 2
} NukBindType;

/* Instancia uma nova estrutura de sandbox */
NukSandbox *nuk_sandbox_create(void);

/* Carrega e aplica regras a partir de um arquivo Nukfile */
int nuk_sandbox_load_file(NukSandbox *sb, const char *filepath);

/* Configura o binário e argumentos de execução */
void nuk_sandbox_set_exec(NukSandbox *sb, const char *exec_path, char **argv, int argc);

/* Configuração de rede e nftables */
void nuk_sandbox_set_net_veth(NukSandbox *sb, const char *jail_ip, const char *gw_ip);
void nuk_sandbox_set_nfilter(NukSandbox *sb, const char *jail_name);
void nuk_sandbox_allow_ip(NukSandbox *sb, const char *ip);

/* Supervisor UUID */
void nuk_sandbox_set_uuid(NukSandbox *sb, bool enable);

/* Binds e limites */
void nuk_sandbox_add_bind(NukSandbox *sb, const char *path, NukBindType type);
void nuk_sandbox_set_max_mem(NukSandbox *sb, int mem_gb);
void nuk_sandbox_set_max_procs(NukSandbox *sb, int max_procs);

/* Lança o processo isolado */
int nuk_sandbox_run(NukSandbox *sb);

/* Libera os recursos alocados */
void nuk_sandbox_free(NukSandbox *sb);

#ifdef __cplusplus
}
#endif

#endif /* NUK4SD_EXPERIMENTAL_NUK_SANDBOX_H */
