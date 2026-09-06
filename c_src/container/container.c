/*
 * container.c
 *
 * Nuk4sd — Container Runtime — utilitários de política
 *
 * Funções de controle da whitelist de operações permitidas em containers
 * selados (sealed=1). Chamadas pelo parser CLI ao processar:
 *   --white-list -e   → container_whitelist_exclude()
 *   --white-list -r   → container_whitelist_restore()
 *
 * Localização: c_src/container/container.c
 * Header:      c_src/container/container.h
 */

#include "container.h"
#include "vault_core.h"

/*
 *  container_whitelist_exclude — exclui a whitelist de um container selado.
 *
 *  Após esta chamada, operações normalmente permitidas pela whitelist padrão
 *  (ex: overlay mount) serão bloqueadas mesmo que o container esteja apenas
 *  selado (não necessariamente com WORM ativo).
 *
 *  Equivalente CLI: --white-list -e
 *
 *  @param c  Container alvo. Não pode ser NULL.
 *  Retorna 0 em sucesso, -1 se c for NULL.
 * */
int container_whitelist_exclude(VaultContainer *c) {
    if (!c) {
        vault_log(LOG_ERROR, "[CONTAINER] container_whitelist_exclude: argumento NULL");
        return -1;
    }
    c->whitelist_excluded = 1;
    vault_log(LOG_WARN,
        "[CONTAINER] whitelist excluída para container '%s' (--white-list -e)"
        " — todas as operações seladas bloqueadas",
        c->path);
    return 0;
}

/*
 *  container_whitelist_restore — restaura a whitelist padrão.
 *
 *  Reverte o efeito de container_whitelist_exclude(). Operações na whitelist
 *  padrão voltam a ser permitidas para containers selados.
 *
 *  Equivalente CLI: --white-list -r
 *
 *  @param c  Container alvo. Não pode ser NULL.
 *  Retorna 0 em sucesso, -1 se c for NULL.
 * */
int container_whitelist_restore(VaultContainer *c) {
    if (!c) {
        vault_log(LOG_ERROR, "[CONTAINER] container_whitelist_restore: argumento NULL");
        return -1;
    }
    c->whitelist_excluded = 0;
    vault_log(LOG_INFO,
        "[CONTAINER] whitelist restaurada para container '%s' (--white-list -r)",
        c->path);
    return 0;
}

/*
 *  container_is_operable — verifica se o container permite a operação
 *  solicitada considerando estado sealed + whitelist.
 *
 *  Retorna 1 se a operação é permitida, 0 se bloqueada.
 *  Não loga — deixa o chamador logar com o contexto correto.
 * */
int container_is_operable(const VaultContainer *c) {
    if (!c) return 0;
    /* Selado + whitelist excluída → nenhuma operação permitida */
    if (c->sealed && c->whitelist_excluded) return 0;
    return 1;
}
