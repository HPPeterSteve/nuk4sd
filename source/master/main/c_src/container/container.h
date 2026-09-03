/*
 * container.h
 *
 * Nuk4sd — Container Runtime — header público
 *
 * Declarações das funções de política de container (whitelist, operabilidade).
 * Para o overlayfs, ver container/overlay.h.
 */

#ifndef NUK4SD_CONTAINER_H
#define NUK4SD_CONTAINER_H

#include "vault_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  Whitelist de operações para containers selados
 *
 *  Por padrão (whitelist_excluded=0), operações na whitelist padrão são
 *  permitidas mesmo com sealed=1. O usuário pode mudar via CLI:
 *    --white-list -e   -> container_whitelist_exclude()  [bloqueia tudo]
 *    --white-list -r   -> container_whitelist_restore()  [restaura padrão]
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Exclui a whitelist — todas as operações seladas são bloqueadas.
 * Equivalente CLI: --white-list -e
 * Retorna 0 em sucesso, -1 se c for NULL. */
int container_whitelist_exclude(VaultContainer *c);

/* Restaura a whitelist padrão.
 * Equivalente CLI: --white-list -r
 * Retorna 0 em sucesso, -1 se c for NULL. */
int container_whitelist_restore(VaultContainer *c);

/* Retorna 1 se o container permite operações (sealed+whitelist considerados),
 * 0 se bloqueado. Não loga — o chamador loga com contexto. */
int container_is_operable(const VaultContainer *c);

#ifdef __cplusplus
}
#endif

#endif /* NUK4SD_CONTAINER_H */
