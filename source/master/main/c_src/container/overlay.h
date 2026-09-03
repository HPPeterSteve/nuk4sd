/*
 * overlay.h
 *
 * Nuk4sd — Container OverlayFS — header público
 *
 * Montagem de overlayfs para VaultContainer com verificação
 * de regras WORM via Vault.worm_flags antes de qualquer operação
 * de escrita na camada upper.
 */

#ifndef NUK4SD_OVERLAY_H
#define NUK4SD_OVERLAY_H

#include "vault_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  mount_overlay — entry point genérico (baixo nível).
 *
 *  Monta lower+upper+work em merged como overlayfs.
 *  vault_root: raiz que upper/work/merged/lower DEVEM ter como prefixo
 *  (verificação via realpath). Passe NULL SOMENTE se os paths já vierem
 *  de uma fonte confiável e pré-validada — nunca com input de usuário.
 *
 *  Retorna 0 em sucesso, -1 em erro.
 * ═══════════════════════════════════════════════════════════════════════════ */
int mount_overlay(const char *upper, const char *work, const char *lower,
                  const char *merged, const char *vault_root);

/* ═══════════════════════════════════════════════════════════════════════════
 *  umount_overlay — lazy-unmount (MNT_DETACH) do ponto de montagem merged.
 *
 *  MNT_DETACH garante que o umount não trava se ainda houver fds abertos
 *  dentro do merged (mesmo padrão do teardown FUSE do vault).
 *
 *  Retorna 0 em sucesso, -1 em erro.
 * ═══════════════════════════════════════════════════════════════════════════ */
int umount_overlay(const char *merged);

/* ═══════════════════════════════════════════════════════════════════════════
 *  overlay_fs_init — entry point de alto nível para containers.
 *
 *  Deriva os paths lower/upper/work/merged de container->path,
 *  checa regras WORM via vault->worm_flags ANTES de qualquer operação
 *  de escrita, e delega a montagem para mount_overlay().
 *
 *  Layout derivado de container->path:
 *    lower  -> <path>/lower
 *    upper  -> <path>/upper  (camada de escrita)
 *    work   -> <path>/work
 *    merged -> <path>/merged (ponto de montagem final)
 *
 *  Se WORM_PROTECT_WRITE ou WORM_PROTECT_SCAN estiver ativo em
 *  vault->worm_flags, a montagem é recusada e retorna -1.
 *
 *  @param container  Não pode ser NULL — fornece path base do container.
 *  @param vault      Não pode ser NULL — usado para checar worm_flags.
 *  Retorna 0 em sucesso, -1 em erro.
 * ═══════════════════════════════════════════════════════════════════════════ */
int overlay_fs_init(const VaultContainer *container, const Vault *vault);

#ifdef __cplusplus
}
#endif

#endif /* NUK4SD_OVERLAY_H */
