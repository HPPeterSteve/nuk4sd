/*
 * nukfile.h [EXPERIMENTAL]
 *
 * Linguagem declarativa Nukfile para o Nuk4sd.
 * Permite definir isolamento, cofres, rede, nftables, UUID e limites
 * de forma modular com suporte a herança via `include`.
 *
 * Módulo experimental em c_src/experimental/
 */

#ifndef NUK4SD_EXPERIMENTAL_NUKFILE_H
#define NUK4SD_EXPERIMENTAL_NUKFILE_H

#include "../sandbox/preset.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * [EXPERIMENTAL]
 * Faz a análise sintática de um arquivo Nukfile e preenche a estrutura CliConfig.
 *
 * Suporta:
 *   - Herança modular via `include <caminho>`
 *   - Bases pré-definidas (ex: include "base/gui", include "base/server", include "base/strict")
 *   - Diretivas de rede (net, nfilter, allow-ip)
 *   - Diretivas de filesystem (read-only, read-write, blacklist, private-tmp, ro-home, etc.)
 *   - Diretivas de segurança (seccomp, caps-drop, uuid)
 *   - Diretivas de recursos (max-mem, max-procs, max-fds)
 *   - Execução (exec/run, vault)
 *
 * Retorno: 0 em caso de sucesso, -1 em caso de erro.
 */
int nukfile_parse(const char *filepath, CliConfig *cfg);

#ifdef __cplusplus
}
#endif

#endif /* NUK4SD_EXPERIMENTAL_NUKFILE_H */
