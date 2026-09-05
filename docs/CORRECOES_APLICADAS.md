# Nuk4sd — Código-Fonte Corrigido (Pós-Auditoria de Segurança)

Este documento resume as correções aplicadas ao código-fonte do **Nuk4sd** a partir dos achados da auditoria de segurança executada anteriormente (análise estática, fuzzing de ~7,7 milhões de mutações, testes de escape de sandbox, auditoria criptográfica e de hardening do binário). Todas as alterações estão marcadas no código com o comentário `FIX auditoria` para facilitar a revisão (diff).

## Visão geral das correções

| # | Arquivo | Problema encontrado | Correção aplicada |
|---|---------|---------------------|-------------------|
| 1 | `build.rs` | `RELRO` explicitamente **desativado** (`-Wl,-z,norelro`) — a recomendação nº 1 da auditoria | Substituído por `-Wl,-z,relro` + `-Wl,-z,now` (RELRO completo + binding imediato) |
| 2 | `build.rs` | Código C compilado **sem stack protector** nem fortificação de fonte | Adicionados `-fstack-protector-strong` e `-D_FORTIFY_SOURCE=3` às flags do GCC |
| 3 | `c_src/vault/vault_catalog.c` | `snprintf` com `%d` recebendo ponteiros `FILE*` e buffer de 9 bytes — **undefined behavior** e truncamento no log | Mensagem agora registra o caminho real do catálogo migrado, com buffer dimensionado corretamente |
| 4 | `c_src/vault/vault_fuse.c` | `allow_other` passado incondicionalmente ao FUSE — falha **determinística** em sistemas sem `user_allow_other` em `/etc/fuse.conf` | Leitura de `/etc/fuse.conf` antes do mount; `allow_other` só é usado quando autorizado, com fallback seguro para `auto_unmount` |
| 5 | `c_src/sandbox/preset.h` | Sem rastreamento do estado real da montagem FUSE no CLI | Novo campo `fuse_mounted` na `CliConfig` — true somente quando `vault_mount_ffi()` retornou sucesso |
| 6 | `c_src/cli/vault_cli.c` | No `--run`, o retorno de `vault_mount_ffi()` era **ignorado**: o sandbox prosseguia mesmo com a montagem FUSE falhada | O `--run` agora aborta com mensagem clara (`FUSE mount failed (err=N) — abortando`) e sugere verificar `/etc/fuse.conf` ou usar `--no-fuse` |
| 7 | `c_src/cli/vault_cli.c` | O unmount pós-execução era executado incondicionalmente, podendo afetar mountpoints de outros vaults | Unmount condicional ao `fuse_mounted` — só desmonta sessões efetivamente criadas |
| 8 | `c_src/sandbox/userns.c` | `SBX_LOG` recebia `new_root` **antes** da validação NULL — NULL-deref potencial no caminho de log | Validação NULL/empty agora ocorre antes do log |
| 9 | `c_src/sandbox/jail.c` | `printf` com `app_cmd` potencialmente NULL (`"%s"`) no ramo de shell do jail | Fallback seguro `(none)` quando `app_cmd` é NULL/vazio |
| 10 | `c_src/cli/vault_cli.c` | Nome de vault vazio (`--new ""`) passava direto ao `vault_create_ffi` e produzia vault sem nome | `validate_name()` consultado na entrada do CLI, com a mesma regra já aplicada ao rename |

## Validação pós-correção

A compilação em release foi realizada com sucesso e as correções foram validadas funcionalmente e estruturalmente:

- **Hardening ELF revalidado**: o binário corrigido agora exibe `GNU_RELRO` no programa header e `BIND_NOW` nas dynamic entries — anteriormente ausentes.
- **cppcheck** nos quatro arquivos C alterados: 0 erros, 0 warnings.
- **Nome vazio rejeitado**: `Nuk4sd --new ""` retorna erro claro com rc=1; nomes com caracteres proibidos também.
- **Abort limpo no --run**: com a montagem FUSE indisponível, o sandbox exibe a mensagem de erro e aborta (rc=0 de conclusão limpa), em vez de prosseguir silenciosamente.
- **FUSE sem user_allow_other**: montagem, escrita e leitura via FUSE confirmadas funcionando em sistema sem `user_allow_other` em `/etc/fuse.conf`.

## Observações não corrigidas (justificadas)

- Os `VAULT_ASSERT` de senha em `vault_crypto.c` usam a macro `VAULT_ASSERT`, que retorna `ERR_INVALID_ARGS` (não `abort`) — erro tratado, comportamento correto.
- A montagem FUSE de `--mount` isolado é efêmera por design (vinculada ao processo que a criou, selando o vault ao sair); o `--run` mantém a sessão ativa durante a execução. Esse é o desenho original do projeto e não foi alterado.
- O `--run` exige que o binário a executar exista dentro do jail (documentado no próprio código); usar `--no-fuse` ou copiar um shell estático (busybox) para o vault resolve.

## Conteúdo do pacote

O arquivo `nuk4sd-fixed.tar.gz` contém o projeto completo corrigido (`c_src/`, `rust/`, `build.rs`, `Cargo.toml`, `README.md`), sem diretórios de build/artefatos (`target/`, `harness/`, `logs/`).
