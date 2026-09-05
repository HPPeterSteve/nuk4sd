# Correção do EOVERFLOW em `mkdtemp`

**Projeto:** Nuk4sd  
**Data da validação:** 2026-08-13  
**Autor:** Manus AI

## Resumo executivo

O erro `EOVERFLOW` não era causado por falta de permissão simples em `/tmp`. O diagnóstico independente mostrou que o processo executado dentro do user namespace permanecia com namespace UID/GID 0, enquanto o mapa configurado era `1000 1000 1`. Como o namespace UID 0 não estava presente no mapa, o kernel apresentava a credencial do processo como `65534:65534` (`overflowuid:overflowgid`). A libc estática então falhava em `mkdtemp`, embora o diretório fosse `01777` e o filesystem fosse gravável.

O problema era agravado por tmpfs montado sem `uid=` e `gid=` explícitos e pelo diretório temporário do jail ter sido criado pelo processo pai com ownership de root. Após a correção, o processo faz uma transição explícita para o UID/GID mapeado antes da preparação do rootfs, o pai normaliza o ownership do diretório privado do jail antes do `unshare`, e os tmpfs recebem ownership e modo explícitos.

## Causa reproduzida

Antes da correção, o diagnóstico dentro do sandbox reportava:

```text
FAIL|mkdtemp|errno=75|Value too large for defined data type
INFO|uid_gid|65534:65534
INFO|directory_stat|mode=1777|uid=1000|gid=1000|dev=31|ino=1
INFO|statfs|type=0x1021994|name=tmpfs|bsize=4096|blocks=16384|bfree=16384|bavail=16384|flags=0x1026
```

A combinação é determinante: o diretório era `tmpfs`, tinha sticky bit e acesso de escrita, mas o processo não possuía uma credencial UID/GID representável pelo mapa ativo.

## Correções aplicadas

| Área | Alteração |
|---|---|
| User namespace | Adicionada `vsb_enter_mapped_identity()`, que aplica `setresgid()` e `setresuid()` para o UID/GID mapeado e verifica o resultado. |
| Capacidades | `PR_SET_KEEPCAPS` e `capset` mantêm apenas temporariamente as capacidades do namespace para que mounts e pivot possam concluir; o fluxo existente de `vsb_drop_caps()` e `NO_NEW_PRIVS` continua sendo executado depois. |
| Jail privado | O processo pai verifica e ajusta o owner do único diretório temporário privado antes do `fork`/`unshare`, evitando `Permission denied` ao criar o scaffolding do rootfs. |
| `/tmp` | tmpfs passa a usar `uid=<real_uid>,gid=<real_gid>,mode=1777` além de `MS_NOSUID|MS_NODEV`. |
| `/dev/shm` | Ownership e modo explícitos foram adicionados, mantendo `MS_NOSUID|MS_NODEV`. |
| `--rw-home` | O tmpfs efêmero recebe ownership do UID/GID mapeado e modo `0700`. |
| Diagnóstico | `tools/diagnose_tmp.c` e `tools/diagnose_tmp.sh` permanecem independentes, sem privilégios e sem alterar dados preexistentes. |

## Evidência pós-correção

O diagnóstico estático executado dentro do Nuk4sd agora retorna:

```text
INFO|base|/tmp
INFO|uid_gid|1000:1000
INFO|abi|sizeof(off_t)=8|sizeof(time_t)=8|sizeof(void*)=8|file_offset_bits=64
PASS|realpath|/tmp
INFO|directory_stat|mode=1777|uid=1000|gid=1000|dev=31|ino=1
PASS|sticky-bit|set
PASS|access-rwx|read-write-search allowed
INFO|statfs|type=0x1021994|name=tmpfs|bsize=4096|blocks=16384|bfree=16384|bavail=16384|flags=0x1026
PASS|mkdtemp|/tmp/nuk4sd-mkdtemp-CRJ2eX
INFO|created_stat|mode=0700|uid=1000|gid=1000|dev=31|ino=2
PASS|created-owner|matches-effective-uid-gid
PASS|create-write-file|/tmp/nuk4sd-mkdtemp-CRJ2eX/probe-file
PASS|rename-file|/tmp/nuk4sd-mkdtemp-CRJ2eX/probe-file-renamed
PASS|unlink-file|removed
PASS|rmdir|removed
SUMMARY|fails=0
```

O teste também completou a preparação do jail, bind read-only, pivot root, drop de capabilities, limites de recursos, Seccomp e execução do payload com código de saída `0`. A campanha hiper-massiva pós-correção executou 46 repetições em 20 casos: 18 casos retornaram `rc=0`, dois gates de cgroup retornaram `rc=255` de forma esperada porque o host não delega cgroup v2, totalizando 285 marcadores PASS, 21 FAIL esperados/inconclusivos e zero timeout.

## Validação de build

A recompilação release terminou com sucesso usando Rust/Cargo 1.97.1. A suíte Rust terminou com **2 testes aprovados e 0 falhas**. O executável responde `Nuk4sd v0.9.26` e o `--help` foi gerado com 163 linhas.

O build ainda emite 55 warnings de código não utilizado. Eles não bloquearam a correção, mas devem ser tratados em uma rodada de higiene de compilação separada.

## Limitações

A correção foi validada no ambiente atual, incluindo o caminho `--no-fuse` usado pelo diagnóstico. A validação de cgroup continua condicionada à delegação do host. O resultado positivo não substitui testes em kernels, libc, arquiteturas e configurações de cgroup diferentes.

Não foram adicionadas opções permissivas nem removidas regras de Seccomp, Landlock, namespaces, limites ou cleanup. O comportamento de falha de cgroup sem delegação permanece fail-closed.

## Arquivos relevantes

- `c_src/cli/vault_cli.c`
- `c_src/sandbox/userns.c`
- `c_src/sandbox/sandbox.h`
- `c_src/sandbox/mounts.c`
- `tools/diagnose_tmp.c`
- `tools/diagnose_tmp.sh`
- `test-results/diagnose_tmp.static.sandbox.fixed4.log`
- `test-results/diagnose_tmp.host.fixed.log`

## Verificação

O pacote acompanha `SHA256SUMS`. Verifique os artefatos com:

```sh
sha256sum -c SHA256SUMS
```

## Controle de escopo desta rodada

A interface web sobre o backend Nuk4sd foi deliberadamente adiada até a conclusão da correção e da regressão do executor. Nenhum trabalho de interface, containerização de frontend ou contrato web novo foi iniciado nesta rodada; o foco permaneceu restrito ao diagnóstico de `/tmp`, correção de identidade/ownership, mounts, build e validação de segurança.

## Suíte adversarial segura

Foi adicionada `tools/safe_confinement_probe.c` com wrapper `tools/safe_confinement_probe.sh`. O probe testa, sem persistência ou exfiltração, escrita em caminhos do host, leitura de `/proc/kcore`, ptrace do PID 1, criação de namespaces aninhados, alteração do hostname, montagem de tmpfs e escrita somente em um workspace temporário próprio.

O baseline executado fora do Nuk4sd apresentou as capacidades esperadas do ambiente de teste: criação de namespaces e montagem de tmpfs privado foram possíveis, mas o workspace foi removido ao final. Dentro do Nuk4sd, usando bind read-only absoluto e binário estático, todos os vetores proibidos foram bloqueados por ausência do caminho, `EPERM` ou política de Seccomp; a escrita privada funcionou somente no workspace temporário e a limpeza foi confirmada. Resultado final: `SUMMARY|fails=0`, processo filho com `exit_code=0`.

O teste inicialmente produziu um falso positivo ao consultar `/proc/1/mem`: em um PID namespace, PID 1 é o próprio processo do jail. O probe foi corrigido para usar `/proc/kcore`, eliminando essa ambiguidade sem alterar o executor.
