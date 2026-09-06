# Bugs e Vulnerabilidades — nuk4sd

Catálogo de tudo que foi encontrado, testado e corrigido durante a sessão de
debug do isolamento (`--run`). Ordem cronológica de descoberta. Cada item diz
severidade, onde estava, como foi confirmado, e o estado atual (corrigido /
pendente).

---

## 1. `vault_sandbox.c` era código morto (não um bug, mas armadilha)

**Severidade:** baixa (confusão de manutenção, não segurança)
**Status:** corrigido — arquivo removido

`vault_sandbox.c` era a versão monolítica pré-refactor do sandbox, dividida
depois em 7 arquivos (`caps.c`, `userns.c`, `mounts.c`, `rlimits.c`,
`seccomp.c`, `jail.c`, `common.c`). Ficou no repo, mas **não está na lista de
compilação do `build.rs`** — editar esse arquivo não tem efeito nenhum no
binário real. Confirmado lendo o comentário do próprio `build.rs` que
documenta o split. Removido do projeto.

---

## 2. `uid_map`/`gid_map` sempre hardcoded para `0, 0`

**Severidade:** crítica (segurança)
**Onde:** `jail.c` (`vault_sandbox_open()`, não é o caminho ativo do `--run`)
**Status:** corrigido

`vsb_write_uid_gid_map(pid, 0, 0)` — o `host_uid`/`host_gid` reais eram
capturados via `getuid()`/`getgid()` mas nunca chegavam na função que
escreve o mapa. Resultado: o `uid_map` real era sempre só `"0 0 1"`,
independente de quem invocou o programa — ns-root mapeava pra host-root de
verdade, não para um usuário sem privilégio. A mensagem de log também
mentia, afirmando mapear para `nobody (65534:65534)` quando na prática
mapeava para root real.

**Nota:** esse era o código de `vault_sandbox_open()` (`jail.c`), que se
provou depois **não ser o caminho ativo** do `--run` (ver item 4). O fix foi
aplicado ali mesmo assim por consistência, mas o bug relevante de verdade
era o item 4.

---

## 3. `vault_catalog.c` — `snprintf` com formato errado

**Severidade:** cosmética / baixo risco
**Onde:** `vault_catalog.c:102`
**Status:** identificado, **não corrigido ainda**

```c
char msg[9];
snprintf(msg, sizeof(msg), "Detalhes: %d", src, dst);
```

`%d` esperando um `int`, recebendo um `FILE*` (`src`); `dst` (outro `FILE*`)
sequer é usado. Buffer `msg[9]` também é pequeno demais para o texto
("Detalhes: " já são 10 caracteres). Inofensivo hoje porque nada crítico
depende desse log, mas é lixo de código que deveria ser limpo.

---

## 4. `run_isolated()` (vault_cli.c) é o caminho ativo real — não `jail.c`

**Severidade:** não é bug, é uma descoberta estrutural crítica pra entender
tudo que veio depois
**Status:** documentado

Existem **duas implementações paralelas** de sandbox: `vault_sandbox_open()`
em `jail.c` e `run_isolated()` em `vault_cli.c` (dentro de um bloco
`#ifdef __linux__`). Só a segunda é exercitada pelo `--run` de verdade —
confirmado lendo o `build.rs` e o fluxo de chamadas do CLI. Isso significa
que fixes aplicados só em `jail.c` (como o item 2) não têm efeito no
comportamento observado em testes reais — sempre validar contra
`vault_cli.c`.

---

## 5. Bind-mount do vault feito no processo pai, antes de qualquer privilégio

**Severidade:** crítica (bloqueava rodar sem sudo)
**Onde:** `vault_cli.c`, `run_isolated()`
**Status:** corrigido

```
[RUN] bind-mount vault→jail_root '...'→'...': Operation not permitted
```

O `mount(vault_path, jail_root, ..., MS_BIND|MS_REC, ...)` acontecia no
processo **pai**, antes do `fork()`/`unshare(CLONE_NEWUSER)` — ou seja,
como usuário comum, sem `CAP_SYS_ADMIN`. Funcionava só com sudo (root real
tem a capability incondicionalmente). **Fix:** mover o bind-mount (e o
`vsb_prepare_jail()` que depende dele) pro **filho**, depois do
`unshare(CLONE_NEWNS)`, onde o processo ganha `CAP_SYS_ADMIN` namespaced.

---

## 6. `newuidmap`/`newgidmap` — dependência introduzida e depois removida

**Severidade:** N/A (etapa intermediária de design, não bug do nuk4sd)
**Status:** superada pelo item 7 — não é mais usada

Primeira tentativa de rodar sem sudo: mapa de 2 linhas
(`"0 0 1\n<uid> <uid> 1\n"`) escrito via `newuidmap`/`newgidmap` (setuid-root,
pacote `uidmap`). Motivo de precisar do helper: processo sem `CAP_SETUID`
só pode escrever 1 linha no `uid_map` diretamente.

Essa abordagem foi **abandonada** — ver item 7, o kernel rejeita esse mapa
de qualquer forma, com ou sem `newuidmap`. Código do helper
(`run_id_helper()`) foi removido do `userns.c`.

---

## 7. **[CRÍTICO]** Kernel rejeita `uid_map` com `outside-id` repetido em 2 linhas

**Severidade:** crítica — travou o design duas vezes até ser isolado corretamente
**Onde:** restrição do próprio kernel Linux, não bug do nuk4sd
**Status:** contornado via redesign (item 8)

Testado e confirmado empiricamente (`write()` direto em `/proc/[pid]/uid_map`
como root real, contornando qualquer questão de `CAP_SETUID`):

```
"0 1000 1\n1000 1000 1\n"   →  EINVAL (Invalid argument)
"0 1000 1\n1000 100000 1\n" →  aceito (outside-ids diferentes)
```

O kernel **não permite** o mesmo `ID-outside-ns` aparecer em duas linhas do
mapa, mesmo com `ID-inside-ns` diferentes em cada uma. Isso invalidou por
completo o design de "root de brinquedo (`0`) + segunda linha pro UID real",
que era a base de tudo desde o item 2. `newuidmap` (item 6) reportava
fielmente essa mesma rejeição do kernel — não era limitação do helper.

---

## 8. Redesign: mapa de identidade (`ruid → ruid`, nunca `0`)

**Severidade:** N/A — é o fix definitivo do item 7
**Status:** implementado e testado

Solução: mapa de **uma linha só**, `"<uid> <uid> 1"` (identidade, não
`"0 <uid> 1"`). Duas propriedades confirmadas por teste direto
(fork+unshare+mount como usuário sem privilégio nenhum):

- **Escrita não-privilegiada funciona** com QUALQUER `ID-inside-ns` (não
  precisa ser `0`) — a única exigência do kernel pra escrita sem
  `CAP_SETUID` é 1 linha só, com `outside-id == UID real do processo`.
  Confirmado testando `"1000 1000 1"` como usuário sem privilégio.
- **Capability de `mount()`/`pivot_root()` não depende do valor do UID
  mapeado** — vem de ser o processo que **criou** o namespace, não de ter
  `ns-uid 0`. Confirmado com teste real (`mount(NULL, "/", MS_PRIVATE|MS_REC)`
  bem-sucedido rodando como `ns-uid 1001` via mapa de identidade).

**Consequência em cascata:** o `setresuid()`/`setresgid()` que existia em
`vault_cli.c` (pra "dropar" de ns-root pro UID real depois do pivot) foi
**removido** — não tem mais como funcionar (não existe segundo `ns-id`
mapeado pra cair nele) e não é mais necessário (o processo já É o UID real
desde o início, sem precisar de troca).

---

## 9. **[CRÍTICO]** Firefox recusa rodar com `getuid() == 0`

**Severidade:** crítica — bloqueava totalmente o `--run firefox`
**Onde:** comportamento do próprio Firefox, exposto pelo design do item 2/6
**Status:** resolvido pelo item 8

```
Running Firefox as root in a regular user's session is not supported.
($HOME is /home/pedro which is owned by nobody.)
```

Com o mapa `"0 -> uid_real"` (design anterior ao item 8), `getuid()` dentro
do sandbox retornava `0` — o Firefox recusa rodar categoricamente nessa
condição, independente do `kuid` real por trás do mapeamento. O comentário
original do código (`"apps gráficos como Firefox ou Evince recusam rodar
como root"`) estava correto — só a implementação da correção (via
`setresuid`, item 5 do design antigo) que não tinha como funcionar dado o
item 7. Resolvido de raiz pelo mapa de identidade (item 8): `getuid()`
mostra o UID real diretamente, sem transição de identidade nenhuma.

---

## 10. **[CRÍTICO]** `mknod()` de device node rejeitado em user namespace não-privilegiado

**Severidade:** crítica — causava crash do Firefox (`SIGSEGV`)
**Onde:** restrição do kernel Linux
**Status:** identificado; fix estrutural aplicado no item 11 (a causa raiz
real não era bem o `mknod`, ver abaixo)

Testado e confirmado empiricamente: `mknod()` para criar um device
character (`S_IFCHR`) falha com `EPERM`, **mesmo com capabilities completas
("=ep") dentro de um user namespace não-privilegiado**. É restrição de
segurança deliberada do kernel — namespace "root de brinquedo" nunca pode
fabricar acesso a device nodes reais, não importa quantas capabilities
"tenha" internamente.

```c
mknod("/caminho/fakenull", S_IFCHR | 0666, makedev(1,3));
// → sempre EPERM em userns não-privilegiado, mesmo como "root" lá dentro
```

**Importante:** o código do `nuk4sd` **já não usa `mknod()`** para
`/dev/null` etc — usa `open(dst, O_CREAT|O_WRONLY, 0444)` (arquivo comum,
que deveria funcionar sem problema). O erro observado nos logs
(`"criar node ... Permission denied"`) vinha de **outro lugar** — ver item
11, a causa raiz real.

---

## 11. **[CRÍTICO]** Bind-mount do vault substituía `jail_root` inteiro, não uma subpasta

**Severidade:** crítica — causa raiz de toda a cascata de erros `[FUSE] ...
failed: -13` (dev nodes, `.config`, `.cache`, fontconfig, tudo)
**Onde:** `vault_cli.c`, `run_isolated()`
**Status:** corrigido

A causa raiz real por trás do item 10 (e de praticamente toda cascata de
erros FUSE vista nos logs): o bind-mount

```c
mount(vault_path_orig, jail_root, NULL, MS_BIND | MS_REC, NULL);
```

**substitui** o conteúdo de `jail_root` pelo do vault (FUSE), em vez de
empilhar um dentro do outro. `jail_root` deixava de ser tmpfs real e virava,
na prática, o próprio FUSE do vault — então **qualquer** escrita de
scaffolding do jail (`/dev/null`, `.config`, `.cache`, autodirs de GUI)
acabava sendo roteada pro backend FUSE do vault, que rejeita criação
arbitrária de arquivo/diretório (`EACCES`/-13). O padrão nos logs sempre
tinha o par:

```
[ERROR] [FUSE] create '/dev/null' failed: -13
[RUN] --dev: criar node '.../dev/null': Permission denied
```

confirmando que a falha vinha do FUSE, não de uma restrição de sandbox.

**Fix:** `jail_root` continua tmpfs real na raiz; o vault passou a ser
bind-montado numa **subpasta dedicada** (`jail_root/vault`), não na raiz.
Scaffolding do jail roda livre em tmpfs de verdade, sem tocar o FUSE do
vault por engano.

**Pendência:** não foi verificado se algum app esperava o conteúdo do vault
na raiz do jail (ex: como `$HOME`/perfil) — vale confirmar com teste real
se isso muda algum comportamento esperado pra apps que leem arquivos do
vault.

---

## 12. `--rw-home` e `--pivot-root` são flags mortas

**Severidade:** baixa/média (comportamento silencioso inesperado)
**Onde:** `vault_cli.c`, tabela de `getopt_long`
**Status:** identificado, **não corrigido ainda**

Ambas registradas em `long_options[]`, mas **sem nenhum `case` tratando
elas** no switch de parsing. O programa aceita as flags sem erro e
simplesmente as ignora — comportamento silencioso, sem aviso nenhum pro
usuário.

---

## 13. `--gui` documentado no `--help`, mas não existe como flag real

**Severidade:** baixa/média (documentação enganosa)
**Onde:** `vault_cli.c`, `print_help()` vs. tabela de `getopt_long`
**Status:** identificado, **não corrigido ainda**

`--gui` aparece no texto de ajuda e nos exemplos (`Nuk4sd --gui`), mas não
tem entrada correspondente em `long_options[]`. Rodar o comando documentado
resultaria em erro de "opção desconhecida" do próprio `getopt_long`.

---

## 14. Diversas flags implementadas mas ausentes do `--help`

**Severidade:** baixa (usabilidade/documentação)
**Status:** corrigido

23 flags existiam no `getopt_long` mas não apareciam em lugar nenhum do
texto de ajuda: `--rw-home`, `--audio`, `--gpu`, `--xdg-runtime`, `--dbus`,
`--dev`, `--display`, `--wayland-display`, `--chroot`, `--pivot-root`,
`--no-seccomp`, `--seccomp-strict`, `--allow-clone3`, `--friendly-sandbox`,
`--permissive`, `--max-procs`, `--max-mem`, `--max-filesize`, `--max-fds`,
`--tmp-size`, `--no-fuse`, `--preset`, `--health`. Todas
adicionadas ao `print_help()` com descrição extraída do código real (não
suposição).

---

## Resumo de status

| # | Item | Severidade | Status |
|---|------|-----------|--------|
| 1 | `vault_sandbox.c` código morto | baixa | ✅ removido |
| 2 | `uid_map` hardcoded `0,0` (jail.c) | crítica | ✅ corrigido |
| 3 | `snprintf` errado em vault_catalog.c | cosmética | ⏳ pendente |
| 4 | `run_isolated()` é o caminho ativo real | — | 📝 documentado |
| 5 | bind-mount do vault sem privilégio | crítica | ✅ corrigido |
| 6 | dependência newuidmap/newgidmap | — | ♻️ superada |
| 7 | kernel rejeita uid_map de 2 linhas c/ outside-id repetido | crítica | ✅ contornado |
| 8 | redesign: mapa de identidade | — | ✅ implementado |
| 9 | Firefox recusa uid 0 | crítica | ✅ resolvido |
| 10 | mknod rejeitado em userns | crítica | 📝 não era a causa raiz real |
| 11 | bind-mount do vault substituía jail_root inteiro | crítica | ✅ corrigido |
| 12 | `--rw-home`/`--pivot-root` mortas | média | ⏳ pendente |
| 13 | `--gui` documentado mas inexistente | média | ⏳ pendente |
| 14 | 23 flags ausentes do `--help` | baixa | ✅ corrigido |

**Pendências abertas pra próxima sessão:** itens 3, 12, 13. E validar item 11
com teste real (`cargo build --release` + `--run firefox` de novo).
