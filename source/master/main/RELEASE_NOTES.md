# Nuk4sd v0.9.30 — Release Notes (Planejado)

**Data:** Em planejamento  
**Branch:** main  
**Tipo:** Debug / Stability release

---

## Visão Geral

Versão de estabilização após debug completo do ciclo 0.9.29. Foco em cobertura de testes de regressão, hardening do container runtime e validação de todos os vetores de escape antes de release público.

---

## Em Planejamento

- [ ] Testes de regressão completos pós-refactor do `c_src/`
- [ ] Validação dos novos módulos `container/` e `sandbox/` contra vetores de escape conhecidos
- [ ] Hardening do `oci.rs` (limites de layers, validação de digest)
- [ ] Revisão de performance do `vault/` após reorganização modular

---

---

# Nuk4sd v0.9.29 — Release Notes (Em Desenvolvimento)

**Data:** 12 de agosto de 2026  
**Branch:** main  
**Tipo:** Refactor + Feature release

---

## Visão Geral

A versão 0.9.29 representa uma reorganização profunda da estrutura de código C, migrando de arquivos monolíticos para uma arquitetura modular por responsabilidade. Introduz o módulo `oci.rs` para integração com o runtime OCI e adiciona suporte a containers com overlay filesystem.

---

## Mudanças Principais

### Refactor: Estrutura Modular do `c_src/`

Os arquivos C que antes viviam soltos na raiz de `c_src/` foram reorganizados em módulos por responsabilidade:

| Módulo | Conteúdo |
|---|---|
| `c_src/sandbox/` | `jail.c`, `caps.c`, `seccomp.c`, `userns.c`, `mounts.c`, `rlimits.c`, `landlock.c` |
| `c_src/vault/` | `vault_core.h`, `vault_engine.c`, `vault_crypto.c`, `vault_catalog.c`, `vault_ffi.c`, `vault_fuse.c`, `vault_health.c`, `vault_monitor.c` |
| `c_src/cli/` | `vault_cli.c`, `vault_cli_log.c`, `vault_cli_log.h` |
| `c_src/container/` | `container.c`, `container.h`, `overlay.c`, `overlay.h` |

### Nova feature: `rust/oci.rs`

Integração com o runtime OCI (Open Container Initiative):
- Pull e extração de imagens OCI via `reqwest` + `tar` + `flate2`
- Suporte a overlayfs para camadas de container
- Compatível com registries padrão (Docker Hub, GHCR)

### Atualização: `rust/ffi.rs` e `rust/main.rs`

Bindings FFI atualizados para refletir o novo layout modular do `c_src/`, com includes apontando para as novas subpastas.

### Scripts de Teste

- Adicionado `sandbox_check.sh` — verificação rápida de integridade do sandbox
- Atualizado `sandbox_mass_test.sh` — testes em massa de vetores de escape

---

## Arquivos Modificados Nesta Versão

- `c_src/sandbox/` — módulo de isolamento (migrado de flat)
- `c_src/vault/` — módulo de vault (migrado de flat)
- `c_src/cli/` — módulo de CLI (migrado de flat)
- `c_src/container/` — novo módulo de container com overlay
- `rust/oci.rs` — novo: runtime OCI
- `rust/ffi.rs` — atualizado: bindings para novo layout
- `rust/main.rs` — atualizado: integrações
- `build.rs` — atualizado: paths de compilação para nova estrutura
- `Cargo.toml` — versão 0.9.29
- `examples/` — novo: exemplos de uso

---

---

# Nuk4sd v0.9.28 — Release Notes

**Data:** 31 de julho de 2026
**Branch:** main
**Tipo:** Bugfix + Security + Feature release

---

## Visão Geral

A versão 0.9.28 representa uma revisão profunda da camada de isolamento do sandbox, resolvendo vulnerabilidades de vazamento de namespace, problemas críticos de execução de aplicações gráficas e refinamentos na interface nativa em Rust. O projeto permanece sem dependência de root/sudo para criação de sandboxes funcionais, operando em paridade técnica com o Bubblewrap (bwrap), motor do Flatpak.

---

## Vulnerabilidades Corrigidas

### [SEC-01] Vazamento de PIDs do Host via /proc (Severidade: Média)

O sandbox montava `/proc` do host via bind-mount herdado antes do `pivot_root`, e o remount pós-pivot falhava silenciosamente porque o mountpoint já estava ocupado. O resultado era que processos dentro do sandbox conseguiam enumerar PIDs reais do host através de `/proc`, violando o isolamento do PID namespace.

**Impacto:** Um processo malicioso dentro do sandbox poderia observar quais processos estão rodando no host, inferir cargas de trabalho, temporizações e potencialmente usar `/proc/<pid>/fd` como canal de leitura se houvesse descritores de arquivo abertos acessíveis.

**Correção:** Implementada sequência de três etapas robusta antes de montar o `/proc` fresco: (1) `umount2(MNT_DETACH)` para desacoplar o procfs herdado de forma lazy sem bloquear em file descriptors abertos; (2) criação do mountpoint com verificação de `EEXIST`; (3) montagem de um novo procfs scoped ao PID namespace do sandbox com `MS_NOSUID | MS_NOEXEC | MS_NODEV`. Cada etapa tem logging estruturado via `vault_log()` e a falha do mount registra `LOG_ERROR` no audit log em vez de silenciar o erro com `perror()`.

### [SEC-02] RLIMIT_AS Quebrando Alocadores 64-bit em Modo GUI (Severidade: Alta)

O sandbox impunha por padrão um limite rígido de espaço de endereçamento virtual (`RLIMIT_AS`) de 4 a 8 GB para todos os modos. Alocadores modernos de 64 bits — especialmente o JIT SpiderMonkey do Firefox e o V8 do Chromium — fazem `mmap()` de regiões de memória virtual muito maiores que a RAM física usada (técnica de reserva antecipada de espaço de endereçamento). Com o limite ativo, o kernel retornava `ENOMEM` nas chamadas de `mmap()` durante a inicialização, resultando em falha silenciosa do processo antes de qualquer renderização.

**Impacto:** Todas as aplicações gráficas modernas baseadas em Electron, Firefox ou Chromium falhavam ao iniciar dentro do sandbox com código de saída 11 (SIGSEGV por acesso a endereço não mapeado).

**Correção:** `RLIMIT_AS` removido dos defaults automáticos. O limite só é aplicado quando o usuário especifica explicitamente `--max-mem <GB>` via CLI.

### [SEC-03] Perfil Seccomp Bloqueando Sandbox Interno de Aplicações (Severidade: Alta)

O Firefox, o Chromium e aplicações baseadas em Electron tentam criar um mini-sandbox interno de content process chamando `capset()` e `chroot()` após a execução principal. O perfil seccomp padrão do Nuk4sd retornava `EPERM` para `capset()`, que o Firefox interpretava como falha fatal na primitiva de sincronização `futex`, abortando com "The futex facility returned an unexpected error code."

**Impacto:** Firefox, GIMP, VS Code e outras aplicações GUI com sandbox interno próprio não conseguiam iniciar.

**Correção:** Adicionado modo "GUI amigável" automático que é ativado sempre que o sandbox detecta modo Wayland ou X11 (`--wayland`/`--x11`). Nesse modo, `capset()`, `chroot()`, `setuid()` e `setgid()` são liberados no perfil seccomp para que o sandbox interno da aplicação funcione. O isolamento real continua garantido pelas camadas do Nuk4sd (capabilities zeradas, PID namespace, filesystem pivot_root), tornando as chamadas inofensivas mesmo que liberadas no filtro BPF.

### [SEC-04] Nós de Dispositivo /dev Ausentes no Sandbox Unprivileged (Severidade: Alta)

No modo unprivileged (sem sudo), o sandbox não conseguia criar device nodes via `mknod()` pois essa syscall exige `CAP_MKNOD`, que não existe no user namespace. Os placeholders de arquivo comum criados para `/dev/null`, `/dev/zero` e `/dev/tty` eram arquivos regulares vazios, não character devices reais.

**Impacto:** Aplicações que escrevem em `/dev/null` acumulavam dados em disco; leituras de `/dev/zero` retornavam EOF; ausência de `/dev/shm`, `/dev/pts` e `/dev/urandom` fazia aplicações gráficas e criptográficas falharem por falta de entropia ou memória compartilhada.

**Correção:** Implementado bind-mount seletivo dos device nodes do host para dentro do sandbox com flag de leitura/escrita para nós `/dev/*`. Os seguintes dispositivos são agora herdados do host em modo leitura/escrita: `/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/random`, `/dev/shm`, `/dev/pts`, `/dev/dri`. Demais bind-mounts de diretórios continuam read-only.

---

## Funcionalidades Novas e Melhorias

### Interface Nativa em Rust (egui/eframe)

A interface gráfica foi completamente reescrita em Rust puro usando o framework `egui` com backend `eframe`. O antigo `nuk4sd_gui.py` (2635 linhas, dependente de PyQt5) foi removido. A nova GUI:

- Não tem dependência de Python, pip ou Qt no sistema operacional.
- É compilada estaticamente no binário `Nuk4sd`, sem runtime separado.
- Comunica-se diretamente com o core C via FFI sem subprocessos ou parsing de stdout.
- Persiste perfis de aplicação em `~/.config/nuk4sd/desktop_apps.json` via serde_json.
- Apresenta cinco abas: Desktop Grid, Vaults FUSE, Lançador, Sandboxes Ativos e Terminal CLI.
- Expõe todas as flags de isolamento disponíveis na interface, sem ocultar opções avançadas.
- Design visual em azul marinho neutro e cinza escuro, sem bibliotecas de tema externas.

### Lançamento de Aplicações GUI sem Vault (--no-fuse)

O Desktop Grid agora detecta automaticamente quando `vault_id == 0` e usa `--no-fuse`, criando um jail temporário em `/tmp` sem exigir que o usuário crie um vault FUSE previamente. O `--rw-home` é adicionado automaticamente para que as aplicações mantenham acesso ao diretório home do usuário e suas configurações.

### Preflight Scan Automático

Antes de executar qualquer binário, o Nuk4sd analisa as dependências do executável via `ldd` e configura automaticamente:
- Detecção de uso de GPU → monta `/dev/dri` e `/sys/dev/char`
- Detecção de GTK/Qt → configura variáveis de ambiente Wayland/X11 e monta `/tmp/.X11-unix`
- Detecção de áudio → monta sockets PipeWire e PulseAudio
- Detecção de uso de rede → aviso se `--no-net` não foi especificado

### Compatibilidade com Ambiente sem Root Verificada

Confirmado que o Nuk4sd opera em paridade técnica com o Bubblewrap em ambiente sem root. A sequência de isolamento é equivalente:

```
unshare(CLONE_NEWUSER)  →  escreve uid_map/gid_map  →
unshare(CLONE_NEWNS | CLONE_NEWPID)  →  bind-mounts  →
pivot_root()  →  drop capabilities  →  NO_NEW_PRIVS  →
seccomp-BPF  →  execvp()
```

Diferentemente do Firejail (binário SUID root), o Nuk4sd não requer o bit setuid e não executa código como root em nenhum momento.

---

## Resultados do Escape Test (v0.9.28)

Teste executado com `escape_test.sh` dentro do sandbox, comparado com baseline do host:

| Vetor | Host (sem sandbox) | Nuk4sd v0.9.28 |
|---|---|---|
| Leitura de /etc/shadow | Não (permissão) | Bloqueado |
| Acesso a ~/.ssh | Não (permissão) | Bloqueado |
| PIDs do host via /proc | Vê 245 PIDs | Bloqueado (PID=1 próprio) |
| mount procfs/bind/tmpfs | Não (sem caps) | Bloqueado |
| chroot | Não (sem caps) | Bloqueado |
| Binário SUID/setuid | Não (sem caps) | Bloqueado (NO_NEW_PRIVS) |
| Capabilities efetivas | Zeradas (usuário normal) | Zeradas |
| kexec_load | Aberta | Bloqueada (KILL_PROCESS) |
| pivot_root aninhado | Não (sem caps) | Bloqueado |
| /dev/mem, /dev/sda, /dev/kmem | Não acessíveis | Não expostos |
| Acesso à rede externa | Aberto | Bloqueado (rede host compartilhada por padrão) |

---

## Comparativo com Firejail 0.9.72

Teste realizado com `firejail --noprofile firefox` e `firejail firefox` (com perfil padrão):

| Camada | Firejail sem perfil | Firejail com perfil | Nuk4sd v0.9.28 |
|---|---|---|---|
| User namespace própria | Não (host) | Não (host) | Sim |
| PID namespace | Sim | Sim | Sim |
| Mount namespace | Sim | Sim | Sim |
| pivot_root | Não | Não | Sim (host detachado) |
| Seccomp-BPF | Desativado | Ativo (modo 2) | Ativo (modo 1) |
| NO_NEW_PRIVS | Não | Sim | Sim |
| Capabilities | CapBnd completo | CapBnd zerado | CapEff zero |
| Requer SUID root | Sim | Sim | Não |
| Perfis por aplicação | Não | 900+ perfis | Genérico (presets por categoria) |

O Firejail leva vantagem nos perfis específicos por aplicação, que contêm whitelists de paths e regras seccomp customizadas para cada programa. O Nuk4sd leva vantagem em user namespace própria, pivot_root completo e ausência de SUID.

---

## Arquivos Modificados Nesta Versão

- `c_src/jail.c` — bind-mount de device nodes `/dev/*` em modo RW; fix do `/proc` herdado
- `c_src/vault_cli.c` — remoção de `RLIMIT_AS` dos defaults; seccomp amigável automático para GUI; remount robusto de `/proc` com `umount2(MNT_DETACH)` + logging estruturado
- `c_src/seccomp.c` — comentários de justificativa expandidos; modo permissivo para sandbox interno de aplicações
- `rust/gui.rs` — interface nativa completa em egui; Desktop Grid; Vaults Manager; Lançador; Terminal
- `rust/ffi.rs` — bindings FFI completos; `rust_vault_copy_file` exportado como símbolo C
- `rust/main.rs` — rota `--gui` para interface nativa
- `Cargo.toml` — dependências serde/serde_json; versão 0.9.28
- `.gitignore` — exclusão de logs, objetos compilados, chaves e arquivos de sessão
