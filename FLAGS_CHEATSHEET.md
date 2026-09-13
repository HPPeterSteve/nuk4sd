# 🧭 Nuk4sd — Dicionário Completo e Cheatsheet de Flags & Arquitetura

Guia exaustivo de referência para todas as flags, subsistemas e sinergias de segurança do **Nuk4sd** (Vault Criptográfico, Isolamento de Processos, Namespaces, Seccomp-BPF, WORM e AppArmor MAC).

---

## 🏛️ Filosofia de Defesa em Profundidade: WORM + AppArmor

> [!IMPORTANT]
> **A Regra de Ouro da Segurança no Nuk4sd:**
> Sempre que operar em ambientes hostis, de auditoria ou forense, combine as flags **WORM** com **AppArmor (MAC)**.

### Por que a dupla WORM + AppArmor é imbatível?
1. **WORM (Write Once, Read Many) — Camada FUSE / Filesystem:**
   - Impede que qualquer processo (mesmo como root na sandbox) execute `unlink()`, `rmdir()`, `rename()` ou modifique blocos gravados (`write()`).
   - Garante a **imutabilidade lógica** dos dados e logs de auditoria.
2. **AppArmor (Mandatory Access Control) — Camada Kernel (LSM):**
   - Confinamento a nível de kernel Linux. Define explicitamente quais caminhos de disco, capacidades POSIX e recursos IPC o binário pode tocar.
   - Mesmo que um invasor descubra um zero-day e escape do sandbox ou ganhe UID 0 (root), o kernel bloqueia acesso direto aos discos brutos (`/dev/sd*`), proíbe desativar o FUSE, e bloqueia `ptrace` sobre o processo de criptografia.
3. **Argon2id + Segredo Offline:**
   - A flag `--disable-apparmor` exige o segredo impresso offline gerado por `--generate-secret` protegido por hash Argon2id (custo de memória e CPU). Sem o papel físico, o invasor não remove a blindagem do kernel.

```bash
# Exemplo de Ativação do Bastião WORM + AppArmor:
nuk4sd --mac-enable                     # 1. Ativa o Mandatory Access Control no catálogo
nuk4sd --generate-secret                # 2. Gera frase de recuperação offline (anote em papel!)
nuk4sd --app-armor all                  # 3. Carrega perfis AppArmor no kernel imediatamente
nuk4sd --vault 1 --protected-scan       # 4. Trava o cofre em WORM Máximo (No-Delete, No-Write, No-Rename)
```

---

## ⚡ 1. Top 10 — Operações Diárias

| Comando | O que faz |
| :--- | :--- |
| `nuk4sd` | Inicia o shell interativo seguro (REPL). |
| `nuk4sd --manual` ou `-m` | Abre o manual operacional e de segurança interativo (5 páginas). |
| `nuk4sd --sysinfo [filter]` | Telemetria do sistema (CPU, RAM, discos, rede, processos isolados). |
| `nuk4sd --ls` | Lista todos os cofres registrados, status, caminhos e regras. |
| `nuk4sd --new <nome> --protected` | Cria um cofre novo criptografado em AES-256-GCM derivado com PBKDF2. |
| `nuk4sd --vault <id> --mount` | Monta o cofre criptografado como pasta FUSE (carrega AppArmor se ativo). |
| `nuk4sd --vault <id> --umount` | Desmonta a pasta FUSE e descarrega o perfil AppArmor. |
| `nuk4sd --vault <id> --run <bin> [args]` | Executa um binário dentro do sandbox estrito com isolamento total. |
| `nuk4sd --vault <id> --run <bin> -k` | Roda liberando a syscall `clone3` (`-k` / `--allow-clone3` p/ Arch Linux/glibc nova). |
| `nuk4sd --gui` | Inicia o ambiente gráfico com o preset `nuk4sd-gui`. |

---

## 🗄️ 2. Gerenciamento de Cofres (Vault Lifecycle)

| Flag | Argumentos | Descrição |
| :--- | :--- | :--- |
| `--ls` | *nenhum* | Lista todos os cofres cadastrados no `catalog.dat`, com ID, nome, status e diretório base. |
| `--new <nome>` | Obrigatório | Cria e registra um novo cofre no catálogo. |
| `--path <dir>` | Opcional | Define onde os dados brutos do cofre serão guardados (padrão: pasta do catálogo). |
| `--protected` | *nenhum* | Exige senha mestre ao criar o cofre (ativa derivação de chave e criptografia AES-256-GCM). |
| `--engine <0-5>` | `0` a `5` | Nível de ofuscação física do cofre: `0` (plano), `1` (1 camada + decoys), `2` (3 camadas), `3` (6 camadas), `4` (16 camadas), `5` (20 camadas + arquivos falsos anti-forense). |
| `--vault <id>` | `<id>` | Seleciona o cofre-alvo pelo número de ID para executar qualquer operação subsequente. |
| `--info` | *nenhum* | Exibe raio-x completo do cofre: parâmetros criptográficos, salt, regras temporais, status. |
| `--files` | *nenhum* | Lista todos os arquivos rastreados no cofre com seus respectivos hashes SHA-256. |
| `--status` | *nenhum* | Retorna o estado instantâneo do cofre (`OK`, `LOCKED`, `ALERT`, `DELETED`). |
| `--scan` | *nenhum* | Varre o cofre validando integridade SHA-256 de todos os arquivos contra o catálogo. |
| `--encrypt` | *nenhum* | Criptografa todos os arquivos planos dentro do cofre gerando wrappers `.enc`. |
| `--decrypt` | *nenhum* | Descriptografa todos os arquivos `.enc` do cofre restaurando os arquivos originais. |
| `--resolve` | *nenhum* | Reconhece e limpa um estado de alerta de integridade disparado por violação. |
| `--mount` | *nenhum* | Monta o cofre como filesystem FUSE em espaço de usuário. |
| `--umount` | *nenhum* | Desmonta a partição FUSE e sincroniza metadados. |
| `--mount-export` | *nenhum* | **Resgate de emergência:** extrai arquivos de um cofre sob WORM extremo ignorando bloqueios FUSE. |
| `--export` | *nenhum* | Exporta/resgata arquivos descriptografados do cofre para uma pasta local. |
| `--file <nome>` | Obrigatório | Usado com `--export` para resgatar um arquivo específico em vez de todos. |
| `--dest <dir>` | Obrigatório | Diretório de destino para exportação ou extração. |
| `--rm` | *nenhum* | **Destrutivo e irreversível:** apaga permanentemente o cofre do disco e do catálogo. |
| `--rename <nome>` | Obrigatório | Renomeia o cofre no catálogo (mantém o diretório físico intacto). |
| `--unlock` | *nenhum* | Destrava um cofre bloqueado após exceder tentativas de senha incorreta. |
| `--passwd` | *nenhum* | Altera a senha mestre do cofre e recriptografa todos os arquivos com o novo segredo. |
| `--rule <n>` | `<n>` tentativas | Define regra de autodestravamento/bloqueio: trava o cofre após *n* senhas erradas. |
| `--hours <A-B>` | Ex: `9-18` | Janela de acesso permitida. Fora do horário estipulado, o acesso é negado. |

---

## 📂 3. Sistema de Arquivos Seguro (Anti-TOCTOU)

Operações atômicas seguras dentro do cofre para mitigar condições de corrida (Time-of-Check to Time-of-Use):

| Flag | Argumentos | Descrição |
| :--- | :--- | :--- |
| `--add <arquivo>` | Obrigatório | Adiciona arquivo ou pasta ao cofre de maneira atômica e segura contra links simbólicos maliciosos. |
| `--recursive` | *nenhum* | Processa diretórios recursivamente ao usar `--add`. |
| `--replace` | *nenhum* | Substitui arquivo existente no cofre caso já exista (por padrão, é rejeitado). |
| `--preserve` | *nenhum* | Preserva permissões POSIX originais (chmod), dono (chown) e timestamps (utime). |
| `--extract <path>` | Obrigatório | Extrai um arquivo ou pasta do cofre para fora dele. |
| `--force` | *nenhum* | Força sobrescrita no destino durante extração sem pedir confirmação. |
| `--mv <orig> <dest>` | 2 caminhos | Move ou renomeia um arquivo internamente no cofre (caminhos relativos ao cofre). |
| `--cp <orig> <dest>` | 2 caminhos | Copia um arquivo internamente preservando criptografia e integridade. |
| `--rm-file <path>` | Obrigatório | Remove um arquivo específico do cofre (respeita restrições WORM se ativas). |
| `--mkdir <dir>` | Obrigatório | Cria um novo subdiretório dentro do cofre. |
| `--rmdir <dir>` | Obrigatório | Remove um subdiretório vazio dentro do cofre. |
| `--tree` | *nenhum* | Exibe a estrutura em árvore visual com galhos coloridos de todo o conteúdo do cofre. |
| `--du` | *nenhum* | Disk Usage: calcula o uso de espaço em disco detalhado por região do cofre. |
| `--find <padrao>` | Ex: `*.pdf` | Busca arquivos e diretórios dentro do cofre usando casamento de padrões glob (`*`, `?`). |

---

## 📸 4. Snapshots & Versionamento Imutável

| Flag | Argumentos | Descrição |
| :--- | :--- | :--- |
| `--snapshot [tag]` | Opcional | Cria um ponto de restauração imutável do cofre com timestamp e tag personalizada opcional. |
| `--snapshots` | *nenhum* | Lista todos os snapshots existentes com datas, tamanhos e tags. |
| `--snapshot-delete <tag>` | Obrigatório | Remove permanentemente um snapshot específico por sua tag. |
| `--snapshot-restore <tag>` | Obrigatório | Restaura o cofre inteiro para o estado exato daquele snapshot no tempo. |
| `--snapshot-diff <t1> [t2]` | 1 ou 2 tags | Compara diferenças entre um snapshot e o estado atual, ou entre dois snapshots distintos. |

---

## 🔍 5. Integridade Criptográfica & Forense

| Flag | Argumentos | Descrição |
| :--- | :--- | :--- |
| `--hash [arquivo]` | Opcional | Calcula SHA-256 de um arquivo específico ou calcula o Merkle/Hash raiz do cofre todo. |
| `--baseline` | *nenhum* | Cria o arquivo criptográfico `.vault_baseline` registrando os hashes de todos os itens atuais. |
| `--verify` | *nenhum* | Compara o cofre atual contra a baseline gravada, denunciando modificações silenciosas. |
| `--integrity` | *nenhum* | Auditoria profunda: valida cabeçalhos `.enc`, magic bytes, salts e integridade de symlinks. |
| `--repair` | *nenhum* | Tenta restaurar automaticamente blocos e arquivos corrompidos a partir do último snapshot saudável. |
| `--diff [outro_path]` | Opcional | Compara o cofre contra a baseline ou contra outro diretório de cofre no disco. |

---

## 💾 6. Backup, Importação & Travas de Concorrência

| Flag | Argumentos | Descrição |
| :--- | :--- | :--- |
| `--backup [arquivo.tar.gz]` | Opcional | Exporta o cofre inteiro em um tarball comprimido e assinado. |
| `--restore-arch <arq.tar.gz>` | Obrigatório | Restaura um cofre a partir de um arquivo de backup `.tar.gz`. |
| `--import <item>` | Arquivo/dir/tar | Importa arquivos avulsos, pastas ou backups diretamente para o cofre ativo. |
| `--lock` | *nenhum* | Registra trava exclusiva de processo (PID lock) impedindo outras instâncias de abrir o cofre. |
| `--lock-status` | *nenhum* | Mostra se o cofre está bloqueado, por qual PID e há quanto tempo. |
| `--force-unlock` | *nenhum* | Remove travas órfãs (ex: após crash do sistema ou desligamento forçado). Operação de operador. |

---

## 🔑 7. Ciclo de Vida de Chaves (Key Management)

| Flag | Argumentos | Descrição |
| :--- | :--- | :--- |
| `--key-info` | *nenhum* | Exibe parâmetros criptográficos: algoritmo (AES-256-GCM), tamanho de chave, iterações PBKDF2 e salt. |
| `--key-rotate <velha> <nova>` | 2 senhas | Re-deriva nova chave mestra e recriptografa todos os headers e wrappers dos arquivos do cofre. |
| `--rekey` | *nenhum* | Re-criptografa todos os arquivos com novos nonces/IVs de 96 bits aleatórios sob a mesma senha (evita desgaste de IV). |

---

## 🛡️ 8. Proteção WORM (Write Once, Read Many)

O mecanismo WORM bloqueia mutações destrutivas na camada do filesystem:

| Flag | Efeito Prático | Retorno de Erro do Kernel |
| :--- | :--- | :--- |
| `--worm-status` | Exibe o mapa de bits de quais proteções WORM estão ativas no momento. | Informativo |
| `--protect-delete` | Bloqueia chamadas `unlink()`, `rmdir()`, `unlinkat()`. Nenhum arquivo pode ser apagado. | `-EPERM` (Operação não permitida) |
| `--protect-rename` | Bloqueia chamadas `rename()`, `renameat2()`. Nenhum arquivo pode ser movido ou renomeado. | `-EPERM` |
| `--protect-write` | Bloqueia escrita em arquivos pré-existentes. Arquivos novos podem ser criados, mas nunca modificados. | `-EPERM` |
| `--protect-read` | Bloqueia leitura de dados no cofre. Transforma o cofre em um "buraco negro" de despejo de logs/arquivamento. | `-EPERM` |
| `--protected-scan` | **Modo Fortaleza:** ativa simultaneamente as 4 proteções acima e dispara auditoria contínua. | Irreversível sem `--mount-export` |
| `--clear-delete` | Desativa a trava de deleção (se o modo permitir). | — |
| `--clear-rename` | Desativa a trava de renomeação. | — |
| `--clear-write` | Desativa a trava de escrita. | — |
| `--clear-read` | Desativa a trava de leitura. | — |

---

## 🔒 9. Mandatory Access Control (AppArmor MAC)

O kernel Linux impõe limites invioláveis através do módulo LSM AppArmor:

| Flag | Argumentos | Descrição |
| :--- | :--- | :--- |
| `--mac-enable` | *nenhum* | Ativa permanentemente o modo MAC no catálogo. Os mounts futuros carregarão perfis AppArmor automaticamente. |
| `--app-armor <all\|vault-ID>` | Obrigatório | Compila e carrega os perfis AppArmor no kernel imediatamente para o alvo especificado. |
| `--mac-status` | *nenhum* | Mostra se o kernel está com AppArmor ativo e se os perfis do Nuk4sd estão em modo `enforce`. |
| `--generate-secret` | *nenhum* | Gera frase de resgate física (`Nuk4sdRecovery + 12 dígitos`) e salva o hash Argon2id em `~/.nuk4sd_mac_secret` (0600). |
| `--disable-apparmor [vault-ID]` | Opcional | Revoga o confinamento AppArmor. Exige digitar a frase de recuperação gerada em `--generate-secret`. |

---

## 📦 10. Container OCI & Imagens de Runtime

| Flag | Argumentos | Descrição |
| :--- | :--- | :--- |
| `--image <url\|distro>` | `ubuntu`, `alpine`, URL | Baixa ou usa a imagem SquashFS de runtime rootfs para instanciar o container do sandbox. Detecta e usa a imagem local do sistema `/usr/share/nuk4sd/runtime/ubuntu24_04.squashfs` automaticamente. |
| `--white-list -e` ou `exclude` | `-e` / `exclude` | Modo lista branca restrito: bloqueia operações não explicitamente declaradas. |
| `--white-list -r` ou `restore` | `-r` / `restore` | Restaura a permissão de operações seladas. |

---

## 🧱 11. Isolamento de Processos no Sandbox (`--run`)

A flag principal para execução segura:
```bash
nuk4sd --vault <id> --run <executável> [-- argumentos...]
```

### Isolamento de Sistema de Arquivos (Bind Mounts & Mascaramento)
| Flag | Descrição |
| :--- | :--- |
| `--ro <caminho>` | Monta a pasta ou arquivo externo como **somente-leitura** dentro da sandbox. |
| `--rw <caminho>` | Monta a pasta externa com permissão de leitura e escrita. |
| `--blacklist <caminho>` | Cega completamente o processo isolado para aquele caminho (ex: `--blacklist ~/.ssh` ou `~/.gnupg`). Sobrepõe com tmpfs vazio. |
| `--ro-home` | Monta a home real (`$HOME`) do usuário como somente-leitura. |
| `--rw-home` | Monta a home real do usuário com escrita (padrão se nenhuma outra for passada). |
| `--tmp-home` | Cria uma home 100% descartável na memória RAM (tmpfs). Nada é gravado no disco real. |
| `--tmp-size <mb>` | Limita o tamanho em MB do tmpfs usado pela `--tmp-home` (padrão: 512MB). |
| `--chroot` | Usa `chroot()` para isolar o sistema de arquivos raiz (compatibilidade). |
| `--pivot-root` | Usa `pivot_root()` (padrão seguro), trocando a raiz do kernel para evitar fugas via `..`. |
| `--no-fuse` | Executa a sandbox sem montar a camada FUSE, lendo arquivos diretamente da área de staging. |

### Namespaces Linux & Identificação
| Flag | Descrição |
| :--- | :--- |
| `--unshare-ipc` | Isola o namespace de IPC (memória compartilhada SysV, semáforos e filas de mensagens). |
| `--unshare-uts` | Isola o namespace UTS, permitindo um hostname exclusivo para o sandbox. |
| `--hostname <nome>` | Define o hostname interno do sandbox (requer `--unshare-uts`). |
| `--new-session` | Executa `setsid()` desvinculando o processo do terminal controlador (evita injeção via ioctl TIOCSTI). |
| `--no-proc` | Não monta `/proc` dentro do sandbox, impedindo listagem de processos do host. |
| `--uuid` | Gera um identificador UUID único, mascara o nome do processo em `/proc` e audita a execução. |
| `--init` | Executa um mini-gerenciador de processos (PID 1) no sandbox para coletar processos zumbis (reaping). |

### Rede & Firewall Privado
| Flag | Descrição |
| :--- | :--- |
| `--no-net` | **Isolamento de ar:** fecha 100% da rede (unshare no namespace de rede). O sandbox fica totalmente offline. |
| `--net-veth [ip]` | Cria um par de interfaces virtuais veth com NAT. IP padrão: `10.0.0.3` (gateway `10.0.0.2`). |
| `--nfilter [nome]` | Instala firewall com `nftables` bloqueando todo o tráfego de saída por padrão (Default Drop). |
| `--allow-ip <ip>` | Libera um endereço IP específico no firewall nftables (ex: `--allow-ip 1.1.1.1`). |

### Display Gráfico, Áudio, GPU & D-Bus
| Flag | Descrição |
| :--- | :--- |
| `--wayland` | Encaminha o socket Wayland (`$XDG_RUNTIME_DIR/wayland-0`) em modo somente-leitura. |
| `--x11` | Encaminha o socket X11 (`/tmp/.X11-unix/X0`) em modo somente-leitura. |
| `--display <opt>` | Customiza a variável `$DISPLAY` exportada para a sandbox (ex: `:1`). |
| `--wayland-display <s>` | Customiza o socket do Wayland (padrão: `wayland-0`). |
| `--audio` | Encaminha sockets de áudio do PipeWire / PulseAudio para reprodução de som. |
| `--gpu` | Monta `/dev/dri` com aceleração por hardware para gráficos 3D e renderização de vídeo. |
| `--xdg-runtime` | Monta o diretório runtime `$XDG_RUNTIME_DIR/<uid>` para sockets do desktop. |
| `--dbus <modo>` | Libera sockets do D-Bus: `session`, `system` ou `both`. |
| `--no-dbus` | Remove `$DBUS_SESSION_BUS_ADDRESS` e oculta sockets D-Bus para evitar bypass de sandbox. |

### Dispositivos (`/dev`)
| Flag | Descrição |
| :--- | :--- |
| `--dev minimal` | Cria `/dev` em tmpfs apenas com `null`, `zero`, `tty` e `urandom`. |
| `--dev standard` | Adiciona `random` e `fuse` aos dispositivos mínimos. |
| `--mount-dev` | Monta `/dev` completo isolado via mknod dinâmico. |

---

## 🛡️ 12. Seccomp-BPF & Filtros de Syscalls

| Flag | Atalho | O que faz |
| :--- | :--- | :--- |
| `--seccomp-strict` | `-q` | Aplica o filtro de syscalls mais rígido: fecha quase toda chamada arriscada do kernel. |
| `--allow-clone3` | `-k` | Permite a syscall `clone3` no filtro Seccomp (essencial para glibc moderna / Arch Linux). |
| `--friendly-sandbox` | — | Permite syscalls de manutenção comuns (`fsync`, `fdatasync`, `renameat2`) para navegadores e apps Electron. |
| `--permissive` | — | Modo tolerante para testar ou diagnosticar apps incompatíveis com a política restrita padrão. |
| `--no-seccomp` | — | Desativa totalmente a filtragem BPF (apenas para depuração profunda). |
| `--no-preflight` | — | Pula a verificação automática de dependências com `ldd` (arranque instantâneo). |
| `--adapter "<regras>"`| — | Compila filtro BPF dinâmico customizado: `"accept: socket, connect decline: ptrace, bpf"`. |

---

## ⚙️ 13. Limitação de Recursos (rlimits & Cgroups v1/v2)

| Flag | Tipo | Descrição |
| :--- | :--- | :--- |
| `--max-procs <n>` | rlimit | Limita o número máximo de processos/threads (`RLIMIT_NPROC`, 1-65535). |
| `--max-mem <gb>` | rlimit | Limita a memória virtual máxima (`RLIMIT_AS`, 1-512 GB). |
| `--max-filesize <mb>` | rlimit | Limita o tamanho de arquivos individuais criados (`RLIMIT_FSIZE`, 1-102400 MB). |
| `--max-fds <n>` | rlimit | Limita a quantidade de descritores de arquivos abertos simultaneamente (`RLIMIT_NOFILE`). |
| `--cgroup [nome]` | cgroup | Ativa contenção por cgroups do kernel (padrão: `nuk4sd/sandbox-<pid>`). |
| `--cgroup-name <nome>` | cgroup | Atribui um nome customizado ao grupo de controle no kernel. |
| `--cpu-shares <n>` | cgroup | Peso de escalonamento de CPU (2 a 262144, padrão 1024). |
| `--cpu-quota <us>` | cgroup | Quota de uso de CPU em microssegundos por período (ex: `50000` = 50% de 1 núcleo). |
| `--cgroup-mem <mb>` | cgroup | Limite de memória física (RAM) via cgroup em megabytes. |

---

## 🎯 14. Presets Prontos (`--preset <nome>`)

Em vez de digitar dezenas de flags, utilize os perfis embutidos:

| Preset | Aplicação Ideal | Flags Ativadas Automaticamente |
| :--- | :--- | :--- |
| `browser` / `firefox` | Navegadores web | Wayland, X11, Áudio, GPU, Friendly-Sandbox, XDG-Runtime. |
| `office` / `evince` | Documentos / PDFs | Wayland, X11, Read-Only Home, No-Net. |
| `dev` / `code` | VS Code, IDEs | Wayland, GPU, RW Home, Blacklist ~/.ssh, Allow-Clone3. |
| `media` / `celluloid` / `hypnotix` | Players de vídeo | Áudio PipeWire, GPU `/dev/dri`, Wayland, X11. |
| `nautilus` / `gedit` | Utilitários de desktop | Interface gráfica básica, Ro-Home, isolamento de IPC. |
| `nuk4sd-gui` | Interface oficial | Ambiente gráfico completo do Nuk4sd. |
| `minimal` | Shell e scripts CLI | Modo texto puro, sem sockets gráficos ou de áudio. |

Também é possível carregar um arquivo `.conf` externo via `--profile <caminho>`.

---

## 📊 15. Observabilidade, Auditoria & Telemetria

| Flag | Descrição |
| :--- | :--- |
| `--stats` | Telemetria estendida: tamanho de arquivos, distribuição de tipos e análise de entropia dos dados. |
| `--usage` | Mostra distribuição de espaço em disco no cofre. |
| `--inspect <arquivo>` | Inspeciona cabeçalho AES-GCM, salt, nonce e estado rastreado de um arquivo específico. |
| `--history` | Exibe o histórico cronológico de operações gravadas em `.vault_history.log`. |
| `--events` | Exibe eventos de auditoria capturados pelo monitor do cofre. |
| `--audit` | Registra no log de auditoria todos os argumentos de execução, bind mounts e alterações de variáveis. |
| `--health <pid>` | Realiza diagnóstico de saúde em tempo real de uma sandbox em execução via PID. |
| `--sysinfo [filtro]` | Painel de telemetria geral (`cpu`, `mem`, `disk`, `net`, `proc`, `all`). |

---

## 🎛️ 16. Flags Globais e Operacionais

| Flag | Descrição |
| :--- | :--- |
| `--password <senha>` | Informa a senha mestre diretamente por argumento (para automação/scripts). Se omitida, solicita no terminal de forma oculta. |
| `--verbose` | Ativa saída detalhada para diagnóstico de operações. |
| `--json` | Retorna o resultado de `--status` e `--scan` formatado em JSON para consumo por scripts e APIs. |
| `--version` | Exibe versão, commit de compilação e suporte da arquitetura. |
| `--help` | Exibe a ajuda detalhada no terminal. |
| `--manual` ou `-m` | Abre o manual operacional e de segurança interativo com paginação. |
