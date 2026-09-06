# Guia do Sandbox Nuk4sd

Este guia detalha como utilizar o ambiente seguro (sandbox) do Nuk4sd para rodar aplicações gráficas e utilitários da CLI. Com as recentes atualizações de segurança (como os filtros Seccomp granulares e logs de kernel), o sandbox está pronto para garantir isolamento máximo com total observabilidade.

## 1. Executando Programas na CLI

Para rodar um programa dentro do cofre isolado, utilize a flag `--run`:

```bash
# Formato Básico
Nuk4sd --vault <id> --run <executável> [-- args_do_programa]

# Exemplo: Rodando um shell bash protegido (assumindo montagens de sistema)
Nuk4sd --vault 1 --ro /bin --ro /lib --ro /usr --run /bin/bash
```

O comando executará o programa fazendo `pivot_root` para dentro do seu cofre, removendo todas as capabilities do Linux (`NO_NEW_PRIVS`) e ativando os filtros Seccomp.

## 2. Controle do Seccomp-BPF

A implementação de Seccomp foi fortificada para bloquear explorações comuns, especificamente flags abusivas em `clone()` (como `CLONE_NEWUSER`). Existem três abordagens:

*   **Padrão**: Permite I/O completo, sockets e uso de memória básico, além de permitir o `clone3` usado em bibliotecas glibc recentes.
*   **Strict (`-q` ou `--seccomp-strict`)**: Bloqueia agressivamente Sockets, Memória Compartilhada (shm) e `clone3`. Restringe o app ao máximo, impedindo até comunicação entre processos que dependem dessas syscalls.
*   **Clone3 Allow (`-k` ou `--allow-clone3`)**: Cria uma exceção no modo estrito apenas para o `clone3`. Extremamente útil para programas modernos que quebram sem essa syscall de thread, mas que você não deseja que tenham acesso à rede ou sockets.

**Exemplo de Proteção Máxima**:
```bash
Nuk4sd --vault 1 --run secret_app --seccomp-strict --allow-clone3 
```

## 4. Usando Perfis Prontos (Profiles)

Ao invés de passar longos comandos na CLI toda vez que quiser rodar um programa, você pode criar perfis prontos `.conf`.

### 4.1. Criando um Perfil

Crie um arquivo em `~/.config/Nuk4sd/browser.conf`:

```text
# Perfil Estrito para Navegador
--no-net
--wayland
--ro /usr
--ro /lib
--ro-home
--blacklist ~/.ssh
--blacklist ~/.gnupg
--audit
```

### 4.2. Carregando um Perfil

Para rodar com o perfil:

```bash
Nuk4sd --vault 1 --profile ~/.config/Nuk4sd/browser.conf --run firefox
```

O Nuk4sd lerá cada flag e configurará todos os bind mounts (`--ro`, `--rw`, `--blacklist`) e opções de isolamento gráfico (`--wayland`, `--x11`) de uma só vez.

## 5. Flags Essenciais de Isolamento

Aqui estão as bandeiras cruciais que você usará com programas:

*   **Bind Mounts:** `--ro <caminho>`, `--rw <caminho>`, `--blacklist <caminho>` (esconde o diretório).
*   **Networking:** `--no-net` (cria um novo namespace de rede, isolando-o da internet).
*   **Gráficos:** `--wayland` e `--x11` (monta os sockets gráficos necessários, permitindo que a GUI renderize de dentro do cofre).
*   **Ambiente/Diretórios Pessoais:** `--ro-home` (torna a pasta do usuário apenas leitura) e `--tmp-home` (falsifica uma pasta `/home` temporária que some ao fechar).
*   **D-Bus:** `--no-dbus` (Isola do D-Bus da sessão do hospedeiro).

## 6. Exemplo de Execução Blindada de Aplicação GUI

Imaginando que queiramos executar um leitor de PDF secreto dentro do cofre de ID 3, montando os binários do sistema em modo readonly, mas garantindo blindagem WORM e isolamento Wayland:

```bash
Nuk4sd --vault 3 \
  --ro /bin --ro /usr --ro /lib --ro /etc \
  --run zathura \
  --wayland \
  --no-net \
  --seccomp-strict \
  --allow-clone3 \
  -- secret_document.pdf
```
