# Nuk4sd 0.9.30 Release Notes

**Data de lançamento:** 13 de Setembro de 2026  
**Tipo de versão:** Minor (Estabilidade, Segurança e Empacotamento)

---

## Destaques da Versão

A versão 0.9.30 introduz o suporte oficial de empacotamento para distribuições baseadas em Debian/Ubuntu e Arch Linux, elimina um vetor crítico de escape no modo interativo (REPL), sincroniza o alinhamento de memória entre os subsistemas em C e Rust, e disponibiliza utilitários nativos de telemetria e documentação no terminal.

---

## Segurança & Confinamento

- **Remoção de escape de shell no REPL (`rust/repl.rs`):** O prefixo `!<comando>` que despachava chamadas arbitrárias para `sh -c` no host foi completamente removido do loop interativo, garantindo que nenhum comando escape dos namespaces, filtros Seccomp e regras Landlock da sandbox.
- **Compatibilidade com Seccomp em glibc moderna (`--allow-clone3` / `-k`):** Adicionada a flag para permitir explicitamente a syscall `clone3` na política BPF. Essencial para executar binários recentes em distribuições como Arch Linux e Ubuntu 24.04 sem abrir mão do isolamento do restante do sistema.

---

## Empacotamento & Distribuição

- **Pacote Debian Oficial (`.deb`):** Suporte nativo à geração de pacotes `.deb` via `cargo-deb`, instalando o binário em `/usr/bin/nuk4sd` com permissões `755` e resolvendo automaticamente dependências do sistema (`libc6`, `libfuse3-3`, `libseccomp2`, `libssl3`, `squashfs-tools`).
- **Suporte Nativo ao Arch Linux (`PKGBUILD` e `nuk4sd.install`):** Criação das receitas de compilação e empacotamento compatíveis com `makepkg -si`, integrando o software diretamente ao gerenciador de pacotes `pacman`.
- **Integração com Desktop:** Adicionado arquivo XDG (`assets/nuk4sd.desktop`) e rotinas de pós-instalação (`debian/postinst`, `debian/postrm`) que registram o aplicativo no menu do sistema e criam atalhos automáticos na Área de Trabalho do usuário.

---

## Motor de Containers & Imagens OCI

- **RootFS SquashFS Embutido (`runtime/ubuntu24_04.squashfs`):** O sistema base Ubuntu 24.04 LTS (35 MB comprimidos) agora é distribuído junto ao pacote em `/usr/share/nuk4sd/runtime/`. O mecanismo em `rust/oci.rs` detecta e descompacta a imagem local via `unsquashfs` automaticamente, permitindo instanciar containers instantaneamente em ambientes sem acesso à internet.

---

## Núcleo & FFI (C / Rust)

- **Sincronização de Memória da Estrutura `CliConfig`:** As definições da struct de configuração em `preset.h` (C) e `preset.rs` (Rust) foram totalmente alinhadas campo a campo. Isso corrige o deslocamento binário que causava falhas de segmentação ao acionar verificações de integridade criptográfica (`--verify`, `--integrity`), travas WORM e rotinas de backup a partir do código Rust.

---

## Interface de Linha de Comando (CLI) & Usabilidade

- **Manual Operacional Integrado (`--manual` / `-m`):** Documentação técnica completa em 5 capítulos navegáveis diretamente no terminal, dispensando conexão com a internet ou páginas man externas.
- **Telemetria de Sistema (`--sysinfo [filtro]`):** Monitoramento em tempo real do uso de CPU, memória RAM, discos, rede e processos confinados na sandbox, com filtros dedicados (`cpu`, `mem`, `disk`, `net`, `proc`).
- **Atalho de Inicialização Gráfica (`--gui`):** Registrada a flag de conveniência `--gui`, mapeada diretamente para o perfil com suporte de display `nuk4sd-gui`.
- **Perfis de Isolamento Declarativos (`--profile`):** O leitor de arquivos `.conf` agora reconhece flags de hardware e áudio (`--audio`, `--gpu`, `--xdg-runtime`, `--dev`, `--seccomp-strict`), permitindo versionar configurações complexas de sandbox em arquivos de texto simples.
