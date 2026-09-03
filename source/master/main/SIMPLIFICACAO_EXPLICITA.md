# Execução Explicitamente Configurada

Esta revisão removeu do caminho de execução o **preflight scan baseado em `ldd`**, as heurísticas que alteravam flags, o engine de honeyfile/decoy, a opção `--engine` e os presets que injetavam opções de isolamento.

O núcleo não tenta mais inferir que uma aplicação precisa de X11, Wayland, GPU, áudio, bibliotecas, dispositivos, binds ou permissões. Nem um perfil de aplicativo altera essas escolhas. Elas precisam ser fornecidas de modo explícito pela CLI ou pela GUI.

## Mecanismos preservados

| Categoria | Componentes mantidos |
|---|---|
| Isolamento de processos | User namespaces, PID/IPC/UTS/cgroup e sessão nova |
| Sistema de arquivos | Binds explícitos, jail root, pivot_root/chroot, FUSE/vault e `/tmp` isolado |
| Redução de privilégio | Capabilities, `no_new_privs` e rlimits |
| Política de syscalls | Seccomp, modo estrito, amigável, permissivo ou aninhado quando escolhido pelo usuário |
| Acesso | Landlock, rede e dispositivos configurados por flags explícitas |
| Integridade | WORM e auditoria quando habilitados explicitamente |

## Uso

Forneça as integrações de desktop que deseja expor. Por exemplo, para uma aplicação gráfica, escolha explicitamente as flags como `--x11`, `--wayland`, `--audio`, `--gpu` ou `--dbus session` conforme necessário. A ausência dessas flags significa que o Nuk4sd não as habilitará por conta própria.
