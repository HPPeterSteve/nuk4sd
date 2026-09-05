#ifndef NUK4SD_PRESET_H
#define NUK4SD_PRESET_H

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

/* FIX: isto costumava se chamar VAULT_PATH_MAX com o mesmo guard
 * `#ifndef` — parecia seguro, mas vault_core.h já #define VAULT_PATH_MAX
 * 512 ANTES deste header ser incluído (vault_cli.c inclui vault_core.h
 * primeiro). O #ifndef nunca disparava, então BindEntry.path/CliConfig
 * eram compilados em C com paths de 512 bytes — enquanto o preset.rs,
 * sem nenhuma visão de vault_core.h, sempre compilou com 4096. Os dois
 * lados calculavam sizeof(CliConfig) diferente (33264 vs 262640 bytes),
 * o calloc() em C alocava heap pequeno demais, e o preflight_scan (Rust)
 * lia campos além do buffer real → segfault.
 *
 * Nome próprio, sem #ifndef, elimina qualquer chance de colisão futura
 * com outra macro do mesmo nome vinda de qualquer outro header. */
#define PRESET_PATH_MAX 4096

#define MAX_BINDS 64

typedef enum { BIND_RO, BIND_RW, BIND_BLACKLIST } BindType;

typedef struct {
    char     path[PRESET_PATH_MAX];
    BindType type;
} BindEntry;

typedef struct {
    /* --vault <id> */
    int32_t vault_id;

    /* Operações de vault */
    bool op_ls, op_info, op_files, op_status, op_scan;
    bool op_encrypt, op_decrypt, op_resolve;
    bool op_mount, op_umount, op_mount_export, op_export;
    bool op_rm, op_unlock, op_passwd, op_rule;
    bool op_worm_status, op_help, op_version;
    bool op_rename;
    
    /* Container Whitelist */
    bool op_whitelist_exclude;
    bool op_whitelist_restore;

    /* OCI Image / Tarball Pulling */
    char *image_url;
    bool  image_url_allocated; /* true se image_url foi alocado via strdup (precisar de free) */

    /* --export */
    char *export_file;
    char *export_dest;

    /* --rename */
    char *rename_to;

    /* --rule */
    int rule_max_fails;
    int rule_hour_from;
    int rule_hour_to;

    /* --new */
    char *new_name;
    char *new_path;
    bool  protected_vault;
    int   engine_level;

    /* WORM */
    uint32_t worm_set;
    uint32_t worm_clear;
    bool     worm_protected_scan;

    /* --run */
    char  *run_exec;
    char **run_argv;
    int    run_argc;

    /* Flags de isolamento básico */
    bool       iso_no_net;
    bool       iso_pivot_root;
    bool       iso_wayland;
    bool       iso_x11;
    bool       iso_ro_home;
    bool       iso_rw_home;
    bool       iso_no_dbus;
    bool       iso_tmp_home;
    bool       iso_audit;
    bool       iso_no_proc;
    bool       iso_new_session;
    bool       iso_unshare_ipc;
    bool       iso_unshare_uts;
    char      *iso_hostname;
    char      *iso_profile;   /* arquivo de perfil no disco */

    /* Desktop runtime (novo) */
    bool       iso_audio;        /* --audio: PipeWire + PulseAudio  */
    bool       iso_dbus_session; /* --dbus session                  */
    bool       iso_dbus_system;  /* --dbus system                   */
    bool       iso_gpu;          /* --gpu: /dev/dri                 */
    bool       iso_xdg_runtime;  /* --xdg-runtime: /run/user/$UID  */
    int        iso_dev_level;    /* --dev minimal(1)/standard(2)   */
    bool       iso_no_seccomp;   /* --no-seccomp: debug/sem BPF    */
    bool       iso_use_chroot;   /* --chroot: usa chroot em vez de pivot_root */
    char      *iso_display;      /* --display :N                   */
    char      *iso_wayland_disp; /* --wayland-display <nome>        */
    char      *iso_preset;       /* --preset firefox/office/dev...  */
    bool       seccomp_strict;   /* --seccomp-strict (-q)           */
    bool       allow_clone3;     /* --allow-clone3 (-k)             */
    bool       friendly_sandbox; /* --friendly-sandbox: syscalls de
                                   * housekeeping extras no seccomp
                                   * (fsync/fdatasync/renameat2) —
                                   * NÃO mexe em chroot/capset/mount.
                                   * preflight_scan() NUNCA seta este
                                   * campo — só o parser de CLI. */
    bool       permissive_sandbox; /* --permissive: libera chroot/capset/
                                     * setuid/setgid no seccomp E devolve
                                     * uma capability bounding mínima
                                     * (CAP_SYS_CHROOT/SETUID/SETGID/
                                     * SETPCAP) em vez do drop total —
                                     * deixa o app GUI montar o PRÓPRIO
                                     * sandbox interno (mesmo caminho do
                                     * Firejail). preflight_scan() também
                                     * NUNCA seta este campo. */
    bool       skip_preflight;     /* --no-preflight: pula o auto-scanner
                                     * de dependências (preflight_scan).
                                     * Útil quando o usuário já sabe quais
                                     * flags usar e não quer o overhead/
                                     * risco do ldd automático. */
    bool       no_fuse;            /* --no-fuse: pula totalmente a etapa de
                                     * montagem FUSE do vault. O jail root é
                                     * criado diretamente em /tmp sem tentar
                                     * montar nenhum cofre criptografado.
                                     * Útil para sandboxes de desenvolvimento
                                     * ou quando o FUSE não está disponível. */

    /* Limites de recurso (0 = padrão interno) */
    int        iso_max_procs;    /* --max-procs <N>                */
    int        iso_max_mem_gb;   /* --max-mem <GB>                 */
    int        iso_max_fsize_mb; /* --max-filesize <MB>            */
    int        iso_max_fds;      /* --max-fds <N>                  */
    int        iso_tmp_size_mb;  /* --tmp-size <MB>                */

    BindEntry  binds[MAX_BINDS];
    int        bind_count;

    /* Gerais */
    bool  verbose;
    bool  debug;                 /* --debug */
    bool  json_output;
    char *password;
} CliConfig;

/* Scanner de dependências cirúrgico */
void preflight_scan(CliConfig *cfg, const char *exec_path);

#endif /* NUK4SD_PRESET_H */
