#ifndef NUK4SD_PRESET_H
#define NUK4SD_PRESET_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

/* Defaults da rede veth isolada — altere aqui caso a sub-rede 10.0.0.x
 * já esteja em uso no host (conflito de roteamento NAT). */
#define VETH_IP_GW "10.0.0.2"   /* IP do gateway (lado host)  */
#define VETH_IP_JAIL "10.0.0.3" /* IP da interface jail       */
#define VETH_CIDR "/24"

/* FIX: isto costumava se chamar VAULT_PATH_MAX com o mesmo guard
 * `#ifndef` —" parecia seguro, mas vault_core.h j define VAULT_PATH_MAX
 * 512 ANTES deste header ser includo (vault_cli.c inclui vault_core.h
 * primeiro). O #ifndef nunca disparava, ento BindEntry.path/CliConfig
 * eram compilados em C com paths de 512 bytes —" enquanto o preset.rs,
 * sem nenhuma viso de vault_core.h, sempre compilou com 4096. Os dois
 * lados calculavam sizeof(CliConfig) diferente (33264 vs 262640 bytes),
 * o calloc() em C alocava heap pequeno demais, e configuraes externas
 * lia campos alm do buffer real — segfault.
 *
 * Nome prprio, sem #ifndef, elimina qualquer chance de coliso futura
 * com outra macro do mesmo nome vinda de qualquer outro header. */
#define PRESET_PATH_MAX 4096

#define MAX_BINDS 64

typedef enum { BINÃO, BIND_RW, BIND_BLACKLIST } BindType;

typedef struct {
    char path[PRESET_PATH_MAX];
    BindType type;
} BindEntry;

typedef struct {
    /* --vault <id> */
    int32_t vault_id;

    /* Operaes de vault */
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
    bool image_url_allocated; /* true se image_url foi alocado via strdup (precisar de free) */

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
    bool protected_vault;

    /* WORM */
    uint32_t worm_set;
    uint32_t worm_clear;
    bool worm_protected_scan;

    /* --run */
    char *run_exec;
    char **run_argv;
    int run_argc;

    /* Flags de isolamento bsico */
    bool iso_no_net;
    bool iso_pivot_root;
    bool iso_wayland;
    bool iso_x11;
    bool iso_ro_home;
    bool iso_rw_home;
    bool iso_no_dbus;
    bool iso_tmp_home;
    bool iso_audit;
    bool iso_no_proc;
    bool iso_new_session;
    bool iso_unshare_ipc;
    bool iso_unshare_uts;
    bool iso_unshare_cgroup; /* --unshare-cgroup */
    char *iso_hostname;
    char *iso_profile; /* arquivo de perfil no disco */

    /* Desktop runtime (novo) */
    bool iso_audio;         /* --audio: PipeWire + PulseAudio  */
    bool iso_dbus_session;  /* --dbus session                  */
    bool iso_dbus_system;   /* --dbus system                   */
    bool iso_gpu;           /* --gpu: /dev/dri                 */
    bool iso_xdg_runtime;   /* --xdg-runtime: /run/user/$UID  */
    int iso_dev_level;      /* --dev minimal(1)/standard(2)   */
    bool iso_no_seccomp;    /* --no-seccomp: debug/sem BPF    */
    bool iso_use_chroot;    /* --chroot: usa chroot em vez de pivot_root */
    char *iso_display;      /* --display :N                   */
    char *iso_wayland_disp; /* --wayland-display <nome>        */

    /* Seccomp granular flags (novo) */
    uint32_t seccomp_allow; /* Bitmask para permitir syscalls (--allow <syscall>) */

#define SALLOW_SOCKET (1u << 0)
#define SALLOW_BIND (1u << 1)
#define SALLOW_LISTEN (1u << 2)
#define SALLOW_ACCEPT (1u << 3)
#define SALLOW_CONNECT (1u << 4)
#define SALLOW_SENÃO (1u << 5)
#define SALLOW_RECVFROM (1u << 6)
#define SALLOW_SENDMSG (1u << 7)
#define SALLOW_RECVMSG (1u << 8)
#define SALLOW_SOCKETPAIR (1u << 9)
#define SALLOW_GETSOCKOPT (1u << 10)
#define SALLOW_SETSOCKOPT (1u << 11)
#define SALLOW_SHMGET (1u << 12)
#define SALLOW_SHMAT (1u << 13)
#define SALLOW_SHMCTL (1u << 14)
#define SALLOW_MEMFD (1u << 15)
#define SALLOW_CLONE3 (1u << 16)
#define SALLOW_FUTEX (1u << 17)
#define SALLOW_FSYNC (1u << 18)
#define SALLOW_RENAMEAT2 (1u << 19)
#define SALLOW_INOTIFY (1u << 20)
#define SALLOW_SPLICE (1u << 21)
#define SALLOW_TIMERFD (1u << 22)
#define SALLOW_SIGNALFD (1u << 23)
#define SALLOW_USERFAULTFD (1u << 24)
#define SALLOW_PTRACE (1u << 25)
#define SALLOW_BPF (1u << 26)
#define SALLOW_MOUNT (1u << 27)
#define SALLOW_CHROOT (1u << 28)
#define SALLOW_SETUID (1u << 29)

    bool no_fuse;      /* --no-fuse: pula totalmente a etapa de
                        * montagem FUSE do vault. O jail root
                        * criado diretamente em /tmp sem tenta
                        * montar nenhum cofre criptografado.
                        * til para sandboxes de desenvolvimento
                        * ou quando o FUSE no est disponvel. */
    bool fuse_mounted; /* FIX auditoria: true SOMENTE se
                        * vault_mount_ffi() retornou 0 —" garante
                        * que o unmount ps-run s desmonta
                        * sesses efetivamente criadas. */

    /* Limites de recurso (0 = padrão interno) */
    int iso_max_procs;    /* --max-procs <N>                */
    int iso_max_mem_gb;   /* --max-mem <GB>                 */
    int iso_max_fsize_mb; /* --max-filesize <MB>            */
    int iso_max_fds;      /* --max-fds <N>                  */
    int iso_tmp_size_mb;  /* --tmp-size <MB>                */

    /* Rede (novo) */
    bool iso_net_veth;       /* --net veth: par veth isolado + NAT   */
    char *iso_net_veth_ip;   /* IP do jail      (default "10.0.0.3") */
    char *iso_net_veth_gw;   /* IP do gateway   (default "10.0.0.2") */
    char *iso_net_veth_name; /* prefixo do par (default "nuk4sd")    */
    char *iso_nfilter_jail;  /* --nfilter <name>: nome do jail para filtro nftables */

    /* Supervisor UUID (--uuid) */
    bool iso_uuid; /* --uuid: habilita supervisor de UUID do sandbox */

    BindEntry binds[MAX_BINDS];
    int bind_count;

    /* Gerais */
    bool verbose;
    bool debug; /* --debug */
    bool json_output;
    bool moz_compat; /* --moz-compat */
    char *password;
} CliConfig;

#endif /* NUK4SD_PRESET_H */
