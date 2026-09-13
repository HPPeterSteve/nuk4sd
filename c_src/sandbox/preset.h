#ifndef NUK4SD_PRESET_H
#define NUK4SD_PRESET_H

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

/* FIX: Renamed from VAULT_PATH_MAX to PRESET_PATH_MAX to avoid macro
 * collision with vault_core.h when included in CLI files. */
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

    /* Vault operations */
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
    bool  image_url_allocated; /* true if image_url was allocated via strdup (requires free) */

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

    /* Basic isolation flags */
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
    char      *iso_profile;   /* profile file on disk */

    /* Desktop runtime */
    bool       iso_audio;        /* --audio: PipeWire + PulseAudio  */
    bool       iso_dbus_session; /* --dbus session                  */
    bool       iso_dbus_system;  /* --dbus system                   */
    bool       iso_gpu;          /* --gpu: /dev/dri                 */
    bool       iso_xdg_runtime;  /* --xdg-runtime: /run/user/$UID  */
    int        iso_dev_level;    /* --dev minimal(1)/standard(2)   */
    bool       iso_mount_dev;    /* --mount-dev: bind /dev /dev/pts /sys */
    bool       iso_no_seccomp;   /* --no-seccomp: debug/no BPF     */
    bool       iso_use_chroot;   /* --chroot: use chroot instead of pivot_root */
    char      *iso_display;      /* --display :N                   */
    char      *iso_wayland_disp; /* --wayland-display <name>       */
    char      *iso_preset;       /* --preset firefox/office/dev...  */
    bool       seccomp_strict;   /* --seccomp-strict (-q)           */
    bool       allow_clone3;     /* --allow-clone3 (-k)             */
    bool       friendly_sandbox; /* --friendly-sandbox: extra housekeeping
                                   * syscalls in seccomp (fsync/fdatasync/renameat2).
                                   * Does NOT alter chroot/capset/mount. */
    bool       permissive_sandbox; /* --permissive: permits chroot/capset/
                                     * setuid/setgid in seccomp AND retains
                                     * minimal capability bounding
                                     * (CAP_SYS_CHROOT/SETUID/SETGID/SETPCAP)
                                     * allowing GUI app internal sandboxing. */
    bool       skip_preflight;     /* --no-preflight: skips auto dependency
                                     * scanner (preflight_scan). */
    bool       no_fuse;            /* --no-fuse: completely skips vault FUSE
                                     * mounting step. Jail root is created
                                     * directly in /tmp without mounting. */

    /* Isolated Network and Firewall */
    bool       iso_net_veth;       /* --net-veth: veth pair + NAT */
    char      *iso_net_veth_ip;    /* internal jail IP (default: 10.0.0.3) */
    char      *iso_net_veth_gw;    /* host gateway IP (default: 10.0.0.2) */
    bool       iso_nfilter;        /* --nfilter: nftables firewall with whitelist */
    char      *iso_nfilter_jail;   /* nftables table/jail name */

    /* Identification, integrity and init */
    bool       iso_uuid;           /* --uuid: generates UUID and hash/proc supervision */
    bool       iso_init;           /* --init: runs mini-init supervisor PID 1 */
    char      *iso_adapter;        /* --adapter "accept: ... decline: ...": flexible seccomp */

    /* Resource limits (0 = internal default) */
    int        iso_max_procs;    /* --max-procs <N>                */
    int        iso_max_mem_gb;   /* --max-mem <GB>                 */
    int        iso_max_fsize_mb; /* --max-filesize <MB>            */
    int        iso_max_fds;      /* --max-fds <N>                  */
    int        iso_tmp_size_mb;  /* --tmp-size <MB>                */

    /* Resource control via Cgroup v1/v2 */
    bool       iso_cgroup;         /* --cgroup: enables cgroups */
    bool       iso_unshare_cgroup; /* unshare cgroup namespace (CLONE_NEWCGROUP) */
    char      *iso_cgroup_name;    /* --cgroup-name <NAME> */
    int        iso_cpu_shares;     /* --cpu-shares <N> */
    int        iso_cpu_quota_us;   /* --cpu-quota <US> */
    int        iso_cgroup_mem_mb;  /* --cgroup-mem <MB> */

    /* Extended vault file operations (Block 1) */
    bool       op_add;
    char      *add_file;
    bool       add_recursive;
    bool       add_replace;
    bool       add_preserve;

    bool       op_extract;
    char      *extract_file;
    char      *extract_dest;
    bool       extract_force;

    bool       op_mv;
    char      *mv_src;
    char      *mv_dest;

    bool       op_cp;
    char      *cp_src;
    char      *cp_dest;

    bool       op_rm_file;
    char      *rm_file_target;

    bool       op_mkdir;
    char      *mkdir_target;

    bool       op_rmdir;
    char      *rmdir_target;

    bool       op_tree;
    bool       op_du;

    bool       op_find;
    char      *find_pattern;

    /* Snapshots & Immutable Versioning (Block 3) */
    bool       op_snapshot;
    char      *snapshot_tag;

    bool       op_snapshots;

    bool       op_snapshot_delete;
    char      *snapshot_del_tag;

    bool       op_snapshot_restore;
    char      *snapshot_restore_tag;

    bool       op_snapshot_diff;
    char      *snapshot_diff_tag1;
    char      *snapshot_diff_tag2;

    /* ── Cryptographic Integrity ─────────────────────────────── */
    bool       op_hash;
    char      *hash_target;        /* NULL = all files */

    bool       op_baseline;
    bool       op_verify;
    bool       op_integrity;
    bool       op_repair;

    bool       op_diff;
    char      *diff_other;         /* NULL = compare vs baseline */

    /* ── Backup & Import ──────────────────────────────────────── */
    bool       op_backup;
    char      *backup_out;         /* NULL = auto name */

    bool       op_restore;
    char      *restore_archive;    /* required */

    bool       op_import;
    char      *import_src;         /* required */

    /* ── Lock/Unlock ──────────────────────────────────────────── */
    bool       op_lock;
    bool       op_lock_status;
    bool       op_force_unlock;

    /* ── Key Lifecycle ──────────────────────────────────────── */
    bool       op_key_info;

    bool       op_key_rotate;
    char      *key_rotate_old;
    char      *key_rotate_new;

    bool       op_rekey;

    /* ── Observability ──────────────────────────────────────── */
    bool       op_stats;
    bool       op_usage;

    bool       op_inspect;
    char      *inspect_target;     /* required */

    bool       op_history;
    bool       op_events;

    BindEntry  binds[MAX_BINDS];
    int        bind_count;

    /* General */
    bool  verbose;
    bool  json_output;
    char *password;

    /* ── MAC AppArmor ─────────────────────────────────────────────
     * --app-armor=<vault-id|all>  loads AppArmor profile(s)
     * --mac-enable / --mac-disable  persist mac_mode to catalog
     * --mac-status                  prints current mac_mode
     * vault_export_dest             destination for --mount-export when
     *                               AppArmor is active (authorized egress) */
    bool  op_app_armor;          /* --app-armor parsed                    */
    char *app_armor_target;      /* "all" or "vault-<id>" string argument  */
    bool  op_mac_enable;         /* --mac-enable                          */
    bool  op_disable_apparmor;   /* --disable-apparmor                    */
    bool  op_mac_status;         /* --mac-status                          */
    bool  op_generate_secret;    /* --generate-secret                     */
    char *vault_export_dest;     /* destination dir for --mount-export     */

    /* Unlocked Features */
    bool  op_manual;             /* --manual: show interactive manual     */
    bool  op_sysinfo;            /* --sysinfo: system and process telemetry */
    char *sysinfo_target;        /* optional target filter                */
    bool  op_gui;                /* --gui: launch desktop GUI             */
} CliConfig;

/* Surgical dependency scanner */
void preflight_scan(CliConfig *cfg, const char *exec_path);

#endif /* NUK4SD_PRESET_H */
