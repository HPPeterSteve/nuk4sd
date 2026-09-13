#ifndef NUK4SD_SANDBOX_H
#define NUK4SD_SANDBOX_H

/*
 * sandbox.h
 *
 * Nuk4sd — Hardened Sandbox — unified shared header
 *
 * Follows Firejail pattern (src/firejail/firejail.h): a single header for
 * the entire subsystem instead of a .h per .c file. Each section below is
 * annotated with a "// file.c" comment indicating where the corresponding
 * function is defined.
 *
 * 5-layer defense-in-depth sandbox (Linux-only):
 *   1. User Namespace  — userns.c    — root in sandbox -> nobody on host
 *   2. Mount Namespace — mounts.c    — virtual /proc + /tmp
 *   3. Pivot Root      — userns.c    — replaces chroot (more secure)
 *   4. Capability Drop — caps.c      — drops all Linux Caps + NO_NEW_PRIVS
 *   5. Seccomp-BPF     — seccomp.c   — explicit allowlist (~120 syscalls), EPERM as default
 *
 * Other modules:
 *   jail.c     — mounts jail directory structure + shell/busybox
 *   rlimits.c  — rlimits (DoS prevention)
 *   common.c   — debug flag shared across all modules
 */

#include "vault_core.h"

#ifdef __linux__
#include <sys/sysmacros.h>
#endif



/*═══
 *  caps.c — Layer 4: Capability Drop
 *═══ */
int vsb_drop_caps(void);
int vsb_caps_drop(const CliConfig *cfg);

/*═══
 *  landlock.c
 *═══ */
int landlock_apply(const CliConfig *cfg, const char *vault_root);

/*═══
 *  userns.c — Layer 1+3: User Namespace + Pivot Root
 *═══ */
int  vsb_pivot_root(const char *new_root, bool mount_proc);
int vsb_write_uid_gid_map(pid_t child_pid, uid_t ruid, gid_t rgid);

/*═══
 *  mounts.c — Layer 2: Mount Namespace
 *═══ */
void vsb_prepare_mounts(void);

/*═══
 *  mount_dev.c — device bind-mounts (/dev, /dev/pts, /sys)
 *═══ */

/** Access policy of a bind-mount. */
typedef enum mount_readonly {
    MOUNT_READONLY,   /**< MS_RDONLY — read-only mount */
    MOUNT_READWRITE,  /**< without MS_RDONLY — read + write */
} mount_readonly_t;

/** Entry in static mount table (sentinel: source == NULL). */
typedef struct mount_entry {
    const char      *source;    /**< host path */
    const char      *target;    /**< jail path */
    mount_readonly_t readonly;  /**< R/W policy */
} mount_entry_t;

void vsb_mount_dev(void);
void vsb_set_mount_dev(bool enabled);

/*═══
 *  rlimits.c — Resource Limits
 *═══ */
void vsb_limit_resources(bool is_gui);

/*═══
 *  seccomp.c — Layer 5: Seccomp-BPF
 *═══ */
int  vsb_apply_seccomp(void);
void vsb_set_seccomp_mode(int strict, int allow_c3, int friendly, int permissive);
void vsb_set_seccomp_adapter(const char *adapter);

/*═══
 *  jail.c — jail directory structure + shell/busybox
 *═══ */
void vsb_prepare_jail(const char *path, bool gui);
void vsb_bind_gui_deps(const char *jail_path);

/*═══
 *  autority.c — Sandbox Identification and Executable Supervision (--uuid)
 *═══ */
typedef struct {
    pid_t       pid;
    const char *original_binary;
    int         pipe_fd[2];
} UuidArgs;

int setup_uuid(UuidArgs args);
int wait_init_binary(UuidArgs args);

/*═══
 *  net.c — Isolated Network via Veth + NAT and Nftables Egress Filter
 *═══ */
int vsb_setup_veth_host(pid_t child_pid, const char *jail_ip, const char *gw_ip, const char *name_prefix);
int vsb_configure_veth_inside(const char *jail_ip, const char *gw_ip, const char *name_prefix);
int vsb_cleanup_veth(const char *name_prefix);
int vsb_net_veth_setup(pid_t child_pid, const char *jail_ip, const char *gw_ip, const char *name_prefix);
int user_send_set_ip(const char *set_name, const char *ip);
int nfilterflag(const char *jail_name, const char *jail_ip);

/*═══
 *  apparmor.c — MAC Layer: AppArmor dynamic profile management
 *═══ */
bool mac_apparmor_available(void);
bool mac_apparmor_is_active(uint32_t vault_id);
int  mac_apparmor_load(const Vault *v);
int  mac_apparmor_remove(uint32_t vault_id);
int  mac_apparmor_apply_all(void);

/* MAC AppArmor Secret validation (via Rust Argon2) */
int rust_generate_mac_secret(char *out_buffer, size_t buffer_size);
int rust_validate_mac_secret(const char *phrase_ptr);

#endif /* NUK4SD_SANDBOX_H */