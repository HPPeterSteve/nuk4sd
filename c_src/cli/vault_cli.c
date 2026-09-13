/*
 * vault_cli.c
 *
 * Nuk4sd  Full CLI flag parser (bwrap style)
 *
 * Single entry point: vault_cli_parse_and_exec(argc, argv)
 * Parses all flags via getopt_long and dispatches to C core.
 *
 * Isolation flags use vsb_* public wrappers from vault_sandbox.c:
 *   vsb_drop_caps()         ’ sandbox_drop_caps()
 *   vsb_apply_seccomp()     ’ apply_seccomp_policy() [allowlist: default EPERM]
 *   vsb_pivot_root()        ’ sandbox_pivot_root()
 *   vsb_prepare_mounts()    ’ sandbox_prepare_mounts()
 *   vsb_write_uid_gid_map() ’ sandbox_write_uid_gid_map()
 *   vsb_prepare_jail()      ’ vault_prepare_jail()
 *
 * Usage:
 *   Nuk4sd --ls
 *   Nuk4sd --vault 3 --encrypt
 *   Nuk4sd --vault 3 --scan --verbose
 *   Nuk4sd --vault 3 --run firefox --no-net --wayland
 *   Nuk4sd --vault 3 --run code --wayland --rw ~/projects --blacklist ~/.ssh
 *   Nuk4sd --new work --path /data/w --protected --engine 2
 *   Nuk4sd --vault 3 --protect-delete --protect-write
 *   Nuk4sd --vault 3 --export --dest ~/rescued
 *
 * Author: Peter Steve
 */

#define _GNU_SOURCE
#include "vault_core.h"
#include "vault_cli_log.h"
#include "preset.h"
#include "sandbox.h"
#include "vault_health.h"
#include "common.h"

#include <getopt.h>
#include <pwd.h>
#include <termios.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <ftw.h>        /* FIX #1: nftw() for safe rm -rf */
#include <arpa/inet.h>
#include <ctype.h>
#include "container.h"

/*  OCI / Cgroup callbacks implemented in Rust (ffi.rs) 
 * Exposed via #[no_mangle] extern "C"  linked through the same static
 * libvault_security.a produced by build.rs. */
extern int rust_oci_pull_image(const char *url_or_alias, const char *target_dir);
extern int rust_cgroup_apply(const char *cgroup_name,
                             unsigned long long pid,
                             long long memory_limit_mb,
                             unsigned long long cpu_shares,
                             long long cpu_quota_us,
                             long long max_procs);
extern int rust_cgroup_cleanup(const char *cgroup_name);
extern int rust_vault_add(const char *vault_path, const char *src_file, bool recursive, bool replace, bool preserve);
extern int rust_vault_extract(const char *vault_path, const char *rel_file, const char *dest_dir, bool force);
extern int rust_vault_mv(const char *vault_path, const char *src_rel, const char *dst_rel);
extern int rust_vault_cp(const char *vault_path, const char *src_rel, const char *dst_rel);
extern int rust_vault_rm_file(const char *vault_path, const char *target_rel);
extern int rust_vault_mkdir(const char *vault_path, const char *dir_rel);
extern int rust_vault_rmdir(const char *vault_path, const char *dir_rel);
extern int rust_vault_tree(const char *vault_path);
extern int rust_vault_du(const char *vault_path);
extern int rust_vault_find(const char *vault_path, const char *pattern);
extern int rust_vault_snapshot(const char *vault_path, const char *tag);
extern int rust_vault_snapshots(const char *vault_path);
extern int rust_vault_snapshot_delete(const char *vault_path, const char *tag);
extern int rust_vault_snapshot_restore(const char *vault_path, const char *tag);
extern int rust_vault_snapshot_diff(const char *vault_path, const char *tag1, const char *tag2);
/* Cryptographic Integrity */
extern int rust_vault_hash(const char *vault_path, const char *target_rel);
extern int rust_vault_baseline(const char *vault_path);
extern int rust_vault_verify(const char *vault_path);
extern int rust_vault_integrity(const char *vault_path);
extern int rust_vault_repair(const char *vault_path);
extern int rust_vault_diff(const char *vault_path, const char *other);
/* Backup & Import */
extern int rust_vault_backup(const char *vault_path, const char *out_archive);
extern int rust_vault_restore(const char *vault_path, const char *in_archive);
extern int rust_vault_import(const char *vault_path, const char *src);
/* Lock */
extern int rust_vault_lock(const char *vault_path);
extern int rust_vault_lock_status(const char *vault_path);
extern int rust_vault_force_unlock(const char *vault_path);
/* Key Lifecycle */
extern int rust_vault_key_info(const char *vault_path);
extern int rust_vault_key_rotate(const char *vault_path, const char *old_pass, const char *new_pass);
extern int rust_vault_rekey(const char *vault_path, const char *pass);
/* Observability */
extern int rust_vault_stats(const char *vault_path);
extern int rust_vault_usage(const char *vault_path);
extern int rust_vault_inspect(const char *vault_path, const char *rel_file);
extern int rust_vault_history(const char *vault_path);
extern int rust_vault_events(const char *vault_path);

#ifdef __linux__
#include <sched.h>
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#endif
/*  FIX #1: rm_rf_nftw  replaces system("rm -rf") 
 * nftw() with FTW_PHYS does not follow symlinks during traversal, blocking
 * any path traversal via symlinks created inside rootfs. */
#ifdef __linux__
static int _rm_rf_cb(const char *path, const struct stat *sb,
                     int typeflag, struct FTW *ftwbuf)
{
    (void)sb; (void)ftwbuf;
    return (typeflag == FTW_DP) ? rmdir(path) : unlink(path);
}
static int rm_rf_safe(const char *path) {
    return nftw(path, _rm_rf_cb, 32, FTW_DEPTH | FTW_PHYS);
}
#endif

/* forward decl  used by --profile loader (load_profile), defined below
 * with remaining bind mount helpers */
static void cli_expand_tilde(const char *in, char *out, size_t out_sz);

/*
 *  WORM bits  mirrors vault_core.h
 * */
#ifndef WORM_PROTECT_DELETE
#define WORM_PROTECT_DELETE  (1u << 0)
#define WORM_PROTECT_RENAME  (1u << 1)
#define WORM_PROTECT_WRITE   (1u << 2)
#define WORM_PROTECT_SCAN    (1u << 3)
#define WORM_PROTECT_READ    (1u << 4)
#endif

/*
 *  Bind-mount entry for --ro / --rw / --blacklist
 * */

/*
 *  Long options enum
 * */
enum {
    OPT_VAULT = 1000,
    OPT_LS, OPT_INFO, OPT_FILES, OPT_STATUS, OPT_SCAN,
    OPT_ENCRYPT, OPT_DECRYPT, OPT_RESOLVE,
    OPT_MOUNT, OPT_UMOUNT, OPT_MOUNT_EXPORT, OPT_EXPORT,
    OPT_FILE, OPT_DEST,
    OPT_RM, OPT_RENAME, OPT_UNLOCK, OPT_PASSWD,
    OPT_RULE, OPT_HOURS,
    OPT_NEW, OPT_PATH, OPT_PROTECTED, OPT_ENGINE,
    /* WORM */
    OPT_WORM_STATUS,
    OPT_PROTECT_DELETE, OPT_PROTECT_RENAME,
    OPT_PROTECT_WRITE,  OPT_PROTECT_READ,
    OPT_PROTECTED_SCAN,
    OPT_CLEAR_DELETE,   OPT_CLEAR_RENAME,
    OPT_CLEAR_WRITE,    OPT_CLEAR_READ,
    OPT_WHITE_LIST,
    OPT_IMAGE,
    /* run */
    OPT_RUN,
    /* basic isolation */
    OPT_NO_NET, OPT_WAYLAND, OPT_X11,
    OPT_RO_HOME, OPT_RW_HOME, OPT_NO_DBUS, OPT_TMP_HOME,
    OPT_RO, OPT_RW, OPT_BLACKLIST,
    OPT_AUDIT, OPT_NO_PROC, OPT_NEW_SESSION,
    OPT_UNSHARE_IPC, OPT_UNSHARE_UTS,
    OPT_HOSTNAME, OPT_PROFILE,
    /* desktop runtime */
    OPT_AUDIO, OPT_DBUS, OPT_GPU, OPT_XDG_RUNTIME,
    OPT_DEV, OPT_MOUNT_DEV, OPT_NO_SECCOMP, OPT_CHROOT, OPT_PIVOT_ROOT,
    OPT_DISPLAY_OPT, OPT_WAYLAND_DISPLAY,
    OPT_PRESET,
    /* resource limits */
    OPT_MAX_PROCS, OPT_MAX_MEM, OPT_MAX_FSIZE, OPT_MAX_FDS, OPT_TMP_SIZE,
    /* general */
    OPT_PASSWORD, OPT_VERBOSE, OPT_JSON, OPT_VERSION, OPT_HELP,
    /* strict seccomp */
    OPT_SECCOMP_STRICT = 'q',
    OPT_ALLOW_CLONE3   = 'k',
    /* permissive seccomp */
    OPT_FRIENDLY_SANDBOX,
    /* Phase 2 roadmap: allows GUI app to mount its own internal sandbox */
    OPT_PERMISSIVE_SANDBOX,
    /* Disables dependency auto-scanner (preflight_scan / ldd) */
    OPT_NO_PREFLIGHT,
    /* Skips vault FUSE mount stage */
    OPT_NO_FUSE,
    /* Inspects isolation of a running PID */
    OPT_HEALTH,
    /* network, firewall and supervision options */
    OPT_UUID,
    OPT_NET_VETH,
    OPT_NFILTER,
    OPT_ALLOW_IP,
    OPT_INIT,
    OPT_ADAPTER,
    /* cgroups v1/v2 */
    OPT_CGROUP,
    OPT_CGROUP_NAME,
    OPT_CPU_SHARES,
    OPT_CPU_QUOTA,
    OPT_CGROUP_MEM,
    /* Vault file operations */
    OPT_ADD,
    OPT_RECURSIVE,
    OPT_REPLACE,
    OPT_PRESERVE,
    OPT_EXTRACT,
    OPT_FORCE,
    OPT_MV,
    OPT_CP,
    OPT_RM_FILE,
    OPT_MKDIR,
    OPT_RMDIR,
    OPT_TREE,
    OPT_DU,
    OPT_FIND,
    /* Snapshots & Immutable Versioning */
    OPT_SNAPSHOT,
    OPT_SNAPSHOTS,
    OPT_SNAPSHOT_DELETE,
    OPT_SNAPSHOT_RESTORE,
    OPT_SNAPSHOT_DIFF,
    /* Cryptographic Integrity */
    OPT_HASH,
    OPT_BASELINE,
    OPT_VERIFY,
    OPT_INTEGRITY,
    OPT_REPAIR,
    OPT_DIFF,
    /* Backup & Import */
    OPT_BACKUP,
    OPT_RESTORE_ARCH,
    OPT_IMPORT,
    /* Lock/Unlock */
    OPT_LOCK,
    OPT_LOCK_STATUS,
    OPT_FORCE_UNLOCK,
    /* Key Lifecycle */
    OPT_KEY_INFO,
    OPT_KEY_ROTATE,
    OPT_REKEY,
    /* Observability */
    OPT_STATS,
    OPT_USAGE,
    OPT_INSPECT,
    OPT_HISTORY,
    OPT_EVENTS,
    /* MAC AppArmor */
    OPT_APP_ARMOR,
    OPT_MAC_ENABLE,
    OPT_DISABLE_APPARMOR,
    OPT_MAC_STATUS,
    OPT_GENERATE_SECRET,
    /* Unlocked Features */
    OPT_MANUAL,
    OPT_SYSINFO,
    OPT_GUI,
};

static const struct option long_options[] = {
    { "vault",           required_argument, NULL, OPT_VAULT },
    { "ls",              no_argument,       NULL, OPT_LS },
    { "info",            no_argument,       NULL, OPT_INFO },
    { "files",           no_argument,       NULL, OPT_FILES },
    { "status",          no_argument,       NULL, OPT_STATUS },
    { "scan",            no_argument,       NULL, OPT_SCAN },
    { "encrypt",         no_argument,       NULL, OPT_ENCRYPT },
    { "decrypt",         no_argument,       NULL, OPT_DECRYPT },
    { "resolve",         no_argument,       NULL, OPT_RESOLVE },
    { "mount",           no_argument,       NULL, OPT_MOUNT },
    { "umount",          no_argument,       NULL, OPT_UMOUNT },
    { "mount-export",    no_argument,       NULL, OPT_MOUNT_EXPORT },
    { "export",          no_argument,       NULL, OPT_EXPORT },
    { "file",            required_argument, NULL, OPT_FILE },
    { "dest",            required_argument, NULL, OPT_DEST },
    { "rm",              no_argument,       NULL, OPT_RM },
    { "rename",          required_argument, NULL, OPT_RENAME },
    { "unlock",          no_argument,       NULL, OPT_UNLOCK },
    { "passwd",          no_argument,       NULL, OPT_PASSWD },
    { "rule",            required_argument, NULL, OPT_RULE },
    { "hours",           required_argument, NULL, OPT_HOURS },
    { "new",             required_argument, NULL, OPT_NEW },
    { "path",            required_argument, NULL, OPT_PATH },
    { "protected",       no_argument,       NULL, OPT_PROTECTED },
    { "engine",          required_argument, NULL, OPT_ENGINE },
    { "worm-status",     no_argument,       NULL, OPT_WORM_STATUS },
    { "protect-delete",  no_argument,       NULL, OPT_PROTECT_DELETE },
    { "protect-rename",  no_argument,       NULL, OPT_PROTECT_RENAME },
    { "protect-write",   no_argument,       NULL, OPT_PROTECT_WRITE },
    { "protect-read",    no_argument,       NULL, OPT_PROTECT_READ },
    { "protected-scan",  no_argument,       NULL, OPT_PROTECTED_SCAN },
    { "clear-delete",    no_argument,       NULL, OPT_CLEAR_DELETE },
    { "clear-rename",    no_argument,       NULL, OPT_CLEAR_RENAME },
    { "clear-write",     no_argument,       NULL, OPT_CLEAR_WRITE },
    { "clear-read",      no_argument,       NULL, OPT_CLEAR_READ },
    { "white-list",      required_argument, NULL, OPT_WHITE_LIST },
    { "image",           required_argument, NULL, OPT_IMAGE },
    { "run",             required_argument, NULL, OPT_RUN },
    { "no-net",          no_argument,       NULL, OPT_NO_NET },
    { "net-veth",        optional_argument, NULL, OPT_NET_VETH },
    { "nfilter",         optional_argument, NULL, OPT_NFILTER },
    { "allow-ip",        required_argument, NULL, OPT_ALLOW_IP },
    { "uuid",            no_argument,       NULL, OPT_UUID },
    { "init",            no_argument,       NULL, OPT_INIT },
    { "wayland",         no_argument,       NULL, OPT_WAYLAND },
    { "x11",             no_argument,       NULL, OPT_X11 },
    { "ro-home",         no_argument,       NULL, OPT_RO_HOME },
    { "rw-home",         no_argument,       NULL, OPT_RW_HOME },
    { "no-dbus",         no_argument,       NULL, OPT_NO_DBUS },
    { "tmp-home",        no_argument,       NULL, OPT_TMP_HOME },
    { "ro",              required_argument, NULL, OPT_RO },
    { "rw",              required_argument, NULL, OPT_RW },
    { "blacklist",       required_argument, NULL, OPT_BLACKLIST },
    { "audit",           no_argument,       NULL, OPT_AUDIT },
    { "no-proc",         no_argument,       NULL, OPT_NO_PROC },
    { "new-session",     no_argument,       NULL, OPT_NEW_SESSION },
    { "unshare-ipc",     no_argument,       NULL, OPT_UNSHARE_IPC },
    { "unshare-uts",     no_argument,       NULL, OPT_UNSHARE_UTS },
    { "hostname",        required_argument, NULL, OPT_HOSTNAME },
    { "profile",         required_argument, NULL, OPT_PROFILE },
    /* desktop runtime */
    { "audio",           no_argument,       NULL, OPT_AUDIO },
    { "dbus",            required_argument, NULL, OPT_DBUS },
    { "gpu",             no_argument,       NULL, OPT_GPU },
    { "xdg-runtime",     no_argument,       NULL, OPT_XDG_RUNTIME },
    { "dev",             required_argument, NULL, OPT_DEV },
    { "mount-dev",       no_argument,       NULL, OPT_MOUNT_DEV },
    { "no-seccomp",      no_argument,       NULL, OPT_NO_SECCOMP },
    { "pivot-root",      no_argument,       NULL, OPT_PIVOT_ROOT },
    { "chroot",          no_argument,       NULL, OPT_CHROOT },
    { "display",         required_argument, NULL, OPT_DISPLAY_OPT },
    { "wayland-display", required_argument, NULL, OPT_WAYLAND_DISPLAY },
    { "preset",          required_argument, NULL, OPT_PRESET },
    /* resource limits */
    { "max-procs",       required_argument, NULL, OPT_MAX_PROCS },
    { "max-mem",         required_argument, NULL, OPT_MAX_MEM },
    { "max-filesize",    required_argument, NULL, OPT_MAX_FSIZE },
    { "max-fds",         required_argument, NULL, OPT_MAX_FDS },
    { "tmp-size",        required_argument, NULL, OPT_TMP_SIZE },
    { "help",            no_argument,       NULL, OPT_HELP },
    /* general */
    { "password",        required_argument, NULL, OPT_PASSWORD },
    { "verbose",         no_argument,       NULL, OPT_VERBOSE },
    { "json",            no_argument,       NULL, OPT_JSON },
    { "version",         no_argument,       NULL, OPT_VERSION },
    { "seccomp-strict",  no_argument,       NULL, 'q' },
    { "allow-clone3",    no_argument,       NULL, 'k' },
    { "friendly-sandbox", no_argument,      NULL, OPT_FRIENDLY_SANDBOX },
    { "permissive",       no_argument,      NULL, OPT_PERMISSIVE_SANDBOX },
    { "adapter",          required_argument, NULL, OPT_ADAPTER },
    { "no-preflight",     no_argument,      NULL, OPT_NO_PREFLIGHT },
    { "no-fuse",          no_argument,      NULL, OPT_NO_FUSE },
    { "health",           required_argument, NULL, OPT_HEALTH },
    /* cgroups v1/v2 */
    { "cgroup",           optional_argument, NULL, OPT_CGROUP },
    { "cgroup-name",      required_argument, NULL, OPT_CGROUP_NAME },
    { "cpu-shares",       required_argument, NULL, OPT_CPU_SHARES },
    { "cpu-quota",        required_argument, NULL, OPT_CPU_QUOTA },
    { "cgroup-mem",       required_argument, NULL, OPT_CGROUP_MEM },
    /* Vault file operations */
    { "add",              required_argument, NULL, OPT_ADD },
    { "recursive",        no_argument,       NULL, OPT_RECURSIVE },
    { "replace",          no_argument,       NULL, OPT_REPLACE },
    { "preserve",         no_argument,       NULL, OPT_PRESERVE },
    { "extract",          required_argument, NULL, OPT_EXTRACT },
    { "force",            no_argument,       NULL, OPT_FORCE },
    { "mv",               required_argument, NULL, OPT_MV },
    { "cp",               required_argument, NULL, OPT_CP },
    { "rm-file",          required_argument, NULL, OPT_RM_FILE },
    { "mkdir",            required_argument, NULL, OPT_MKDIR },
    { "rmdir",            required_argument, NULL, OPT_RMDIR },
    { "tree",             no_argument,       NULL, OPT_TREE },
    { "du",               no_argument,       NULL, OPT_DU },
    { "find",             required_argument, NULL, OPT_FIND },
    /* Snapshots & Immutable Versioning */
    { "snapshot",         optional_argument, NULL, OPT_SNAPSHOT },
    { "snapshots",        no_argument,       NULL, OPT_SNAPSHOTS },
    { "snapshot-delete",  required_argument, NULL, OPT_SNAPSHOT_DELETE },
    { "snapshot-restore", required_argument, NULL, OPT_SNAPSHOT_RESTORE },
    { "snapshot-diff",    required_argument, NULL, OPT_SNAPSHOT_DIFF },
    /* Cryptographic Integrity */
    { "hash",             optional_argument, NULL, OPT_HASH },
    { "baseline",         no_argument,       NULL, OPT_BASELINE },
    { "verify",           no_argument,       NULL, OPT_VERIFY },
    { "integrity",        no_argument,       NULL, OPT_INTEGRITY },
    { "repair",           no_argument,       NULL, OPT_REPAIR },
    { "diff",             optional_argument, NULL, OPT_DIFF },
    /* Backup & Import */
    { "backup",           optional_argument, NULL, OPT_BACKUP },
    { "restore-arch",     required_argument, NULL, OPT_RESTORE_ARCH },
    { "import",           required_argument, NULL, OPT_IMPORT },
    { "lock",             no_argument,       NULL, OPT_LOCK },
    { "lock-status",      no_argument,       NULL, OPT_LOCK_STATUS },
    { "force-unlock",     no_argument,       NULL, OPT_FORCE_UNLOCK },
    { "key-info",         no_argument,       NULL, OPT_KEY_INFO },
    { "key-rotate",       required_argument, NULL, OPT_KEY_ROTATE },
    { "rekey",            no_argument,       NULL, OPT_REKEY },
    /* Observability */
    { "stats",            no_argument,       NULL, OPT_STATS },
    { "usage",            no_argument,       NULL, OPT_USAGE },
    { "inspect",          required_argument, NULL, OPT_INSPECT },
    { "history",          no_argument,       NULL, OPT_HISTORY },
    { "events",           no_argument,       NULL, OPT_EVENTS },
    { "app-armor",         required_argument, NULL, OPT_APP_ARMOR },
    { "mac-enable",        no_argument,       NULL, OPT_MAC_ENABLE },
    { "disable-apparmor",  optional_argument, NULL, OPT_DISABLE_APPARMOR },
    { "mac-status",        no_argument,       NULL, OPT_MAC_STATUS },
    { "generate-secret",   no_argument,       NULL, OPT_GENERATE_SECRET },
    { "manual",            no_argument,       NULL, OPT_MANUAL },
    { "sysinfo",           optional_argument, NULL, OPT_SYSINFO },
    { "gui",               no_argument,       NULL, OPT_GUI },
    { NULL, 0, NULL, 0 }
};

/*
 *  Helpers
 * */
static void print_ok(const char *msg)   { printf("\033[32mœ %s\033[0m\n", msg); }
static void print_err(const char *msg)  { fprintf(stderr, "\033[31mœ– %s\033[0m\n", msg); }
static void print_warn(const char *msg) { fprintf(stderr, "\033[33mš  %s\033[0m\n", msg); }

static char *read_password_silent(const char *prompt) {
    static char buf[256];
    struct termios old, nw;
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    if (tcgetattr(STDIN_FILENO, &old) != 0) {
        if (fgets(buf, sizeof(buf), stdin))
            buf[strcspn(buf, "\n")] = '\0';
        return buf;
    }
    nw = old;
    nw.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &nw);
    memset(buf, 0, sizeof(buf));
    if (fgets(buf, sizeof(buf), stdin))
        buf[strcspn(buf, "\n")] = '\0';
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    fprintf(stderr, "\n");
    return buf;
}

/*
 *  Help
 * */
static void print_help(void) {
    printf(
"\nNuk4sd  hardened vault & isolation engine\n"
"Usage: nuk4sd [--vault <id>] <operation> [flags]\n\n"

" Vault Management \n"
"  --ls\n"
"    List all registered vaults with their id, name, status and path.\n\n"

"  --new <name>\n"
"    Create a new vault with the given name and register it in the catalog.\n\n"

"    --path <dir>\n"
"      Directory where the vault files will be stored.\n"
"      Defaults to the catalog directory if omitted.\n\n"

"    --protected\n"
"      Require a password to access the vault.\n"
"      Encryption is AES-256-GCM, key derived via PBKDF2-SHA256.\n\n"

"    --engine <0-5>\n"
"      Obfuscation level applied to the vault directory structure.\n"
"        0  none (plain layout)\n"
"        1  1 obfuscation layer + decoy files\n"
"        2  3 obfuscation layers\n"
"        3  6 obfuscation layers\n"
"        4  16 layers + fake files\n"
"        5  20 layers + fake files (maximum)\n\n"

"  --vault <id>\n"
"    Select a specific vault by numeric id for subsequent operations.\n\n"

"    --info\n"
"      Display full vault details: id, name, path, status, encryption\n"
"      parameters, salt, creation time and security rules.\n\n"

"    --files\n"
"      List all files tracked inside the vault with their SHA-256 hashes.\n\n"

"    --status\n"
"      Quick one-line status: OK / LOCKED / ALERT / DELETED.\n\n"

"    --scan\n"
"      SHA-256 integrity scan of all tracked vault files.\n"
"      Reports missing, modified or unexpected files.\n\n"

"    --encrypt\n"
"      Encrypt all files in the vault with AES-256-GCM.\n"
"      Files are re-keyed from the vault password + PBKDF2 salt.\n\n"

"    --decrypt\n"
"      Decrypt all AES-256-GCM encrypted files in the vault.\n\n"

"    --resolve\n"
"      Acknowledge and clear an active integrity alert on the vault.\n\n"

"    --mount\n"
"      Mount the vault as a FUSE filesystem at its configured mountpoint.\n"
"      AppArmor profile is loaded automatically if mac_mode is enabled.\n\n"

"    --umount\n"
"      Unmount the FUSE filesystem. AppArmor profile is removed.\n\n"

"    --export [--file <f>]\n"
"      Rescue file(s) from the vault to a local directory.\n"
"      Use --file to rescue a specific file, omit for all files.\n\n"

"      --dest <dir>\n"
"        Destination directory for the exported files.\n\n"

"    --mount-export\n"
"      Rescue files from a PROTECTED-SCAN vault, bypassing the FUSE layer.\n"
"      Required when the vault is in maximum protection mode.\n\n"

"    --rm\n"
"      Permanently delete the vault and all its files. Irreversible.\n\n"

"    --rename <name>\n"
"      Rename the vault in the catalog. Does not move files on disk.\n\n"

"    --unlock\n"
"      Unlock a vault that was locked due to too many failed password attempts.\n\n"

"    --passwd\n"
"      Interactively change the vault password. All .enc files are re-keyed.\n\n"

"    --rule <n>\n"
"      Set security rule: lock vault after n failed password attempts.\n\n"

"      --hours <from>-<to>\n"
"        Restrict access to a time window, e.g. --hours 9-18\n"
"        Access outside this range is denied.\n\n"

" Vault Filesystem (Anti-TOCTOU Secure Operations) \n"
"  --add <file>\n"
"    Add a file or directory to the vault with atomic, TOCTOU-safe ops.\n\n"

"    --recursive\n"
"      Include subdirectories recursively when adding a directory.\n\n"

"    --replace\n"
"      Replace an existing file in the vault instead of rejecting the add.\n\n"

"    --preserve\n"
"      Preserve the file's original permissions, ownership and timestamps.\n\n"

"  --extract <file>\n"
"    Extract a file or folder from the vault to a local path.\n\n"

"    --dest <dir>\n"
"      Destination directory for the extracted file (default: current dir).\n\n"

"    --force\n"
"      Overwrite existing files at the destination without prompting.\n\n"

"  --mv <src> <dest>\n"
"    Move or rename a file inside the vault. Both paths are vault-relative.\n\n"

"  --cp <src> <dest>\n"
"    Copy a file inside the vault. Both paths are vault-relative.\n\n"

"  --rm-file <file>\n"
"    Remove a specific file from the vault.\n\n"

"  --mkdir <dir>\n"
"    Create a directory inside the vault.\n\n"

"  --rmdir <dir>\n"
"    Remove an empty directory from the vault.\n\n"

"  --tree\n"
"    Display the vault directory structure as a formatted file tree.\n\n"

"  --du\n"
"    Show disk space usage broken down by vault region.\n\n"

"  --find <pattern>\n"
"    Search for files and folders inside the vault matching the given glob\n"
"    pattern. Case-sensitive. Supports * and ? wildcards.\n\n"

" Snapshots & Immutable Versioning \n"
"  --snapshot [tag]\n"
"    Create an immutable snapshot of the current vault state.\n"
"    Optionally label it with a human-readable tag.\n\n"

"  --snapshots\n"
"    List all existing snapshots with their tags and creation timestamps.\n\n"

"  --snapshot-delete <tag>\n"
"    Permanently delete a specific snapshot by tag. Irreversible.\n\n"

"  --snapshot-restore <tag>\n"
"    Restore the vault to the state captured in the given snapshot.\n\n"

"  --snapshot-diff <tag1> [tag2]\n"
"    Compare differences between a snapshot and the current vault state,\n"
"    or between two snapshots if tag2 is provided.\n\n"

" Cryptographic Integrity \n"
"  --hash [file]\n"
"    Compute SHA-256 of a specific vault file, or of the entire vault\n"
"    if no file is given.\n\n"

"  --baseline\n"
"    Generate a cryptographic baseline file (.vault_baseline) recording\n"
"    the SHA-256 of every tracked file at this point in time.\n\n"

"  --verify\n"
"    Verify the current vault state against the saved baseline.\n"
"    Reports any file that was added, removed or modified.\n\n"

"  --integrity\n"
"    Structural audit: validates .enc file headers and checks for\n"
"    broken or unexpected symlinks inside the vault.\n\n"

"  --repair\n"
"    Attempt to repair corrupted files by restoring from the latest snapshot.\n\n"

"  --diff [other-vault-path]\n"
"    Compare the vault against its baseline, or against another vault\n"
"    directory if a path is provided.\n\n"

" Backup & Portability \n"
"  --backup [out.tar.gz]\n"
"    Export the vault as a compressed archive (.tar.gz).\n"
"    Defaults to <vault-name>.tar.gz in the current directory.\n\n"

"  --restore-arch <file.tar.gz>\n"
"    Restore a vault from a backup archive produced by --backup.\n\n"

"  --import <file|dir|.tar.gz>\n"
"    Import a file, directory, or backup archive into the vault.\n\n"

" Lock & Unlock \n"
"  --lock\n"
"    Lock the vault, recording process metadata (PID) to prevent concurrent\n"
"    access from other instances.\n\n"

"  --lock-status\n"
"    Display the current lock status of the vault.\n\n"

"  --force-unlock\n"
"    Forcibly remove the vault lock. Use when a previous process crashed\n"
"    and left a stale lock. Operator-level operation.\n\n"

" Key Lifecycle \n"
"  --key-info\n"
"    Display the vault's cryptographic parameters: algorithm, key length,\n"
"    PBKDF2 iterations, salt (hex) and derivation purpose labels.\n\n"

"  --key-rotate <old> <new>\n"
"    Re-encrypt all .enc files using a new password.\n"
"    Derives a new key via PBKDF2 and re-wraps every file.\n\n"

"  --rekey\n"
"    Re-encrypt all .enc files with fresh random nonces and salts\n"
"    using the same password. Eliminates nonce reuse risk.\n\n"

" WORM Protection \n"
"  --worm-status\n"
"    Show which WORM (Write Once Read Many) flags are active on the vault.\n\n"

"  --protect-delete\n"
"    Block all unlink/rmdir calls on vault files ’ returns EPERM.\n"
"    Files cannot be deleted while this flag is set.\n\n"

"  --protect-rename\n"
"    Block rename/move operations on vault files ’ returns EPERM.\n\n"

"  --protect-write\n"
"    Block write operations on existing vault files ’ returns EPERM.\n"
"    New files can still be created.\n\n"

"  --protect-read\n"
"    Block read access to vault files ’ returns EPERM.\n"
"    Used for pure write-only or archival vaults.\n\n"

"  --protected-scan\n"
"    Enable maximum WORM protection (all protections + integrity scan).\n"
"    Irreversible without operator intervention. Use --mount-export to\n"
"    rescue files from a vault in this state.\n\n"

"  --clear-delete / --clear-rename / --clear-write / --clear-read\n"
"    Remove the corresponding WORM flag from the vault.\n\n"

" Container Whitelist \n"
"  --white-list -e\n"
"    Exclude whitelist mode: block operations that are not in the whitelist\n"
"    (sealed operations are denied by default).\n\n"

"  --white-list -r\n"
"    Restore whitelist mode: allow sealed operations again.\n\n"

" Image & Container Runtime \n"
"  --image <url|alpine|ubuntu>\n"
"    Download and set up an external rootfs image before --run.\n"
"    Accepts a URL or a named distribution (alpine, ubuntu).\n\n"

" Run Program in Vault Sandbox \n"
"  --vault <id> --run <exec> [-- exec-args...]\n"
"    Execute a program inside the vault sandbox using Linux namespaces,\n"
"    seccomp-BPF, cgroups and optional FUSE. Everything after '--' is\n"
"    passed as arguments directly to the sandboxed executable.\n\n"

"  Filesystem:\n"
"    --ro <path>\n"
"      Bind mount <path> read-only inside the sandbox.\n"
"      The sandboxed program can read but not write to this path.\n\n"

"    --rw <path>\n"
"      Bind mount <path> read-write inside the sandbox.\n\n"

"    --blacklist <path>\n"
"      Make <path> completely invisible inside the sandbox by overlaying\n"
"      it with a tmpfs or null mount.\n\n"

"    --ro-home\n"
"      Bind mount $HOME read-only inside the sandbox.\n\n"

"    --rw-home\n"
"      Bind mount $HOME read-write (default if neither --ro-home\n"
"      nor --tmp-home are specified).\n\n"

"    --tmp-home\n"
"      Create an ephemeral $HOME in tmpfs. All changes vanish on exit.\n\n"

"  Network & Firewall:\n"
"    --no-net\n"
"      Unshare the network namespace. The sandbox has no network access.\n\n"

"    --net-veth [ip]\n"
"      Create an isolated network via a veth pair + NAT.\n"
"      Default IP: 10.0.0.3. The sandbox has internet through the host NAT.\n\n"

"    --nfilter [name]\n"
"      Install an nftables firewall with default drop egress policy.\n"
"      Optionally name the ruleset.\n\n"

"    --allow-ip <ip>\n"
"      Add an IP address to the nftables firewall whitelist.\n"
"      Only whitelisted IPs can be reached by the sandbox.\n\n"

"  Identification & Supervision:\n"
"    --uuid\n"
"      Generate a unique UUID, mask the process name in /proc and\n"
"      perform automatic integrity audit on exec.\n\n"

"    --init\n"
"      Run a mini-init (PID 1) inside the sandbox with zombie reaping\n"
"      and sshd support. Automatically assigns a UUID.\n\n"

"  Display:\n"
"    --wayland\n"
"      Pass the Wayland socket and XDG_RUNTIME_DIR (read-only) into\n"
"      the sandbox. Required for Wayland GUI apps.\n\n"

"    --x11\n"
"      Pass the X11 socket /tmp/.X11-unix (read-only) into the sandbox.\n"
"      Required for X11 GUI apps.\n\n"

"    --display <opt>\n"
"      Customize the DISPLAY environment variable exported to the sandbox.\n\n"

"    --wayland-display <s>\n"
"      Customize WAYLAND_DISPLAY (default: wayland-0).\n\n"

"  Audio / GPU / D-Bus:\n"
"    --audio\n"
"      Expose the PulseAudio/PipeWire socket (read-only) to the sandbox.\n\n"

"    --gpu\n"
"      Mount /dev/dri to enable GPU hardware acceleration in the sandbox.\n\n"

"    --xdg-runtime\n"
"      Mount $XDG_RUNTIME_DIR/<uid> beyond what --wayland already includes.\n\n"

"    --dbus <mode>\n"
"      Expose D-Bus socket(s). Mode: 'session', 'system', or 'both'.\n\n"

"    --no-dbus\n"
"      Remove DBUS_SESSION_BUS_ADDRESS and cover the socket path.\n"
"      Prevents any D-Bus communication from within the sandbox.\n\n"

"  Devices:\n"
"    --dev <level>\n"
"      Control /dev nodes available in the sandbox.\n"
"        minimal   null, zero, tty, urandom\n"
"        standard  minimal + random, fuse\n\n"

"    --mount-dev\n"
"      Mount an isolated /dev in tmpfs with essential nodes via mknod.\n"
"      More flexible than --dev when custom node sets are needed.\n\n"

"  Namespaces:\n"
"    --unshare-ipc\n"
"      Isolate the IPC namespace (SysV shared memory, semaphores, queues).\n\n"

"    --unshare-uts\n"
"      Isolate the UTS namespace so the sandbox has its own hostname.\n\n"

"    --hostname <name>\n"
"      Set the sandbox hostname. Requires --unshare-uts.\n\n"

"    --new-session\n"
"      Call setsid() to detach the sandbox from the controlling terminal.\n\n"

"    --no-proc\n"
"      Do not mount /proc inside the sandbox.\n"
"      Prevents process enumeration from within the jail.\n\n"

"  Root Filesystem:\n"
"    --chroot\n"
"      Use chroot() instead of pivot_root() to set the sandbox root.\n"
"      Weaker isolation  pivot_root() is preferred whenever possible.\n\n"

"    --pivot-root\n"
"      Explicitly force pivot_root() as the root isolation mechanism.\n"
"      This is the default when available.\n\n"

"  Seccomp / Capabilities:\n"
"    --no-seccomp\n"
"      Disable the seccomp-BPF syscall filter. Not recommended.\n"
"      Removes the last layer of kernel-level syscall protection.\n\n"

"    --seccomp-strict\n"
"      Apply a stricter seccomp allowlist with fewer permitted syscalls.\n\n"

"    --allow-clone3\n"
"      Add clone3 to the seccomp allowlist. Some newer libcs require it.\n"
"      Disabled by default for security.\n\n"

"    --friendly-sandbox\n"
"      Allow extra housekeeping syscalls (fsync, fdatasync, renameat2)\n"
"      without relaxing chroot, capset or mount restrictions.\n\n"

"    --permissive\n"
"      General permissive mode. Less strict than the default seccomp policy.\n\n"

"    --adapter <rules>\n"
"      Define a custom adaptive seccomp filter at runtime.\n"
"      Format: \"accept: <syscall,...> decline: <syscall,...>\"\n"
"      Both tags also accept 'empty' to skip that direction.\n"
"      Example: --adapter \"accept: socket, connect decline: ptrace, bpf\"\n\n"

"  Resources (rlimits):\n"
"    --max-procs <n>\n"
"      Set RLIMIT_NPROC  maximum number of processes (1-65535).\n\n"

"    --max-mem <gb>\n"
"      Set RLIMIT_AS  maximum virtual memory in gigabytes (1-512).\n\n"

"    --max-filesize <mb>\n"
"      Set RLIMIT_FSIZE  maximum single-file size in megabytes (1-102400).\n\n"

"    --max-fds <n>\n"
"      Set RLIMIT_NOFILE  maximum open file descriptors (1-65535).\n\n"

"    --tmp-size <mb>\n"
"      Size in MB of the tmpfs used by --tmp-home (1-102400).\n\n"

"  Resource Control (Cgroups v1/v2):\n"
"    --cgroup [name]\n"
"      Enable cgroups isolation. Default group: nuk4sd/sandbox-<pid>.\n\n"

"    --cgroup-name <name>\n"
"      Define a custom name for the cgroup instead of the auto-generated one.\n\n"

"    --cpu-shares <n>\n"
"      CPU weight/shares (2-262144, default 1024). Higher = more CPU time.\n\n"

"    --cpu-quota <us>\n"
"      CPU quota in microseconds per period.\n"
"      Example: 50000 = 50% of one CPU core.\n\n"

"    --cgroup-mem <mb>\n"
"      Virtual memory limit for the cgroup in megabytes.\n\n"

"  FUSE:\n"
"    --no-fuse\n"
"      Do not mount the vault via FUSE. Files are copied directly.\n\n"

"  Audit:\n"
"    --audit\n"
"      Log all exec arguments, bind mount operations and environment\n"
"      variable changes to the audit trail.\n\n"

"  Profile:\n"
"    --profile <file>\n"
"      Load isolation flags from a .conf file (one flag per line).\n"
"      Lines starting with # are treated as comments.\n\n"

"    --preset <name>\n"
"      Load a named pre-configured isolation profile.\n"
"      Built-in presets: firefox, browser, flameshot, office, evince,\n"
"      dev, code, gedit, media, celluloid, hypnotix, nautilus and minimal.\n\n"

" Observability & Audit \n"
"  --stats\n"
"    Extended telemetry: file sizes, type breakdown and entropy analysis.\n\n"

"  --usage\n"
"    Show disk space usage broken down by vault region.\n\n"

"  --inspect <file>\n"
"    Inspect a specific file's metadata, AES-GCM header and tracked state.\n\n"

"  --history\n"
"    Show the operation log from .vault_history.log.\n\n"

"  --events\n"
"    Show recent audit events recorded by the vault monitor.\n\n"

" MAC / AppArmor Protection \n"
"  Mandatory Access Control via Linux AppArmor.\n"
"  AppArmor confines the nuk4sd process at the kernel level:\n"
"  only whitelisted operations are permitted per-vault profile.\n\n"

"  --mac-enable\n"
"    Globally enable AppArmor MAC mode. Sets mac_mode=1 in the catalog.\n"
"    Future vault mount/unmount operations will automatically load\n"
"    and remove the corresponding AppArmor profile.\n\n"

"  --app-armor <all|vault-<id>>\n"
"    Load AppArmor profiles immediately for the specified target.\n"
"      all         applies to every vault in the catalog.\n"
"      vault-<id>  applies only to the vault with the given numeric id.\n"
"    Vaults that already have an active profile are silently skipped.\n\n"

"  --mac-status\n"
"    Show whether AppArmor MAC is enabled, disabled or pending\n"
"    first-run configuration.\n\n"

"  --generate-secret\n"
"    Generate a one-time AppArmor recovery secret.\n"
"    A random phrase (Nuk4sdRecovery + 12 random digits) is printed once.\n"
"    Write it on paper  it is NEVER stored in plaintext on disk.\n"
"    The Argon2id hash is saved at ~/.nuk4sd_mac_secret (mode 600).\n\n"

"  --disable-apparmor [vault-<id>]\n"
"    Revoke AppArmor protection. Requires the recovery phrase from\n"
"    --generate-secret. Input is silent (no terminal echo).\n"
"      No argument   disables all vaults + sets mac_mode=0.\n"
"      vault-<id>    disables only that specific vault.\n"
"    A wrong phrase is rejected and the attempt is written to the audit log.\n\n"

" General \n"
"  --gui\n"
"    Launch the graphical interface (nuk4sd_gui.py).\n\n"

"  --password <pass>\n"
"    Provide the vault password inline. If omitted, it is prompted securely.\n\n"

"  --verbose\n"
"    Enable verbose output for all operations.\n\n"

"  --json\n"
"    Output --status and --scan results as JSON for scripting.\n\n"

"  --health <pid>\n"
"    Run a health check on a running sandbox identified by its PID.\n\n"

"  --manual, -m\n"
"    Open the interactive operational and security manual.\n\n"
"  --sysinfo [filter]\n"
"    Display system telemetry, resource usage and isolated processes.\n"
"    Optional filter: cpu, mem, disk, net, proc, all.\n\n"
"  --gui\n"
"    Launch the desktop GUI environment using the nuk4sd-gui preset.\n\n"
"  --version\n"
"    Show Nuk4sd version and build information.\n\n"

"  --help\n"
"    Show this help message.\n\n"

"  Sandbox tuning (--run):\n"
"    --no-preflight\n"
"      Skip the ldd dependency auto-scan (preflight_scan).\n"
"      Use with statically-linked or stripped binaries, or when\n"
"      you already know the exact flags needed.\n\n"

" Examples \n"
"  Launch the GUI:\n"
"    nuk4sd --gui\n\n"

"  List all vaults:\n"
"    nuk4sd --ls\n\n"

"  Encrypt all files in vault 3:\n"
"    nuk4sd --vault 3 --encrypt\n\n"

"  Integrity scan with verbose output:\n"
"    nuk4sd --vault 3 --scan --verbose\n\n"

"  Run Firefox with full network isolation:\n"
"    nuk4sd --vault 3 --run firefox --no-net --wayland\n\n"

"  Run GIMP with Wayland and read-only fonts:\n"
"    nuk4sd --vault 3 --run gimp --wayland --ro /usr/share/fonts\n\n"

"  Run a hardened shell with IPC + proc isolation and audit:\n"
"    nuk4sd --vault 3 --run bash --no-net --unshare-ipc --no-proc --audit\n\n"

"  Run VS Code with rw projects, blocking .ssh:\n"
"    nuk4sd --vault 3 --run code --wayland --rw ~/projects --blacklist ~/.ssh\n\n"

"  Run mpv with file passed after '--':\n"
"    nuk4sd --vault 3 --run mpv --x11 --ro /media/films -- /media/films/movie.mkv\n\n"

"  Run busybox statically linked (skip preflight):\n"
"    nuk4sd --vault 3 --run busybox --no-preflight --no-net\n\n"

"  Run sshd with veth networking:\n"
"    nuk4sd --vault 1 --run /usr/sbin/sshd -D --init --net-veth --mount-dev\n\n"

"  Run with custom adaptive seccomp filter:\n"
"    nuk4sd --vault 1 --run ./app --adapter \"accept: socket, connect decline: ptrace, bpf\"\n\n"

"  Run alpine container:\n"
"    nuk4sd --image alpine --run /bin/sh --net-veth --mount-dev\n\n"

"  Run nuk4sd GUI via preset:\n"
"    nuk4sd --vault 0 --preset nuk4sd-gui --run python3 -- nuk4sd_gui.py\n\n"

"  Create a new protected vault:\n"
"    nuk4sd --new work --path /data/work --protected --engine 2\n\n"

"  Apply WORM protections:\n"
"    nuk4sd --vault 3 --protect-delete --protect-write\n\n"

"  Export rescued files:\n"
"    nuk4sd --vault 3 --export --dest ~/rescued --file secret.pdf.enc\n\n"

"  AppArmor setup workflow:\n"
"    nuk4sd --mac-enable\n"
"    nuk4sd --generate-secret        # write the phrase on paper\n"
"    nuk4sd --app-armor all          # load profiles immediately\n"
"    nuk4sd --disable-apparmor       # enter phrase to revoke\n\n"
    );
}

/*
 *  Profile loader
 *  Format: one flag per line, lines starting with # are comments
 *
 *  Example ~/.config/Nuk4sd/browser.conf:
 *    # browser profile
 *    --no-net
 *    --wayland
 *    --ro /usr/share/fonts
 *    --blacklist ~/.ssh
 *    --blacklist ~/.gnupg
 * */
static void load_profile(CliConfig *cfg, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "š  profile '%s' not found\n", path); return; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Remove comment and whitespace */
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        p[strcspn(p, "\r\n")] = '\0';
        if (!*p) continue;

        if      (!strcmp(p, "--no-net"))       cfg->iso_no_net      = true;
        else if (!strcmp(p, "--wayland"))       cfg->iso_wayland     = true;
        else if (!strcmp(p, "--x11"))           cfg->iso_x11         = true;
        else if (!strcmp(p, "--ro-home"))       cfg->iso_ro_home     = true;
        else if (!strcmp(p, "--rw-home"))       cfg->iso_rw_home     = true;
        else if (!strcmp(p, "--no-dbus"))       cfg->iso_no_dbus     = true;
        else if (!strcmp(p, "--tmp-home"))      cfg->iso_tmp_home    = true;
        else if (!strcmp(p, "--audit"))         cfg->iso_audit       = true;
        else if (!strcmp(p, "--no-proc"))       cfg->iso_no_proc     = true;
        else if (!strcmp(p, "--new-session"))   cfg->iso_new_session = true;
        else if (!strcmp(p, "--unshare-ipc"))   cfg->iso_unshare_ipc = true;
        else if (!strcmp(p, "--unshare-uts"))   cfg->iso_unshare_uts = true;
        else if (!strcmp(p, "--uuid"))          cfg->iso_uuid        = true;
        else if (!strcmp(p, "--init")) {
            cfg->iso_init        = true;
            cfg->iso_uuid        = true;
        }
        else if (!strcmp(p, "--mount-dev"))     cfg->iso_mount_dev   = true;
        else if (!strcmp(p, "--net-veth")) {
            cfg->iso_net_veth    = true;
            if (!cfg->iso_net_veth_ip) cfg->iso_net_veth_ip = "10.0.0.3";
            if (!cfg->iso_net_veth_gw) cfg->iso_net_veth_gw = "10.0.0.2";
        }
        else if (!strcmp(p, "--nfilter")) {
            cfg->iso_nfilter     = true;
            if (!cfg->iso_nfilter_jail) cfg->iso_nfilter_jail = "nuk4sd_jail";
        }
        else if (!strncmp(p, "--adapter ", 10)) cfg->iso_adapter = strdup(p + 10);
        else if (!strncmp(p, "--cgroup-name ", 14)) {
            cfg->iso_cgroup = true;
            cfg->iso_cgroup_name = strdup(p + 14);
        }
        else if (!strcmp(p, "--cgroup")) {
            cfg->iso_cgroup = true;
            cfg->iso_unshare_cgroup = true;
        }
        else if (!strncmp(p, "--cpu-shares ", 13)) {
            cfg->iso_cgroup = true;
            cfg->iso_cpu_shares = atoi(p + 13);
        }
        else if (!strncmp(p, "--cpu-quota ", 12)) {
            cfg->iso_cgroup = true;
            cfg->iso_cpu_quota_us = atoi(p + 12);
        }
        else if (!strncmp(p, "--cgroup-mem ", 13)) {
            cfg->iso_cgroup = true;
            cfg->iso_cgroup_mem_mb = atoi(p + 13);
        }
        else if (!strncmp(p, "--ro ", 5) && cfg->bind_count < MAX_BINDS) {
            cli_expand_tilde(p+5, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
            cfg->binds[cfg->bind_count++].type = BIND_RO;
        }
        else if (!strncmp(p, "--rw ", 5) && cfg->bind_count < MAX_BINDS) {
            cli_expand_tilde(p+5, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
            cfg->binds[cfg->bind_count++].type = BIND_RW;
        }
        else if (!strncmp(p, "--blacklist ", 12) && cfg->bind_count < MAX_BINDS) {
            cli_expand_tilde(p+12, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
            cfg->binds[cfg->bind_count++].type = BIND_BLACKLIST;
        }
        /* Desktop & Runtime */
        else if (!strcmp(p, "--audio"))             cfg->iso_audio          = true;
        else if (!strcmp(p, "--gpu"))               cfg->iso_gpu            = true;
        else if (!strcmp(p, "--xdg-runtime"))       cfg->iso_xdg_runtime    = true;
        else if (!strcmp(p, "--no-seccomp"))        cfg->iso_no_seccomp     = true;
        else if (!strcmp(p, "--seccomp-strict") || !strcmp(p, "-q")) cfg->seccomp_strict = true;
        else if (!strcmp(p, "--allow-clone3") || !strcmp(p, "-k"))   cfg->allow_clone3   = true;
        else if (!strcmp(p, "--friendly-sandbox"))  cfg->friendly_sandbox   = true;
        else if (!strcmp(p, "--permissive"))        cfg->permissive_sandbox = true;
        else if (!strcmp(p, "--chroot"))            cfg->iso_use_chroot     = true;
        else if (!strcmp(p, "--no-fuse"))           cfg->no_fuse            = true;
        else if (!strcmp(p, "--no-preflight"))      cfg->skip_preflight     = true;
        else if (!strncmp(p, "--dev ", 6))          cfg->iso_dev_level      = atoi(p + 6);
        else if (!strncmp(p, "--preset ", 9))       cfg->iso_preset         = strdup(p + 9);
        else if (!strncmp(p, "--display ", 10))     cfg->iso_display        = strdup(p + 10);
        else if (!strncmp(p, "--wayland-display ", 18)) cfg->iso_wayland_disp = strdup(p + 18);
        else if (!strncmp(p, "--hostname ", 11))    cfg->iso_hostname       = strdup(p + 11);
        else if (!strncmp(p, "--max-procs ", 12))   cfg->iso_max_procs      = atoi(p + 12);
        else if (!strncmp(p, "--max-mem ", 10))     cfg->iso_max_mem_gb     = atoi(p + 10);
        else if (!strncmp(p, "--max-filesize ", 15)) cfg->iso_max_fsize_mb  = atoi(p + 15);
        else if (!strncmp(p, "--max-fds ", 10))     cfg->iso_max_fds        = atoi(p + 10);
        else if (!strncmp(p, "--tmp-size ", 11))    cfg->iso_tmp_size_mb    = atoi(p + 11);
        else {
            fprintf(stderr, "š  profile '%s': unknown flag '%s'  skipped\n", path, p);
        }
    }
    fclose(f);
}

/*
 *  Parsing Helpers
 * */
static long parse_int_arg(const char *s, long min, long max, const char *flag_name, int *err) {
    char *endptr;
    errno = 0;
    long val = strtol(s, &endptr, 10);
    if (errno != 0 || endptr == s || *endptr != '\0') {
        fprintf(stderr, "š  invalid integer for %s: '%s'\n", flag_name, s);
        if (err) *err = 1;
        return 0;
    }
    if (val < min || val > max) {
        fprintf(stderr, "š  value for %s out of range [%ld..%ld]: %ld\n", flag_name, min, max, val);
        if (err) *err = 1;
        return 0;
    }
    return val;
}

/*
 *  cli_mkdir_p  creates all intermediate path components
 *  path: COMPLETE path of directory to create (does not include filename)
 * */
static int cli_mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    size_t len = snprintf(tmp, sizeof(tmp), "%s", path);
    if (len == 0 || len >= sizeof(tmp)) { errno = ENAMETOOLONG; return -1; }

    if (len > 0 && tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

/*
 *  cli_expand_tilde  expands "~" and "~/rest" to real $HOME
 * */
static void cli_expand_tilde(const char *in, char *out, size_t out_sz) {
    if (in[0] != '~' || (in[1] != '/' && in[1] != '\0')) {
        snprintf(out, out_sz, "%s", in);
        return;
    }

    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') {
        struct passwd *pw = getpwuid(getuid());
        home = (pw && pw->pw_dir) ? pw->pw_dir : NULL;
    }
    if (!home) {
        fprintf(stderr, "š  cli_expand_tilde: HOME not set, keeping '%s' literal\n", in);
        snprintf(out, out_sz, "%s", in);
        return;
    }

    if (in[1] == '\0')
        snprintf(out, out_sz, "%s", home);          /* "~"       -> "$HOME"      */
    else
        snprintf(out, out_sz, "%s%s", home, in + 1); /* "~/foo"  -> "$HOME/foo"  */
}

/*
 *  bind_path_is_safe  prevents path traversal outside vault_path
 * */
static bool bind_path_is_safe(const char *vault_path, const char *dst) {
    char resolved_vault[PATH_MAX];
    if (!realpath(vault_path, resolved_vault)) return false;

    char probe[PATH_MAX];
    snprintf(probe, sizeof(probe), "%s", dst);
    char resolved_probe[PATH_MAX];

    while (!realpath(probe, resolved_probe)) {
        char *slash = strrchr(probe, '/');
        if (!slash || slash == probe) return false;
        *slash = '\0';
    }

    size_t vlen = strlen(resolved_vault);
    return strncmp(resolved_probe, resolved_vault, vlen) == 0 &&
           (resolved_probe[vlen] == '/' || resolved_probe[vlen] == '\0');
}

/*
 *  Main Parser
 * */

static int parse_flags(int argc, char **argv, CliConfig *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->vault_id       = -1;
    cfg->rule_hour_from = -1;
    cfg->rule_hour_to   = -1;

    optind = 0;

    int opt, opt_index = 0;
    while ((opt = getopt_long(argc, argv, "qk", long_options, &opt_index)) != -1) {
        switch (opt) {
        case OPT_VAULT:    cfg->vault_id    = (int32_t)atoi(optarg); break;
        case OPT_LS:       cfg->op_ls       = true; break;
        case OPT_INFO:     cfg->op_info     = true; break;
        case OPT_FILES:    cfg->op_files    = true; break;
        case OPT_STATUS:   cfg->op_status   = true; break;
        case OPT_SCAN:     cfg->op_scan     = true; break;
        case OPT_ENCRYPT:  cfg->op_encrypt  = true; break;
        case OPT_DECRYPT:  cfg->op_decrypt  = true; break;
        case OPT_RESOLVE:  cfg->op_resolve  = true; break;
        case OPT_MOUNT:    cfg->op_mount    = true; break;
        case OPT_UMOUNT:   cfg->op_umount   = true; break;
        case OPT_MOUNT_EXPORT: cfg->op_mount_export = true; break;
        case OPT_EXPORT:   cfg->op_export   = true; break;
        case OPT_FILE:     cfg->export_file = optarg; break;
        case OPT_DEST:     cfg->export_dest = optarg; break;
        case OPT_RM:       cfg->op_rm       = true; break;
        case OPT_RENAME:   cfg->op_rename   = true; cfg->rename_to = optarg; break;
        case OPT_UNLOCK:   cfg->op_unlock   = true; break;
        case OPT_PASSWD:   cfg->op_passwd   = true; break;
        case OPT_RULE:
            cfg->op_rule        = true;
            cfg->rule_max_fails = atoi(optarg);
            break;
        case OPT_HOURS: {
            char *dash = strchr(optarg, '-');
            if (!dash) { print_err("--hours: use format 9-18"); return -1; }
            cfg->rule_hour_from = atoi(optarg);
            cfg->rule_hour_to   = atoi(dash + 1);
            break;
        }
        case OPT_NEW:       cfg->new_name        = optarg; break;
        case OPT_PATH:      cfg->new_path         = optarg; break;
        case OPT_PROTECTED: cfg->protected_vault  = true;   break;
        case OPT_ENGINE:
            cfg->engine_level = atoi(optarg);
            if (cfg->engine_level < 0 || cfg->engine_level > 5) {
                print_err("--engine: value must be 0-5"); return -1;
            }
            break;
        /* WORM */
        case OPT_WORM_STATUS:    cfg->op_worm_status      = true;                 break;
        case OPT_PROTECT_DELETE: cfg->worm_set            |= WORM_PROTECT_DELETE; break;
        case OPT_PROTECT_RENAME: cfg->worm_set            |= WORM_PROTECT_RENAME; break;
        case OPT_PROTECT_WRITE:  cfg->worm_set            |= WORM_PROTECT_WRITE;  break;
        case OPT_PROTECT_READ:   cfg->worm_set            |= WORM_PROTECT_READ;   break;
        case OPT_PROTECTED_SCAN: cfg->worm_protected_scan  = true;                break;
        case OPT_CLEAR_DELETE:   cfg->worm_clear          |= WORM_PROTECT_DELETE; break;
        case OPT_CLEAR_RENAME:   cfg->worm_clear          |= WORM_PROTECT_RENAME; break;
        case OPT_CLEAR_WRITE:    cfg->worm_clear          |= WORM_PROTECT_WRITE;  break;
        case OPT_CLEAR_READ:     cfg->worm_clear          |= WORM_PROTECT_READ;   break;
        case OPT_WHITE_LIST:
            if (!strcmp(optarg, "-e") || !strcmp(optarg, "exclude") || !strcmp(optarg, "e")) {
                cfg->op_whitelist_exclude = true;
            } else if (!strcmp(optarg, "-r") || !strcmp(optarg, "restore") || !strcmp(optarg, "r")) {
                cfg->op_whitelist_restore = true;
            } else {
                print_err("--white-list must be '-e' or '-r'");
                return -1;
            }
            break;
        case OPT_IMAGE:
            cfg->image_url = optarg;
            break;
        /* run */
        case OPT_RUN: cfg->run_exec = optarg; break;
        /* isolation */
        case OPT_NO_NET:       cfg->iso_no_net      = true;   break;
        case OPT_UUID:         cfg->iso_uuid        = true;   break;
        case OPT_INIT:
            cfg->iso_init        = true;
            cfg->iso_uuid        = true;
            break;
        case OPT_NET_VETH: {
            cfg->iso_net_veth = true;
            const char *ip = (optarg && *optarg) ? optarg : "10.0.0.3";
            struct in_addr a;
            if (inet_pton(AF_INET, ip, &a) != 1) {
                print_err("--net-veth: Invalid IPv4"); return -1;
            }
            cfg->iso_net_veth_ip = (char *)ip;
            cfg->iso_net_veth_gw = "10.0.0.2";
            break;
        }
        case OPT_NFILTER:
            cfg->iso_nfilter = true;
            if (optarg && *optarg) {
                for (const char *p = optarg; *p; p++) {
                    if (!isalnum((unsigned char)*p) && *p != '_') {
                        print_err("--nfilter: invalid name (alphanumeric and _ only)"); return -1;
                    }
                }
                cfg->iso_nfilter_jail = optarg;
            } else {
                cfg->iso_nfilter_jail = "nuk4sd_jail";
            }
            break;
        case OPT_ALLOW_IP: {
            struct in_addr a;
            if (inet_pton(AF_INET, optarg, &a) != 1) {
                print_err("--allow-ip: Invalid IPv4"); return -1;
            }
            cfg->iso_nfilter = true;
            if (!cfg->iso_nfilter_jail)
                cfg->iso_nfilter_jail = "nuk4sd_jail";
            if (user_send_set_ip(cfg->iso_nfilter_jail, optarg) != 0) {
                print_warn("Failed to add IP to whitelist");
            }
            break;
        }
        case OPT_WAYLAND:      cfg->iso_wayland     = true;   break;
        case OPT_X11:          cfg->iso_x11         = true;   break;
        case OPT_RO_HOME:      cfg->iso_ro_home     = true;   break;
        case OPT_NO_DBUS:      cfg->iso_no_dbus     = true;   break;
        case OPT_TMP_HOME:     cfg->iso_tmp_home    = true;   break;
        case OPT_AUDIT:        cfg->iso_audit       = true;   break;
        case OPT_NO_PROC:      cfg->iso_no_proc     = true;   break;
        case OPT_NEW_SESSION:  cfg->iso_new_session = true;   break;
        case OPT_UNSHARE_IPC:  cfg->iso_unshare_ipc = true;  break;
        case OPT_UNSHARE_UTS:  cfg->iso_unshare_uts = true;  break;
        case OPT_HOSTNAME:     cfg->iso_hostname    = optarg; break;
        case OPT_PROFILE:      cfg->iso_profile     = optarg; break;
        /* desktop runtime */
        case OPT_AUDIO:        cfg->iso_audio        = true;   break;
        case OPT_GPU:          cfg->iso_gpu          = true;   break;
        case OPT_XDG_RUNTIME:  cfg->iso_xdg_runtime  = true;   break;
        case OPT_NO_SECCOMP:   cfg->iso_no_seccomp   = true;   break;
        case OPT_CHROOT:       cfg->iso_use_chroot   = true;   break;
        case OPT_DISPLAY_OPT:  cfg->iso_display      = optarg; break;
        case OPT_WAYLAND_DISPLAY: cfg->iso_wayland_disp = optarg; break;
        case OPT_PRESET:       cfg->iso_preset       = optarg; break;
        case OPT_DBUS:
            if (!strcmp(optarg, "session") || !strcmp(optarg, "both"))
                cfg->iso_dbus_session = true;
            if (!strcmp(optarg, "system")  || !strcmp(optarg, "both"))
                cfg->iso_dbus_system  = true;
            if (!strcmp(optarg, "session") || !strcmp(optarg, "system") || !strcmp(optarg, "both"))
                break;
            print_err("--dbus: use 'session', 'system' or 'both'");
            return -1;
        case OPT_DEV:
            if      (!strcmp(optarg, "minimal")  || !strcmp(optarg, "1")) cfg->iso_dev_level = 1;
            else if (!strcmp(optarg, "standard") || !strcmp(optarg, "2")) cfg->iso_dev_level = 2;
            else { print_err("--dev: use 'minimal', 'standard', '1' or '2'"); return -1; }
            break;
        case OPT_MOUNT_DEV:
            cfg->iso_mount_dev = true;
            break;
        case OPT_MAX_PROCS: {
            int _e = 0;
            cfg->iso_max_procs    = (int)parse_int_arg(optarg, 1, 65535, "--max-procs", &_e);
            if (_e) return -1;
            break;
        }
        case OPT_MAX_MEM: {
            int _e = 0;
            cfg->iso_max_mem_gb   = (int)parse_int_arg(optarg, 1, 512, "--max-mem", &_e);
            if (_e) return -1;
            break;
        }
        case OPT_MAX_FSIZE: {
            int _e = 0;
            cfg->iso_max_fsize_mb = (int)parse_int_arg(optarg, 1, 102400, "--max-filesize", &_e);
            if (_e) return -1;
            break;
        }
        case OPT_MAX_FDS: {
            int _e = 0;
            cfg->iso_max_fds      = (int)parse_int_arg(optarg, 1, 65535, "--max-fds", &_e);
            if (_e) return -1;
            break;
        }
        case OPT_TMP_SIZE: {
            int _e = 0;
            cfg->iso_tmp_size_mb  = (int)parse_int_arg(optarg, 1, 102400, "--tmp-size", &_e);
            if (_e) return -1;
            break;
        }
        /* general */
        case OPT_PASSWORD: cfg->password    = optarg; break;
        case OPT_VERBOSE:  cfg->verbose     = true;   break;
        case OPT_JSON:     cfg->json_output = true;   break;
        case OPT_VERSION:  cfg->op_version  = true;   break;
        case OPT_HELP:     cfg->op_help     = true;   break;
        case 'q':          cfg->seccomp_strict = true; break;
        case 'k':          cfg->allow_clone3   = true; break;
        case OPT_FRIENDLY_SANDBOX: cfg->friendly_sandbox = true; break;
        case OPT_ADAPTER:  cfg->iso_adapter    = optarg; break;
        /* cgroups v1/v2 */
        case OPT_CGROUP:
            cfg->iso_cgroup = true;
            cfg->iso_unshare_cgroup = true;
            if (optarg && optarg[0]) cfg->iso_cgroup_name = optarg;
            break;
        case OPT_CGROUP_NAME:
            cfg->iso_cgroup = true;
            cfg->iso_cgroup_name = optarg;
            break;
        case OPT_CPU_SHARES: {
            int _e = 0;
            cfg->iso_cpu_shares = (int)parse_int_arg(optarg, 2, 262144, "--cpu-shares", &_e);
            if (_e) return -1;
            cfg->iso_cgroup = true;
            break;
        }
        case OPT_CPU_QUOTA: {
            int _e = 0;
            cfg->iso_cpu_quota_us = (int)parse_int_arg(optarg, 1000, 10000000, "--cpu-quota", &_e);
            if (_e) return -1;
            cfg->iso_cgroup = true;
            break;
        }
        case OPT_CGROUP_MEM: {
            int _e = 0;
            cfg->iso_cgroup_mem_mb = (int)parse_int_arg(optarg, 16, 1048576, "--cgroup-mem", &_e);
            if (_e) return -1;
            cfg->iso_cgroup = true;
            break;
        }
        case OPT_NO_PREFLIGHT: cfg->skip_preflight = true; break;
        case OPT_NO_FUSE:      cfg->no_fuse        = true; break;
        case OPT_HEALTH: {
            pid_t target = (pid_t)atoi(optarg);
            if (target <= 0) {
                fprintf(stderr, "error: --health requires a valid PID\n");
                free(cfg);
                return 1;
            }
            int r = sandbox_health_check(target);
            free(cfg);
            return r;
        }
        /* bind mounts */
        case OPT_RO:
            if (cfg->bind_count < MAX_BINDS) {
                cli_expand_tilde(optarg, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
                cfg->binds[cfg->bind_count++].type = BIND_RO;
            }
            break;
        case OPT_RW:
            if (cfg->bind_count < MAX_BINDS) {
                cli_expand_tilde(optarg, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
                cfg->binds[cfg->bind_count++].type = BIND_RW;
            }
            break;
        case OPT_BLACKLIST:
            if (cfg->bind_count < MAX_BINDS) {
                cli_expand_tilde(optarg, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
                cfg->binds[cfg->bind_count++].type = BIND_BLACKLIST;
            }
            break;
        /* Extended file operations */
        case OPT_ADD:
            cfg->op_add = true;
            cfg->add_file = optarg;
            break;
        case OPT_RECURSIVE:
            cfg->add_recursive = true;
            break;
        case OPT_REPLACE:
            cfg->add_replace = true;
            break;
        case OPT_PRESERVE:
            cfg->add_preserve = true;
            break;
        case OPT_EXTRACT:
            cfg->op_extract = true;
            cfg->extract_file = optarg;
            break;
        case OPT_FORCE:
            cfg->extract_force = true;
            break;
        case OPT_MV:
            cfg->op_mv = true;
            cfg->mv_src = optarg;
            if (optind < argc && argv[optind][0] != '-') {
                cfg->mv_dest = argv[optind++];
            }
            break;
        case OPT_CP:
            cfg->op_cp = true;
            cfg->cp_src = optarg;
            if (optind < argc && argv[optind][0] != '-') {
                cfg->cp_dest = argv[optind++];
            }
            break;
        case OPT_RM_FILE:
            cfg->op_rm_file = true;
            cfg->rm_file_target = optarg;
            break;
        case OPT_MKDIR:
            cfg->op_mkdir = true;
            cfg->mkdir_target = optarg;
            break;
        case OPT_RMDIR:
            cfg->op_rmdir = true;
            cfg->rmdir_target = optarg;
            break;
        case OPT_TREE:
            cfg->op_tree = true;
            break;
        case OPT_DU:
            cfg->op_du = true;
            break;
        case OPT_FIND:
            cfg->op_find = true;
            cfg->find_pattern = optarg;
            break;
        /* Snapshots & Immutable Versioning */
        case OPT_SNAPSHOT:
            cfg->op_snapshot = true;
            if (optarg && optarg[0]) {
                cfg->snapshot_tag = optarg;
            } else if (optind < argc && argv[optind][0] != '-') {
                cfg->snapshot_tag = argv[optind++];
            }
            break;
        case OPT_SNAPSHOTS:
            cfg->op_snapshots = true;
            break;
        case OPT_SNAPSHOT_DELETE:
            cfg->op_snapshot_delete = true;
            cfg->snapshot_del_tag = optarg;
            break;
        case OPT_SNAPSHOT_RESTORE:
            cfg->op_snapshot_restore = true;
            cfg->snapshot_restore_tag = optarg;
            break;
        case OPT_SNAPSHOT_DIFF:
            cfg->op_snapshot_diff = true;
            cfg->snapshot_diff_tag1 = optarg;
            if (optind < argc && argv[optind][0] != '-') {
                cfg->snapshot_diff_tag2 = argv[optind++];
            }
            break;
        /*  Cryptographic Integrity  */
        case OPT_HASH:
            cfg->op_hash = true;
            if (optarg && optarg[0]) {
                cfg->hash_target = optarg;
            } else if (optind < argc && argv[optind][0] != '-') {
                cfg->hash_target = argv[optind++];
            }
            break;
        case OPT_BASELINE:
            cfg->op_baseline = true;
            break;
        case OPT_VERIFY:
            cfg->op_verify = true;
            break;
        case OPT_INTEGRITY:
            cfg->op_integrity = true;
            break;
        case OPT_REPAIR:
            cfg->op_repair = true;
            break;
        case OPT_DIFF:
            cfg->op_diff = true;
            if (optarg && optarg[0]) {
                cfg->diff_other = optarg;
            } else if (optind < argc && argv[optind][0] != '-') {
                cfg->diff_other = argv[optind++];
            }
            break;
        /*  Backup & Import  */
        case OPT_BACKUP:
            cfg->op_backup = true;
            if (optarg && optarg[0]) {
                cfg->backup_out = optarg;
            } else if (optind < argc && argv[optind][0] != '-') {
                cfg->backup_out = argv[optind++];
            }
            break;
        case OPT_RESTORE_ARCH:
            cfg->op_restore = true;
            cfg->restore_archive = optarg;
            break;
        case OPT_IMPORT:
            cfg->op_import = true;
            cfg->import_src = optarg;
            break;
        /*  Lock/Unlock  */
        case OPT_LOCK:
            cfg->op_lock = true;
            break;
        case OPT_LOCK_STATUS:
            cfg->op_lock_status = true;
            break;
        case OPT_FORCE_UNLOCK:
            cfg->op_force_unlock = true;
            break;
        /*  Key Lifecycle  */
        case OPT_KEY_INFO:
            cfg->op_key_info = true;
            break;
        case OPT_KEY_ROTATE:
            cfg->op_key_rotate = true;
            cfg->key_rotate_old = optarg;
            if (optind < argc && argv[optind][0] != '-') {
                cfg->key_rotate_new = argv[optind++];
            }
            break;
        case OPT_REKEY:
            cfg->op_rekey = true;
            break;
        /*  Observability  */
        case OPT_STATS:
            cfg->op_stats = true;
            break;
        case OPT_USAGE:
            cfg->op_usage = true;
            break;
        case OPT_INSPECT:
            cfg->op_inspect = true;
            cfg->inspect_target = optarg;
            break;
        case OPT_HISTORY:
            cfg->op_history = true;
            break;
        case OPT_EVENTS:
            cfg->op_events = true;
            break;
        case OPT_APP_ARMOR:
            cfg->op_app_armor = true;
            cfg->app_armor_target = optarg; /* "all" or "vault-<id>" */
            break;
        case OPT_MAC_ENABLE:
            cfg->op_mac_enable = true;
            break;
        case OPT_DISABLE_APPARMOR:
            cfg->op_disable_apparmor = true;
            if (optarg)
                cfg->app_armor_target = optarg; /* vault-<id> or NULL = all */
            break;
        case OPT_MAC_STATUS:
            cfg->op_mac_status = true;
            break;
        case OPT_GENERATE_SECRET:
            cfg->op_generate_secret = true;
            break;
        case OPT_MANUAL:
            cfg->op_manual = true;
            break;
        case OPT_SYSINFO:
            cfg->op_sysinfo = true;
            if (optarg && optarg[0])
                cfg->sysinfo_target = optarg;
            break;
        case OPT_GUI:
            cfg->op_gui = true;
            cfg->iso_preset = "nuk4sd-gui";
            break;
        case '?':
        default:
            fprintf(stderr, "  Use --help for usage.\n");
            return -1;
        }
    }

    if (cfg->run_exec && optind < argc) {
        cfg->run_argv = &argv[optind];
        cfg->run_argc = argc - optind;
    }

    if (cfg->iso_profile)
        load_profile(cfg, cfg->iso_profile);

    if (cfg->iso_preset) {
        const char *p = cfg->iso_preset;
        if (!strcmp(p, "firefox") || !strcmp(p, "browser") || !strcmp(p, "flameshot")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_audio        = true;
            cfg->iso_dbus_session = true;
            cfg->iso_gpu          = true;
            cfg->iso_xdg_runtime  = true;
            cfg->iso_rw_home      = true;
            cfg->permissive_sandbox = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 2;  /* standard */
            setenv("MOZ_WEBRENDER", "software", 0);
            setenv("LIBGL_ALWAYS_SOFTWARE", "1", 0);
        } else if (!strcmp(p, "office") || !strcmp(p, "evince") || !strcmp(p, "gnome-calculator") || !strcmp(p, "nautilus")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_audio        = true;
            cfg->iso_dbus_session = true;
            cfg->iso_xdg_runtime  = true;
            cfg->iso_rw_home      = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 1;  /* minimal */
        } else if (!strcmp(p, "dev") || !strcmp(p, "code") || !strcmp(p, "gedit")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_dbus_session = true;
            cfg->iso_xdg_runtime  = true;
            cfg->iso_rw_home      = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 1;
        } else if (!strcmp(p, "media") || !strcmp(p, "celluloid") || !strcmp(p, "hypnotix")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_audio        = true;
            cfg->iso_gpu          = true;
            cfg->iso_dbus_session = true;
            cfg->iso_xdg_runtime  = true;
            cfg->iso_rw_home      = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 2;
        } else if (!strcmp(p, "nuk4sd-gui")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_dbus_session = true;
            cfg->iso_xdg_runtime  = true;
            cfg->iso_gpu          = true;
            cfg->iso_rw_home      = true;
            cfg->permissive_sandbox = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 2;
        } else if (!strcmp(p, "minimal")) {
            /* basic sandbox without display */
        } else {
            fprintf(stderr, "š  unknown preset '%s'. Available: firefox, browser, office, evince, dev, code, gedit, media, celluloid, hypnotix, flameshot, nautilus, nuk4sd-gui, minimal\n", p);
        }
    }

    if (cfg->iso_no_net && cfg->iso_net_veth) {
        print_err("[SECURITY] Conflict: --no-net and --net-veth are mutually exclusive.");
        return -1;
    }
    if (cfg->iso_nfilter && !cfg->iso_net_veth) {
        print_err("[SECURITY] --nfilter requires isolated network enabled (--net-veth).");
        return -1;
    }

    return 0;
}

/*
 *  run_isolated()  runs program inside vault sandbox
 * */
#ifdef __linux__

static uid_t resolve_real_uid(void) {
    uid_t real_uid = getuid();
    const char *sudo_uid_s = getenv("SUDO_UID");
    if (sudo_uid_s && *sudo_uid_s) {
        errno = 0;
        char *end = NULL;
        long parsed = strtol(sudo_uid_s, &end, 10);
        if (errno == 0 && end != sudo_uid_s && *end == '\0' &&
            parsed >= 0 && parsed <= 65535)
            real_uid = (uid_t)parsed;
    }
    return real_uid;
}

static gid_t resolve_real_gid(void) {
    gid_t real_gid = getgid();
    const char *sudo_gid_s = getenv("SUDO_GID");
    if (sudo_gid_s && *sudo_gid_s) {
        errno = 0;
        char *end = NULL;
        long parsed = strtol(sudo_gid_s, &end, 10);
        if (errno == 0 && end != sudo_gid_s && *end == '\0' &&
            parsed >= 0 && parsed <= 65535)
            real_gid = (gid_t)parsed;
    }
    return real_gid;
}

static int run_isolated(CliConfig *cfg, char *vault_path) {
    if (cfg->run_exec && !cfg->skip_preflight) {
        preflight_scan(cfg, cfg->run_exec);
    } else if (cfg->run_exec && cfg->skip_preflight) {
        fprintf(stderr, "[RUN] preflight_scan disabled via --no-preflight\n");
    }

    uid_t real_uid = resolve_real_uid();
    gid_t real_gid = resolve_real_gid();
    bool gui_mode = cfg->iso_wayland || cfg->iso_x11;

    char jail_root[PATH_MAX];
    snprintf(jail_root, sizeof(jail_root), "/tmp/Nuk4sd-jail-XXXXXX");
    if (mkdtemp(jail_root) == NULL) {
        perror("[RUN] mkdtemp jail_root in /tmp");
        return -1;
    }
    const char *vault_path_orig = vault_path;
    vault_path = jail_root;

    int sync_pipe[2], ready_pipe[2];
    if (pipe(sync_pipe) != 0 || pipe(ready_pipe) != 0) {
        perror("[RUN] pipe"); return -1;
    }
    int net_ready_pipe[2] = { -1, -1 }, net_sync_pipe[2] = { -1, -1 };
    if (cfg->iso_net_veth) {
        if (pipe(net_ready_pipe) != 0 || pipe(net_sync_pipe) != 0) {
            perror("[RUN] net pipe"); return -1;
        }
    }

    if (cfg->iso_audit) {
        fprintf(stderr, "[audit] exec:         %s\n", cfg->run_exec);
        fprintf(stderr, "[audit] vault_path:   %s\n", vault_path);
        fprintf(stderr, "[audit] no-net=%d  wayland=%d  x11=%d  ro-home=%d\n",
                cfg->iso_no_net, cfg->iso_wayland, cfg->iso_x11, cfg->iso_ro_home);
        fprintf(stderr, "[audit] no-dbus=%d  tmp-home=%d  no-proc=%d\n",
                cfg->iso_no_dbus, cfg->iso_tmp_home, cfg->iso_no_proc);
        fprintf(stderr, "[audit] unshare-ipc=%d  unshare-uts=%d  new-session=%d\n",
                cfg->iso_unshare_ipc, cfg->iso_unshare_uts, cfg->iso_new_session);
        for (int i = 0; i < cfg->bind_count; i++) {
            const char *t = cfg->binds[i].type == BIND_RO       ? "ro"
                          : cfg->binds[i].type == BIND_RW       ? "rw"
                          :                                        "blacklist";
            fprintf(stderr, "[audit] bind[%d]: --%s %s\n", i, t, cfg->binds[i].path);
        }
    }

    {
        const char *bpaths[MAX_BINDS];
        int         btypes[MAX_BINDS];
        for (int i = 0; i < cfg->bind_count; i++) {
            bpaths[i] = cfg->binds[i].path;
            btypes[i] = (int)cfg->binds[i].type;
        }
        cli_log_sandbox_config(
            cfg->run_exec, vault_path,
            cfg->iso_no_net, cfg->iso_wayland, cfg->iso_x11,
            cfg->iso_no_dbus, cfg->iso_ro_home, cfg->iso_tmp_home,
            cfg->iso_no_proc, cfg->iso_unshare_ipc, cfg->iso_unshare_uts,
            cfg->iso_new_session, cfg->iso_hostname,
            cfg->bind_count, bpaths, btypes
        );
    }

    pid_t pid = fork();
    if (pid < 0) { perror("[RUN] fork"); return -1; }

    /*
     *  PARENT PROCESS
     * */
    if (pid > 0) {
        vault_auth_pid_add_ffi(pid);

        close(ready_pipe[1]);
        close(sync_pipe[0]);

        char c;
        if (read(ready_pipe[0], &c, 1) != 1)
            perror("[RUN] ready_pipe read");
        close(ready_pipe[0]);

        if (vsb_write_uid_gid_map(pid, real_uid, real_gid) != 0) {
            fprintf(stderr, "[RUN][FATAL] uid_map/gid_map failed  aborting sandbox.\n");
            kill(pid, SIGKILL);
            close(sync_pipe[1]);
            int status;
            waitpid(pid, &status, 0);
            vault_auth_pid_remove_ffi(pid);
            umount2(jail_root, MNT_DETACH);
            rmdir(jail_root);
            return -1;
        }

        char cg_name[128] = {0};
        bool cg_applied = false;
        if (cfg->iso_cgroup || cfg->iso_cpu_shares > 0 || cfg->iso_cpu_quota_us > 0 || cfg->iso_cgroup_mem_mb > 0) {
            if (cfg->iso_cgroup_name && cfg->iso_cgroup_name[0]) {
                snprintf(cg_name, sizeof(cg_name), "nuk4sd/%s", cfg->iso_cgroup_name);
            } else {
                snprintf(cg_name, sizeof(cg_name), "nuk4sd/sandbox-%d", (int)pid);
            }
            long long mem_mb = cfg->iso_cgroup_mem_mb > 0
                ? (long long)cfg->iso_cgroup_mem_mb
                : (cfg->iso_max_mem_gb > 0 ? (long long)cfg->iso_max_mem_gb * 1024 : 0);
            unsigned long long shares = cfg->iso_cpu_shares > 0 ? (unsigned long long)cfg->iso_cpu_shares : 1024;
            long long quota = cfg->iso_cpu_quota_us > 0 ? (long long)cfg->iso_cpu_quota_us : 0;
            long long procs = cfg->iso_max_procs > 0 ? (long long)cfg->iso_max_procs : 0;

            int rc = rust_cgroup_apply(cg_name, (unsigned long long)pid, mem_mb, shares, quota, procs);
            if (rc == 0) {
                cg_applied = true;
                if (cfg->verbose) {
                    printf("[CGROUP] Cgroup '%s' applied successfully to PID %d.\n", cg_name, (int)pid);
                }
            } else {
                if (cfg->iso_cgroup) {
                    fprintf(stderr, "[RUN][FATAL] Failed to apply cgroup '%s' to PID %d (no cgroup delegation on host).\n", cg_name, (int)pid);
                    kill(pid, SIGKILL);
                    close(sync_pipe[1]);
                    int status;
                    waitpid(pid, &status, 0);
                    vault_auth_pid_remove_ffi(pid);
                    umount2(jail_root, MNT_DETACH);
                    rmdir(jail_root);
                    return -1;
                } else {
                    fprintf(stderr, "[CGROUP][WARN] Cgroup unavailable on host  maintaining default rlimit bounds.\n");
                }
            }
        }

        close(sync_pipe[1]);

        if (cfg->iso_net_veth) {
            close(net_ready_pipe[1]);
            close(net_sync_pipe[0]);
            char nr;
            if (read(net_ready_pipe[0], &nr, 1) == 1) {
                const char *j_ip = cfg->iso_net_veth_ip ? cfg->iso_net_veth_ip : "10.0.0.3";
                const char *g_ip = cfg->iso_net_veth_gw ? cfg->iso_net_veth_gw : "10.0.0.2";
                vsb_net_veth_setup(pid, j_ip, g_ip, "nuk4sd-veth");
            }
            close(net_ready_pipe[0]);
            char ns = 'k';
            write(net_sync_pipe[1], &ns, 1);
            close(net_sync_pipe[1]);
        }

        int status;
        waitpid(pid, &status, 0);
        vault_auth_pid_remove_ffi(pid);

        if (cg_applied && cg_name[0]) {
            rust_cgroup_cleanup(cg_name);
        }

        if (cfg->iso_net_veth) {
            vsb_cleanup_veth("nuk4sd-veth");
        }

        if (umount2(jail_root, MNT_DETACH) != 0)
            fprintf(stderr, "[RUN] umount jail_root '%s': %s (non-fatal)\n",
                    jail_root, strerror(errno));
        rmdir(jail_root);

        if (WIFSIGNALED(status)) {
            fprintf(stderr, "[RUN] process killed by signal %d "
                    "(possible seccomp/namespace violation)\n", WTERMSIG(status));
            cli_log_sandbox_exit(pid, -1, WTERMSIG(status));
            return -1;
        }
        int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        cli_log_sandbox_exit(pid, exit_code, 0);
        return exit_code;
    }

    /*
     *  CHILD PROCESS  5-layer sandbox + extra isolations
     * */
    close(sync_pipe[1]);
    close(ready_pipe[0]);
    prctl(PR_SET_NAME, "Nuk4sd-Run", 0, 0, 0);

    /*  [Layer 1] User Namespace  */
    if (unshare(CLONE_NEWUSER) != 0) {
        fprintf(stderr, "[RUN] unshare CLONE_NEWUSER: %s\n", strerror(errno));
        cli_log_namespace_event("CLONE_NEWUSER", CLONE_NEWUSER, getpid(), errno);
        _exit(1);
    }
    cli_log_namespace_event("CLONE_NEWUSER", CLONE_NEWUSER, getpid(), 0);
    { char r = 'r'; write(ready_pipe[1], &r, 1); close(ready_pipe[1]); }
    { char r; read(sync_pipe[0], &r, 1); close(sync_pipe[0]); }

    /*  [Layer 2] Additional Namespaces  */
    int ns_flags = CLONE_NEWNS | CLONE_NEWPID;
    if (cfg->iso_no_net || cfg->iso_net_veth) ns_flags |= CLONE_NEWNET;
    if (cfg->iso_unshare_ipc)                 ns_flags |= CLONE_NEWIPC;
    if (cfg->iso_unshare_uts)                 ns_flags |= CLONE_NEWUTS;
#ifdef CLONE_NEWCGROUP
    if (cfg->iso_cgroup || cfg->iso_unshare_cgroup) ns_flags |= CLONE_NEWCGROUP;
#endif

    if (unshare(ns_flags) != 0) {
        fprintf(stderr, "[RUN] unshare namespaces (0x%x): %s\n",
                ns_flags, strerror(errno));
        cli_log_namespace_event("MOUNT|PID|...", ns_flags, getpid(), errno);
        _exit(1);
    }
    cli_log_namespace_event("CLONE_NEWNS|CLONE_NEWPID|extras", ns_flags, getpid(), 0);

    if (cfg->iso_net_veth) {
        close(net_ready_pipe[0]);
        close(net_sync_pipe[1]);
        char nr = 'r';
        write(net_ready_pipe[1], &nr, 1);
        close(net_ready_pipe[1]);
        char ns;
        if (read(net_sync_pipe[0], &ns, 1) != 1) {
            fprintf(stderr, "[RUN] net_sync_pipe read failed\n");
        }
        close(net_sync_pipe[0]);

        const char *j_ip = cfg->iso_net_veth_ip ? cfg->iso_net_veth_ip : "10.0.0.3";
        const char *g_ip = cfg->iso_net_veth_gw ? cfg->iso_net_veth_gw : "10.0.0.2";
        vsb_configure_veth_inside(j_ip, g_ip, "nuk4sd-veth");

        if (cfg->iso_nfilter) {
            const char *j_name = cfg->iso_nfilter_jail ? cfg->iso_nfilter_jail : "nuk4sd_jail";
            if (nfilterflag(j_name, j_ip) != 0) {
                fprintf(stderr,
                        "[RUN][FATAL] nfilterflag failed for jail '%s' -- "
                        "aborting to prevent execution without network egress filter\n", j_name);
                _exit(1);
            }
        }
    }

    char vault_mount_point[PATH_MAX];
    snprintf(vault_mount_point, sizeof(vault_mount_point), "%s/vault", jail_root);
    if (mkdir(vault_mount_point, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "[RUN] mkdir subfolder of vault '%s': %s\n",
                vault_mount_point, strerror(errno));
        _exit(1);
    }
    if (mount(vault_path_orig, vault_mount_point, NULL, MS_BIND | MS_REC, NULL) != 0) {
        fprintf(stderr, "[RUN] bind-mount vault’'%s': %s\n",
                vault_mount_point, strerror(errno));
        _exit(1);
    }
    fprintf(stderr, "[RUN] jail_root: '%s' (real tmpfs; vault in '%s/vault')\n",
            jail_root, jail_root);

    vsb_prepare_jail(vault_path, gui_mode);

    if (cfg->iso_unshare_uts && cfg->iso_hostname)
        sethostname(cfg->iso_hostname, strlen(cfg->iso_hostname));

    if (cfg->iso_new_session)
        setsid();

    pid_t ns_pid = fork();
    if (ns_pid < 0)  { perror("[RUN] fork PID NS"); _exit(1); }
    if (ns_pid > 0)  {
        int st;
        waitpid(ns_pid, &st, 0);
        if (WIFSIGNALED(st)) {
            int sig = WTERMSIG(st);
            fprintf(stderr,
                "[RUN][FATAL] child process (PID 1 of namespace) killed by signal %d (%s)"
                "  possible seccomp/allowlist violation if sig=31 (SIGSYS). "
                "Check 'dmesg' for 'audit: type=1326 ... comm=\"<process>\" syscall=N'.\n",
                sig, strsignal(sig));
            _exit(128 + sig);
        }
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
    }

    /* •• PID 1 inside namespace ••• */

    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
        perror("[RUN] MS_PRIVATE / (non-fatal)");
    cli_log_mount_event("none", "/", "private", MS_REC | MS_PRIVATE,
                        (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0 ? errno : 0));

    /*  Bind mounts --ro / --rw / --blacklist  */
    for (int i = 0; i < cfg->bind_count; i++) {
        const char *src = cfg->binds[i].path;
        struct stat st;
        if (stat(src, &st) != 0) {
            fprintf(stderr, "[RUN] bind: '%s' not found  skipping\n", src);
            continue;
        }

        switch (cfg->binds[i].type) {

        case BIND_RO: {
            char dst[PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, src);

            if (!bind_path_is_safe(vault_path, dst)) {
                fprintf(stderr, "[RUN] --ro '%s': path escapes vault jail  refusing\n", src);
                cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC, EPERM);
                break;
            }

            if (S_ISDIR(st.st_mode)) {
                if (cli_mkdir_p(dst, 0755) != 0) {
                    fprintf(stderr, "[RUN] --ro mkdir_p '%s': %s\n", dst, strerror(errno));
                    cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC, errno);
                    break;
                }
            } else {
                char parent[PATH_MAX];
                snprintf(parent, sizeof(parent), "%s", dst);
                char *slash = strrchr(parent, '/');
                if (slash) { *slash = '\0'; cli_mkdir_p(parent, 0755); }

                int fd = open(dst, O_CREAT | O_WRONLY, 0666);
                if (fd >= 0) {
                    close(fd);
                } else {
                    fprintf(stderr, "[RUN] --ro open '%s': %s\n", dst, strerror(errno));
                    cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC, errno);
                    break;
                }
            }
            if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) == 0) {
                mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
                int check_fd = open(dst, O_PATH | O_NOFOLLOW | O_CLOEXEC);
                if (check_fd < 0 && errno == ELOOP) {
                    fprintf(stderr, "[RUN] --ro '%s': symlink escape detected  unmounting\n", src);
                    umount2(dst, MNT_DETACH);
                    cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC, EPERM);
                } else {
                    if (check_fd >= 0) close(check_fd);
                    cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC | MS_RDONLY, 0);
                }
            } else {
                fprintf(stderr, "[RUN] --ro bind '%s': %s\n", src, strerror(errno));
                cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC, errno); 
            }
            break;
        }
        case BIND_RW: {
            char dst[PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, src);

            if (!bind_path_is_safe(vault_path, dst)) {
                fprintf(stderr, "[RUN] --rw '%s': path escapes vault jail  refusing\n", src);
                cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, EPERM);
                break;
            }

            if (S_ISDIR(st.st_mode)) {
                if (cli_mkdir_p(dst, 0755) != 0) {
                    fprintf(stderr, "[RUN] --rw mkdir_p '%s': %s\n", dst, strerror(errno));
                    cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, errno);
                    break;
                }
            } else {
                char parent[PATH_MAX];
                snprintf(parent, sizeof(parent), "%s", dst);
                char *slash = strrchr(parent, '/');
                if (slash) { *slash = '\0'; cli_mkdir_p(parent, 0755); }

                int fd = open(dst, O_CREAT | O_WRONLY, 0666);
                if (fd >= 0) {
                    close(fd);
                } else {
                    fprintf(stderr, "[RUN] --rw open '%s': %s\n", dst, strerror(errno));
                    cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, errno);
                    break;
                }
            }

            if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) != 0) {
                fprintf(stderr, "[RUN] --rw bind '%s': %s\n", src, strerror(errno));
                cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, errno);
            } else {
                mount(NULL, dst, NULL,
                      MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_REC, NULL);
                int check_fd = open(dst, O_PATH | O_NOFOLLOW | O_CLOEXEC);
                if (check_fd < 0 && errno == ELOOP) {
                    fprintf(stderr, "[RUN] --rw '%s': symlink escape detected  unmounting\n", src);
                    umount2(dst, MNT_DETACH);
                    cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, EPERM);
                } else {
                    if (check_fd >= 0) close(check_fd);
                    cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, 0);
                }
            }
            break;
        }
        case BIND_BLACKLIST:
            if (S_ISDIR(st.st_mode)) {
                if (mount("tmpfs", src, "tmpfs",
                          MS_NOSUID | MS_NODEV | MS_RDONLY, "size=0") != 0) {
                    fprintf(stderr, "[RUN] --blacklist dir '%s': %s\n",
                            src, strerror(errno));
                    cli_log_mount_event("tmpfs", src, "blacklist-dir",
                                        MS_NOSUID | MS_NODEV | MS_RDONLY, errno);
                } else {
                    cli_log_mount_event("tmpfs", src, "blacklist-dir",
                                        MS_NOSUID | MS_NODEV | MS_RDONLY, 0);
                }
            } else {
                if (mount("/dev/null", src, NULL, MS_BIND, NULL) != 0) {
                    fprintf(stderr, "[RUN] --blacklist file '%s': %s\n",
                            src, strerror(errno));
                    cli_log_mount_event("/dev/null", src, "blacklist-file", MS_BIND, errno);
                } else {
                    cli_log_mount_event("/dev/null", src, "blacklist-file", MS_BIND, 0);
                }
            }
            break;
        }
    }

    /*  --ro-home / --rw-home: Maps original $HOME into jail  */
    if (cfg->iso_ro_home || cfg->iso_rw_home) {
        const char *sudo_user = getenv("SUDO_USER");
        char home[PATH_MAX] = {0};
        if (sudo_user && *sudo_user) {
            bool sudo_user_safe = (strlen(sudo_user) < 64 &&
                                   strpbrk(sudo_user, "/.\\ :@!") == NULL);
            if (sudo_user_safe) {
                snprintf(home, sizeof(home), "/home/%s", sudo_user);
            } else {
                fprintf(stderr, "[RUN] SUDO_USER contains invalid characters  ignoring (possible path traversal)\n");
            }
        }
        if (!home[0]) {
            const char *h = getenv("HOME");
            if (h && *h) {
                snprintf(home, sizeof(home), "%s", h);
            } else {
                struct passwd *pw = getpwuid(real_uid);
                if (pw && pw->pw_dir)
                    snprintf(home, sizeof(home), "%s", pw->pw_dir);
            }
        }

        struct stat st;
        if (home[0] && stat(home, &st) == 0) {
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, home);

            if (cli_mkdir_p(dst, 0755) == 0) {
                char nuk_fuse[VAULT_PATH_MAX];
                snprintf(nuk_fuse, sizeof(nuk_fuse),
                         "%s%s/.local/share/Nuk4sd", vault_path, home);
                umount2(nuk_fuse, MNT_DETACH);

                if (mount(home, dst, NULL, MS_BIND | MS_REC, NULL) == 0) {
                    if (cfg->iso_ro_home) {
                        mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
                    } else {
                        char nuk_mnt[VAULT_PATH_MAX];
                        snprintf(nuk_mnt, sizeof(nuk_mnt),
                                 "%s%s/.local/share/Nuk4sd", vault_path, home);
                        if (cli_mkdir_p(nuk_mnt, 0700) == 0) {
                            mount("tmpfs", nuk_mnt, "tmpfs",
                                  MS_NOSUID | MS_NODEV, "size=4m");
                        }
                    }
                } else {
                    fprintf(stderr, "[RUN] --rw-home bind '%s' -> '%s': %s\n", home, dst, strerror(errno));
                }
            }
        }
    }

    if (cfg->iso_wayland) {
        char xdg[128];
        snprintf(xdg, sizeof(xdg), "/run/user/%d", (int)real_uid);

        char dst_xdg[VAULT_PATH_MAX];
        snprintf(dst_xdg, sizeof(dst_xdg), "%s%s", vault_path, xdg);
        mkdir(dst_xdg, 0700);

        struct stat ws;
        if (stat(xdg, &ws) == 0) {
            if (mount(xdg, dst_xdg, NULL, MS_BIND | MS_REC, NULL) == 0)
                mount(NULL, dst_xdg, NULL,
                      MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        } else {
            fprintf(stderr,
                "[RUN] --wayland: '%s' not found (real uid=%d)  "
                "Wayland socket will not be mounted\n", xdg, (int)real_uid);
        }

        const char *host_wayland_display = getenv("WAYLAND_DISPLAY");
        if (host_wayland_display && *host_wayland_display) {
            setenv("WAYLAND_DISPLAY", host_wayland_display, 1);
        } else {
            char wayland_sock[VAULT_PATH_MAX];
            snprintf(wayland_sock, sizeof(wayland_sock), "%s/wayland-0", xdg);
            struct stat st_w0;
            if (stat(wayland_sock, &st_w0) == 0) {
                setenv("WAYLAND_DISPLAY", "wayland-0", 1);
            } else {
                unsetenv("WAYLAND_DISPLAY");
            }
        }
        setenv("XDG_RUNTIME_DIR", xdg, 1);
        setenv("QT_QPA_PLATFORM", "wayland;xcb", 1);
        setenv("GDK_BACKEND",     "wayland,x11",  1);
    }

    /*  --x11: pass read-only X11 socket  */
    if (cfg->iso_x11) {
        const char *x11_src = "/tmp/.X11-unix";
        char x11_dst[VAULT_PATH_MAX];
        snprintf(x11_dst, sizeof(x11_dst), "%s/tmp/.X11-unix", vault_path);
        mkdir(x11_dst, 01777);

        struct stat xs;
        if (stat(x11_src, &xs) == 0) {
            if (mount(x11_src, x11_dst, NULL, MS_BIND | MS_REC, NULL) == 0)
                mount(NULL, x11_dst, NULL,
                      MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        }

        const char *xauth_src = getenv("XAUTHORITY");
        char xauth_fallback[VAULT_PATH_MAX];
        if (!xauth_src || !*xauth_src) {
            struct passwd *pw = getpwuid(real_uid);
            if (pw && pw->pw_dir) {
                snprintf(xauth_fallback, sizeof(xauth_fallback), "%s/.Xauthority", pw->pw_dir);
                xauth_src = xauth_fallback;
            }
        }
        if (xauth_src && *xauth_src) {
            struct stat xa_st;
            if (stat(xauth_src, &xa_st) == 0 && S_ISREG(xa_st.st_mode)) {
                char xauth_dst[VAULT_PATH_MAX];
                snprintf(xauth_dst, sizeof(xauth_dst), "%s/tmp/.Xauthority", vault_path);
                int fd = open(xauth_dst, O_CREAT | O_WRONLY, 0600);
                if (fd >= 0) close(fd);
                if (mount(xauth_src, xauth_dst, NULL, MS_BIND, NULL) == 0)
                    mount(NULL, xauth_dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
                setenv("XAUTHORITY", "/tmp/.Xauthority", 1);
            } else {
                fprintf(stderr,
                    "[RUN] --x11: XAUTHORITY '%s' not found  "
                    "X11 connection will likely be refused\n", xauth_src);
            }
        }
    }

    if (!cfg->iso_wayland && !cfg->iso_x11) {
        unsetenv("WAYLAND_DISPLAY");
        unsetenv("DISPLAY");
    }

    if (cfg->iso_no_dbus) {
        const char *bus_addr = getenv("DBUS_SESSION_BUS_ADDRESS");
        if (bus_addr && !strncmp(bus_addr, "unix:path=", 10)) {
            
            const char *sock = bus_addr + 10;
            struct stat ds;

            if (stat(sock, &ds) == 0)
                mount("/dev/null", sock, NULL, MS_BIND, NULL);
        }
        unsetenv("DBUS_SESSION_BUS_ADDRESS");
    }

    {
        char j_null[VAULT_PATH_MAX], j_zero[VAULT_PATH_MAX], j_tty[VAULT_PATH_MAX];
        snprintf(j_null, sizeof(j_null), "%s/dev/null", vault_path);
        snprintf(j_zero, sizeof(j_zero), "%s/dev/zero", vault_path);
        snprintf(j_tty,  sizeof(j_tty),  "%s/dev/tty",  vault_path);
        mount("/dev/null", j_null, NULL, MS_BIND, NULL);
        mount("/dev/zero", j_zero, NULL, MS_BIND, NULL);
        mount("/dev/tty",  j_tty,  NULL, MS_BIND, NULL);
    }

    if (!cfg->iso_no_proc) {
        char j_proc[VAULT_PATH_MAX];
        snprintf(j_proc, sizeof(j_proc), "%s/proc", vault_path);
        mkdir(j_proc, 0555);
        mount("proc", j_proc, "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
    }

    if (gui_mode) {
        const char *host_dirs[] = {
            "/usr", "/lib", "/lib64",
            "/usr/share/icons",
            "/etc/fonts", "/etc/alternatives",
            "/etc/ld.so.conf.d",
            "/etc/ssl",
            "/sys/dev/char", "/sys/devices", "/sys/class", NULL
        };

        for (int i = 0; host_dirs[i]; i++) {
            struct stat hst;
            if (stat(host_dirs[i], &hst) != 0) continue;
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, host_dirs[i]);

            if (S_ISDIR(hst.st_mode) && cli_mkdir_p(dst, 0755) != 0) {
                fprintf(stderr, "[RUN] gui-autodir mkdir_p '%s': %s\n", dst, strerror(errno));
                cli_log_mount_event(host_dirs[i], dst, "gui-autodir", MS_BIND | MS_REC, errno);

                continue;
            }
            umount2(dst, MNT_DETACH);
            if (mount(host_dirs[i], dst, NULL, MS_BIND | MS_REC, NULL) == 0) {
                mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
                cli_log_mount_event(host_dirs[i], dst, "gui-autodir", MS_BIND | MS_REC | MS_RDONLY, 0);
            } else {
                fprintf(stderr, "[RUN] gui-autodir bind '%s': %s\n", host_dirs[i], strerror(errno));
                cli_log_mount_event(host_dirs[i], dst, "gui-autodir", MS_BIND | MS_REC, errno);
            }
        }


        const char *etc_files[] = {
            "/etc/ld.so.cache",
            "/etc/nsswitch.conf",
            "/etc/passwd",
            "/etc/group",
            "/etc/localtime",
            "/etc/resolv.conf",
            NULL
        };
        for (int i = 0; etc_files[i]; i++) {
            struct stat est;
            if (stat(etc_files[i], &est) != 0) continue;
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, etc_files[i]);
            char par[VAULT_PATH_MAX];
            snprintf(par, sizeof(par), "%s", dst);
            char *sl = strrchr(par, '/');
            if (sl) { *sl = '\0'; cli_mkdir_p(par, 0755); }
            int fd = open(dst, O_CREAT | O_WRONLY, 0644);
            if (fd >= 0) close(fd);
            if (mount(etc_files[i], dst, NULL, MS_BIND, NULL) == 0) {
                mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
                cli_log_mount_event(etc_files[i], dst, "gui-etc-file", MS_BIND | MS_RDONLY, 0);
            } else {
                fprintf(stderr, "[RUN] gui-etc-file bind '%s': %s\n",
                        etc_files[i], strerror(errno));
                cli_log_mount_event(etc_files[i], dst, "gui-etc-file", MS_BIND, errno);
            }
        }
    }

    /*•
     *  DESKTOP RUNTIME  audio, dbus, gpu, xdg-runtime, dev, display
     * ===================================================================== */

#define ENSURE_XDG_DIR(xdg_buf, xdg_buf_sz)                                    \
    do {                                                                       \
        uid_t _ru_uid = real_uid;                                   \
        char _r[VAULT_PATH_MAX], _ru[VAULT_PATH_MAX], _rxu[VAULT_PATH_MAX];    \
        snprintf(_r,   sizeof(_r),   "%s/run",            vault_path);         \
        snprintf(_ru,  sizeof(_ru),  "%s/run/user",       vault_path);         \
        snprintf(_rxu, sizeof(_rxu), "%s/run/user/%d",    vault_path, (int)_ru_uid); \
        mkdir(_r, 0755); mkdir(_ru, 0755); mkdir(_rxu, 0700);                  \
        snprintf((xdg_buf), (xdg_buf_sz), "/run/user/%d", (int)_ru_uid);       \
    } while(0)

    if (cfg->iso_xdg_runtime) {
        char xdg[128]; ENSURE_XDG_DIR(xdg, sizeof(xdg));
        char xdg_dst[VAULT_PATH_MAX];
        snprintf(xdg_dst, sizeof(xdg_dst), "%s%s", vault_path, xdg);
        struct stat xst;
        if (stat(xdg, &xst) == 0) {
            if (mount(xdg, xdg_dst, NULL, MS_BIND | MS_REC, NULL) == 0)
                mount(NULL, xdg_dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        }
        setenv("XDG_RUNTIME_DIR", xdg, 1);
    }

    if (cfg->iso_audio) {
        char xdg[128]; ENSURE_XDG_DIR(xdg, sizeof(xdg));
        if (!cfg->iso_xdg_runtime) {
            char pw_src[256], pw_dst[VAULT_PATH_MAX];
            snprintf(pw_src, sizeof(pw_src), "%s/pipewire-0", xdg);
            snprintf(pw_dst, sizeof(pw_dst), "%s%s/pipewire-0", vault_path, xdg);
            struct stat pst;
            if (stat(pw_src, &pst) == 0) {
                int fd = open(pw_dst, O_CREAT|O_WRONLY, 0600); if (fd>=0) close(fd);
                mount(pw_src, pw_dst, NULL, MS_BIND, NULL);
            }
            char pulse_src[256], pulse_dst[VAULT_PATH_MAX];
            snprintf(pulse_src, sizeof(pulse_src), "%s/pulse", xdg);
            snprintf(pulse_dst, sizeof(pulse_dst), "%s%s/pulse", vault_path, xdg);
            if (stat(pulse_src, &pst) == 0) {
                mkdir(pulse_dst, 0700);
                mount(pulse_src, pulse_dst, NULL, MS_BIND | MS_REC, NULL);
            }
        }
        char xdg_env[128];
        snprintf(xdg_env, sizeof(xdg_env), "/run/user/%d", (int)real_uid);
        setenv("PIPEWIRE_RUNTIME_DIR", xdg_env, 1);
        setenv("PULSE_RUNTIME_PATH",   xdg_env, 1);
        char pulse_addr[256];
        snprintf(pulse_addr, sizeof(pulse_addr), "unix:%s/pulse/native", xdg_env);
        setenv("PULSE_SERVER", pulse_addr, 1);
    }

    if (cfg->iso_dbus_session && !cfg->iso_xdg_runtime) {
        char xdg[128]; ENSURE_XDG_DIR(xdg, sizeof(xdg));
        char bus_src[256], bus_dst[VAULT_PATH_MAX];
        snprintf(bus_src, sizeof(bus_src), "%s/bus", xdg);
        snprintf(bus_dst, sizeof(bus_dst), "%s%s/bus", vault_path, xdg);
        struct stat bst;
        if (stat(bus_src, &bst) == 0) {
            int fd = open(bus_dst, O_CREAT|O_WRONLY, 0600); if (fd>=0) close(fd);
            mount(bus_src, bus_dst, NULL, MS_BIND, NULL);
        }
    }
    if (cfg->iso_dbus_session) {
        char addr[256];
        snprintf(addr, sizeof(addr), "unix:path=/run/user/%d/bus", (int)real_uid);
        setenv("DBUS_SESSION_BUS_ADDRESS", addr, 1);
    }

    if (cfg->iso_dbus_system) {
        const char *sys_src = "/run/dbus/system_bus_socket";
        char sys_dir[VAULT_PATH_MAX], sys_dst[VAULT_PATH_MAX];
        snprintf(sys_dir, sizeof(sys_dir), "%s/run/dbus", vault_path);
        snprintf(sys_dst, sizeof(sys_dst), "%s/run/dbus/system_bus_socket", vault_path);
        struct stat sst;
        mkdir(sys_dir, 0755);
        if (stat(sys_src, &sst) == 0) {
            int fd = open(sys_dst, O_CREAT|O_WRONLY, 0600); if (fd>=0) close(fd);
            mount(sys_src, sys_dst, NULL, MS_BIND, NULL);
        }
        setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/dbus/system_bus_socket", 1);
    }

    if (cfg->iso_dbus_session || cfg->iso_dbus_system || cfg->iso_xdg_runtime) {
        const char *srcs[] = { "/var/lib/dbus/machine-id", "/etc/machine-id", NULL };
        for (int i = 0; srcs[i]; i++) {
            struct stat mst;
            if (stat(srcs[i], &mst) != 0) continue;
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, srcs[i]);
            char par[VAULT_PATH_MAX]; snprintf(par, sizeof(par), "%s", dst);
            char *sl = strrchr(par, '/');
            if (sl) { *sl = '\0';
                for (char *p = par+1; *p; p++) {
                    if (*p == '/') { *p='\0'; mkdir(par,0755); *p='/'; }
                }
                mkdir(par, 0755);
            }
            int fd = open(dst, O_CREAT|O_WRONLY, 0444); if (fd>=0) close(fd);
            mount(srcs[i], dst, NULL, MS_BIND, NULL);
        }
    }

    if (cfg->iso_gpu) {
        char dri_dst[VAULT_PATH_MAX];
        snprintf(dri_dst, sizeof(dri_dst), "%s/dev/dri", vault_path);
        struct stat gst;
        if (stat("/dev/dri", &gst) == 0) {
            mkdir(dri_dst, 0755);
            if (mount("/dev/dri", dri_dst, NULL, MS_BIND | MS_REC, NULL) != 0)
                fprintf(stderr, "[RUN] --gpu: bind /dev/dri: %s\n", strerror(errno));
        }
    }

    if (cfg->iso_dev_level >= 1) {
        char dev_dir[VAULT_PATH_MAX];
        snprintf(dev_dir, sizeof(dev_dir), "%s/dev", vault_path);
        if (cli_mkdir_p(dev_dir, 0755) != 0)
            fprintf(stderr, "[RUN] --dev: mkdir_p '%s': %s\n", dev_dir, strerror(errno));

        const char *devs[] = { "/dev/null", "/dev/zero", "/dev/tty", "/dev/urandom", "/dev/random", NULL };
        for (int i = 0; devs[i]; i++) {
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, devs[i]);
            int fd = open(dst, O_CREAT|O_WRONLY, 0444);
            if (fd >= 0) close(fd);
            else fprintf(stderr, "[RUN] --dev: create node '%s': %s\n", dst, strerror(errno));
            if (mount(devs[i], dst, NULL, MS_BIND, NULL) != 0)
                fprintf(stderr, "[RUN] --dev: bind '%s': %s\n", devs[i], strerror(errno));
        }
        char shm_dst[VAULT_PATH_MAX];
        snprintf(shm_dst, sizeof(shm_dst), "%s/dev/shm", vault_path);
        if (mkdir(shm_dst, 01777) != 0 && errno != EEXIST)
            fprintf(stderr, "[RUN] --dev: mkdir '%s': %s\n", shm_dst, strerror(errno));
        if (mount("tmpfs", shm_dst, "tmpfs", MS_NOSUID|MS_NODEV, "size=256m") != 0)
            fprintf(stderr, "[RUN] --dev: mount tmpfs on '%s': %s\n", shm_dst, strerror(errno));
    }
    if (cfg->iso_dev_level >= 2) {
        char fuse_dst[VAULT_PATH_MAX];
        snprintf(fuse_dst, sizeof(fuse_dst), "%s/dev/fuse", vault_path);
        struct stat fst;
        if (stat("/dev/fuse", &fst) == 0) {
            int fd = open(fuse_dst, O_CREAT|O_WRONLY, 0660);
            if (fd >= 0) close(fd);
            else fprintf(stderr, "[RUN] --dev: create node '%s': %s\n", fuse_dst, strerror(errno));
            if (mount("/dev/fuse", fuse_dst, NULL, MS_BIND, NULL) != 0)
                fprintf(stderr, "[RUN] --dev: bind '/dev/fuse': %s\n", strerror(errno));
        }
    }

    if (cfg->iso_display)
        setenv("DISPLAY", cfg->iso_display, 1);
    if (cfg->iso_wayland_disp)
        setenv("WAYLAND_DISPLAY", cfg->iso_wayland_disp, 1);

    if (gui_mode) {
        setenv("MOZ_NO_REMOTE", "1", 1);
    }
#undef ENSURE_XDG_DIR

    /*  [Layer 3] Filesystem Isolation  */
    if (cfg->iso_use_chroot) {
        if (chroot(vault_path) != 0) {
            fprintf(stderr, "[RUN] chroot '%s': %s\n", vault_path, strerror(errno));
            cli_log_pivot_root(vault_path, errno);
            _exit(1);
        }
        if (chdir("/") != 0) {
            perror("[RUN] chdir / after chroot");
            _exit(1);
        }
        cli_log_pivot_root(vault_path, 0);
        fprintf(stderr, "[RUN] [INFO] filesystem isolated via chroot\n");
    } else {
        if (vsb_pivot_root(vault_path, !cfg->iso_no_proc) != 0) {
            fprintf(stderr, "[RUN] pivot_root '%s': %s  try --chroot as fallback\n",
                    vault_path, strerror(errno));
            cli_log_pivot_root(vault_path, errno);
            _exit(1);
        }
        cli_log_pivot_root(vault_path, 0);
    }

    if (!cfg->iso_no_proc && cfg->iso_use_chroot) {
        if (umount2("/proc", MNT_DETACH) != 0 && errno != EINVAL && errno != ENOENT) {
            vault_log(LOG_WARN,
                      "[SANDBOX] umount2('/proc', MNT_DETACH): %s  "
                      "continuing (legacy proc may leak host PIDs)",
                      strerror(errno));
        }

        if (mkdir("/proc", 0555) != 0 && errno != EEXIST) {
            vault_log(LOG_WARN,
                      "[SANDBOX] mkdir('/proc'): %s  "
                      "trying mount anyway",
                      strerror(errno));
        }

        if (mount("proc", "/proc", "proc",
                  MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0) {
            vault_log(LOG_ERROR,
                      "[SANDBOX] mount('/proc', procfs): %s  "
                      "sandbox may expose host PIDs! "
                      "Use --no-proc to disable /proc completely.",
                      strerror(errno));
        } else {
            vault_log(LOG_INFO,
                      "[SANDBOX] /proc remounted (fresh procfs, PID-namespace scoped) "
                      " host PIDs not visible inside sandbox.");
        }
    } else {
        umount2("/proc", MNT_DETACH);
        vault_log(LOG_INFO, "[SANDBOX] --no-proc: /proc disabled.");
    }
    {
        int sz = cfg->iso_tmp_size_mb ? cfg->iso_tmp_size_mb : 64;
        char sz_opt[32]; snprintf(sz_opt, sizeof(sz_opt), "size=%dm", sz);
        mkdir("/tmp", 01777);
        if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, sz_opt) != 0)
            perror("[RUN] mount /tmp post-isolation (non-fatal)");
    }

    if (cfg->iso_tmp_home) {
        char th[] = "/tmp/Nuk4sd-home-XXXXXX";
        char *dir = mkdtemp(th);
        if (dir) {
            setenv("HOME", dir, 1);

            if (gui_mode && real_uid != 0) {
                if (chown(dir, real_uid, real_gid) != 0)
                    perror("[RUN] --tmp-home chown to real_uid/real_gid");
            }
        } else {
            perror("[RUN] --tmp-home mkdtemp");
        }
    }

    if (gui_mode) {
        const char *sudo_user = getenv("SUDO_USER");
        if (sudo_user && !cfg->iso_tmp_home) {
            char orig_home[256];
            snprintf(orig_home, sizeof(orig_home), "/home/%s", sudo_user);
            setenv("HOME", orig_home, 1);
        }
    }

    /*  [Layer 4] Drop capabilities + NO_NEW_PRIVS  */
    if (vsb_drop_caps() != 0) {
        fprintf(stderr, "[RUN] cap drop failed\n");
        cli_log_cap_drop(-1);
        _exit(1);
    }
    cli_log_cap_drop(0);

    {
        struct rlimit rl;
        int   p  = cfg->iso_max_procs    ? cfg->iso_max_procs    : 512;
        long  fs = cfg->iso_max_fsize_mb
                   ? (long)cfg->iso_max_fsize_mb * 1024 * 1024
                   : gui_mode
                       ? (long)1024 * 1024 * 1024
                       : (long)512  * 1024 * 1024;
        int   fd = cfg->iso_max_fds      ? cfg->iso_max_fds      : 4096;
        if (cfg->iso_max_mem_gb > 0) {
            long m = (long)cfg->iso_max_mem_gb * 1024 * 1024 * 1024;
            rl.rlim_cur = rl.rlim_max = (rlim_t)m;  setrlimit(RLIMIT_AS,     &rl);
            cli_log_rlimit("RLIMIT_AS",     m, m);
        }
        rl.rlim_cur = rl.rlim_max = (rlim_t)p;  setrlimit(RLIMIT_NPROC,  &rl);
        cli_log_rlimit("RLIMIT_NPROC",  p, p);
        rl.rlim_cur = rl.rlim_max = (rlim_t)fs; setrlimit(RLIMIT_FSIZE,  &rl);
        cli_log_rlimit("RLIMIT_FSIZE",  fs, fs);
        rl.rlim_cur = rl.rlim_max = (rlim_t)fd; setrlimit(RLIMIT_NOFILE, &rl);
        cli_log_rlimit("RLIMIT_NOFILE", fd, fd);
    }

    /*  [Layer 5] Seccomp-BPF  */
    if (cfg->iso_no_seccomp) {
        fprintf(stderr, "[RUN] š   --no-seccomp: BPF disabled (debug mode)\n");
        cli_log_seccomp(0);
    } else {
        int permissive = cfg->permissive_sandbox || (gui_mode && !cfg->seccomp_strict);
        int friendly = cfg->friendly_sandbox || (gui_mode && !cfg->seccomp_strict);
        vsb_set_seccomp_mode(cfg->seccomp_strict ? 1 : 0, cfg->allow_clone3 ? 1 : 0,
                             friendly ? 1 : 0, permissive ? 1 : 0);
        if (cfg->iso_adapter && cfg->iso_adapter[0]) {
            vsb_set_seccomp_adapter(cfg->iso_adapter);
        }
        vsb_set_mount_dev(cfg->iso_mount_dev);
        if (permissive) {
            vault_log(LOG_AUDIT,
                      "[SECURITY] Friendly GUI Mode ACTIVE ‚ exec='%s' ‚ vault_id=%d ‚ pid=%d ‚ "
                      "chroot/capset/setuid/setgid ALLOWED in seccomp for app internal sandbox.",
                      cfg->run_exec ? cfg->run_exec : "?", cfg->vault_id, (int)getpid());
        }

        /* [LANDLOCK] Layer 3 MAC (VFS restriction) before Seccomp */
        if (!cfg->permissive_sandbox) {
            int ll_ret = landlock_apply(cfg, vault_path);
            if (ll_ret == 0) {
                if (cfg->verbose)
                    printf("  -> [Layer 5] Landlock MAC enforced (VFS restrictions active)\n");
            } else if (ll_ret == -2) {
                fprintf(stderr,
                        "[SANDBOX][WARN] Landlock supported by kernel but failed -- "
                        "VFS unrestricted. Check logs for details.\n");
            }
        }

        /* [SECCOMP] Layer 4 MAC (Syscall restriction) */
        if (vsb_apply_seccomp() != 0) {
            fprintf(stderr, "[RUN] seccomp load failed\n");
            cli_log_seccomp(-1);
            _exit(1);
        }
        cli_log_seccomp(0);
    }

    /*  Build final argv and execvp  */
    int total = 1 + cfg->run_argc;
    char **exec_argv = calloc((size_t)(total + 1), sizeof(char *));
    if (!exec_argv) _exit(1);

    exec_argv[0] = cfg->run_exec;
    for (int i = 0; i < cfg->run_argc; i++)
        exec_argv[i + 1] = cfg->run_argv[i];
    exec_argv[total] = NULL;

    /*  FIX #2: Close all FDs before execvp (CVE-2024-21626 pattern)  */
#ifdef __linux__
    {
        long cr = syscall(436, 3, ~0U, 0); /* close_range(3, UINT_MAX, 0) */
        if (cr != 0) {
            long max_fd = sysconf(_SC_OPEN_MAX);
            if (max_fd < 0) max_fd = 1024;
            for (long fd = 3; fd < max_fd; fd++)
                close((int)fd);
        }
    }
#endif

    /*  --uuid: Cryptographic process identification in sandbox  */
    if (cfg->iso_uuid) {
        UuidArgs uargs = {
            .pid = getpid(),
            .original_binary = cfg->run_exec,
            .pipe_fd = { -1, -1 }
        };
        setup_uuid(uargs);
    }

    cli_log_exec(cfg->run_exec, exec_argv, total);

    /*  --init: Mini-Init Supervisor PID 1 (zombie reaper for sshd/daemons)  */
    if (cfg->iso_init) {
        return nuk_mini_init(cfg->run_exec, exec_argv);
    }

    execvp(cfg->run_exec, exec_argv);
    fprintf(stderr, "[RUN] execvp '%s': %s\n", cfg->run_exec, strerror(errno));
    cli_log(CLI_LOG_ERROR, "EXEC", "execvp('%s') failed: %s",
            cfg->run_exec, strerror(errno));
    _exit(127);
}

#else  /* !__linux__ */

static int run_isolated(CliConfig *cfg, char *vault_path) {
    (void)cfg; (void)vault_path;
    print_err("--run isolation is only available on Linux.");
    return -1;
}

#endif /* __linux__ */

/*
 *  Main Dispatcher
 * */
static int dispatch(CliConfig *cfg) {
    int ret = 0;
    uint32_t id = (uint32_t)cfg->vault_id;

    /*  No vault required  */
    if (cfg->op_help)    { print_help();                return 0; }
    if (cfg->op_version) { printf("Nuk4sd v0.9.30\n");  return 0; }
    if (cfg->op_ls)      { vault_list_ffi();            return 0; }

    /*  --new <name>  */
    if (cfg->new_name) {
        int vtype = cfg->protected_vault ? 1 : 0;
        char pass_buf[256] = {0}, cnf_buf[256] = {0};
        char *pass = cfg->password;

        if (cfg->protected_vault && !pass) {
            char *p1 = read_password_silent("Vault password: ");
            strncpy(pass_buf, p1, sizeof(pass_buf)-1);
            char *p2 = read_password_silent("Confirm password: ");
            strncpy(cnf_buf,  p2, sizeof(cnf_buf)-1);
            if (strcmp(pass_buf, cnf_buf) != 0) {
                print_err("Passwords do not match.");
                explicit_bzero(pass_buf, sizeof(pass_buf));
                explicit_bzero(cnf_buf,  sizeof(cnf_buf));
                return 1;
            }
            pass = pass_buf;
        }

        ret = vault_create_ffi(cfg->new_name, vtype, cfg->new_path, pass);
        explicit_bzero(pass_buf, sizeof(pass_buf));
        explicit_bzero(cnf_buf,  sizeof(cnf_buf));

        if (ret != 0) {
            char m[128];
            snprintf(m, sizeof(m), "Failed to create vault (err=%d)", ret);
            print_err(m);
            return ret;
        }
        print_ok("Vault created.");

        if (cfg->engine_level > 0) {
            if (vault_apply_engine_ffi(cfg->new_name, cfg->engine_level) == 0) {
                char m[64];
                snprintf(m, sizeof(m), "Engine %d applied.", cfg->engine_level);
                print_ok(m);
            } else {
                print_warn("Engine not applied.");
            }
        }
        return 0;
    }

    /*  Check if --vault <id> was provided for operations requiring it  */
    bool is_vault_file_or_snap_op = (
        cfg->op_add || cfg->op_extract || cfg->op_mv ||
        cfg->op_cp || cfg->op_rm_file || cfg->op_mkdir ||
        cfg->op_rmdir || cfg->op_tree || cfg->op_du ||
        cfg->op_find || cfg->op_snapshot || cfg->op_snapshots ||
        cfg->op_snapshot_delete || cfg->op_snapshot_restore ||
        cfg->op_snapshot_diff ||
        cfg->op_hash     || cfg->op_baseline  || cfg->op_verify ||
        cfg->op_integrity|| cfg->op_repair    || cfg->op_diff   ||
        cfg->op_backup   || cfg->op_restore   || cfg->op_import ||
        cfg->op_lock     || cfg->op_lock_status|| cfg->op_force_unlock ||
        cfg->op_key_info || cfg->op_key_rotate || cfg->op_rekey ||
        cfg->op_stats    || cfg->op_usage     || cfg->op_inspect ||
        cfg->op_history  || cfg->op_events
    );

    bool needs_id = (cfg->op_info || cfg->op_files || cfg->op_status ||
                     cfg->op_scan || cfg->op_encrypt || cfg->op_decrypt ||
                     cfg->op_resolve || cfg->op_mount || cfg->op_umount ||
                     cfg->op_mount_export || cfg->op_export ||
                     cfg->op_rm || cfg->op_rename || cfg->op_unlock ||
                     cfg->op_passwd || cfg->op_rule || cfg->op_worm_status ||
                     cfg->worm_set || cfg->worm_clear ||
                     cfg->worm_protected_scan ||
                     is_vault_file_or_snap_op ||
                     (cfg->run_exec && !cfg->no_fuse));

    if (needs_id && cfg->vault_id < 0) {
        print_err("--vault <id> required. Use --ls to list vault IDs.");
        return 1;
    }

    /*  Resolve password when required  */
    char pass_buf[256] = {0};
    char *pass = cfg->password;
    bool needs_pass = (cfg->op_encrypt || cfg->op_decrypt || cfg->op_rm ||
                       cfg->op_rename  || cfg->op_unlock  || cfg->op_mount ||
                       cfg->op_resolve || cfg->op_export  ||
                       cfg->op_mount_export || cfg->run_exec);

    if (needs_pass && !pass && vault_is_protected_ffi(id)) {
        char *p = read_password_silent("Vault password: ");
        strncpy(pass_buf, p, sizeof(pass_buf)-1);
        pass = pass_buf;
    }

    /*••
     *  Dispatch by operation
     *•• */

    if (is_vault_file_or_snap_op) {
        char vpath[VAULT_PATH_MAX];
        if (vault_get_real_path_ffi(id, vpath, sizeof(vpath)) != 0) {
            print_err("Vault not found or storage path unavailable.");
            ret = 1;
            goto cleanup;
        }

        if (cfg->op_add) {
            if (!cfg->add_file) { print_err("--add requires <file>"); ret = 1; }
            else ret = rust_vault_add(vpath, cfg->add_file, cfg->add_recursive, cfg->add_replace, cfg->add_preserve);
        } else if (cfg->op_extract) {
            if (!cfg->extract_file) { print_err("--extract requires <file>"); ret = 1; }
            else {
                const char *dest = cfg->extract_dest ? cfg->extract_dest : (cfg->export_dest ? cfg->export_dest : ".");
                ret = rust_vault_extract(vpath, cfg->extract_file, dest, cfg->extract_force);
            }
        } else if (cfg->op_mv) {
            if (!cfg->mv_src || !cfg->mv_dest) { print_err("--mv requires <src> and <dest>"); ret = 1; }
            else ret = rust_vault_mv(vpath, cfg->mv_src, cfg->mv_dest);
        } else if (cfg->op_cp) {
            if (!cfg->cp_src || !cfg->cp_dest) { print_err("--cp requires <src> and <dest>"); ret = 1; }
            else ret = rust_vault_cp(vpath, cfg->cp_src, cfg->cp_dest);
        } else if (cfg->op_rm_file) {
            if (!cfg->rm_file_target) { print_err("--rm-file requires <file>"); ret = 1; }
            else ret = rust_vault_rm_file(vpath, cfg->rm_file_target);
        } else if (cfg->op_mkdir) {
            if (!cfg->mkdir_target) { print_err("--mkdir requires <dir>"); ret = 1; }
            else ret = rust_vault_mkdir(vpath, cfg->mkdir_target);
        } else if (cfg->op_rmdir) {
            if (!cfg->rmdir_target) { print_err("--rmdir requires <dir>"); ret = 1; }
            else ret = rust_vault_rmdir(vpath, cfg->rmdir_target);
        } else if (cfg->op_tree) {
            ret = rust_vault_tree(vpath);
        } else if (cfg->op_du) {
            ret = rust_vault_du(vpath);
        } else if (cfg->op_find) {
            if (!cfg->find_pattern) { print_err("--find requires <pattern>"); ret = 1; }
            else ret = rust_vault_find(vpath, cfg->find_pattern);
        } else if (cfg->op_snapshot) {
            ret = rust_vault_snapshot(vpath, cfg->snapshot_tag);
        } else if (cfg->op_snapshots) {
            ret = rust_vault_snapshots(vpath);
        } else if (cfg->op_snapshot_delete) {
            if (!cfg->snapshot_del_tag) { print_err("--snapshot-delete requires <tag>"); ret = 1; }
            else ret = rust_vault_snapshot_delete(vpath, cfg->snapshot_del_tag);
        } else if (cfg->op_snapshot_restore) {
            if (!cfg->snapshot_restore_tag) { print_err("--snapshot-restore requires <tag>"); ret = 1; }
            else ret = rust_vault_snapshot_restore(vpath, cfg->snapshot_restore_tag);
        } else if (cfg->op_snapshot_diff) {
            if (!cfg->snapshot_diff_tag1) { print_err("--snapshot-diff requires <tag1> [tag2]"); ret = 1; }
            else ret = rust_vault_snapshot_diff(vpath, cfg->snapshot_diff_tag1, cfg->snapshot_diff_tag2);
        /*  Cryptographic Integrity  */
        } else if (cfg->op_hash) {
            ret = rust_vault_hash(vpath, cfg->hash_target);
        } else if (cfg->op_baseline) {
            ret = rust_vault_baseline(vpath);
        } else if (cfg->op_verify) {
            ret = rust_vault_verify(vpath);
        } else if (cfg->op_integrity) {
            ret = rust_vault_integrity(vpath);
        } else if (cfg->op_repair) {
#ifdef __linux__
            uint32_t wf = vault_worm_get_flags_ffi(id);
            if (wf & WORM_PROTECT_WRITE) {
                print_err("[WORM] --repair blocked: WORM_PROTECT_WRITE active on this vault.");
                ret = -EPERM;
            } else
#endif
            ret = rust_vault_repair(vpath);
        } else if (cfg->op_diff) {
            ret = rust_vault_diff(vpath, cfg->diff_other);
        /*  Backup & Import  */
        } else if (cfg->op_backup) {
            ret = rust_vault_backup(vpath, cfg->backup_out);
        } else if (cfg->op_restore) {
            if (!cfg->restore_archive) { print_err("--restore-arch requires <archive.tar.gz>"); ret = 1; }
            else {
#ifdef __linux__
                uint32_t wf = vault_worm_get_flags_ffi(id);
                if (wf & WORM_PROTECT_WRITE) {
                    print_err("[WORM] --restore-arch blocked: WORM_PROTECT_WRITE active.");
                    ret = -EPERM;
                } else
#endif
                ret = rust_vault_restore(vpath, cfg->restore_archive);
            }
        } else if (cfg->op_import) {
            if (!cfg->import_src) { print_err("--import requires <source>"); ret = 1; }
            else {
#ifdef __linux__
                uint32_t wf = vault_worm_get_flags_ffi(id);
                if (wf & WORM_PROTECT_WRITE) {
                    print_err("[WORM] --import blocked: WORM_PROTECT_WRITE active.");
                    ret = -EPERM;
                } else
#endif
                ret = rust_vault_import(vpath, cfg->import_src);
            }
        /*  Lock/Unlock  */
        } else if (cfg->op_lock) {
            ret = rust_vault_lock(vpath);
        } else if (cfg->op_lock_status) {
            ret = rust_vault_lock_status(vpath);
        } else if (cfg->op_force_unlock) {
            ret = rust_vault_force_unlock(vpath);
        /*  Key Lifecycle  */
        } else if (cfg->op_key_info) {
            ret = rust_vault_key_info(vpath);
        } else if (cfg->op_key_rotate) {
            if (!cfg->key_rotate_old || !cfg->key_rotate_new) {
                print_err("--key-rotate requires <old-pass> <new-pass>");
                ret = 1;
            } else {
                ret = rust_vault_key_rotate(vpath, cfg->key_rotate_old, cfg->key_rotate_new);
            }
        } else if (cfg->op_rekey) {
            const char *p = cfg->password;
            if (!p || !p[0]) {
                char *rp = read_password_silent("Current vault password: ");
                strncpy(pass_buf, rp, sizeof(pass_buf)-1);
                p = pass_buf;
            }
            ret = rust_vault_rekey(vpath, p);
        /*  Observability  */
        } else if (cfg->op_stats) {
            ret = rust_vault_stats(vpath);
        } else if (cfg->op_usage) {
            ret = rust_vault_usage(vpath);
        } else if (cfg->op_inspect) {
            if (!cfg->inspect_target) { print_err("--inspect requires <file>"); ret = 1; }
            else ret = rust_vault_inspect(vpath, cfg->inspect_target);
        } else if (cfg->op_history) {
            ret = rust_vault_history(vpath);
        } else if (cfg->op_events) {
            ret = rust_vault_events(vpath);
        }
        goto cleanup;

    /*  MAC AppArmor (global, no vault-id needed)  */
    if (cfg->op_mac_enable) {
        g_catalog.mac_mode = 1;
        catalog_save();
        printf("AppArmor MAC protection enabled globally.\n");
        cli_log(CLI_LOG_AUDIT, "MAC", "mac_mode set to 1 (enabled)");
        goto cleanup;
    }
    if (cfg->op_disable_apparmor) {
        char phrase[128];
        fprintf(stderr, "Secret phrase required to disable AppArmor protection.\n");
        fprintf(stderr, "Phrase: ");
        fflush(stderr);

        struct termios old_term, silent_term;
        tcgetattr(STDIN_FILENO, &old_term);
        silent_term = old_term;
        silent_term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
        tcsetattr(STDIN_FILENO, TCSANOW, &silent_term);
        if (!fgets(phrase, sizeof(phrase), stdin)) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
            print_err("Failed to read phrase.");
            ret = 1;
            goto cleanup;
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        fprintf(stderr, "\n");
        phrase[strcspn(phrase, "\n")] = '\0';

        if (!rust_validate_mac_secret(phrase)) {
            print_err("Invalid secret phrase. AppArmor remains active.");
            cli_log(CLI_LOG_AUDIT, "MAC", "disable-apparmor rejected: invalid phrase");
            ret = 1;
            goto cleanup;
        }

        const char *target = cfg->app_armor_target;
        if (!target || strcmp(target, "all") == 0) {
            /* Disable for all vaults */
            for (uint32_t vault_index = 0; vault_index < g_catalog.count; vault_index++) {
                Vault *current_vault = &g_catalog.vaults[vault_index];
                if (mac_apparmor_is_active(current_vault->id))
                    mac_apparmor_remove(current_vault->id);
            }
            g_catalog.mac_mode = 0;
            catalog_save();
            print_ok("AppArmor disabled for all vaults.");
            cli_log(CLI_LOG_AUDIT, "MAC", "disable-apparmor: all vaults cleared");
        } else {
            /* Disable for a specific vault by name or id */
            bool vault_found = false;
            for (uint32_t vault_index = 0; vault_index < g_catalog.count; vault_index++) {
                Vault *current_vault = &g_catalog.vaults[vault_index];
                char vault_id_str[32];
                snprintf(vault_id_str, sizeof(vault_id_str), "vault-%u", current_vault->id);
                if (strcmp(target, vault_id_str) == 0 ||
                    strcmp(target, current_vault->name) == 0) {
                    mac_apparmor_remove(current_vault->id);
                    print_ok("AppArmor disabled for vault.");
                    cli_log(CLI_LOG_AUDIT, "MAC", "disable-apparmor: vault cleared");
                    vault_found = true;
                    break;
                }
            }
            if (!vault_found) {
                print_err("Vault not found.");
                ret = 1;
            }
        }
        goto cleanup;
    }
    if (cfg->op_mac_status) {
        const char *mode_str =
            g_catalog.mac_mode == 1  ? "enabled" :
            g_catalog.mac_mode == 0  ? "disabled" :
                                       "not configured (first-run pending)";
        printf("AppArmor MAC: %s\n", mode_str);
        goto cleanup;
    }
    if (cfg->op_generate_secret) {
        char secret_phrase[256];
        if (rust_generate_mac_secret(secret_phrase, sizeof(secret_phrase)) != 0) {
            print_err("Failed to generate secret phrase.");
            ret = 1;
            goto cleanup;
        }
        printf("\n");
        printf("  AppArmor Recovery Secret\n");
        printf("  \n");
        printf("  %s\n", secret_phrase);
        printf("  \n");
        printf("\n");
        printf("  Write this phrase down on paper and store it safely.\n");
        printf("  It will NOT be shown again. The hash is saved at ~/.nuk4sd_mac_secret.\n");
        printf("  Use --disable-apparmor to revoke protection with this phrase.\n");
        printf("\n");
        cli_log(CLI_LOG_AUDIT, "MAC", "generate-secret: new Argon2 secret generated");
        goto cleanup;
    }
    if (cfg->op_app_armor) {
        if (!mac_apparmor_available()) {
            print_err("AppArmor not available on this kernel.");
            ret = 1;
            goto cleanup;
        }
        if (!cfg->app_armor_target) {
            print_err("--app-armor requires an argument: 'all' or 'vault-<id>'");
            ret = 1;
            goto cleanup;
        }
        if (strcmp(cfg->app_armor_target, "all") == 0) {
            int loaded = mac_apparmor_apply_all();
            printf("%d vault profile(s) loaded.\n", loaded);
        } else if (strncmp(cfg->app_armor_target, "vault-", 6) == 0) {
            uint32_t target_vault_id = (uint32_t)atoi(cfg->app_armor_target + 6);
            Vault *target_vault = NULL;
            for (uint32_t vi = 0; vi < g_catalog.count; vi++) {
                if (g_catalog.vaults[vi].id == target_vault_id) {
                    target_vault = &g_catalog.vaults[vi];
                    break;
                }
            }
            if (!target_vault) {
                print_err("Vault not found.");
                ret = 1;
                goto cleanup;
            }
            if (!target_vault->is_mounted) {
                print_err("Vault must be mounted to apply AppArmor profile.");
                ret = 1;
                goto cleanup;
            }
            ret = (mac_apparmor_load(target_vault) == ERR_OK) ? 0 : 1;
            if (ret == 0)
                printf("AppArmor profile loaded for vault %u.\n", target_vault_id);
        } else {
            print_err("Invalid argument. Use 'all' or 'vault-<id>'.");
            ret = 1;
        }
        goto cleanup;
    }

    if (cfg->op_info)  { cli_log_operation_start("INFO",  id); vault_info_ffi(id);  goto cleanup; }
    if (cfg->op_files) { cli_log_operation_start("FILES", id); vault_files_ffi(id); goto cleanup; }

    if (cfg->op_status) {
        int s = vault_get_status_ffi(id);
        const char *label = s == 0 ? "OK"
                          : s == 1 ? "LOCKED"
                          : s == 2 ? "ALERT"
                          :          "DELETED";
        if (cfg->json_output)
            printf("{\"id\":%u,\"status\":\"%s\"}\n", id, label);
        else
            printf("  Vault %u  \033[1m%s\033[0m\n", id, label);
        goto cleanup;
    }

    if (cfg->op_scan) {
        char report[8192] = {0};
        cli_log_operation_start("SCAN", id);
        int issues = vault_scan_report_ffi(id, report, sizeof(report));
        cli_log(CLI_LOG_INFO, "SCAN", "vault_id=%d SHA-256 issues=%d", id, issues);
        if (cfg->json_output) {
            printf("{\"id\":%u,\"issues\":%d,\"detail\":\"%s\"}\n",
                   id, issues, report);
        } else if (issues > 0) {
            printf("\033[31mš  ALERT: %d file(s) modified since last scan:\033[0m\n%s",
                   issues, report);
            printf("  Use --resolve to approve changes.\n");
        } else {
            print_ok("Scan complete. Integrity verified (SHA-256).");
        }
        goto cleanup;
    }

    if (cfg->op_encrypt) {
        if (!pass || !pass[0]) { print_err("Password required."); ret=1; goto cleanup; }
        cli_log_operation_start("ENCRYPT", id);
        ret = vault_encrypt_ffi(id, pass);
        cli_log_operation_result("ENCRYPT", id, ret);
        if (ret == 0) print_ok("Files encrypted (AES-256-GCM).");
        else { char m[64]; snprintf(m,sizeof(m),"Encrypt failed (err=%d)",ret); print_err(m); }
        goto cleanup;
    }

    if (cfg->op_decrypt) {
        if (!pass || !pass[0]) { print_err("Password required."); ret=1; goto cleanup; }
        cli_log_operation_start("DECRYPT", id);
        ret = vault_decrypt_ffi(id, pass);
        cli_log_operation_result("DECRYPT", id, ret);
        if (ret == 0) print_ok("Files decrypted.");
        else { char m[64]; snprintf(m,sizeof(m),"Decrypt failed (err=%d)",ret); print_err(m); }
        goto cleanup;
    }

    if (cfg->op_resolve) {
        cli_log_operation_start("RESOLVE", id);
        ret = vault_resolve_ffi(id, pass);
        cli_log_operation_result("RESOLVE", id, ret);
        if (ret == 0) print_ok("Alert resolved. Status reset to OK.");
        else print_err("Resolve failed.");
        goto cleanup;
    }

    if (cfg->op_mount) {
        cli_log_operation_start("MOUNT", id);
        ret = vault_mount_ffi(id, pass ? pass : "");
        cli_log_operation_result("MOUNT", id, ret);
        if (ret == 0) print_ok("Vault mounted via FUSE.");
        else { char m[64]; snprintf(m,sizeof(m),"Mount failed (err=%d)",ret); print_err(m); }
        goto cleanup;
    }

    if (cfg->op_umount) {
        cli_log_operation_start("UMOUNT", id);
        ret = vault_unmount_ffi(id);
        cli_log_operation_result("UMOUNT", id, ret);
        if (ret == 0) print_ok("Vault unmounted.");
        else print_err("Unmount failed. If PROTECTED-SCAN, use --mount-export.");
        goto cleanup;
    }

    if (cfg->op_export || cfg->op_mount_export) {
        const char *dst = cfg->export_dest ? cfg->export_dest : ".";
        cli_log_operation_start(cfg->op_mount_export ? "MOUNT-EXPORT" : "EXPORT", id);
        cli_log(CLI_LOG_INFO, "EXPORT", "dest='%s' file='%s'",
                dst, cfg->export_file ? cfg->export_file : "(all)");
        ret = vault_mount_export_ffi(id, pass ? pass : "", dst, cfg->export_file);
        cli_log_operation_result("EXPORT", id, ret);
        if (ret == 0) {
            char m[VAULT_PATH_MAX];
            snprintf(m, sizeof(m), "Exported to: %s", dst);
            print_ok(m);
        } else {
            print_err("Export failed.");
        }
        goto cleanup;
    }

    if (cfg->op_rm) {
        ret = vault_delete_ffi(id, pass);
        if (ret == 0) print_ok("Vault deleted.");
        else print_err("Delete failed.");
        goto cleanup;
    }

    if (cfg->op_rename) {
        ret = vault_rename_ffi(id, cfg->rename_to, pass);
        if (ret == 0) print_ok("Vault renamed.");
        else print_err("Rename failed.");
        goto cleanup;
    }

    if (cfg->op_unlock) {
        if (!pass || !pass[0]) {
            char *p = read_password_silent("Password: ");
            strncpy(pass_buf, p, sizeof(pass_buf)-1);
            pass = pass_buf;
        }
        ret = vault_unlock_ffi(id, pass);
        if (ret == 0) print_ok("Vault unlocked.");
        else print_err("Unlock failed.");
        goto cleanup;
    }

    if (cfg->op_passwd) {
        char old_buf[256]={0}, new_buf[256]={0}, cnf_buf[256]={0};
        strncpy(old_buf, read_password_silent("Current password: "), sizeof(old_buf)-1);
        strncpy(new_buf, read_password_silent("New password: "),     sizeof(new_buf)-1);
        strncpy(cnf_buf, read_password_silent("Confirm: "),          sizeof(cnf_buf)-1);

        if (strcmp(new_buf, cnf_buf) != 0) {
            print_err("Passwords do not match.");
            explicit_bzero(old_buf, sizeof(old_buf));
            explicit_bzero(new_buf, sizeof(new_buf));
            explicit_bzero(cnf_buf, sizeof(cnf_buf));
            ret = 1;
            goto cleanup;
        }
        ret = vault_change_password_ffi(id, old_buf, new_buf);
        explicit_bzero(old_buf, sizeof(old_buf));
        explicit_bzero(new_buf, sizeof(new_buf));
        explicit_bzero(cnf_buf, sizeof(cnf_buf));
        if (ret == 0) print_ok("Password changed.");
        else print_err("Password change failed.");
        goto cleanup;
    }

    if (cfg->op_rule) {
        ret = vault_rule_ffi(id, cfg->rule_max_fails,
                             cfg->rule_hour_from, cfg->rule_hour_to);
        if (ret == 0) {
            char m[128];
            snprintf(m, sizeof(m), "Rule added: max_fails=%d hours=%d-%d",
                     cfg->rule_max_fails, cfg->rule_hour_from, cfg->rule_hour_to);
            print_ok(m);
        } else {
            print_err("Rule add failed.");
        }
        goto cleanup;
    }

    /*  WORM  */
    if (cfg->op_worm_status) {
        uint32_t f = vault_worm_get_flags_ffi(id);
        cli_log_worm_status(id, f);
        printf("\n  WORM  vault %u (raw flags 0x%02x)\n", id, f);
        printf("  %-16s %s\n", "delete:",
               f & WORM_PROTECT_DELETE ? "\033[31mBLOCKED\033[0m" : "allowed");
        printf("  %-16s %s\n", "rename:",
               f & WORM_PROTECT_RENAME ? "\033[31mBLOCKED\033[0m" : "allowed");
        printf("  %-16s %s\n", "write:",
               f & WORM_PROTECT_WRITE  ? "\033[31mBLOCKED\033[0m" : "allowed");
        printf("  %-16s %s\n", "read:",
               f & WORM_PROTECT_READ   ? "\033[31mBLOCKED\033[0m" : "allowed");
        printf("  %-16s %s\n\n", "protected-scan:",
               f & WORM_PROTECT_SCAN   ?
               "\033[31mACTIVE (immutable  use --mount-export to rescue)\033[0m" :
               "inactive");
        goto cleanup;
    }

    if (cfg->worm_protected_scan) {
        printf("\033[31mš   PROTECTED-SCAN is IRREVERSIBLE.\033[0m\n");
        printf("   The vault will become completely immutable.\n");
        printf("   Only --mount-export can rescue files afterwards.\n");
        printf("   Type 'yes' to confirm: ");
        fflush(stdout);
        char ans[16] = {0};
        if (fgets(ans, sizeof(ans), stdin) && !strncmp(ans, "yes", 3)) {
            ret = vault_worm_set_scan_ffi(id);
            if (ret == 0) print_ok("PROTECTED-SCAN activated.");
            else print_err("Failed to activate PROTECTED-SCAN.");
        } else {
            print_warn("Cancelled.");
        }
        goto cleanup;
    }

    if (cfg->worm_set) {
        cli_log_worm_flags(id, cfg->worm_set, 0);
        ret = vault_worm_set_flags_ffi(id, cfg->worm_set);
        cli_log_operation_result("WORM-SET", id, ret);
        if (ret == 0) {
            char m[64];
            snprintf(m, sizeof(m), "WORM protections enabled (0x%02x).", cfg->worm_set);
            print_ok(m);
        } else {
            print_err("WORM set failed.");
        }
    }

    if (cfg->worm_clear) {
        cli_log_worm_flags(id, 0, cfg->worm_clear);
        ret = vault_worm_clear_flags_ffi(id, cfg->worm_clear);
        cli_log_operation_result("WORM-CLEAR", id, ret);
        if (ret == 0) {
            char m[64];
            snprintf(m, sizeof(m), "WORM protections removed (0x%02x).", cfg->worm_clear);
            print_ok(m);
        } else {
            print_err("WORM clear failed.");
        }
    }

    if (cfg->worm_set || cfg->worm_clear) goto cleanup;

    /*  Container Whitelist  */
    if (cfg->op_whitelist_exclude || cfg->op_whitelist_restore) {
        VaultContainer c;
        memset(&c, 0, sizeof(c));
        c.id = id;
        c.sealed = 1;
        
        if (cfg->op_whitelist_exclude) {
            container_whitelist_exclude(&c);
        }
        if (cfg->op_whitelist_restore) {
            container_whitelist_restore(&c);
        }
        ret = -1;
        goto cleanup;
    }

    /*  --image <alias|url>  */
    if (cfg->image_url) {
        char lowerdir[VAULT_PATH_MAX];
        snprintf(lowerdir, sizeof(lowerdir), "/tmp/nuk4sd-img-%u-XXXXXX", id);
        if (mkdtemp(lowerdir) == NULL) {
            perror("[IMAGE] mkdtemp lowerdir");
        } else {
            if (cfg->verbose)
                printf("  ’ pulling image '%s' into %s...\n", cfg->image_url, lowerdir);
            int pull_ret = rust_oci_pull_image(cfg->image_url, lowerdir);
            if (pull_ret != 0) {
                print_warn("Image pull failed  falling back to vault root.");
                rmdir(lowerdir);
            } else {
                if (cfg->verbose)
                    printf("  ’ image ready at %s\n", lowerdir);
                cfg->no_fuse = true;
                cfg->image_url = strdup(lowerdir);
                cfg->image_url_allocated = true;
            }
        }
    }

    /*  --run <exec>  */
    if (cfg->run_exec) {
        char vault_path[VAULT_PATH_MAX];

        if (cfg->no_fuse) {
            if (cfg->image_url) {
                snprintf(vault_path, sizeof(vault_path), "%s", cfg->image_url);
                if (cfg->verbose)
                    printf("  ’ using OCI rootfs at '%s'\n", vault_path);
            } else {
                snprintf(vault_path, sizeof(vault_path), "/tmp/Nuk4sd-nofuse-XXXXXX");
                if (mkdtemp(vault_path) == NULL) {
                    perror("[RUN] --no-fuse: mkdtemp jail root");
                    ret = 1;
                    goto cleanup;
                }
                if (cfg->verbose)
                    printf("  --no-fuse: using jail root at '%s' (without FUSE)\n", vault_path);
            }
        } else {
            if (vault_get_real_path_ffi(id, vault_path, sizeof(vault_path)) != 0) {
                print_err("Vault not found or path unavailable.");
                ret = 1;
                goto cleanup;
            }

            if (cfg->verbose)
                printf("  ’ mounting vault %u via FUSE...\n", id);
            vault_mount_ffi(id, pass ? pass : "");
        }

        if (cfg->verbose) {
            printf("  ’ exec: %s", cfg->run_exec);
            for (int i = 0; i < cfg->run_argc; i++)
                printf(" %s", cfg->run_argv[i]);
            printf("\n");
            printf("  ’ net=%s  wayland=%d  x11=%d  ro-home=%d  "
                   "no-dbus=%d  tmp-home=%d  no-proc=%d  no-fuse=%d\n",
                   cfg->iso_no_net ? "isolated" : "host",
                   cfg->iso_wayland, cfg->iso_x11, cfg->iso_ro_home,
                   cfg->iso_no_dbus, cfg->iso_tmp_home, cfg->iso_no_proc,
                   cfg->no_fuse);
        }

        ret = run_isolated(cfg, vault_path);

        if (cfg->no_fuse) {
            if (cfg->image_url) {
                if (cfg->verbose)
                    printf("  ’ cleaning OCI rootfs at '%s'...\n", vault_path);
#ifdef __linux__
                if (rm_rf_safe(vault_path) != 0)
                    fprintf(stderr, "[RUN] rm_rf_safe('%s') failed: %s\n",
                            vault_path, strerror(errno));
#else
                rmdir(vault_path);
#endif
                if (cfg->image_url_allocated) {
                    free(cfg->image_url);
                    cfg->image_url = NULL;
                    cfg->image_url_allocated = false;
                }
            } else {
                rmdir(vault_path);
            }
        } else {
            if (cfg->verbose)
                printf("  ’ unmounting vault %u (run finished)...\n", id);
            vault_unmount_ffi(id);
        }

        goto cleanup;
    }

    print_err("No operation specified. Use --help for usage.");
    ret = 1;

cleanup:
    explicit_bzero(pass_buf, sizeof(pass_buf));
    return ret;
}

/*
 *  FFI Entry point  called by main.rs
 * */
static int8_t cli_mac_first_run_prompt(void) {
    fprintf(stderr, "Enable AppArmor MAC protection for vaults? [y/N]: ");
    fflush(stderr);

    char user_response = 0;
    if (read(STDIN_FILENO, &user_response, 1) == 1
        && (user_response == 'y' || user_response == 'Y')) {
        return 1;
    }
    return 0;
}

int vault_cli_parse_and_exec(int argc, char **argv) {
    CliConfig *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) {
        fprintf(stderr, "[FATAL] calloc CliConfig: out of memory\n");
        return 1;
    }

    cli_log_init(NULL);

    /* First-run: ask user once whether to enable AppArmor MAC globally.
     * g_catalog.mac_mode is populated by vault_ffi_init -> catalog_load
     * before this function is called. -1 means never configured. */
    if (g_catalog.mac_mode == -1) {
        g_catalog.mac_mode = cli_mac_first_run_prompt();
        catalog_save();
        cli_log(CLI_LOG_AUDIT, "MAC",
                "First-run: user set mac_mode=%d", g_catalog.mac_mode);
    }

    if (parse_flags(argc, argv, cfg) != 0) {
        cli_log(CLI_LOG_ERROR, "COMMAND", "parse_flags failed  invalid args");
        cli_log_close();
        free(cfg);
        return 1;
    }

    cli_log_set_verbose(cfg->verbose);
    cli_log_command(argc, argv, cfg->vault_id);

    int ret = dispatch(cfg);

    cli_log(CLI_LOG_INFO, "COMMAND", "ended ret=%d", ret);
    cli_log_close();
    free(cfg);
    return ret;
}

/*
 *  vault_sandbox_run_ffi()
 * */
static void bind_add_ffi(CliConfig *cfg, const char *path, BindType type) {
    if (!path || !*path || cfg->bind_count >= MAX_BINDS) return;
    cli_expand_tilde(path, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
    cfg->binds[cfg->bind_count++].type = type;
}

int vault_sandbox_run_ffi(
    uint32_t    vault_id,
    const char *password,
    const char *exec_path,
    bool        no_net,
    bool        wayland,
    bool        x11,
    bool        audio,
    bool        ro_home,
    bool        no_fuse,
    bool        seccomp_strict,
    bool        use_chroot,
    const char *const *ro_paths,        uint32_t ro_count,
    const char *const *rw_paths,        uint32_t rw_count,
    const char *const *blacklist_paths, uint32_t blacklist_count
) {
    if (!exec_path || !*exec_path) return (int)ERR_INVALID_ARGS;

    CliConfig *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) return (int)ERR_NO_MEMORY;

    cli_log_init(NULL);

    cfg->vault_id       = (int32_t)vault_id;
    cfg->rule_hour_from = -1;
    cfg->rule_hour_to   = -1;

    cfg->run_exec = (char *)exec_path;
    cfg->password = (char *)password;

    cfg->iso_no_net     = no_net;
    cfg->iso_wayland    = wayland;
    cfg->iso_x11        = x11;
    cfg->iso_audio      = audio;
    cfg->iso_ro_home    = ro_home;
    cfg->no_fuse        = no_fuse;
    cfg->seccomp_strict = seccomp_strict;
    cfg->iso_use_chroot = use_chroot;

    for (uint32_t i = 0; i < ro_count && ro_paths; i++)
        bind_add_ffi(cfg, ro_paths[i], BIND_RO);
    for (uint32_t i = 0; i < rw_count && rw_paths; i++)
        bind_add_ffi(cfg, rw_paths[i], BIND_RW);
    for (uint32_t i = 0; i < blacklist_count && blacklist_paths; i++)
        bind_add_ffi(cfg, blacklist_paths[i], BIND_BLACKLIST);

    cli_log_set_verbose(cfg->verbose);
    cli_log(CLI_LOG_INFO, "COMMAND", "vault_sandbox_run_ffi: vault=%u exec=%s binds=%d",
            vault_id, exec_path, cfg->bind_count);

    int ret = dispatch(cfg);

    cli_log(CLI_LOG_INFO, "COMMAND", "ended ret=%d", ret);
    cli_log_close();
    free(cfg);
    return ret;
}
