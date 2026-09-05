/*
 * vault_core.h
 *
 * VAULT SECURITY SYSTEM — Unified Header
 * All structs, enums, constants and forward declarations.
 *
 * Split from diamondVaults.c — Peter Steve (architecture)
 * Date: 2026-05-13
 */

#ifndef VAULT_CORE_H
#define VAULT_CORE_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#define VAULT_NAME_MAX 128
#define VAULT_PATH_MAX 512

/* Struct used by vault_list_ids_ffi for bulk vault listing (FFI) */
typedef struct {
    uint32_t id;
    char path[VAULT_PATH_MAX];
} VaultIdPath;

#ifdef __linux__
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/fanotify.h>

    /* Per-file leaky bucket for fine-grained throttling */
    typedef struct FileBucket
    {
        char path[VAULT_PATH_MAX];
        double credits;
        time_t last_update;
        int time_esgoted;
        int credits_flash;
        struct FileBucket *next;
    } FileBucket;

#include <sys/inotify.h>
#include <sys/wait.h>
#include <pthread.h>
#include <termios.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <seccomp.h>
#include <sched.h>
#include <sys/capability.h>
#endif

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

/* ─────────────────────────────────────────────
 *  COMPILE-TIME CONSTANTS
 * ───────────────────────────────────────────── */
/* Paths now resolved dynamically in resolve_paths() */
extern char g_catalog_path[VAULT_PATH_MAX];
extern char g_catalog_file[VAULT_PATH_MAX];
extern char g_log_file[VAULT_PATH_MAX];
extern char g_lock_file[VAULT_PATH_MAX];

/* Macros for legacy code compatibility pointing to the global variables */
#define VAULT_CATALOG_PATH g_catalog_path
#define VAULT_CATALOG_FILE g_catalog_file
#define VAULT_LOG_FILE g_log_file
#define VAULT_LOCK_FILE g_lock_file

#define MAX_VAULTS 2048
#define MAX_FILES_PER_VAULT 4096
#define HASH_HEX_LEN 65 /* SHA-256 hex + NUL */
#define SALT_LEN 32
#define KEY_LEN 32 /* AES-256 */

#define PBKDF2_ITER 310000 /* OWASP 2023 recommendation */
#define MAX_PASS_ATTEMPTS 3
#define MAX_PASS_LEN 256

#ifdef __linux__
#define INOTIFY_BUFSZ (4096 * (sizeof(struct inotify_event) + NAME_MAX + 1))
#endif

/* Sandbox v2 */
#define SANDBOX_NOBODY_UID 65534
#define SANDBOX_NOBODY_GID 65534
#define SANDBOX_JAIL_MARKER ".diamond_jail_ready"
#define SANDBOX_TMP_SIZE "mode=1777,size=64m"

/* AES-256-GCM */
#define GCM_IV_LEN 12 /* 96 bits */
#define GCM_TAG_LEN 16

    /* Alert intervals in seconds */
    static const long ALERT_INTERVALS[] = {
        300, 600, 900, 1800, 3600, 7200, 14400, 28800,
        43200, 86400, 172800, 259200, 604800, 1209600,
        1814400, 2592000, 5184000, 7776000, 15552000, 31536000};
#define NUM_ALERT_INTERVALS (sizeof(ALERT_INTERVALS) / sizeof(ALERT_INTERVALS[0]))

/* Catalog binary format */
#define CATALOG_MAGIC "VLTS"
#define CATALOG_VER 2   /* v2: added worm_flags per-vault (uint32_t) */
#define FCOUNT_MAX 1000

/* Rule engine */
#define MAX_RULES 64

    /* ─────────────────────────────────────────────
     *  ENUMERATIONS
     * ───────────────────────────────────────────── */
    typedef enum
    {
        VAULT_TYPE_NORMAL = 0,
        VAULT_TYPE_PROTECTED = 1
    } VaultType;

    typedef enum
    {
        VAULT_STATUS_OK = 0,
        VAULT_STATUS_LOCKED = 1,
        VAULT_STATUS_ALERT = 2,
        VAULT_STATUS_DELETED = 3
    } VaultStatus;

    typedef enum
    {
        LOG_INFO = 0,
        LOG_WARN = 1,
        LOG_ERROR = 2,
        LOG_ALERT = 3,
        LOG_AUDIT = 4
    } LogLevel;

    typedef enum
    {
        ERR_OK = 0,
        ERR_INVALID_ARGS = -1,
        ERR_NO_MEMORY = -2,
        ERR_IO = -3,
        ERR_CRYPTO = -4,
        ERR_AUTH_FAIL = -5,
        ERR_VAULT_LOCKED = -6,
        ERR_VAULT_EXISTS = -7,
        ERR_VAULT_NOT_FOUND = -8,
        ERR_PERM_DENIED = -9,
        ERR_CATALOG_FULL = -10,
        ERR_PATH_INVALID = -11,
        ERR_PASS_REQUIRED = -12,
        ERR_INTEGRITY = -13,
        ERR_SYSTEM = -14,
        /* Kernel Error Strict Codes */
        ERR_SYSTEM_UNSHARE_FAILED = -15,
        ERR_SYSTEM_MOUNT_FAILED = -16,
        ERR_SYSTEM_PIVOT_ROOT_FAILED = -17,
        ERR_SYSTEM_CLONE_FAILED = -18
    } VaultErrorr;

    /* ─────────────────────────────────────────────
     *  DATA STRUCTURES
     * ───────────────────────────────────────────── */

    /* Vault Container (Self-Executing Bundle) */
    typedef struct {
        uint32_t id;
        char path[VAULT_PATH_MAX];          // Caminho onde o vault-container está armazenado
        char image_tarball[VAULT_PATH_MAX]; // Imagem base do SO (ex: ubuntu.tar.gz)
        char entrypoint[512];              // Comando a rodar no start
        int sealed;                        // 1 se selado para transporte

        /* Política de whitelist para containers selados (sealed=1).
         * Por padrão (whitelist_excluded=0), operações na whitelist (ex: overlay
         * mount) são permitidas mesmo com o container selado.
         *
         * CLI:
         *   --white-list -e   → whitelist_excluded = 1 (exclui whitelist — bloqueia tudo)
         *   --white-list -r   → whitelist_excluded = 0 (restaura whitelist padrão)  */
        int whitelist_excluded;

        int require_network;
        int require_gui;
    } VaultContainer;

    /* One file entry in the hash map */
    typedef struct FileEntry
    {
        char filename[NAME_MAX + 1];
        char hash[HASH_HEX_LEN];
        time_t last_seen;
        bool modified;
        struct FileEntry *next;
    } FileEntry;

/* Hash map bucket */
#define HASHMAP_BUCKETS 256
    typedef struct
    {
        FileEntry *buckets[HASHMAP_BUCKETS];
        size_t count;
    } FileHashMap;

    /* Alert state per vault */
    typedef struct
    {
        time_t first_triggered;
        time_t last_alerted;
        size_t interval_idx;
        size_t alert_count;
        char reason[256];
    } AlertState;

    /* Core vault structure */
    typedef struct
    {
        uint32_t id;
        char name[VAULT_NAME_MAX];
        VaultType type;
        VaultStatus status;
        bool has_pass;
        char path[VAULT_PATH_MAX];
        char cipher_path[VAULT_PATH_MAX];
        bool is_mounted;
        time_t created_at;
        time_t last_check;
        int failed_attempts;

        /* Auth */
        uint8_t salt[SALT_LEN];
        uint8_t pass_hash[SHA256_DIGEST_LENGTH]; /* PBKDF2(pass, salt) */

        /* File integrity */
        FileHashMap hashmap;

        /* Alert state */
        AlertState alert;

        /* fanotify watch descriptor (Linux only) */
        int fanotify_wd;

        /* Protection */
        bool write_mode; /* True only during authorized write operations */

        /* ── WORM / Protection flags ─────────────────────────────────────
         * Bitmask controlling FUSE-level enforcement.
         *
         *  WORM_PROTECT_DELETE  — unlink/rmdir → EPERM
         *  WORM_PROTECT_RENAME  — rename       → EPERM
         *  WORM_PROTECT_WRITE   — write to an existing file → EPERM
         *                         (new file creation via vfuse_create is still allowed)
         *  WORM_PROTECT_READ    — read to an existing file → EPERM
         *  WORM_PROTECT_SCAN    — "protected-scan" mode: all three protections above
         *                         are forced ON and cannot be changed at runtime;
         *                         the only way to retrieve files is mount-export.
         *
         * Persistence: stored in catalog.dat alongside the rest of Vault fields.
         * ──── */
#define WORM_PROTECT_DELETE  (1u << 0)   /* --protect-delete  */
#define WORM_PROTECT_RENAME  (1u << 1)   /* --protect-rename  */
#define WORM_PROTECT_WRITE   (1u << 2)   /* --no-write        */
#define WORM_PROTECT_SCAN    (1u << 3)   /* --protected-scan  (immutable super-flag) */
#define WORM_PROTECT_READ    (1u << 4)   /* --protect-read    */
#define WORM_PROTECT_ALL     (WORM_PROTECT_DELETE | WORM_PROTECT_READ | WORM_PROTECT_RENAME | WORM_PROTECT_WRITE)

        uint32_t worm_flags; /* bitmask of WORM_PROTECT_* above */

        /* Optional per-file buckets (linked list) */
        FileBucket *file_buckets;
        double bucket_credits;

        /* Engine de isolamento (0 = sem engine, 1-5 = níveis de proteção) */
        int engine_level;
    } Vault;

    /* Evaluate a single WORM flag against the vault.
     * WORM_PROTECT_SCAN forces ALL protection bits regardless of the stored mask. */
    static inline bool worm_check(const Vault *v, uint32_t flag)
    {
        if (!v) return false;
        /* SCAN super-flag: treat every protection bit as set */
        if (v->worm_flags & WORM_PROTECT_SCAN)
            return (flag & WORM_PROTECT_ALL) != 0;
        return (v->worm_flags & flag) != 0;
    }

    /* Catalog: flat array of vaults */
    typedef struct
    {
        Vault vaults[MAX_VAULTS];
        uint32_t count;
        uint32_t next_id;
        char category[32]; /* "diamond" */
    } Catalog;

    /* Monitor thread context */
    typedef struct
    {
        Catalog *catalog;
        int fanoti_fd;
        volatile bool running;
        bool quiet_mode; /* Se true, reduz verbosidade de alertas do monitor */
#ifdef __linux__
        pthread_mutex_t lock;
#endif
    } MonitorCtx;

    /* Rule engine */
    typedef struct
    {
        uint32_t vault_id;
        int max_failed_attempts;
        int allowed_hour_from; /* 0-23, -1 = no restriction */
        int allowed_hour_to;
    } VaultRule;

    /* ─────────────────────────────────────────────
     *  GLOBALS (extern — defined in vault_catalog.c)
     * ───────────────────────────────────────────── */
    extern Catalog g_catalog;
    extern MonitorCtx g_monitor;
    extern FILE *g_logfp;
    extern bool g_verbose;
    extern VaultRule g_rules[MAX_RULES];
    extern uint32_t g_rule_count;
    extern volatile bool g_running;
    void resolve_paths(void);

/* ─────────────────────────────────────────────
 *  ASSERTION MACROS
 * ───────────────────────────────────────────── */
#define VAULT_ASSERT(cond, err, fmt, ...)                       \
    do                                                          \
    {                                                           \
        if (!(cond))                                            \
        {                                                       \
            vault_log(LOG_ERROR, "ASSERT FAILED [%s:%d]: " fmt, \
                      __FILE__, __LINE__, ##__VA_ARGS__);       \
            return (err);                                       \
        }                                                       \
    } while (0)

#define VAULT_ASSERT_VOID(cond, fmt, ...)                       \
    do                                                          \
    {                                                           \
        if (!(cond))                                            \
        {                                                       \
            vault_log(LOG_ERROR, "ASSERT FAILED [%s:%d]: " fmt, \
                      __FILE__, __LINE__, ##__VA_ARGS__);       \
            return;                                             \
        }                                                       \
    } while (0)

    /* ─────────────────────────────────────────────
     *  FUNCTION DECLARATIONS
     * ───────────────────────────────────────────── */

    /* vault_crypto.c */
    void vault_log(LogLevel lvl, const char *fmt, ...);
    void log_init(void);
    const char *vault_strerror(VaultErrorr err);
    char *sanitize_arg(char *s);
    VaultErrorr validate_path(const char *path);
    VaultErrorr validate_name(const char *name);
    void sha256_hex(const uint8_t *data, size_t len, char out[HASH_HEX_LEN]);
    VaultErrorr sha256_file(const char *path, char out[HASH_HEX_LEN]);
    /* [FIX-6] Use sempre derive_key_for com um propósito explícito
     * ("auth-verify", "file-encryption", etc.) — nunca derive_key() puro
     * para novos usos, pois isso reintroduziria a reutilização de chave
     * entre o hash de autenticação persistido e a chave de criptografia. */
    VaultErrorr derive_key_for(const char *password, const uint8_t *salt,
                              const char *purpose, uint8_t key[KEY_LEN]);
    VaultErrorr derive_key(const char *password, const uint8_t *salt, uint8_t key[KEY_LEN]);
    VaultErrorr auth_set_password(Vault *v, const char *password);
    VaultErrorr auth_verify_password(Vault *v, const char *password);
    VaultErrorr encrypt_file(const char *inpath, const char *outpath, const uint8_t key[KEY_LEN]);
    VaultErrorr decrypt_file(const char *inpath, const char *outpath, const uint8_t key[KEY_LEN]);

    /* vault_catalog.c */
    VaultErrorr catalog_save(void);
    VaultErrorr catalog_load(void);
    uint32_t hashmap_bucket(const char *s);
    FileEntry *hashmap_find(FileHashMap *m, const char *filename);
    FileEntry *hashmap_insert(FileHashMap *m, const char *filename);
    void hashmap_clear(FileHashMap *m);
    Vault *vault_find_by_id(uint32_t id);
    Vault *vault_find_by_name(const char *name);
    VaultErrorr vault_create(const char *name_arg, VaultType type, const char *path_arg, const char *password);
    VaultErrorr vault_delete(uint32_t id, const char *password);
    VaultErrorr vault_rename(uint32_t id, const char *new_name, const char *password);
    VaultErrorr vault_unlock(uint32_t id, const char *password);
    VaultErrorr vault_change_password(uint32_t id, const char *old_pass, const char *new_pass);

    /* vault_monitor.c */
    void monitor_scan_vault(Vault *v);
    void vault_enforce_readonly(Vault *v);
    void vault_set_write_mode(Vault *v, bool enable);
    void alert_trigger(Vault *v, const char *reason);
    void alert_check_escalation(Vault *v);
    VaultErrorr alert_resolve(uint32_t id, const char *password);
    void rule_add(uint32_t vault_id, int max_fails, int hour_from, int hour_to);
    void rule_evaluate(Vault *v);
#ifdef __linux__
    void *monitor_thread(void *arg);
    void monitor_add_vault_watches(MonitorCtx *ctx);
#endif

    /* vault_sandbox.c */
    VaultErrorr vault_sandbox_open(Vault *v, const char *password, bool gui_mode, const char *app_cmd);

    /* vault_fuse.c */
    VaultErrorr vault_fuse_mount(Vault *v);
    VaultErrorr vault_fuse_unmount(Vault *v);

    /* vault_fuse.c — WORM helpers */
    /* Returns true when the SCAN super-flag is active (immutable mode). */
    bool vault_worm_is_scan_locked(const Vault *v);
    /* Set/clear individual protection flags. Fails with ERR_PERM_DENIED when
     * WORM_PROTECT_SCAN is active (use vault_worm_set_scan() to enable scan lock;
     * once set it cannot be cleared programmatically). */
    VaultErrorr vault_worm_set_flags(Vault *v, uint32_t flags);
    VaultErrorr vault_worm_clear_flags(Vault *v, uint32_t flags);
    /* Engage full WORM+scan lock (sets WORM_PROTECT_SCAN | WORM_PROTECT_ALL).
     * Irreversible at runtime — only mount-export can retrieve files. */
    VaultErrorr vault_worm_set_scan(Vault *v);

/* vault_engine.c */
#define ENGINE_LEVEL_MIN 0               /* sem engine */
#define ENGINE_LEVEL_MAX 5               /* OverlayFS  */
#define ENGINE_DECOY_DIR ".engine_decoy" /* subdir de iscas dentro do vault */
#define ENGINE_REAL_DIR ".engine_real"   /* subdir de arquivos reais        */
#define ENGINE_LOG_PREFIX "[ENGINE]"

    /* Camadas por engine:
     *   0 → 0 camadas (sem labirinto)
     *   1 → 1 camada,  arquivos a-z
     *   2 → 3 camadas, arquivos a-z por camada
     *   3 → 6 camadas, arquivos a-z por camada
     *   4 → 16 camadas + binários falsos .enc
     *   5 → 20 camadas + binários falsos .enc (OverlayFS adicionado depois)
     */
    static const int ENGINE_LAYER_COUNT[] = {0, 1, 3, 6, 16, 20};

    VaultErrorr engine_apply(Vault *v);
    VaultErrorr engine_validate(Vault *v);
    /* [FIX-2 cleanup] engine_is_decoy_path(path) removida — usava strstr()
     * (vulnerável a path traversal). Use engine_is_decoy_path_v(vault, path). */

    /* vault_cli.c (standalone CLI — only for diamondVaults standalone binary) */
    /* Not needed for FFI build */

    /* ─────────────────────────────────────────────
     *  REVERSE FFI (Rust functions called from C)
     * ───────────────────────────────────────────── */
    extern int rust_vault_copy_file(const char *src, const char *dst);
    extern int rust_vault_remove_file(const char *path);

    /* ─────────────────────────────────────────────
     *  FFI EXPORTS (vault_ffi.c)
     * ───────────────────────────────────────────── */
    int vault_ffi_init(void);
    int vault_ffi_shutdown(void);

    int vault_create_ffi(const char *name, int vault_type, const char *path, const char *password);
    int vault_delete_ffi(uint32_t id, const char *password);
    int vault_rename_ffi(uint32_t id, const char *new_name, const char *password);
    int vault_unlock_ffi(uint32_t id, const char *password);
    int vault_change_password_ffi(uint32_t id, const char *old_pass, const char *new_pass);
    int vault_encrypt_ffi(uint32_t id, const char *password);
    int vault_decrypt_ffi(uint32_t id, const char *password);
    int vault_scan_ffi(uint32_t id);
    int vault_scan_report_ffi(uint32_t id, char *out, size_t out_len);
    int vault_resolve_ffi(uint32_t id, const char *password);
    void vault_info_ffi(uint32_t id);
    void vault_list_ffi(void);
    void vault_files_ffi(uint32_t id);
    int vault_sandbox_ffi(uint32_t id, const char *password, int gui_mode, const char *app_cmd);
    int vault_rule_ffi(uint32_t vault_id, int max_fails, int hour_from, int hour_to);
    int vault_get_status_ffi(uint32_t id);
    int vault_export_file_ffi(uint32_t id, const char *filename, const char *dst_path);
    int vault_export_and_decrypt_file_ffi(uint32_t id, const char *filename, const char *dst_path, const char *password);
    int vault_get_real_path_ffi(uint32_t id, char *out_path, size_t out_len);
    int vault_is_protected_ffi(uint32_t id);
    int vault_apply_engine_ffi(const char *name, int engine_level);
    int vault_validate_engine_ffi(uint32_t id);
    int vault_mount_ffi(uint32_t id, const char *password);
    int vault_unmount_ffi(uint32_t id);

    /* WORM flag FFI — called from Rust */
    int vault_worm_set_flags_ffi(uint32_t id, uint32_t flags);
    int vault_worm_clear_flags_ffi(uint32_t id, uint32_t flags);
    int vault_worm_set_scan_ffi(uint32_t id);
    uint32_t vault_worm_get_flags_ffi(uint32_t id);

    /* mount-export FFI */
    int vault_mount_export_ffi(uint32_t id, const char *password,
                               const char *dst_dir, const char *filename);
    int vault_list_ids_ffi(VaultIdPath *out, uint32_t out_cap, uint32_t *out_count);
    uint32_t vault_count_ffi(void);
    void vault_auth_pid_add_ffi(pid_t pid);
    void vault_auth_pid_remove_ffi(pid_t pid);
    int vault_auth_pid_is_authorized_ffi(pid_t pid);

    /* Wrappers do sandbox (vsb_*) movidos para sandbox.h — split modular
     * de vault_sandbox.c em caps.c/userns.c/mounts.c/rlimits.c/seccomp.c/
     * jail.c/common.c. Quem precisar deles inclui "sandbox.h" direto. */

    /* ── vault_cli.c — entry point FFI ── */
    int vault_cli_parse_and_exec(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* VAULT_CORE_H */