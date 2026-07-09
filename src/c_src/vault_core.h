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

#define _GNU_SOURCE
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
#define VAULT_CATALOG_PATH "/var/lib/vault_security"
#define VAULT_CATALOG_FILE "/var/lib/vault_security/catalog.dat"
    /* Optional per-file buckets (linked list) for slow-stealth detection */
    FileBucket *file_buckets;
#define VAULT_LOG_FILE "/var/log/vault_security.log"
#define VAULT_LOCK_FILE "/var/run/vault_security.pid"

#define MAX_VAULTS 2048
#define MAX_FILES_PER_VAULT 4096
#define VAULT_NAME_MAX 128
#define VAULT_PATH_MAX 512
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
#define CATALOG_VER 1
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
        ERR_SYSTEM = -14
    } VaultError;

    /* ─────────────────────────────────────────────
     *  DATA STRUCTURES
     * ───────────────────────────────────────────── */

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

        /* Engine de isolamento (0 = sem engine, 1-5 = níveis de proteção) */
        int engine_level;
    } Vault;

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
        int fanotify_fd;
        volatile bool running;
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
    const char *vault_strerror(VaultError err);
    char *sanitize_arg(char *s);
    VaultError validate_path(const char *path);
    VaultError validate_name(const char *name);
    void sha256_hex(const uint8_t *data, size_t len, char out[HASH_HEX_LEN]);
    VaultError sha256_file(const char *path, char out[HASH_HEX_LEN]);
    VaultError derive_key(const char *password, const uint8_t *salt, uint8_t key[KEY_LEN]);
    VaultError auth_set_password(Vault *v, const char *password);
    VaultError auth_verify_password(Vault *v, const char *password);
    VaultError encrypt_file(const char *inpath, const char *outpath, const uint8_t key[KEY_LEN]);
    VaultError decrypt_file(const char *inpath, const char *outpath, const uint8_t key[KEY_LEN]);

    /* vault_catalog.c */
    VaultError catalog_save(void);
    VaultError catalog_load(void);
    uint32_t hashmap_bucket(const char *s);
    FileEntry *hashmap_find(FileHashMap *m, const char *filename);
    FileEntry *hashmap_insert(FileHashMap *m, const char *filename);
    void hashmap_clear(FileHashMap *m);
    Vault *vault_find_by_id(uint32_t id);
    Vault *vault_find_by_name(const char *name);
    VaultError vault_create(const char *name_arg, VaultType type, const char *path_arg, const char *password);
    VaultError vault_delete(uint32_t id, const char *password);
    VaultError vault_rename(uint32_t id, const char *new_name, const char *password);
    VaultError vault_unlock(uint32_t id, const char *password);
    VaultError vault_change_password(uint32_t id, const char *old_pass, const char *new_pass);

    /* vault_monitor.c */
    void monitor_scan_vault(Vault *v);
    void vault_enforce_readonly(Vault *v);
    void vault_set_write_mode(Vault *v, bool enable);
    void alert_trigger(Vault *v, const char *reason);
    void alert_check_escalation(Vault *v);
    VaultError alert_resolve(uint32_t id, const char *password);
    void rule_add(uint32_t vault_id, int max_fails, int hour_from, int hour_to);
    void rule_evaluate(Vault *v);
#ifdef __linux__
    void *monitor_thread(void *arg);
    void monitor_add_vault_watches(MonitorCtx *ctx);
#endif

    /* vault_sandbox.c */
    VaultError vault_sandbox_open(Vault *v, const char *password);

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

    VaultError engine_apply(Vault *v);
    VaultError engine_validate(Vault *v);
    bool engine_is_decoy_path(const char *path);

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
    int vault_sandbox_ffi(uint32_t id, const char *password);
    int vault_rule_ffi(uint32_t vault_id, int max_fails, int hour_from, int hour_to);
    int vault_get_status_ffi(uint32_t id);
    int vault_export_file_ffi(uint32_t id, const char *filename, const char *dst_path);

#ifdef __cplusplus
}
#endif

#endif /* VAULT_CORE_H */
