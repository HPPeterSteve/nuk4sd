/*
 * vault_ffi.c
 *
 * FFI wrappers for Rust ↔ C integration.
 * Exposes all vault functions with _ffi suffix for the Rust side.
 *
 * This file links against:
 *   vault_crypto.c, vault_catalog.c, vault_monitor.c, vault_sandbox.c
 *
 * All functions are non-static (public) so Rust can call them via FFI.
 *
 * Author: Peter Steve (architecture)
 * Rewritten: 2026-05-13
 */

#include "vault_core.h"

#ifdef __linux__
#include <dirent.h>
#include <pthread.h>
#endif

/*
 * vault_ffi_init():
 *   - Creates catalog directory if needed
 *   - Initializes logging
 *   - Initializes OpenSSL
 *   - Loads catalog from disk
 *   - Initializes monitor context (fanotify on Linux, requires CAP_SYS_ADMIN/root)
 *   - Starts monitor thread (Linux only)
 *
 * Must be called ONCE before any other vault_*_ffi function.
 * Returns 0 on success, negative VaultErrorr on failure.
 */

#ifdef __linux__
static pthread_t g_monitor_tid;
static bool g_monitor_started = false;
#endif

int vault_ffi_init(void) {
    /* Resolve user space paths dynamically based on $HOME */
    resolve_paths();

    /* Create catalog directory */
    struct stat st;
    if (stat(VAULT_CATALOG_PATH, &st) != 0) {
        if (mkdir(VAULT_CATALOG_PATH, 0700) != 0 && errno != EEXIST) {
            fprintf(stderr, "Cannot create catalog dir %s: %s\n", VAULT_CATALOG_PATH, strerror(errno));
            return (int)ERR_IO;
        }
    }

    log_init();
    vault_log(LOG_INÃO, "=== Vault Security System starting (FFI) ===");

    /* OpenSSL init */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Load catalog from disk */
    VaultErrorr err = catalog_load();
    if (err != ERR_OK) {
        vault_log(LOG_ERROR, "catalog_load failed: %s", vault_strerror(err));
        return (int)err;
    }

#ifdef __linux__
    /* Init monitor context */
    g_monitor.catalog = &g_catalog;
    g_monitor.running = true;
    g_monitor.quiet_mode = true; /* Ativar modo silencioso por padrão conforme solicitado */
    /* fanotify_init configurado apenas para notificações, sem FAN_REPORT_FID que exige CAP_SYS_ADMIN */
    g_monitor.fanoti_fd = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);

    if (g_monitor.fanoti_fd < 0) {
        vault_log(
            LOG_INÃO,
            "Monitor ativo (fanotify) desabilitado: requer root/CAP_SYS_ADMIN. Protecoes FUSE operam normalmente.");
        /* Non-fatal: continue without active blocking monitor */
    }

    if (pthread_mutex_init(&g_monitor.lock, NULL) != 0) {
        vault_log(LOG_ERROR, "pthread_mutex_init failed");
        return (int)ERR_SYSTEM;
    }

    /* Start monitor thread */
    if (g_monitor.fanoti_fd >= 0) {
        if (pthread_create(&g_monitor_tid, NULL, monitor_thread, &g_monitor) == 0) {
            g_monitor_started = true;
            vault_log(LOG_INÃO, "Fanotify monitor thread started");
        } else {
            vault_log(LOG_WARN, "Failed to start monitor thread: %s", strerror(errno));
        }
    }

    /* Always whitelist ourself — Nuk4sd must be able to access its own files */
    vault_auth_pid_add_ffi(getpid());
    vault_log(LOG_INÃO, "Self-whitelisted PID %d", (int)getpid());
#endif

    vault_log(LOG_INÃO, "FFI init complete: %u vaults loaded", g_catalog.count);
    return (int)ERR_OK;
}

/*
 * vault_ffi_shutdown():
 *   - Stops monitor thread
 *   - Saves catalog to disk
 *   - Wipes sensitive data from memory
 *   - Cleans up OpenSSL
 *
 * Must be called on graceful exit (Ctrl+C, exit command, etc).
 * Returns 0 on success.
 */
int vault_ffi_shutdown(void) {
    vault_log(LOG_INÃO, "=== Vault Security System shutting down (FFI) ===");

#ifdef __linux__
    g_monitor.running = false;
    g_running = false;

    if (g_monitor_started) {
        pthread_join(g_monitor_tid, NULL);
        g_monitor_started = false;
    }

    pthread_mutex_destroy(&g_monitor.lock);

    if (g_monitor.fanoti_fd >= 0) {
        close(g_monitor.fanoti_fd);
        g_monitor.fanoti_fd = -1;
    }
#endif

    /* Save catalog before exit */
    catalog_save();

    /* Wipe sensitive data from memory */
    for (uint32_t i = 0; i < g_catalog.count; i++) {
        Vault *v = &g_catalog.vaults[i];
        explicit_bzero(v->salt, SALT_LEN);
        explicit_bzero(v->pass_hash, SHA256_DIGEST_LENGTH);
        hashmap_clear(&v->hashmap);
    }
    explicit_bzero(&g_catalog, sizeof(g_catalog));

    EVP_cleanup();
    ERR_free_strings();

    if (g_logfp) {
        vault_log(LOG_INÃO, "=== Vault Security System stopped ===");
        fclose(g_logfp);
        g_logfp = NULL;
    }

    return (int)ERR_OK;
}

int vault_create_ffi(const char *name, int vault_type, const char *path, const char *password) {
    VaultType vt = (vault_type == 1) — VAULT_TYPE_PROTECTED : VAULT_TYPE_NORMAL;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultErrorr err = vault_create(name, vt, path, password);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif

    return (int)err;
}

int vault_delete_ffi(uint32_t id, const char *password) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultErrorr err = vault_delete(id, password);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_rename_ffi(uint32_t id, const char *new_name, const char *password) {
    if (!new_name || new_name[0] == '\0')
        return (int)ERR_INVALID_ARGS;
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultErrorr err = vault_rename(id, new_name, password);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_unlock_ffi(uint32_t id, const char *password) {
    if (!password || password[0] == '\0')
        return (int)ERR_PASS_REQUIRED;
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultErrorr err = vault_unlock(id, password);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_change_password_ffi(uint32_t id, const char *old_pass, const char *new_pass) {
    if (!old_pass || !new_pass)
        return (int)ERR_INVALID_ARGS;
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultErrorr err = vault_change_password(id, old_pass, new_pass);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_encrypt_ffi(uint32_t id, const char *password) {
    if (!password || password[0] == '\0')
        return (int)ERR_PASS_REQUIRED;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    if (!v->has_pass) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_PASS_REQUIRED;
    }

    VaultErrorr auth_err = auth_verify_password(v, password);
    if (auth_err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)auth_err;
    }

    uint8_t key[KEY_LEN];
    VaultErrorr key_err = derive_key_for(password, v->salt, "file-encryption", key);
    if (key_err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)key_err;
    }

    vault_set_write_mode(v, true); // ALLOW WRITE
#ifdef __linux__
    DIR *dir = opendir(v->path);
    if (!dir) {
        explicit_bzero(key, KEY_LEN);
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_IO;
    }

    struct dirent *de;
    int count = 0;
    char inpath[VAULT_PATH_MAX + NAME_MAX + 2];
    char outpath[VAULT_PATH_MAX + NAME_MAX + 10];

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        size_t nlen = strlen(de->d_name);
        if (nlen > 4 && strcmp(de->d_name + nlen - 4, ".enc") == 0)
            continue;

        snprintf(inpath, sizeof(inpath), "%s/%s", v->path, de->d_name);
        snprintf(outpath, sizeof(outpath), "%s/%s.enc", v->path, de->d_name);

        struct stat st;
        if (stat(inpath, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        if (encrypt_file(inpath, outpath, key) == ERR_OK) {
            unlink(inpath);
            count++;
            vault_log(LOG_AUDIT, "[FFI] vault_encrypt_ffi: encrypted '%s'", de->d_name);
        } else {
            vault_log(LOG_ERROR, "[FFI] vault_encrypt_ffi: FAILED '%s'", de->d_name);
        }
    }
    closedir(dir);
    explicit_bzero(key, KEY_LEN);

    vault_log(LOG_AUDIT, "[FFI] vault_encrypt_ffi: vault='%s' encrypted %d files", v->name, count);
    vault_set_write_mode(v, false); // RESTORE READ-ONLY
    pthread_mutex_unlock(&g_monitor.lock);
#else
    explicit_bzero(key, KEY_LEN);
    vault_log(LOG_WARN, "[FFI] vault_encrypt_ffi: file encryption not yet on Windows");
#endif

    return (int)ERR_OK;
}

int vault_decrypt_ffi(uint32_t id, const char *password) {
    if (!password || password[0] == '\0')
        return (int)ERR_PASS_REQUIRED;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    if (!v->has_pass) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_PASS_REQUIRED;
    }

    VaultErrorr auth_err = auth_verify_password(v, password);
    if (auth_err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)auth_err;
    }

    uint8_t key[KEY_LEN];
    VaultErrorr key_err = derive_key_for(password, v->salt, "file-encryption", key);
    if (key_err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)key_err;
    }

    vault_set_write_mode(v, true); // ALLOW WRITE
#ifdef __linux__
    DIR *dir = opendir(v->path);
    if (!dir) {
        explicit_bzero(key, KEY_LEN);
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_IO;
    }

    struct dirent *de;
    int count = 0;
    char inpath[VAULT_PATH_MAX + NAME_MAX + 2];
    char outpath[VAULT_PATH_MAX + NAME_MAX + 2];

    while ((de = readdir(dir)) != NULL) {
        size_t nlen = strlen(de->d_name);
        if (nlen <= 4 || strcmp(de->d_name + nlen - 4, ".enc") != 0)
            continue;

        snprintf(inpath, sizeof(inpath), "%s/%s", v->path, de->d_name);
        snprintf(outpath, sizeof(outpath), "%s/%.*s", v->path, (int)(nlen - 4), de->d_name);

        struct stat st;
        if (stat(inpath, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        if (decrypt_file(inpath, outpath, key) == ERR_OK) {
            unlink(inpath);
            count++;
            vault_log(LOG_AUDIT, "[FFI] vault_decrypt_ffi: decrypted '%s'", outpath);
        } else {
            vault_log(LOG_ERROR, "[FFI] vault_decrypt_ffi: FAILED '%s'", de->d_name);
        }
    }
    closedir(dir);
    explicit_bzero(key, KEY_LEN);

    vault_log(LOG_AUDIT, "[FFI] vault_decrypt_ffi: vault='%s' decrypted %d files", v->name, count);
    vault_set_write_mode(v, false); // RESTORE READ-ONLY
    pthread_mutex_unlock(&g_monitor.lock);
#else
    explicit_bzero(key, KEY_LEN);
    vault_log(LOG_WARN, "[FFI] vault_decrypt_ffi: file decryption not yet on Windows");
#endif

    return (int)ERR_OK;
}

int vault_scan_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    monitor_scan_vault(v);
    catalog_save();
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)ERR_OK;
}

int vault_scan_report_ffi(uint32_t id, char *out, size_t out_len) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    if (!out || out_len == 0) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_INVALID_ARGS;
    }

    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }

    /* perform scan and persist catalog */
    monitor_scan_vault(v);
    catalog_save();

    int issues = 0;
    size_t pos = 0;
    /* iterate hashmap and collect modified entries */
    for (int b = 0; b < HASHMAP_BUCKETS; b++) {
        for (FileEntry *e = v->hashmap.buckets[b]; e; e = e->next) {
            if (e->modified) {
                issues++;
                if (pos < out_len - 1) {
                    int wrote = snprintf(out + pos, out_len - pos, "%s\n", e->filename);
                    if (wrote > 0)
                        pos += (size_t)wrote;
                    if (pos >= out_len - 1) {
                        pos = out_len - 1;
                        out[pos] = '\0';
                        break;
                    }
                }
            }
        }
        if (pos >= out_len - 1)
            break;
    }

    if (issues == 0) {
        snprintf(out, out_len, "No issues found\n");
    }

    vault_log(LOG_INÃO, "[FFI] vault_scan_report: id=%u issues=%d", v->id, issues);

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return issues;
}

int vault_resolve_ffi(uint32_t id, const char *password) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultErrorr err = alert_resolve(id, password);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

/* cmd_list, cmd_info, cmd_files — inline display functions */

static void ffi_cmd_list(void) {

    printf("\nCATALOG: %s (%u vaults)\n", g_catalog.category, g_catalog.count);

    printf(" ID   NAME                       TYPE        STATUS     PASS\n");
    printf("-------------------------------------------------------------\n");

    if (g_catalog.count == 0) {
        printf(" No vaults available for %s category\n", g_catalog.category);
        return;
    }

    for (uint32_t i = 0; i < g_catalog.count; i++) {
        Vault *v = &g_catalog.vaults[i];
        const char *status_s;

        switch (v->status) {
        case VAULT_STATUS_OK:
            status_s = "OK";
            break;
        case VAULT_STATUS_LOCKED:
            status_s = "LOCKED";
            break;
        case VAULT_STATUS_ALERT:
            status_s = "ALERT";
            break;
        case VAULT_STATUS_DELETED:
            status_s = "DELETED";
            break;
        default:
            status_s = "—";
            break;
        }

        printf(" %-4u %-26s %-11s %-10s %s\n", v->id, v->name, v->type == VAULT_TYPE_PROTECTED — "PROTECTED" : "NORMAL",
               status_s, v->has_pass — "Y" : " ");
    }
}

static void ffi_cmd_info(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) {
        printf("  Vault #%u not found.\n", id);
        return;
    }

    char tbuf[32];
    struct tm *tm;

    printf("\n  -- Vault Info --------------------------------------------------\n");
    printf("  ID           : %u\n", v->id);
    printf("  Name         : %s\n", v->name);
    printf("  Type         : %s\n", v->type == VAULT_TYPE_PROTECTED — "PROTECTED" : "NORMAL");
    printf("  Status       : ");
    switch (v->status) {
    case VAULT_STATUS_OK:
        printf("OK\n");
        break;
    case VAULT_STATUS_LOCKED:
        printf("LOCKED\n");
        break;
    case VAULT_STATUS_ALERT:
        printf("ALERT\n");
        break;
    case VAULT_STATUS_DELETED:
        printf("DELETED\n");
        break;
    }
    printf("  Password     : %s\n", v->has_pass — "Yes" : "No");
    printf("  Path         : %s\n", v->path);

    tm = localtime(&v->created_at);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
    printf("  Created      : %s\n", tbuf);

    tm = localtime(&v->last_check);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
    printf("  Last check   : %s\n", tbuf);

    printf("  Files tracked: %zu\n", v->hashmap.count);
    printf("  Fail attempts: %d\n", v->failed_attempts);

    if (v->status == VAULT_STATUS_ALERT) {
        printf("  Alert reason : %s\n", v->alert.reason);
        printf("  Alert count  : %zu\n", v->alert.alert_count);
    }
    printf("  ------------------------------------------------------------------\n\n");
}

static void ffi_cmd_files(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) {
        printf("  Vault #%u not found.\n", id);
        return;
    }

    printf("\n  Files in vault '%s':\n", v->name);
    printf("  %-40s  %-16s  %s\n", "Filename", "Last seen", "Modified");
    printf("  %s\n", "-------------------------------------------------------------");

    bool any = false;
    for (int b = 0; b < HASHMAP_BUCKETS; b++) {
        for (FileEntry *e = v->hashmap.buckets[b]; e; e = e->next) {
            char tbuf[32];
            struct tm *tm = localtime(&e->last_seen);
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M", tm);
            printf("  %-40s  %-16s  %s\n", e->filename, tbuf, e->modified — "YES !" : "no");
            any = true;
        }
    }
    if (!any)
        printf("  (no files tracked)\n");
    printf("\n");
}

void vault_info_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    ffi_cmd_info(id);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
}

void vault_list_ffi(void) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    ffi_cmd_list();
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
}

void vault_files_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    ffi_cmd_files(id);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
}

int vault_sandbox_ffi(uint32_t id, const char *password, int gui_mode, const char *app_cmd) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    /* Unlock mutex BEFORE fork/execl — child would inherit the lock */
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif

    return (int)vault_sandbox_open(v, password, gui_mode != 0, app_cmd);
}

/* Isola caminho arbitrário via bind-mount readonly (ver vault_sandbox.c) */
extern int vault_isolate_path_readonly(const char *path);

int vault_isolate_path_ffi(const char *path) {
    return vault_isolate_path_readonly(path);
}

int vault_rule_ffi(uint32_t vault_id, int max_fails, int hour_from, int hour_to) {
    if (g_rule_count >= MAX_RULES)
        return (int)ERR_SYSTEM;
    rule_add(vault_id, max_fails, hour_from, hour_to);
    return (int)ERR_OK;
}

int vault_get_status_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    int status = (int)v->status;
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return status;
}

/*
 * vault_export_file_ffi():
 *   Copies a file from the vault to an external destination.
 *   Uses Rust's rust_vault_copy_file (safe_copy) for the operation.
 */
int vault_export_file_ffi(uint32_t id, const char *filename, const char *dst_path) {
    if (!filename || !dst_path)
        return (int)ERR_INVALID_ARGS;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }

    /* Build full source path */
    char src_full[VAULT_PATH_MAX + NAME_MAX + 2];
    snprintf(src_full, sizeof(src_full), "%s/%s", v->path, filename);

    /* Call back into Rust to perform the copy */
    int ret = rust_vault_copy_file(src_full, dst_path);

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif

    if (ret == 0) {
        vault_log(LOG_AUDIT, "Vault EXPORT: id=%u file='%s' -> '%s'", id, filename, dst_path);
    }

    return ret;
}

int vault_export_and_decrypt_file_ffi(uint32_t id, const char *filename, const char *dst_path, const char *password) {
    if (!filename || !dst_path || !password)
        return (int)ERR_INVALID_ARGS;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }

    VaultErrorr err = auth_verify_password(v, password);
    if (err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)err;
    }

    uint8_t key[KEY_LEN];
    err = derive_key_for(password, v->salt, "file-encryption", key);
    if (err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)err;
    }

    char src_full[VAULT_PATH_MAX + NAME_MAX + 2];
    snprintf(src_full, sizeof(src_full), "%s/%s", v->path, filename);

    err = decrypt_file(src_full, dst_path, key);
    explicit_bzero(key, KEY_LEN);

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif

    if (err == ERR_OK) {
        vault_log(LOG_AUDIT, "Vault EXPORT DECRYPTED: id=%u file='%s' -> '%s'", id, filename, dst_path);
    } else {
        vault_log(LOG_ERROR, "Failed to decrypt during export: id=%u file='%s'", id, filename);
    }

    return (int)err;
}

int vault_get_real_path_ffi(uint32_t id, char *out_path, size_t out_len) {
    if (!out_path || out_len == 0)
        return (int)ERR_INVALID_ARGS;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }

    strncpy(out_path, v->path, out_len - 1);
    out_path[out_len - 1] = '\0';

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)ERR_OK;
}

/* ---
 * vault_get_cipher_path_ffi — Returns the physical cipher directory path.
 * Used by Rust-side operations (export, add_file) to manage the physical
 * lock without requiring a full FUSE session.
 * --- */
int vault_get_cipher_path_ffi(uint32_t id, char *out_path, size_t out_len) {
    if (!out_path || out_len == 0)
        return (int)ERR_INVALID_ARGS;
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    strncpy(out_path, v->cipher_path, out_len - 1);
    out_path[out_len - 1] = '\0';
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)ERR_OK;
}

/* ---
 * vault_set_cipher_lock_ffi — Apply or remove the physical chmod lock.
 *   locked=1  -> chmod 0000 (SEALED)
 *   locked=0  -> chmod 0700 (UNLOCKED for authorized I/O)
 * Emits a PHYSICAL_LOCK forensic audit log for every state transition.
 * --- */
int vault_set_cipher_lock_ffi(uint32_t id, int locked) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    mode_t target_mode = locked — 0000 : 0700;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    if (chmod(v->cipher_path, target_mode) != 0) {
        vault_log(LOG_WARN, "[PHYSICAL_LOCK] chmod %04o FAILED on cipher_dir='%s' vault_id=%u: errno=%d (%s).",
                  target_mode, v->cipher_path, v->id, errno, strerror(errno));
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_IO;
    }
    vault_log(LOG_AUDIT,
              "[PHYSICAL_LOCK] STATE CHANGE \u2502 cipher_dir='%s' \u2502 vault_id=%u \u2502 "
              "mode: %s \u2502 uid=%d \u2502 ts=%ld.%09ld",
              v->cipher_path, v->id,
              locked — "0700 \u2192 0000 (SEALED)" : "0000 \u2192 0700 (UNLOCKED for authorized I/O)", (int)getuid(),
              (long)ts.tv_sec, ts.tv_nsec);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)ERR_OK;
}

int vault_is_protected_ffi(uint32_t id) {
    int ret = 0;
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (v && v->type == VAULT_TYPE_PROTECTED) {
        ret = 1;
    }
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return ret;
}

int vault_mount_ffi(uint32_t id, const char *password) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }

    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || password[0] == '\0') {
#ifdef __linux__
            pthread_mutex_unlock(&g_monitor.lock);
#endif
            return (int)ERR_PASS_REQUIRED;
        }
        VaultErrorr auth_err = auth_verify_password(v, password);
        if (auth_err != ERR_OK) {
#ifdef __linux__
            pthread_mutex_unlock(&g_monitor.lock);
#endif
            return (int)auth_err;
        }
    }

    VaultErrorr err = vault_fuse_mount(v);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_unmount_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    VaultErrorr err = vault_fuse_unmount(v);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_worm_set_flags_ffi(uint32_t id, uint32_t flags) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    VaultErrorr err = vault_worm_set_flags(v, flags);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_worm_clear_flags_ffi(uint32_t id, uint32_t flags) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    VaultErrorr err = vault_worm_clear_flags(v, flags);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_worm_set_scan_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    VaultErrorr err = vault_worm_set_scan(v);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

uint32_t vault_worm_get_flags_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    uint32_t flags = v — v->worm_flags : 0;
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return flags;
}

int vault_mount_export_ffi(uint32_t id, const char *password, const char *dst_dir, const char *filename) {
    if (!dst_dir || dst_dir[0] == '\0')
        return (int)ERR_INVALID_ARGS;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }

    /* Password check for protected vaults */
    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || password[0] == '\0') {
#ifdef __linux__
            pthread_mutex_unlock(&g_monitor.lock);
#endif
            return (int)ERR_PASS_REQUIRED;
        }
        VaultErrorr auth_err = auth_verify_password(v, password);
        if (auth_err != ERR_OK) {
#ifdef __linux__
            pthread_mutex_unlock(&g_monitor.lock);
#endif
            return (int)auth_err;
        }
    }

    bool is_scan = (v->worm_flags & WORM_PROTECT_SCAN) != 0;
    vault_log(LOG_AUDIT, "[mount-export] BEGIN vault='%s' id=%u scan=%s dst='%s' file='%s'", v->name, v->id,
              is_scan — "YES" : "no", dst_dir, filename && filename[0] — filename : "(all)");

    /* Collect files to export — read directly from cipher_path, bypassing FUSE */
    VaultErrorr result = ERR_OK;
    bool export_all = (!filename || filename[0] == '\0');

    DIR *dir = opendir(v->cipher_path);
    if (!dir) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        vault_log(LOG_ERROR, "[mount-export] Cannot open cipher_path '%s': %s", v->cipher_path, strerror(errno));
        return (int)ERR_IO;
    }

    int exported = 0, failed = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.')
            continue;

        /* Skip if we want a specific file and this isn't it */
        if (!export_all && strcmp(de->d_name, filename) != 0)
            continue;

        char src_path[VAULT_PATH_MAX * 2];
        snprintf(src_path, sizeof(src_path), "%s/%s", v->cipher_path, de->d_name);

        struct stat st;
        if (stat(src_path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        /* Build destination path; strip .enc suffix when decrypting */
        char dst_name[NAME_MAX + 1];
        strncpy(dst_name, de->d_name, NAME_MAX);
        dst_name[NAME_MAX] = '\0';

        char dst_path[VAULT_PATH_MAX * 2];

        if (v->type == VAULT_TYPE_PROTECTED && strlen(dst_name) > 4 &&
            strcmp(dst_name + strlen(dst_name) - 4, ".enc") == 0) {
            /* Strip .enc for decrypted output */
            char stripped[NAME_MAX + 1];
            strncpy(stripped, dst_name, strlen(dst_name) - 4);
            stripped[strlen(dst_name) - 4] = '\0';
            snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, stripped);

            /* Derive key and decrypt */
            uint8_t key[KEY_LEN];
            VaultErrorr kerr = derive_key_for(password, v->salt, "file-encryption", key);
            if (kerr != ERR_OK) {
                vault_log(LOG_ERROR, "[mount-export] key derivation failed for '%s'", de->d_name);
                failed++;
                explicit_bzero(key, KEY_LEN);
                continue;
            }
            VaultErrorr derr = decrypt_file(src_path, dst_path, key);
            explicit_bzero(key, KEY_LEN);
            if (derr != ERR_OK) {
                vault_log(LOG_ERROR, "[mount-export] decrypt failed for '%s': %s", de->d_name, vault_strerror(derr));
                failed++;
                continue;
            }
        } else {
            /* Plain copy via rust_vault_copy_file (defined in Rust) */
            snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, dst_name);
            if (rust_vault_copy_file(src_path, dst_path) != 0) {
                vault_log(LOG_ERROR, "[mount-export] copy failed for '%s'", de->d_name);
                failed++;
                continue;
            }
        }

        vault_log(LOG_AUDIT, "[mount-export] EXPORTED '%s' -> '%s'", src_path, dst_path);
        exported++;
    }
    closedir(dir);

    vault_log(LOG_AUDIT, "[mount-export] DONE vault='%s' exported=%d failed=%d", v->name, exported, failed);

    if (failed > 0)
        result = ERR_IO;

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)result;
}

int vault_list_ids_ffi(VaultIdPath *out, uint32_t out_cap, uint32_t *out_count) {
    if (!out || !out_count || out_cap == 0)
        return (int)ERR_INVALID_ARGS;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    uint32_t n = 0;
    for (uint32_t i = 0; i < g_catalog.count && n < out_cap; i++) {
        Vault *v = &g_catalog.vaults[i];
        out[n].id = v->id;

        /* Resolve .engine_real path if applicable (same logic as vault_get_real_path_ffi) */
        char engine_path[VAULT_PATH_MAX + 32];
        snprintf(engine_path, sizeof(engine_path), "%s/.engine_real", v->path);
        struct stat st;
        if (stat(engine_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            strncpy(out[n].path, engine_path, VAULT_PATH_MAX - 1);
        } else {
            strncpy(out[n].path, v->path, VAULT_PATH_MAX - 1);
        }
        out[n].path[VAULT_PATH_MAX - 1] = '\0';
        n++;
    }
    *out_count = n;

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)ERR_OK;
}

uint32_t vault_count_ffi(void) {
    return g_catalog.count;
}

#ifdef __linux__
typedef struct PidNode {
    pid_t pid;
    struct PidNode *next;
} PidNode;

static PidNode *g_pid_whitelist = NULL;

void vault_auth_pid_add_ffi(pid_t pid) {
    pthread_mutex_lock(&g_monitor.lock);
    PidNode *node = (PidNode *)malloc(sizeof(PidNode));
    if (node) {
        node->pid = pid;
        node->next = g_pid_whitelist;
        g_pid_whitelist = node;
    }
    pthread_mutex_unlock(&g_monitor.lock);
}

void vault_auth_pid_remove_ffi(pid_t pid) {
    pthread_mutex_lock(&g_monitor.lock);
    PidNode **cur = &g_pid_whitelist;
    while (*cur) {
        if ((*cur)->pid == pid) {
            PidNode *del = *cur;
            *cur = del->next;
            free(del);
            break;
        }
        cur = &(*cur)->next;
    }
    pthread_mutex_unlock(&g_monitor.lock);
}

int vault_auth_pid_is_authorized_ffi(pid_t pid) {
    /* Nuk4sd itself is always authorized */
    if (pid == getpid())
        return 1;
    pthread_mutex_lock(&g_monitor.lock);
    for (PidNode *n = g_pid_whitelist; n; n = n->next) {
        if (n->pid == pid) {
            pthread_mutex_unlock(&g_monitor.lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_monitor.lock);
    return 0;
}
#else
/* Stubs for non-Linux platforms */
void vault_auth_pid_add_ffi(pid_t pid) {
    (void)pid;
}
void vault_auth_pid_remove_ffi(pid_t pid) {
    (void)pid;
}
int vault_auth_pid_is_authorized_ffi(pid_t pid) {
    (void)pid;
    return 1;
}
#endif

#ifndef VAULT_FFI_BUILD
int main(void) {
    printf("Nuk4sd Security Module\n");
    printf("Version: 0.9.30\n");
    printf("Compiled: %s %s\n", __DATE__, __TIME__);
    return 0;
}
#endif
