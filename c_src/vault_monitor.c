/*
 * vault_monitor.c
 *
 * VAULT SECURITY SYSTEM — File Integrity Monitor, Alerts, Rules
 * Sections 8, 9, 10, 11 from legacy monolith
 *
 * Contains:
 *   - File integrity scanning (SHA-256 per-file)
 *   - Alert system with temporal escalation
 *   - Rule engine (max fails, time windows)
 *   - inotify monitor thread (Linux only)
 *
 * Author: Peter Steve (architecture)
 * Split: 2026-05-13
 */

#include "vault_core.h"

#ifdef __linux__
#include <dirent.h>
#endif

/* ─────────────────────────────────────────────────────────────────────────
 *  is_sandbox_internal() — Filter inotify events caused by the sandbox
 *  setup itself (vault_prepare_jail + sandbox_pivot_root), preventing
 *  false-positive anti-ransomware alerts on our own internal files.
 *
 *  Files filtered:
 *    .Nuk4sd_jail_ready  — jail marker written by vault_prepare_jail()
 *    .sandbox_*           — mkdtemp temp dir used by sandbox_pivot_root()
 *    proc / tmp / dev / bin / lib / lib64  — jail subdirectories
 * ───────────────────────────────────────────────────────────────────────── */
static inline bool is_sandbox_internal(const char *name)
{
    if (!name || name[0] == '\0')
        return false;
    if (strcmp(name, SANDBOX_JAIL_MARKER) == 0)
        return true; /* .Nuk4sd_jail_ready */
    if (strncmp(name, ".sandbox_", 9) == 0)
        return true; /* .sandbox_XXXXXX     */
    /* Jail subdirectories created by vault_prepare_jail() */
    if (strcmp(name, "proc") == 0)
        return true;
    if (strcmp(name, "tmp") == 0)
        return true;
    if (strcmp(name, "dev") == 0)
        return true;
    if (strcmp(name, "bin") == 0)
        return true;
    if (strcmp(name, "lib") == 0)
        return true;
    if (strcmp(name, "lib64") == 0)
        return true;
    return false;
}

/* Helper: replenish per-file bucket credits */
static void replenish_file_bucket_if_needed(FileBucket *fb, time_t now)
{
    if (!fb)
        return;
    if (fb->last_update == 0)
    {
        fb->credits = 15.0;
        fb->time_esgoted = 0;
        fb->credits_flash = 2;
        fb->last_update = now;
        return;
    }
    double elapsed = difftime(now, fb->last_update);
    fb->credits += elapsed * 0.025; /* Refill 0.1 credit per second */
    if (fb->credits > 15.0)
        fb->credits = 15.0;
    fb->last_update = now;
}

/* Helper: deduct credit and alert if exhausted */
static void deduct_credit_and_maybe_alert(Vault *v, FileBucket *fb, const char *evname)
{
    if (!fb || !v)
        return;
    fb->credits -= 1.0;
    if (fb->credits <= 0.0)
    {
        fb->credits = 0.0;
        vault_log(LOG_ALERT, "[CRITICAL] Emergency! All credits exhausted for file '%s' in vault '%s'!", evname, v->name);
        char reason[256];
        snprintf(reason, sizeof(reason), "Emergency! All credits exhausted for file '%s' %s", evname, fb->time_esgoted > 0 ? "(multiple times)" : "");
        alert_trigger(v, reason);
        vault_enforce_readonly(v);
    }
    else if (fb->credits <= 1.0)
    {
        fb->time_esgoted++;
        vault_log(LOG_WARN, "[%s] Warning: Credits exhausted for file '%s' in vault '%s' (time_esgoted=%d)", v->name,
                  evname, v->name, fb->time_esgoted);
    }
}
static void flash_credit_reduce(Vault *v, FileBucket *fb, const char *evname)
{
    if (!fb || !v)
        return;
    if (fb->credits_flash > 0)
    {
        fb->credits_flash--;
        fb->credits -= 0.5; // Flash deduction
        vault_log(LOG_WARN, "[%s] Flash deduction: -0.5 credits for file '%s' in vault '%s' (flash_credits left: %d)", v->name,
                  evname, v->name, fb->credits_flash);
        if (fb->credits < 0.0)
            fb->credits = 0.0;
    }
}

/*
 * [FIX-7] suspect_access() era chamada mas nunca existia em nenhum arquivo
 * do projeto — o build quebrava no link (undefined reference), e o gcc
 * silenciosamente assumia um "int" implícito, o que corromperia o
 * ponteiro FileEntry* caso alguém desligasse -Werror.
 *
 * Este stub é INTENCIONALMENTE conservador: sempre retorna NULL (nunca
 * marca como suspeito), só pra parar o crash/undefined behavior e deixar
 * o projeto linkável. A heurística real de "o que é um acesso suspeito"
 * (ex: taxa de acesso anômala, muitos arquivos diferentes em pouco tempo,
 * acesso fora do --hours configurado) ainda precisa ser escrita — é
 * decisão de produto, não algo que dá pra inventar aqui.
 */
static FileEntry *suspect_access(Vault *v, FileEntry *e, time_t now)
{
    (void)v;
    (void)e;
    (void)now;
    return NULL;
}

/* Handler: IN_ACCESS event */
static void handle_in_access_event(Vault *v, const char *evname, FileBucket *fb, time_t now)
{
    if (!v || !evname)
        return;
    if (is_sandbox_internal(evname))
    {
        vault_log(LOG_INFO, "[%s] Sandbox internal access (ignored): %s", v->name, evname);
        return;
    }
    FileEntry *e = hashmap_find(&v->hashmap, evname);
    FileEntry *sus = suspect_access(v, e, now);
    if (sus)
    {
        double credits = fb ? fb->credits : -1.0;
        vault_log(LOG_ALERT, "[%s] SUSPICIOUS ACCESS %s (credits=%.2f)", v->name, evname, credits);
        char reason[256];
        snprintf(reason, sizeof(reason), "Suspicious access: %s", evname);
        alert_trigger(v, reason);
    }
    else
    {
        double credits = fb ? fb->credits : v->bucket_credits;
        vault_log(LOG_INFO, "[%s] inotify: ACCESSED %s (Remaining credits: %.2f)", v->name, evname, credits);
    }
}

/* Handler: IN_MODIFY event */
static void handle_in_modify_event(Vault *v, const char *evname, bool is_sandbox, bool write_mode)
{
    if (!v || !evname)
        return;
    if (is_sandbox)
    {
        vault_log(LOG_INFO, "[%s] Sandbox internal write (ignored): %s", v->name, evname);
    }
    else if (!write_mode)
    {
        vault_log(LOG_ALERT, "[CRITICAL] UNAUTHORIZED WRITE detected on '%s' in vault '%s'!", evname, v->name);
        char reason[256];
        snprintf(reason, sizeof(reason), "Unauthorized write (Ransomware attempt?): %s", evname);
        alert_trigger(v, reason);
        vault_enforce_readonly(v);
    }
    else
    {
        vault_log(LOG_INFO, "[%s] Authorized modification: %s", v->name, evname);
        monitor_scan_vault(v);
    }
}

/* Per-file bucket helpers */
static FileBucket *find_file_bucket(Vault *v, const char *path)
{
    if (!v || !path)
        return NULL;
    FileBucket *fb = v->file_buckets;
    while (fb)
    {
        if (strncmp(fb->path, path, VAULT_PATH_MAX) == 0)
            return fb;
        fb = fb->next;
    }
    return NULL;
}

static FileBucket *create_file_bucket(Vault *v, const char *path)
{
    if (!v || !path)
        return NULL;
    FileBucket *fb = (FileBucket *)calloc(1, sizeof(FileBucket));
    if (!fb)
        return NULL;
    strncpy(fb->path, path, VAULT_PATH_MAX - 1);
    fb->credits = 15.0;
    fb->last_update = time(NULL);
    fb->next = v->file_buckets;
    v->file_buckets = fb;
    return fb;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 8: FILE INTEGRITY MONITOR
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Enforces read-only permissions (0400) on all files in the vault */
void vault_enforce_readonly(Vault *v)
{
    if (v->status == VAULT_STATUS_DELETED)
        return;
#ifdef __linux__
    DIR *dir = opendir(v->path);
    if (!dir)
        return;

    struct dirent *de;
    char filepath[VAULT_PATH_MAX + NAME_MAX + 2];
    while ((de = readdir(dir)) != NULL)
    {
        if (de->d_name[0] == '.')
            continue;
        snprintf(filepath, sizeof(filepath), "%s/%s", v->path, de->d_name);
        chmod(filepath, 0400); // Read-only for owner, none for others
    }
    closedir(dir);
    v->write_mode = false;
    vault_log(LOG_INFO, "[PROTECTION] Vault '%s' set to READ-ONLY mode", v->name);
#endif
}

/* Enables/Disables write mode (0600) for authorized operations */
void vault_set_write_mode(Vault *v, bool enable)
{
    if (v->status == VAULT_STATUS_DELETED)
        return;
#ifdef __linux__
    DIR *dir = opendir(v->path);
    if (!dir)
        return;

    struct dirent *de;
    char filepath[VAULT_PATH_MAX + NAME_MAX + 2];
    while ((de = readdir(dir)) != NULL)
    {
        if (de->d_name[0] == '.')
            continue;
        snprintf(filepath, sizeof(filepath), "%s/%s", v->path, de->d_name);
        chmod(filepath, enable ? 0600 : 0400);
    }
    closedir(dir);
    v->write_mode = enable;
    vault_log(LOG_INFO, "[PROTECTION] Vault '%s' write_mode: %s", v->name, enable ? "ON" : "OFF");
#endif
}

void monitor_scan_vault(Vault *v)
{
    if (v->status == VAULT_STATUS_DELETED)
        return;

#ifdef __linux__
    DIR *dir = opendir(v->path);
    if (!dir)
    {
        vault_log(LOG_ERROR, "Cannot scan vault '%s' at '%s': %s",
                  v->name, v->path, strerror(errno));
        return;
    }

    struct dirent *de;
    char filepath[VAULT_PATH_MAX + NAME_MAX + 2];

    while ((de = readdir(dir)) != NULL)
    {
        if (de->d_name[0] == '.')
            continue;

        snprintf(filepath, sizeof(filepath), "%s/%s", v->path, de->d_name);

        struct stat st;
        if (stat(filepath, &st) != 0)
            continue;
        if (!S_ISREG(st.st_mode))
            continue;

        char new_hash[HASH_HEX_LEN];
        if (sha256_file(filepath, new_hash) != ERR_OK)
            continue;

        FileEntry *e = hashmap_find(&v->hashmap, de->d_name);

        if (!e)
        {
            e = hashmap_insert(&v->hashmap, de->d_name);
            if (e)
            {
                memcpy(e->hash, new_hash, HASH_HEX_LEN);
                e->last_seen = time(NULL);
                e->modified = false;
                vault_log(LOG_INFO, "[%s] New file registered: %s", v->name, de->d_name);
            }
        }
        else
        {
            if (CRYPTO_memcmp(e->hash, new_hash, HASH_HEX_LEN) != 0)
            {
                if (!e->modified)
                {
                    e->modified = true;
                    vault_log(LOG_ALERT, "[%s] File MODIFIED: %s", v->name, de->d_name);
                    char reason[256];
                    snprintf(reason, sizeof(reason), "File modified: %s", de->d_name);
                    alert_trigger(v, reason);
                }
                memcpy(e->hash, new_hash, HASH_HEX_LEN);
            }
            else
            {
                e->modified = false;
            }
            e->last_seen = time(NULL);
        }
    }

    closedir(dir);
#endif /* __linux__ */

    v->last_check = time(NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 9: ALERT SYSTEM
 * ═══════════════════════════════════════════════════════════════════════════ */

void alert_trigger(Vault *v, const char *reason)
{
    time_t now = time(NULL);

    if (v->alert.first_triggered == 0)
    {
        v->alert.first_triggered = now;
        v->alert.interval_idx = 0;
    }

    strncpy(v->alert.reason, reason, 255);
    v->alert.reason[255] = '\0';
    v->status = VAULT_STATUS_ALERT;

    vault_log(LOG_ALERT, "ALERT [vault=%s id=%u]: %s", v->name, v->id, reason);
    catalog_save();
}

void alert_check_escalation(Vault *v)
{
    if (v->status != VAULT_STATUS_ALERT)
        return;

    time_t now = time(NULL);

    if (v->alert.last_alerted == 0)
    {
        vault_log(LOG_ALERT, "REPEAT ALERT [%s] (count=%zu): %s",
                  v->name, ++v->alert.alert_count, v->alert.reason);
        fprintf(stderr, "\n  *** VAULT ALERT *** [%s] %s\n\n", v->name, v->alert.reason);
        v->alert.last_alerted = now;
        return;
    }

    long interval = (v->alert.interval_idx < NUM_ALERT_INTERVALS)
                        ? ALERT_INTERVALS[v->alert.interval_idx]
                        : ALERT_INTERVALS[NUM_ALERT_INTERVALS - 1];

    if (now - v->alert.last_alerted >= interval)
    {
        v->alert.alert_count++;
        vault_log(LOG_ALERT, "REPEAT ALERT [%s] (count=%zu, interval=%lds): %s",
                  v->name, v->alert.alert_count, interval, v->alert.reason);
        fprintf(stderr, "\n  *** VAULT ALERT (x%zu) *** [%s] %s\n\n",
                v->alert.alert_count, v->name, v->alert.reason);

        v->alert.last_alerted = now;
        if (v->alert.interval_idx < NUM_ALERT_INTERVALS - 1)
            v->alert.interval_idx++;
    }
}

VaultErrorr alert_resolve(uint32_t id, const char *password)
{
    Vault *v = vault_find_by_id(id);
    if (!v)
        return ERR_VAULT_NOT_FOUND;

    if (v->type == VAULT_TYPE_PROTECTED)
    {
        if (!password || !*password)
            return ERR_PASS_REQUIRED;
        VaultErrorr err = auth_verify_password(v, password);
        if (err != ERR_OK)
            return err;
    }

    /* Clear modified flags */
    for (int b = 0; b < HASHMAP_BUCKETS; b++)
        // [FIX-5] Limpa a flag modified de todas as entradas do hashmap, não apenas das modificadas.
        for (FileEntry *e = v->hashmap.buckets[b]; e; e = e->next)
            e->modified = false;
    // [FIX-5] Reseta o estado de alerta e escalonamento, não apenas a razão.
    memset(&v->alert, 0, sizeof(v->alert));
    v->status = VAULT_STATUS_OK;
    vault_enforce_readonly(v);
    // [FIX-5] Log de resolução de alerta, incluindo o motivo original.
    vault_log(LOG_AUDIT, "Alert RESOLVED for vault '%s' (id=%u)", v->name, v->id);
    return catalog_save();
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 10: RULE ENGINE
 * ═══════════════════════════════════════════════════════════════════════════ */

void rule_add(uint32_t vault_id, int max_fails, int hour_from, int hour_to)
{
    if (g_rule_count >= MAX_RULES)
        return;

    VaultRule *r = &g_rules[g_rule_count++];
    r->vault_id             = vault_id;
    r->max_failed_attempts  = max_fails;
    r->allowed_hour_from    = hour_from;
    r->allowed_hour_to      = hour_to;
}

void rule_evaluate(Vault *v)
{
    if (!v)
        return;

    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    int hour = tm_now ? tm_now->tm_hour : -1;

    for (uint32_t i = 0; i < g_rule_count; i++)
    {
        VaultRule *r = &g_rules[i];

        if (r->vault_id != v->id)
            continue;

        /* Check max failed attempts */
        if (r->max_failed_attempts > 0 &&
            v->failed_attempts >= r->max_failed_attempts)
        {
            alert_trigger(v, "Max failed login attempts exceeded (rule)");
            return;
        }

        /* Check time-window restriction */
        if (r->allowed_hour_from >= 0 && r->allowed_hour_to >= 0 && hour >= 0)
        {
            int in_window;
            if (r->allowed_hour_from <= r->allowed_hour_to)
                in_window = (hour >= r->allowed_hour_from && hour <= r->allowed_hour_to);
            else
                /* Overnight window e.g. 22-06 */
                in_window = (hour >= r->allowed_hour_from || hour <= r->allowed_hour_to);

            if (!in_window)
            {
                alert_trigger(v, "Access outside allowed time window (rule)");
                return;
            }
        }
    }
}

#ifdef __linux__

void monitor_add_vault_watches(MonitorCtx *ctx)
{
    if (ctx->fanotify_fd < 0)
        return;
    for (uint32_t i = 0; i < ctx->catalog->count; i++)
    {
        Vault *v = &ctx->catalog->vaults[i];
        if (v->status == VAULT_STATUS_DELETED)
            continue;
        if (v->fanotify_wd >= 0)
            continue;
        
        /* Skip fanotify marks if vault is mounted via FUSE (FUSE already handles WORM) */
        if (v->is_mounted)
            continue;

        /* FAN_MARK_FILESYSTEM requires CAP_SYS_ADMIN. Fallback to just watching the dir */
        int ret = fanotify_mark(
            ctx->fanotify_fd,
            FAN_MARK_ADD,
            FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_ONDIR,
            AT_FDCWD,
            v->cipher_path);

        if (ret < 0) {
            /* Downgrade to LOG_INFO, missing fanotify is not critical as FUSE provides protection */
            vault_log(LOG_INFO, "fanotify_mark skip '%s': %s (requires privileges)", v->cipher_path, strerror(errno));
            v->fanotify_wd = -1; /* mark failed */
        }
        else
        {
            v->fanotify_wd = 1; /* Mark added */
            vault_log(LOG_INFO, "fanotify active passive protection for cipherdir '%s'", v->cipher_path);
        }
    }
}

static Vault *monitor_vault_by_path(MonitorCtx *ctx, const char *path)
{
    for (uint32_t i = 0; i < ctx->catalog->count; i++)
    {
        Vault *v = &ctx->catalog->vaults[i];
        if (v->status == VAULT_STATUS_DELETED)
            continue;
        /* Simple prefix check */
        if (strlen(v->cipher_path) > 0 && strncmp(path, v->cipher_path, strlen(v->cipher_path)) == 0)
            return v;
    }
    return NULL;
}

void *monitor_thread(void *arg)
{
    MonitorCtx *ctx = (MonitorCtx *)arg;
    char buf[4096] __attribute__((aligned(8)));

    vault_log(LOG_INFO, "Monitor thread started (fanotify fd=%d)", ctx->fanotify_fd);

    /* Initial scan */
    pthread_mutex_lock(&ctx->lock);
    monitor_add_vault_watches(ctx);
    for (uint32_t i = 0; i < ctx->catalog->count; i++)
        monitor_scan_vault(&ctx->catalog->vaults[i]);
    pthread_mutex_unlock(&ctx->lock);

    while (ctx->running && ctx->fanotify_fd >= 0)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx->fanotify_fd, &rfds);
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};

        int ret = select(ctx->fanotify_fd + 1, &rfds, NULL, NULL, &tv);

        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            vault_log(LOG_ERROR, "monitor select(): %s", strerror(errno));
            break;
        }

        pthread_mutex_lock(&ctx->lock);

        if (ret > 0 && FD_ISSET(ctx->fanotify_fd, &rfds))
        {
            ssize_t len = read(ctx->fanotify_fd, buf, sizeof(buf));
            if (len < 0)
            {
                if (errno != EAGAIN)
                    vault_log(LOG_ERROR, "fanotify read: %s", strerror(errno));
            }
            else
            {
                const struct fanotify_event_metadata *metadata;
                metadata = (struct fanotify_event_metadata *)buf;

                while (FAN_EVENT_OK(metadata, len))
                {
                    if (metadata->vers != FANOTIFY_METADATA_VERSION)
                    {
                        vault_log(LOG_ERROR, "Mismatch of fanotify metadata version");
                        break;
                    }

                    if (metadata->fd >= 0)
                    {
                        char path[VAULT_PATH_MAX];
                        char procfd[32];
                        snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", metadata->fd);
                        ssize_t path_len = readlink(procfd, path, sizeof(path) - 1);
                        if (path_len > 0)
                        {
                            path[path_len] = '\0';
                        }
                        else
                        { 
                            /*
                            * Replaced strcpy with strncpy: 
                            * focusing on resolving the leakage issue, 
                            * memory was not checked to the end.
                            */
                            strncpy(path, "(unknown)", sizeof(path));
                            path[sizeof(path) - 1] = '\0';
                        }

                        Vault *v = monitor_vault_by_path(ctx, path);

                        if (metadata->mask & FAN_ACCESS)
                        {
                            if (v) vault_log(LOG_AUDIT, "Passive Scan: ACCESS on '%s' (PID: %d)", path, metadata->pid);
                        }
                        if (metadata->mask & FAN_MODIFY)
                        {
                            if (v) vault_log(LOG_AUDIT, "Passive Scan: MODIFY on '%s' (PID: %d)", path, metadata->pid);
                        }
                        if (metadata->mask & FAN_CLOSE_WRITE)
                        {
                            if (v) vault_log(LOG_AUDIT, "Passive Scan: CLOSE_WRITE on '%s' (PID: %d)", path, metadata->pid);
                        }
                        

                        close(metadata->fd);
                    }
                    metadata = FAN_EVENT_NEXT(metadata, len);
                }
            }
        }

        /* Periodic alert escalation check
        * este alerta foi implementado depois das versões 1.0 
        mas não é tão util para maioria dos casos 
        */
        for (uint32_t i = 0; i < ctx->catalog->count; i++)
            alert_check_escalation(&ctx->catalog->vaults[i]);

        /* Re-add watches for new vaults */
        monitor_add_vault_watches(ctx);

        pthread_mutex_unlock(&ctx->lock);
    }

    vault_log(LOG_INFO, "Monitor thread stopped");
    return NULL;
}

#endif /* __linux__ */