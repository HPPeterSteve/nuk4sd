/*
 * vault_catalog.c
 *
 * VAULT SECURITY SYSTEM — Catalog & Vault Manager
 * Sections 5, 6, 7 from legacy monolith
 *
 * Contains:
 *   - FileHashMap operations
 *   - Binary catalog serialisation (VLTS format)
 *   - Vault CRUD (create, delete, rename, unlock, change_password)
 *   - Global state definitions
 *
 * Author: Peter Steve (architecture)
 * Split: 2026-05-13
 */

#include "vault_core.h"

/* ─────────────────────────────────────────────
 *  GLOBALS (defined here, extern'd in vault_core.h)
 * ───────────────────────────────────────────── */
Catalog g_catalog;
MonitorCtx g_monitor;
FILE *g_logfp = NULL;
bool g_verbose = false;
VaultRule g_rules[MAX_RULES];
uint32_t g_rule_count = 0;
volatile bool g_running = true;

/* Dynamic paths */
char g_catalog_path[VAULT_PATH_MAX];
char g_catalog_file[VAULT_PATH_MAX];
char g_log_file[VAULT_PATH_MAX];
char g_lock_file[VAULT_PATH_MAX];

/* Cria todos os diretórios do caminho (equivalente a `mkdir -p`).
 * Necessário porque mkdir() simples falha com ENOENT se QUALQUER
 * diretório pai estiver faltando (ex: ~/.local não existe ainda). */
static int mkdir_p(const char *path) {
    char tmp[VAULT_PATH_MAX];
    size_t len = snprintf(tmp, sizeof(tmp), "%s", path);
    if (len == 0 || len >= sizeof(tmp)) return -1;

    /* remove trailing slash, se houver */
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

/* Resolve paths based on $HOME and migrate legacy catalog if needed */
void resolve_paths(void) {
    const char *home = getenv("HOME");
    if (!home) {
        home = "/root"; /* Fallback */
    }

    snprintf(g_catalog_path, sizeof(g_catalog_path), "%s/.local/share/Nuk4sd", home);
    snprintf(g_catalog_file, sizeof(g_catalog_file), "%s/.local/share/Nuk4sd/catalog.dat", home);
    snprintf(g_log_file, sizeof(g_log_file), "%s/.local/share/Nuk4sd/vault_security.log", home);
    snprintf(g_lock_file, sizeof(g_lock_file), "%s/.local/share/Nuk4sd/vault_security.pid", home);

    /* Create dir if it doesn't exist (cria toda a árvore, incluindo ~/.local) */
    struct stat st;
    if (stat(g_catalog_path, &st) != 0) {
        if (mkdir_p(g_catalog_path) != 0) {
            vault_log(LOG_ERROR, "Falha ao criar diretório do catálogo '%s': %s",
                      g_catalog_path, strerror(errno));
        }
    }

    /* Auto-migrate from legacy root path if user-space catalog doesn't exist yet */
    const char *legacy_catalog = "/var/lib/vault_security/catalog.dat";
    if (stat(g_catalog_file, &st) != 0 && stat(legacy_catalog, &st) == 0) {
        vault_log(LOG_INFO, "Migrando catalog.dat legado de %s para %s", legacy_catalog, g_catalog_file);
        
        FILE *src = fopen(legacy_catalog, "rb");
        if (src) {
            FILE *dst = fopen(g_catalog_file, "wb");
            if (dst) {
                char buf[8192];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
                    fwrite(buf, 1, n, dst);
                }
                fclose(dst);
                chmod(g_catalog_file, 0600);
                /* substituindo antigo vault-log que não mostrava argumento nenhum*/
                char msg[9];
                snprintf(msg, sizeof(msg), "Detalhes: %d", src, dst);
                vault_log(LOG_INFO, msg);
                
            } else {
                vault_log(LOG_ERROR, "Falha ao criar o novo catalog.dat em %s", g_catalog_file);
            }
            fclose(src);

        } else {
            int saved_errno = errno;  /* captura antes que outra chamada mude errno */
            if (saved_errno == EACCES || saved_errno == EPERM || saved_errno == ENOENT || saved_errno == EISDIR || saved_errno == EROFS) {
                vault_log(LOG_WARN, "Sem permissão para ler catalog.dat legado em '%s': %s",
                    legacy_catalog, strerror(saved_errno));
            } else {
                vault_log(LOG_WARN, "Não foi possível abrir catalog.dat legado em '%s': %s",
                    legacy_catalog, strerror(saved_errno));
            }
        }
    }
}

/*
  *  SECTION 5: FILE HASH MAP
 * */

uint32_t hashmap_bucket(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s)
    {
        h ^= (uint8_t)*s++;
        h *= 16777619u;
    }
    return h % HASHMAP_BUCKETS;
}

FileEntry *hashmap_find(FileHashMap *m, const char *filename)
{
    uint32_t b = hashmap_bucket(filename);
    for (FileEntry *e = m->buckets[b]; e; e = e->next)
        if (strcmp(e->filename, filename) == 0)
            return e;
    return NULL;
}

FileEntry *hashmap_insert(FileHashMap *m, const char *filename)
{
    uint32_t b = hashmap_bucket(filename);
    FileEntry *e = hashmap_find(m, filename);
    if (e)
        return e;

    e = calloc(1, sizeof(FileEntry));
    if (!e)
        return NULL;

    strncpy(e->filename, filename, NAME_MAX);
    e->filename[NAME_MAX] = '\0';
    e->next = m->buckets[b];
    m->buckets[b] = e;
    m->count++;
    return e;
}

void hashmap_clear(FileHashMap *m)
{
    for (int i = 0; i < HASHMAP_BUCKETS; i++)
    {
        FileEntry *e = m->buckets[i];
        while (e)
        {
            FileEntry *next = e->next;
            free(e);
            e = next;
        }
        m->buckets[i] = NULL;
    }
    m->count = 0;
}

/*
  *  SECTION 6: CATALOG SERIALISATION
 * */

VaultErrorr catalog_save(void)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", VAULT_CATALOG_FILE);

    FILE *fp = fopen(tmp, "wb");
    if (!fp)
    {
        vault_log(LOG_ERROR, "catalog_save: cannot open %s: %s", tmp, strerror(errno));
        return ERR_IO;
    }

    /* Header */
    fwrite(CATALOG_MAGIC, 1, 4, fp);
    uint8_t ver = CATALOG_VER;
    fwrite(&ver, 1, 1, fp);
    fwrite(&g_catalog.count, 4, 1, fp);
    fwrite(&g_catalog.next_id, 4, 1, fp);
    fwrite(g_catalog.category, 1, 32, fp);

    for (uint32_t i = 0; i < g_catalog.count; i++)
    {
        Vault *v = &g_catalog.vaults[i];

        fwrite(&v->id, sizeof(v->id), 1, fp);
        fwrite(v->name, VAULT_NAME_MAX, 1, fp);
        fwrite(&v->type, sizeof(v->type), 1, fp);
        fwrite(&v->status, sizeof(v->status), 1, fp);
        uint8_t hp = v->has_pass ? 1 : 0;
        fwrite(&hp, 1, 1, fp);
        fwrite(v->path, VAULT_PATH_MAX, 1, fp);
        fwrite(v->cipher_path, VAULT_PATH_MAX, 1, fp);
        fwrite(&v->created_at, sizeof(v->created_at), 1, fp);
        fwrite(&v->last_check, sizeof(v->last_check), 1, fp);
        fwrite(&v->failed_attempts, sizeof(v->failed_attempts), 1, fp);

        fwrite(&v->alert.interval_idx, sizeof(size_t), 1, fp);
        fwrite(&v->alert.first_triggered, sizeof(time_t), 1, fp);
        fwrite(&v->alert.last_alerted, sizeof(time_t), 1, fp);
        fwrite(&v->alert.alert_count, sizeof(size_t), 1, fp);
        fwrite(v->alert.reason, 256, 1, fp);

        fwrite(v->salt, SALT_LEN, 1, fp);
        fwrite(v->pass_hash, SHA256_DIGEST_LENGTH, 1, fp);

        /* v2: WORM protection flags — persisted so flags survive process restarts */
        fwrite(&v->worm_flags, sizeof(v->worm_flags), 1, fp);

        /* File entries */
        uint32_t fcount = (uint32_t)v->hashmap.count;
        if (fcount > FCOUNT_MAX)
        {
            fcount = FCOUNT_MAX;
        }
        uint32_t written = 0;

        fwrite(&fcount, sizeof(fcount), 1, fp);

        for (int b = 0; b < HASHMAP_BUCKETS && written < fcount; b++)
        {
            for (FileEntry *e = v->hashmap.buckets[b]; e && written < fcount; e = e->next)
            {
                fwrite(e->filename, NAME_MAX + 1, 1, fp);
                fwrite(e->hash, HASH_HEX_LEN, 1, fp);
                fwrite(&e->last_seen, sizeof(time_t), 1, fp);
                uint8_t mod = e->modified ? 1 : 0;
                fwrite(&mod, 1, 1, fp);
                written++;
            }
        }
    }

    fclose(fp);

    /* Atomic rename */
    if (rename(tmp, VAULT_CATALOG_FILE) != 0)
    {
        vault_log(LOG_ERROR, "catalog_save: rename failed: %s", strerror(errno));
        unlink(tmp);
        return ERR_IO;
    }

    chmod(VAULT_CATALOG_FILE, 0600);
    vault_log(LOG_INFO, "Catalog saved (%u vaults)", g_catalog.count);
    return ERR_OK;
}

VaultErrorr catalog_load(void)
{
    FILE *fp = fopen(VAULT_CATALOG_FILE, "rb");
    if (!fp)
    {
        if (errno == ENOENT)
        {
            vault_log(LOG_INFO, "No catalog found, starting fresh");
            strncpy(g_catalog.category, "Nuk4sd", 31);
            g_catalog.next_id = 1;
            return ERR_OK;
        }
        vault_log(LOG_ERROR, "catalog_load: %s", strerror(errno));
        return ERR_IO;
    }

    char magic[5] = {0};
    if (fread(magic, 1, 4, fp) != 4 || CRYPTO_memcmp(magic, CATALOG_MAGIC, 4) != 0)
    {
        fclose(fp);
        vault_log(LOG_ERROR, "Catalog file corrupt or wrong format");
        return ERR_IO;
    }

    uint8_t ver;
    if (fread(&ver, 1, 1, fp) != 1)
    {
        fclose(fp);
        vault_log(LOG_ERROR, "catalog_load: failed to read version byte");
        return ERR_IO;
    }
    if (ver != CATALOG_VER)
    {
        fclose(fp);
        vault_log(LOG_WARN,
                  "catalog_load: version mismatch (file=%d expected=%d). "
                  "Starting fresh — old catalog archived to catalog.dat.v%d.bak.",
                  ver, CATALOG_VER, ver);
        /* Archive the old catalog so the user does not lose data. */
        char bak[VAULT_PATH_MAX];
        snprintf(bak, sizeof(bak), "%s.v%d.bak", VAULT_CATALOG_FILE, ver);
        rename(VAULT_CATALOG_FILE, bak);
        strncpy(g_catalog.category, "Nuk4sd", 31);
        g_catalog.next_id = 1;
        return ERR_OK;
    }

#define FREAD_CHECK(dst, sz, fp)                                                               \
    do                                                                                         \
    {                                                                                          \
        if (fread(dst, sz, 1, fp) != 1)                                                        \
        {                                                                                      \
            vault_log(LOG_ERROR, "catalog_load: truncated read at %s:%d", __FILE__, __LINE__); \
            fclose(fp);                                                                        \
            return ERR_IO;                                                                     \
        }                                                                                      \
    } while (0)

    FREAD_CHECK(&g_catalog.count, 4, fp);
    FREAD_CHECK(&g_catalog.next_id, 4, fp);
    FREAD_CHECK(g_catalog.category, 32, fp);

    if (g_catalog.count > MAX_VAULTS)
    {
        fclose(fp);
        vault_log(LOG_ERROR, "Catalog claims %u vaults (max %d)", g_catalog.count, MAX_VAULTS);
        return ERR_IO;
    }

    for (uint32_t i = 0; i < g_catalog.count; i++)
    {
        Vault *v = &g_catalog.vaults[i];
        memset(v, 0, sizeof(Vault));

        FREAD_CHECK(&v->id, sizeof(v->id), fp);
        FREAD_CHECK(v->name, VAULT_NAME_MAX, fp);
        FREAD_CHECK(&v->type, sizeof(v->type), fp);
        FREAD_CHECK(&v->status, sizeof(v->status), fp);
        uint8_t hp;
        FREAD_CHECK(&hp, 1, fp);
        v->has_pass = (hp != 0);
        FREAD_CHECK(v->path, VAULT_PATH_MAX, fp);
        FREAD_CHECK(v->cipher_path, VAULT_PATH_MAX, fp);
        FREAD_CHECK(&v->created_at, sizeof(v->created_at), fp);
        FREAD_CHECK(&v->last_check, sizeof(v->last_check), fp);
        FREAD_CHECK(&v->failed_attempts, sizeof(v->failed_attempts), fp);
        FREAD_CHECK(&v->alert.interval_idx, sizeof(size_t), fp);
        FREAD_CHECK(&v->alert.first_triggered, sizeof(time_t), fp);
        FREAD_CHECK(&v->alert.last_alerted, sizeof(time_t), fp);
        FREAD_CHECK(&v->alert.alert_count, sizeof(size_t), fp);
        FREAD_CHECK(v->alert.reason, 256, fp);
        FREAD_CHECK(v->salt, SALT_LEN, fp);
        FREAD_CHECK(v->pass_hash, SHA256_DIGEST_LENGTH, fp);

        /* v2: WORM flags — restore exactly the bits that were persisted */
        FREAD_CHECK(&v->worm_flags, sizeof(v->worm_flags), fp);

        uint32_t fcount;
        FREAD_CHECK(&fcount, 4, fp);
        if (fcount > MAX_FILES_PER_VAULT)
        {
            vault_log(LOG_ERROR, "catalog_load: invalid fcount: %u", fcount);
            fclose(fp);
            return ERR_IO;
        }

        for (uint32_t f = 0; f < fcount; f++)
        {
            char fname[NAME_MAX + 1];
            char fhash[HASH_HEX_LEN];
            time_t ls;
            uint8_t mod;

            FREAD_CHECK(fname, NAME_MAX + 1, fp);
            FREAD_CHECK(fhash, HASH_HEX_LEN, fp);
            FREAD_CHECK(&ls, sizeof(time_t), fp);
            FREAD_CHECK(&mod, 1, fp);

            FileEntry *e = hashmap_insert(&v->hashmap, fname);
            if (e)
            {
                memcpy(e->hash, fhash, HASH_HEX_LEN);
                e->last_seen = ls;
                e->modified = (mod != 0);
            }
        }

        v->fanotify_wd = -1;
    }

#undef FREAD_CHECK

    fclose(fp);
    vault_log(LOG_INFO, "Catalog loaded: %u vaults (category: %s)",
              g_catalog.count, g_catalog.category);
    return ERR_OK;
}

/*
  *  SECTION 7: VAULT MANAGER
 * */

Vault *vault_find_by_id(uint32_t id)
{
    for (uint32_t i = 0; i < g_catalog.count; i++)
        if (g_catalog.vaults[i].id == id)
            return &g_catalog.vaults[i];
    return NULL;
}

Vault *vault_find_by_name(const char *name)
{
    for (uint32_t i = 0; i < g_catalog.count; i++)
        if (strcmp(g_catalog.vaults[i].name, name) == 0)
            return &g_catalog.vaults[i];
    return NULL;
}

/* Auto-increment naming: Nuk4sd_N */
static void vault_auto_name(char *out, size_t outsz)
{
    uint32_t n = 1;
    char candidate[VAULT_NAME_MAX];
    do
    {
        snprintf(candidate, sizeof(candidate), "Nuk4sd_%u", n++);
    } while (vault_find_by_name(candidate) != NULL);
    strncpy(out, candidate, outsz - 1);
    out[outsz - 1] = '\0';
}

VaultErrorr vault_create(const char *name_arg, VaultType type,
                        const char *path_arg, const char *password)
{
    if (g_catalog.count >= MAX_VAULTS)
        return ERR_CATALOG_FULL;

    char name_buf[VAULT_NAME_MAX];
    char path_buf[VAULT_PATH_MAX];

    if (name_arg && *name_arg)
    {
        char *n = sanitize_arg((char *)name_arg);
        if (strlen(n) >= VAULT_NAME_MAX)
        {
            vault_log(LOG_ERROR, "Vault name too long (max %d chars)", VAULT_NAME_MAX - 1);
            return ERR_INVALID_ARGS;
        }
        snprintf(name_buf, sizeof(name_buf), "%s", n);
    }
    else
    {
        vault_auto_name(name_buf, sizeof(name_buf));
        vault_log(LOG_INFO, "No name given, using auto-name: %s", name_buf);
    }

    VaultErrorr err;
    err = validate_name(name_buf);
    if (err != ERR_OK)
        return err;

    if (vault_find_by_name(name_buf))
    {
        vault_log(LOG_ERROR, "Vault '%s' already exists", name_buf);
        return ERR_VAULT_EXISTS;
    }

    if (path_arg && *path_arg)
    {
        char *p = sanitize_arg((char *)path_arg);
        snprintf(path_buf, sizeof(path_buf), "%s", p);
        err = validate_path(path_buf);
        if (err != ERR_OK)
            return err;
    }
    else
    {
        snprintf(path_buf, sizeof(path_buf), "%s/%s", VAULT_CATALOG_PATH, name_buf);
    }

    if (type == VAULT_TYPE_PROTECTED && (!password || !*password))
    {
        vault_log(LOG_ERROR, "Protected vault requires a password");
        return ERR_PASS_REQUIRED;
    }

    /* Create virtual mount directory */
    if (mkdir(path_buf, 0700) != 0 && errno != EEXIST)
    {
        vault_log(LOG_ERROR, "mkdir '%s' failed: %s", path_buf, strerror(errno));
        return ERR_IO;
    }

    Vault *v = &g_catalog.vaults[g_catalog.count];
    memset(v, 0, sizeof(Vault));

    v->id = g_catalog.next_id++;
    v->type = type;
    v->status = VAULT_STATUS_OK;
    v->created_at = time(NULL);
    v->last_check = v->created_at;
    v->fanotify_wd = -1; /* used to be inotify_wd */
    v->is_mounted = false;

    strncpy(v->name, name_buf, VAULT_NAME_MAX - 1);
    strncpy(v->path, path_buf, VAULT_PATH_MAX - 1);
    vault_log(LOG_INFO, "Vault '%s' created at %s", v->name, path_buf);

    /* Setup cipher path */
    snprintf(v->cipher_path, VAULT_PATH_MAX, "%s/cipher_%u", VAULT_CATALOG_PATH, v->id);
    if (mkdir(v->cipher_path, 0700) != 0 && errno != EEXIST)
    {
        vault_log(LOG_ERROR, "mkdir cipher '%s' failed: %s", v->cipher_path, strerror(errno));
        return ERR_IO;
    }

    if (type == VAULT_TYPE_PROTECTED)
    {
        err = auth_set_password(v, password);
        if (err != ERR_OK)
            return err;
        
        if (geteuid() == 0) {
            vault_log(LOG_INFO, "Applying root protections to protected vault.");
            /* We can enforce chattr or other things here in the future */
        } else {
            vault_log(LOG_WARN, "Protected vault created without root privileges. Full cipherdir protection degraded.");
        }
    }

    g_catalog.count++;
    vault_enforce_readonly(v); // Start protected
    err = catalog_save();

    /* ── PHYSICAL LOCK: seal the cipher directory from the OS immediately ── */
    if (chmod(v->cipher_path, 0000) != 0) {
        vault_log(LOG_WARN,
                  "[PHYSICAL_LOCK] WARNING: chmod 0000 FAILED on cipher_dir='%s': errno=%d (%s). "
                  "Physical isolation NOT enforced. Data may be accessible at OS level.",
                  v->cipher_path, errno, strerror(errno));
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        vault_log(LOG_AUDIT,
                  "[PHYSICAL_LOCK] SEALED │ cipher_dir='%s' │ vault_id=%u │ name='%s' │ "
                  "mode: 0700 → 0000 (immutable, no OS access) │ uid=%d │ ts=%ld.%09ld │ "
                  "State: FULLY ISOLATED. Only Nuk4sd daemon can unlock via FUSE or export.",
                  v->cipher_path, v->id, v->name,
                  (int)getuid(), (long)ts.tv_sec, ts.tv_nsec);
    }

    vault_log(LOG_AUDIT, "Vault CREATED: id=%u name='%s' type=%s path='%s' cipher='%s'",
              v->id, v->name,
              type == VAULT_TYPE_PROTECTED ? "PROTECTED" : "NORMAL",
              v->path, v->cipher_path);

    vault_log(LOG_INFO, "Vault created successfully: ID=%u, Name=%s, Path=%s", v->id, v->name, v->path);

    return err;
}

VaultErrorr vault_delete(uint32_t id, const char *password)
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

    vault_log(LOG_AUDIT, "Vault DELETED: id=%u name='%s'", v->id, v->name);

    /* Clear sensitive data before removal */
    explicit_bzero(v->salt, SALT_LEN);
    explicit_bzero(v->pass_hash, SHA256_DIGEST_LENGTH);
    hashmap_clear(&v->hashmap);

    /* Compact array */
    uint32_t idx = (uint32_t)(v - g_catalog.vaults);
    memmove(&g_catalog.vaults[idx],
            &g_catalog.vaults[idx + 1],
            (g_catalog.count - idx - 1) * sizeof(Vault));
    g_catalog.count--;

    return catalog_save();
}

VaultErrorr vault_rename(uint32_t id, const char *new_name, const char *password)
{
    Vault *v = vault_find_by_id(id);
    if (!v)
        return ERR_VAULT_NOT_FOUND;

    char *n = sanitize_arg((char *)new_name);
    if (strlen(n) >= VAULT_NAME_MAX)
    {
        vault_log(LOG_ERROR, "Vault name too long (max %d chars)", VAULT_NAME_MAX - 1);
        return ERR_INVALID_ARGS;
    }
    VaultErrorr err = validate_name(n);
    if (err != ERR_OK)
        return err;

    if (vault_find_by_name(n))
    {
        vault_log(LOG_ERROR, "Vault name '%s' already in use", n);
        return ERR_VAULT_EXISTS;
    }

    if (v->type == VAULT_TYPE_PROTECTED)
    {
        if (!password || !*password)
            return ERR_PASS_REQUIRED;
        err = auth_verify_password(v, password);
        if (err != ERR_OK)
            return err;
    }

    vault_log(LOG_AUDIT, "Vault RENAMED: id=%u '%s' -> '%s'", v->id, v->name, n);
    strncpy(v->name, n, VAULT_NAME_MAX - 1);
    return catalog_save();
}

VaultErrorr vault_unlock(uint32_t id, const char *password)
{
    Vault *v = vault_find_by_id(id);
    if (!v)
        return ERR_VAULT_NOT_FOUND;
    if (v->status != VAULT_STATUS_LOCKED)
    {
        printf("Vault '%s' is not locked.\n", v->name);
        return ERR_OK;
    }
    if (!password || !*password)
        return ERR_PASS_REQUIRED;

    VaultErrorr err = auth_verify_password(v, password);
    if (err != ERR_OK)
    {
        vault_log(LOG_ALERT, "Unlock attempt failed for locked vault '%s'", v->name);
        return err;
    }

    v->status = VAULT_STATUS_OK;
    v->failed_attempts = 0;
    vault_log(LOG_AUDIT, "Vault UNLOCKED: id=%u name='%s'", v->id, v->name);
    return catalog_save();
}

VaultErrorr vault_change_password(uint32_t id, const char *old_pass,
                                 const char *new_pass)
{
    Vault *v = vault_find_by_id(id);
    if (!v)
        return ERR_VAULT_NOT_FOUND;
    if (!v->has_pass)
    {
        vault_log(LOG_ERROR, "Vault '%s' has no password to change", v->name);
        return ERR_PASS_REQUIRED;
    }

    VaultErrorr err = auth_verify_password(v, old_pass);
    if (err != ERR_OK)
        return err;

    err = auth_set_password(v, new_pass);
    if (err != ERR_OK)
        return err;

    vault_log(LOG_AUDIT, "Password CHANGED for vault '%s'", v->name);
    return catalog_save();
}