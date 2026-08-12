/*
 * vault_crypto.c
 *
 * VAULT SECURITY SYSTEM — Cryptography, Logging, Sanitisation
 * Sections 1-4 from legacy monolith
 *
 * Contains:
 *   - Logging (vault_log, log_init)
 *   - Errorr handling (vault_strerror)
 *   - Argument sanitisation (sanitize_arg, validate_path, validate_name)
 *   - SHA-256 (buffer & file)
 *   - PBKDF2-HMAC-SHA256 key derivation
 *   - Password auth (set, verify)
 *   - AES-256-GCM encrypt/decrypt
 *
 * Author: Peter Steve (architecture)
 * Split: 2026-05-13
 */

#include "vault_core.h"

/* ═══════════════════════════════════════════════════════════════════════════
/* ═══════════════════════════════════════════════════════════════════════════
  *  SECTION 1: LOGGING
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char *log_level_str(LogLevel lvl)
{
    switch (lvl)
    {
    case LOG_INFO:
        return "INFO ";
    case LOG_WARN:
        return "WARN ";
    case LOG_ERROR:
        return "ERROR";
    case LOG_ALERT:
        return "ALERT";
    case LOG_AUDIT:
        return "AUDIT";
    default:
        return "?????";
    }
}

static void escape_json_string(const char *src, char *dst, size_t dst_size) {
    size_t i = 0, j = 0;
    while (src[i] && j < dst_size - 2) {
        if (src[i] == '\n') {
            if (j >= dst_size - 3) break;
            dst[j++] = '\\';
            dst[j++] = 'n';
            i++;
        } else if (src[i] == '\r') {
            if (j >= dst_size - 3) break;
            dst[j++] = '\\';
            dst[j++] = 'r';
            i++;
        } else if (src[i] == '\t') {
            if (j >= dst_size - 3) break;
            dst[j++] = '\\';
            dst[j++] = 't';
            i++;
        } else if (src[i] == '"' || src[i] == '\\') {
            if (j >= dst_size - 3) break;
            dst[j++] = '\\';
            dst[j++] = src[i++];
        } else {
            dst[j++] = src[i++];
        }
    }
    dst[j] = '\0';
}

void vault_log(LogLevel lvl, const char *fmt, ...)
{
    char timebuf[32];
    time_t now = time(NULL);
    struct tm *temp_info = gmtime(&now);
    /* Format ISO 8601 */
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", temp_info);

    char msgbuf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
    va_end(ap);

    char console_buf[2048];
    if (lvl >= LOG_WARN || g_verbose)
    {
        const char *level_str = log_level_str(lvl);
        snprintf(console_buf, sizeof(console_buf), "[%s] [%s] %s\n", timebuf, level_str, msgbuf);
        if (lvl == LOG_ALERT || lvl == LOG_ERROR) {
            fputs(console_buf, stderr);
        } else {
            fputs(console_buf, stdout);
        }
    }

    if (g_logfp)
    {
        char escaped_msg[2048];
        escape_json_string(msgbuf, escaped_msg, sizeof(escaped_msg));
        
        char json_buf[4096];
        snprintf(json_buf, sizeof(json_buf), 
                 "{\"timestamp\":\"%s\",\"level\":\"%s\",\"message\":\"%s\",\"pid\":%d}\n", 
                 timebuf, log_level_str(lvl), escaped_msg, getpid());
        fputs(json_buf, g_logfp);
        fflush(g_logfp);
    }
}

void log_init(void)
{
    g_logfp = fopen(VAULT_LOG_FILE, "a");
    if (!g_logfp)
    {
        /* Fallback: try home dir */
        char fallback[256];
        const char *home = getenv("HOME");
        if (home)
        {
            snprintf(fallback, sizeof(fallback), "%s/.vault_security.log", home);
            g_logfp = fopen(fallback, "a");
        }
        if (!g_logfp) {
            char warn_msg[] = "WARNING: cannot open log file, logging to stderr only\n";
            fputs(warn_msg, stderr);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
/* ═══════════════════════════════════════════════════════════════════════════
  *  SECTION 2: ERROR HANDLING
 * ═══════════════════════════════════════════════════════════════════════════ */

const char *vault_strerror(VaultErrorr err)
{
    switch (err)
    {
    case ERR_OK:
        return "Success";
    case ERR_INVALID_ARGS:
        return "Invalid arguments";
    case ERR_NO_MEMORY:
        return "Out of memory";
    case ERR_IO:
        return "I/O error";
    case ERR_CRYPTO:
        return "Cryptographic error";
    case ERR_AUTH_FAIL:
        return "Authentication failure";
    case ERR_VAULT_LOCKED:
        return "Vault is locked";
    case ERR_VAULT_EXISTS:
        return "Vault already exists";
    case ERR_VAULT_NOT_FOUND:
        return "Vault not found";
    case ERR_PERM_DENIED:
        return "Permission denied";
    case ERR_CATALOG_FULL:
        return "Catalog is full (max 2048 vaults)";
    case ERR_PATH_INVALID:
        return "Invalid path";
    case ERR_PASS_REQUIRED:
        return "Password required for protected vault";
    case ERR_INTEGRITY:
        return "File integrity violation";
    case ERR_SYSTEM:
        return "System error";
    default:
        return "Unknown error";
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
/* ═══════════════════════════════════════════════════════════════════════════
  *  SECTION 3: ARGUMENT & STRING SANITISATION
 * ═══════════════════════════════════════════════════════════════════════════ */

char *sanitize_arg(char *s)
{
    if (!s)
        return NULL;

    /* Trim leading whitespace */
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
        s++;

    /* Strip surrounding quotes */
    size_t len = strlen(s);
    if (len >= 2)
    {
        if ((s[0] == '"' && s[len - 1] == '"') ||
            (s[0] == '\'' && s[len - 1] == '\''))
        {
            s[len - 1] = '\0';
            s++;
            len -= 2;
        }
    }

    /* Trim trailing whitespace */
    if (len > 0)
    {
        char *end = s + len - 1;
        while (end > s && (*end == ' ' || *end == '\t' ||
                           *end == '\n' || *end == '\r'))
        {
            *end-- = '\0';
        }
    }

    return s;
}

VaultErrorr validate_path(const char *path)
{
    if (!path || path[0] == '\0')
        return ERR_PATH_INVALID;
    if (strlen(path) >= VAULT_PATH_MAX)
        return ERR_PATH_INVALID;
    /* Must be absolute */
    if (path[0] != '/')
        return ERR_PATH_INVALID;
    /* Reject path traversal */
    if (strstr(path, "/../") ||
        (strlen(path) >= 3 && strcmp(path + strlen(path) - 3, "/..") == 0))
        return ERR_PATH_INVALID;
    /* Reject control characters */
    for (const char *p = path; *p; p++)
    {
        if ((unsigned char)*p < 0x20)
        {
            vault_log(LOG_ERROR, "validate_path: control character (0x%02x) in path",
                      (unsigned char)*p);
            return ERR_PATH_INVALID;
        }
    }
    return ERR_OK;
}

VaultErrorr validate_name(const char *name)
{
    if (!name || name[0] == '\0')
        return ERR_INVALID_ARGS;
    if (strlen(name) >= VAULT_NAME_MAX)
        return ERR_INVALID_ARGS;
    for (const char *p = name; *p; p++)
    {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-'))
        {
            vault_log(LOG_ERROR, "Invalid character '%c' in vault name", *p);
            return ERR_INVALID_ARGS;
        }
    }
    return ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
/* ═══════════════════════════════════════════════════════════════════════════
  *  SECTION 4: CRYPTOGRAPHY
 * ═══════════════════════════════════════════════════════════════════════════ */

void sha256_hex(const uint8_t *data, size_t len, char out[HASH_HEX_LEN])
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[HASH_HEX_LEN - 1] = '\0';
}

VaultErrorr sha256_file(const char *path, char out[HASH_HEX_LEN])
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return ERR_IO;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        fclose(fp);
        return ERR_CRYPTO;
    }

    /* FIX: single init (was double-init in original) */
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
    {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return ERR_CRYPTO;
    }

    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        EVP_DigestUpdate(ctx, buf, n);

    if (ferror(fp))
    {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return ERR_IO;
    }

    uint8_t digest[SHA256_DIGEST_LENGTH];
    unsigned int dlen = 0;
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    if (dlen != SHA256_DIGEST_LENGTH)
    {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return ERR_CRYPTO;
    }
    EVP_MD_CTX_free(ctx);
    if (fclose(fp) != 0)
        return ERR_IO;

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[HASH_HEX_LEN - 1] = '\0';

    return ERR_OK;
}

/*
 * [FIX-6] Separação de domínio: o mesmo password+salt derivava
 * simultaneamente o pass_hash (persistido em catalog.dat) e a chave
 * AES-256 real usada em encrypt_file/decrypt_file — ou seja, a chave
 * de criptografia ficava salva em texto claro (disfarçada de "hash de
 * senha") no catálogo. Qualquer leitura de catalog.dat expunha a chave
 * sem precisar quebrar o PBKDF2.
 *
 * Agora cada finalidade usa um salt efetivo diferente (salt original +
 * label de propósito), tornando pass_hash e a chave de criptografia
 * valores independentes, mesmo com password e salt-base idênticos.
 */
VaultErrorr derive_key_for(const char *password, const uint8_t *salt,
                          const char *purpose, uint8_t key[KEY_LEN])
{
    if (!password || !salt || !purpose || !key)
        return ERR_INVALID_ARGS;

    uint8_t salted[SALT_LEN + 32];
    size_t purpose_len = strlen(purpose);
    if (purpose_len > 32)
        purpose_len = 32;

    memcpy(salted, salt, SALT_LEN);
    memcpy(salted + SALT_LEN, purpose, purpose_len);

    int rc = PKCS5_PBKDF2_HMAC(
        password, (int)strlen(password),
        salted, SALT_LEN + purpose_len,
        PBKDF2_ITER,
        EVP_sha256(),
        KEY_LEN, key);

    explicit_bzero(salted, sizeof(salted));

    if (rc != 1)
    {
        vault_log(LOG_ERROR, "PBKDF2 failed: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        return ERR_CRYPTO;
    }
    return ERR_OK;
}

/* Mantido apenas como wrapper de compatibilidade interna — sempre chama
 * derive_key_for com um propósito explícito. Nunca use isto para gerar
 * simultaneamente o hash de autenticação e a chave de criptografia. */
VaultErrorr derive_key(const char *password, const uint8_t *salt,
                      uint8_t key[KEY_LEN])
{
    return derive_key_for(password, salt, "legacy-unscoped", key);
}

VaultErrorr auth_set_password(Vault *v, const char *password)
{
    VAULT_ASSERT(v && password, ERR_INVALID_ARGS, "null vault or password");
    VAULT_ASSERT(strlen(password) >= 8, ERR_INVALID_ARGS,
                 "Password must be at least 8 characters");
    VAULT_ASSERT(strlen(password) < MAX_PASS_LEN, ERR_INVALID_ARGS,
                 "Password too long (max %d chars)", MAX_PASS_LEN - 1);

    if (RAND_bytes(v->salt, SALT_LEN) != 1)
    {
        vault_log(LOG_ERROR, "Cannot generate random salt");
        return ERR_CRYPTO;
    }

    uint8_t key[KEY_LEN];
    VaultErrorr err = derive_key_for(password, v->salt, "auth-verify", key);
    if (err != ERR_OK)
        return err;

    memcpy(v->pass_hash, key, SHA256_DIGEST_LENGTH);
    explicit_bzero(key, KEY_LEN);

    v->has_pass = true;
    vault_log(LOG_AUDIT, "Password set for vault '%s' (id=%u)", v->name, v->id);
    return ERR_OK;
}

VaultErrorr auth_verify_password(Vault *v, const char *password)
{
    VAULT_ASSERT(v && password, ERR_INVALID_ARGS, "null vault or password");

    if (!v->has_pass)
    {
        vault_log(LOG_WARN, "Vault '%s' has no password set", v->name);
        return ERR_PASS_REQUIRED;
    }

    uint8_t key[KEY_LEN];
    VaultErrorr err = derive_key_for(password, v->salt, "auth-verify", key);
    if (err != ERR_OK)
        return err;

    bool match = (CRYPTO_memcmp(v->pass_hash, key, SHA256_DIGEST_LENGTH) == 0);
    explicit_bzero(key, KEY_LEN);

    if (!match)
    {
        v->failed_attempts++;
        vault_log(LOG_AUDIT, "Auth FAILED for vault '%s' (attempt %d/%d)",
                  v->name, v->failed_attempts, MAX_PASS_ATTEMPTS);

        if (v->failed_attempts >= MAX_PASS_ATTEMPTS)
        {
            v->status = VAULT_STATUS_LOCKED;
            vault_log(LOG_ALERT, "Vault '%s' LOCKED after %d failed attempts",
                      v->name, MAX_PASS_ATTEMPTS);
            catalog_save();
        }
        return ERR_AUTH_FAIL;
    }

    v->failed_attempts = 0;
    vault_log(LOG_AUDIT, "Auth OK for vault '%s'", v->name);
    return ERR_OK;
}

VaultErrorr encrypt_file(const char *inpath, const char *outpath,
                        const uint8_t key[KEY_LEN])
{
    FILE *fin = fopen(inpath, "rb");
    FILE *fout = fopen(outpath, "wb");
    VaultErrorr ret = ERR_OK;
    EVP_CIPHER_CTX *ctx = NULL;

    if (!fin || !fout)
    {
        vault_log(LOG_ERROR, "encrypt_file: cannot open files: %s", strerror(errno));
        ret = ERR_IO;
        goto cleanup;
    }

    uint8_t iv[GCM_IV_LEN];
    if (RAND_bytes(iv, GCM_IV_LEN) != 1)
    {
        ret = ERR_CRYPTO;
        goto cleanup;
    }

    if (fwrite(iv, 1, GCM_IV_LEN, fout) != GCM_IV_LEN)
    {
        ret = ERR_IO;
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        ret = ERR_CRYPTO;
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1)
    {
        ret = ERR_CRYPTO;
        goto cleanup;
    }

    uint8_t inbuf[65536], outbuf[65536];
    int outlen;
    size_t n;

    while ((n = fread(inbuf, 1, sizeof(inbuf), fin)) > 0)
    {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)n) != 1)
        {
            ret = ERR_CRYPTO;
            goto cleanup;
        }
        if (fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen)
        {
            ret = ERR_IO;
            goto cleanup;
        }
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1)
    {
        ret = ERR_CRYPTO;
        goto cleanup;
    }
    if (outlen > 0 && fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen)
    {
        ret = ERR_IO;
        goto cleanup;
    }

    uint8_t tag[GCM_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1)
    {
        ret = ERR_CRYPTO;
        goto cleanup;
    }
    if (fwrite(tag, 1, GCM_TAG_LEN, fout) != GCM_TAG_LEN)
    {
        ret = ERR_IO;
    }

cleanup:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    if (fin)
        fclose(fin);
    if (fout)
    {
        fclose(fout);
        if (ret != ERR_OK)
            unlink(outpath);
    }
    return ret;
}

VaultErrorr decrypt_file(const char *inpath, const char *outpath,
                        const uint8_t key[KEY_LEN])
{
    FILE *fin = fopen(inpath, "rb");
    FILE *fout = fopen(outpath, "wb");
    VaultErrorr ret = ERR_OK;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *filebuf = NULL;

    if (!fin || !fout)
    {
        ret = ERR_IO;
        goto cleanup;
    }

    fseek(fin, 0, SEEK_END);
    long fsize = ftell(fin);
    rewind(fin);

    if (fsize < (long)(GCM_IV_LEN + GCM_TAG_LEN))
    {
        vault_log(LOG_ERROR, "decrypt_file: file too small");
        ret = ERR_IO;
        goto cleanup;
    }

    filebuf = malloc((size_t)fsize);
    if (!filebuf)
    {
        ret = ERR_NO_MEMORY;
        goto cleanup;
    }

    if (fread(filebuf, 1, (size_t)fsize, fin) != (size_t)fsize)
    {
        ret = ERR_IO;
        goto cleanup;
    }

    uint8_t *iv = filebuf;
    uint8_t *ciphertext = filebuf + GCM_IV_LEN;
    size_t ct_len = (size_t)fsize - GCM_IV_LEN - GCM_TAG_LEN;
    uint8_t *tag = filebuf + GCM_IV_LEN + ct_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        ret = ERR_CRYPTO;
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1)
    {
        ret = ERR_CRYPTO;
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1)
    {
        ret = ERR_CRYPTO;
        goto cleanup;
    }

    uint8_t outbuf[65536];
    int outlen;
    size_t offset = 0;

    while (offset < ct_len)
    {
        size_t chunk = ct_len - offset;
        if (chunk > sizeof(outbuf))
            chunk = sizeof(outbuf);

        if (EVP_DecryptUpdate(ctx, outbuf, &outlen,
                              ciphertext + offset, (int)chunk) != 1)
        {
            ret = ERR_CRYPTO;
            goto cleanup;
        }
        if (fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen)
        {
            ret = ERR_IO;
            goto cleanup;
        }
        offset += chunk;
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1)
    {
        vault_log(LOG_ERROR, "decrypt_file: GCM verification failed — data tampered or wrong key");
        ret = ERR_CRYPTO;
        goto cleanup;
    }
    if (outlen > 0 && fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen)
    {
        ret = ERR_IO;
    }

cleanup:
    if (filebuf)
    {
        explicit_bzero(filebuf, (size_t)(fsize > 0 ? fsize : 0));
        free(filebuf);
    }
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    if (fin)
        fclose(fin);
    if (fout)
    {
        fclose(fout);
        if (ret != ERR_OK)
            unlink(outpath);
    }
    return ret;
}