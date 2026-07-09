/*
 * vault_ffi.c
 *
 * Implementações das funções exportadas para o Rust via FFI.
 *
 * Este arquivo deve ser compilado junto com vault_security.c e
 * linkedado na libvault_security.a que o Rust consome.
 *
 * Como vault_security.c declara todas as suas funções como `static`,
 * este arquivo os chama através de wrappers públicos (sem static).
 *
 * ESTRATÉGIA:
 *   vault_security.c   → lógica interna (static)
 *   vault_ffi.c        → wrappers públicos (sem static) que chamam a lógica
 *
 * Para isso, vault_security.c precisa de pequenas adições:
 *   1. #include "vault_ffi.h" no topo
 *   2. As funções internas que o FFI precisa devem ter versões não-static
 *      com o sufixo _ffi — implementadas aqui.
 *
 * Compile:
 *   gcc -O2 -c vault_security.c -o vault_security.o -lssl -lcrypto -lpthread
 *   gcc -O2 -c vault_ffi.c      -o vault_ffi.o
 *   ar rcs libvault_security.a vault_security.o vault_ffi.o
 *
 * No build.rs do Rust:
 *   println!("cargo:rustc-link-lib=static=vault_security");
 *   println!("cargo:rustc-link-lib=ssl");
 *   println!("cargo:rustc-link-lib=crypto");
 *   println!("cargo:rustc-link-lib=pthread");
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "vault_ffi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/*
 * ─────────────────────────────────────────────────────────────────────────
 * Declarações externas dos símbolos internos de vault_security.c
 * que precisamos acessar. Como eles são `static` lá, a única forma
 * limpa é mover as declarações para um header interno compartilhado.
 *
 * Alternativa adotada aqui: compilar vault_ffi.c incluindo vault_security.c
 * com uma flag especial que converte os statics relevantes em externos.
 *
 * ABORDAGEM RECOMENDADA (sem modificar vault_security.c):
 *   Adicionar ao vault_security.c, logo antes do main():
 *
 *     #include "vault_ffi_impl.c"   // inclui este arquivo diretamente
 *
 *   Assim os símbolos static ficam visíveis dentro da mesma unidade de
 *   compilação.
 *
 * A seguir implementamos cada função FFI assumindo que ela será incluída
 * em vault_security.c via:
 *
 *     // No final de vault_security.c, antes do main():
 *     #include "vault_ffi_impl.c"
 *
 * ─────────────────────────────────────────────────────────────────────────
 */

/* ── Vault lifecycle ────────────────────────────────────────────────────── */

int vault_create_ffi(
    const char *name,
    int vault_type,
    const char *path,
    const char *password)
{
    VaultType vt = (vault_type == 1) ? VAULT_TYPE_PROTECTED : VAULT_TYPE_NORMAL;

    pthread_mutex_lock(&g_monitor.lock);
    VaultError err = vault_create(name, vt, path, password);
    pthread_mutex_unlock(&g_monitor.lock);

    return (int)err;
}

int vault_delete_ffi(uint32_t id, const char *password)
{
    pthread_mutex_lock(&g_monitor.lock);
    VaultError err = vault_delete(id, password);
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)err;
}

int vault_rename_ffi(uint32_t id, const char *new_name, const char *password)
{
    if (!new_name || new_name[0] == '\0')
        return (int)ERR_INVALID_ARGS;
    pthread_mutex_lock(&g_monitor.lock);
    VaultError err = vault_rename(id, new_name, password);
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)err;
}

int vault_unlock_ffi(uint32_t id, const char *password)
{
    if (!password || password[0] == '\0')
        return (int)ERR_PASS_REQUIRED;
    pthread_mutex_lock(&g_monitor.lock);
    VaultError err = vault_unlock(id, password);
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)err;
}

int vault_change_password_ffi(uint32_t id, const char *old_pass, const char *new_pass)
{
    if (!old_pass || !new_pass)
        return (int)ERR_INVALID_ARGS;
    pthread_mutex_lock(&g_monitor.lock);
    VaultError err = vault_change_password(id, old_pass, new_pass);
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)err;
}

/* ── Criptografia ───────────────────────────────────────────────────────── */

/*
 * vault_encrypt_ffi / vault_decrypt_ffi:
 * A lógica original está em cmd_encrypt_vault / cmd_decrypt_vault (que lêem
 * a senha via terminal). Aqui recebemos a senha já pronta via parâmetro.
 */

int vault_encrypt_ffi(uint32_t id, const char *password)
{
    if (!password || password[0] == '\0')
        return (int)ERR_PASS_REQUIRED;

    pthread_mutex_lock(&g_monitor.lock);

    Vault *v = vault_find_by_id(id);
    if (!v)
    {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_VAULT_NOT_FOUND;
    }
    if (!v->has_pass)
    {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_PASS_REQUIRED;
    }

    VaultError auth_err = auth_verify_password(v, password);
    if (auth_err != ERR_OK)
    {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)auth_err;
    }

    uint8_t key[KEY_LEN];
    VaultError key_err = derive_key(password, v->salt, key);
    if (key_err != ERR_OK)
    {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)key_err;
    }

    DIR *dir = opendir(v->path);
    if (!dir)
    {
        explicit_bzero(key, KEY_LEN);
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_IO;
    }

    struct dirent *de;
    int count = 0;
    char inpath[VAULT_PATH_MAX + NAME_MAX + 2];
    char outpath[VAULT_PATH_MAX + NAME_MAX + 10];

    while ((de = readdir(dir)) != NULL)
    {
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

        if (encrypt_file(inpath, outpath, key) == ERR_OK)
        {
            unlink(inpath);
            count++;
            vault_log(LOG_AUDIT, "[FFI] vault_encrypt_ffi: encrypted '%s'", de->d_name);
        }
        else
        {
            vault_log(LOG_ERROR, "[FFI] vault_encrypt_ffi: FAILED '%s'", de->d_name);
        }
    }
    closedir(dir);
    explicit_bzero(key, KEY_LEN);

    vault_log(LOG_AUDIT, "[FFI] vault_encrypt_ffi: vault='%s' encrypted %d files", v->name, count);
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)ERR_OK;
}

int vault_decrypt_ffi(uint32_t id, const char *password)
{
    if (!password || password[0] == '\0')
        return (int)ERR_PASS_REQUIRED;

    pthread_mutex_lock(&g_monitor.lock);

    Vault *v = vault_find_by_id(id);
    if (!v)
    {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_VAULT_NOT_FOUND;
    }
    if (!v->has_pass)
    {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_PASS_REQUIRED;
    }

    VaultError auth_err = auth_verify_password(v, password);
    if (auth_err != ERR_OK)
    {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)auth_err;
    }

    uint8_t key[KEY_LEN];
    VaultError key_err = derive_key(password, v->salt, key);
    if (key_err != ERR_OK)
    {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)key_err;
    }

    DIR *dir = opendir(v->path);
    if (!dir)
    {
        explicit_bzero(key, KEY_LEN);
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_IO;
    }

    struct dirent *de;
    int count = 0;
    char inpath[VAULT_PATH_MAX + NAME_MAX + 2];
    char outpath[VAULT_PATH_MAX + NAME_MAX + 2];

    while ((de = readdir(dir)) != NULL)
    {
        size_t nlen = strlen(de->d_name);
        if (nlen <= 4 || strcmp(de->d_name + nlen - 4, ".enc") != 0)
            continue;

        snprintf(inpath, sizeof(inpath), "%s/%s", v->path, de->d_name);
        snprintf(outpath, sizeof(outpath), "%s/%.*s", v->path,
                 (int)(nlen - 4), de->d_name);

        struct stat st;
        if (stat(inpath, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        if (decrypt_file(inpath, outpath, key) == ERR_OK)
        {
            unlink(inpath);
            count++;
            vault_log(LOG_AUDIT, "[FFI] vault_decrypt_ffi: decrypted '%s'", outpath);
        }
        else
        {
            vault_log(LOG_ERROR, "[FFI] vault_decrypt_ffi: FAILED '%s'", de->d_name);
        }
    }
    closedir(dir);
    explicit_bzero(key, KEY_LEN);

    vault_log(LOG_AUDIT, "[FFI] vault_decrypt_ffi: vault='%s' decrypted %d files", v->name, count);
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)ERR_OK;
}

/* ── Integridade ────────────────────────────────────────────────────────── */

int vault_scan_ffi(uint32_t id)
{
    pthread_mutex_lock(&g_monitor.lock);
    Vault *v = vault_find_by_id(id);
    if (!v)
    {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_VAULT_NOT_FOUND;
    }
    monitor_scan_vault(v);
    catalog_save();
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)ERR_OK;
}

int vault_resolve_ffi(uint32_t id, const char *password)
{
    pthread_mutex_lock(&g_monitor.lock);
    VaultError err = alert_resolve(id, password);
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)err;
}

/* ── Display ────────────────────────────────────────────────────────────── */

void vault_info_ffi(uint32_t id)
{
    pthread_mutex_lock(&g_monitor.lock);
    cmd_info(id);
    pthread_mutex_unlock(&g_monitor.lock);
}

void vault_list_ffi(void)
{
    pthread_mutex_lock(&g_monitor.lock);
    cmd_list();
    pthread_mutex_unlock(&g_monitor.lock);
}

void vault_files_ffi(uint32_t id)
{
    pthread_mutex_lock(&g_monitor.lock);
    cmd_files(id);
    pthread_mutex_unlock(&g_monitor.lock);
}

/* ── Sandbox ────────────────────────────────────────────────────────────── */

int vault_sandbox_ffi(uint32_t id, const char *password)
{
    pthread_mutex_lock(&g_monitor.lock);
    Vault *v = vault_find_by_id(id);
    if (!v)
    {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_VAULT_NOT_FOUND;
    }
    /* Desbloqueia o mutex ANTES do fork/execl, pois o filho herdaria o lock */
    pthread_mutex_unlock(&g_monitor.lock);

    return (int)vault_sandbox_open(v, password);
}

/* ── Rule engine ────────────────────────────────────────────────────────── */

int vault_rule_ffi(uint32_t vault_id, int max_fails, int hour_from, int hour_to)
{
    if (g_rule_count >= MAX_RULES)
        return (int)ERR_SYSTEM;
    rule_add(vault_id, max_fails, hour_from, hour_to);
    return (int)ERR_OK;
}

/* ── Status ─────────────────────────────────────────────────────────────── */

int vault_get_status_ffi(uint32_t id)
{
    pthread_mutex_lock(&g_monitor.lock);
    Vault *v = vault_find_by_id(id);
    if (!v)
    {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_VAULT_NOT_FOUND;
    }
    int status = (int)v->status;
    pthread_mutex_unlock(&g_monitor.lock);
    return status;
}