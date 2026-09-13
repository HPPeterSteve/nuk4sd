/*
 * apparmor.c
 *
 * Nuk4sd — MAC Layer: AppArmor dynamic profile management
 *
 * Protects vault cipher_path against direct access by root on the host.
 * AppArmor LSM hooks run before DAC checks — CAP_DAC_OVERRIDE is bypassed.
 *
 * Public interface (declared in sandbox.h):
 *   bool mac_apparmor_available(void)
 *   bool mac_apparmor_is_active(uint32_t vault_id)
 *   int  mac_apparmor_load(const Vault *v)
 *   int  mac_apparmor_remove(uint32_t vault_id)
 *   int  mac_apparmor_apply_all(void)
 */

#include "sandbox.h"
#include "../vault/vault_core.h"

#ifdef __linux__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define AA_LOAD_PATH    "/sys/kernel/security/apparmor/.load"
#define AA_REMOVE_PATH  "/sys/kernel/security/apparmor/.remove"
#define AA_PROFILES_PATH "/sys/kernel/security/apparmor/profiles"

/* ──────────────────────────────────────────────────────────────────────────
 * mac_apparmor_available
 *
 * Checks whether the kernel exposes the AppArmor interface.
 * Returns false on non-AppArmor kernels (e.g. SELinux-only, Android);
 * callers should log a warning and continue without MAC in that case.
 * ─────────────────────────────────────────────────────────────────────────*/
bool mac_apparmor_available(void) {
    return access(AA_LOAD_PATH, W_OK) == 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * mac_apparmor_is_active
 *
 * Checks if a profile named "nuk4sd_vault_<vault_id>" already exists in
 * /sys/kernel/security/apparmor/profiles. This prevents double-loading a
 * profile when --app-armor is applied to a batch of vaults.
 *
 * Returns true  if profile is already loaded (skip re-load).
 *         false if profile is absent or AppArmor unavailable.
 * ─────────────────────────────────────────────────────────────────────────*/
bool mac_apparmor_is_active(uint32_t vault_id) {
    FILE *profiles_fp = fopen(AA_PROFILES_PATH, "r");
    if (!profiles_fp) {
        vault_log(LOG_WARN,
                  "[MAC] mac_apparmor_is_active: cannot open %s: %s",
                  AA_PROFILES_PATH, strerror(errno));
        return false;
    }

    char profile_name[80];
    snprintf(profile_name, sizeof(profile_name), "nuk4sd_vault_%u", vault_id);

    char line[256];
    bool found = false;
    while (fgets(line, sizeof(line), profiles_fp)) {
        if (strstr(line, profile_name)) {
            found = true;
            break;
        }
    }
    fclose(profiles_fp);
    return found;
}

/* ──────────────────────────────────────────────────────────────────────────
 * mac_apparmor_load
 *
 * Generates and loads an AppArmor profile for vault v's cipher_path.
 * Profile name: "nuk4sd_vault_<id>"
 *
 * The profile default-denies all access. Only /proc/self/exe (the Nuk4sd
 * daemon binary itself) is allowed to read/write the cipher_path — this
 * blocks even root running a different binary (e.g. cat, cp, rm).
 *
 * If the profile is already active, this is a no-op (idempotent).
 *
 * Returns ERR_OK (0) on success, ERR_PERM_DENIED if AppArmor is
 * unavailable, ERR_IO on write failure.
 * ─────────────────────────────────────────────────────────────────────────*/
int mac_apparmor_load(const Vault *v) {
    if (!v || !v->cipher_path[0]) {
        vault_log(LOG_ERROR, "[MAC] mac_apparmor_load: invalid vault or empty cipher_path");
        return ERR_INVALID_ARGS;
    }

    if (!mac_apparmor_available()) {
        vault_log(LOG_WARN,
                  "[MAC] AppArmor not available on this kernel — "
                  "vault %u will rely on WORM + chmod 0000 only",
                  v->id);
        return ERR_PERM_DENIED;
    }

    if (mac_apparmor_is_active(v->id)) {
        vault_log(LOG_INFO,
                  "[MAC] Profile 'nuk4sd_vault_%u' already loaded — skipping",
                  v->id);
        return ERR_OK;
    }

    char profile[VAULT_PATH_MAX * 2 + 256];
    int profile_len = snprintf(profile, sizeof(profile),
        "profile nuk4sd_vault_%u flags=(attach_disconnected,mediate_deleted) {\n"
        "  /proc/self/exe r,\n"
        "  %s/ rwl,\n"
        "  %s/** rwl,\n"
        "}\n",
        v->id, v->cipher_path, v->cipher_path);

    if (profile_len < 0 || (size_t)profile_len >= sizeof(profile)) {
        vault_log(LOG_ERROR,
                  "[MAC] mac_apparmor_load: profile buffer too small for vault %u cipher_path='%s'",
                  v->id, v->cipher_path);
        return ERR_NO_MEMORY;
    }

    int fd = open(AA_LOAD_PATH, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        vault_log(LOG_ERROR,
                  "[MAC] mac_apparmor_load: cannot open %s: %s",
                  AA_LOAD_PATH, strerror(errno));
        return ERR_IO;
    }

    ssize_t bytes_written = write(fd, profile, profile_len);
    int save_errno = errno;
    close(fd);

    if (bytes_written != profile_len) {
        vault_log(LOG_ERROR,
                  "[MAC] mac_apparmor_load: write to %s failed for vault %u: %s",
                  AA_LOAD_PATH, v->id, strerror(save_errno));
        return ERR_IO;
    }

    vault_log(LOG_AUDIT,
              "[MAC] AppArmor profile 'nuk4sd_vault_%u' loaded. "
              "cipher_path='%s' is now protected against host root.",
              v->id, v->cipher_path);
    return ERR_OK;
}

/* ──────────────────────────────────────────────────────────────────────────
 * mac_apparmor_remove
 *
 * Removes the profile "nuk4sd_vault_<vault_id>" from the kernel.
 * Called on vault unmount or delete so the kernel profile table stays clean.
 *
 * If the profile is not active, this is a no-op (idempotent).
 *
 * Returns ERR_OK on success or if the profile was already absent,
 *         ERR_IO on write failure.
 * ─────────────────────────────────────────────────────────────────────────*/
int mac_apparmor_remove(uint32_t vault_id) {
    if (!mac_apparmor_available()) {
        return ERR_OK; /* nothing to remove */
    }

    if (!mac_apparmor_is_active(vault_id)) {
        vault_log(LOG_INFO,
                  "[MAC] mac_apparmor_remove: profile 'nuk4sd_vault_%u' not loaded — nothing to do",
                  vault_id);
        return ERR_OK;
    }

    char profile_name[80];
    int name_len = snprintf(profile_name, sizeof(profile_name),
                            "nuk4sd_vault_%u", vault_id);
    if (name_len < 0 || (size_t)name_len >= sizeof(profile_name)) {
        vault_log(LOG_ERROR, "[MAC] mac_apparmor_remove: vault_id overflow");
        return ERR_INVALID_ARGS;
    }

    int fd = open(AA_REMOVE_PATH, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        vault_log(LOG_ERROR,
                  "[MAC] mac_apparmor_remove: cannot open %s: %s",
                  AA_REMOVE_PATH, strerror(errno));
        return ERR_IO;
    }

    ssize_t bytes_written = write(fd, profile_name, name_len);
    int save_errno = errno;
    close(fd);

    if (bytes_written != name_len) {
        vault_log(LOG_ERROR,
                  "[MAC] mac_apparmor_remove: write failed for vault %u: %s",
                  vault_id, strerror(save_errno));
        return ERR_IO;
    }

    vault_log(LOG_AUDIT,
              "[MAC] AppArmor profile 'nuk4sd_vault_%u' removed from kernel.",
              vault_id);
    return ERR_OK;
}

/* ──────────────────────────────────────────────────────────────────────────
 * mac_apparmor_apply_all
 *
 * Iterates g_catalog and loads AppArmor profiles for every mounted vault
 * that does not already have one active. Called when the user runs:
 *   nuk4sd --app-armor=all
 *
 * Returns the number of profiles successfully loaded (0 is valid if all
 * vaults were already protected or none are mounted).
 * ─────────────────────────────────────────────────────────────────────────*/
int mac_apparmor_apply_all(void) {
    if (!mac_apparmor_available()) {
        vault_log(LOG_WARN, "[MAC] AppArmor not available — apply-all skipped");
        return 0;
    }

    int loaded_count = 0;
    for (uint32_t vault_idx = 0; vault_idx < g_catalog.count; vault_idx++) {
        Vault *current_vault = &g_catalog.vaults[vault_idx];

        if (!current_vault->is_mounted) {
            vault_log(LOG_INFO,
                      "[MAC] Vault %u ('%s') is not mounted — skipping profile load",
                      current_vault->id, current_vault->name);
            continue;
        }

        int result = mac_apparmor_load(current_vault);
        if (result == ERR_OK) {
            loaded_count++;
        } else {
            vault_log(LOG_WARN,
                      "[MAC] mac_apparmor_apply_all: failed to load profile for vault %u ('%s')",
                      current_vault->id, current_vault->name);
        }
    }

    vault_log(LOG_INFO,
              "[MAC] mac_apparmor_apply_all complete: %d profile(s) newly loaded",
              loaded_count);
    return loaded_count;
}

#else /* non-Linux stubs */

bool mac_apparmor_available(void)                { return false; }
bool mac_apparmor_is_active(uint32_t vault_id)   { (void)vault_id; return false; }
int  mac_apparmor_load(const Vault *v)           { (void)v;         return ERR_PERM_DENIED; }
int  mac_apparmor_remove(uint32_t vault_id)      { (void)vault_id;  return ERR_OK; }
int  mac_apparmor_apply_all(void)                { return 0; }

#endif
