/*
 * vault_engine.c
 *
 * VAULT SECURITY SYSTEM — Isolation Engine (Honeyfile Labyrinth)
 *
 * Available engines (tree depth x branching factor — see ENGINE_TREE_DEPTH /
 * ENGINE_TREE_BRANCH in vault_core.h):
 *   0 → no engine (default behavior)
 *   1 → depth 1, branch 1   (1 node)
 *   2 → depth 2, branch 2   (6 nodes)
 *   3 → depth 3, branch 2   (14 nodes)
 *   4 → depth 4, branch 3   (120 nodes)  + fake binaries instead of text
 *   5 → depth 5, branch 3   (363 nodes)  + fake binaries [OverlayFS to be added]
 *
 * Structure created inside vault:
 *
 *   <vault_path>/
 *     .engine_decoy/                 ← decoy labyrinth (public to attacker)
 *       layer_01_00/                 ← depth 1, child index 0
 *         a.<ext> … z.<ext>          ← extension picked at random per file
 *         layer_02_00/               ← depth 2, child 0 of layer_01_00
 *           a.<ext> … z.<ext>
 *         layer_02_01/               ← depth 2, child 1 of layer_01_00 (sibling)
 *           a.<ext> … z.<ext>
 *       layer_01_01/                 ← depth 1, child index 1 (sibling of layer_01_00)
 *         ...
 *     .engine_real/                  ← where real files should be stored
 *
 * Each node has BRANCH direct children (true tree, not a single-child funnel).
 * Extensions are drawn at random per file from TEXT_EXT_POOL / BINARY_EXT_POOL
 * instead of a fixed .txt/.enc, so decoy files can't be filtered by extension
 * alone. A hard node-count cap (ENGINE_MAX_DECOY_NODES) refuses to build a
 * labyrinth whose depth/branch combination would explode disk usage.
 *
 * Strict constraints:
 *   - All operations verify vault is not DELETED/LOCKED
 *   - Paths are validated with realpath() before any mkdir/write
 *   - Each created file is verified with stat() post write
 *   - Logs at each stage (start, progress, success, error)
 *   - On partial error, best-effort cleanup is executed
 *
 * Applied fixes (v2):
 *   [FIX-1] strncmp path traversal: checks separator after vault prefix
 *   [FIX-2] engine_is_decoy_path: uses realpath+strncmp instead of strstr
 *   [FIX-3] engine_apply: best-effort cleanup on layers_failed > 0
 *   [FIX-4] engine_write_text_decoy: varied content and realistic size
 *   [FIX-5] engine_write_binary_decoy: varied magic byte per file
 *
 * Applied fixes (v3 — tree labyrinth):
 *   [FIX-7] engine_apply/engine_validate: recursive N-ary tree instead of a
 *           single-child funnel; siblings are independent, so one missing
 *           branch no longer masks validation of the others
 *   [FIX-8] engine_populate_layer: per-file random extension (TEXT_EXT_POOL /
 *           BINARY_EXT_POOL) instead of fixed .txt/.enc
 *   [FIX-9] engine_apply: hard cap (ENGINE_MAX_DECOY_NODES) computed from
 *           depth/branch before touching disk, refuses configs that would
 *           create an unreasonable number of directories
 *
 * Author: Nuk4sd — Peter Steve (architecture)
 */

#include "vault_core.h"

#ifdef __linux__
#include <dirent.h>
#endif

/* ─────────────────────────────────────────────────────────────────────────
 *  Internal helpers
 * ───────────── */

/* Creates a directory with 0700 permissions. */
static VaultErrorr engine_mkdir(const char *path)
{
    if (!path || path[0] == '\0')
    {
        vault_log(LOG_ERROR, "%s engine_mkdir: empty path", ENGINE_LOG_PREFIX);
        return ERR_INVALID_ARGS;
    }

    struct stat st;
    if (stat(path, &st) == 0)
    {
        if (!S_ISDIR(st.st_mode))
        {
            vault_log(LOG_ERROR, "%s '%s' exists but is not a directory",
                      ENGINE_LOG_PREFIX, path);
            return ERR_IO;
        }
        return ERR_OK;
    }

    if (mkdir(path, 0700) != 0)
    {
        vault_log(LOG_ERROR, "%s mkdir('%s'): %s",
                  ENGINE_LOG_PREFIX, path, strerror(errno));
        return ERR_IO;
    }

    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s mkdir('%s'): created but stat failed",
                  ENGINE_LOG_PREFIX, path);
        return ERR_IO;
    }

    vault_log(LOG_INFO, "%s directory created: %s", ENGINE_LOG_PREFIX, path);
    return ERR_OK;
}

/* [FIX-1] Validates that a path is contained inside the vault.
 * Checks separator after prefix to prevent /vault1 accepting /vault1_evil. */
static VaultErrorr engine_validate_inside_vault(const Vault *v, const char *path)
{
    char resolved[PATH_MAX];
    char vault_resolved[PATH_MAX];

    if (!realpath(v->path, vault_resolved))
    {
        vault_log(LOG_ERROR, "%s realpath(vault): %s",
                  ENGINE_LOG_PREFIX, strerror(errno));
        return ERR_PATH_INVALID;
    }

    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);

    char *slash = strrchr(tmp, '/');
    if (!slash)
    {
        vault_log(LOG_ERROR, "%s path missing separator: %s",
                  ENGINE_LOG_PREFIX, path);
        return ERR_PATH_INVALID;
    }

    *slash = '\0';
    if (!realpath(tmp, resolved))
    {
        vault_log(LOG_ERROR, "%s realpath(parent of '%s'): %s",
                  ENGINE_LOG_PREFIX, path, strerror(errno));
        return ERR_PATH_INVALID;
    }

    size_t vlen = strlen(vault_resolved);

    if (strncmp(resolved, vault_resolved, vlen) != 0 ||
        (resolved[vlen] != '/' && resolved[vlen] != '\0'))
    {
        vault_log(LOG_ERROR, "%s PATH VIOLATION: '%s' outside vault '%s'",
                  ENGINE_LOG_PREFIX, path, vault_resolved);
        return ERR_PERM_DENIED;
    }

    return ERR_OK;
}

/* [FIX-4] Plausible content table for text decoys. */
static const char *DECOY_TEMPLATES[] = {
    "Project Status Report\n"
    "======================\n"
    "Quarter: Q3\nDepartment: Operations\nPrepared by: Systems Audit\n\n"
    "Executive Summary:\n"
    "This document outlines the current operational status and key performance\n"
    "indicators for the reporting period. Infrastructure metrics remain within\n"
    "acceptable thresholds. Detailed breakdowns are available upon request.\n\n"
    "Key Findings:\n"
    "  - Uptime: 99.94%%\n  - Incidents resolved: 14\n"
    "  - Pending tasks: 3\n  - Budget variance: -2.1%%\n\n"
    "Next review scheduled: end of quarter.\n",

    "Internal Memo\n==============\n"
    "To: All Staff\nFrom: Management\n"
    "Subject: Updated Access Policies\n\n"
    "Effective immediately, all personnel must comply with the revised data\n"
    "handling protocols described in policy document SEC-2024-11.\n"
    "Violations will be subject to disciplinary review.\n\n"
    "Please acknowledge receipt by logging into the HR portal.\n",

    "Financial Summary\n==================\n"
    "Period: January - June\nEntity: Nuk4sd Holdings\n\n"
    "Revenue:         $4,820,310.00\nOperating Costs: $3,104,820.50\n"
    "Net Income:      $1,715,489.50\nEBITDA Margin:   35.6%%\n\n"
    "Notes:\nFigures are preliminary and subject to audit confirmation.\n"
    "See Appendix B for detailed line-item breakdown.\n",

    "System Configuration Backup\n============================\n"
    "Host: vault-node-04\nOS: Ubuntu 22.04 LTS\n"
    "Kernel: 5.15.0-91-generic\nGenerated: automated\n\n"
    "[network]\ninterface=eth0\nip=10.0.1.44\ngateway=10.0.1.1\n"
    "dns=8.8.8.8,1.1.1.1\n\n"
    "[storage]\nmount=/data\ntype=ext4\ncapacity=2TB\nused=847GB\n\n"
    "[backup]\nschedule=daily\nretention=30d\nlast_run=success\n",

    "Employee Records - Confidential\n================================\n"
    "Record ID: EMP-00847\nName: [REDACTED]\nDepartment: Engineering\n"
    "Start Date: 2019-03-12\nLevel: Senior\n\n"
    "Performance Review (Latest):\n"
    "  Rating: Exceeds Expectations\n  Score: 4.7 / 5.0\n"
    "  Reviewer: [REDACTED]\n\n"
    "Compensation: see HR system.\nAccess Level: 3\nClearance: Standard\n",
};

#define DECOY_TEMPLATE_COUNT ((int)(sizeof(DECOY_TEMPLATES) / sizeof(DECOY_TEMPLATES[0])))

/* [FIX-6] Random per-session seed — initialized once in engine_apply().
 * Prevents template/magic index from being purely deterministic based on
 * file letter (letter % N), avoiding automated fingerprinting by an attacker.
 * Seed is generated via getrandom() or /dev/urandom and XOR'd to index. */
static uint32_t engine_session_seed = 0;

/* [FIX-8] Extension pools used to name decoy files. Picked at random per
 * file instead of a fixed .txt/.enc, so an attacker can't filter decoys
 * out of a scan just by extension. Kept plausible (things that legitimately
 * show up in a home/office directory) rather than exotic. */
static const char *TEXT_EXT_POOL[] = {
    "txt", "log", "cfg", "md", "csv", "conf", "json", "yaml", "ini", "bak"};
#define TEXT_EXT_COUNT ((int)(sizeof(TEXT_EXT_POOL) / sizeof(TEXT_EXT_POOL[0])))

static const char *BINARY_EXT_POOL[] = {
    "enc", "dat", "bin", "db", "cache", "idx", "tmp", "old", "dump", "img"};
#define BINARY_EXT_COUNT ((int)(sizeof(BINARY_EXT_POOL) / sizeof(BINARY_EXT_POOL[0])))

/* FNV-1a — cheap, non-cryptographic hash used only to pick an extension.
 * Never use this for anything security-relevant (that's what
 * engine_session_seed + getrandom() are for in the write_* functions). */
static uint32_t engine_hash_str(const char *s)
{
    uint32_t h = 2166136261u;
    for (; *s; s++)
    {
        h ^= (uint8_t)*s;
        h *= 16777619u;
    }
    return h;
}

/* [FIX-8] Picks an extension for 'letter' inside 'layer_path'. Mixes the
 * per-session seed with the layer path and letter so the same letter gets
 * a different extension in different layers/sessions, without needing to
 * persist any extra state for engine_validate() to recompute later. */
static const char *engine_pick_extension(bool binary, const char *layer_path, char letter)
{
    uint32_t h = engine_hash_str(layer_path) ^ (uint32_t)(uint8_t)letter ^ engine_session_seed;
    if (binary)
        return BINARY_EXT_POOL[h % (uint32_t)BINARY_EXT_COUNT];
    return TEXT_EXT_POOL[h % (uint32_t)TEXT_EXT_COUNT];
}

/* [FIX-4] Writes text decoy file with varied content. */
static VaultErrorr engine_write_text_decoy(const char *filepath, char letter)
{
    int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        if (errno == ELOOP)
        {
            vault_log(LOG_ALERT, "%s fopen->open ELOOP (symlink) on '%s'", ENGINE_LOG_PREFIX, filepath);
        }
        else
        {
            vault_log(LOG_ERROR, "%s open('%s'): %s", ENGINE_LOG_PREFIX, filepath, strerror(errno));
        }
        return ERR_IO;
    }
    FILE *f = fdopen(fd, "w");
    if (!f)
    {
        close(fd);
        vault_log(LOG_ERROR, "%s fdopen('%s') failed", ENGINE_LOG_PREFIX, filepath);
        return ERR_IO;
    }

    int tmpl_idx = (int)(((uint32_t)(letter - 'a') + engine_session_seed) % (uint32_t)DECOY_TEMPLATE_COUNT);
    fprintf(f, "%s", DECOY_TEMPLATES[tmpl_idx]);

    static const char *LOREM =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod "
        "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, "
        "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo. "
        "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore "
        "eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.\n";

    int repeats = 2 + ((letter - 'a') % 5);
    for (int i = 0; i < repeats; i++)
    {
        fputs(LOREM, f);
    }

    if (fflush(f) != 0)
    {
        vault_log(LOG_ERROR, "%s fflush('%s'): %s",
                  ENGINE_LOG_PREFIX, filepath, strerror(errno));
        fclose(f);
        return ERR_IO;
    }
    fclose(f);

    struct stat st;
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s decoy file unconfirmed: %s",
                  ENGINE_LOG_PREFIX, filepath);
        return ERR_IO;
    }

    return ERR_OK;
}

/* [FIX-5] Magic bytes of real formats to vary across files. */
static const struct
{
    uint8_t bytes[4];
    size_t len;
} REAL_MAGIC[] = {
    {{0x25, 0x50, 0x44, 0x46}, 4}, /* %PDF */
    {{0x50, 0x4B, 0x03, 0x04}, 4}, /* PK (ZIP/DOCX/XLSX) */
    {{0xFF, 0xD8, 0xFF, 0xE0}, 4}, /* JPEG JFIF */
    {{0x89, 0x50, 0x4E, 0x47}, 4}, /* PNG */
    {{0x52, 0x49, 0x46, 0x46}, 4}, /* RIFF (WAV/AVI) */
};

#define REAL_MAGIC_COUNT ((int)(sizeof(REAL_MAGIC) / sizeof(REAL_MAGIC[0])))

/* [FIX-5] Fake binary with letter-rotating magic. */
static VaultErrorr engine_write_binary_decoy(const char *filepath, char letter)
{
    uint8_t buf[512];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        vault_log(LOG_ERROR, "%s open(/dev/urandom): %s",
                  ENGINE_LOG_PREFIX, strerror(errno));
        return ERR_IO;
    }

    ssize_t got = read(fd, buf, sizeof(buf));
    close(fd);

    if (got != (ssize_t)sizeof(buf))
    {
        vault_log(LOG_ERROR, "%s urandom read %zd bytes (expected %zu)",
                  ENGINE_LOG_PREFIX, got, sizeof(buf));
        return ERR_IO;
    }

    int magic_idx = (int)(((uint32_t)(letter - 'a') + engine_session_seed) % (uint32_t)REAL_MAGIC_COUNT);
    memcpy(buf, REAL_MAGIC[magic_idx].bytes, REAL_MAGIC[magic_idx].len);

    int out_fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out_fd < 0)
    {
        if (errno == ELOOP)
        {
            vault_log(LOG_ALERT, "%s fopen->open ELOOP (symlink) on '%s'", ENGINE_LOG_PREFIX, filepath);
        }
        else
        {
            vault_log(LOG_ERROR, "%s open(bin '%s'): %s", ENGINE_LOG_PREFIX, filepath, strerror(errno));
        }
        return ERR_IO;
    }
    FILE *f = fdopen(out_fd, "wb");
    if (!f)
    {
        close(out_fd);
        vault_log(LOG_ERROR, "%s fdopen(bin '%s') failed", ENGINE_LOG_PREFIX, filepath);
        return ERR_IO;
    }

    size_t written = fwrite(buf, 1, sizeof(buf), f);
    if (fflush(f) != 0)
    {
        vault_log(LOG_ERROR, "%s fflush(bin '%s'): %s",
                  ENGINE_LOG_PREFIX, filepath, strerror(errno));
        fclose(f);
        return ERR_IO;
    }
    fclose(f);

    if (written != sizeof(buf))
    {
        vault_log(LOG_ERROR, "%s incomplete fwrite in '%s': %zu/%zu bytes",
                  ENGINE_LOG_PREFIX, filepath, written, sizeof(buf));
        return ERR_IO;
    }

    struct stat st;
    if (stat(filepath, &st) != 0 || st.st_size != (off_t)sizeof(buf))
    {
        vault_log(LOG_ERROR, "%s fake binary unconfirmed: %s",
                  ENGINE_LOG_PREFIX, filepath);
        return ERR_IO;
    }

    return ERR_OK;
}

/* Populates a layer with a-z files. */
static VaultErrorr engine_populate_layer(const char *layer_path, bool binary)
{
    int errors = 0;
    int created = 0;

    vault_log(LOG_INFO, "%s populating layer: %s (%s)",
              ENGINE_LOG_PREFIX, layer_path, binary ? "binary" : "text");

    for (char c = 'a'; c <= 'z'; c++)
    {
        const char *ext = engine_pick_extension(binary, layer_path, c);

        char filepath[PATH_MAX];
        snprintf(filepath, sizeof(filepath), "%s/%c.%s", layer_path, c, ext);

        VaultErrorr err = binary
                             ? engine_write_binary_decoy(filepath, c)
                             : engine_write_text_decoy(filepath, c);

        if (err != ERR_OK)
        {
            vault_log(LOG_ERROR, "%s error creating decoy '%s': %s",
                      ENGINE_LOG_PREFIX, filepath, vault_strerror(err));
            errors++;
            continue;
        }

        if (chmod(filepath, 0400) != 0)
        {
            vault_log(LOG_WARN, "%s chmod(0400) on '%s': %s",
                      ENGINE_LOG_PREFIX, filepath, strerror(errno));
        }

        created++;
    }

    vault_log(LOG_INFO, "%s layer '%s': %d files created, %d errors",
              ENGINE_LOG_PREFIX, layer_path, created, errors);

    if (errors > 0)
    {
        vault_log(LOG_ERROR, "%s incomplete layer: %d/%d files failed",
                  ENGINE_LOG_PREFIX, errors, created + errors);
        return ERR_IO;
    }

    return ERR_OK;
}
static const char *rm_paths[] = {
    "/bin/rm",
    "/usr/bin/rm",
    "/usr/local/bin/rm",
    NULL
};
/* [FIX-3] Best-effort cleanup: removes partial labyrinth. */
static void engine_cleanup_decoy(const char *decoy_root)
{
    if (!decoy_root || decoy_root[0] == '\0')
        return;

    vault_log(LOG_WARN, "%s cleanup: removing partial labyrinth at '%s'",
              ENGINE_LOG_PREFIX, decoy_root);

    
    pid_t pid = fork();
      if (pid < 0) {
      vault_log(LOG_ERROR, "%s cleanup: fork failed: %s", ENGINE_LOG_PREFIX, strerror(errno));
        return;
      }
      if (pid == 0) {
    /* child: executes rm directly without shell */
        char *const args[] = { "rm", "-rf", (char *)decoy_root, NULL };
        for (int i = 0; rm_paths[i] != NULL; i++) {
            execv(rm_paths[i], args);
        }
        exit(127); /* execv failed on all attempts */
      }
      int status;
       if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
         vault_log(LOG_WARN, "%s cleanup: rm -rf returned error", ENGINE_LOG_PREFIX);
       else 
         vault_log(LOG_INFO, "%s cleanup: partial labyrinth removed", ENGINE_LOG_PREFIX);
}

/* [FIX-9] Hard cap on total decoy directories. Depth/branch combinations
 * grow exponentially (sum of branch^1 .. branch^depth) — this refuses to
 * build a labyrinth big enough to hurt the filesystem before touching disk,
 * even if ENGINE_TREE_DEPTH/ENGINE_TREE_BRANCH are misconfigured later. */
#define ENGINE_MAX_DECOY_NODES 5000

/* Total non-root directories a (branch, depth) tree will create:
 * branch + branch^2 + ... + branch^depth. */
static long engine_estimate_nodes(int branch, int depth)
{
    long total = 0;
    long level_nodes = branch;
    for (int i = 1; i <= depth; i++)
    {
        total += level_nodes;
        level_nodes *= branch;
    }
    return total;
}

/* Builds one directory name for a tree node: "layer_<depth>_<child index>". */
static void engine_child_dirname(char *out, size_t outsz, int depth, int idx)
{
    snprintf(out, outsz, "layer_%02d_%02d", depth, idx);
}

/* [FIX-7] Recursively builds an N-ary decoy tree under 'parent_path'.
 * Each node gets 'branch' children; recursion stops at 'max_depth'.
 * Siblings are independent: a failure in one branch does not stop the
 * others from being attempted (unlike the old single-child funnel, where
 * one failure aborted the whole chain below it). */
static void engine_build_subtree(const Vault *v, const char *parent_path,
                                  int depth, int max_depth, int branch,
                                  bool binary, int *layers_ok, int *layers_failed)
{
    if (depth > max_depth)
        return;

    for (int idx = 0; idx < branch; idx++)
    {
        char dirname[64];
        engine_child_dirname(dirname, sizeof(dirname), depth, idx);

        char node_path[PATH_MAX];
        int wlen = snprintf(node_path, sizeof(node_path), "%s/%s", parent_path, dirname);
        if (wlen < 0 || (size_t)wlen >= sizeof(node_path))
        {
            vault_log(LOG_ERROR, "%s node depth=%d idx=%d: path exceeded PATH_MAX",
                      ENGINE_LOG_PREFIX, depth, idx);
            (*layers_failed)++;
            continue;
        }

        vault_log(LOG_INFO, "%s creating node depth=%d/%d idx=%d/%d: %s",
                  ENGINE_LOG_PREFIX, depth, max_depth, idx, branch, node_path);

        VaultErrorr err = engine_validate_inside_vault(v, node_path);
        if (err != ERR_OK)
        {
            vault_log(LOG_ERROR, "%s node depth=%d idx=%d: path validation failed",
                      ENGINE_LOG_PREFIX, depth, idx);
            (*layers_failed)++;
            continue;
        }

        err = engine_mkdir(node_path);
        if (err != ERR_OK)
        {
            vault_log(LOG_ERROR, "%s node depth=%d idx=%d: mkdir failed: %s",
                      ENGINE_LOG_PREFIX, depth, idx, vault_strerror(err));
            (*layers_failed)++;
            continue;
        }

        err = engine_populate_layer(node_path, binary);
        if (err != ERR_OK)
        {
            vault_log(LOG_ERROR, "%s node depth=%d idx=%d: populate failed: %s",
                      ENGINE_LOG_PREFIX, depth, idx, vault_strerror(err));
            (*layers_failed)++;
            continue;
        }

        vault_log(LOG_INFO, "%s ✓ node depth=%d idx=%d completed", ENGINE_LOG_PREFIX, depth, idx);
        (*layers_ok)++;

        /* Recurse: this node's children live inside it, as siblings of each other. */
        engine_build_subtree(v, node_path, depth + 1, max_depth, branch, binary,
                              layers_ok, layers_failed);
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  engine_apply() — public entry point
 * ───────────── */
VaultErrorr engine_apply(Vault *v)
{
    if (!v)
    {
        vault_log(LOG_ERROR, "%s engine_apply: vault NULL", ENGINE_LOG_PREFIX);
        return ERR_INVALID_ARGS;
    }

    if (v->status == VAULT_STATUS_DELETED)
    {
        vault_log(LOG_ERROR, "%s engine_apply: vault '%s' is DELETED",
                  ENGINE_LOG_PREFIX, v->name);
        return ERR_INVALID_ARGS;
    }

    if (v->status == VAULT_STATUS_LOCKED)
    {
        vault_log(LOG_ERROR, "%s engine_apply: vault '%s' is LOCKED",
                  ENGINE_LOG_PREFIX, v->name);
        return ERR_VAULT_LOCKED;
    }

    int level = v->engine_level;

    if (level < ENGINE_LEVEL_MIN || level > ENGINE_LEVEL_MAX)
    {
        vault_log(LOG_ERROR, "%s engine_apply: invalid level %d (valid: %d-%d)",
                  ENGINE_LOG_PREFIX, level, ENGINE_LEVEL_MIN, ENGINE_LEVEL_MAX);
        return ERR_INVALID_ARGS;
    }

    if (level == 0)
    {
        vault_log(LOG_INFO, "%s engine 0 selected — no labyrinth", ENGINE_LOG_PREFIX);
        return ERR_OK;
    }

    vault_log(LOG_INFO, "%s applying engine %d to vault '%s' (path='%s')",
              ENGINE_LOG_PREFIX, level, v->name, v->path);

    /* [FIX-6] Initializes per-session random seed for decoy templates. */
    {
        uint32_t seed = 0;
#ifdef __linux__
        if (syscall(SYS_getrandom, &seed, sizeof(seed), 0) != sizeof(seed)) {
            /* Fallback: /dev/urandom */
            int urfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
            if (urfd >= 0) {
                (void)read(urfd, &seed, sizeof(seed));
                close(urfd);
            }
        }
#endif
        engine_session_seed = seed;
        vault_log(LOG_INFO, "%s engine session seed initialized (seed=%u)",
                  ENGINE_LOG_PREFIX, engine_session_seed);
    }

    char decoy_root[PATH_MAX];
    snprintf(decoy_root, sizeof(decoy_root), "%s/%s", v->path, ENGINE_DECOY_DIR);

    VaultErrorr err = engine_mkdir(decoy_root);
    if (err != ERR_OK)
    {
        vault_log(LOG_ERROR, "%s failed to create decoy root directory: %s",
                  ENGINE_LOG_PREFIX, vault_strerror(err));
        return err;
    }

    char real_dir[PATH_MAX];
    snprintf(real_dir, sizeof(real_dir), "%s/%s", v->path, ENGINE_REAL_DIR);

    err = engine_mkdir(real_dir);
    if (err != ERR_OK)
    {
        vault_log(LOG_ERROR, "%s failed to create real directory: %s",
                  ENGINE_LOG_PREFIX, vault_strerror(err));
        return err;
    }

    if (chmod(real_dir, 0700) != 0)
    {
        vault_log(LOG_WARN, "%s chmod(0700) on real_dir: %s",
                  ENGINE_LOG_PREFIX, strerror(errno));
    }

    int max_depth = ENGINE_TREE_DEPTH[level];
    int branch = ENGINE_TREE_BRANCH[level];
    bool binary = (level >= 4);

    long estimated_nodes = engine_estimate_nodes(branch, max_depth);
    long estimated_files = estimated_nodes * 26;

    vault_log(LOG_INFO,
              "%s engine %d: depth=%d branch=%d — estimated %ld nodes, ~%ld decoy files, mode=%s",
              ENGINE_LOG_PREFIX, level, max_depth, branch, estimated_nodes, estimated_files,
              binary ? "binary" : "text");

    /* [FIX-9] Refuse before touching disk if this configuration is too big. */
    if (estimated_nodes > ENGINE_MAX_DECOY_NODES)
    {
        vault_log(LOG_ERROR,
                  "%s engine %d refused: %ld estimated nodes exceeds safety cap (%d) — "
                  "check ENGINE_TREE_DEPTH/ENGINE_TREE_BRANCH for level %d",
                  ENGINE_LOG_PREFIX, level, estimated_nodes, ENGINE_MAX_DECOY_NODES, level);
        return ERR_INVALID_ARGS;
    }

    int layers_ok = 0;
    int layers_failed = 0;

    /* [FIX-7] True N-ary tree: decoy_root has 'branch' children at depth 1,
     * each of those has 'branch' children at depth 2, and so on down to
     * 'max_depth'. Siblings are independent of each other. */
    engine_build_subtree(v, decoy_root, 1, max_depth, branch, binary,
                         &layers_ok, &layers_failed);

    vault_log(LOG_INFO,
              "%s engine %d applied to vault '%s': %d/%ld nodes OK, %d failures",
              ENGINE_LOG_PREFIX, level, v->name,
              layers_ok, estimated_nodes, layers_failed);

    /* [FIX-3] Cleanup if labyrinth remained partial */
    if (layers_failed > 0)
    {
        vault_log(LOG_ERROR,
                  "%s engine %d INCOMPLETE: %d nodes failed — running cleanup",
                  ENGINE_LOG_PREFIX, level, layers_failed);
        engine_cleanup_decoy(decoy_root);
        return ERR_IO;
    }

    if (level == 5)
    {
        vault_log(LOG_INFO,
                  "%s engine 5: depth-%d branch-%d labyrinth created. "
                  "OverlayFS will be implemented in future phase.",
                  ENGINE_LOG_PREFIX, max_depth, branch);
    }

    vault_log(LOG_INFO, "%s engine %d fully applied to vault '%s'",
              ENGINE_LOG_PREFIX, level, v->name);

    return ERR_OK;
}

/* [FIX-8] Since extensions are now random per file, validation can't guess
 * the exact filename anymore — it scans the directory instead and accepts
 * any "<letter>.<ext>" where <ext> is one of the known pools. Returns the
 * count of the 26 expected letters ('a'-'z') NOT found as a regular file. */
static int engine_check_layer_files(const char *layer_path, bool binary)
{
#ifndef __linux__
    (void)layer_path;
    (void)binary;
    return 26; /* dirent not available on this platform build */
#else
    bool found[26] = {0};

    DIR *d = opendir(layer_path);
    if (!d)
    {
        vault_log(LOG_ERROR, "%s opendir('%s'): %s",
                  ENGINE_LOG_PREFIX, layer_path, strerror(errno));
        return 26;
    }

    const char **pool = binary ? BINARY_EXT_POOL : TEXT_EXT_POOL;
    int pool_count = binary ? BINARY_EXT_COUNT : TEXT_EXT_COUNT;

    struct dirent *de;
    while ((de = readdir(d)) != NULL)
    {
        const char *name = de->d_name;
        char letter = name[0];
        if (letter < 'a' || letter > 'z' || name[1] != '.' || name[2] == '\0')
            continue;

        const char *ext = name + 2;
        for (int i = 0; i < pool_count; i++)
        {
            if (strcmp(ext, pool[i]) == 0)
            {
                found[letter - 'a'] = true;
                break;
            }
        }
    }
    closedir(d);

    int missing = 0;
    for (int i = 0; i < 26; i++)
        if (!found[i])
            missing++;

    return missing;
#endif
}

/* [FIX-7] Recursively validates an N-ary decoy tree. Unlike the old funnel
 * (which stopped at the first missing layer, hiding the state of everything
 * below it), a missing node here only stops descent into THAT branch —
 * sibling branches are still checked independently. */
static void engine_validate_subtree(const char *parent_path, int depth, int max_depth,
                                    int branch, bool binary,
                                    int *missing_layers, int *missing_files)
{
    if (depth > max_depth)
        return;

    for (int idx = 0; idx < branch; idx++)
    {
        char dirname[64];
        engine_child_dirname(dirname, sizeof(dirname), depth, idx);

        char node_path[PATH_MAX];
        snprintf(node_path, sizeof(node_path), "%s/%s", parent_path, dirname);

        struct stat st;
        if (stat(node_path, &st) != 0 || !S_ISDIR(st.st_mode))
        {
            vault_log(LOG_ERROR, "%s missing node: %s", ENGINE_LOG_PREFIX, node_path);
            (*missing_layers)++;
            continue; /* can't descend into a node that doesn't exist, but
                       * siblings are unaffected — keep checking them */
        }

        int missing_here = engine_check_layer_files(node_path, binary);
        if (missing_here > 0)
        {
            vault_log(LOG_WARN, "%s node '%s': %d/26 decoy files missing",
                      ENGINE_LOG_PREFIX, node_path, missing_here);
            (*missing_files) += missing_here;
        }

        engine_validate_subtree(node_path, depth + 1, max_depth, branch, binary,
                                missing_layers, missing_files);
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  engine_validate() — checks labyrinth integrity
 * ───────────── */
VaultErrorr engine_validate(Vault *v)
{
    if (!v)
    {
        vault_log(LOG_ERROR, "%s engine_validate: vault NULL", ENGINE_LOG_PREFIX);
        return ERR_INVALID_ARGS;
    }

    int level = v->engine_level;

    if (level == 0)
    {
        vault_log(LOG_INFO, "%s engine_validate: engine 0 — nothing to validate", ENGINE_LOG_PREFIX);
        return ERR_OK;
    }

    if (level < ENGINE_LEVEL_MIN || level > ENGINE_LEVEL_MAX)
    {
        vault_log(LOG_ERROR, "%s engine_validate: invalid level %d",
                  ENGINE_LOG_PREFIX, level);
        return ERR_INVALID_ARGS;
    }

    vault_log(LOG_INFO, "%s validating engine %d for vault '%s'",
              ENGINE_LOG_PREFIX, level, v->name);

    char decoy_root[PATH_MAX];
    snprintf(decoy_root, sizeof(decoy_root), "%s/%s", v->path, ENGINE_DECOY_DIR);

    struct stat st;
    if (stat(decoy_root, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s decoy directory missing: %s",
                  ENGINE_LOG_PREFIX, decoy_root);
        return ERR_INTEGRITY;
    }

    char real_dir[PATH_MAX];
    snprintf(real_dir, sizeof(real_dir), "%s/%s", v->path, ENGINE_REAL_DIR);

    if (stat(real_dir, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s real directory missing: %s",
                  ENGINE_LOG_PREFIX, real_dir);
        return ERR_INTEGRITY;
    }

    int max_depth = ENGINE_TREE_DEPTH[level];
    int branch = ENGINE_TREE_BRANCH[level];
    bool binary = (level >= 4);
    int missing_layers = 0;
    int missing_files = 0;

    /* [FIX-7] Same recursive descent used in engine_apply() — depth/branch
     * must match exactly, otherwise validation checks the wrong locations. */
    engine_validate_subtree(decoy_root, 1, max_depth, branch, binary,
                            &missing_layers, &missing_files);

    if (missing_layers > 0 || missing_files > 0)
    {
        vault_log(LOG_ERROR,
                  "%s validation FAILED: %d missing nodes, %d missing files",
                  ENGINE_LOG_PREFIX, missing_layers, missing_files);

        char reason[256];
        snprintf(reason, sizeof(reason),
                 "Engine %d compromised: %d nodes, %d files removed",
                 level, missing_layers, missing_files);
        alert_trigger(v, reason);

        return ERR_INTEGRITY;
    }

    vault_log(LOG_INFO,
              "%s engine %d for vault '%s' SUCCESSFULLY VALIDATED (depth=%d branch=%d)",
              ENGINE_LOG_PREFIX, level, v->name, max_depth, branch);
    return ERR_OK;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  [FIX-2] engine_is_decoy_path_v() — safe version with realpath
 * ───────────── */
bool engine_is_decoy_path_v(const Vault *v, const char *path)
{
    if (!v || !path)
        return false;

    char decoy_root[PATH_MAX];
    char decoy_resolved[PATH_MAX];
    char path_resolved[PATH_MAX];

    snprintf(decoy_root, sizeof(decoy_root), "%s/%s", v->path, ENGINE_DECOY_DIR);

    if (!realpath(decoy_root, decoy_resolved))
        return false;
    if (!realpath(path, path_resolved))
        return false;

    size_t dlen = strlen(decoy_resolved);

    return (strncmp(path_resolved, decoy_resolved, dlen) == 0 &&
            (path_resolved[dlen] == '/' || path_resolved[dlen] == '\0'));
}