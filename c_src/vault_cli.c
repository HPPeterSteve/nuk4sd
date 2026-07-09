/*
 * vault_cli.c
 *
 * Nuk4sd — CLI flag parser completo (estilo bwrap)
 *
 * Ponto de entrada único: vault_cli_parse_and_exec(argc, argv)
 * Parseia todas as flags via getopt_long e despacha ao core C.
 *
 * Flags de isolamento usam os wrappers públicos vsb_* de vault_sandbox.c:
 *   vsb_drop_caps()         → sandbox_drop_caps()
 *   vsb_apply_seccomp()     → apply_seccomp_policy()
 *   vsb_pivot_root()        → sandbox_pivot_root()
 *   vsb_prepare_mounts()    → sandbox_prepare_mounts()
 *   vsb_write_uid_gid_map() → sandbox_write_uid_gid_map()
 *   vsb_prepare_jail()      → vault_prepare_jail()
 *
 * Uso:
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

#include <getopt.h>
#include <termios.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <fcntl.h>

#ifdef __linux__
#include <sched.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  WORM bits — espelha vault_core.h
 * ═══════════════════════════════════════════════════════════════════════════ */
#ifndef WORM_PROTECT_DELETE
#define WORM_PROTECT_DELETE  (1u << 0)
#define WORM_PROTECT_RENAME  (1u << 1)
#define WORM_PROTECT_WRITE   (1u << 2)
#define WORM_PROTECT_SCAN    (1u << 3)
#define WORM_PROTECT_READ    (1u << 4)
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  Bind-mount entry para --ro / --rw / --blacklist
 * ═══════════════════════════════════════════════════════════════════════════ */
#define MAX_BINDS 64

typedef enum { BIND_RO, BIND_RW, BIND_BLACKLIST } BindType;

typedef struct {
    char     path[VAULT_PATH_MAX];
    BindType type;
} BindEntry;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Struct de configuração — preenchida pelo getopt_long
 * ═══════════════════════════════════════════════════════════════════════════ */
typedef struct {
    /* --vault <id> */
    int32_t vault_id;

    /* Operações de vault */
    bool op_ls, op_info, op_files, op_status, op_scan;
    bool op_encrypt, op_decrypt, op_resolve;
    bool op_mount, op_umount, op_mount_export, op_export;
    bool op_rm, op_unlock, op_passwd, op_rule;
    bool op_worm_status, op_help, op_version;
    bool op_rename;

    /* --export */
    char *export_file;
    char *export_dest;

    /* --rename */
    char *rename_to;

    /* --rule */
    int rule_max_fails;
    int rule_hour_from;
    int rule_hour_to;

    /* --new */
    char *new_name;
    char *new_path;
    bool  protected_vault;
    int   engine_level;

    /* WORM */
    uint32_t worm_set;
    uint32_t worm_clear;
    bool     worm_protected_scan;

    /* --run */
    char  *run_exec;
    char **run_argv;
    int    run_argc;

    /* Flags de isolamento básico */
    bool       iso_no_net;
    bool       iso_pivot_root;
    bool       iso_wayland;
    bool       iso_x11;
    bool       iso_ro_home;
    bool       iso_no_dbus;
    bool       iso_tmp_home;
    bool       iso_audit;
    bool       iso_no_proc;
    bool       iso_new_session;
    bool       iso_unshare_ipc;
    bool       iso_unshare_uts;
    char      *iso_hostname;
    char      *iso_profile;   /* arquivo de perfil no disco */

    /* Desktop runtime (novo) */
    bool       iso_audio;        /* --audio: PipeWire + PulseAudio  */
    bool       iso_dbus_session; /* --dbus session                  */
    bool       iso_dbus_system;  /* --dbus system                   */
    bool       iso_gpu;          /* --gpu: /dev/dri                 */
    bool       iso_xdg_runtime;  /* --xdg-runtime: /run/user/$UID  */
    int        iso_dev_level;    /* --dev minimal(1)/standard(2)   */
    bool       iso_no_seccomp;   /* --no-seccomp: debug/sem BPF    */
    bool       iso_use_chroot;   /* --chroot: usa chroot em vez de pivot_root */
    char      *iso_display;      /* --display :N                   */
    char      *iso_wayland_disp; /* --wayland-display <nome>        */
    char      *iso_preset;       /* --preset firefox/office/dev...  */
    bool       seccomp_strict;   /* --seccomp-strict (-q)           */
    bool       allow_clone3;     /* --allow-clone3 (-k)             */

    /* Limites de recurso (0 = padrão interno) */
    int        iso_max_procs;    /* --max-procs <N>                */
    int        iso_max_mem_gb;   /* --max-mem <GB>                 */
    int        iso_max_fsize_mb; /* --max-filesize <MB>            */
    int        iso_max_fds;      /* --max-fds <N>                  */
    int        iso_tmp_size_mb;  /* --tmp-size <MB>                */

    BindEntry  binds[MAX_BINDS];
    int        bind_count;

    /* Gerais */
    bool  verbose;
    bool  debug;                 /* --debug */
    bool  json_output;
    char *password;
} CliConfig;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Enum de opções longas
 * ═══════════════════════════════════════════════════════════════════════════ */
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
    /* run */
    OPT_RUN,
    /* isolamento básico */
    OPT_NO_NET, OPT_WAYLAND, OPT_X11,
    OPT_RO_HOME, OPT_NO_DBUS, OPT_TMP_HOME,
    OPT_RO, OPT_RW, OPT_BLACKLIST,
    OPT_AUDIT, OPT_NO_PROC, OPT_NEW_SESSION,
    OPT_UNSHARE_IPC, OPT_UNSHARE_UTS,
    OPT_HOSTNAME, OPT_PROFILE,
    /* desktop runtime */
    OPT_AUDIO, OPT_DBUS, OPT_GPU, OPT_XDG_RUNTIME,
    OPT_DEV, OPT_NO_SECCOMP, OPT_CHROOT,OPT_PIVOT_ROOT,
    OPT_DISPLAY_OPT, OPT_WAYLAND_DISPLAY,
    OPT_PRESET,
    /* limites de recurso */
    OPT_MAX_PROCS, OPT_MAX_MEM, OPT_MAX_FSIZE, OPT_MAX_FDS, OPT_TMP_SIZE,
    /* gerais */
    OPT_PASSWORD, OPT_VERBOSE, OPT_DEBUG, OPT_JSON, OPT_VERSION, OPT_HELP,
    /* strict seccomp */
    OPT_SECCOMP_STRICT = 'q',
    OPT_ALLOW_CLONE3   = 'k',
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
    { "run",             required_argument, NULL, OPT_RUN },
    { "no-net",          no_argument,       NULL, OPT_NO_NET },
    { "wayland",         no_argument,       NULL, OPT_WAYLAND },
    { "x11",             no_argument,       NULL, OPT_X11 },
    { "ro-home",         no_argument,       NULL, OPT_RO_HOME },
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
    { "no-seccomp",      no_argument,       NULL, OPT_NO_SECCOMP },
    { "pivot-root",      no_argument,       NULL, OPT_PIVOT_ROOT },
    { "chroot",          no_argument,       NULL, OPT_CHROOT },
    { "display",         required_argument, NULL, OPT_DISPLAY_OPT },
    { "wayland-display", required_argument, NULL, OPT_WAYLAND_DISPLAY },
    { "preset",          required_argument, NULL, OPT_PRESET },
    /* limites de recurso */
    { "max-procs",       required_argument, NULL, OPT_MAX_PROCS },
    { "max-mem",         required_argument, NULL, OPT_MAX_MEM },
    { "max-filesize",    required_argument, NULL, OPT_MAX_FSIZE },
    { "max-fds",         required_argument, NULL, OPT_MAX_FDS },
    { "tmp-size",        required_argument, NULL, OPT_TMP_SIZE },
    { "help",            no_argument, NULL, OPT_HELP },
    /* gerais */
    { "password",        required_argument, NULL, OPT_PASSWORD },
    { "verbose",         no_argument,       NULL, OPT_VERBOSE },
    { "debug",           no_argument,       NULL, OPT_DEBUG },
    { "json",            no_argument,       NULL, OPT_JSON },
    { "version",         no_argument,       NULL, OPT_VERSION },
    { "seccomp-strict",  no_argument,       NULL, 'q' },
    { "allow-clone3",    no_argument,       NULL, 'k' },
    { NULL, 0, NULL, 0 }
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */
static void print_ok(const char *msg)   { printf("\033[32m✔ %s\033[0m\n", msg); }
static void print_err(const char *msg)  { fprintf(stderr, "\033[31m✖ %s\033[0m\n", msg); }
static void print_warn(const char *msg) { fprintf(stderr, "\033[33m⚠ %s\033[0m\n", msg); }

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

/* ═══════════════════════════════════════════════════════════════════════════
 *  Help
 * ═══════════════════════════════════════════════════════════════════════════ */
static void print_help(void) {
    printf(
"\nNuk4sd — hardened vault & isolation engine\n"
"Usage: Nuk4sd [--vault <id>] <operation> [flags]\n\n"

"── Vault ──────────────────────────────────────────────────────────\n"
"  --ls                         list all vaults\n"
"  --vault <id>                 select vault\n"
"    --info                     show full details\n"
"    --files                    list tracked files + SHA-256 hashes\n"
"    --status                   quick status (OK/LOCKED/ALERT/DELETED)\n"
"    --scan                     SHA-256 integrity scan\n"
"    --encrypt                  encrypt all files (AES-256-GCM)\n"
"    --decrypt                  decrypt all files\n"
"    --resolve                  resolve active integrity alert\n"
"    --mount                    mount vault via FUSE\n"
"    --umount                   unmount FUSE\n"
"    --export [--file <f>]      rescue file(s) from vault\n"
"      --dest <dir>             destination directory\n"
"    --mount-export             rescue from PROTECTED-SCAN vault (bypass FUSE)\n"
"    --rm                       delete vault (irreversible)\n"
"    --rename <name>            rename vault in catalog\n"
"    --unlock                   unlock after failed-attempt lockout\n"
"    --passwd                   change vault password (PBKDF2)\n"
"    --rule <n>                 add security rule (n = max password fails)\n"
"      --hours <from>-<to>      time window e.g. --hours 9-18\n\n"

"── Create ─────────────────────────────────────────────────────────\n"
"  --new <name>                 create new vault\n"
"    --path <dir>               vault directory (default: catalog location)\n"
"    --protected                require password (AES-256-GCM + PBKDF2)\n"
"    --engine <0-5>             obfuscation engine level\n"
"                               0 = none  1 = 1 layer + decoys\n"
"                               2 = 3 layers  3 = 6 layers\n"
"                               4 = 16 layers + fake .enc\n"
"                               5 = 20 layers + fake .enc\n\n"

"── WORM Protection ────────────────────────────────────────────────\n"
"  --vault <id> --worm-status           show active WORM flags\n"
"  --vault <id> --protect-delete        block unlink/rmdir → EPERM\n"
"  --vault <id> --protect-rename        block rename → EPERM\n"
"  --vault <id> --protect-write         block write on existing files → EPERM\n"
"  --vault <id> --protect-read          block read → EPERM\n"
"  --vault <id> --protected-scan        MAX protection (irreversible, use mount-export to rescue)\n"
"  --vault <id> --clear-delete          remove delete block\n"
"  --vault <id> --clear-rename          remove rename block\n"
"  --vault <id> --clear-write           remove write block\n"
"  --vault <id> --clear-read            remove read block\n\n"

"── Run Program in Vault Sandbox ───────────────────────────────────\n"
"  --vault <id> --run <exec> [-- exec-args...]\n\n"
"  Filesystem:\n"
"    --ro <path>          bind mount path read-only inside sandbox\n"
"    --rw <path>          bind mount path read-write inside sandbox\n"
"    --blacklist <path>   make path invisible (tmpfs/null over it)\n"
"    --ro-home            bind mount $HOME read-only\n"
"    --tmp-home           ephemeral $HOME in tmpfs (vanishes on exit)\n\n"
"  Network:\n"
"    --no-net             unshare network namespace (full isolation)\n\n"
"  Display:\n"
"    --wayland            pass Wayland socket + XDG_RUNTIME_DIR (read-only)\n"
"    --x11                pass X11 socket /tmp/.X11-unix (read-only)\n\n"
"  D-Bus:\n"
"    --no-dbus            remove DBUS_SESSION_BUS_ADDRESS + cover socket\n\n"
"  Namespaces:\n"
"    --unshare-ipc        isolate IPC namespace (SysV shm/sem/mq)\n"
"    --unshare-uts        isolate UTS namespace (hostname)\n"
"    --hostname <name>    set sandbox hostname (requires --unshare-uts)\n"
"    --new-session        setsid() — detach from controlling terminal\n"
"    --no-proc            do not mount /proc inside sandbox\n\n"
"  Audit:\n"
"    --audit              log exec args, all bind mounts, env changes\n\n"
"  Profile:\n"
"    --profile <file>     load isolation flags from .conf file\n"
"                         (one flag per line, e.g. --no-net)\n\n"

"── General ────────────────────────────────────────────────────────\n"
"  --password <pass>      provide password inline (prompted if omitted)\n"
"  --verbose              verbose output\n"
"  --json                 JSON output for --status and --scan\n"
"  --version              show version\n"
"  --help                 this help\n\n"

"Examples:\n"
"  Nuk4sd --ls\n"
"  Nuk4sd --vault 3 --encrypt\n"
"  Nuk4sd --vault 3 --scan --verbose\n"
"  Nuk4sd --vault 3 --run firefox --no-net --wayland\n"
"  Nuk4sd --vault 3 --run gimp --wayland --ro /usr/share/fonts\n"
"  Nuk4sd --vault 3 --run bash --no-net --unshare-ipc --no-proc --audit\n"
"  Nuk4sd --vault 3 --run code --wayland --rw ~/projects --blacklist ~/.ssh\n"
"  Nuk4sd --vault 3 --run mpv --x11 --ro /media/films -- /media/films/movie.mkv\n"
"  Nuk4sd --new work --path /data/work --protected --engine 2\n"
"  Nuk4sd --vault 3 --protect-delete --protect-write\n"
"  Nuk4sd --vault 3 --export --dest ~/rescued --file secret.pdf.enc\n\n"
    );
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Profile loader
 *  Formato: uma flag por linha, linhas com # são comentários
 *
 *  Exemplo ~/.config/Nuk4sd/browser.conf:
 *    # perfil para navegadores
 *    --no-net
 *    --wayland
 *    --ro /usr/share/fonts
 *    --blacklist ~/.ssh
 *    --blacklist ~/.gnupg
 * ═══════════════════════════════════════════════════════════════════════════ */
static void load_profile(CliConfig *cfg, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "⚠ profile '%s' not found\n", path); return; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Remove comentário e whitespace */
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
        else if (!strcmp(p, "--no-dbus"))       cfg->iso_no_dbus     = true;
        else if (!strcmp(p, "--tmp-home"))      cfg->iso_tmp_home    = true;
        else if (!strcmp(p, "--audit"))         cfg->iso_audit       = true;
        else if (!strcmp(p, "--no-proc"))       cfg->iso_no_proc     = true;
        else if (!strcmp(p, "--new-session"))   cfg->iso_new_session = true;
        else if (!strcmp(p, "--unshare-ipc"))   cfg->iso_unshare_ipc = true;
        else if (!strcmp(p, "--unshare-uts"))   cfg->iso_unshare_uts = true;
        else if (!strncmp(p, "--ro ", 5) && cfg->bind_count < MAX_BINDS) {
            strncpy(cfg->binds[cfg->bind_count].path, p+5, VAULT_PATH_MAX-1);
            cfg->binds[cfg->bind_count++].type = BIND_RO;
        }
        else if (!strncmp(p, "--rw ", 5) && cfg->bind_count < MAX_BINDS) {
            strncpy(cfg->binds[cfg->bind_count].path, p+5, VAULT_PATH_MAX-1);
            cfg->binds[cfg->bind_count++].type = BIND_RW;
        }
        else if (!strncmp(p, "--blacklist ", 12) && cfg->bind_count < MAX_BINDS) {
            strncpy(cfg->binds[cfg->bind_count].path, p+12, VAULT_PATH_MAX-1);
            cfg->binds[cfg->bind_count++].type = BIND_BLACKLIST;
        }
        else {
            fprintf(stderr, "⚠ profile '%s': unknown flag '%s' — skipped\n", path, p);
        }
    }
    fclose(f);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Helpers de Parsing
 * ═══════════════════════════════════════════════════════════════════════════ */
static long parse_int_arg(const char *s, long min, long max, const char *flag_name, int *err) {
    char *endptr;
    errno = 0;
    long val = strtol(s, &endptr, 10);
    if (errno != 0 || endptr == s || *endptr != '\0') {
        fprintf(stderr, "⚠ invalid integer for %s: '%s'\n", flag_name, s);
        if (err) *err = 1;
        return 0;
    }
    if (val < min || val > max) {
        fprintf(stderr, "⚠ value for %s out of range [%ld..%ld]: %ld\n", flag_name, min, max, val);
        if (err) *err = 1;
        return 0;
    }
    return val;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Parser principal
 * ═══════════════════════════════════════════════════════════════════════════ */
static int parse_flags(int argc, char **argv, CliConfig *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->vault_id       = -1;
    cfg->rule_hour_from = -1;
    cfg->rule_hour_to   = -1;

    /* CRÍTICO: optind é estático/global na libc e persiste entre chamadas
     * de getopt_long() dentro do mesmo processo. Como vault_cli_parse_and_exec()
     * pode ser invocado múltiplas vezes no mesmo processo (REPL — um comando
     * por linha), é obrigatório resetar o estado do getopt aqui, senão o
     * segundo comando em diante começa o parse além do fim do novo argv e
     * nenhuma flag é reconhecida (cai sempre no print_help() do dispatcher).
     * optind = 0 é a extensão GNU que força reinicialização completa,
     * inclusive do ponteiro interno nextchar — optind = 1 sozinho não é
     * suficiente em todos os casos. */
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
        /* run */
        case OPT_RUN: cfg->run_exec = optarg; break;
        /* isolamento */
        case OPT_NO_NET:       cfg->iso_no_net      = true;   break;
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
            if      (!strcmp(optarg, "minimal"))  cfg->iso_dev_level = 1;
            else if (!strcmp(optarg, "standard")) cfg->iso_dev_level = 2;
            else { print_err("--dev: use 'minimal' or 'standard'"); return -1; }
            break;
        /* limites de recurso */
        case OPT_MAX_PROCS:   cfg->iso_max_procs    = atoi(optarg); break;
        case OPT_MAX_MEM:     cfg->iso_max_mem_gb   = atoi(optarg); break;
        case OPT_MAX_FSIZE:   cfg->iso_max_fsize_mb = atoi(optarg); break;
        case OPT_MAX_FDS:     cfg->iso_max_fds      = atoi(optarg); break;
        case OPT_TMP_SIZE:    cfg->iso_tmp_size_mb  = atoi(optarg); break;
        /* gerais */
        case OPT_PASSWORD: cfg->password    = optarg; break;
        case OPT_VERBOSE:  cfg->verbose     = true;   break;
        case OPT_DEBUG:    cfg->debug       = true;   break;
        case OPT_JSON:     cfg->json_output = true;   break;
        case OPT_VERSION:  cfg->op_version  = true;   break;
        case OPT_HELP:     cfg->op_help     = true;   break;
        case 'q':          cfg->seccomp_strict = true; break;
        case 'k':          cfg->allow_clone3   = true; break;
        /* bind mounts */
        case OPT_RO:
            if (cfg->bind_count < MAX_BINDS) {
                strncpy(cfg->binds[cfg->bind_count].path, optarg, VAULT_PATH_MAX-1);
                cfg->binds[cfg->bind_count++].type = BIND_RO;
            }
            break;
        case OPT_RW:
            if (cfg->bind_count < MAX_BINDS) {
                strncpy(cfg->binds[cfg->bind_count].path, optarg, VAULT_PATH_MAX-1);
                cfg->binds[cfg->bind_count++].type = BIND_RW;
            }
            break;
        case OPT_BLACKLIST:
            if (cfg->bind_count < MAX_BINDS) {
                strncpy(cfg->binds[cfg->bind_count].path, optarg, VAULT_PATH_MAX-1);
                cfg->binds[cfg->bind_count++].type = BIND_BLACKLIST;
            }
            break;
        case '?':
        default:
            fprintf(stderr, "  Use --help for usage.\n");
            return -1;
        }
    }

    /* Argumentos após -- são passados diretamente ao exec */
    if (cfg->run_exec && optind < argc) {
        cfg->run_argv = &argv[optind];
        cfg->run_argc = argc - optind;
    }

    /* Carrega profile de arquivo se especificado */
    if (cfg->iso_profile)
        load_profile(cfg, cfg->iso_profile);

    /* Aplica preset built-in (antes do profile de arquivo para que flags
     * explícitas na linha de comando sobrescrevam o preset) */
    if (cfg->iso_preset) {
        const char *p = cfg->iso_preset;
        if (!strcmp(p, "firefox") || !strcmp(p, "browser")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_audio        = true;
            cfg->iso_dbus_session = true;
            cfg->iso_gpu          = true;
            cfg->iso_xdg_runtime  = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 2;  /* standard */
        } else if (!strcmp(p, "office")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_audio        = true;
            cfg->iso_dbus_session = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 1;  /* minimal */
        } else if (!strcmp(p, "dev") || !strcmp(p, "code")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_dbus_session = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 1;
        } else if (!strcmp(p, "media")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_audio        = true;
            cfg->iso_gpu          = true;
            cfg->iso_xdg_runtime  = true;
        } else if (!strcmp(p, "minimal")) {
            /* sandbox básico sem display */
        } else {
            fprintf(stderr, "⚠ preset '%s' desconhecido. Disponíveis: firefox, browser, office, dev, code, media, minimal\n", p);
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  run_isolated() — executa programa dentro do sandbox do vault
 *
 *  Usa os wrappers públicos vsb_* de vault_sandbox.c que expõem as funções
 *  internas do sandbox de 5 camadas já implementado:
 *    vsb_prepare_jail()      → prepara estrutura de diretórios do jail
 *    vsb_write_uid_gid_map() → escreve uid_map/gid_map no filho
 *    vsb_pivot_root()        → pivot_root para o vault
 *    vsb_prepare_mounts()    → monta /proc e /tmp dentro do jail
 *    vsb_drop_caps()         → remove todas as capabilities Linux
 *    vsb_apply_seccomp()     → carrega BPF allowlist completa
 *
 *  Isolamento adicional gerenciado aqui:
 *    --ro/--rw/--blacklist → bind mounts antes do pivot
 *    --ro-home             → bind read-only do $HOME
 *    --tmp-home            → tmpfs vazio como $HOME
 *    --wayland             → bind /run/user/<uid> read-only + env vars
 *    --x11                 → bind /tmp/.X11-unix read-only
 *    --no-dbus             → remove env + cobre socket
 *    --no-net              → CLONE_NEWNET
 *    --unshare-ipc         → CLONE_NEWIPC
 *    --unshare-uts         → CLONE_NEWUTS + sethostname
 *    --new-session         → setsid()
 *    --no-proc             → não monta /proc
 * ═══════════════════════════════════════════════════════════════════════════ */
#ifdef __linux__

static int run_isolated(CliConfig *cfg, char *vault_path) {
    bool gui_mode = cfg->iso_wayland || cfg->iso_x11;

    vsb_set_debug(cfg->debug);

    /* Prepara estrutura de jail dentro do vault usando o vault_sandbox.c */
    vsb_prepare_jail(vault_path, gui_mode);

    /* Pipes de sincronização pai ↔ filho (mesmo padrão do vault_sandbox_open) */
    int sync_pipe[2], ready_pipe[2];
    if (pipe(sync_pipe) != 0 || pipe(ready_pipe) != 0) {
        perror("[RUN] pipe"); return -1;
    }

    /* Audit: loga configuração antes de forkar */
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

    /* ── Log massivo da configuração do sandbox ─────────────────────────── */
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

    /* ════════════════════════════════════════════════════════════════════
     *  PROCESSO PAI — escreve uid/gid map e aguarda o filho
     * ════════════════════════════════════════════════════════════════════ */
    if (pid > 0) {
        vault_auth_pid_add_ffi(pid);

        close(ready_pipe[1]);
        close(sync_pipe[0]);

        /* Aguarda filho sinalizar que fez unshare(CLONE_NEWUSER) */
        char c;
        if (read(ready_pipe[0], &c, 1) != 1)
            perror("[RUN] ready_pipe read");
        close(ready_pipe[0]);

        /* Escreve uid_map/gid_map usando o helper do vault_sandbox.c */
        vsb_write_uid_gid_map(pid);

        /* Libera filho para continuar */
        close(sync_pipe[1]);

        int status;
        waitpid(pid, &status, 0);
        vault_auth_pid_remove_ffi(pid);

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

    /* ════════════════════════════════════════════════════════════════════
     *  PROCESSO FILHO — sandbox de 5 camadas + isolamentos extras
     * ════════════════════════════════════════════════════════════════════ */
    close(sync_pipe[1]);
    close(ready_pipe[0]);
    prctl(PR_SET_NAME, "Nuk4sd-Run", 0, 0, 0);

    /* ── [Camada 1] User Namespace ──────────────────────────────────────── */
    if (unshare(CLONE_NEWUSER) != 0) {
        fprintf(stderr, "[RUN] unshare CLONE_NEWUSER: %s\n", strerror(errno));
        cli_log_namespace_event("CLONE_NEWUSER", CLONE_NEWUSER, getpid(), errno);
        _exit(1);
    }
    cli_log_namespace_event("CLONE_NEWUSER", CLONE_NEWUSER, getpid(), 0);
    /* Avisa pai: user namespace pronta para receber uid/gid map */
    { char r = 'r'; write(ready_pipe[1], &r, 1); close(ready_pipe[1]); }
    /* Aguarda pai escrever uid_map/gid_map */
    { char r; read(sync_pipe[0], &r, 1); close(sync_pipe[0]); }

    /* ── [Camada 2] Namespaces adicionais ───────────────────────────────── */
    int ns_flags = CLONE_NEWNS | CLONE_NEWPID;
    if (cfg->iso_no_net)      ns_flags |= CLONE_NEWNET;
    if (cfg->iso_unshare_ipc) ns_flags |= CLONE_NEWIPC;
    if (cfg->iso_unshare_uts) ns_flags |= CLONE_NEWUTS;

    if (unshare(ns_flags) != 0) {
        fprintf(stderr, "[RUN] unshare namespaces (0x%x): %s\n",
                ns_flags, strerror(errno));
        cli_log_namespace_event("MOUNT|PID|...", ns_flags, getpid(), errno);
        _exit(1);
    }
    cli_log_namespace_event("CLONE_NEWNS|CLONE_NEWPID|extras", ns_flags, getpid(), 0);

    /* Hostname isolado dentro do UTS namespace */
    if (cfg->iso_unshare_uts && cfg->iso_hostname)
        sethostname(cfg->iso_hostname, strlen(cfg->iso_hostname));

    /* Detach do terminal */
    if (cfg->iso_new_session)
        setsid();

    /* Fork para virar PID 1 dentro do PID namespace */
    pid_t ns_pid = fork();
    if (ns_pid < 0)  { perror("[RUN] fork PID NS"); _exit(1); }
    if (ns_pid > 0)  {
        int st;
        waitpid(ns_pid, &st, 0);
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
    }

    /* ════════════════ PID 1 dentro do namespace ════════════════════════ */

    /* Torna o mount tree privado para que os bind mounts não vazem */
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
        perror("[RUN] MS_PRIVATE / (non-fatal)");
    cli_log_mount_event("none", "/", "private", MS_REC | MS_PRIVATE,
                        (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0 ? errno : 0));

    /* ── Bind mounts --ro / --rw / --blacklist ──────────────────────────── */
    for (int i = 0; i < cfg->bind_count; i++) {
        const char *src = cfg->binds[i].path;
        struct stat st;
        if (stat(src, &st) != 0) {
            fprintf(stderr, "[RUN] bind: '%s' not found — skipping\n", src);
            continue;
        }

        switch (cfg->binds[i].type) {

        case BIND_RO:
            if (mount(src, src, NULL, MS_BIND | MS_REC, NULL) == 0) {
                mount(NULL, src, NULL,
                      MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
                cli_log_mount_event(src, src, "bind-ro",
                                    MS_BIND | MS_REC | MS_RDONLY, 0);
            } else {
                fprintf(stderr, "[RUN] --ro bind '%s': %s\n", src, strerror(errno));
                cli_log_mount_event(src, src, "bind-ro", MS_BIND | MS_REC, errno);
            }
            break;

        case BIND_RW:
            if (mount(src, src, NULL, MS_BIND | MS_REC, NULL) != 0) {
                fprintf(stderr, "[RUN] --rw bind '%s': %s\n", src, strerror(errno));
                cli_log_mount_event(src, src, "bind-rw", MS_BIND | MS_REC, errno);
            } else {
                cli_log_mount_event(src, src, "bind-rw", MS_BIND | MS_REC, 0);
            }
            break;

        case BIND_BLACKLIST:
            /* Diretório: monta tmpfs vazio sobre ele (tamanho 0 = somente leitura) */
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
                /* Arquivo: bind monta /dev/null sobre ele */
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

    /* ── --ro-home: $HOME read-only ─────────────────────────────────────── */
    if (cfg->iso_ro_home) {
        const char *home = getenv("HOME");
        if (home && home[0]) {
            if (mount(home, home, NULL, MS_BIND | MS_REC, NULL) == 0)
                mount(NULL, home, NULL,
                      MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
            else
                fprintf(stderr, "[RUN] --ro-home bind '%s': %s\n",
                        home, strerror(errno));
        }
    }

    /* ── --tmp-home: $HOME efêmero em tmpfs ─────────────────────────────── */
    if (cfg->iso_tmp_home) {
        char th[] = "/tmp/Nuk4sd-home-XXXXXX";
        char *dir = mkdtemp(th);
        if (dir) {
            if (mount("tmpfs", dir, "tmpfs",
                      MS_NOSUID | MS_NODEV, "size=64m") == 0)
                setenv("HOME", dir, 1);
            else
                perror("[RUN] --tmp-home tmpfs");
        }
    }

    /* ── --wayland: passa socket Wayland read-only ──────────────────────── */
    if (cfg->iso_wayland) {
        char xdg[128];
        snprintf(xdg, sizeof(xdg), "/run/user/%d", (int)getuid());

        /* Cria ponto de montagem dentro do vault */
        char dst_xdg[VAULT_PATH_MAX];
        snprintf(dst_xdg, sizeof(dst_xdg), "%s%s", vault_path, xdg);
        mkdir(dst_xdg, 0700);

        struct stat ws;
        if (stat(xdg, &ws) == 0) {
            if (mount(xdg, dst_xdg, NULL, MS_BIND | MS_REC, NULL) == 0)
                mount(NULL, dst_xdg, NULL,
                      MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        }

        setenv("WAYLAND_DISPLAY", "wayland-0", 1);
        setenv("XDG_RUNTIME_DIR", xdg, 1);
        setenv("QT_QPA_PLATFORM", "wayland;xcb", 1);
        setenv("GDK_BACKEND",     "wayland,x11",  1);
    }

    /* ── --x11: passa socket X11 read-only ──────────────────────────────── */
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
        /* mantém DISPLAY do ambiente pai */
    }

    /* ── Sem display: remove ambas as vars ──────────────────────────────── */
    if (!cfg->iso_wayland && !cfg->iso_x11) {
        unsetenv("WAYLAND_DISPLAY");
        unsetenv("DISPLAY");
    }

    /* ── --no-dbus: remove env + cobre socket ───────────────────────────── */
    if (cfg->iso_no_dbus) {
        const char *bus_addr = getenv("DBUS_SESSION_BUS_ADDRESS");
        /* Cobre o socket físico com /dev/null antes de remover a variável */
        if (bus_addr && !strncmp(bus_addr, "unix:path=", 10)) {
            const char *sock = bus_addr + 10;
            struct stat ds;
            if (stat(sock, &ds) == 0)
                mount("/dev/null", sock, NULL, MS_BIND, NULL);
        }
        unsetenv("DBUS_SESSION_BUS_ADDRESS");
    }

    /* ── Devices básicos dentro do vault ────────────────────────────────── */
    {
        char j_null[VAULT_PATH_MAX], j_zero[VAULT_PATH_MAX], j_tty[VAULT_PATH_MAX];
        snprintf(j_null, sizeof(j_null), "%s/dev/null", vault_path);
        snprintf(j_zero, sizeof(j_zero), "%s/dev/zero", vault_path);
        snprintf(j_tty,  sizeof(j_tty),  "%s/dev/tty",  vault_path);
        mount("/dev/null", j_null, NULL, MS_BIND, NULL);
        mount("/dev/zero", j_zero, NULL, MS_BIND, NULL);
        mount("/dev/tty",  j_tty,  NULL, MS_BIND, NULL);
    }

    /* ── /proc dentro do vault (antes do pivot) ─────────────────────────── */
    if (!cfg->iso_no_proc) {
        char j_proc[VAULT_PATH_MAX];
        snprintf(j_proc, sizeof(j_proc), "%s/proc", vault_path);
        mkdir(j_proc, 0555);
        mount("proc", j_proc, "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
    }

    /* ── /tmp tmpfs dentro do vault ─────────────────────────────────────── */
    {
        char j_tmp[VAULT_PATH_MAX];
        snprintf(j_tmp, sizeof(j_tmp), "%s/tmp", vault_path);
        mkdir(j_tmp, 01777);
        mount("tmpfs", j_tmp, "tmpfs", MS_NOSUID | MS_NODEV, "size=64m");
    }

    /* ── GUI auto-dirs: monta /usr /lib /lib64 /etc/fonts read-only ───── */
    if (gui_mode) {
        const char *host_dirs[] = {
            "/usr", "/lib", "/lib64",
            "/etc/fonts", "/etc/alternatives",
            "/sys/dev/char", NULL
        };
        for (int i = 0; host_dirs[i]; i++) {
            struct stat hst;
            if (stat(host_dirs[i], &hst) != 0) continue;
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, host_dirs[i]);
            if (S_ISDIR(hst.st_mode)) mkdir(dst, 0755);
            if (mount(host_dirs[i], dst, NULL, MS_BIND | MS_REC, NULL) == 0)
                mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        }
    }

    /* ═════════════════════════════════════════════════════════════════════
     *  DESKTOP RUNTIME — audio, dbus, gpu, xdg-runtime, dev, display
     * ===================================================================== */

    /* Helper: garante /run/user/$UID dentro do vault */
#define ENSURE_XDG_DIR(xdg_buf, xdg_buf_sz)                                    \
    do {                                                                         \
        char _r[VAULT_PATH_MAX], _ru[VAULT_PATH_MAX], _rxu[VAULT_PATH_MAX];    \
        snprintf(_r,   sizeof(_r),   "%s/run",            vault_path);          \
        snprintf(_ru,  sizeof(_ru),  "%s/run/user",       vault_path);          \
        snprintf(_rxu, sizeof(_rxu), "%s/run/user/%d",    vault_path, (int)getuid()); \
        mkdir(_r, 0755); mkdir(_ru, 0755); mkdir(_rxu, 0700);                   \
        snprintf((xdg_buf), (xdg_buf_sz), "/run/user/%d", (int)getuid());      \
    } while(0)

    /* ── --xdg-runtime: monta /run/user/$UID inteiro (wayland+pulse+bus) ─ */
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

    /* ── --audio: PipeWire + PulseAudio ─────────────────────────────────── */
    if (cfg->iso_audio) {
        char xdg[128]; ENSURE_XDG_DIR(xdg, sizeof(xdg));
        /* Sockets individuais apenas se xdg-runtime não montou tudo */
        if (!cfg->iso_xdg_runtime) {
            /* PipeWire socket */
            char pw_src[256], pw_dst[VAULT_PATH_MAX];
            snprintf(pw_src, sizeof(pw_src), "%s/pipewire-0", xdg);
            snprintf(pw_dst, sizeof(pw_dst), "%s%s/pipewire-0", vault_path, xdg);
            struct stat pst;
            if (stat(pw_src, &pst) == 0) {
                int fd = open(pw_dst, O_CREAT|O_WRONLY, 0600); if (fd>=0) close(fd);
                mount(pw_src, pw_dst, NULL, MS_BIND, NULL);
            }
            /* PulseAudio socket dir */
            char pulse_src[256], pulse_dst[VAULT_PATH_MAX];
            snprintf(pulse_src, sizeof(pulse_src), "%s/pulse", xdg);
            snprintf(pulse_dst, sizeof(pulse_dst), "%s%s/pulse", vault_path, xdg);
            if (stat(pulse_src, &pst) == 0) {
                mkdir(pulse_dst, 0700);
                mount(pulse_src, pulse_dst, NULL, MS_BIND | MS_REC, NULL);
            }
        }
        /* Env vars de audio */
        char xdg_env[128];
        snprintf(xdg_env, sizeof(xdg_env), "/run/user/%d", (int)getuid());
        setenv("PIPEWIRE_RUNTIME_DIR", xdg_env, 1);
        setenv("PULSE_RUNTIME_PATH",   xdg_env, 1);
        char pulse_addr[256];
        snprintf(pulse_addr, sizeof(pulse_addr), "unix:%s/pulse/native", xdg_env);
        setenv("PULSE_SERVER", pulse_addr, 1);
    }

    /* ── --dbus session: /run/user/$UID/bus ─────────────────────────────── */
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
        snprintf(addr, sizeof(addr), "unix:path=/run/user/%d/bus", (int)getuid());
        setenv("DBUS_SESSION_BUS_ADDRESS", addr, 1);
    }

    /* ── --dbus system: /run/dbus/system_bus_socket ──────────────────────── */
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

    /* ── dbus: machine-id — lido pelo GLib/Firefox antes de qualquer socket */
    if (cfg->iso_dbus_session || cfg->iso_dbus_system || cfg->iso_xdg_runtime) {
        const char *srcs[] = { "/var/lib/dbus/machine-id", "/etc/machine-id", NULL };
        for (int i = 0; srcs[i]; i++) {
            struct stat mst;
            if (stat(srcs[i], &mst) != 0) continue;
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, srcs[i]);
            /* Garante o diretório pai */
            char par[VAULT_PATH_MAX]; snprintf(par, sizeof(par), "%s", dst);
            char *sl = strrchr(par, '/');
            if (sl) { *sl = '\0';
                /* mkdir -p simplificado: tenta criar cada componente */
                for (char *p = par+1; *p; p++) {
                    if (*p == '/') { *p='\0'; mkdir(par,0755); *p='/'; }
                }
                mkdir(par, 0755);
            }
            int fd = open(dst, O_CREAT|O_WRONLY, 0444); if (fd>=0) close(fd);
            mount(srcs[i], dst, NULL, MS_BIND, NULL);
        }
    }

    /* ── --gpu: /dev/dri (GPU hardware acceleration) ─────────────────────── */
    if (cfg->iso_gpu) {
        char dri_dst[VAULT_PATH_MAX];
        snprintf(dri_dst, sizeof(dri_dst), "%s/dev/dri", vault_path);
        struct stat gst;
        if (stat("/dev/dri", &gst) == 0) {
            mkdir(dri_dst, 0755);
            if (mount("/dev/dri", dri_dst, NULL, MS_BIND | MS_REC, NULL) != 0)
                fprintf(stderr, "[RUN] --gpu: bind /dev/dri: %s\n", strerror(errno));
        } else {
            fprintf(stderr, "[RUN] --gpu: /dev/dri not found (no discrete GPU?)\n");
        }
        setenv("LIBGL_ALWAYS_SOFTWARE", "0", 1);
    }

    /* ── --dev minimal/standard: nós /dev adicionais ─────────────────────── */
    if (cfg->iso_dev_level >= 1) {
        /* minimal: urandom, random, shm */
        const char *devs[] = { "/dev/urandom", "/dev/random", NULL };
        for (int i = 0; devs[i]; i++) {
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, devs[i]);
            int fd = open(dst, O_CREAT|O_WRONLY, 0444); if (fd>=0) close(fd);
            mount(devs[i], dst, NULL, MS_BIND, NULL);
        }
        char shm_dst[VAULT_PATH_MAX];
        snprintf(shm_dst, sizeof(shm_dst), "%s/dev/shm", vault_path);
        mkdir(shm_dst, 01777);
        mount("tmpfs", shm_dst, "tmpfs", MS_NOSUID|MS_NODEV, "size=256m");
    }
    if (cfg->iso_dev_level >= 2) {
        /* standard: adiciona /dev/fuse para apps que usam FUSE interno */
        char fuse_dst[VAULT_PATH_MAX];
        snprintf(fuse_dst, sizeof(fuse_dst), "%s/dev/fuse", vault_path);
        struct stat fst;
        if (stat("/dev/fuse", &fst) == 0) {
            int fd = open(fuse_dst, O_CREAT|O_WRONLY, 0660); if (fd>=0) close(fd);
            mount("/dev/fuse", fuse_dst, NULL, MS_BIND, NULL);
        }
    }

    /* ── --display/:--wayland-display: override explícito de display ────── */
    if (cfg->iso_display)
        setenv("DISPLAY", cfg->iso_display, 1);
    if (cfg->iso_wayland_disp)
        setenv("WAYLAND_DISPLAY", cfg->iso_wayland_disp, 1);

#undef ENSURE_XDG_DIR

    /* ── [Camada 3] Isolamento de filesystem ────────────────────────────── *
     *  --chroot : mais simples, funciona sem suporte pleno a mount NS.     *
     *  padrão   : pivot_root — mais seguro, sem acesso ao oldroot.         */
    if (cfg->iso_use_chroot) {
        /* chroot funciona dentro do user namespace (uid 0 mapeado tem       *
         * CAP_SYS_CHROOT dentro do namespace, não exige root no host).      */
        /* TEMPORARILY DISABLED FOR TESTING
        if (chroot(vault_path) != 0) {
            fprintf(stderr, "[RUN] chroot '%s': %s\n", vault_path, strerror(errno));
            cli_log_pivot_root(vault_path, errno);
            _exit(1);
        }
        if (chdir("/") != 0) {
            perror("[RUN] chdir / after chroot");
            _exit(1);
        }
        */
        cli_log_pivot_root(vault_path, 0);   /* reutiliza o log existente */
        fprintf(stderr, "[RUN] [INFO] filesystem isolado via chroot\n");
    } else {
        if (vsb_pivot_root(vault_path) != 0) {
            fprintf(stderr, "[RUN] pivot_root '%s': %s — tente --chroot como fallback\n",
                    vault_path, strerror(errno));
            cli_log_pivot_root(vault_path, errno);
            _exit(1);
        }
        cli_log_pivot_root(vault_path, 0);
    }

    /* Remonta /proc e /tmp após isolamento */
    if (!cfg->iso_no_proc) {
        mkdir("/proc", 0555);
        if (mount("proc", "/proc", "proc",
                  MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0)
            perror("[RUN] mount /proc post-isolamento (non-fatal)");
    }
    {
        int sz = cfg->iso_tmp_size_mb ? cfg->iso_tmp_size_mb : 64;
        char sz_opt[32]; snprintf(sz_opt, sizeof(sz_opt), "size=%dm", sz);
        mkdir("/tmp", 01777);
        if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, sz_opt) != 0)
            perror("[RUN] mount /tmp post-isolamento (non-fatal)");
    }

    /* ── [Camada 4] Drop capabilities + NO_NEW_PRIVS ────────────────────── */
    if (vsb_drop_caps() != 0) {
        fprintf(stderr, "[RUN] cap drop failed\n");
        cli_log_cap_drop(-1);
        _exit(1);
    }
    cli_log_cap_drop(0);

    /* Rlimits — valores das flags ou defaults GUI-friendly */
    {
        struct rlimit rl;
        int   p  = cfg->iso_max_procs    ? cfg->iso_max_procs    : 512;
        long  m  = cfg->iso_max_mem_gb   ? (long)cfg->iso_max_mem_gb * 1024 * 1024 * 1024
                                         : (long)4 * 1024 * 1024 * 1024;
        long  fs = cfg->iso_max_fsize_mb ? (long)cfg->iso_max_fsize_mb * 1024 * 1024
                                         : (long)512 * 1024 * 1024;
        int   fd = cfg->iso_max_fds      ? cfg->iso_max_fds      : 4096;
        rl.rlim_cur = rl.rlim_max = (rlim_t)p;  setrlimit(RLIMIT_NPROC,  &rl);
        cli_log_rlimit("RLIMIT_NPROC",  p, p);
        rl.rlim_cur = rl.rlim_max = (rlim_t)m;  setrlimit(RLIMIT_AS,     &rl);
        cli_log_rlimit("RLIMIT_AS",     m, m);
        rl.rlim_cur = rl.rlim_max = (rlim_t)fs; setrlimit(RLIMIT_FSIZE,  &rl);
        cli_log_rlimit("RLIMIT_FSIZE",  fs, fs);
        rl.rlim_cur = rl.rlim_max = (rlim_t)fd; setrlimit(RLIMIT_NOFILE, &rl);
        cli_log_rlimit("RLIMIT_NOFILE", fd, fd);
    }

    /* ── [Camada 5] Seccomp-BPF (skipável via --no-seccomp para debug) ──── */
    if (cfg->iso_no_seccomp) {
        fprintf(stderr, "[RUN] ⚠  --no-seccomp: BPF desativado (modo debug)\n");
        cli_log_seccomp(0);
    } else {
        vsb_set_seccomp_mode(cfg->seccomp_strict ? 1 : 0, cfg->allow_clone3 ? 1 : 0);
        if (vsb_apply_seccomp() != 0) {
            fprintf(stderr, "[RUN] seccomp load failed\n");
            cli_log_seccomp(-1);
            _exit(1);
        }
        cli_log_seccomp(0);
    }

    /* ── Monta argv final e execvp ──────────────────────────────────────── */
    int total = 1 + cfg->run_argc;
    char **exec_argv = calloc((size_t)(total + 1), sizeof(char *));
    if (!exec_argv) _exit(1);

    exec_argv[0] = cfg->run_exec;
    for (int i = 0; i < cfg->run_argc; i++)
        exec_argv[i + 1] = cfg->run_argv[i];
    exec_argv[total] = NULL;

    cli_log_exec(cfg->run_exec, exec_argv, total);
    execvp(cfg->run_exec, exec_argv);
    fprintf(stderr, "[RUN] execvp '%s': %s\n", cfg->run_exec, strerror(errno));
    cli_log(CLI_LOG_ERROR, "EXEC", "execvp('%s') falhou: %s",
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

/* ═══════════════════════════════════════════════════════════════════════════
 *  Dispatcher principal
 * ═══════════════════════════════════════════════════════════════════════════ */
static int dispatch(CliConfig *cfg) {
    int ret = 0;
    uint32_t id = (uint32_t)cfg->vault_id;

    /* ── Sem vault necessário ────────────────────────────────────────────── */
    if (cfg->op_help)    { print_help();                return 0; }
    if (cfg->op_version) { printf("Nuk4sd v1.4\n"); return 0; }
    if (cfg->op_ls)      { vault_list_ffi();            return 0; }

    /* ── --new <nome> ────────────────────────────────────────────────────── */
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

    /* ── Verifica se --vault <id> foi fornecido para operações que precisam ─ */
    bool needs_id = (cfg->op_info || cfg->op_files || cfg->op_status ||
                     cfg->op_scan || cfg->op_encrypt || cfg->op_decrypt ||
                     cfg->op_resolve || cfg->op_mount || cfg->op_umount ||
                     cfg->op_mount_export || cfg->op_export ||
                     cfg->op_rm || cfg->op_rename || cfg->op_unlock ||
                     cfg->op_passwd || cfg->op_rule || cfg->op_worm_status ||
                     cfg->worm_set || cfg->worm_clear ||
                     cfg->worm_protected_scan || cfg->run_exec);

    if (needs_id && cfg->vault_id < 0) {
        print_err("--vault <id> required. Use --ls to list vault IDs.");
        return 1;
    }

    /* ── Resolve senha quando necessário ───────────────────────────────── */
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

    /* ══════════════════════════════════════════════════════════════════════
     *  Despacho por operação
     * ══════════════════════════════════════════════════════════════════════ */

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
            printf("  Vault %u — \033[1m%s\033[0m\n", id, label);
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
            printf("\033[31m⚠ ALERT: %d file(s) modified since last scan:\033[0m\n%s",
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

    /* ── WORM ──────────────────────────────────────────────────────────── */
    if (cfg->op_worm_status) {
        uint32_t f = vault_worm_get_flags_ffi(id);
        cli_log_worm_status(id, f);
        printf("\n  WORM — vault %u (raw flags 0x%02x)\n", id, f);
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
               "\033[31mACTIVE (immutable — use --mount-export to rescue)\033[0m" :
               "inactive");
        goto cleanup;
    }

    if (cfg->worm_protected_scan) {
        printf("\033[31m⚠  PROTECTED-SCAN is IRREVERSIBLE.\033[0m\n");
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

    /* ── --run <exec> ──────────────────────────────────────────────────── */
    if (cfg->run_exec) {
        char vault_path[VAULT_PATH_MAX];
        if (vault_get_real_path_ffi(id, vault_path, sizeof(vault_path)) != 0) {
            print_err("Vault not found or path unavailable.");
            ret = 1;
            goto cleanup;
        }

        /* Monta o vault via FUSE antes de isolar (será visível dentro) */
        if (cfg->verbose)
            printf("  → mounting vault %u via FUSE...\n", id);
        vault_mount_ffi(id, pass ? pass : "");

        if (cfg->verbose) {
            printf("  → exec: %s", cfg->run_exec);
            for (int i = 0; i < cfg->run_argc; i++)
                printf(" %s", cfg->run_argv[i]);
            printf("\n");
            printf("  → net=%s  wayland=%d  x11=%d  ro-home=%d  "
                   "no-dbus=%d  tmp-home=%d  no-proc=%d\n",
                   cfg->iso_no_net ? "isolated" : "host",
                   cfg->iso_wayland, cfg->iso_x11, cfg->iso_ro_home,
                   cfg->iso_no_dbus, cfg->iso_tmp_home, cfg->iso_no_proc);
        }

        ret = run_isolated(cfg, vault_path);

        /* Desmonta o vault FUSE após o programa isolado encerrar */
        if (cfg->verbose)
            printf("  → unmounting vault %u (run finished)...\n", id);
        vault_unmount_ffi(id);

        goto cleanup;
    }

    /* Nenhuma operação reconhecida */
    print_err("No operation specified. Use --help for usage.");
    ret = 1;

cleanup:
    explicit_bzero(pass_buf, sizeof(pass_buf));
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Entry point FFI — chamado pelo main.rs
 * ═══════════════════════════════════════════════════════════════════════════ */
int vault_cli_parse_and_exec(int argc, char **argv) {
    CliConfig cfg;

    /* Inicializa logger (path=NULL → usa ~/.local/share/Nuk4sd/cli.log) */
    cli_log_init(NULL);

    if (parse_flags(argc, argv, &cfg) != 0) {
        cli_log(CLI_LOG_ERROR, "COMMAND", "parse_flags falhou — args inválidos");
        cli_log_close();
        return 1;
    }

    /* Activa verbose no logger se --verbose foi passado */
    cli_log_set_verbose(cfg.verbose);

    /* Loga o comando recebido (sem expor --password) */
    cli_log_command(argc, argv, cfg.vault_id);

    int ret = dispatch(&cfg);

    cli_log(CLI_LOG_INFO, "COMMAND", "encerrado ret=%d", ret);
    cli_log_close();
    return ret;
}