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
#include "preset.h"
#include "sandbox.h"
#include "vault_health.h"
// Adiciona temporariamente em vault_cli.c, no início do main ou do parse_flags:

#include <getopt.h>
#include <pwd.h>
#include <termios.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <ftw.h>        /* FIX #1: nftw() para rm -rf seguro */
#include "container.h"

/* ── OCI / Cgroup callbacks implemented in Rust (ffi.rs) ───────────────────
 * Exposed via #[no_mangle] extern "C" — linked through the same static
 * libvault_security.a produced by build.rs. */
extern int rust_oci_pull_image(const char *url_or_alias, const char *target_dir);
extern int rust_cgroup_apply(const char *cgroup_name,
                             unsigned long long pid,
                             long long memory_limit_mb,
                             unsigned long long cpu_shares);

#ifdef __linux__
#include <sched.h>
#endif
/* ── FIX #1: rm_rf_nftw — substitui system("rm -rf") ─────────────────────
 * nftw() com FTW_PHYS não segue symlinks durante a travessia, bloqueando
 * qualquer path traversal via symlinks criados dentro do rootfs. */
#ifdef __linux__
static int _rm_rf_cb(const char *path, const struct stat *sb,
                     int typeflag, struct FTW *ftwbuf)
{
    (void)sb; (void)ftwbuf;
    return (typeflag == FTW_DP) ? rmdir(path) : unlink(path);
}
static int rm_rf_safe(const char *path) {
    return nftw(path, _rm_rf_cb, 32, FTW_DEPTH | FTW_PHYS);
}
#endif

/* forward decl (load_profile helper) */

/* forward decl — usada pelo loader de --profile (load_profile), definida
 * mais abaixo junto com o resto dos helpers de bind mount */
static void cli_expand_tilde(const char *in, char *out, size_t out_sz);

/*
 *  WORM bits — espelha vault_core.h
 * */
#ifndef WORM_PROTECT_DELETE
#define WORM_PROTECT_DELETE  (1u << 0)
#define WORM_PROTECT_RENAME  (1u << 1)
#define WORM_PROTECT_WRITE   (1u << 2)
#define WORM_PROTECT_SCAN    (1u << 3)
#define WORM_PROTECT_READ    (1u << 4)
#endif

/*
 *  Bind-mount entry para --ro / --rw / --blacklist
 * */
/* As estruturas BindEntry e CliConfig foram movidas para preset.h
 * para permitir o uso pelo módulo preflight_scan. */

/*
 *  Enum de opções longas
 * */
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
    OPT_WHITE_LIST,
    OPT_IMAGE,
    /* run */
    OPT_RUN,
    /* isolamento básico */
    OPT_NO_NET, OPT_WAYLAND, OPT_X11,
    OPT_RO_HOME, OPT_RW_HOME, OPT_NO_DBUS, OPT_TMP_HOME,
    OPT_RO, OPT_RW, OPT_BLACKLIST,
    OPT_AUDIT, OPT_NO_PROC, OPT_NEW_SESSION,
    OPT_UNSHARE_IPC, OPT_UNSHARE_UTS,
    OPT_HOSTNAME, OPT_PROFILE,
    /* desktop runtime */
    OPT_AUDIO, OPT_DBUS, OPT_GPU, OPT_XDG_RUNTIME,
    OPT_DEV, OPT_MOUNT_DEV, OPT_NO_SECCOMP, OPT_CHROOT, OPT_PIVOT_ROOT,
    OPT_DISPLAY_OPT, OPT_WAYLAND_DISPLAY,
    OPT_PRESET,
    /* limites de recurso */
    OPT_MAX_PROCS, OPT_MAX_MEM, OPT_MAX_FSIZE, OPT_MAX_FDS, OPT_TMP_SIZE,
    /* gerais */
    OPT_PASSWORD, OPT_VERBOSE, OPT_JSON, OPT_VERSION, OPT_HELP,
    /* strict seccomp */
    OPT_SECCOMP_STRICT = 'q',
    OPT_ALLOW_CLONE3   = 'k',
    /* seccomp permissivo (Fase 1 do roadmap --friendly-sandbox) */
    OPT_FRIENDLY_SANDBOX,
    /* Fase 2 do roadmap: deixa o app GUI montar o PRÓPRIO sandbox interno */
    OPT_PERMISSIVE_SANDBOX,
    /* Desativa o auto-scanner de dependências (preflight_scan / ldd) */
    OPT_NO_PREFLIGHT,
    /* Pula a etapa de montagem FUSE do vault */
    OPT_NO_FUSE,
    /* Inspeciona isolamento de um PID em execução */
    OPT_HEALTH,
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
    { "white-list",      required_argument, NULL, OPT_WHITE_LIST },
    { "image",           required_argument, NULL, OPT_IMAGE },
    { "run",             required_argument, NULL, OPT_RUN },
    { "no-net",          no_argument,       NULL, OPT_NO_NET },
    { "wayland",         no_argument,       NULL, OPT_WAYLAND },
    { "x11",             no_argument,       NULL, OPT_X11 },
    { "ro-home",         no_argument,       NULL, OPT_RO_HOME },
    { "rw-home",         no_argument,       NULL, OPT_RW_HOME },
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
    { "mount-dev",       no_argument,       NULL, OPT_MOUNT_DEV },
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
    { "json",            no_argument,       NULL, OPT_JSON },
    { "version",         no_argument,       NULL, OPT_VERSION },
    { "seccomp-strict",  no_argument,       NULL, 'q' },
    { "allow-clone3",    no_argument,       NULL, 'k' },
    { "friendly-sandbox", no_argument,      NULL, OPT_FRIENDLY_SANDBOX },
    { "permissive",       no_argument,      NULL, OPT_PERMISSIVE_SANDBOX },
    { "no-preflight",     no_argument,      NULL, OPT_NO_PREFLIGHT },
    { "no-fuse",          no_argument,      NULL, OPT_NO_FUSE },
    { "health",           required_argument, NULL, OPT_HEALTH },
    { NULL, 0, NULL, 0 }
};

/*
 *  Helpers
 * */
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

/*
 *  Help
 * */
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

"── Container Whitelist ────────────────────────────────────────────\n"
"  --vault <id> --white-list -e         exclude whitelist (block sealed ops)\n"
"  --vault <id> --white-list -r         restore whitelist (allow sealed ops)\n\n"

"── Image & Container Runtime ──────────────────────────────────────\n"
"  --image <url|alpine|ubuntu>          baixar rootfs externo antes do run\n\n"

"── Run Program in Vault Sandbox ───────────────────────────────────\n"
"  --vault <id> --run <exec> [-- exec-args...]\n\n"
"  Filesystem:\n"
"    --ro <path>          bind mount path read-only inside sandbox\n"
"    --rw <path>          bind mount path read-write inside sandbox\n"
"    --blacklist <path>   make path invisible (tmpfs/null over it)\n"
"    --ro-home            bind mount $HOME read-only\n"
"    --rw-home            bind mount $HOME read-write (padrão se nem --ro-home\n"
"                         nem --tmp-home forem passados)\n"
"    --tmp-home           ephemeral $HOME in tmpfs (vanishes on exit)\n\n"
"  Network:\n"
"    --no-net             unshare network namespace (full isolation)\n\n"
"  Display:\n"
"    --wayland            pass Wayland socket + XDG_RUNTIME_DIR (read-only)\n"
"    --x11                pass X11 socket /tmp/.X11-unix (read-only)\n"
"    --display <opt>      customiza a variável DISPLAY exportada pro sandbox\n"
"    --wayland-display <s> customiza WAYLAND_DISPLAY (padrão: wayland-0)\n\n"
"  Áudio / GPU / D-Bus:\n"
"    --audio              expõe socket de PulseAudio/PipeWire (read-only)\n"
"    --gpu                monta /dev/dri (aceleração gráfica)\n"
"    --xdg-runtime         monta $XDG_RUNTIME_DIR/<uid> além do que --wayland já traz\n"
"    --dbus <modo>        'session', 'system' ou 'both' — expõe socket(s) D-Bus\n\n"
"  D-Bus:\n"
"    --no-dbus            remove DBUS_SESSION_BUS_ADDRESS + cover socket\n\n"
"  Dispositivos:\n"
"    --dev <nível>        'minimal' (null/zero/tty/urandom) ou 'standard'\n"
"                         (+ random/fuse) — nodes de /dev disponíveis no jail\n\n"
"  Namespaces:\n"
"    --unshare-ipc        isolate IPC namespace (SysV shm/sem/mq)\n"
"    --unshare-uts        isolate UTS namespace (hostname)\n"
"    --hostname <name>    set sandbox hostname (requires --unshare-uts)\n"
"    --new-session        setsid() — detach from controlling terminal\n"
"    --no-proc            do not mount /proc inside sandbox\n\n"
"  Filesystem raiz:\n"
"    --chroot             usa chroot() em vez de pivot_root() (mais fraco,\n"
"                         permite escape via path traversal — evite se puder)\n"
"    --pivot-root          força pivot_root() explicitamente (padrão já usado\n"
"                         automaticamente quando disponível)\n\n"
"  Seccomp / Capabilities:\n"
"    --no-seccomp          desliga o filtro seccomp-BPF (NÃO recomendado —\n"
"                         remove a última camada de proteção contra syscalls)\n"
"    --seccomp-strict      allowlist mais restrita (menos syscalls liberadas)\n"
"    --allow-clone3        libera a syscall clone3 na allowlist (algumas libc\n"
"                         novas dependem dela; desligada por padrão)\n"
"    --friendly-sandbox    libera syscalls extras de housekeeping no seccomp\n"
"                         (fsync/fdatasync/renameat2) — não mexe em\n"
"                         chroot/capset/mount\n"
"    --permissive          modo permissivo geral (menos rígido que o padrão)\n\n"
"  Recursos (rlimits):\n"
"    --max-procs <n>       RLIMIT_NPROC (1-65535)\n"
"    --max-mem <gb>        RLIMIT_AS em GB (1-512)\n"
"    --max-filesize <mb>   RLIMIT_FSIZE em MB (1-102400)\n"
"    --max-fds <n>         RLIMIT_NOFILE (1-65535)\n"
"    --tmp-size <mb>       tamanho do tmpfs usado por --tmp-home (1-102400)\n\n"
"  FUSE:\n"
"    --no-fuse             não monta o vault via FUSE (usa cópia direta)\n\n"
"  Audit:\n"
"    --audit              log exec args, all bind mounts, env changes\n\n"
"  Profile:\n"
"    --profile <file>     load isolation flags from .conf file\n"
"                         (one flag per line, e.g. --no-net)\n"
"    --preset <nome>      carrega um preset nomeado de flags pré-configurado\n\n"

"── General ────────────────────────────────────────────────────────\n"
"  --gui                  launch the graphical interface (nuk4sd_gui.py)\n"
"  --password <pass>      provide password inline (prompted if omitted)\n"
"  --verbose              verbose output\n"
"  --json                 JSON output for --status and --scan\n"
"  --health <pid>          roda checagem de saúde num sandbox já rodando (PID)\n"
"  --version              show version\n"
"  --help                 this help\n\n"

"  Sandbox tuning (--run):\n"
"    --no-preflight       skip ldd dependency auto-scan (preflight_scan)\n"
"                         use when you already know the flags needed, or\n"
"                         with statically-linked / stripped binaries\n\n"

"Examples:\n"
"  Nuk4sd --gui\n"
"  Nuk4sd --ls\n"
"  Nuk4sd --vault 3 --encrypt\n"
"  Nuk4sd --vault 3 --scan --verbose\n"
"  Nuk4sd --vault 3 --run firefox --no-net --wayland\n"
"  Nuk4sd --vault 3 --run gimp --wayland --ro /usr/share/fonts\n"
"  Nuk4sd --vault 3 --run bash --no-net --unshare-ipc --no-proc --audit\n"
"  Nuk4sd --vault 3 --run code --wayland --rw ~/projects --blacklist ~/.ssh\n"
"  Nuk4sd --vault 3 --run mpv --x11 --ro /media/films -- /media/films/movie.mkv\n"
"  Nuk4sd --vault 3 --run busybox --no-preflight --no-net\n"
"  Nuk4sd --vault 0 --preset nuk4sd-gui --run python3 -- nuk4sd_gui.py\n"
"  Nuk4sd --new work --path /data/work --protected --engine 2\n"
"  Nuk4sd --vault 3 --protect-delete --protect-write\n"
"  Nuk4sd --vault 3 --export --dest ~/rescued --file secret.pdf.enc\n\n"
    );
}

/*
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
 * */
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
        else if (!strcmp(p, "--rw-home"))       cfg->iso_rw_home     = true;
        else if (!strcmp(p, "--no-dbus"))       cfg->iso_no_dbus     = true;
        else if (!strcmp(p, "--tmp-home"))      cfg->iso_tmp_home    = true;
        else if (!strcmp(p, "--audit"))         cfg->iso_audit       = true;
        else if (!strcmp(p, "--no-proc"))       cfg->iso_no_proc     = true;
        else if (!strcmp(p, "--new-session"))   cfg->iso_new_session = true;
        else if (!strcmp(p, "--unshare-ipc"))   cfg->iso_unshare_ipc = true;
        else if (!strcmp(p, "--unshare-uts"))   cfg->iso_unshare_uts = true;
        else if (!strncmp(p, "--ro ", 5) && cfg->bind_count < MAX_BINDS) {
            cli_expand_tilde(p+5, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
            cfg->binds[cfg->bind_count++].type = BIND_RO;
        }
        else if (!strncmp(p, "--rw ", 5) && cfg->bind_count < MAX_BINDS) {
            cli_expand_tilde(p+5, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
            cfg->binds[cfg->bind_count++].type = BIND_RW;
        }
        else if (!strncmp(p, "--blacklist ", 12) && cfg->bind_count < MAX_BINDS) {
            cli_expand_tilde(p+12, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
            cfg->binds[cfg->bind_count++].type = BIND_BLACKLIST;
        }
        else {
            fprintf(stderr, "⚠ profile '%s': unknown flag '%s' — skipped\n", path, p);
        }
    }
    fclose(f);
}

/*
 *  Helpers de Parsing
 * */
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

/*
 *  cli_mkdir_p — cria todos os componentes intermediários do path
 *  path: caminho COMPLETO do diretório a criar (não inclui nome de arquivo)
 *
 *  Necessário para --ro/--rw: mkdir() simples falha com ENOENT se qualquer
 *  diretório pai dentro do vault ainda não existir (ex: dst = vault/usr/share/fonts
 *  mas vault/usr/share ainda não foi criado).
 * */
static int cli_mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    size_t len = snprintf(tmp, sizeof(tmp), "%s", path);
    if (len == 0 || len >= sizeof(tmp)) { errno = ENAMETOOLONG; return -1; }

    if (len > 0 && tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

/*
 *  cli_expand_tilde — expande "~" e "~/resto" pro $HOME real
 *
 *  Sem isso, "--blacklist ~/.ssh" chega no bloco de binds como o path
 *  literal "~/.ssh" (diretório chamado "~" que não existe), o stat() falha,
 *  o bind é silenciosamente pulado, e o blacklist nunca é aplicado de fato.
 *  Escreve o resultado em `out` (tamanho `out_sz`). Se não começar com "~",
 *  ou não houver HOME disponível, copia o path original sem modificar.
 * */
static void cli_expand_tilde(const char *in, char *out, size_t out_sz) {
    if (in[0] != '~' || (in[1] != '/' && in[1] != '\0')) {
        snprintf(out, out_sz, "%s", in);
        return;
    }

    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') {
        struct passwd *pw = getpwuid(getuid());
        home = (pw && pw->pw_dir) ? pw->pw_dir : NULL;
    }
    if (!home) {
        /* sem HOME resolvível: mantém o path literal (vai falhar no stat
         * como antes, mas não silenciosamente — logamos o motivo). */
        fprintf(stderr, "⚠ cli_expand_tilde: HOME não definido, mantendo '%s' literal\n", in);
        snprintf(out, out_sz, "%s", in);
        return;
    }

    if (in[1] == '\0')
        snprintf(out, out_sz, "%s", home);          /* "~"       -> "$HOME"      */
    else
        snprintf(out, out_sz, "%s%s", home, in + 1); /* "~/foo"  -> "$HOME/foo"  */
}

/*
 *  bind_path_is_safe — impede path traversal para fora do vault_path
 *  Verifica se dst, após resolução, ainda tem vault_path como prefixo.
 *  Como dst pode ainda não existir, sobe no path até achar um componente
 *  já existente para poder chamar realpath().
 * */
static bool bind_path_is_safe(const char *vault_path, const char *dst) {
    char resolved_vault[PATH_MAX];
    if (!realpath(vault_path, resolved_vault)) return false;

    char probe[PATH_MAX];
    snprintf(probe, sizeof(probe), "%s", dst);
    char resolved_probe[PATH_MAX];

    while (!realpath(probe, resolved_probe)) {
        char *slash = strrchr(probe, '/');
        if (!slash || slash == probe) return false; /* chegou na raiz sem achar nada existente */
        *slash = '\0';
    }

    size_t vlen = strlen(resolved_vault);
    return strncmp(resolved_probe, resolved_vault, vlen) == 0 &&
           (resolved_probe[vlen] == '/' || resolved_probe[vlen] == '\0');
}

/*
 *  Parser principal
 * */
 // Adiciona temporariamente em vault_cli.c, no início do main ou do parse_flags:

static int parse_flags(int argc, char **argv, CliConfig *cfg) {
    // Adiciona temporariamente em vault_cli.c, no início do main ou do parse_flags:
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
        case OPT_WHITE_LIST:
            if (!strcmp(optarg, "-e") || !strcmp(optarg, "exclude") || !strcmp(optarg, "e")) {
                cfg->op_whitelist_exclude = true;
            } else if (!strcmp(optarg, "-r") || !strcmp(optarg, "restore") || !strcmp(optarg, "r")) {
                cfg->op_whitelist_restore = true;
            } else {
                print_err("--white-list must be '-e' or '-r'");
                return -1;
            }
            break;
        case OPT_IMAGE:
            cfg->image_url = optarg;
            break;
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
            if      (!strcmp(optarg, "minimal")  || !strcmp(optarg, "1")) cfg->iso_dev_level = 1;
            else if (!strcmp(optarg, "standard") || !strcmp(optarg, "2")) cfg->iso_dev_level = 2;
            else { print_err("--dev: use 'minimal', 'standard', '1' or '2'"); return -1; }
            break;
        case OPT_MOUNT_DEV:
            cfg->iso_mount_dev = true;
            break;
        /* limites de recurso — parse_int_arg() valida range e
         * detecta overflow; atoi() retornava 0 silenciosamente
         * em caso de argumento inválido ou negativo, o que poderia
         * resultar em um rlim_t com wrap-around ao multiplicar.  */
        case OPT_MAX_PROCS: {
            int _e = 0;
            cfg->iso_max_procs    = (int)parse_int_arg(optarg, 1, 65535, "--max-procs", &_e);
            if (_e) return -1;
            break;
        }
        case OPT_MAX_MEM: {
            int _e = 0;
            cfg->iso_max_mem_gb   = (int)parse_int_arg(optarg, 1, 512, "--max-mem", &_e);
            if (_e) return -1;
            break;
        }
        case OPT_MAX_FSIZE: {
            int _e = 0;
            cfg->iso_max_fsize_mb = (int)parse_int_arg(optarg, 1, 102400, "--max-filesize", &_e);
            if (_e) return -1;
            break;
        }
        case OPT_MAX_FDS: {
            int _e = 0;
            cfg->iso_max_fds      = (int)parse_int_arg(optarg, 1, 65535, "--max-fds", &_e);
            if (_e) return -1;
            break;
        }
        case OPT_TMP_SIZE: {
            int _e = 0;
            cfg->iso_tmp_size_mb  = (int)parse_int_arg(optarg, 1, 102400, "--tmp-size", &_e);
            if (_e) return -1;
            break;
        }
        /* gerais */
        case OPT_PASSWORD: cfg->password    = optarg; break;
        case OPT_VERBOSE:  cfg->verbose     = true;   break;
        case OPT_JSON:     cfg->json_output = true;   break;
        case OPT_VERSION:  cfg->op_version  = true;   break;
        case OPT_HELP:     cfg->op_help     = true;   break;
        case 'q':          cfg->seccomp_strict = true; break;
        case 'k':          cfg->allow_clone3   = true; break;
        case OPT_FRIENDLY_SANDBOX: cfg->friendly_sandbox = true; break;
        case OPT_PERMISSIVE_SANDBOX: cfg->permissive_sandbox = true; break;
        case OPT_NO_PREFLIGHT: cfg->skip_preflight = true; break;
        case OPT_NO_FUSE:      cfg->no_fuse        = true; break;
        case OPT_HEALTH: {
            pid_t target = (pid_t)atoi(optarg);
            if (target <= 0) {
                fprintf(stderr, "error: --health requires a valid PID\n");
                free(cfg);
                return 1;
            }
            int r = sandbox_health_check(target);
            free(cfg);
            return r;
        }
        /* bind mounts */
        case OPT_RO:
            if (cfg->bind_count < MAX_BINDS) {
                cli_expand_tilde(optarg, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
                cfg->binds[cfg->bind_count++].type = BIND_RO;
            }
            break;
        case OPT_RW:
            if (cfg->bind_count < MAX_BINDS) {
                cli_expand_tilde(optarg, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
                cfg->binds[cfg->bind_count++].type = BIND_RW;
            }
            break;
        case OPT_BLACKLIST:
            if (cfg->bind_count < MAX_BINDS) {
                cli_expand_tilde(optarg, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
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
        if (!strcmp(p, "firefox") || !strcmp(p, "browser") || !strcmp(p, "flameshot")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_audio        = true;
            cfg->iso_dbus_session = true;
            cfg->iso_gpu          = true;
            cfg->iso_xdg_runtime  = true;
            cfg->iso_rw_home      = true;
            cfg->permissive_sandbox = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 2;  /* standard */
            setenv("MOZ_WEBRENDER", "software", 0);
            setenv("LIBGL_ALWAYS_SOFTWARE", "1", 0);
        } else if (!strcmp(p, "office") || !strcmp(p, "evince") || !strcmp(p, "gnome-calculator") || !strcmp(p, "nautilus")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_audio        = true;
            cfg->iso_dbus_session = true;
            cfg->iso_xdg_runtime  = true;
            cfg->iso_rw_home      = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 1;  /* minimal */
        } else if (!strcmp(p, "dev") || !strcmp(p, "code") || !strcmp(p, "gedit")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_dbus_session = true;
            cfg->iso_xdg_runtime  = true;
            cfg->iso_rw_home      = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 1;
        } else if (!strcmp(p, "media") || !strcmp(p, "celluloid") || !strcmp(p, "hypnotix")) {
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_audio        = true;
            cfg->iso_gpu          = true;
            cfg->iso_dbus_session = true;  /* mpv/celluloid/hypnotix usam D-Bus para IPC e MPRIS */
            cfg->iso_xdg_runtime  = true;
            cfg->iso_rw_home      = true;
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 2;
        } else if (!strcmp(p, "nuk4sd-gui")) {
            /* Preset especial para rodar a PRÓPRIA GUI em sandbox */
            cfg->iso_wayland      = true;
            cfg->iso_x11          = true;
            cfg->iso_dbus_session = true;
            cfg->iso_xdg_runtime  = true;
            cfg->iso_gpu          = true;
            cfg->iso_rw_home      = true;     /* Para ~/.config/nuk4sd e ~/.local/share/Nuk4sd */
            cfg->permissive_sandbox = true;   /* Para o app poder criar child sandboxes */
            if (!cfg->iso_dev_level) cfg->iso_dev_level = 2;
        } else if (!strcmp(p, "minimal")) {
            /* sandbox básico sem display */
        } else {
            fprintf(stderr, "⚠ preset '%s' desconhecido. Disponíveis: firefox, browser, office, evince, dev, code, gedit, media, celluloid, hypnotix, flameshot, nautilus, nuk4sd-gui, minimal\n", p);
        }
    }

    return 0;
}

/*
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
 * */
#ifdef __linux__

/* resolve_real_uid(): resolve o UID "de verdade" da sessão gráfica do
 * usuário, mesmo quando o Nuk4sd inteiro roda como root via `sudo`.
 *
 * Problema que isso resolve: getuid() sozinho, sob `sudo`, retorna 0
 * (root) desde o início do processo — então qualquer path construído
 * como "/run/user/%d" vira "/run/user/0", que geralmente nem existe.
 * O compositor Wayland, o PipeWire/Pulse e o D-Bus session bus do
 * usuário real vivem em "/run/user/<uid original>" (ex: 1000), nunca
 * em "/run/user/0". `sudo` exporta esse UID original em $SUDO_UID —
 * usamos isso como fonte preferencial, com getuid() como fallback pro
 * caso raro de rodar sem sudo (ex: já como root de verdade, ou dentro
 * de outro mecanismo de elevação que não seta $SUDO_UID).
 *
 * Esta função é a ÚNICA fonte de verdade pra isso no arquivo — antes,
 * só o bloco --wayland fazia essa resolução; --xdg-runtime, --audio e
 * --dbus session usavam getuid() puro via a macro ENSURE_XDG_DIR, e
 * como esses blocos rodam DEPOIS do --wayland (e no preset "firefox"
 * todos ficam ligados ao mesmo tempo), a variável de ambiente correta
 * setada pelo --wayland era sobrescrita pela errada logo em seguida —
 * causando falha de conexão ao Wayland/D-Bus mesmo com o socket certo
 * disponível no host. */
static uid_t resolve_real_uid(void) {
    uid_t real_uid = getuid();
    const char *sudo_uid_s = getenv("SUDO_UID");
    if (sudo_uid_s && *sudo_uid_s) {
        errno = 0;
        char *end = NULL;
        long parsed = strtol(sudo_uid_s, &end, 10);
        /* FIX #7: bound check explícito — UID válido é 0..65535 */
        if (errno == 0 && end != sudo_uid_s && *end == '\0' &&
            parsed >= 0 && parsed <= 65535)
            real_uid = (uid_t)parsed;
    }
    return real_uid;
}

static gid_t resolve_real_gid(void) {
    gid_t real_gid = getgid();
    const char *sudo_gid_s = getenv("SUDO_GID");
    if (sudo_gid_s && *sudo_gid_s) {
        errno = 0;
        char *end = NULL;
        long parsed = strtol(sudo_gid_s, &end, 10);
        /* FIX #7: bound check explícito — GID válido é 0..65535 */
        if (errno == 0 && end != sudo_gid_s && *end == '\0' &&
            parsed >= 0 && parsed <= 65535)
            real_gid = (gid_t)parsed;
    }
    return real_gid;
}

static int run_isolated(CliConfig *cfg, char *vault_path) {
    /* Auto-scanner: descobre dependências via ldd e altera as
     * flags no cfg ANTES de aplicarmos o isolamento.
     * Pode ser desativado com --no-preflight quando o usuário
     * já sabe quais flags usar, ou em binários estáticos/stripped
     * onde o ldd pode se comportar de forma inesperada. */
    if (cfg->run_exec && !cfg->skip_preflight) {
        preflight_scan(cfg, cfg->run_exec);
    } else if (cfg->run_exec && cfg->skip_preflight) {
        fprintf(stderr, "[RUN] preflight_scan desativado via --no-preflight\n");
    }

    uid_t real_uid = resolve_real_uid();
    gid_t real_gid = resolve_real_gid();
    bool gui_mode = cfg->iso_wayland || cfg->iso_x11;

    /* ── Cria jail_root em /tmp (filesystem real, não FUSE) ─────────────────
     *
     * Problema: o vault é exposto via FUSE. O kernel Linux rejeita
     * chroot(), pivot_root() e mount() num mountpoint FUSE com EACCES,
     * independente de capabilities ou user namespace — o FUSE driver não
     * implementa as operações necessárias para servir de nova raiz.
     *
     * Solução: cria um diretório temporário em /tmp (tmpfs real do kernel).
     * O diretório em si é só criado aqui no pai (mkdir não exige privilégio
     * nenhum) — mas o BIND-MOUNT do vault nele e o vsb_prepare_jail() agora
     * rodam DENTRO do filho, depois do unshare(CLONE_NEWUSER|CLONE_NEWNS)
     * (ver mais abaixo). mount() exige CAP_SYS_ADMIN, e sem sudo o processo
     * pai não tem isso — só ganha essa capability (namespaced) depois de
     * criar seu próprio user namespace. Fazer o bind aqui no pai, como
     * antes, funcionava só porque sempre rodava como root real (sudo).
     *
     * O diretório /tmp/Nuk4sd-jail-XXXXXX é removido automaticamente
     * após o processo filho encerrar (cleanup no pai) — o bind-mount em si
     * já desaparece sozinho quando o mount namespace privado do filho é
     * destruído na saída dele, então só falta remover o diretório vazio. */
    char jail_root[PATH_MAX];
    snprintf(jail_root, sizeof(jail_root), "/tmp/Nuk4sd-jail-XXXXXX");
    if (mkdtemp(jail_root) == NULL) {
        perror("[RUN] mkdtemp jail_root em /tmp");
        return -1;
    }
    /* A partir daqui, usar jail_root em vez de vault_path para todas as
     * operações de montagem e isolamento de filesystem (o bind de verdade
     * só acontece dentro do filho, mais abaixo). */
    const char *vault_path_orig = vault_path;
    vault_path = jail_root;

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

    /*
     *  PROCESSO PAI — escreve uid/gid map e aguarda o filho
     * */
    if (pid > 0) {
        vault_auth_pid_add_ffi(pid);

        close(ready_pipe[1]);
        close(sync_pipe[0]);

        /* Aguarda filho sinalizar que fez unshare(CLONE_NEWUSER) */
        char c;
        if (read(ready_pipe[0], &c, 1) != 1)
            perror("[RUN] ready_pipe read");
        close(ready_pipe[0]);

        /* Escreve uid_map/gid_map usando o helper do vault_sandbox.c.
         * Se falhar (nem newuidmap/newgidmap nem write direto funcionaram),
         * o filho ficaria preso como UID/GID de overflow (65534) — mata ele
         * em vez de liberar pra rodar num estado quebrado (ver cadeia de
         * falhas em cascata que isso causa: FUSE EACCES em tudo, /dev/null
         * nunca criado, crash do app). */
        if (vsb_write_uid_gid_map(pid, real_uid, real_gid) != 0) {
            fprintf(stderr, "[RUN][FATAL] uid_map/gid_map falhou — abortando sandbox.\n");
            kill(pid, SIGKILL);
            close(sync_pipe[1]);
            int status;
            waitpid(pid, &status, 0);
            vault_auth_pid_remove_ffi(pid);
            umount2(jail_root, MNT_DETACH);
            rmdir(jail_root);
            return -1;
        }

        /* Libera filho para continuar */
        close(sync_pipe[1]);

        int status;
        waitpid(pid, &status, 0);
        vault_auth_pid_remove_ffi(pid);

        /* Limpa jail_root temporário (/tmp/Nuk4sd-jail-XXXXXX):
         * desmonta o bind do vault FUSE e remove o diretório vazio. */
        if (umount2(jail_root, MNT_DETACH) != 0)
            fprintf(stderr, "[RUN] umount jail_root '%s': %s (non-fatal)\n",
                    jail_root, strerror(errno));
        rmdir(jail_root);

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

    /*
     *  PROCESSO FILHO — sandbox de 5 camadas + isolamentos extras
     * */
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

    /* ── bind-monta o vault FUSE → SUBPASTA dedicada dentro de jail_root ──
     * Precisa acontecer AQUI (depois do unshare(CLONE_NEWNS) acima), não
     * antes do fork() no pai: mount() exige CAP_SYS_ADMIN, e sem sudo só
     * temos essa capability (namespaced) depois de criar nosso próprio
     * user+mount namespace. Ver comentário no processo pai sobre jail_root.
     *
     * [FIX ESTRUTURAL] Antes, isso montava o vault DIRETO em cima de
     * jail_root (mount(vault, jail_root, ...)) — o que SUBSTITUI o
     * conteúdo de jail_root pelo do vault, em vez de empilhar um dentro do
     * outro. Resultado: jail_root parava de ser tmpfs real e virava, na
     * prática, o próprio FUSE do vault — e QUALQUER coisa criada depois
     * (--dev, --ro-home, os autodirs de GUI) esbarrava nas regras do FUSE
     * (que não permite mkdir/create arbitrário), explicando TODOS os
     * "[FUSE] create/mkdir failed: -13" que apareciam em cascata.
     *
     * Agora: jail_root continua tmpfs real na raiz. O vault fica numa
     * subpasta dedicada (jail_root/vault) — scaffolding do jail (dev,
     * etc, home real via --ro-home, autodirs de GUI) roda livre no tmpfs
     * de verdade, sem nunca tocar o FUSE do vault sem querer. */
    char vault_mount_point[PATH_MAX];
    snprintf(vault_mount_point, sizeof(vault_mount_point), "%s/vault", jail_root);
    if (mkdir(vault_mount_point, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "[RUN] mkdir subpasta do vault '%s': %s\n",
                vault_mount_point, strerror(errno));
        _exit(1);
    }
    if (mount(vault_path_orig, vault_mount_point, NULL, MS_BIND | MS_REC, NULL) != 0) {
        fprintf(stderr, "[RUN] bind-mount vault→'%s': %s\n",
                vault_mount_point, strerror(errno));
        _exit(1);
    }
    fprintf(stderr, "[RUN] jail_root: '%s' (tmpfs real; vault em '%s/vault')\n",
            jail_root, jail_root);

    /* Prepara estrutura de jail (dev/proc/tmp/bin/lib/...) em jail_root,
     * que agora É tmpfs real de verdade — nunca mais toca o FUSE do vault
     * sem querer. */
    vsb_prepare_jail(vault_path, gui_mode);

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
        if (WIFSIGNALED(st)) {
            int sig = WTERMSIG(st);
            fprintf(stderr,
                "[RUN][FATAL] processo filho (PID 1 do namespace) morto pelo sinal %d (%s)"
                " — possível violação de seccomp/allowlist se sig=31 (SIGSYS). "
                "Verifique 'dmesg' por 'audit: type=1326 ... comm=\"<processo>\" syscall=N'.\n",
                sig, strsignal(sig));
            _exit(128 + sig);
        }
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
    }

    /* ══ PID 1 dentro do namespace ═══ */

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

        case BIND_RO: {
            char dst[PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, src);

            if (!bind_path_is_safe(vault_path, dst)) {
                fprintf(stderr, "[RUN] --ro '%s': path escapes vault jail — refusing\n", src);
                cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC, EPERM);
                break;
            }

            if (S_ISDIR(st.st_mode)) {
                if (cli_mkdir_p(dst, 0755) != 0) {
                    fprintf(stderr, "[RUN] --ro mkdir_p '%s': %s\n", dst, strerror(errno));
                    cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC, errno);
                    break;
                }
            } else {
                /* garante o diretório pai antes de criar o arquivo de destino */
                char parent[PATH_MAX];
                snprintf(parent, sizeof(parent), "%s", dst);
                char *slash = strrchr(parent, '/');
                if (slash) { *slash = '\0'; cli_mkdir_p(parent, 0755); }

                int fd = open(dst, O_CREAT | O_WRONLY, 0666);
                if (fd >= 0) {
                    close(fd);
                } else {
                    fprintf(stderr, "[RUN] --ro open '%s': %s\n", dst, strerror(errno));
                    cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC, errno);
                    break;
                }
            }
            if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) == 0) {
                mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
                /* FIX #3: verificar que dst não é symlink fora do jail (race TOCTOU) */
                int check_fd = open(dst, O_PATH | O_NOFOLLOW | O_CLOEXEC);
                if (check_fd < 0 && errno == ELOOP) {
                    fprintf(stderr, "[RUN] --ro '%s': symlink escape detectado — desmontando\n", src);
                    umount2(dst, MNT_DETACH);
                    cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC, EPERM);
                } else {
                    if (check_fd >= 0) close(check_fd);
                    cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC | MS_RDONLY, 0);
                }
            } else {
                fprintf(stderr, "[RUN] --ro bind '%s': %s\n", src, strerror(errno));
                cli_log_mount_event(src, dst, "bind-ro", MS_BIND | MS_REC, errno); 
            }
            break;
        }
        case BIND_RW: {
            char dst[PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, src);

            if (!bind_path_is_safe(vault_path, dst)) {
                fprintf(stderr, "[RUN] --rw '%s': path escapes vault jail — refusing\n", src);
                cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, EPERM);
                break;
            }

            /* cria o destino ANTES de montar */
            if (S_ISDIR(st.st_mode)) {
                if (cli_mkdir_p(dst, 0755) != 0) {
                    fprintf(stderr, "[RUN] --rw mkdir_p '%s': %s\n", dst, strerror(errno));
                    cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, errno);
                    break;
                }
            } else {
                char parent[PATH_MAX];
                snprintf(parent, sizeof(parent), "%s", dst);
                char *slash = strrchr(parent, '/');
                if (slash) { *slash = '\0'; cli_mkdir_p(parent, 0755); }

                int fd = open(dst, O_CREAT | O_WRONLY, 0666);
                if (fd >= 0) {
                    close(fd);
                } else {
                    fprintf(stderr, "[RUN] --rw open '%s': %s\n", dst, strerror(errno));
                    cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, errno);
                    break;
                }
            }

            if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) != 0) {
                fprintf(stderr, "[RUN] --rw bind '%s': %s\n", src, strerror(errno));
                cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, errno);
            } else {
                /* FIX #8: remount com MS_NOSUID|MS_NODEV para prevenir escalonamento
                 * via device nodes ou SUID binaries dentro do bind-rw */
                mount(NULL, dst, NULL,
                      MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_REC, NULL);
                /* FIX #3: verificar symlink escape pós-mount */
                int check_fd = open(dst, O_PATH | O_NOFOLLOW | O_CLOEXEC);
                if (check_fd < 0 && errno == ELOOP) {
                    fprintf(stderr, "[RUN] --rw '%s': symlink escape detectado — desmontando\n", src);
                    umount2(dst, MNT_DETACH);
                    cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, EPERM);
                } else {
                    if (check_fd >= 0) close(check_fd);
                    cli_log_mount_event(src, dst, "bind-rw", MS_BIND | MS_REC, 0);
                }
            }
            break;
        }
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

    /* ── --ro-home / --rw-home: Mapeia o $HOME original para dentro do jail ─── */
    if (cfg->iso_ro_home || cfg->iso_rw_home) {
        const char *sudo_user = getenv("SUDO_USER");
        char home[PATH_MAX] = {0};
        if (sudo_user && *sudo_user) {
            /* FIX #4: validar SUDO_USER contra charset seguro — recusar '/', '.', '\' etc.
             * Previne path traversal: SUDO_USER=../../../../etc/shadow → /home/../../../../etc/shadow */
            bool sudo_user_safe = (strlen(sudo_user) < 64 &&
                                   strpbrk(sudo_user, "/.\\ :@!") == NULL);
            if (sudo_user_safe) {
                snprintf(home, sizeof(home), "/home/%s", sudo_user);
            } else {
                fprintf(stderr, "[RUN] SUDO_USER cont\u00e9m caracteres inv\u00e1lidos — ignorando (possivel path traversal)\n");
                /* fallback para HOME ou getpwuid() abaixo */
            }
        }
        if (!home[0]) {
            const char *h = getenv("HOME");
            if (h && *h) {
                snprintf(home, sizeof(home), "%s", h);
            } else {
                struct passwd *pw = getpwuid(real_uid);
                if (pw && pw->pw_dir)
                    snprintf(home, sizeof(home), "%s", pw->pw_dir);
            }
        }

        struct stat st;
        if (home[0] && stat(home, &st) == 0) {
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, home);

            /* Antes de bind-montar o $HOME real, desvincula o FUSE
             * endpoint órfão do vault que foi herdado via MS_BIND|MS_REC.
             * Sem isso, o subdiretório .local/share/Nuk4sd fica como um
             * dead-end FUSE e qualquer IO (ex: recently-used.xbel do GTK)
             * falha com "endpoint desconectado". */
            if (cli_mkdir_p(dst, 0755) == 0) {
                char nuk_fuse[VAULT_PATH_MAX];
                snprintf(nuk_fuse, sizeof(nuk_fuse),
                         "%s%s/.local/share/Nuk4sd", vault_path, home);
                umount2(nuk_fuse, MNT_DETACH); /* ignora EINVAL se não estava montado */

                if (mount(home, dst, NULL, MS_BIND | MS_REC, NULL) == 0) {
                    if (cfg->iso_ro_home) {
                        mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
                    } else {
                        /* rw-home: após o bind, o Nuk4sd dentro do home
                         * aparece novamente como FUSE (agora ligado ao
                         * namespace do jail). Cobre com tmpfs para
                         * evitar que o app acesse o cofre diretamente. */
                        char nuk_mnt[VAULT_PATH_MAX];
                        snprintf(nuk_mnt, sizeof(nuk_mnt),
                                 "%s%s/.local/share/Nuk4sd", vault_path, home);
                        if (cli_mkdir_p(nuk_mnt, 0700) == 0) {
                            mount("tmpfs", nuk_mnt, "tmpfs",
                                  MS_NOSUID | MS_NODEV, "size=4m");
                        }
                    }
                } else {
                    fprintf(stderr, "[RUN] --rw-home bind '%s' -> '%s': %s\n", home, dst, strerror(errno));
                }
            }
        }
    }


    /* --tmp-home: movido para depois do pivot_root() + remount de /tmp —
     * ver bloco pós-isolamento mais abaixo. Montar aqui (pré-pivot) cria o
     * diretório no /tmp do HOST, que fica órfão assim que pivot_root() troca
     * a raiz — $HOME acaba apontando pra um path inexistente dentro do jail. */

    /* ── --wayland: passa socket Wayland read-only ────────────────────────
     * Dois problemas corrigidos aqui:
     *
     * 1) getuid() sozinho quebra quando invocado via `sudo`: nesse caso o
     *    processo inteiro já roda como UID 0 desde o main(), então
     *    getuid()==0 aponta pra /run/user/0 (que geralmente nem existe),
     *    em vez do /run/user/<uid real> onde o compositor Wayland da
     *    sessão gráfica realmente cria o socket. `sudo` exporta o UID
     *    original em $SUDO_UID — usamos isso como fonte preferencial.
     *
     * 2) "wayland-0" estava hardcoded — nem todo mundo usa esse nome de
     *    socket (pode ser wayland-1, etc, dependendo da sessão). Lemos
     *    $WAYLAND_DISPLAY do ambiente e só caímos pro default se não
     *    existir.
     *
     * Observação: se `sudo` foi chamado sem `-E` (ou sudoers sem
     * env_keep pra essas variáveis), o próprio sudo já apaga
     * $WAYLAND_DISPLAY antes do nosso processo nascer — nesse caso não
     * tem o que o Nuk4sd faça sozinho; é preciso `sudo -E` ou configurar
     * env_keep no sudoers para XDG_RUNTIME_DIR/WAYLAND_DISPLAY/DISPLAY. */
    if (cfg->iso_wayland) {
        char xdg[128];
        snprintf(xdg, sizeof(xdg), "/run/user/%d", (int)real_uid);

        /* Cria ponto de montagem dentro do vault */
        char dst_xdg[VAULT_PATH_MAX];
        snprintf(dst_xdg, sizeof(dst_xdg), "%s%s", vault_path, xdg);
        mkdir(dst_xdg, 0700);

        struct stat ws;
        if (stat(xdg, &ws) == 0) {
            if (mount(xdg, dst_xdg, NULL, MS_BIND | MS_REC, NULL) == 0)
                mount(NULL, dst_xdg, NULL,
                      MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        } else {
            fprintf(stderr,
                "[RUN] --wayland: '%s' não encontrado (uid real=%d) — "
                "socket Wayland não será montado\n", xdg, (int)real_uid);
        }

        const char *host_wayland_display = getenv("WAYLAND_DISPLAY");
        if (host_wayland_display && *host_wayland_display) {
            setenv("WAYLAND_DISPLAY", host_wayland_display, 1);
        } else {
            char wayland_sock[VAULT_PATH_MAX];
            snprintf(wayland_sock, sizeof(wayland_sock), "%s/wayland-0", xdg);
            struct stat st_w0;
            if (stat(wayland_sock, &st_w0) == 0) {
                setenv("WAYLAND_DISPLAY", "wayland-0", 1);
            } else {
                unsetenv("WAYLAND_DISPLAY");
            }
        }
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

        /* XAUTHORITY: sem isso o X server recusa a conexão com
         * "Authorization required, but no authorization protocol
         * specified" — porque, sob `sudo`, $HOME normalmente vira
         * /root, então o cookie MIT-MAGIC-COOKIE do usuário real (em
         * ~<usuário real>/.Xauthority) nunca é encontrado. Resolvemos
         * o UID/HOME reais (mesma lógica do --wayland) e priorizamos
         * $XAUTHORITY já setado no ambiente, com fallback pro caminho
         * padrão dentro do HOME do usuário real. */
        const char *xauth_src = getenv("XAUTHORITY");
        char xauth_fallback[VAULT_PATH_MAX];
        if (!xauth_src || !*xauth_src) {
            struct passwd *pw = getpwuid(real_uid);
            if (pw && pw->pw_dir) {
                snprintf(xauth_fallback, sizeof(xauth_fallback), "%s/.Xauthority", pw->pw_dir);
                xauth_src = xauth_fallback;
            }
        }
        if (xauth_src && *xauth_src) {
            struct stat xa_st;
            if (stat(xauth_src, &xa_st) == 0 && S_ISREG(xa_st.st_mode)) {
                char xauth_dst[VAULT_PATH_MAX];
                snprintf(xauth_dst, sizeof(xauth_dst), "%s/tmp/.Xauthority", vault_path);
                int fd = open(xauth_dst, O_CREAT | O_WRONLY, 0600);
                if (fd >= 0) close(fd);
                if (mount(xauth_src, xauth_dst, NULL, MS_BIND, NULL) == 0)
                    mount(NULL, xauth_dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
                setenv("XAUTHORITY", "/tmp/.Xauthority", 1);
            } else {
                fprintf(stderr,
                    "[RUN] --x11: XAUTHORITY '%s' não encontrado — "
                    "conexão X11 provavelmente será recusada\n", xauth_src);
            }
        }
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

    /* ── /tmp tmpfs dentro do vault ───────────────────────────────────────
     * REMOVIDO: este mount pré-pivot era redundante — o remount pós-pivot
     * (mais abaixo, logo após pivot_root()) sempre sobrescreve /tmp de
     * qualquer forma. Montar tmpfs aqui só servia pra soterrar qualquer
     * --ro/--rw que o usuário tenha aplicado sob /tmp antes deste ponto.
     *
     * LIMITAÇÃO CONHECIDA: qualquer --ro/--rw/--blacklist cujo destino
     * caia sob /tmp ainda é sobrescrito pelo remount pós-pivot de /tmp
     * (necessário para --tmp-size e para dar um /tmp limpo por padrão).
     * Fix definitivo requer mover o loop de bind mounts pra depois desse
     * remount — fica registrado como TODO para o refactor de
     * vsb_apply_binds() já planejado. */

    /* ── GUI auto-dirs: monta /usr /lib /lib64 /etc/fonts + arquivos /etc
     *    críticos para o dynamic linker e apps GUI read-only ──────────────
     *
     * Diretórios montados com MS_BIND|MS_REC|RDONLY:
     *   /usr /lib /lib64        — binários e bibliotecas do sistema
     *   /etc/fonts              — fontconfig (GTK/Qt precisam)
     *   /etc/alternatives       — update-alternatives links
     *   /etc/ld.so.conf.d       — paths extras do dynamic linker
     *   /etc/ssl                — certificados TLS (HTTPS)
     *   /sys/dev/char           — device numbers (udev queries)
     *   /sys/devices            — árvore real dos dispositivos PCI/DRM: os
     *                             symlinks em /sys/dev/char/MAJOR:MINOR
     *                             apontam pra cá. Sem isso, o Mesa segue o
     *                             link e cai num caminho inexistente dentro
     *                             do jail — "MESA-LOADER: failed to
     *                             retrieve device information" / "egl:
     *                             failed to create dri2 screen".
     *   /sys/class              — mesma razão: alguns loaders (libdrm,
     *                             udev) consultam /sys/class/drm além do
     *                             caminho via /sys/dev/char.
     *
     * Arquivos bind-montados individualmente (read-only):
     *   /etc/ld.so.cache        — cache do dynamic linker: SEM ISSO o
     *                             ld-linux não resolve as .so do Firefox
     *                             e o processo termina antes de main().
     *   /etc/nsswitch.conf      — resolução NSS: getpwuid/getgrnam/
     *                             gethostbyname usados pelo GLib/Firefox.
     *   /etc/passwd /etc/group  — getpwuid() para HOME, username, etc.
     *   /etc/localtime          — fuso horário: glib chama no startup.
     *   /etc/resolv.conf        — DNS: sem isso Firefox não resolve nomes.
     *
     * Nota: /etc/ssl já inclui /etc/ssl/certs (certificados raiz TLS).
     * ─────────────────────────────────────────────────────────────────── */
    if (gui_mode) {
        const char *host_dirs[] = {
            /* Ordem importa: /usr precisa vir antes de /usr/share/icons.
             * A entrada explícita /usr/share/icons garante que os ícones do
             * host sobrescrevem qualquer esqueleto físico do vault, evitando
             * o erro "endpoint desconectado" do GTK (evince, gnome-calc). */
            "/usr", "/lib", "/lib64",
            "/usr/share/icons",
            "/etc/fonts", "/etc/alternatives",
            "/etc/ld.so.conf.d",
            "/etc/ssl",
            "/sys/dev/char", "/sys/devices", "/sys/class", NULL
        };

        for (int i = 0; host_dirs[i]; i++) {
            struct stat hst;
            if (stat(host_dirs[i], &hst) != 0) continue;
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, host_dirs[i]);

            if (S_ISDIR(hst.st_mode) && cli_mkdir_p(dst, 0755) != 0) {
                /* Componente pai (ex: "/etc") ainda não existe dentro do
                 * vault fresco — mkdir_p cria a árvore inteira. Sem isso,
                 * um mkdir() de um nível só falhava com ENOENT pra
                 * "/etc/fonts" e "/etc/alternatives" (pai "/etc" ausente),
                 * o mount() seguinte falhava também, e nada disso era
                 * logado: /etc inteiro simplesmente não existia dentro do
                 * jail e programas GUI (fontconfig/NSS) morriam cedo. */
                fprintf(stderr, "[RUN] gui-autodir mkdir_p '%s': %s\n", dst, strerror(errno));
                cli_log_mount_event(host_dirs[i], dst, "gui-autodir", MS_BIND | MS_REC, errno);

                continue;
            }
            /* Descarta o submount FUSE herdado do vault bind-mount antes de
             * sobrescrever com o path real do host. Sem isso, o kernel
             * mantém os stubs FUSE do cofre como dead-ends dentro da árvore
             * do /usr, e o GTK morre com "endpoint desconectado" ao tentar
             * abrir ícones (ex: Mint-X/status/16/image-missing.png). */
            umount2(dst, MNT_DETACH); /* ignora EINVAL se não tinha nada montado */
            if (mount(host_dirs[i], dst, NULL, MS_BIND | MS_REC, NULL) == 0) {
                mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
                cli_log_mount_event(host_dirs[i], dst, "gui-autodir", MS_BIND | MS_REC | MS_RDONLY, 0);
            } else {
                fprintf(stderr, "[RUN] gui-autodir bind '%s': %s\n", host_dirs[i], strerror(errno));
                cli_log_mount_event(host_dirs[i], dst, "gui-autodir", MS_BIND | MS_REC, errno);
            }
        }


        /* Arquivos /etc individuais — bind-mount de arquivo único (não dir)
         * Precisam do diretório pai criado antes do open(O_CREAT).        */
        const char *etc_files[] = {
            "/etc/ld.so.cache",
            "/etc/nsswitch.conf",
            "/etc/passwd",
            "/etc/group",
            "/etc/localtime",
            "/etc/resolv.conf",
            NULL
        };
        for (int i = 0; etc_files[i]; i++) {
            struct stat est;
            if (stat(etc_files[i], &est) != 0) continue;
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, etc_files[i]);
            /* garante o diretório pai dentro do vault */
            char par[VAULT_PATH_MAX];
            snprintf(par, sizeof(par), "%s", dst);
            char *sl = strrchr(par, '/');
            if (sl) { *sl = '\0'; cli_mkdir_p(par, 0755); }
            int fd = open(dst, O_CREAT | O_WRONLY, 0644);
            if (fd >= 0) close(fd);
            if (mount(etc_files[i], dst, NULL, MS_BIND, NULL) == 0) {
                mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
                cli_log_mount_event(etc_files[i], dst, "gui-etc-file", MS_BIND | MS_RDONLY, 0);
            } else {
                fprintf(stderr, "[RUN] gui-etc-file bind '%s': %s\n",
                        etc_files[i], strerror(errno));
                cli_log_mount_event(etc_files[i], dst, "gui-etc-file", MS_BIND, errno);
            }
        }

        /* ── Variáveis de ambiente GTK/GDK: loaders de imagem e ícones ──────
         * Sem GDK_PIXBUF_MODULE_FILE, o GTK não sabe onde estao os decoders
         * de PNG/SVG/etc, então qualquer ícone falha com "image format not
         * recognized" e o app trava (evince, gnome-calculator, etc).
         * Colocamos a variável apontando para o loaders.cache do host que
         * ja foi bind-montado via /usr. */
        /* O ambiente GTK herda o PATH do host. Tentar forçar o 
         * GDK_PIXBUF_MODULE_FILE frequentemente quebra os loaders embutidos
         * de PNG, causando o erro "image format not recognized" com GResource. */
    }

    /*═
     *  DESKTOP RUNTIME — audio, dbus, gpu, xdg-runtime, dev, display
     * ===================================================================== */

    /* Helper: garante /run/user/$UID dentro do vault */
#define ENSURE_XDG_DIR(xdg_buf, xdg_buf_sz)                                    \
    do {                                                                       \
        uid_t _ru_uid = real_uid;                                   \
        char _r[VAULT_PATH_MAX], _ru[VAULT_PATH_MAX], _rxu[VAULT_PATH_MAX];    \
        snprintf(_r,   sizeof(_r),   "%s/run",            vault_path);         \
        snprintf(_ru,  sizeof(_ru),  "%s/run/user",       vault_path);         \
        snprintf(_rxu, sizeof(_rxu), "%s/run/user/%d",    vault_path, (int)_ru_uid); \
        mkdir(_r, 0755); mkdir(_ru, 0755); mkdir(_rxu, 0700);                  \
        snprintf((xdg_buf), (xdg_buf_sz), "/run/user/%d", (int)_ru_uid);       \
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
        snprintf(xdg_env, sizeof(xdg_env), "/run/user/%d", (int)real_uid);
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
        snprintf(addr, sizeof(addr), "unix:path=/run/user/%d/bus", (int)real_uid);
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
        }
    }

    /* ── --dev minimal/standard: nós /dev adicionais ───────────────────────
     * Mesmo bug dos outros dois blocos (gui-autodir): o vault fresco não
     * tem NENHUM "/dev" dentro dele. open(dst, O_CREAT) e mkdir(shm_dst)
     * assumiam que o pai "/dev" já existia — sem isso, ambos falhavam com
     * ENOENT silenciosamente, então /dev/urandom, /dev/random, /dev/shm e
     * /dev/fuse nunca eram criados de fato, mesmo com --dev standard. */
    if (cfg->iso_dev_level >= 1) {
        char dev_dir[VAULT_PATH_MAX];
        snprintf(dev_dir, sizeof(dev_dir), "%s/dev", vault_path);
        if (cli_mkdir_p(dev_dir, 0755) != 0)
            fprintf(stderr, "[RUN] --dev: mkdir_p '%s': %s\n", dev_dir, strerror(errno));

        /* minimal: null, zero, tty, urandom, random, shm */
        const char *devs[] = { "/dev/null", "/dev/zero", "/dev/tty", "/dev/urandom", "/dev/random", NULL };
        for (int i = 0; devs[i]; i++) {
            char dst[VAULT_PATH_MAX];
            snprintf(dst, sizeof(dst), "%s%s", vault_path, devs[i]);
            int fd = open(dst, O_CREAT|O_WRONLY, 0444);
            if (fd >= 0) close(fd);
            else fprintf(stderr, "[RUN] --dev: criar node '%s': %s\n", dst, strerror(errno));
            if (mount(devs[i], dst, NULL, MS_BIND, NULL) != 0)
                fprintf(stderr, "[RUN] --dev: bind '%s': %s\n", devs[i], strerror(errno));
        }
        char shm_dst[VAULT_PATH_MAX];
        snprintf(shm_dst, sizeof(shm_dst), "%s/dev/shm", vault_path);
        if (mkdir(shm_dst, 01777) != 0 && errno != EEXIST)
            fprintf(stderr, "[RUN] --dev: mkdir '%s': %s\n", shm_dst, strerror(errno));
        if (mount("tmpfs", shm_dst, "tmpfs", MS_NOSUID|MS_NODEV, "size=256m") != 0)
            fprintf(stderr, "[RUN] --dev: mount tmpfs em '%s': %s\n", shm_dst, strerror(errno));
    }
    if (cfg->iso_dev_level >= 2) {
        /* standard: adiciona /dev/fuse para apps que usam FUSE interno */
        char fuse_dst[VAULT_PATH_MAX];
        snprintf(fuse_dst, sizeof(fuse_dst), "%s/dev/fuse", vault_path);
        struct stat fst;
        if (stat("/dev/fuse", &fst) == 0) {
            int fd = open(fuse_dst, O_CREAT|O_WRONLY, 0660);
            if (fd >= 0) close(fd);
            else fprintf(stderr, "[RUN] --dev: criar node '%s': %s\n", fuse_dst, strerror(errno));
            if (mount("/dev/fuse", fuse_dst, NULL, MS_BIND, NULL) != 0)
                fprintf(stderr, "[RUN] --dev: bind '/dev/fuse': %s\n", strerror(errno));
        }
    }

    /* ── --display/:--wayland-display: override explícito de display ────── */
    if (cfg->iso_display)
        setenv("DISPLAY", cfg->iso_display, 1);
    if (cfg->iso_wayland_disp)
        setenv("WAYLAND_DISPLAY", cfg->iso_wayland_disp, 1);

    /* ── Firefox: desativa o sandbox INTERNO do content process ──────────
     *
     * O Nuk4sd já dropa TODAS as Linux Capabilities (Layer 4) antes do
     * exec, incluindo CAP_SYS_CHROOT. O Firefox, por padrão, tenta montar
     * seu PRÓPRIO sandbox de content-process (chamando chroot()/capset()
     * de novo, um nível "dentro" do nosso). Isso sempre falha aqui —
     * é exatamente o que aparece em TODA execução:
     *
     *   [N] Sandbox: capset (drop all): EPERM
     *   [N] Sandbox: capset (chroot helper): EPERM
     *   [N] Sandbox: chroot: EPERM
     *
     * Builds recentes do Firefox tratam essa falha do sandbox interno
     * como fatal para o content process conseguir *renderizar* — o
     * processo não crasha, mas a aba fica permanentemente em branco
     * (exatamente o sintoma reportado: janela abre, título "Firefox"
     * aparece, mas a página nunca desenha nada, mesmo depois de vários
     * minutos, até fechar).
     *
     * Como o Nuk4sd JÁ isola o processo inteiro (user/mount/pid
     * namespaces + seccomp-BPF + pivot_root + cap drop total), o
     * sandbox aninhado do Firefox é redundante aqui — desativá-lo não
     * é uma regressão de segurança relevante neste contexto. */
    if (gui_mode) {
        // setenv("MOZ_DISABLE_CONTENT_SANDBOX", "1", 1);
        setenv("MOZ_NO_REMOTE", "1", 1);
    }
#undef ENSURE_XDG_DIR

    /* ── [Camada 3] Isolamento de filesystem ────────────────────────────── *
     *  --chroot : mais simples, funciona sem suporte pleno a mount NS.     *
     *  padrão   : pivot_root — mais seguro, sem acesso ao oldroot.         *
     *                                                                       *
     *  Nota: chroot() funciona dentro do user namespace porque UID 0 do    *
     *  namespace tem CAP_SYS_CHROOT internamente, sem exigir root no host. */
    if (cfg->iso_use_chroot) {
        if (chroot(vault_path) != 0) {
            fprintf(stderr, "[RUN] chroot '%s': %s\n", vault_path, strerror(errno));
            cli_log_pivot_root(vault_path, errno);
            _exit(1);
        }
        if (chdir("/") != 0) {
            perror("[RUN] chdir / after chroot");
            _exit(1);
        }
        cli_log_pivot_root(vault_path, 0);
        fprintf(stderr, "[RUN] [INFO] filesystem isolado via chroot\n");
    } else {
        if (vsb_pivot_root(vault_path, !cfg->iso_no_proc) != 0) {
            fprintf(stderr, "[RUN] pivot_root '%s': %s — tente --chroot como fallback\n",
                    vault_path, strerror(errno));
            cli_log_pivot_root(vault_path, errno);
            _exit(1);
        }
        cli_log_pivot_root(vault_path, 0);
    }

    /* ── Remonta /proc fresco após isolamento ──────────────────────────────
     *
     * Problema que este bloco resolve:
     *   Antes do pivot_root(), o código monta /proc do HOST via bind-mount
     *   (ou herda via MS_REC do namespace pai). Esse /proc contém os PIDs
     *   reais do host — visíveis dentro do sandbox mesmo após o pivot.
     *   No teste de escape, o sandbox mostrava 5 PIDs externos em vez de
     *   só o PID 1 interno.
     *
     * Solução em 3 etapas com tratamento de erro em cada:
     *
     *   [1] umount2(MNT_DETACH): desacopla o /proc herdado sem bloquear
     *       em processos que ainda têm handles abertos. MNT_DETACH é o
     *       equivalente ao "lazy unmount" — o mountpoint some da árvore
     *       imediatamente mas o kernel mantém a referência enquanto há
     *       processos com FDs abertos. Falha esperada se já foi
     *       desmontado (EINVAL) — tratamos como não-fatal.
     *
     *   [2] mkdir("/proc", 0555): cria o mountpoint se não existir.
     *       Se já existe (EEXIST) é OK — continuamos.
     *       Qualquer outro erro (EROFS, EACCES) é registrado mas não
     *       mata o processo, pois /proc pode já existir do jail_prepare.
     *
     *   [3] mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV):
     *       Monta um procfs NOVO, que enxerga APENAS os PIDs do PID
     *       namespace atual (criado pelo unshare(CLONE_NEWPID) mais cedo).
     *       Resultado: dentro do sandbox, /proc lista só PID 1 (o próprio
     *       processo) e seus filhos — zero PIDs do host visíveis.
     *       Se falhar, o sandbox continua mas registramos o erro no audit
     *       log para que o operador saiba que o /proc está "sujo".
     *
     * Flags de montagem:
     *   MS_NOSUID  — binários setuid em /proc não ganham privilégio
     *   MS_NOEXEC  — não executa binários direto de /proc
     *   MS_NODEV   — ignora device nodes em /proc (não há, mas defesa extra)
     */
    if (!cfg->iso_no_proc && cfg->iso_use_chroot) {
        /* [1] Desacopla /proc herdado do host (lazy — não bloqueia) */
        if (umount2("/proc", MNT_DETACH) != 0 && errno != EINVAL && errno != ENOENT) {
            vault_log(LOG_WARN,
                      "[SANDBOX] umount2('/proc', MNT_DETACH): %s — "
                      "continuando (proc legado pode vazar PIDs do host)",
                      strerror(errno));
        }

        /* [2] Garante que o mountpoint existe */
        if (mkdir("/proc", 0555) != 0 && errno != EEXIST) {
            vault_log(LOG_WARN,
                      "[SANDBOX] mkdir('/proc'): %s — "
                      "tentando montar mesmo assim",
                      strerror(errno));
        }

        /* [3] Monta procfs novo, scoped ao PID namespace atual */
        if (mount("proc", "/proc", "proc",
                  MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0) {
            vault_log(LOG_ERROR,
                      "[SANDBOX] mount('/proc', procfs): %s — "
                      "sandbox pode expor PIDs do host! "
                      "Use --no-proc para desativar /proc completamente.",
                      strerror(errno));
            /* Não mata o processo: apps como bash, ps e top precisam de
             * /proc, mas se o mount falhou o sandbox ainda está isolado
             * em todos os outros vetores (caps, seccomp, filesystem). */
        } else {
            vault_log(LOG_INFO,
                      "[SANDBOX] /proc remontado (procfs fresco, PID-namespace scoped) "
                      "— PIDs do host não visíveis dentro do sandbox.");
        }
    } else {
        /* --no-proc: desacopla qualquer /proc legado sem montar nada novo */
        umount2("/proc", MNT_DETACH); /* ignora erro: pode não haver nada */
        vault_log(LOG_INFO, "[SANDBOX] --no-proc: /proc desativado.");
    }
    {
        int sz = cfg->iso_tmp_size_mb ? cfg->iso_tmp_size_mb : 64;
        char sz_opt[32]; snprintf(sz_opt, sizeof(sz_opt), "size=%dm", sz);
        mkdir("/tmp", 01777);
        if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, sz_opt) != 0)
            perror("[RUN] mount /tmp post-isolamento (non-fatal)");
    }

    /* ── --tmp-home: $HOME efêmero em tmpfs ───────────────────────────────
     * Precisa rodar AQUI (pós pivot_root() + remount de /tmp), não antes.
     * mkdtemp() antes do pivot cria o diretório no /tmp do HOST, que fica
     * órfão assim que pivot_root() troca a raiz — $HOME acabava apontando
     * pra um path que não existe dentro do jail. Rodando depois, "/tmp"
     * já se refere ao /tmp do próprio vault, então o path resultante é
     * válido para o processo que vamos exec() a seguir. */
    if (cfg->iso_tmp_home) {
        char th[] = "/tmp/Nuk4sd-home-XXXXXX";
        char *dir = mkdtemp(th);   /* mkdtemp() já cria o diretório */
        if (dir) {
            setenv("HOME", dir, 1);

            /* [ATUALIZADO] Com o mapa de linha única (ver userns.c), o
             * processo já É o UID real desde o início — não existe mais uma
             * fase "ainda root" seguida de um drop. Esse mkdtemp() já cria
             * o diretório dono=real_uid diretamente. O chown() abaixo vira
             * um no-op na maioria dos casos (já é o dono certo); mantido
             * só como rede de segurança pro caso sudo, onde real_uid pode
             * ser 0 de propósito (root real, sem redesign nenhum aqui). */
            if (gui_mode && real_uid != 0) {
                if (chown(dir, real_uid, real_gid) != 0)
                    perror("[RUN] --tmp-home chown para real_uid/real_gid");
            }
        } else {
            perror("[RUN] --tmp-home mkdtemp");
        }
    }

    /* [REDESIGN] O setresuid()/setresgid() que existia aqui não funciona
     * mais e nunca vai funcionar de novo: dependia de um SEGUNDO ns-uid
     * mapeado (real_uid -> real_uid) pra "cair" nele depois do jail
     * montado. Esse segundo ns-uid não existe mais — o kernel rejeita
     * (EINVAL) qualquer uid_map com o mesmo outside-id repetido em duas
     * linhas (testado e confirmado diretamente, não é limitação de
     * newuidmap/CAP_SETUID). Ver sandbox_write_uid_gid_map() em userns.c.
     *
     * Não é substituível por "trocar pra outro uid": qualquer outro ns-id
     * mapearia pra um UID DIFERENTE do seu real, o que quebraria de novo o
     * acesso ao FUSE/socket Wayland — o problema que resolvemos ao trocar
     * pra mapa de linha única. O processo fica como ns-uid 0 (mapeado pro
     * seu UID real) do início ao fim — sem "drop" no meio, porque não tem
     * privilégio real sobrando pra dropar: capabilities já caem na Camada 4
     * logo abaixo, que é a proteção que realmente importa aqui. */
    if (gui_mode) {
        const char *sudo_user = getenv("SUDO_USER");
        if (sudo_user && !cfg->iso_tmp_home) {
            char orig_home[256];
            snprintf(orig_home, sizeof(orig_home), "/home/%s", sudo_user);
            setenv("HOME", orig_home, 1);
        }
    }

    /* ── [Camada 4] Drop capabilities + NO_NEW_PRIVS ────────────────────── */
    if (vsb_drop_caps() != 0) {
        fprintf(stderr, "[RUN] cap drop failed\n");
        cli_log_cap_drop(-1);
        _exit(1);
    }
    cli_log_cap_drop(0);

    /* Rlimits — valores das flags ou defaults ajustados por modo
     *
     * RLIMIT_AS (espaço de endereçamento virtual):
     *   gui_mode → 8 GB: browsers (Firefox/Chromium) com JIT SpiderMonkey/V8
     *     + processos de conteúdo + IPC + WebGL alocam agressivamente mmap()
     *     para regiões de memória virtual muito maiores que a RAM física em
     *     uso. Com 4 GB o content process morre com ENOMEM silenciosamente
     *     antes de renderizar a primeira página.
     *   modo CLI → 4 GB: conservador, suficiente para shells e utilitários.
     *
     * RLIMIT_FSIZE (tamanho máximo de arquivo escrito):
     *   gui_mode → 1 GB: Firefox grava cache, SQLite, downloads na sessão.
     *   modo CLI → 512 MB: suficiente para a maioria dos apps de terminal.
     *
     * Os valores explícitos das flags sempre sobrescrevem estes defaults. */
    {
        struct rlimit rl;
        int   p  = cfg->iso_max_procs    ? cfg->iso_max_procs    : 512;
        long  fs = cfg->iso_max_fsize_mb
                   ? (long)cfg->iso_max_fsize_mb * 1024 * 1024
                   : gui_mode
                       ? (long)1024 * 1024 * 1024        /* GUI: cache + downloads   */
                       : (long)512  * 1024 * 1024;       /* CLI: conservador         */
        int   fd = cfg->iso_max_fds      ? cfg->iso_max_fds      : 4096;
        if (cfg->iso_max_mem_gb > 0) {
            long m = (long)cfg->iso_max_mem_gb * 1024 * 1024 * 1024;
            rl.rlim_cur = rl.rlim_max = (rlim_t)m;  setrlimit(RLIMIT_AS,     &rl);
            cli_log_rlimit("RLIMIT_AS",     m, m);
        }
        rl.rlim_cur = rl.rlim_max = (rlim_t)p;  setrlimit(RLIMIT_NPROC,  &rl);
        cli_log_rlimit("RLIMIT_NPROC",  p, p);
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
        int permissive = cfg->permissive_sandbox || (gui_mode && !cfg->seccomp_strict);
        int friendly = cfg->friendly_sandbox || (gui_mode && !cfg->seccomp_strict);
        vsb_set_seccomp_mode(cfg->seccomp_strict ? 1 : 0, cfg->allow_clone3 ? 1 : 0,
                             friendly ? 1 : 0, permissive ? 1 : 0);
        vsb_set_mount_dev(cfg->iso_mount_dev);
        if (permissive) {
            vault_log(LOG_AUDIT,
                      "[SECURITY] Modo amigável GUI ATIVO │ exec='%s' │ vault_id=%d │ pid=%d │ "
                      "chroot/capset/setuid/setgid LIBERADOS no seccomp para sandbox interno do app.",
                      cfg->run_exec ? cfg->run_exec : "?", cfg->vault_id, (int)getpid());
        }

        /* [LANDLOCK] Terceira camada de MAC (restrição VFS) antes do Seccomp */
        if (!cfg->permissive_sandbox) {
            /* Só aplica Landlock em modo estrito, pois modo permissivo permite tudo */
            if (landlock_apply(cfg, vault_path) == 0) {
                if (cfg->verbose)
                    printf("  → [Layer 5] Landlock MAC enforced (VFS restrictions active)\n");
            }
        }

        /* [SECCOMP] Quarta camada de MAC (restrição de Syscalls) */
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

    /* ── FIX #2: Fechar todos os FDs antes do execvp (CVE-2024-21626 pattern) ──
     * Evita que o processo no sandbox herde FDs abertos apontando para paths
     * do host via /proc/self/fd/N. close_range() é atômico (Linux 5.9+);
     * fallback para loop manual em kernels mais antigos. */
#ifdef __linux__
    {
        /* Tenta close_range() primeiro (Linux 5.9+, syscall 436) */
        long cr = syscall(436, 3, ~0U, 0); /* close_range(3, UINT_MAX, 0) */
        if (cr != 0) {
            /* Fallback: loop manual */
            long max_fd = sysconf(_SC_OPEN_MAX);
            if (max_fd < 0) max_fd = 1024;
            for (long fd = 3; fd < max_fd; fd++)
                close((int)fd);
        }
    }
#endif

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

/*
 *  Dispatcher principal
 * */
static int dispatch(CliConfig *cfg) {
    int ret = 0;
    uint32_t id = (uint32_t)cfg->vault_id;

    /* ── Sem vault necessário ────────────────────────────────────────────── */
    if (cfg->op_help)    { print_help();                return 0; }
    if (cfg->op_version) { printf("Nuk4sd v0.9.30\n");  return 0; }
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
                     cfg->worm_protected_scan ||
                     /* --run precisa de vault_id apenas quando não usa --no-fuse */
                     (cfg->run_exec && !cfg->no_fuse));

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

    /*══
     *  Despacho por operação
     *══ */

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

    /* ── Container Whitelist ────────────────────────────────────────────── */
    if (cfg->op_whitelist_exclude || cfg->op_whitelist_restore) {
        VaultContainer c;
        memset(&c, 0, sizeof(c));
        c.id = id;
        c.sealed = 1;
        
        if (cfg->op_whitelist_exclude) {
            container_whitelist_exclude(&c);
        }
        if (cfg->op_whitelist_restore) {
            container_whitelist_restore(&c);
        }
        ret = -1;
        goto cleanup;
    }

    /* ── --image <alias|url> ────────────────────────────────────────────
     * Pull & extract a rootfs image from GitHub before launching the sandbox.
     * The image populates the container lowerdir that OverlayFS will stack.
     * On failure the flag is treated as non-fatal — the sandbox still launches
     * using the vault's own cipher_path as lowerdir (existing behaviour). */
    if (cfg->image_url) {
        char lowerdir[VAULT_PATH_MAX];
        snprintf(lowerdir, sizeof(lowerdir), "/tmp/nuk4sd-img-%u-XXXXXX", id);
        if (mkdtemp(lowerdir) == NULL) {
            perror("[IMAGE] mkdtemp lowerdir");
        } else {
            if (cfg->verbose)
                printf("  → pulling image '%s' into %s...\n", cfg->image_url, lowerdir);
            int pull_ret = rust_oci_pull_image(cfg->image_url, lowerdir);
            if (pull_ret != 0) {
                print_warn("Image pull failed — falling back to vault root.");
                rmdir(lowerdir);
            } else {
                if (cfg->verbose)
                    printf("  → image ready at %s\n", lowerdir);
                /* Store the extracted lowerdir path so run_isolated() can use it
                 * as the jail root instead of the FUSE vault path. */
                /* FIX #5: registrar que image_url foi alocado via strdup */
                cfg->no_fuse = true;
                cfg->image_url = strdup(lowerdir);
                cfg->image_url_allocated = true;
            }
        }
    }

    /* ── --run <exec> ──────────────────────────────────────────────────── */
    if (cfg->run_exec) {
        char vault_path[VAULT_PATH_MAX];

        if (cfg->no_fuse) {
            /* Se --image foi usado e a extração foi bem-sucedida, cfg->image_url
             * agora aponta para o rootfs extraído. Usamos ele diretamente como
             * jail root — sem criar um tmpdir vazio separado.
             * Caso contrário (--no-fuse sem --image): cria tmpdir vazio. */
            if (cfg->image_url) {
                /* rootfs OCI já extraído — usa diretamente */
                snprintf(vault_path, sizeof(vault_path), "%s", cfg->image_url);
                if (cfg->verbose)
                    printf("  → using OCI rootfs at '%s'\n", vault_path);
            } else {
                /* --no-fuse puro: tmpdir vazio como jail root */
                snprintf(vault_path, sizeof(vault_path), "/tmp/Nuk4sd-nofuse-XXXXXX");
                if (mkdtemp(vault_path) == NULL) {
                    perror("[RUN] --no-fuse: mkdtemp jail root");
                    ret = 1;
                    goto cleanup;
                }
                if (cfg->verbose)
                    printf("  --no-fuse: usando jail root em '%s' (sem FUSE)\n", vault_path);
            }
        } else {
            if (vault_get_real_path_ffi(id, vault_path, sizeof(vault_path)) != 0) {
                print_err("Vault not found or path unavailable.");
                ret = 1;
                goto cleanup;
            }

            /* Monta o vault via FUSE antes de isolar (será visível dentro) */
            if (cfg->verbose)
                printf("  → mounting vault %u via FUSE...\n", id);
            vault_mount_ffi(id, pass ? pass : "");
        }

        if (cfg->verbose) {
            printf("  → exec: %s", cfg->run_exec);
            for (int i = 0; i < cfg->run_argc; i++)
                printf(" %s", cfg->run_argv[i]);
            printf("\n");
            printf("  → net=%s  wayland=%d  x11=%d  ro-home=%d  "
                   "no-dbus=%d  tmp-home=%d  no-proc=%d  no-fuse=%d\n",
                   cfg->iso_no_net ? "isolated" : "host",
                   cfg->iso_wayland, cfg->iso_x11, cfg->iso_ro_home,
                   cfg->iso_no_dbus, cfg->iso_tmp_home, cfg->iso_no_proc,
                   cfg->no_fuse);
        }

        ret = run_isolated(cfg, vault_path);

        if (cfg->no_fuse) {
            if (cfg->image_url) {
                /* FIX #1: substituiu system("rm -rf") por nftw() — sem injeção de shell,
                 * FTW_PHYS impede seguir symlinks durante a limpeza do rootfs OCI. */
                if (cfg->verbose)
                    printf("  → cleaning OCI rootfs at '%s'...\n", vault_path);
#ifdef __linux__
                if (rm_rf_safe(vault_path) != 0)
                    fprintf(stderr, "[RUN] rm_rf_safe('%s') falhou: %s\n",
                            vault_path, strerror(errno));
#else
                rmdir(vault_path); /* stub Windows */
#endif
                /* FIX #5: liberar image_url apenas se foi alocado dinamicamente */
                if (cfg->image_url_allocated) {
                    free(cfg->image_url);
                    cfg->image_url = NULL;
                    cfg->image_url_allocated = false;
                }
            } else {
                /* --no-fuse puro: diretório vazio criado por mkdtemp */
                rmdir(vault_path);
            }
        } else {
            /* Desmonta o vault FUSE após o programa isolado encerrar */
            if (cfg->verbose)
                printf("  → unmounting vault %u (run finished)...\n", id);
            vault_unmount_ffi(id);
        }

        goto cleanup;
    }

    /* Nenhuma operação reconhecida */
    print_err("No operation specified. Use --help for usage.");
    ret = 1;

cleanup:
    explicit_bzero(pass_buf, sizeof(pass_buf));
    return ret;
}

/*
 *  Entry point FFI — chamado pelo main.rs
 * */
int vault_cli_parse_and_exec(int argc, char **argv) {
    /* CliConfig tem ~260 KB (binds[64][4096]) — alocada na stack estouraria
     * o limite padrão (8 MB) quando combinada com os frames do Rust runtime
     * e das funções aninhadas (preflight_scan, run_isolated).
     * calloc() aloca no heap e garante zero-init (equivale a memset 0). */
    CliConfig *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) {
        fprintf(stderr, "[FATAL] calloc CliConfig: out of memory\n");
        return 1;
    }

    /* Inicializa logger (path=NULL → usa ~/.local/share/Nuk4sd/cli.log) */
    cli_log_init(NULL);

    if (parse_flags(argc, argv, cfg) != 0) {
        cli_log(CLI_LOG_ERROR, "COMMAND", "parse_flags falhou — args inválidos");
        cli_log_close();
        free(cfg);
        return 1;
    }

    /* Activa verbose no logger se --verbose foi passado */
    cli_log_set_verbose(cfg->verbose);

    /* Loga o comando recebido (sem expor --password) */
    cli_log_command(argc, argv, cfg->vault_id);

    int ret = dispatch(cfg);

    cli_log(CLI_LOG_INFO, "COMMAND", "encerrado ret=%d", ret);
    cli_log_close();
    free(cfg);
    return ret;
}

/*
 *  vault_sandbox_run_ffi()
 *
 *  Lança um executável isolado no sandbox de um vault preenchendo o
 *  CliConfig DIRETO a partir de parâmetros tipados — sem montar string de
 *  linha de comando, sem join(" ")/split_whitespace() e sem passar por
 *  parse_flags()/getopt_long().
 *
 *  Motivo de existir: a GUI (Rust/egui) montava antes uma string tipo
 *  "--vault 3 --run <exe> --wayland --rw <path>" e mandava pro parser de
 *  texto via vault_cli_parse_and_exec(). Isso quebra silenciosamente sempre
 *  que <exe> ou <path> contém espaço (nome de pasta comum tipo
 *  "Meus Documentos"), porque getopt_long() exige que cada valor seja um
 *  argv[] próprio — um re-split por espaço não preserva isso.
 *
 *  Aqui os valores chegam via FFI já como campos separados (ponteiros C
 *  distintos), então nunca existe re-tokenização nenhuma: um path com
 *  espaço, acento ou qualquer caractere chega intacto.
 *
 *  Reaproveita 100% do mesmo caminho de execução (dispatch(), preflight_scan(),
 *  bind mounts, seccomp, jail, etc.) que vault_cli_parse_and_exec() usa —
 *  só a origem dos dados em CliConfig muda.
 *
 *  ro_paths/rw_paths/blacklist_paths podem ser NULL com count=0 quando não
 *  usados. Cada array é uma lista de ponteiros C string (sem separador
 *  nenhum dentro de cada elemento — o problema original nunca volta).
 * ───────────────────────────────────────────────────────────────────────── */
static void bind_add_ffi(CliConfig *cfg, const char *path, BindType type) {
    if (!path || !*path || cfg->bind_count >= MAX_BINDS) return;
    cli_expand_tilde(path, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
    cfg->binds[cfg->bind_count++].type = type;
}

int vault_sandbox_run_ffi(
    uint32_t    vault_id,
    const char *password,
    const char *exec_path,
    bool        no_net,
    bool        wayland,
    bool        x11,
    bool        audio,
    bool        ro_home,
    bool        no_fuse,
    bool        seccomp_strict,
    bool        use_chroot,
    const char *const *ro_paths,        uint32_t ro_count,
    const char *const *rw_paths,        uint32_t rw_count,
    const char *const *blacklist_paths, uint32_t blacklist_count
) {
    if (!exec_path || !*exec_path) return (int)ERR_INVALID_ARGS;

    CliConfig *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) return (int)ERR_NO_MEMORY;

    cli_log_init(NULL);

    cfg->vault_id       = (int32_t)vault_id;
    cfg->rule_hour_from = -1;
    cfg->rule_hour_to   = -1;

    cfg->run_exec = (char *)exec_path;  /* dispatch()/preflight_scan() só leem */
    cfg->password = (char *)password;

    cfg->iso_no_net     = no_net;
    cfg->iso_wayland    = wayland;
    cfg->iso_x11        = x11;
    cfg->iso_audio      = audio;
    cfg->iso_ro_home    = ro_home;
    cfg->no_fuse        = no_fuse;
    cfg->seccomp_strict = seccomp_strict;
    cfg->iso_use_chroot = use_chroot;

    for (uint32_t i = 0; i < ro_count && ro_paths; i++)
        bind_add_ffi(cfg, ro_paths[i], BIND_RO);
    for (uint32_t i = 0; i < rw_count && rw_paths; i++)
        bind_add_ffi(cfg, rw_paths[i], BIND_RW);
    for (uint32_t i = 0; i < blacklist_count && blacklist_paths; i++)
        bind_add_ffi(cfg, blacklist_paths[i], BIND_BLACKLIST);

    cli_log_set_verbose(cfg->verbose);
    cli_log(CLI_LOG_INFO, "COMMAND", "vault_sandbox_run_ffi: vault=%u exec=%s binds=%d",
            vault_id, exec_path, cfg->bind_count);

    int ret = dispatch(cfg);

    cli_log(CLI_LOG_INFO, "COMMAND", "encerrado ret=%d", ret);
    cli_log_close();
    free(cfg);
    return ret;
}