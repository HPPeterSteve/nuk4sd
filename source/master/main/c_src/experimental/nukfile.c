/*
 * nukfile.c [EXPERIMENTAL]
 *
 * Implementação do parser e executor da linguagem declarativa Nukfile.
 * Módulo experimental em c_src/experimental/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "nukfile.h"
#include "../sandbox/sandbox.h"

#define MAX_INCLUDE_DEPTH 10

static int nukfile_parse_internal(const char *filepath, CliConfig *cfg, int depth);

/* Utilitário para converter strings como "2G", "512M", "1024K" ou "100" em MB/GB */
static long parse_size_with_unit(const char *str, char unit_target) {
    if (!str || !*str) return 0;
    char *endptr;
    double val = strtod(str, &endptr);
    if (val <= 0) return 0;

    while (*endptr && isspace((unsigned char)*endptr)) endptr++;
    char u = *endptr ? toupper((unsigned char)*endptr) : 'M';

    if (unit_target == 'G') {
        if (u == 'M') return (long)(val / 1024.0);
        if (u == 'K') return (long)(val / (1024.0 * 1024.0));
        return (long)val; /* Padrão assume GB */
    } else if (unit_target == 'M') {
        if (u == 'G') return (long)(val * 1024.0);
        if (u == 'K') return (long)(val / 1024.0);
        return (long)val; /* Padrão assume MB */
    }
    return (long)val;
}

/* Remove aspas iniciais/finais de uma string */
static void strip_quotes(char *str) {
    if (!str) return;
    size_t len = strlen(str);
    if (len >= 2 && ((str[0] == '"' && str[len - 1] == '"') || (str[0] == '\'' && str[len - 1] == '\''))) {
        memmove(str, str + 1, len - 2);
        str[len - 2] = '\0';
    }
}

/* Helper para adicionar caminhos a lista de binds de forma segura */
static void add_bind(CliConfig *cfg, const char *path, BindType type) {
    if (!path || !*path || cfg->bind_count >= MAX_BINDS) return;
    cli_expand_tilde(path, cfg->binds[cfg->bind_count].path, PRESET_PATH_MAX);
    cfg->binds[cfg->bind_count].type = type;
    cfg->bind_count++;
}

/* Aplica modelos base embutidos (templates pré-configurados) */
static void apply_base_template(const char *name, CliConfig *cfg) {
    if (!strcasecmp(name, "gui") || !strcasecmp(name, "base/gui")) {
        cfg->iso_wayland = true;
        cfg->iso_x11 = true;
        cfg->iso_gpu = true;
        cfg->iso_audio = true;
        add_bind(cfg, "/usr/share/fonts", BINFO);
        add_bind(cfg, "/etc/fonts", BINFO);
        vault_log(LOG_INFO, "[Nukfile] Base 'gui' carregada com sucesso.");
    } else if (!strcasecmp(name, "server") || !strcasecmp(name, "base/server")) {
        cfg->iso_no_proc = true;
        cfg->iso_no_dbus = true;
        cfg->iso_new_session = true;
        cfg->iso_unshare_ipc = true;
        cfg->iso_unshare_uts = true;
        vault_log(LOG_INFO, "[Nukfile] Base 'server' carregada com sucesso.");
    } else if (!strcasecmp(name, "strict") || !strcasecmp(name, "base/strict")) {
        cfg->iso_no_net = true;
        cfg->iso_no_dbus = true;
        cfg->iso_no_proc = true;
        cfg->iso_unshare_ipc = true;
        cfg->iso_unshare_uts = true;
        cfg->iso_unshare_cgroup = true;
        vault_log(LOG_INFO, "[Nukfile] Base 'strict' carregada com sucesso.");
    }
}

static int nukfile_parse_internal(const char *filepath, CliConfig *cfg, int depth) {
    if (depth > MAX_INCLUDE_DEPTH) {
        fprintf(stderr, "[Nukfile][ERROR] Profundidade máxima de 'include' excedida (%s)\n", filepath);
        return -1;
    }

    /* Expande caminho do Nukfile caso use ~ */
    char expanded_path[PRESET_PATH_MAX];
    cli_expand_tilde(filepath, expanded_path, sizeof(expanded_path));

    FILE *f = fopen(expanded_path, "r");
    if (!f) {
        /* Tenta procurar na pasta do sistema (/etc/nuk4sd/profiles/) se não achar localmente */
        char sys_path[PRESET_PATH_MAX];
        snprintf(sys_path, sizeof(sys_path), "/etc/nuk4sd/profiles/%s", filepath);
        f = fopen(sys_path, "r");
        if (!f) {
            fprintf(stderr, "[Nukfile][ERROR] Arquivo de perfil não encontrado: '%s'\n", filepath);
            return -1;
        }
    }

    char line[1024];
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;

        /* Remove comentários e quebras de linha */
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';

        char *ptr = line;
        while (*ptr && isspace((unsigned char)*ptr)) ptr++;
        ptr[strcspn(ptr, "\r\n")] = '\0';

        if (!*ptr) continue; /* Linha vazia */

        /* Divide em comando e argumentos */
        char cmd[256] = {0};
        char args[768] = {0};
        if (sscanf(ptr, "%255s %[^\n]", cmd, args) < 1) continue;

        strip_quotes(args);

        /* ── 1. Herança e Inclusão ───────────────────────────────────────── */
        if (!strcasecmp(cmd, "include")) {
            if (!strncmp(args, "base/", 5) || !strcasecmp(args, "gui") || !strcasecmp(args, "server") || !strcasecmp(args, "strict")) {
                apply_base_template(args, cfg);
            } else {
                nukfile_parse_internal(args, cfg, depth + 1);
            }
        }
        /* ── 2. Identificação e Cofre ─────────────────────────────────────── */
        else if (!strcasecmp(cmd, "vault")) {
            if (isdigit((unsigned char)args[0])) {
                cfg->vault_id = atoi(args);
            }
        }
        else if (!strcasecmp(cmd, "exec") || !strcasecmp(cmd, "run")) {
            if (args[0] != '\0') {
                char *first_space = strchr(args, ' ');
                if (first_space) {
                    *first_space = '\0';
                    cfg->run_exec = strdup(args);
                    char *extra_args = first_space + 1;
                    char *token = strtok(extra_args, " ");
                    while (token && cfg->run_argc < 32) {
                        cfg->run_argv[cfg->run_argc++] = strdup(token);
                        token = strtok(NULL, " ");
                    }
                } else {
                    cfg->run_exec = strdup(args);
                }
            }
        }
        /* ── 3. Rede e Filtro (nftables) ─────────────────────────────────── */
        else if (!strcasecmp(cmd, "net")) {
            if (!strcasecmp(args, "none")) cfg->iso_no_net = true;
            else if (!strcasecmp(args, "veth")) cfg->iso_net_veth = true;
        }
        else if (!strcasecmp(cmd, "nfilter")) {
            if (cfg->iso_nfilter_jail) free(cfg->iso_nfilter_jail);
            cfg->iso_nfilter_jail = strdup(args);
        }
        else if (!strcasecmp(cmd, "allow-ip")) {
            if (cfg->iso_nfilter_jail) {
                user_send_set_ip(cfg->iso_nfilter_jail, args);
            } else {
                user_send_set_ip("default", args);
            }
        }
        /* ── 4. Identificação de Processo (UUID) ─────────────────────────── */
        else if (!strcasecmp(cmd, "uuid")) {
            if (!*args || !strcasecmp(args, "enable") || !strcasecmp(args, "true") || !strcasecmp(args, "1")) {
                cfg->iso_uuid = true;
            }
        }
        /* ── 5. Filesystem & Bind Mounts ─────────────────────────────────── */
        else if (!strcasecmp(cmd, "read-only") || !strcasecmp(cmd, "ro")) {
            char *path_token = strtok(args, " ");
            while (path_token) {
                add_bind(cfg, path_token, BINFO);
                path_token = strtok(NULL, " ");
            }
        }
        else if (!strcasecmp(cmd, "read-write") || !strcasecmp(cmd, "rw")) {
            char *path_token = strtok(args, " ");
            while (path_token) {
                add_bind(cfg, path_token, BIND_RW);
                path_token = strtok(NULL, " ");
            }
        }
        else if (!strcasecmp(cmd, "blacklist")) {
            char *path_token = strtok(args, " ");
            while (path_token) {
                add_bind(cfg, path_token, BIND_BLACKLIST);
                path_token = strtok(NULL, " ");
            }
        }
        else if (!strcasecmp(cmd, "private-tmp")) {
            cfg->iso_tmp_home = true;
        }
        else if (!strcasecmp(cmd, "ro-home")) {
            cfg->iso_ro_home = true;
        }
        else if (!strcasecmp(cmd, "rw-home")) {
            cfg->iso_rw_home = true;
        }
        /* ── 6. Display & Recursos Multimedia ────────────────────────────── */
        else if (!strcasecmp(cmd, "wayland"))  cfg->iso_wayland = true;
        else if (!strcasecmp(cmd, "x11"))      cfg->iso_x11 = true;
        else if (!strcasecmp(cmd, "audio"))    cfg->iso_audio = true;
        else if (!strcasecmp(cmd, "gpu"))      cfg->iso_gpu = true;
        else if (!strcasecmp(cmd, "no-dbus"))  cfg->iso_no_dbus = true;
        /* ── 7. Segurança (Seccomp / Caps) ────────────────────────────────── */
        else if (!strcasecmp(cmd, "seccomp")) {
            if (!strcasecmp(args, "strict")) cfg->seccomp_strict = true;
            else if (!strcasecmp(args, "none") || !strcasecmp(args, "off")) cfg->iso_no_seccomp = true;
        }
        /* ── 8. Limites de Recursos ───────────────────────────────────────── */
        else if (!strcasecmp(cmd, "max-mem")) {
            cfg->iso_max_mem_gb = (int)parse_size_with_unit(args, 'G');
        }
        else if (!strcasecmp(cmd, "max-procs")) {
            cfg->iso_max_procs = atoi(args);
        }
        else if (!strcasecmp(cmd, "max-fds")) {
            cfg->iso_max_fds = atoi(args);
        }
        else if (!strcasecmp(cmd, "hostname")) {
            snprintf(cfg->iso_hostname, sizeof(cfg->iso_hostname), "%s", args);
            cfg->iso_unshare_uts = true;
        }
        else {
            fprintf(stderr, "[Nukfile][WARN] Linha %d: comando desconhecido '%s'\n", line_num, cmd);
        }
    }

    fclose(f);
    return 0;
}

int nukfile_parse(const char *filepath, CliConfig *cfg) {
    if (!filepath || !cfg) return -1;
    return nukfile_parse_internal(filepath, cfg, 0);
}
