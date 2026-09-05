/*
 * nuk_sandbox.c [EXPERIMENTAL]
 *
 * Implementação técnica da biblioteca de sandbox e integração com o leitor de Nukfile.
 */

#include "nuk_sandbox.h"
#include "../sandbox/preset.h"
#include "nukfile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct NukSandbox {
    CliConfig cfg;
};

NukSandbox *nuk_sandbox_create(void) {
    NukSandbox *sb = calloc(1, sizeof(NukSandbox));
    if (!sb)
        return NULL;
    return sb;
}

int nuk_sandbox_load_file(NukSandbox *sb, const char *filepath) {
    if (!sb || !filepath)
        return -1;
    return nukfile_parse(filepath, &sb->cfg);
}

void nuk_sandbox_set_exec(NukSandbox *sb, const char *exec_path, char **argv, int argc) {
    if (!sb || !exec_path)
        return;
    if (sb->cfg.run_exec)
        free(sb->cfg.run_exec);
    sb->cfg.run_exec = strdup(exec_path);

    sb->cfg.run_argc = 0;
    if (argv && argc > 0) {
        for (int i = 0; i < argc && i < 32; i++) {
            if (argv[i]) {
                sb->cfg.run_argv[sb->cfg.run_argc++] = strdup(argv[i]);
            }
        }
    }
}

void nuk_sandbox_set_net_veth(NukSandbox *sb, const char *jail_ip, const char *gw_ip) {
    if (!sb)
        return;
    sb->cfg.iso_net_veth = true;
    if (jail_ip)
        sb->cfg.iso_net_veth_ip = strdup(jail_ip);
    if (gw_ip)
        sb->cfg.iso_net_veth_gw = strdup(gw_ip);
}

void nuk_sandbox_set_nfilter(NukSandbox *sb, const char *jail_name) {
    if (!sb || !jail_name)
        return;
    if (sb->cfg.iso_nfilter_jail)
        free(sb->cfg.iso_nfilter_jail);
    sb->cfg.iso_nfilter_jail = strdup(jail_name);
}

void nuk_sandbox_allow_ip(NukSandbox *sb, const char *ip) {
    if (!sb || !ip)
        return;
    if (sb->cfg.iso_nfilter_jail) {
        user_send_set_ip(sb->cfg.iso_nfilter_jail, ip);
    } else {
        user_send_set_ip("default", ip);
    }
}

void nuk_sandbox_set_uuid(NukSandbox *sb, bool enable) {
    if (!sb)
        return;
    sb->cfg.iso_uuid = enable;
}

void nuk_sandbox_add_bind(NukSandbox *sb, const char *path, NukBindType type) {
    if (!sb || !path || sb->cfg.bind_count >= MAX_BINDS)
        return;
    cli_expand_tilde(path, sb->cfg.binds[sb->cfg.bind_count].path, PRESET_PATH_MAX);
    sb->cfg.binds[sb->cfg.bind_count].type = (BindType)type;
    sb->cfg.bind_count++;
}

void nuk_sandbox_set_max_mem(NukSandbox *sb, int mem_gb) {
    if (!sb)
        return;
    sb->cfg.iso_max_mem_gb = mem_gb;
}

void nuk_sandbox_set_max_procs(NukSandbox *sb, int max_procs) {
    if (!sb)
        return;
    sb->cfg.iso_max_procs = max_procs;
}

int nuk_sandbox_run(NukSandbox *sb) {
    if (!sb || !sb->cfg.run_exec)
        return -1;
    /* Invocação direta da rotina de isolamento do sandbox */
    return run_isolated(&sb->cfg, "/tmp");
}

void nuk_sandbox_free(NukSandbox *sb) {
    if (!sb)
        return;
    if (sb->cfg.run_exec)
        free(sb->cfg.run_exec);
    for (int i = 0; i < sb->cfg.run_argc; i++) {
        if (sb->cfg.run_argv[i])
            free(sb->cfg.run_argv[i]);
    }
    if (sb->cfg.iso_nfilter_jail)
        free(sb->cfg.iso_nfilter_jail);
    free(sb);
}
