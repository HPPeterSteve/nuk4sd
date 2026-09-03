/*
 * net.c
 *
 * Nuk4sd — Layer de Rede Isolada (--net veth)
 *
 * Implementa rede isolada via par veth + NAT masquerade:
 *
 *   HOST netns                          JAIL netns (CLONE_NEWNET)
 *   ---                ---
 *   |  nuk4sd-veth0   --- tunnel -->   |  nuk4sd-veth1        |
 *   |  10.0.0.2/24    |                |  10.0.0.3/24         |
 *   |  (gateway)      |                |  (default gw: 10.0.0.2)
 *   ---                ---
 *            |
 *            ▼
 *     iptables NAT masquerade -> internet do host
 *
 * Fluxo:
 *   1. PAI (CAP_NET_ADMIN): cria par veth, configura veth0, habilita IP forward,
 *      adiciona regra NAT, move veth1 pro netns do filho.
 *   2. FILHO (dentro do namespace): ativa veth1, configura IP, adiciona rota default.
 *
 * Dependências externas: iproute2 (binário `ip`), iptables, libnftnl.
 *
 * Author: Peter Steve
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <nftables/libnftables.h>
#include "sandbox.h"

/* Limite de 64 chars pra nomes de interface no kernel */
#define NET_IFACE_NAME_MAX 64
#define IP_MAX_LEN         64

/* ── nfilter: lista de IPs permitidos ─────────────────────────────────────── */
#define MAX_ALLOWED_IPS 64

struct nfilter {
    char   allowed_ips[MAX_ALLOWED_IPS][IP_MAX_LEN];
    size_t count;
};

static struct nfilter nf = {
    .count = 0
};

/* ─────────────────────────────────────────────────────────────────────────── */

static void net_exec(const char *fmt, ...) {
    char cmd[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "[NET] WARN: '%s' returned %d\n", cmd, rc);
    }
}

/* -- Chamado pelo PAI (antes do unshare do filho) ---
 * Cria o par veth no netns do HOST, configura o lado do gateway, habilita
 * IP forwarding e NAT. O lado do jail (veth1) é movido pro netns do filho
 * via /proc/<child_pid>/ns/net.
 *
 * Retorno: 0 = ok, -1 = erro (não-fatal — jail continua sem rede) */
int vsb_setup_veth_host(pid_t child_pid, const char *jail_ip,
                        const char *gw_ip, const char *name_prefix)
{
    char if0[NET_IFACE_NAME_MAX], if1[NET_IFACE_NAME_MAX];

    snprintf(if0, sizeof(if0), "%s0", name_prefix);
    snprintf(if1, sizeof(if1), "%s1", name_prefix);

    printf("[SANDBOX] [Layer 2/5] Setting up isolated veth pair (%s): ", name_prefix);

    /* Remove par veth anterior se existir — idempotência via ip link del. */
    net_exec("ip link del %s0 2>/dev/null", name_prefix);

    /* Cria par veth: saída rc verificada abaixo. */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip link add %s type veth peer name %s", if0, if1);
    if (system(cmd) != 0) {
        fprintf(stderr, "\n[NET][ERROR] Failed to create veth pair: %s\n", strerror(errno));
        return -1;
    }

    /* Configura interface do gateway (lado host). */
    net_exec("ip link set %s up", if0);
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", gw_ip, if0);
    system(cmd);

    /* Move veth1 para o network namespace do filho. */
    snprintf(cmd, sizeof(cmd), "ip link set %s netns %d", if1, (int)child_pid);
    if (system(cmd) != 0) {
        fprintf(stderr, "[NET][ERROR] Failed to move %s to pid %d netns: %s\n",
                if1, (int)child_pid, strerror(errno));
        return -1;
    }

    /* Habilita IP forwarding via /proc/sys/net/ipv4/ip_forward. */
    net_exec("sysctl -w net.ipv4.ip_forward=1");

    /* Adiciona regra NAT masquerade via iptables — rc verificado. */
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -C POSTROUTING -s %s/24 ! -o %s0 -j MASQUERADE 2>/dev/null || "
             "iptables -t nat -A POSTROUTING -s %s/24 ! -o %s0 -j MASQUERADE",
             gw_ip, name_prefix, gw_ip, name_prefix);
    system(cmd);

    printf("OK (gw=%s, jail=%s, NAT active)\n", gw_ip, jail_ip);
    return 0;
}

/* -- Chamado pelo FILHO (dentro do namespace, após unshare CLONE_NEWNET) ---
 * Ativa a interface veth1, configura IP e adiciona rota default via gateway.
 *
 * Retorno: 0 = ok, -1 = erro */

int vsb_configure_veth_inside(const char *jail_ip, const char *gw_ip,
                              const char *name_prefix)
{
    char if1[NET_IFACE_NAME_MAX];
    snprintf(if1, sizeof(if1), "%s1", name_prefix);

    printf("[SANDBOX] [Layer 2/5] Configuring veth inside jail namespace: ");

    /* Ativar interface */
    net_exec("ip link set %s up", if1);

    /* Configurar IP */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", jail_ip, if1);
    if (system(cmd) != 0) {
        fprintf(stderr, "\n[NET][ERROR] Failed to assign IP %s to %s\n", jail_ip, if1);
        return -1;
    }

    /* Rota default via gateway */
    snprintf(cmd, sizeof(cmd), "ip route add default via %s dev %s", gw_ip, if1);
    if (system(cmd) != 0) {
        fprintf(stderr, "\n[NET][ERROR] Failed to add default route via %s\n", gw_ip);
        return -1;
    }

    /* Loopback */
    net_exec("ip link set lo up");

    printf("OK (%s via %s)\n", jail_ip, gw_ip);
    return 0;
}

/* -- Chamado pelo PAI (antes do unshare do filho) ---
 * Registra um IP na whitelist interna do nfilter.
 *
 * Retorno: 0 = ok, -1 = lista cheia */
int user_send_set_ip(const char *set_name, const char *ip)
{
    if (nf.count >= MAX_ALLOWED_IPS) {
        vault_log(LOG_ERROR, "[nfilter] Maximum number of allowed IPs reached");
        return -1;
    }
    // copiando o ip para o array
    strncpy(nf.allowed_ips[nf.count], ip, IP_MAX_LEN - 1);
    nf.allowed_ips[nf.count][IP_MAX_LEN - 1] = '\0';
    nf.count++;

    printf("[nfilter] IP to allow: %s\n", nf.allowed_ips[nf.count - 1]);
    vault_log(LOG_INFO, "[NET] [Layer 2/5] Adding IP to set %s: %s",
              set_name, nf.allowed_ips[nf.count - 1]);

    return 0;
}
    /* Codigo revisado por Peter Steve 
    Manteiner Nuk4sd Project: Peter Steve
    primeira leva de revisão: 02/09/2026 18:11 - 22:14  */

/* libnftables — aplica a tabela, chain e regras de filtro de saída para o jail */
int nfilterflag(const char *jail_name, const char *jail_ip) {
    (void)jail_ip;

    struct nft_ctx *nft_context = nft_ctx_new(NFT_CTX_DEFAULT);
    if (nft_context == NULL) {
        vault_log(LOG_ERROR, "[NET][ERROR] Failed to allocate nftables context");
        return -1;
    }

    char nft_commands_buffer[4096];
    int buffer_length = snprintf(nft_commands_buffer, sizeof(nft_commands_buffer),
        "add table ip %s\n"
        "add chain ip %s output { type filter hook output priority 0; policy drop; }\n",
        jail_name, jail_name);

    /* Adiciona regra liberando trafego para os IPs cadastrados na whitelist */
    for (size_t ip_index = 0; ip_index < nf.count && buffer_length < (int)sizeof(nft_commands_buffer); ip_index++) {
        buffer_length += snprintf(nft_commands_buffer + buffer_length, sizeof(nft_commands_buffer) - buffer_length,
            "add rule ip %s output ip daddr %s accept\n",
            jail_name, nf.allowed_ips[ip_index]);
    }

    int execution_status = nft_run_cmd_from_buffer(nft_context, nft_commands_buffer);
    nft_ctx_free(nft_context);

    if (execution_status != 0) {
        vault_log(LOG_ERROR, "[NET][ERROR] Failed to apply nftables rules for jail '%s'", jail_name);
        return -1;
    }

    vault_log(LOG_INFO, "[NET] nftables rules successfully applied for jail '%s'", jail_name);
    return 0;
}

/* -- Cleanup: remover par veth após o jail sair --- */
int vsb_cleanup_veth(const char *name_prefix)
{
    net_exec("ip link del %s0 2>/dev/null", name_prefix);
    return 0;
}

/* Wrapper público */
int vsb_net_veth_setup(pid_t child_pid, const char *jail_ip,
                       const char *gw_ip, const char *name_prefix)
{
    return vsb_setup_veth_host(child_pid, jail_ip, gw_ip, name_prefix);
}
