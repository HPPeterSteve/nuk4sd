/*
 * net.c
 *
 * Nuk4sd — Isolated Network Layer (--net veth)
 *
 * Implements an isolated network via a veth pair + NAT masquerade:
 *
 *   HOST netns                          JAIL netns (CLONE_NEWNET)
 *   ---                ---
 *   |  nuk4sd-veth0   --- tunnel -->   |  nuk4sd-veth1        |
 *   |  10.0.0.2/24    |                |  10.0.0.3/24         |
 *   |  (gateway)      |                |  (default gw: 10.0.0.2)
 *   ---                ---
 *            |
 *            ▼
 *     iptables NAT masquerade -> host internet
 *
 * Flow:
 *   1. PARENT (CAP_NET_ADMIN): creates veth pair, configures veth0, enables IP forwarding,
 *      adds NAT rule, moves veth1 to the child's netns.
 *   2. CHILD (inside namespace): activates veth1, configures IP, adds default route.
 *
 * External dependencies: iproute2 (`ip` binary), iptables, libnftnl.
 *
 * Author: Peter Steve
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <nftables/libnftables.h>
#include <sched.h>

/* 64 char limit for interface names in kernel */
#define NET_IFACE_NAME_MAX 64
#define IP_MAX_LEN 64

/* ── nfilter: allowed IPs list ───────────────────────────────────────────── */
#define MAX_ALLOWED_IPS 64

struct nfilter {
    char allowed_ips[MAX_ALLOWED_IPS][IP_MAX_LEN];
    size_t count;
};

static struct nfilter nf = {.count = 0};

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

/* ── Validates name_prefix for use in system() calls ───────────────────
 * Allowed charset: [a-zA-Z0-9._-], max length: 15 chars
 * (IFNAMSIZ - 1 in kernel: interfaces like nuk4sd-veth0 have 12 chars).
 * Rejects any input that could inject shell commands.
 *
 * Returns 0 if valid, -1 if invalid. */
static int validate_name_prefix(const char *p) {
    if (!p || *p == '\0') {
        vault_log(LOG_ERROR, "[NET] empty or NULL name_prefix");
        return -1;
    }
    size_t len = 0;
    for (const char *c = p; *c; c++, len++) {
        if (!isalnum((unsigned char)*c) && *c != '.' && *c != '_' && *c != '-') {
            vault_log(LOG_ERROR,
                      "[NET] name_prefix '%s' contains invalid character '%c' (only [a-zA-Z0-9._-])",
                      p, *c);
            return -1;
        }
    }
    /* Kernel IFNAMSIZ = 16 (includes NUL); real name = prefix + '0'/'1' = len+1 */
    if (len == 0 || len > 14) {
        vault_log(LOG_ERROR,
                  "[NET] name_prefix '%s' with invalid length %zu (max 14)",
                  p, len);
        return -1;
    }
    return 0;
}

/* -- Called by PARENT (before child unshare) ---
 * Creates veth pair in HOST netns, configures gateway side, enables
 * IP forwarding and NAT. The jail side (veth1) is moved to child netns
 * via /proc/<child_pid>/ns/net.
 *
 * Return: 0 = ok, -1 = error (non-fatal — jail continues without network) */
int vsb_setup_veth_host(pid_t child_pid, const char *jail_ip, const char *gw_ip, const char *name_prefix) {
    if (!jail_ip || !gw_ip || !name_prefix)
        return -1;

    /* Validate name_prefix before any interpolation in system() */
    if (validate_name_prefix(name_prefix) != 0)
        return -1;

    struct in_addr a1, a2;
    if (inet_pton(AF_INET, jail_ip, &a1) != 1 || inet_pton(AF_INET, gw_ip, &a2) != 1) {
        vault_log(LOG_ERROR, "[NET] Invalid IP in veth setup: jail=%s, gw=%s", jail_ip, gw_ip);
        return -1;
    }

    char if0[NET_IFACE_NAME_MAX], if1[NET_IFACE_NAME_MAX];

    snprintf(if0, sizeof(if0), "%s0", name_prefix);
    snprintf(if1, sizeof(if1), "%s1", name_prefix);

    /* Remove previous veth pair if exists — idempotency via ip link del. */
    net_exec("ip link del %s0 2>/dev/null", name_prefix);

    /* Create veth pair: rc verified below. */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip link add %s type veth peer name %s", if0, if1);
    if (system(cmd) != 0) {
        vault_log(LOG_ERROR, "[NET] Failed to create veth pair: %s", strerror(errno));
        return -1;
    }

    /* Configure gateway interface (host side). */
    net_exec("ip link set %s up", if0);
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", gw_ip, if0);
    system(cmd);

    /* Move veth1 to child network namespace. */
    snprintf(cmd, sizeof(cmd), "ip link set %s netns %d", if1, (int)child_pid);
    if (system(cmd) != 0) {
        vault_log(LOG_ERROR, "[NET] Failed to move %s to pid %d netns: %s", if1, (int)child_pid, strerror(errno));
        return -1;
    }

    /* Enable IP forwarding via /proc/sys/net/ipv4/ip_forward. */
    net_exec("sysctl -w net.ipv4.ip_forward=1");

    /* Add NAT masquerade rule via iptables — rc verified. */
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -C POSTROUTING -s %s/24 ! -o %s0 -j MASQUERADE 2>/dev/null || "
             "iptables -t nat -A POSTROUTING -s %s/24 ! -o %s0 -j MASQUERADE",
             gw_ip, name_prefix, gw_ip, name_prefix);
    system(cmd);

    vault_log(LOG_INFO, "[NET] Isolated veth pair '%s' setup: gw=%s, jail=%s, NAT active", name_prefix, gw_ip, jail_ip);
    return 0;
}

/* -- Called by CHILD (inside namespace, after unshare CLONE_NEWNET) ---
 * Activates veth1 interface, configures IP, and adds default route via gateway.
 *
 * Return: 0 = ok, -1 = error */

int vsb_configure_veth_inside(const char *jail_ip, const char *gw_ip, const char *name_prefix) {
    if (validate_name_prefix(name_prefix) != 0)
        return -1;

    char if1[NET_IFACE_NAME_MAX];
    snprintf(if1, sizeof(if1), "%s1", name_prefix);

    /* Activate interface */
    net_exec("ip link set %s up", if1);

    /* Configure IP */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", jail_ip, if1);
    if (system(cmd) != 0) {
        vault_log(LOG_ERROR, "[NET] Failed to assign IP %s to %s", jail_ip, if1);
        return -1;
    }

    /* Default route via gateway */
    snprintf(cmd, sizeof(cmd), "ip route add default via %s dev %s", gw_ip, if1);
    if (system(cmd) != 0) {
        vault_log(LOG_ERROR, "[NET] Failed to add default route via %s", gw_ip);
        return -1;
    }

    /* Loopback */
    net_exec("ip link set lo up");

    vault_log(LOG_INFO, "[NET] Configured veth inside jail namespace: %s via %s", jail_ip, gw_ip);
    return 0;
}

#include <arpa/inet.h>

/* -- Called by PARENT (before child unshare) ---
 * Registers an IP in nfilter's internal whitelist.
 *
 * Return: 0 = ok, -1 = full list or invalid IP */
int user_send_set_ip(const char *set_name, const char *ip) {
    if (!ip)
        return -1;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        vault_log(LOG_ERROR, "[nfilter] Invalid IPv4 address: '%s'", ip);
        return -1;
    }

    if (nf.count >= MAX_ALLOWED_IPS) {
        vault_log(LOG_ERROR, "[nfilter] Maximum number of allowed IPs reached");
        return -1;
    }
    // copying ip to array
    strncpy(nf.allowed_ips[nf.count], ip, IP_MAX_LEN - 1);
    nf.allowed_ips[nf.count][IP_MAX_LEN - 1] = '\0';
    nf.count++;

    vault_log(LOG_INFO, "[NET] Adding IP to set %s: %s", set_name, nf.allowed_ips[nf.count - 1]);

    return 0;
}

/* Code reviewed by Peter Steve
Maintainer Nuk4sd Project: Peter Steve
First round of review: 09/02/2026 18:11 - 22:14  */

/* libnftables — applies table, chain, and egress filter rules for the jail */
int nfilterflag(const char *jail_name, const char *jail_ip) {
    (void)jail_ip;

    /* Validate jail_name length before any snprintf —
     * a huge name would truncate the buffer silently. */
    if (!jail_name || strlen(jail_name) == 0 || strlen(jail_name) > 64) {
        vault_log(LOG_ERROR,
                  "[NET][ERROR] nfilterflag: invalid or too long jail_name (max 64 chars)");
        return -1;
    }

    struct nft_ctx *nft_context = nft_ctx_new(NFT_CTX_DEFAULT);
    if (nft_context == NULL) {
        vault_log(LOG_ERROR, "[NET][ERROR] Failed to allocate nftables context");
        return -1;
    }

    char nft_commands_buffer[4096];

    /* Check buffer capacity for worst case BEFORE first snprintf:
     * header (table + chain) + nf.count IP rules (~128 bytes each). */
    size_t worst_case = 256 + (nf.count * 128); /* generous margin */
    if (worst_case >= sizeof(nft_commands_buffer)) {
        vault_log(LOG_ERROR,
                  "[NET][ERROR] Insufficient nftables rules buffer for %zu IPs — aborting",
                  nf.count);
        nft_ctx_free(nft_context);
        return -1;
    }

    int buffer_length = snprintf(nft_commands_buffer, sizeof(nft_commands_buffer),
                                 "add table ip %s\n"
                                 "add chain ip %s output { type filter hook output priority 0; policy drop; }\n",
                                 jail_name, jail_name);

    /* Add rule allowing traffic to whitelisted IPs */
    for (size_t ip_index = 0; ip_index < nf.count; ip_index++) {
        if (buffer_length >= (int)sizeof(nft_commands_buffer) - 128) {
            vault_log(LOG_ERROR, "[NET] nftables rules buffer overflow — aborting to prevent truncated rules");
            nft_ctx_free(nft_context);
            return -1;
        }
        buffer_length += snprintf(nft_commands_buffer + buffer_length, sizeof(nft_commands_buffer) - buffer_length,
                                  "add rule ip %s output ip daddr %s accept\n", jail_name, nf.allowed_ips[ip_index]);
    }

    int execution_status = nft_run_cmd_from_buffer(nft_context, nft_commands_buffer);
    nft_ctx_free(nft_context);

    if (execution_status != 0) {
        vault_log(LOG_ERROR,
                  "[NET][ERROR] nft_run_cmd_from_buffer failed (status=%d) applying "
                  "rules for jail '%s' — network unfiltered!",
                  execution_status, jail_name);
        return -1;
    }

    vault_log(LOG_INFO, "[NET] nftables rules successfully applied for jail '%s'", jail_name);
    return 0;
}

/* -- Cleanup: remove veth pair after jail exits --- */
int vsb_cleanup_veth(const char *name_prefix) {
    if (validate_name_prefix(name_prefix) != 0)
        return -1;
    net_exec("ip link del %s0 2>/dev/null", name_prefix);
    return 0;
}

/* Public wrapper */
int vsb_net_veth_setup(pid_t child_pid, const char *jail_ip, const char *gw_ip, const char *name_prefix) {
    return vsb_setup_veth_host(child_pid, jail_ip, gw_ip, name_prefix);
}

#else /* !__linux__ */

int vsb_setup_veth_host(pid_t child_pid, const char *jail_ip, const char *gw_ip, const char *name_prefix) {
    (void)child_pid; (void)jail_ip; (void)gw_ip; (void)name_prefix;
    return 0;
}

int vsb_configure_veth_inside(const char *jail_ip, const char *gw_ip, const char *name_prefix) {
    (void)jail_ip; (void)gw_ip; (void)name_prefix;
    return 0;
}

int user_send_set_ip(const char *set_name, const char *ip) {
    (void)set_name; (void)ip;
    return 0;
}

int nfilterflag(const char *jail_name, const char *jail_ip) {
    (void)jail_name; (void)jail_ip;
    return 0;
}

int vsb_cleanup_veth(const char *name_prefix) {
    (void)name_prefix;
    return 0;
}

int vsb_net_veth_setup(pid_t child_pid, const char *jail_ip, const char *gw_ip, const char *name_prefix) {
    (void)child_pid; (void)jail_ip; (void)gw_ip; (void)name_prefix;
    return 0;
}

#endif /* __linux__ */
