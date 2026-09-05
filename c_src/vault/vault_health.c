/*
 * vault_health.c
 *
 * Nuk4sd — Sandbox Health Inspector
 *
 * Lê /proc/<pid>/ para verificar se um processo sandboxed está
 * de fato isolado. Emite JSON para a GUI consumir.
 *
 * Uso via CLI:
 *   Nuk4sd --health <pid>
 *
 * Saída (stdout, JSON):
 * {
 *   "pid": 12345,
 *   "exe": "/usr/bin/firefox",
 *   "caps_effective": "0000000000000000",
 *   "caps_dropped": true,
 *   "no_new_privs": true,
 *   "seccomp": 2,
 *   "seccomp_label": "filter",
 *   "ns_user_isolated": true,
 *   "ns_mnt_isolated": true,
 *   "ns_net_isolated": true,
 *   "ns_pid_isolated": true,
 *   "ns_ipc_isolated": false,
 *   "ns_uts_isolated": false,
 *   "verdict": "isolated",
 *   "issues": []
 * }
 *
 * verdict pode ser: "isolated" | "partial" | "exposed"
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

#include "vault_health.h"

/* ── Lê um campo do /proc/<pid>/status ───────────────────────────────────── */
static int read_status_field(pid_t pid, const char *field, char *out, size_t outsz)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, field, strlen(field)) == 0) {
            /* "FieldName:\tvalue\n" */
            char *colon = strchr(line, ':');
            if (colon) {
                char *val = colon + 1;
                while (*val == '\t' || *val == ' ') val++;
                size_t len = strlen(val);
                while (len > 0 && (val[len-1] == '\n' || val[len-1] == '\r')) val[--len] = '\0';
                snprintf(out, outsz, "%s", val);
                fclose(f);
                return 0;
            }
        }
    }
    fclose(f);
    return -1;
}

/* ── Lê o inode do namespace de /proc/<pid>/ns/<ns_name> ─────────────────── */
static ino_t read_ns_inode(pid_t pid, const char *ns)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/ns/%s", (int)pid, ns);
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return st.st_ino;
}

/* ── Lê /proc/<pid>/exe via readlink ─────────────────────────────────────── */
static void read_exe(pid_t pid, char *out, size_t outsz)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", (int)pid);
    ssize_t n = readlink(path, out, outsz - 1);
    if (n > 0) out[n] = '\0';
    else snprintf(out, outsz, "(unknown)");
}

/* ── Escapa string simples para JSON ─────────────────────────────────────── */
static void json_str(FILE *out, const char *s)
{
    fputc('"', out);
    for (; *s; s++) {
        if (*s == '"')       fputs("\\\"", out);
        else if (*s == '\\') fputs("\\\\", out);
        else if (*s == '\n') fputs("\\n", out);
        else                 fputc(*s, out);
    }
    fputc('"', out);
}

/* ── Ponto de entrada público ─────────────────────────────────────────────── */
int sandbox_health_check(pid_t pid)
{
    /* Verificar se o pid existe */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", (int)pid);
    struct stat st;
    if (stat(proc_path, &st) != 0) {
        fprintf(stderr, "{\"error\": \"pid %d not found\"}\n", (int)pid);
        return 1;
    }

    /* ── Ler campos do /proc/<pid>/status ── */
    char caps_eff[32]  = "?";
    char nnp_str[8]    = "?";
    char seccomp_str[8] = "?";

    read_status_field(pid, "CapEff",     caps_eff,    sizeof(caps_eff));
    read_status_field(pid, "NoNewPrivs", nnp_str,     sizeof(nnp_str));
    read_status_field(pid, "Seccomp",    seccomp_str, sizeof(seccomp_str));

    bool caps_dropped  = (strcmp(caps_eff, "0000000000000000") == 0);
    bool no_new_privs  = (atoi(nnp_str) == 1);
    int  seccomp_val   = atoi(seccomp_str);

    const char *seccomp_label;
    switch (seccomp_val) {
        case 0:  seccomp_label = "disabled";  break;
        case 1:  seccomp_label = "strict";    break;
        case 2:  seccomp_label = "filter";    break;
        default: seccomp_label = "unknown";   break;
    }

    /* ── Comparar namespaces com o processo init (pid 1) ── */
    const char *ns_names[] = { "user", "mnt", "net", "pid", "ipc", "uts", NULL };
    bool ns_isolated[6] = {false};
    for (int i = 0; ns_names[i]; i++) {
        ino_t self_ino = read_ns_inode(1,   ns_names[i]);
        ino_t proc_ino = read_ns_inode(pid, ns_names[i]);
        /* Se o inode for diferente do PID 1, está em namespace próprio */
        ns_isolated[i] = (self_ino != 0 && proc_ino != 0 && self_ino != proc_ino);
    }
    bool ns_user = ns_isolated[0];
    bool ns_mnt  = ns_isolated[1];
    bool ns_net  = ns_isolated[2];
    bool ns_pid  = ns_isolated[3];
    bool ns_ipc  = ns_isolated[4];
    bool ns_uts  = ns_isolated[5];

    /* ── Ler executável ── */
    char exe[PATH_MAX] = "";
    read_exe(pid, exe, sizeof(exe));

    /* ── Construir lista de issues ── */
    const char *issues[16];
    int n_issues = 0;

    if (!caps_dropped)          issues[n_issues++] = "capabilities not fully dropped";
    if (!no_new_privs)          issues[n_issues++] = "NO_NEW_PRIVS not set — execve() can escalate";
    if (seccomp_val == 0)       issues[n_issues++] = "seccomp disabled — all syscalls allowed";
    if (!ns_user)               issues[n_issues++] = "no user namespace — running in host UID space";
    if (!ns_mnt)                issues[n_issues++] = "no mount namespace — host filesystem visible";
    if (!ns_net)                issues[n_issues++] = "no network namespace — full host network access";
    if (!ns_pid)                issues[n_issues++] = "no PID namespace — can see all host processes";

    /* ── Veredicto ── */
    const char *verdict;
    /* Critérios mínimos para "isolated": caps, NNP, seccomp, mnt, user */
    int score = (caps_dropped ? 1 : 0) + (no_new_privs ? 1 : 0)
              + (seccomp_val > 0 ? 1 : 0) + (ns_mnt ? 1 : 0)
              + (ns_user ? 1 : 0) + (ns_net ? 1 : 0);

    if (score == 6)      verdict = "isolated";
    else if (score >= 3) verdict = "partial";
    else                 verdict = "exposed";

    /* ── Emitir JSON ── */
    printf("{\n");
    printf("  \"pid\": %d,\n", (int)pid);
    printf("  \"exe\": "); json_str(stdout, exe); printf(",\n");
    printf("  \"caps_effective\": "); json_str(stdout, caps_eff); printf(",\n");
    printf("  \"caps_dropped\": %s,\n", caps_dropped ? "true" : "false");
    printf("  \"no_new_privs\": %s,\n", no_new_privs ? "true" : "false");
    printf("  \"seccomp\": %d,\n", seccomp_val);
    printf("  \"seccomp_label\": "); json_str(stdout, seccomp_label); printf(",\n");
    printf("  \"ns_user_isolated\": %s,\n", ns_user ? "true" : "false");
    printf("  \"ns_mnt_isolated\": %s,\n",  ns_mnt  ? "true" : "false");
    printf("  \"ns_net_isolated\": %s,\n",  ns_net  ? "true" : "false");
    printf("  \"ns_pid_isolated\": %s,\n",  ns_pid  ? "true" : "false");
    printf("  \"ns_ipc_isolated\": %s,\n",  ns_ipc  ? "true" : "false");
    printf("  \"ns_uts_isolated\": %s,\n",  ns_uts  ? "true" : "false");
    printf("  \"verdict\": "); json_str(stdout, verdict); printf(",\n");
    printf("  \"issues\": [");
    for (int i = 0; i < n_issues; i++) {
        if (i > 0) printf(", ");
        json_str(stdout, issues[i]);
    }
    printf("]\n");
    printf("}\n");

    return 0;
}
