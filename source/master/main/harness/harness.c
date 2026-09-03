/* Fuzz harness: lê uma linha de comandos do stdin, constrói argv e chama
   vault_cli_parse (o parser da CLI do Nuk4sd). Usado com afl++ e sanitizadores. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

/* O parser da CLI é exposto via vault_core.h? Verificamos a declaração. */
#include "vault_core.h"

/* Declaração do parser principal do vault_cli.c */
extern int vault_cli_parse_and_exec(int argc, char **argv);

static char *extra[8] = {NULL};

static char line[65536];
static char *args[8192];

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    while (fgets(line, sizeof(line), stdin)) {
        /* Termina na primeira \n */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        int n = 0;
        args[n++] = "Nuk4sd";
        char *p = line;
        while (*p && n < 8190) {
            while (*p == ' ' || *p == '\t') p++;
            if (!*p) break;
            char *start = p;
            while (*p && *p != ' ') p++;
            if (*p) { *p = '\0'; p++; }
            args[n++] = start;
        }
        args[n] = NULL;
        vault_cli_parse_and_exec(n, args);
    }
    return 0;
}
