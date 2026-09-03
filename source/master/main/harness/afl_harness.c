/* AFL++ persistent-mode harness para o parser da CLI do Nuk4sd.
 * Cada TestCase = uma linha de comandos; parseada e executada.
 * Modo persistente: 10000 iterações por fork, muito mais rápido. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "vault_core.h"
extern unsigned int  *__afl_fuzz_len;
extern unsigned char *__afl_fuzz_ptr;
extern unsigned int __afl_persistent_loop(unsigned int max_cnt);

extern int vault_cli_parse_and_exec(int argc, char **argv);

static char buf[65536];
static char *args[4096];

static void no_input(int sig) {
    (void)sig;
    fprintf(stderr, "[harness] stdin vazio, esperando TestCase...\n");
}

static void run_one(void) {
    int n = 0;
    args[n++] = "Nuk4sd";
    char *p = buf;
    while (*p && n < 4094) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        char *start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) { *p = '\0'; p++; }
        args[n++] = start;
    }
    args[n] = NULL;
    if (n > 1)
        vault_cli_parse_and_exec(n, args);
}

int main(int argc, char **argv) {
    signal(SIGALRM, no_input);

#ifdef __AFL_COMPILER
    while (__afl_persistent_loop(500)) {
        size_t len = *__afl_fuzz_len;
        if (len == 0) break;
        if (len >= sizeof(buf)) len = sizeof(buf) - 1;
        memcpy(buf, __afl_fuzz_ptr, len);
        buf[len] = '\0';
        run_one();
    }
#else
    /* Fallback: modo stdin (pipe manual) ou file mode (afl-fuzz dry run) */
    if (argc > 1) {
        FILE *f = fopen(argv[1], "r");
        if (f) {
            while (fgets(buf, sizeof(buf), f)) run_one();
            fclose(f);
        }
    } else {
        while (fgets(buf, sizeof(buf), stdin)) run_one();
    }
#endif
    return 0;
}
