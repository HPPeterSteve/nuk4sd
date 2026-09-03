#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/limits.h>

static bool bind_path_is_safe(const char *vault_path, const char *dst) {
    char resolved_vault[PATH_MAX];
    if (!realpath(vault_path, resolved_vault)) return false;

    char probe[PATH_MAX];
    snprintf(probe, sizeof(probe), "%s", dst);
    char resolved_probe[PATH_MAX];

    while (!realpath(probe, resolved_probe)) {
        char *slash = strrchr(probe, '/');
        if (!slash || slash == probe) return false;
        *slash = '\0';
    }

    size_t vlen = strlen(resolved_vault);
    return strncmp(resolved_probe, resolved_vault, vlen) == 0 &&
           (resolved_probe[vlen] == '/' || resolved_probe[vlen] == '\0');
}

int main(int argc, char **argv) {
    if (argc != 3) return 1;
    bool safe = bind_path_is_safe(argv[1], argv[2]);
    printf("safe: %d\n", safe);
    return 0;
}
