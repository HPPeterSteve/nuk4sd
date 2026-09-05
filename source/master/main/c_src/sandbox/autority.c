#include "sandbox.h"
#include <uuid/uuid.h>
/*
 * codigo fonte responsável pela flag de --uuid
 * pai cria um processo supervisor para o sandbox e cria processo filho
 * espera o binario criar o sandbox e pega uuid
 * pega o uuid do sandbox, pegando o caminho daquele binario
 * filho aguarda o pai ler o /proc/[pid]/exe e verificar se é o binario original
 * filho prepara um novo nome para o processo
 * se sim, monitorar uuid fornecido ja pelas structs
 * se nao, ele para de monitorar e deixa o processo vivo. isso não é trabalho do --uuid
 * cria um nome hasheado daquele processo
 * verifica a cada momento se o processo deu exit code, se sim, ele encerra também
 */
#ifdef __linux__

static int hash_string(const char *str) {
    unsigned int hash = 5381;
    int c;
    while ((c = (unsigned char)*str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return (int)(hash & 0x7FFFFFFF);
}

int setup_uuid(UuidArgs args) {
    uuid_t uuid;
    char uuid_str[37];
    int exitcode = 0;

    /* gera uuid para sandboxes */
    uuid_generate(uuid);
    if (uuid_is_null(uuid)) {
        vault_log(LOG_ERROR, "[uuid] Failed to generate uuid for sandbox %s",
                  args.original_binary ? args.original_binary : "unknown");
        return -1;
    }

    /* aqui o filho deve verificar se o uuid é nulo, se sim, ele para de
     * monitorar e deixa o processo vivo. */
    uuid_unparse(uuid, uuid_str);

    /* envia uuid para o filho via pipe, se configurado */
    if (args.pipe_fd[1] >= 0) {
        if (write(args.pipe_fd[1], uuid_str, sizeof(uuid_str)) < 0) {
            vault_log(LOG_ERROR, "[uuid] Failed to write to pipe: %s", strerror(errno));
            exitcode = 1;
        }
    }

    /* prepara um novo nome para o processo */
    char hash_str[16];
    int hash = hash_string(uuid_str);

    snprintf(hash_str, sizeof(hash_str), "%d", hash);
    vault_log(LOG_INFO, "[uuid] Setting process name to: %s", hash_str);

    if (prctl(PR_SET_NAME, hash_str, 0, 0, 0) < 0) {
        vault_log(LOG_ERROR, "[uuid] Failed to set process name: %s", strerror(errno));
        exitcode = 1;
    }

    setenv("NUK4SD_SANDBOX_UUID", uuid_str, 1);

    vault_log(LOG_INFO, "[uuid] Process %d with uuid %s configured successfully", (int)args.pid, uuid_str);

    /* limpa dados sensíveis da stack */
    explicit_bzero(uuid_str, sizeof(uuid_str));
    vault_log(LOG_INFO, "[uuid] Explicitly clearing uuid_str");

    explicit_bzero(hash_str, sizeof(hash_str));
    vault_log(LOG_INFO, "[uuid] Explicitly clearing hash_str");

    return exitcode;
}

int wait_init_binary(UuidArgs args) {
    if (args.pid <= 0)
        return -1;

    vault_log(LOG_INFO, "[uuid] Supervisor checking child process pid: %d", (int)args.pid);

    char exe_path[PATH_MAX];
    char readed_path[PATH_MAX];

    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", (int)args.pid);

    ssize_t nread = readlink(exe_path, readed_path, sizeof(readed_path) - 1);

    /* aqui o supervisor lê o caminho absoluto do executavel que o processo está executando */

    if (nread < 0) {
        vault_log(LOG_ERROR, "[uuid] Failed to read executable path: %s", strerror(errno));
        return -1;
    }

    /* garante o null terminator */
    readed_path[nread] = '\0';

    /* verifica se o caminho absoluto do executavel é igual ao original */
    if (args.original_binary && strcmp(args.original_binary, readed_path) != 0) {
        vault_log(LOG_ERROR, "[uuid] Binary path does not match the original path: %s (expected: %s)", readed_path,
                  args.original_binary);
        return -1;
    }

    return 0;
}

#else /* !__linux__ */

int setup_uuid(UuidArgs args) {
    (void)args;
    return 0;
}

int wait_init_binary(UuidArgs args) {
    (void)args;
    return 0;
}

#endif /* __linux__ */
