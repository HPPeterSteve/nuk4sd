/*
 * vault_engine.c
 *
 * VAULT SECURITY SYSTEM — Engine de Isolamento (Honeyfile Labyrinth)
 *
 * Engines disponíveis:
 *   0 → sem engine (comportamento padrão)
 *   1 → 1  camada  de pastas isca + arquivos a-z
 *   2 → 3  camadas de pastas isca + arquivos a-z por camada
 *   3 → 6  camadas de pastas isca + arquivos a-z por camada
 *   4 → 16 camadas + binários falsos (.enc) em vez de texto
 *   5 → 20 camadas + binários falsos (.enc) [OverlayFS adicionado futuramente]
 *
 * Estrutura criada dentro do vault:
 *
 *   <vault_path>/
 *     .engine_decoy/          ← labirinto de iscas (público para o atacante)
 *       layer_01/
 *         a.txt … z.txt       (engines 1-3) ou a.enc … z.enc (engines 4-5)
 *         layer_02/           ← ANINHADA dentro de layer_01, não ao lado
 *           a.txt … z.txt
 *           layer_03/         ← funil: cada camada só existe dentro da anterior
 *             ...
 *     .engine_real/           ← onde os arquivos reais devem ser guardados
 *
 * Restrições severas:
 *   - Todas as operações verificam que o vault não está DELETED/LOCKED
 *   - Caminhos são validados com realpath() antes de qualquer mkdir/write
 *   - Cada arquivo criado é verificado com stat() após a escrita
 *   - Logs at each stage (start, progress, success, error)
 *   - Em caso de erro parcial, cleanup best-effort é executado
 *
 * Fixes aplicados (v2):
 *   [FIX-1] strncmp path traversal: verifica separador após prefixo do vault
 *   [FIX-2] engine_is_decoy_path: usa realpath+strncmp em vez de strstr
 *   [FIX-3] engine_apply: cleanup best-effort ao detectar layers_failed > 0
 *   [FIX-4] engine_write_text_decoy: conteúdo variado e tamanho realístico
 *   [FIX-5] engine_write_binary_decoy: magic byte variado por arquivo
 *
 * Author: gerado junto ao Nuk4sd — Peter Steve (architecture)
 */

#include "vault_core.h"

#ifdef __linux__
#include <dirent.h>
#endif

/* ─────────────────────────────────────────────────────────────────────────
 *  Helpers internos
 * ───────────── */

/* Cria um diretório com permissões 0700. */
static VaultErrorr engine_mkdir(const char *path)
{
    if (!path || path[0] == '\0')
    {
        vault_log(LOG_ERROR, "%s engine_mkdir: caminho vazio", ENGINE_LOG_PREFIX);
        return ERR_INVALID_ARGS;
    }

    /*
    if (mkdir(path, 0000) != 0)
    {
        vault_log(LOG_ERROR, "%s mkdir denied('%s'): %s",
                  ENGINE_LOG_PREFIX, path, strerror(errno));
        return ERR_IO;
    }
        */

    struct stat st;
    if (stat(path, &st) == 0)
    {
        if (!S_ISDIR(st.st_mode))
        {
            vault_log(LOG_ERROR, "%s '%s' existe mas não é diretório",
                      ENGINE_LOG_PREFIX, path);
            return ERR_IO;
        }
        return ERR_OK;
    }

    if (mkdir(path, 0700) != 0)
    {
        vault_log(LOG_ERROR, "%s mkdir('%s'): %s",
                  ENGINE_LOG_PREFIX, path, strerror(errno));
        return ERR_IO;
    }

    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s mkdir('%s'): criado mas stat falhou",
                  ENGINE_LOG_PREFIX, path);
        return ERR_IO;
    }

    vault_log(LOG_INFO, "%s diretório criado: %s", ENGINE_LOG_PREFIX, path);
    return ERR_OK;
}

/* [FIX-1] Valida que um caminho está contido dentro do vault.
 * Verifica separador após prefixo para evitar /vault1 aceitar /vault1_evil. */
static VaultErrorr engine_validate_inside_vault(const Vault *v, const char *path)
{
    char resolved[PATH_MAX];
    char vault_resolved[PATH_MAX];

    if (!realpath(v->path, vault_resolved))
    {
        vault_log(LOG_ERROR, "%s realpath(vault): %s",
                  ENGINE_LOG_PREFIX, strerror(errno));
        return ERR_PATH_INVALID;
    }

    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);

    char *slash = strrchr(tmp, '/');
    if (!slash)
    {
        vault_log(LOG_ERROR, "%s caminho sem separador: %s",
                  ENGINE_LOG_PREFIX, path);
        return ERR_PATH_INVALID;
    }

    *slash = '\0';
    if (!realpath(tmp, resolved))
    {
        vault_log(LOG_ERROR, "%s realpath(pai de '%s'): %s",
                  ENGINE_LOG_PREFIX, path, strerror(errno));
        return ERR_PATH_INVALID;
    }

    size_t vlen = strlen(vault_resolved);

    if (strncmp(resolved, vault_resolved, vlen) != 0 ||
        (resolved[vlen] != '/' && resolved[vlen] != '\0'))
    {
        vault_log(LOG_ERROR, "%s VIOLAÇÃO DE PATH: '%s' fora do vault '%s'",
                  ENGINE_LOG_PREFIX, path, vault_resolved);
        return ERR_PERM_DENIED;
    }

    return ERR_OK;
}

/* [FIX-4] Tabela de conteúdo plausível para iscas de texto. */
static const char *DECOY_TEMPLATES[] = {
    "Project Status Report\n"
    "======================\n"
    "Quarter: Q3\nDepartment: Operations\nPrepared by: Systems Audit\n\n"
    "Executive Summary:\n"
    "This document outlines the current operational status and key performance\n"
    "indicators for the reporting period. Infrastructure metrics remain within\n"
    "acceptable thresholds. Detailed breakdowns are available upon request.\n\n"
    "Key Findings:\n"
    "  - Uptime: 99.94%%\n  - Incidents resolved: 14\n"
    "  - Pending tasks: 3\n  - Budget variance: -2.1%%\n\n"
    "Next review scheduled: end of quarter.\n",

    "Internal Memo\n==============\n"
    "To: All Staff\nFrom: Management\n"
    "Subject: Updated Access Policies\n\n"
    "Effective immediately, all personnel must comply with the revised data\n"
    "handling protocols described in policy document SEC-2024-11.\n"
    "Violations will be subject to disciplinary review.\n\n"
    "Please acknowledge receipt by logging into the HR portal.\n",

    "Financial Summary\n==================\n"
    "Period: January - June\nEntity: Nuk4sd Holdings\n\n"
    "Revenue:         $4,820,310.00\nOperating Costs: $3,104,820.50\n"
    "Net Income:      $1,715,489.50\nEBITDA Margin:   35.6%%\n\n"
    "Notes:\nFigures are preliminary and subject to audit confirmation.\n"
    "See Appendix B for detailed line-item breakdown.\n",

    "System Configuration Backup\n============================\n"
    "Host: vault-node-04\nOS: Ubuntu 22.04 LTS\n"
    "Kernel: 5.15.0-91-generic\nGenerated: automated\n\n"
    "[network]\ninterface=eth0\nip=10.0.1.44\ngateway=10.0.1.1\n"
    "dns=8.8.8.8,1.1.1.1\n\n"
    "[storage]\nmount=/data\ntype=ext4\ncapacity=2TB\nused=847GB\n\n"
    "[backup]\nschedule=daily\nretention=30d\nlast_run=success\n",

    "Employee Records - Confidential\n================================\n"
    "Record ID: EMP-00847\nName: [REDACTED]\nDepartment: Engineering\n"
    "Start Date: 2019-03-12\nLevel: Senior\n\n"
    "Performance Review (Latest):\n"
    "  Rating: Exceeds Expectations\n  Score: 4.7 / 5.0\n"
    "  Reviewer: [REDACTED]\n\n"
    "Compensation: see HR system.\nAccess Level: 3\nClearance: Standard\n",
};

#define DECOY_TEMPLATE_COUNT ((int)(sizeof(DECOY_TEMPLATES) / sizeof(DECOY_TEMPLATES[0])))

/* [FIX-4] Escreve arquivo isca de texto com conteúdo variado. */
static VaultErrorr engine_write_text_decoy(const char *filepath, char letter)
{
    int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        if (errno == ELOOP)
        {
            vault_log(LOG_ALERT, "%s fopen->open ELOOP (symlink) on '%s'", ENGINE_LOG_PREFIX, filepath);
        }
        else
        {
            vault_log(LOG_ERROR, "%s open('%s'): %s", ENGINE_LOG_PREFIX, filepath, strerror(errno));
        }
        return ERR_IO;
    }
    FILE *f = fdopen(fd, "w");
    if (!f)
    {
        close(fd);
        vault_log(LOG_ERROR, "%s fdopen('%s') failed", ENGINE_LOG_PREFIX, filepath);
        return ERR_IO;
    }

    int tmpl_idx = (letter - 'a') % DECOY_TEMPLATE_COUNT;
    fprintf(f, "%s", DECOY_TEMPLATES[tmpl_idx]);

    static const char *LOREM =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod "
        "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, "
        "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo. "
        "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore "
        "eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.\n";

    int repeats = 2 + ((letter - 'a') % 5);
    for (int i = 0; i < repeats; i++)
    {
        fputs(LOREM, f);
    }

    if (fflush(f) != 0)
    {
        vault_log(LOG_ERROR, "%s fflush('%s'): %s",
                  ENGINE_LOG_PREFIX, filepath, strerror(errno));
        fclose(f);
        return ERR_IO;
    }
    fclose(f);

    struct stat st;
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s arquivo isca não confirmado: %s",
                  ENGINE_LOG_PREFIX, filepath);
        return ERR_IO;
    }

    return ERR_OK;
}

/* [FIX-5] Magic bytes de formatos reais para variar entre arquivos. */
static const struct
{
    uint8_t bytes[4];
    size_t len;
} REAL_MAGIC[] = {
    {{0x25, 0x50, 0x44, 0x46}, 4}, /* %PDF */
    {{0x50, 0x4B, 0x03, 0x04}, 4}, /* PK (ZIP/DOCX/XLSX) */
    {{0xFF, 0xD8, 0xFF, 0xE0}, 4}, /* JPEG JFIF */
    {{0x89, 0x50, 0x4E, 0x47}, 4}, /* PNG */
    {{0x52, 0x49, 0x46, 0x46}, 4}, /* RIFF (WAV/AVI) */
};

#define REAL_MAGIC_COUNT ((int)(sizeof(REAL_MAGIC) / sizeof(REAL_MAGIC[0])))

/* [FIX-5] Binário falso com magic rotativo por letra. */
static VaultErrorr engine_write_binary_decoy(const char *filepath, char letter)
{
    uint8_t buf[512];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        vault_log(LOG_ERROR, "%s open(/dev/urandom): %s",
                  ENGINE_LOG_PREFIX, strerror(errno));
        return ERR_IO;
    }

    ssize_t got = read(fd, buf, sizeof(buf));
    close(fd);

    if (got != (ssize_t)sizeof(buf))
    {
        vault_log(LOG_ERROR, "%s urandom leu %zd bytes (esperado %zu)",
                  ENGINE_LOG_PREFIX, got, sizeof(buf));
        return ERR_IO;
    }

    int magic_idx = (letter - 'a') % REAL_MAGIC_COUNT;
    memcpy(buf, REAL_MAGIC[magic_idx].bytes, REAL_MAGIC[magic_idx].len);

    int out_fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out_fd < 0)
    {
        if (errno == ELOOP)
        {
            vault_log(LOG_ALERT, "%s fopen->open ELOOP (symlink) on '%s'", ENGINE_LOG_PREFIX, filepath);
        }
        else
        {
            vault_log(LOG_ERROR, "%s open(bin '%s'): %s", ENGINE_LOG_PREFIX, filepath, strerror(errno));
        }
        return ERR_IO;
    }
    FILE *f = fdopen(out_fd, "wb");
    if (!f)
    {
        close(out_fd);
        vault_log(LOG_ERROR, "%s fdopen(bin '%s') failed", ENGINE_LOG_PREFIX, filepath);
        return ERR_IO;
    }

    size_t written = fwrite(buf, 1, sizeof(buf), f);
    if (fflush(f) != 0)
    {
        vault_log(LOG_ERROR, "%s fflush(bin '%s'): %s",
                  ENGINE_LOG_PREFIX, filepath, strerror(errno));
        fclose(f);
        return ERR_IO;
    }
    fclose(f);

    if (written != sizeof(buf))
    {
        vault_log(LOG_ERROR, "%s fwrite incompleto em '%s': %zu/%zu bytes",
                  ENGINE_LOG_PREFIX, filepath, written, sizeof(buf));
        return ERR_IO;
    }

    struct stat st;
    if (stat(filepath, &st) != 0 || st.st_size != (off_t)sizeof(buf))
    {
        vault_log(LOG_ERROR, "%s binário falso não confirmado: %s",
                  ENGINE_LOG_PREFIX, filepath);
        return ERR_IO;
    }

    return ERR_OK;
}

/* Popula uma camada com arquivos a-z. */
static VaultErrorr engine_populate_layer(const char *layer_path, bool binary)
{
    int errors = 0;
    int created = 0;

    vault_log(LOG_INFO, "%s populando camada: %s (%s)",
              ENGINE_LOG_PREFIX, layer_path, binary ? "binário" : "texto");

    for (char c = 'a'; c <= 'z'; c++)
    {
        char filepath[PATH_MAX];
        if (binary)
            snprintf(filepath, sizeof(filepath), "%s/%c.enc", layer_path, c);
        else
            snprintf(filepath, sizeof(filepath), "%s/%c.txt", layer_path, c);

        VaultErrorr err = binary
                             ? engine_write_binary_decoy(filepath, c)
                             : engine_write_text_decoy(filepath, c);

        if (err != ERR_OK)
        {
            vault_log(LOG_ERROR, "%s erro ao criar isca '%s': %s",
                      ENGINE_LOG_PREFIX, filepath, vault_strerror(err));
            errors++;
            continue;
        }

        if (chmod(filepath, 0400) != 0)
        {
            vault_log(LOG_WARN, "%s chmod(0400) em '%s': %s",
                      ENGINE_LOG_PREFIX, filepath, strerror(errno));
        }

        created++;
    }

    vault_log(LOG_INFO, "%s camada '%s': %d arquivos criados, %d erros",
              ENGINE_LOG_PREFIX, layer_path, created, errors);

    if (errors > 0)
    {
        vault_log(LOG_ERROR, "%s camada incompleta: %d/%d arquivos falharam",
                  ENGINE_LOG_PREFIX, errors, created + errors);
        return ERR_IO;
    }

    return ERR_OK;
}
static const char *rm_paths[] = {
    "/bin/rm",
    "/usr/bin/rm",
    "/usr/local/bin/rm",
    NULL
};
/* [FIX-3] Cleanup best-effort: remove labirinto parcial. */
static void engine_cleanup_decoy(const char *decoy_root)
{
    if (!decoy_root || decoy_root[0] == '\0')
        return;

    vault_log(LOG_WARN, "%s cleanup: removendo labirinto parcial em '%s'",
              ENGINE_LOG_PREFIX, decoy_root);

    
    pid_t pid = fork();
      if (pid < 0) {
      vault_log(LOG_ERROR, "%s cleanup: fork failed: %s", ENGINE_LOG_PREFIX, strerror(errno));
        return;
      }
      if (pid == 0) {
    /* filho: executa rm diretamente, sem shell */
        char *const args[] = { "rm", "-rf", (char *)decoy_root, NULL };
        for (int i = 0; rm_paths[i] != NULL; i++) {
            execv(rm_paths[i], args);
        }
        exit(127); /* execv falhou em todas as tentativas */
      }
      int status;
       if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
         vault_log(LOG_WARN, "%s cleanup: rm -rf retornou erro", ENGINE_LOG_PREFIX);
       else 
         vault_log(LOG_INFO, "%s cleanup: labirinto parcial removido", ENGINE_LOG_PREFIX);
}

/* ─────────────────────────────────────────────────────────────────────────
 *  engine_apply() — ponto de entrada público
 * ───────────── */
VaultErrorr engine_apply(Vault *v)
{
    if (!v)
    {
        vault_log(LOG_ERROR, "%s engine_apply: vault NULL", ENGINE_LOG_PREFIX);
        return ERR_INVALID_ARGS;
    }

    if (v->status == VAULT_STATUS_DELETED)
    {
        vault_log(LOG_ERROR, "%s engine_apply: vault '%s' está DELETED",
                  ENGINE_LOG_PREFIX, v->name);
        return ERR_INVALID_ARGS;
    }

    if (v->status == VAULT_STATUS_LOCKED)
    {
        vault_log(LOG_ERROR, "%s engine_apply: vault '%s' está LOCKED",
                  ENGINE_LOG_PREFIX, v->name);
        return ERR_VAULT_LOCKED;
    }

    int level = v->engine_level;

    if (level < ENGINE_LEVEL_MIN || level > ENGINE_LEVEL_MAX)
    {
        vault_log(LOG_ERROR, "%s engine_apply: nível inválido %d (válido: %d-%d)",
                  ENGINE_LOG_PREFIX, level, ENGINE_LEVEL_MIN, ENGINE_LEVEL_MAX);
        return ERR_INVALID_ARGS;
    }

    if (level == 0)
    {
        vault_log(LOG_INFO, "%s engine 0 selecionado — sem labirinto", ENGINE_LOG_PREFIX);
        return ERR_OK;
    }

    vault_log(LOG_INFO, "%s aplicando engine %d ao vault '%s' (path='%s')",
              ENGINE_LOG_PREFIX, level, v->name, v->path);

    char decoy_root[PATH_MAX];
    snprintf(decoy_root, sizeof(decoy_root), "%s/%s", v->path, ENGINE_DECOY_DIR);

    VaultErrorr err = engine_mkdir(decoy_root);
    if (err != ERR_OK)
    {
        vault_log(LOG_ERROR, "%s falha ao criar diretório raiz de iscas: %s",
                  ENGINE_LOG_PREFIX, vault_strerror(err));
        return err;
    }

    char real_dir[PATH_MAX];
    snprintf(real_dir, sizeof(real_dir), "%s/%s", v->path, ENGINE_REAL_DIR);

    err = engine_mkdir(real_dir);
    if (err != ERR_OK)
    {
        vault_log(LOG_ERROR, "%s falha ao criar diretório real: %s",
                  ENGINE_LOG_PREFIX, vault_strerror(err));
        return err;
    }

    if (chmod(real_dir, 0700) != 0)
    {
        vault_log(LOG_WARN, "%s chmod(0700) em real_dir: %s",
                  ENGINE_LOG_PREFIX, strerror(errno));
    }

    int layer_count = ENGINE_LAYER_COUNT[level];
    bool binary = (level >= 4);

    vault_log(LOG_INFO, "%s engine %d: %d camadas, modo=%s",
              ENGINE_LOG_PREFIX, level, layer_count,
              binary ? "binário (.enc)" : "texto (.txt)");

    int layers_ok = 0;
    int layers_failed = 0;

    /* Labirinto ANINHADO: cada camada fica DENTRO da anterior (funil), não
     * lado a lado sob decoy_root. 'cursor' começa no decoy_root e desce um
     * nível a cada iteração — layer_01/layer_02/.../layer_NN, cada uma
     * contida na anterior. Isso força uma travessia recursiva de verdade em
     * vez de uma listagem plana com 'ls'/'find -maxdepth 2'. */
    char cursor[PATH_MAX];
    snprintf(cursor, sizeof(cursor), "%s", decoy_root);

    for (int i = 1; i <= layer_count; i++)
    {
        char layer_path[PATH_MAX];
        int wlen = snprintf(layer_path, sizeof(layer_path), "%s/layer_%02d", cursor, i);
        if (wlen < 0 || (size_t)wlen >= sizeof(layer_path))
        {
            vault_log(LOG_ERROR, "%s camada %d: caminho excedeu PATH_MAX, abortando",
                      ENGINE_LOG_PREFIX, i);
            layers_failed++;
            break;
        }

        vault_log(LOG_INFO, "%s criando camada %d/%d: %s",
                  ENGINE_LOG_PREFIX, i, layer_count, layer_path);

        err = engine_validate_inside_vault(v, layer_path);
        if (err != ERR_OK)
        {
            vault_log(LOG_ERROR, "%s camada %d: validação de caminho falhou",
                      ENGINE_LOG_PREFIX, i);
            layers_failed++;
            continue;
        }

        err = engine_mkdir(layer_path);
        if (err != ERR_OK)
        {
            vault_log(LOG_ERROR, "%s camada %d: mkdir falhou: %s",
                      ENGINE_LOG_PREFIX, i, vault_strerror(err));
            layers_failed++;
            continue;
        }

        err = engine_populate_layer(layer_path, binary);
        if (err != ERR_OK)
        {
            vault_log(LOG_ERROR, "%s camada %d: populate falhou: %s",
                      ENGINE_LOG_PREFIX, i, vault_strerror(err));
            layers_failed++;
            continue;
        }

        vault_log(LOG_INFO, "%s ✓ camada %d/%d concluída",
                  ENGINE_LOG_PREFIX, i, layer_count);
        layers_ok++;

        /* Desce um nível: a próxima camada nasce DENTRO desta. */
        snprintf(cursor, sizeof(cursor), "%s", layer_path);
    }

    vault_log(LOG_INFO,
              "%s engine %d aplicado ao vault '%s': %d/%d layers OK, %d falhas",
              ENGINE_LOG_PREFIX, level, v->name,
              layers_ok, layer_count, layers_failed);

    /* [FIX-3] Cleanup se labirinto ficou parcial */
    if (layers_failed > 0)
    {
        vault_log(LOG_ERROR,
                  "%s engine %d INCOMPLETO: %d camadas falharam — executando cleanup",
                  ENGINE_LOG_PREFIX, level, layers_failed);
        engine_cleanup_decoy(decoy_root);
        return ERR_IO;
    }

    if (level == 5)
    {
        vault_log(LOG_INFO,
                  "%s engine 5: labirinto de 20 camadas criado. "
                  "OverlayFS será implementado em etapa futura.",
                  ENGINE_LOG_PREFIX);
    }

    vault_log(LOG_INFO, "%s engine %d totalmente aplicado ao vault '%s'",
              ENGINE_LOG_PREFIX, level, v->name);

    return ERR_OK;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  engine_validate() — verifica integridade do labirinto
 * ───────────── */
VaultErrorr engine_validate(Vault *v)
{
    if (!v)
    {
        vault_log(LOG_ERROR, "%s engine_validate: vault NULL", ENGINE_LOG_PREFIX);
        return ERR_INVALID_ARGS;
    }

    int level = v->engine_level;

    if (level == 0)
    {
        vault_log(LOG_INFO, "%s engine_validate: engine 0 — nada a validar", ENGINE_LOG_PREFIX);
        return ERR_OK;
    }

    if (level < ENGINE_LEVEL_MIN || level > ENGINE_LEVEL_MAX)
    {
        vault_log(LOG_ERROR, "%s engine_validate: nível inválido %d",
                  ENGINE_LOG_PREFIX, level);
        return ERR_INVALID_ARGS;
    }

    vault_log(LOG_INFO, "%s validando engine %d do vault '%s'",
              ENGINE_LOG_PREFIX, level, v->name);

    char decoy_root[PATH_MAX];
    snprintf(decoy_root, sizeof(decoy_root), "%s/%s", v->path, ENGINE_DECOY_DIR);

    struct stat st;
    if (stat(decoy_root, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s diretório de iscas ausente: %s",
                  ENGINE_LOG_PREFIX, decoy_root);
        return ERR_INTEGRITY;
    }

    char real_dir[PATH_MAX];
    snprintf(real_dir, sizeof(real_dir), "%s/%s", v->path, ENGINE_REAL_DIR);

    if (stat(real_dir, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s diretório real ausente: %s",
                  ENGINE_LOG_PREFIX, real_dir);
        return ERR_INTEGRITY;
    }

    int layer_count = ENGINE_LAYER_COUNT[level];
    bool binary = (level >= 4);
    int missing_layers = 0;
    int missing_files = 0;

    /* Mesma lógica de descida usada em engine_apply() — precisa bater
     * exatamente, senão a validação procura as camadas no lugar errado. */
    char cursor[PATH_MAX];
    snprintf(cursor, sizeof(cursor), "%s", decoy_root);

    for (int i = 1; i <= layer_count; i++)
    {
        char layer_path[PATH_MAX];
        snprintf(layer_path, sizeof(layer_path), "%s/layer_%02d", cursor, i);

        if (stat(layer_path, &st) != 0 || !S_ISDIR(st.st_mode))
        {
            vault_log(LOG_ERROR, "%s camada ausente: %s",
                      ENGINE_LOG_PREFIX, layer_path);
            missing_layers++;
            /* Sem a camada, não dá pra descer mais — para aqui, senão as
             * próximas 'ausências' são só efeito cascata da primeira. */
            break;
        }

        for (char c = 'a'; c <= 'z'; c++)
        {
            char filepath[PATH_MAX];
            if (binary)
                snprintf(filepath, sizeof(filepath), "%s/%c.enc", layer_path, c);
            else
                snprintf(filepath, sizeof(filepath), "%s/%c.txt", layer_path, c);

            if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
            {
                vault_log(LOG_WARN, "%s arquivo isca ausente: %s",
                          ENGINE_LOG_PREFIX, filepath);
                missing_files++;
            }
        }

        snprintf(cursor, sizeof(cursor), "%s", layer_path);
    }

    if (missing_layers > 0 || missing_files > 0)
    {
        vault_log(LOG_ERROR,
                  "%s validação FALHOU: %d camadas ausentes, %d arquivos ausentes",
                  ENGINE_LOG_PREFIX, missing_layers, missing_files);

        char reason[256];
        snprintf(reason, sizeof(reason),
                 "Engine %d comprometido: %d camadas, %d arquivos removidos",
                 level, missing_layers, missing_files);
        alert_trigger(v, reason);

        return ERR_INTEGRITY;
    }

    vault_log(LOG_INFO, "%s engine %d do vault '%s' SUCCESSFULLY VALIDATED (%d layers OK)",
              ENGINE_LOG_PREFIX, level, v->name, layer_count);
    return ERR_OK;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  [FIX-2] engine_is_decoy_path_v() — versão segura com realpath
 * ───────────── */
bool engine_is_decoy_path_v(const Vault *v, const char *path)
{
    if (!v || !path)
        return false;

    char decoy_root[PATH_MAX];
    char decoy_resolved[PATH_MAX];
    char path_resolved[PATH_MAX];

    snprintf(decoy_root, sizeof(decoy_root), "%s/%s", v->path, ENGINE_DECOY_DIR);

    if (!realpath(decoy_root, decoy_resolved))
        return false;
    if (!realpath(path, path_resolved))
        return false;

    size_t dlen = strlen(decoy_resolved);

    return (strncmp(path_resolved, decoy_resolved, dlen) == 0 &&
            (path_resolved[dlen] == '/' || path_resolved[dlen] == '\0'));
}

/* [FIX-2 cleanup] engine_is_decoy_path(path) foi removida: era um
 * "wrapper de compatibilidade" que fazia strstr(path, ENGINE_DECOY_DIR)
 * — exatamente a checagem vulnerável a path traversal que o FIX-2
 * substituiu por realpath()+strncmp() em engine_is_decoy_path_v().
 * Não havia nenhum chamador no código atual, mas continuava exportada
 * no header como se fosse segura para uso. Use sempre
 * engine_is_decoy_path_v(vault, path). */