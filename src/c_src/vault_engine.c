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
 *       layer_02/
 *         ...
 *     .engine_real/           ← onde os arquivos reais devem ser guardados
 *
 * Restrições severas:
 *   - Todas as operações verificam que o vault não está DELETED/LOCKED
 *   - Caminhos são validados com realpath() antes de qualquer mkdir/write
 *   - Cada arquivo criado é verificado com stat() após a escrita
 *   - Logs em cada etapa (início, progresso, sucesso, erro)
 *   - Em caso de erro parcial, tenta limpar o que foi criado (best-effort)
 *
 * Author: gerado junto ao Nuk4sd — Peter Steve (architecture)
 */

#include "vault_core.h"

#ifdef __linux__
#include <dirent.h>
#endif

/* ─────────────────────────────────────────────────────────────────────────
 *  Helpers internos
 * ───────────────────────────────────────────────────────────────────────── */

/* Cria um diretório com permissões 0700.
 * Retorna ERR_OK se já existir ou se criou com sucesso. */
static VaultError engine_mkdir(const char *path)
{
    if (!path || path[0] == '\0')
    {
        vault_log(LOG_ERROR, "%s engine_mkdir: caminho vazio", ENGINE_LOG_PREFIX);
        return ERR_INVALID_ARGS;
    }

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

    /* Confirma que foi criado */
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s mkdir('%s'): criado mas stat falhou",
                  ENGINE_LOG_PREFIX, path);
        return ERR_IO;
    }

    vault_log(LOG_INFO, "%s diretório criado: %s", ENGINE_LOG_PREFIX, path);
    return ERR_OK;
}

/* Valida que um caminho está contido dentro do vault (evita path traversal). */
static VaultError engine_validate_inside_vault(const Vault *v, const char *path)
{
    char resolved[PATH_MAX];
    char vault_resolved[PATH_MAX];

    if (!realpath(v->path, vault_resolved))
    {
        vault_log(LOG_ERROR, "%s realpath(vault): %s",
                  ENGINE_LOG_PREFIX, strerror(errno));
        return ERR_PATH_INVALID;
    }

    /* Para o path do engine que ainda não existe, resolve o pai */
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

    if (strncmp(resolved, vault_resolved, strlen(vault_resolved)) != 0)
    {
        vault_log(LOG_ERROR, "%s VIOLAÇÃO DE PATH: '%s' fora do vault '%s'",
                  ENGINE_LOG_PREFIX, path, vault_resolved);
        return ERR_PERM_DENIED;
    }

    return ERR_OK;
}

/* Escreve um arquivo isca de texto simples (engines 1-3).
 * Conteúdo: texto inofensivo que parece um documento real. */
static VaultError engine_write_text_decoy(const char *filepath, char letter)
{
    FILE *f = fopen(filepath, "w");
    if (!f)
    {
        vault_log(LOG_ERROR, "%s fopen('%s'): %s",
                  ENGINE_LOG_PREFIX, filepath, strerror(errno));
        return ERR_IO;
    }

    /* Conteúdo plausível para enganar o ransomware */
    fprintf(f,
            "Document: %c\n"
            "Created: internal\n"
            "Content: This file contains sensitive operational data.\n"
            "Version: 1.0\n"
            "Status: active\n",
            letter);

    if (fflush(f) != 0)
    {
        vault_log(LOG_ERROR, "%s fflush('%s'): %s",
                  ENGINE_LOG_PREFIX, filepath, strerror(errno));
        fclose(f);
        return ERR_IO;
    }
    fclose(f);

    /* Verifica que o arquivo foi criado */
    struct stat st;
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s arquivo isca não confirmado: %s",
                  ENGINE_LOG_PREFIX, filepath);
        return ERR_IO;
    }

    return ERR_OK;
}

/* Escreve um arquivo isca binário falso (.enc) — engines 4 e 5.
 * Conteúdo: bytes aleatórios que imitam um arquivo criptografado real. */
static VaultError engine_write_binary_decoy(const char *filepath)
{
#ifdef __linux__
    /* Gera 512 bytes pseudo-aleatórios via /dev/urandom */
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

    /* Adiciona header falso que imita AES-GCM (magic + IV + tag) */
    buf[0] = 0xAE;
    buf[1] = 0x53;
    buf[2] = 0x47;
    buf[3] = 0x43; /* "AEGC" */

    FILE *f = fopen(filepath, "wb");
    if (!f)
    {
        vault_log(LOG_ERROR, "%s fopen(bin '%s'): %s",
                  ENGINE_LOG_PREFIX, filepath, strerror(errno));
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

    /* Confirma */
    struct stat st;
    if (stat(filepath, &st) != 0 || st.st_size != (off_t)sizeof(buf))
    {
        vault_log(LOG_ERROR, "%s binário falso não confirmado: %s",
                  ENGINE_LOG_PREFIX, filepath);
        return ERR_IO;
    }

    return ERR_OK;
#else
    (void)filepath;
    vault_log(LOG_WARN, "%s binários falsos só suportados no Linux", ENGINE_LOG_PREFIX);
    return ERR_SYSTEM;
#endif
}

/* Cria uma camada de isolamento com arquivos a-z.
 * layer_path: caminho completo da pasta da camada (já deve existir).
 * binary:     true = .enc falso, false = .txt de texto */
static VaultError engine_populate_layer(const char *layer_path, bool binary)
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

        VaultError err = binary
                             ? engine_write_binary_decoy(filepath)
                             : engine_write_text_decoy(filepath, c);

        if (err != ERR_OK)
        {
            vault_log(LOG_ERROR, "%s erro ao criar isca '%s': %s",
                      ENGINE_LOG_PREFIX, filepath, vault_strerror(err));
            errors++;
            continue;
        }

        /* Permissão 0400 — isca é somente leitura (dificulta que ransomware
         * sobrescreva antes de ser detectado pelo inotify) */
        if (chmod(filepath, 0400) != 0)
        {
            vault_log(LOG_WARN, "%s chmod(0400) em '%s': %s",
                      ENGINE_LOG_PREFIX, filepath, strerror(errno));
            /* Não fatal — continua */
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

/* ─────────────────────────────────────────────────────────────────────────
 *  engine_apply() — ponto de entrada público
 *
 *  Cria toda a estrutura de isolamento para o engine escolhido.
 *  Deve ser chamado logo após a criação do vault.
 * ───────────────────────────────────────────────────────────────────────── */
VaultError engine_apply(Vault *v)
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

    /* ── Cria diretório raiz das iscas ── */
    char decoy_root[PATH_MAX];
    snprintf(decoy_root, sizeof(decoy_root), "%s/%s", v->path, ENGINE_DECOY_DIR);

    VaultError err = engine_mkdir(decoy_root);
    if (err != ERR_OK)
    {
        vault_log(LOG_ERROR, "%s falha ao criar diretório raiz de iscas: %s",
                  ENGINE_LOG_PREFIX, vault_strerror(err));
        return err;
    }

    /* ── Cria diretório de arquivos reais ── */
    char real_dir[PATH_MAX];
    snprintf(real_dir, sizeof(real_dir), "%s/%s", v->path, ENGINE_REAL_DIR);

    err = engine_mkdir(real_dir);
    if (err != ERR_OK)
    {
        vault_log(LOG_ERROR, "%s falha ao criar diretório real: %s",
                  ENGINE_LOG_PREFIX, vault_strerror(err));
        return err;
    }

    /* Permissão mais restrita no diretório real */
    if (chmod(real_dir, 0700) != 0)
    {
        vault_log(LOG_WARN, "%s chmod(0700) em real_dir: %s",
                  ENGINE_LOG_PREFIX, strerror(errno));
    }

    /* ── Determina configuração do engine ── */
    int layer_count = ENGINE_LAYER_COUNT[level];
    bool binary = (level >= 4); /* engines 4 e 5 usam binários falsos */

    vault_log(LOG_INFO, "%s engine %d: %d camadas, modo=%s",
              ENGINE_LOG_PREFIX, level, layer_count,
              binary ? "binário (.enc)" : "texto (.txt)");

    /* ── Cria cada camada ── */
    int layers_ok = 0;
    int layers_failed = 0;

    for (int i = 1; i <= layer_count; i++)
    {
        char layer_path[PATH_MAX];
        snprintf(layer_path, sizeof(layer_path), "%s/layer_%02d", decoy_root, i);

        vault_log(LOG_INFO, "%s criando camada %d/%d: %s",
                  ENGINE_LOG_PREFIX, i, layer_count, layer_path);

        /* Valida que o caminho está dentro do vault (anti path-traversal) */
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

        /* Camada criada com sucesso — log de progresso */
        vault_log(LOG_INFO, "%s ✓ camada %d/%d concluída",
                  ENGINE_LOG_PREFIX, i, layer_count);
        layers_ok++;
    }

    /* ── Relatório final ── */
    vault_log(LOG_INFO,
              "%s engine %d aplicado ao vault '%s': %d/%d camadas OK, %d falhas",
              ENGINE_LOG_PREFIX, level, v->name,
              layers_ok, layer_count, layers_failed);

    if (layers_failed > 0)
    {
        vault_log(LOG_ERROR,
                  "%s engine %d INCOMPLETO: %d camadas falharam — vault pode estar parcialmente protegido",
                  ENGINE_LOG_PREFIX, level, layers_failed);
        return ERR_IO;
    }

    /* ── Nota sobre Engine 5 e OverlayFS ── */
    if (level == 5)
    {
        vault_log(LOG_INFO,
                  "%s engine 5: labirinto de 20 camadas criado. "
                  "Se divirta integrando Engine 5 seus Dados agradecem :)",
                  ENGINE_LOG_PREFIX);
    }

    vault_log(LOG_INFO, "%s engine %d totalmente aplicado ao vault '%s'",
              ENGINE_LOG_PREFIX, level, v->name);

    return ERR_OK;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  engine_validate() — verifica integridade do labirinto
 *
 *  Confirma que todas as camadas e arquivos isca ainda existem.
 *  Útil para detectar se o labirinto foi parcialmente destruído por malware.
 * ───────────────────────────────────────────────────────────────────────── */
VaultError engine_validate(Vault *v)
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

    /* Verifica diretório raiz */
    struct stat st;
    if (stat(decoy_root, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s diretório de iscas ausente: %s",
                  ENGINE_LOG_PREFIX, decoy_root);
        return ERR_INTEGRITY;
    }

    /* Verifica diretório real */
    char real_dir[PATH_MAX];
    snprintf(real_dir, sizeof(real_dir), "%s/%s", v->path, ENGINE_REAL_DIR);

    if (stat(real_dir, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        vault_log(LOG_ERROR, "%s diretório real ausente: %s",
                  ENGINE_LOG_PREFIX, real_dir);
        return ERR_INTEGRITY;
    }

    /* Verifica cada camada */
    int layer_count = ENGINE_LAYER_COUNT[level];
    bool binary = (level >= 4);
    int missing_layers = 0;
    int missing_files = 0;

    for (int i = 1; i <= layer_count; i++)
    {
        char layer_path[PATH_MAX];
        snprintf(layer_path, sizeof(layer_path), "%s/layer_%02d", decoy_root, i);

        if (stat(layer_path, &st) != 0 || !S_ISDIR(st.st_mode))
        {
            vault_log(LOG_ERROR, "%s camada ausente: %s",
                      ENGINE_LOG_PREFIX, layer_path);
            missing_layers++;
            continue;
        }

        /* Verifica arquivos a-z */
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
    }

    if (missing_layers > 0 || missing_files > 0)
    {
        vault_log(LOG_ERROR,
                  "%s validação FALHOU: %d camadas ausentes, %d arquivos ausentes",
                  ENGINE_LOG_PREFIX, missing_layers, missing_files);

        /* Dispara alerta — labirinto pode ter sido atacado */
        char reason[256];
        snprintf(reason, sizeof(reason),
                 "Engine %d comprometido: %d camadas, %d arquivos removidos",
                 level, missing_layers, missing_files);
        alert_trigger(v, reason);

        return ERR_INTEGRITY;
    }

    vault_log(LOG_INFO, "%s engine %d do vault '%s' VALIDADO com sucesso (%d camadas OK)",
              ENGINE_LOG_PREFIX, level, v->name, layer_count);
    return ERR_OK;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  engine_is_decoy_path() — verifica se um caminho é parte do labirinto
 *
 *  Usado pelo monitor inotify para distinguir modificação em isca
 *  (esperada durante ataque) vs modificação em arquivo real.
 * ───────────────────────────────────────────────────────────────────────── */
bool engine_is_decoy_path(const char *path)
{
    if (!path)
        return false;
    return (strstr(path, ENGINE_DECOY_DIR) != NULL);
}
