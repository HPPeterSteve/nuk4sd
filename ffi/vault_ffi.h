/*
 * vault_ffi.h
 *
 * Funções exportadas por vault_security.c para serem chamadas via FFI pelo Rust.
 * Inclua este header no vault_security.c ou compile junto.
 *
 * Todas as funções são prefixadas com vault_*_ffi para evitar colisão
 * com os símbolos estáticos internos do .c.
 *
 * ABI: C, sem name mangling.
 *      Strings são const char* (UTF-8, NUL-terminated).
 *      Retorno int = VaultError (0 = ERR_OK, negativo = erro).
 */

#ifndef VAULT_FFI_H
#define VAULT_FFI_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

    /* ── Vault lifecycle ──────────────────────────────────────────────────── */

    /**
     * Cria um cofre no catálogo.
     * @param name       Nome do cofre (NULL = auto-incremento diamond_vault_N)
     * @param vault_type 0 = NORMAL, 1 = PROTECTED
     * @param path       Caminho absoluto (NULL = padrão em /var/lib/vault_security)
     * @param password   Senha (obrigatória se vault_type == 1, NULL caso contrário)
     * @return VaultError (0 = OK)
     */
    int vault_create_ffi(
        const char *name,
        int vault_type,
        const char *path,
        const char *password);

    /**
     * Deleta um cofre pelo ID numérico.
     * @param id       ID do cofre
     * @param password Senha (obrigatória para cofres PROTECTED, NULL para NORMAL)
     * @return VaultError
     */
    int vault_delete_ffi(uint32_t id, const char *password);

    /**
     * Renomeia um cofre.
     * @param id       ID do cofre
     * @param new_name Novo nome (validado: alfanumérico + _ + -)
     * @param password Senha (obrigatória para PROTECTED)
     * @return VaultError
     */
    int vault_rename_ffi(uint32_t id, const char *new_name, const char *password);

    /**
     * Desbloqueia cofre após lockout por tentativas falhas.
     * @param id       ID do cofre
     * @param password Senha correta
     * @return VaultError
     */
    int vault_unlock_ffi(uint32_t id, const char *password);

    /**
     * Troca a senha de um cofre protegido.
     * @param id       ID do cofre
     * @param old_pass Senha atual
     * @param new_pass Nova senha (mín. 8 chars)
     * @return VaultError
     */
    int vault_change_password_ffi(uint32_t id, const char *old_pass, const char *new_pass);

    /* ── Criptografia ─────────────────────────────────────────────────────── */

    /**
     * Criptografa todos os arquivos do cofre com AES-256-CBC.
     * Arquivos já com extensão .enc são ignorados.
     * @param id       ID do cofre
     * @param password Senha para derivação de chave (PBKDF2)
     * @return VaultError
     */
    int vault_encrypt_ffi(uint32_t id, const char *password);

    /**
     * Descriptografa arquivos .enc do cofre.
     * @param id       ID do cofre
     * @param password Senha para derivação de chave
     * @return VaultError
     */
    int vault_decrypt_ffi(uint32_t id, const char *password);

    /* ── Integridade / monitor ────────────────────────────────────────────── */

    /**
     * Força varredura SHA-256 em todos os arquivos do cofre.
     * Registra modificações e dispara alertas conforme necessário.
     * @param id ID do cofre
     * @return VaultError
     */
    int vault_scan_ffi(uint32_t id);

    /**
     * Resolve alerta ativo de um cofre (limpa flags de modificação).
     * @param id       ID do cofre
     * @param password Senha (obrigatória para PROTECTED, NULL para NORMAL)
     * @return VaultError
     */
    int vault_resolve_ffi(uint32_t id, const char *password);

    /* ── Display (imprime no stdout do processo C) ────────────────────────── */

    /** Exibe informações detalhadas de um cofre. */
    void vault_info_ffi(uint32_t id);

    /** Lista todos os cofres do catálogo em formato tabular. */
    void vault_list_ffi(void);

    /** Lista arquivos rastreados e seus hashes em um cofre. */
    void vault_files_ffi(uint32_t id);

    /* ── Sandbox ──────────────────────────────────────────────────────────── */

    /**
     * Abre cofre em shell sandbox (fork + chdir + chroot se root).
     * Bloqueia até o shell filho terminar.
     * @param id       ID do cofre
     * @param password Senha (obrigatória para PROTECTED)
     * @return VaultError
     */
    int vault_sandbox_ffi(uint32_t id, const char *password);

    /* ── Rule engine ──────────────────────────────────────────────────────── */

    /**
     * Adiciona regra de segurança a um cofre.
     * @param vault_id  ID do cofre alvo
     * @param max_fails Máximo de tentativas falhas antes de bloquear (-1 = desativado)
     * @param hour_from Início da janela de acesso permitida 0-23 (-1 = sem restrição)
     * @param hour_to   Fim da janela de acesso 0-23 (-1 = sem restrição)
     * @return 0 (OK) ou -14 (tabela cheia)
     */
    int vault_rule_ffi(uint32_t vault_id, int max_fails, int hour_from, int hour_to);

    /* ── Status ───────────────────────────────────────────────────────────── */

    /**
     * Retorna o status numérico de um cofre.
     * @return 0=OK, 1=LOCKED, 2=ALERT, 3=DELETED, -8=não encontrado
     */
    int vault_get_status_ffi(uint32_t id);

#ifdef __cplusplus
}
#endif

#endif /* VAULT_FFI_H */