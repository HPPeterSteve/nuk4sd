/*
 * common.c
 *
 * Nuk4sd — Hardened Sandbox — estado compartilhado entre todos os módulos
 * Extraído de vault_sandbox.c (split modular, estilo Firejail).
 */

#include "sandbox.h"

#ifdef __linux__

bool g_sandbox_debug = false;

void vsb_set_debug(bool debug) {
    g_sandbox_debug = debug;
}

#endif /* __linux__ */
