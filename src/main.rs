/*
 * main.rs
 *
 * Nuk4sd — entry point minimalista
 *
 * Delega todo o parsing de flags e execução ao core C (vault_cli.c).
 * O Rust é responsável apenas por:
 *   1. Inicializar o core C (vault_ffi_init)
 *   2. Passar argc/argv para vault_cli_parse_and_exec
 *   3. Chamar vault_ffi_shutdown na saída
 *   4. Expor callbacks C→Rust (rust_vault_copy_file, etc.)
 *
 * Modo interativo (sem argumentos): abre o REPL via repl.rs
 */

mod crypto;
mod log;
mod manual;
mod path_assistant;
mod repl;
mod sys_info;
mod vault;

use std::ffi::CString;
use std::os::raw::{c_char, c_int};

/* ─────────────────────────────────────────────────────────────────────────
 *  FFI — entry point do core C
 * ───────────────────────────────────────────────────────────────────────── */
extern "C" {
    fn vault_ffi_init() -> c_int;
    fn vault_ffi_shutdown() -> c_int;
    fn vault_cli_parse_and_exec(argc: c_int, argv: *const *const c_char) -> c_int;
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let is_cli = args.len() > 1;

    /* --help and --version must never touch catalog.dat.
     * Detect them early and delegate directly to the CLI without init. */
    let is_info_only = args.len() == 2 &&
        (args[1] == "--help" || args[1] == "-h" || args[1] == "--version");

    /* Inicializa core C (loads catalog, starts monitor thread, etc.)
     * Skipped for pure read-only informational flags. */
    if !is_info_only {
        let init_result = unsafe { vault_ffi_init() };
        if init_result != 0 {
            eprintln!(
                "\x1b[33m⚠ C core init failed ({}), continuing without persistence.\x1b[0m",
                init_result
            );
        }
    }

    /* Ctrl+C graceful shutdown */
    ctrlc::set_handler(|| {
        unsafe { vault_ffi_shutdown(); }
        std::process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");

    let exit_code = if is_cli {
        /* ── Modo CLI: passa argv direto ao core C ───────────────────── */
        let c_args: Vec<CString> = args
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap_or_default())
            .collect();

        let c_ptrs: Vec<*const c_char> = c_args.iter().map(|s| s.as_ptr()).collect();

        unsafe {
            vault_cli_parse_and_exec(c_ptrs.len() as c_int, c_ptrs.as_ptr())
        }
    } else {
        /* ── Modo interativo: REPL ───────────────────────────────────── */
        repl::run();
        0
    };

    if !is_info_only {
        unsafe { vault_ffi_shutdown(); }
    }
    std::process::exit(exit_code);
}
