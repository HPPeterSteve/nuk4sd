/*
 * main.rs
 *
 * Nuk4sd — minimal entry point
 *
 * Delegates all flag parsing and execution to the C core (vault_cli.c).
 * Rust is responsible only for:
 *   1. Initializing the C core (vault_ffi_init)
 *   2. Passing argc/argv to vault_cli_parse_and_exec
 *   3. Calling vault_ffi_shutdown on exit
 *   4. Exposing C->Rust callbacks (rust_vault_copy_file, etc.)
 *
 * Interactive mode (no arguments): opens REPL via repl.rs
 */

mod crypto;
mod ffi;
mod log;
mod manual;
mod path_assistant;
mod preset;
mod repl;
mod sys_info;
pub mod oci;
pub mod vault_ops;

use std::ffi::CString;
use std::os::raw::{c_char, c_int};

/* ─────────────────────────────────────────────────────────────────────────
 *  FFI — C core entry point
 * ───────────────────────────────────────────────────────────────────────── */
extern "C" {
    fn vault_ffi_init() -> c_int;
    fn vault_ffi_shutdown() -> c_int;
    fn vault_cli_parse_and_exec(argc: c_int, argv: *const *const c_char) -> c_int;
}


fn main() {
    let args: Vec<String> = std::env::args().collect();
    let is_cli = args.len() > 1;

    // [PORTABLE CONTAINER MODE]
    // If executable is running alongside a .vault_container_meta file, it bypasses
    // standard initialization (REPL/CLI) and enters isolated Sandbox/Container mode directly.
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let meta_path = exe_dir.join(".vault_container_meta");
            if meta_path.exists() {
                println!("[Nuk4sd] Vault-Container mode detected (auto-exec). Reading {}...", meta_path.display());
                // Future: read JSON/struct here and call ffi::run_sandbox
                println!("[Nuk4sd] TODO: Start container via ffi::run_sandbox using package metadata.");
                std::process::exit(0);
            }
        }
    }

    /* --help and --version must never touch catalog.dat.
     * Detect them early and delegate directly to the CLI without init. */
    let is_info_only = args.len() == 2 &&
        (args[1] == "--help" || args[1] == "-h" || args[1] == "--version");

    /* Initialize C core (loads catalog, starts monitor thread, etc.)
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
        /* ── CLI Mode: pass argv directly to C core ───────────────────── */
        let c_args: Vec<CString> = args
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap_or_default())
            .collect();

        let c_ptrs: Vec<*const c_char> = c_args.iter().map(|s| s.as_ptr()).collect();

        unsafe {
            vault_cli_parse_and_exec(c_ptrs.len() as c_int, c_ptrs.as_ptr())
        }
    } else {
        /* ── Interactive Mode: REPL ───────────────────────────────────── */
        repl::run();
        0
    };

    if !is_info_only {
        unsafe { vault_ffi_shutdown(); }
    }
    std::process::exit(exit_code);
}
