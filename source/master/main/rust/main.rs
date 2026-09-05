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
mod daemon;
mod ffi;
mod log;
mod manual;
#[cfg(target_os = "linux")]
pub mod oci;
mod path_assistant;
mod repl;
mod sys_info;

use std::ffi::CString;
use std::os::raw::{c_char, c_int};

/* ─────────────────────────────────────────────────────────────────────────
 *  FFI — entry point do core C
 * ───────────── */
extern "C" {
    fn vault_ffi_init() -> c_int;
    fn vault_ffi_shutdown() -> c_int;
    fn vault_cli_parse_and_exec(argc: c_int, argv: *const *const c_char) -> c_int;
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let is_cli = args.len() > 1;

    // Daemon local: inicia apenas com a flag explícita e usa caminhos derivados
    // de XDG_RUNTIME_DIR. Nenhum caminho, comando ou argv é aceito do cliente.
    if args.get(1).map(String::as_str) == Some("--daemon") {
        #[cfg(target_os = "linux")]
        {
            let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from(format!("/tmp/nuk4sd-{}", unsafe { libc::geteuid() })));
            let nuk4sd_dir = runtime_dir.join("nuk4sd");
            let socket = nuk4sd_dir.join("daemon.sock");
            let pid = nuk4sd_dir.join("daemon.pid");
            if let Err(error) = ffi::init() {
                eprintln!("[Nuk4sd daemon] core_init: {}", error.message());
                std::process::exit(1);
            }
            let result = daemon::run(socket, pid, nuk4sd_dir);
            if let Err(error) = ffi::shutdown() {
                eprintln!("[Nuk4sd daemon] core_shutdown: {}", error.message());
            }
            if let Err(error) = result {
                eprintln!("[Nuk4sd daemon] {error}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("[Nuk4sd daemon] unsupported_platform");
            std::process::exit(1);
        }
    }

    // [MODO PORTABLE CONTAINER]
    // Se o executável estiver rodando ao lado de um .vault_container_meta, ele ignora
    // a inicialização padrão (REPL/CLI) e entra direto no modo Sandbox/Container isolado.
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let meta_path = exe_dir.join(".vault_container_meta");
            if meta_path.exists() {
                println!(
                    "[Nuk4sd] Detectado modo Vault-Container (auto-execução). Lendo {}...",
                    meta_path.display()
                );
                // No futuro ler o JSON/struct aqui e chamar ffi::run_sandbox
                println!("[Nuk4sd] TODO: Iniciar container via ffi::run_sandbox usando os metadados do pacote.");
                std::process::exit(0);
            }
        }
    }

    /* --help and --version must never touch catalog.dat.
     * Detect them early and delegate directly to the CLI without init. */
    let is_info_only = args.len() == 2 && (args[1] == "--help" || args[1] == "-h" || args[1] == "--version");

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
        unsafe {
            vault_ffi_shutdown();
        }
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

        unsafe { vault_cli_parse_and_exec(c_ptrs.len() as c_int, c_ptrs.as_ptr()) }
    } else {
        /* ── Modo interativo: REPL ───────────────────────────────────── */
        repl::run();
        0
    };

    if !is_info_only {
        unsafe {
            vault_ffi_shutdown();
        }
    }
    std::process::exit(exit_code);
}
