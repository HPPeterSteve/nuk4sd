//! preset.rs — Reescrita em Rust do preset.c
//!
//! Expõe `preflight_scan()` via FFI para o C (vault_cli.c) chamar
//! exatamente como antes: `void preflight_scan(CliConfig *cfg, const char *exec_path)`
//!
//! Vantagens sobre o preset.c:
//!   - Sem buffer overflow: Strings são `Vec<u8>` / `String` com crescimento dinâmico
//!   - Sem estático mutável não thread-safe: ldd_out era `static char[256KB]`
//!   - Sem strncpy truncado silencioso
//!   - run_cmd_with_timeout reimplementado com Command + thread + channel (sem fork manual)
//!   - realpath() aplicado em todos os paths antes de entrar no cfg->binds
//!   - which_in_path(): busca nativa em $PATH, sem depender de /usr/bin/which existir no host
//!
//! Para integrar:
//!   1. Adiciona este arquivo em src/preset.rs
//!   2. Em build.rs, remove a compilação de c_src/preset.c
//!   3. Declara o módulo em src/lib.rs ou src/main.rs:
//!        mod preset;
//!        pub use preset::preflight_scan;
//!
//! O C continua chamando via:
//!   extern void preflight_scan(CliConfig *cfg, const char *exec_path);

#![allow(non_snake_case, dead_code)]

use std::ffi::{CStr, CString};
use std::io::Read;
use std::os::raw::{c_char, c_int};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

// ─── Constantes espelhadas do preset.h ────────────────────────────────────────

const VAULT_PATH_MAX: usize = 4096;
const MAX_BINDS: usize = 64;
const RUN_TIMEOUT_MS: u64 = 3000;

// ─── Tipos espelhados do preset.h ─────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BindType {
    BindRo = 0,
    BindRw = 1,
    BindBlacklist = 2,
}

#[repr(C)]
pub struct BindEntry {
    pub path: [u8; VAULT_PATH_MAX],
    pub bind_type: BindType,
}

/// Espelho exato de CliConfig em preset.h.
/// IMPORTANTE: o layout em memória deve ser idêntico ao C — não reordene campos.
#[repr(C)]
pub struct CliConfig {
    pub vault_id: i32,

    // op_ booleans
    pub op_ls: bool, pub op_info: bool, pub op_files: bool,
    pub op_status: bool, pub op_scan: bool,
    pub op_encrypt: bool, pub op_decrypt: bool, pub op_resolve: bool,
    pub op_mount: bool, pub op_umount: bool, pub op_mount_export: bool,
    pub op_export: bool, pub op_rm: bool, pub op_unlock: bool,
    pub op_passwd: bool, pub op_rule: bool, pub op_worm_status: bool,
    pub op_help: bool, pub op_version: bool, pub op_rename: bool,

    pub export_file: *mut c_char,
    pub export_dest: *mut c_char,
    pub rename_to: *mut c_char,

    pub rule_max_fails: c_int,
    pub rule_hour_from: c_int,
    pub rule_hour_to: c_int,

    pub new_name: *mut c_char,
    pub new_path: *mut c_char,
    pub protected_vault: bool,
    pub engine_level: c_int,

    // WORM
    pub worm_set: u32,
    pub worm_clear: u32,
    pub worm_protected_scan: bool,

    // --run
    pub run_exec: *mut c_char,
    pub run_argv: *mut *mut c_char,
    pub run_argc: c_int,

    // iso flags
    pub iso_no_net: bool,
    pub iso_pivot_root: bool,
    pub iso_wayland: bool,
    pub iso_x11: bool,
    pub iso_ro_home: bool,
    pub iso_rw_home: bool,
    pub iso_no_dbus: bool,
    pub iso_tmp_home: bool,
    pub iso_audit: bool,
    pub iso_no_proc: bool,
    pub iso_new_session: bool,
    pub iso_unshare_ipc: bool,
    pub iso_unshare_uts: bool,
    pub iso_hostname: *mut c_char,
    pub iso_profile: *mut c_char,

    // desktop runtime
    pub iso_audio: bool,
    pub iso_dbus_session: bool,
    pub iso_dbus_system: bool,
    pub iso_gpu: bool,
    pub iso_xdg_runtime: bool,
    pub iso_dev_level: c_int,
    pub iso_no_seccomp: bool,
    pub iso_use_chroot: bool,
    pub iso_display: *mut c_char,
    pub iso_wayland_disp: *mut c_char,
    pub iso_preset: *mut c_char,
    pub seccomp_strict: bool,
    pub allow_clone3: bool,
    pub friendly_sandbox: bool,
    pub permissive_sandbox: bool,

    // resource limits
    pub iso_max_procs: c_int,
    pub iso_max_mem_gb: c_int,
    pub iso_max_fsize_mb: c_int,
    pub iso_max_fds: c_int,
    pub iso_tmp_size_mb: c_int,

    pub binds: [BindEntry; MAX_BINDS],
    pub bind_count: c_int,

    pub verbose: bool,
    pub debug: bool,
    pub json_output: bool,
    pub password: *mut c_char,
}


// ─── run_cmd_with_timeout ─────────────────────────────────────────────────────

fn run_cmd_with_timeout(program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let mut stdout = child.stdout.take()?;

    let (tx, rx) = mpsc::channel::<String>();

    thread::spawn(move || {
        let mut buf = String::with_capacity(256 * 1024);
        let _ = stdout.read_to_string(&mut buf);
        let _ = tx.send(buf);
    });

    match rx.recv_timeout(Duration::from_millis(RUN_TIMEOUT_MS)) {
        Ok(output) => {
            let _ = child.wait();
            Some(output)
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "[PREFLIGHT SCAN] ldd timeout ({}ms) — FUSE pode estar stale; pulando scan de libs",
                RUN_TIMEOUT_MS
            );
            None
        }
    }
}

// ─── which_in_path — busca nativa em $PATH ────────────────────────────────────
//
// Substitui o shell-out pra `/usr/bin/which`. Três motivos:
//   1. `/usr/bin/which` não existe em todo host (Alpine, imagens mínimas,
//      NixOS sem coreutils extra) — a versão anterior falhava mesmo quando
//      o binário procurado existia normalmente no $PATH.
//   2. Evita spawnar processo + thread + channel + timeout de 3s só pra
//      resolver um path — isso é uma lookup pura, resolve em microssegundos
//      lendo $PATH diretamente.
//   3. Retorna o PRIMEIRO caminho executável de verdade (checa o bit +x via
//      permissions().mode(), não só a existência do arquivo) — o `which`
//      do sistema às vezes aponta pra symlink quebrado ou arquivo sem
//      permissão de execução, e o execvp() subsequente rejeitaria mesmo assim.
fn which_in_path(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = Path::new(name);
        return if is_executable_file(p) { Some(p.to_path_buf()) } else { None };
    }

    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable_file(p: &Path) -> bool {
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

// ─── Análise de saída do ldd ──────────────────────────────────────────────────


#[derive(Debug, Default)]
pub struct RuntimeProfile {
    pub gui: bool,
    pub x11: bool,
    pub wayland: bool,
    pub gpu: bool,
    pub audio: bool,
    pub network: bool,
    pub dbus: bool,
    pub usb: bool,
    pub camera: bool,
    pub bluetooth: bool,
    pub printer: bool,
    pub fuse: bool,
    pub userns: bool,
    pub shared_memory: bool,
}


pub fn analyze_ldd(ldd_output: &str) -> RuntimeProfile {
    let mut p = RuntimeProfile::default();

    for line in ldd_output.lines() {
        let l = line.to_ascii_lowercase();

        if contains_any(&l, &[
            "libgtk",
            "libqt",
            "libgdk",
            "libfltk",
            "libwx",
            "libtk",
        ]) {
            p.gui = true;
        }

        // X11
        if contains_any(&l, &[
            "libx11",
            "libxcb",
            "libxrandr",
            "libxrender",
            "libxfixes",
            "libxext",
            "libxi",
            "libxcursor",
        ]) {
            p.x11 = true;
        }

        // Wayland
        if contains_any(&l, &[
            "libwayland",
            "libdecor",
        ]) {
            p.wayland = true;
        }

        // GPU
        if contains_any(&l, &[
            "libgl",
            "libegl",
            "libgles",
            "libvulkan",
            "libdrm",
            "libgbm",
        ]) {
            p.gpu = true;
        }

        // Audio
        if contains_any(&l, &[
            "libpulse",
            "libasound",
            "libpipewire",
            "libjack",
        ]) {
            p.audio = true;
        }

        // Rede
        if contains_any(&l, &[
            "libcurl",
            "libssl",
            "libcrypto",
            "libnss3",
            "libnspr4",
            "libssh",
            "libgio",
        ]) {
            p.network = true;
        }

        // DBus
        if contains_any(&l, &[
            "libdbus",
            "libsystemd",
        ]) {
            p.dbus = true;
        }

        // USB
        if l.contains("libusb") {
            p.usb = true;
        }

        // Webcam
        if contains_any(&l, &[
            "libcamera",
            "libv4l",
        ]) {
            p.camera = true;
        }

        // Bluetooth
        if l.contains("libbluetooth") {
            p.bluetooth = true;
        }

        // Impressão
        if l.contains("libcups") {
            p.printer = true;
        }

        // FUSE
        if l.contains("libfuse") {
            p.fuse = true;
        }

        // Shared Memory
        if contains_any(&l, &[
            "libshm",
            "libxshmfence",
        ]) {
            p.shared_memory = true;
        }
    }

    p
}

fn contains_any(line: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| line.contains(p))
}

// ─── Heurística por nome ──────────────────────────────────────────────────────

fn apply_heuristic_by_name(path: &str, p: &mut RuntimeProfile) {
    let known = ["firefox", "libreoffice", "chrome", "obs", "vlc", "gimp",
                 "qbittorrent", "transmission", "geany", "hypnotix"];
    if known.iter().any(|n| path.contains(n)) {
        p.gui = true;
        p.gpu = true;
        p.audio = true;
        p.network = true;
    }
}

// ─── realpath seguro ──────────────────────────────────────────────────────────

fn safe_realpath(p: &str) -> Option<PathBuf> {
    let path = Path::new(p);
    if let Ok(resolved) = path.canonicalize() {
        return Some(resolved);
    }
    if path.is_absolute() {
        Some(path.to_path_buf())
    } else {
        None
    }
}

// ─── Adiciona bind entry ao cfg (com realpath) ────────────────────────────────

unsafe fn cfg_add_bind(cfg: &mut CliConfig, path: &str, bind_type: BindType) {
    let count = cfg.bind_count as usize;
    if count >= MAX_BINDS {
        return;
    }

    let resolved = match safe_realpath(path) {
        Some(p) => p,
        None => {
            eprintln!(
                "  ✖ bind rejeitado: path relativo ou inválido '{}' (use path absoluto)",
                path
            );
            return;
        }
    };

    let resolved_str = resolved.to_string_lossy();
    let bytes = resolved_str.as_bytes();
    let copy_len = bytes.len().min(VAULT_PATH_MAX - 1);

    cfg.binds[count].path[..copy_len].copy_from_slice(&bytes[..copy_len]);
    cfg.binds[count].path[copy_len] = 0;
    cfg.binds[count].bind_type = bind_type;
    cfg.bind_count += 1;
}

// ─── FFI entry point ──────────────────────────────────────────────────────────

/// # Safety
/// `cfg` deve ser um ponteiro válido para CliConfig alocado pelo C.
/// `exec_path` deve ser uma string C válida terminada em '\0'.
#[no_mangle]
pub unsafe extern "C" fn preflight_scan(cfg: *mut CliConfig, exec_path: *const c_char) {
    if cfg.is_null() || exec_path.is_null() {
        return;
    }

    let cfg = &mut *cfg;

    let exec_str = match CStr::from_ptr(exec_path).to_str() {
        Ok(s) => s,
        Err(_) => return,
    };

    // ── Valida o executável com metadata() (equiv. a stat()) ──────────────
    if exec_str.starts_with('/') || exec_str.starts_with('.') {
        match std::fs::metadata(exec_str) {
            Ok(m) if m.is_file() => {}
            _ => {
                eprintln!(
                    "[PREFLIGHT SCAN] '{}' não encontrado ou não é binário — pulando",
                    exec_str
                );
                return;
            }
        }
    }

    // ── Resolve caminho absoluto (busca nativa em $PATH, sem shell-out) ───
    let full_exec_path: String = if exec_str.starts_with('/') || exec_str.starts_with('.') {
        exec_str.to_string()
    } else {
        match which_in_path(exec_str) {
            Some(p) => p.to_string_lossy().into_owned(),
            None => {
                eprintln!(
                    "[PREFLIGHT SCAN] não foi possível resolver '{}' no $PATH — pulando",
                    exec_str
                );
                return;
            }
        }
    };

    if full_exec_path.is_empty() {
        eprintln!("[PREFLIGHT SCAN] path vazio após resolução — pulando");
        return;
    }

    // ── Executa ldd com timeout ───────────────────────────────────────────
    let ldd_output = run_cmd_with_timeout("/usr/bin/ldd", &[&full_exec_path])
        .unwrap_or_default();

    // ── Analisa dependências ──────────────────────────────────────────────
    let mut deps = analyze_ldd(&ldd_output);

    if !deps.gui {
        apply_heuristic_by_name(&full_exec_path, &mut deps);
    }

    // ── Relatório ─────────────────────────────────────────────────────────
    eprintln!("[PREFLIGHT SCAN] Analisando '{}'...", full_exec_path);

    let has_preset = !cfg.iso_preset.is_null();

    if deps.gui && !has_preset {
        eprintln!("  ✓ Detectado GTK/Qt/GUI (configurando X11, Wayland, ícones)");
        if !cfg.iso_wayland && !cfg.iso_x11 {
            cfg.iso_wayland = true;
            cfg.iso_x11     = true;
        }
        cfg.iso_dbus_session = true;
        cfg.iso_dev_level    = 2;
    }

    if deps.gpu && !has_preset {
        eprintln!("  ✓ Detectado uso de GPU (montando /dev/dri)");
        cfg.iso_gpu = true;
    } else if !deps.gpu && cfg.verbose {
        eprintln!("  ⚠ GPU não detectada");
    }

    if deps.audio && !has_preset {
        eprintln!("  ✓ Detectado Áudio (montando PulseAudio/PipeWire)");
        cfg.iso_audio = true;
    }

    if deps.network && cfg.iso_no_net && !has_preset {
        eprintln!("  ⚠ Atenção: Binário usa rede, mas iso_no_net está ativo.");
    }

    // ── Empréstimo automático de binário externo ──────────────────────────
    let is_system_path = full_exec_path.starts_with("/usr/")
        || full_exec_path.starts_with("/bin/")
        || full_exec_path.starts_with("/lib")
        || full_exec_path.starts_with("/sbin/")
        || full_exec_path.starts_with("/usr/bin/")
        || full_exec_path.starts_with("/usr/lib/")
        || full_exec_path.starts_with("/usr/sbin/")
        || full_exec_path.starts_with("/usr/local/")
        || full_exec_path.starts_with("/usr/local/bin/")
        || full_exec_path.starts_with("/usr/local/lib/")
        || full_exec_path.starts_with("/usr/local/sbin/");

    if !is_system_path {
        eprintln!("  ✓ Empréstimo de binário externo ativado: {}", full_exec_path);
        cfg_add_bind(cfg, &full_exec_path, BindType::BindRo);
    }

    eprintln!("[LANCANDO SANDBOX...]");
}

// ─── Testes ───────────────────────────────────────────────────────────────────

