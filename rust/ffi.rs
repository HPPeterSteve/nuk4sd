/*
 * ffi.rs
 *
 * Safe Rust bindings for vault_ffi.c and vault_cli.c (core C).
 * All calls execute directly in memory via static linking.
 */

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

pub const VAULT_PATH_MAX: usize = 512;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VaultIdPathRaw {
    pub id: u32,
    pub path: [c_char; VAULT_PATH_MAX],
}

impl Default for VaultIdPathRaw {
    fn default() -> Self {
        VaultIdPathRaw {
            id: 0,
            path: [0; VAULT_PATH_MAX],
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultEntry {
    pub id: u32,
    pub path: String,
    pub status: VaultStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultStatus {
    Ok,
    Locked,
    Alert,
    Deleted,
    Unknown(i32),
}

impl VaultStatus {
    pub fn from_raw(v: c_int) -> Self {
        match v {
            0 => VaultStatus::Ok,
            1 => VaultStatus::Locked,
            2 => VaultStatus::Alert,
            3 => VaultStatus::Deleted,
            other => VaultStatus::Unknown(other),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            VaultStatus::Ok => "Mounted / Active",
            VaultStatus::Locked => "Unmounted / Locked",
            VaultStatus::Alert => "Integrity Alert",
            VaultStatus::Deleted => "Removed",
            VaultStatus::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    Ok,
    InvalidArgs,
    NoMemory,
    Io,
    Crypto,
    AuthFail,
    VaultLocked,
    VaultExists,
    VaultNotFound,
    PermDenied,
    CatalogFull,
    PathInvalid,
    PassRequired,
    Integrity,
    System,
    SystemUnshareFailed,
    SystemMountFailed,
    SystemPivotRootFailed,
    SystemCloneFailed,
    Unknown(i32),
}

impl VaultError {
    pub fn from_raw(v: c_int) -> Self {
        match v {
            0 => VaultError::Ok,
            -1 => VaultError::InvalidArgs,
            -2 => VaultError::NoMemory,
            -3 => VaultError::Io,
            -4 => VaultError::Crypto,
            -5 => VaultError::AuthFail,
            -6 => VaultError::VaultLocked,
            -7 => VaultError::VaultExists,
            -8 => VaultError::VaultNotFound,
            -9 => VaultError::PermDenied,
            -10 => VaultError::CatalogFull,
            -11 => VaultError::PathInvalid,
            -12 => VaultError::PassRequired,
            -13 => VaultError::Integrity,
            -14 => VaultError::System,
            -15 => VaultError::SystemUnshareFailed,
            -16 => VaultError::SystemMountFailed,
            -17 => VaultError::SystemPivotRootFailed,
            -18 => VaultError::SystemCloneFailed,
            other => VaultError::Unknown(other),
        }
    }

    pub fn message(&self) -> String {
        match self {
            VaultError::Ok => "Operation completed successfully".into(),
            VaultError::InvalidArgs => "Invalid arguments".into(),
            VaultError::NoMemory => "Insufficient memory".into(),
            VaultError::Io => "Input/output error (I/O)".into(),
            VaultError::Crypto => "Cryptography error (OpenSSL/Argon2)".into(),
            VaultError::AuthFail => "Incorrect password or authentication failure".into(),
            VaultError::VaultLocked => "The vault is locked".into(),
            VaultError::VaultExists => "The specified vault already exists".into(),
            VaultError::VaultNotFound => "Vault not found".into(),
            VaultError::PermDenied => "Permission denied".into(),
            VaultError::CatalogFull => "Vault catalog full".into(),
            VaultError::PathInvalid => "Invalid file path".into(),
            VaultError::PassRequired => "Password is required".into(),
            VaultError::Integrity => "Integrity verification failure".into(),
            VaultError::System => "Operating system subsystem error".into(),
            VaultError::SystemUnshareFailed => "[KERNEL] Syscall unshare() failed to isolate namespaces".into(),
            VaultError::SystemMountFailed => "[KERNEL] Syscall mount() failed (possible EPERM/EINVAL)".into(),
            VaultError::SystemPivotRootFailed => "[KERNEL] Syscall pivot_root() failed to swap root".into(),
            VaultError::SystemCloneFailed => "[KERNEL] Syscall clone() failed to start subprocess".into(),
            VaultError::Unknown(code) => format!("Unknown error ({code})"),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VaultContainerRaw {
    pub id: u32,
    pub path: [c_char; VAULT_PATH_MAX],
    pub image_tarball: [c_char; VAULT_PATH_MAX],
    pub entrypoint: [c_char; 512],
    pub sealed: c_int,
    pub require_network: c_int,
    pub require_gui: c_int,
}

pub type VResult = Result<(), VaultError>;

fn check(raw: c_int) -> VResult {
    let e = VaultError::from_raw(raw);
    if e == VaultError::Ok {
        Ok(())
    } else {
        Err(e)
    }
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

extern "C" {
    fn vault_ffi_init() -> c_int;
    fn vault_ffi_shutdown() -> c_int;

    fn vault_create_ffi(
        name: *const c_char,
        vault_type: c_int,
        path: *const c_char,
        password: *const c_char,
    ) -> c_int;
    fn vault_delete_ffi(id: u32, password: *const c_char) -> c_int;

    fn vault_mount_ffi(id: u32, password: *const c_char) -> c_int;
    fn vault_unmount_ffi(id: u32) -> c_int;

    fn vault_encrypt_ffi(id: u32, password: *const c_char) -> c_int;
    fn vault_decrypt_ffi(id: u32, password: *const c_char) -> c_int;

    fn vault_get_status_ffi(id: u32) -> c_int;

    fn vault_sandbox_ffi(
        id: u32,
        password: *const c_char,
        gui_mode: c_int,
        app_cmd: *const c_char,
    ) -> c_int;

    fn vault_list_ids_ffi(out: *mut VaultIdPathRaw, out_cap: u32, out_count: *mut u32) -> c_int;
    fn vault_count_ffi() -> u32;

    fn vault_cli_parse_and_exec(argc: c_int, argv: *const *const c_char) -> c_int;

    /// Launches the sandbox with CliConfig populated directly by typed parameters —
    /// no command line string, no join/split, no getopt. See vault_cli.c for rationale
    /// (path with space bug workaround).
    fn vault_sandbox_run_ffi(
        vault_id: u32,
        password: *const c_char,
        exec_path: *const c_char,
        no_net: bool,
        wayland: bool,
        x11: bool,
        audio: bool,
        ro_home: bool,
        no_fuse: bool,
        seccomp_strict: bool,
        use_chroot: bool,

        ro_paths: *const *const c_char,
        ro_count: u32,
        rw_paths: *const *const c_char,
        rw_count: u32,
        blacklist_paths: *const *const c_char,
        blacklist_count: u32,
    ) -> c_int;

    /* ── OCI / Container ─────────────────────────────────── */
    /// Notify C side that OCI image has been pulled and extracted.
    /// C calls this back after vault_cli dispatches --image.
    fn vault_oci_image_ready_ffi(
        vault_id: u32,
        lowerdir: *const c_char,
    ) -> c_int;
}

/* ── no_mangle FFI callbacks — invoked by vault_cli.c via function pointer ─── */

/// Called from C when --image is parsed and the user wants to pull a rootfs image.
/// Resolves short names (alpine, ubuntu, kali) to GitHub release URLs.
#[cfg(target_os = "linux")]
#[no_mangle]
pub extern "C" fn rust_oci_pull_image(
    url_or_alias: *const c_char,
    target_dir: *const c_char,
) -> c_int {
    use crate::oci::pull_and_extract_image;
    use std::path::Path;

    let url_raw = unsafe { CStr::from_ptr(url_or_alias) }.to_string_lossy();
    let dir_raw = unsafe { CStr::from_ptr(target_dir) }.to_string_lossy();

    /* Check for bundled or local SquashFS runtime first before downloading */
    if url_raw == "ubuntu" || url_raw == "ubuntu-noble" || url_raw == "default" {
        let candidates = [
            std::env::var("NUK4SD_RUNTIME_PATH").unwrap_or_default(),
            "/usr/share/nuk4sd/runtime/ubuntu24_04.squashfs".to_string(),
            "./runtime/ubuntu24_04.squashfs".to_string(),
        ];
        for cand in &candidates {
            if !cand.is_empty() && Path::new(cand).exists() {
                println!("[Nuk4sd] Using bundled SquashFS runtime: {}", cand);
                return match pull_and_extract_image(cand, target) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("[OCI] extract squashfs failed: {}", e);
                        -1
                    }
                };
            }
        }
    }

    /* Resolve aliases → GitHub release download URLs */
    let url = match url_raw.as_ref() {
        "alpine" | "alpine-latest" =>
            "https://github.com/alpinelinux/alpine-minirootfs/releases/download/v3.20.0/alpine-minirootfs-3.20.0-x86_64.tar.gz",
        "ubuntu" | "ubuntu-noble" =>
            "https://github.com/ubuntu-lts/ubuntu-rootfs/releases/latest/download/ubuntu-noble-amd64-rootfs.tar.gz",
        "debian" | "debian-stable" =>
            "https://github.com/debuerreotype/docker-debian-artifacts/raw/dist-amd64/stable/rootfs.tar.xz",
        "kali" | "kali-latest" =>
            "https://kali.download/base-images/current/kali-linux-latest-amd64-netinst.iso",
        other => other, /* raw URL passthrough */
    };

    let target = Path::new(dir_raw.as_ref());
    match pull_and_extract_image(url, target) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[OCI] pull_and_extract_image failed: {}", e);
            -1
        }
    }
}

/// Called from C when a child PID needs cgroup limits applied.
#[cfg(target_os = "linux")]
#[no_mangle]
pub extern "C" fn rust_cgroup_apply(
    cgroup_name: *const c_char,
    pid: u64,
    memory_limit_mb: i64,
    cpu_shares: u64,
    cpu_quota_us: i64,
    max_procs: i64,
) -> c_int {
    use crate::oci::apply_cgroup_limits;

    if cgroup_name.is_null() {
        return -1;
    }
    let name = unsafe { CStr::from_ptr(cgroup_name) }.to_string_lossy();
    match apply_cgroup_limits(&name, pid, memory_limit_mb, cpu_shares, cpu_quota_us, max_procs) {
        Ok(_cg) => 0,
        Err(e) => {
            eprintln!("[CGROUP] apply failed: {}", e);
            -1
        }
    }
}

/// Called from C when child terminates to remove the cgroup.
#[cfg(target_os = "linux")]
#[no_mangle]
pub extern "C" fn rust_cgroup_cleanup(
    cgroup_name: *const c_char,
) -> c_int {
    use crate::oci::remove_cgroup;

    if cgroup_name.is_null() {
        return 0;
    }
    let name = unsafe { CStr::from_ptr(cgroup_name) }.to_string_lossy();
    if let Err(e) = remove_cgroup(&name) {
        eprintln!("[CGROUP] cleanup warning: {}", e);
        return -1;
    }
    0
}

/// Stub for non-Linux targets to keep the build clean on Windows.
#[cfg(not(target_os = "linux"))]
#[no_mangle]
pub extern "C" fn rust_oci_pull_image(
    _url_or_alias: *const c_char,
    _target_dir: *const c_char,
) -> c_int { -1 }

#[cfg(not(target_os = "linux"))]
#[no_mangle]
pub extern "C" fn rust_cgroup_apply(
    _cgroup_name: *const c_char,
    _pid: u64,
    _memory_limit_mb: i64,
    _cpu_shares: u64,
    _cpu_quota_us: i64,
    _max_procs: i64,
) -> c_int { -1 }

#[cfg(not(target_os = "linux"))]
#[no_mangle]
pub extern "C" fn rust_cgroup_cleanup(
    _cgroup_name: *const c_char,
) -> c_int { 0 }

// ─── Vault Operations FFI (Rust -> C) ────────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_vault_add(
    vault_path: *const c_char,
    src_file: *const c_char,
    recursive: bool,
    replace: bool,
    preserve: bool,
) -> c_int {
    if vault_path.is_null() || src_file.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let src = unsafe { CStr::from_ptr(src_file) }.to_string_lossy();
    match crate::vault_ops::vault_add(&vp, &src, recursive, replace, preserve) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-ADD] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_extract(
    vault_path: *const c_char,
    rel_file: *const c_char,
    dest_dir: *const c_char,
    force: bool,
) -> c_int {
    if vault_path.is_null() || rel_file.is_null() || dest_dir.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let src = unsafe { CStr::from_ptr(rel_file) }.to_string_lossy();
    let dst = unsafe { CStr::from_ptr(dest_dir) }.to_string_lossy();
    match crate::vault_ops::vault_extract(&vp, &src, &dst, force) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-EXTRACT] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_mv(
    vault_path: *const c_char,
    src_rel: *const c_char,
    dst_rel: *const c_char,
) -> c_int {
    if vault_path.is_null() || src_rel.is_null() || dst_rel.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let src = unsafe { CStr::from_ptr(src_rel) }.to_string_lossy();
    let dst = unsafe { CStr::from_ptr(dst_rel) }.to_string_lossy();
    match crate::vault_ops::vault_mv(&vp, &src, &dst) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-MV] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_cp(
    vault_path: *const c_char,
    src_rel: *const c_char,
    dst_rel: *const c_char,
) -> c_int {
    if vault_path.is_null() || src_rel.is_null() || dst_rel.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let src = unsafe { CStr::from_ptr(src_rel) }.to_string_lossy();
    let dst = unsafe { CStr::from_ptr(dst_rel) }.to_string_lossy();
    match crate::vault_ops::vault_cp(&vp, &src, &dst) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-CP] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_rm_file(
    vault_path: *const c_char,
    target_rel: *const c_char,
) -> c_int {
    if vault_path.is_null() || target_rel.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let target = unsafe { CStr::from_ptr(target_rel) }.to_string_lossy();
    match crate::vault_ops::vault_rm_file(&vp, &target) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-RM] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_mkdir(
    vault_path: *const c_char,
    dir_rel: *const c_char,
) -> c_int {
    if vault_path.is_null() || dir_rel.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let dir = unsafe { CStr::from_ptr(dir_rel) }.to_string_lossy();
    match crate::vault_ops::vault_mkdir(&vp, &dir) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-MKDIR] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_rmdir(
    vault_path: *const c_char,
    dir_rel: *const c_char,
) -> c_int {
    if vault_path.is_null() || dir_rel.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let dir = unsafe { CStr::from_ptr(dir_rel) }.to_string_lossy();
    match crate::vault_ops::vault_rmdir(&vp, &dir) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-RMDIR] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_tree(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_tree(&vp) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-TREE] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_du(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_du(&vp) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-DU] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_find(
    vault_path: *const c_char,
    pattern: *const c_char,
) -> c_int {
    if vault_path.is_null() || pattern.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let pat = unsafe { CStr::from_ptr(pattern) }.to_string_lossy();
    match crate::vault_ops::vault_find(&vp, &pat) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-FIND] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_snapshot(
    vault_path: *const c_char,
    tag: *const c_char,
) -> c_int {
    if vault_path.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let tag_opt = if tag.is_null() {
        None
    } else {
        let s = unsafe { CStr::from_ptr(tag) }.to_string_lossy();
        if s.trim().is_empty() { None } else { Some(s) }
    };
    match crate::vault_ops::vault_snapshot_create(&vp, tag_opt.as_deref()) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-SNAPSHOT] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_snapshots(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_snapshot_list(&vp) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-SNAPSHOTS] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_snapshot_delete(
    vault_path: *const c_char,
    tag: *const c_char,
) -> c_int {
    if vault_path.is_null() || tag.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let t = unsafe { CStr::from_ptr(tag) }.to_string_lossy();
    match crate::vault_ops::vault_snapshot_delete(&vp, &t) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-SNAPSHOT-DELETE] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_snapshot_restore(
    vault_path: *const c_char,
    tag: *const c_char,
) -> c_int {
    if vault_path.is_null() || tag.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let t = unsafe { CStr::from_ptr(tag) }.to_string_lossy();
    match crate::vault_ops::vault_snapshot_restore(&vp, &t) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-SNAPSHOT-RESTORE] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_snapshot_diff(
    vault_path: *const c_char,
    tag1: *const c_char,
    tag2: *const c_char,
) -> c_int {
    if vault_path.is_null() || tag1.is_null() {
        return -1;
    }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let t1 = unsafe { CStr::from_ptr(tag1) }.to_string_lossy();
    let t2_opt = if tag2.is_null() {
        None
    } else {
        let s = unsafe { CStr::from_ptr(tag2) }.to_string_lossy();
        if s.trim().is_empty() { None } else { Some(s) }
    };
    match crate::vault_ops::vault_snapshot_diff(&vp, &t1, t2_opt.as_deref()) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✖ [VAULT-SNAPSHOT-DIFF] {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_hash(
    vault_path: *const c_char,
    target_rel: *const c_char,
) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let rel_opt = if target_rel.is_null() {
        None
    } else {
        let s = unsafe { CStr::from_ptr(target_rel) }.to_string_lossy();
        if s.trim().is_empty() { None } else { Some(s) }
    };
    match crate::vault_ops::vault_hash(&vp, rel_opt.as_deref()) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-HASH] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_baseline(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_baseline(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-BASELINE] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_verify(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_verify(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-VERIFY] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_integrity(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_integrity(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-INTEGRITY] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_repair(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_repair(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-REPAIR] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_diff(vault_path: *const c_char, other: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let other_opt = if other.is_null() {
        None
    } else {
        let s = unsafe { CStr::from_ptr(other) }.to_string_lossy();
        if s.trim().is_empty() { None } else { Some(s) }
    };
    match crate::vault_ops::vault_diff(&vp, other_opt.as_deref()) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-DIFF] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_backup(vault_path: *const c_char, out_archive: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let out_opt = if out_archive.is_null() {
        None
    } else {
        let s = unsafe { CStr::from_ptr(out_archive) }.to_string_lossy();
        if s.trim().is_empty() { None } else { Some(s) }
    };
    match crate::vault_ops::vault_backup(&vp, out_opt.as_deref()) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-BACKUP] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_restore(vault_path: *const c_char, in_archive: *const c_char) -> c_int {
    if vault_path.is_null() || in_archive.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let arch = unsafe { CStr::from_ptr(in_archive) }.to_string_lossy();
    match crate::vault_ops::vault_restore(&vp, &arch) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-RESTORE] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_import(vault_path: *const c_char, src: *const c_char) -> c_int {
    if vault_path.is_null() || src.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let s = unsafe { CStr::from_ptr(src) }.to_string_lossy();
    match crate::vault_ops::vault_import(&vp, &s) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-IMPORT] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_lock(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_lock(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-LOCK] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_lock_status(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_lock_status(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-LOCK-STATUS] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_force_unlock(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_force_unlock(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-FORCE-UNLOCK] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_key_info(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_key_info(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-KEY-INFO] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_key_rotate(
    vault_path: *const c_char,
    old_p: *const c_char,
    new_p: *const c_char,
) -> c_int {
    if vault_path.is_null() || old_p.is_null() || new_p.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let o = unsafe { CStr::from_ptr(old_p) }.to_string_lossy();
    let n = unsafe { CStr::from_ptr(new_p) }.to_string_lossy();
    match crate::vault_ops::vault_key_rotate(&vp, &o, &n) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-KEY-ROTATE] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_rekey(vault_path: *const c_char, pass: *const c_char) -> c_int {
    if vault_path.is_null() || pass.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let p = unsafe { CStr::from_ptr(pass) }.to_string_lossy();
    match crate::vault_ops::vault_rekey(&vp, &p) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-REKEY] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_stats(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_stats(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-STATS] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_usage(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_usage(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-USAGE] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_inspect(vault_path: *const c_char, rel_file: *const c_char) -> c_int {
    if vault_path.is_null() || rel_file.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    let f = unsafe { CStr::from_ptr(rel_file) }.to_string_lossy();
    match crate::vault_ops::vault_inspect(&vp, &f) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-INSPECT] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_history(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_history(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-HISTORY] {}", e); -1 }
    }
}

#[no_mangle]
pub extern "C" fn rust_vault_events(vault_path: *const c_char) -> c_int {
    if vault_path.is_null() { return -1; }
    let vp = unsafe { CStr::from_ptr(vault_path) }.to_string_lossy();
    match crate::vault_ops::vault_events(&vp) {
        Ok(_) => 0,
        Err(e) => { eprintln!("✖ [VAULT-EVENTS] {}", e); -1 }
    }
}




pub fn init() -> VResult {
    unsafe { check(vault_ffi_init()) }
}

pub fn shutdown() -> VResult {
    unsafe { check(vault_ffi_shutdown()) }
}

pub fn create_vault(name: &str, protected: bool, path: &str, password: &str) -> VResult {
    let name_c = cstr(name);
    let path_c = cstr(path);
    let pass_c = cstr(password);
    let vtype = if protected { 1 } else { 0 };
    unsafe {
        check(vault_create_ffi(
            name_c.as_ptr(),
            vtype,
            path_c.as_ptr(),
            pass_c.as_ptr(),
        ))
    }
}

pub fn delete_vault(id: u32, password: &str) -> VResult {
    let pass_c = cstr(password);
    unsafe { check(vault_delete_ffi(id, pass_c.as_ptr())) }
}

pub fn mount(id: u32, password: &str) -> VResult {
    let pass_c = cstr(password);
    unsafe { check(vault_mount_ffi(id, pass_c.as_ptr())) }
}

pub fn unmount(id: u32) -> VResult {
    unsafe { check(vault_unmount_ffi(id)) }
}

pub fn encrypt(id: u32, password: &str) -> VResult {
    let pass_c = cstr(password);
    unsafe { check(vault_encrypt_ffi(id, pass_c.as_ptr())) }
}

pub fn decrypt(id: u32, password: &str) -> VResult {
    let pass_c = cstr(password);
    unsafe { check(vault_decrypt_ffi(id, pass_c.as_ptr())) }
}

pub fn open_sandbox(id: u32, password: &str, gui_mode: bool, app_cmd: &str) -> VResult {
    let pass_c = cstr(password);
    let cmd_c = cstr(app_cmd);
    unsafe {
        check(vault_sandbox_ffi(
            id,
            pass_c.as_ptr(),
            gui_mode as c_int,
            cmd_c.as_ptr(),
        ))
    }
}

pub fn status(id: u32) -> Result<VaultStatus, VaultError> {
    let raw = unsafe { vault_get_status_ffi(id) };
    if raw < 0 {
        Err(VaultError::from_raw(raw))
    } else {
        Ok(VaultStatus::from_raw(raw))
    }
}

pub fn list_vaults() -> Result<Vec<VaultEntry>, VaultError> {
    let cap = unsafe { vault_count_ffi() }.max(1);
    let mut raw = vec![VaultIdPathRaw::default(); cap as usize];
    let mut count: u32 = 0;

    let rc = unsafe { vault_list_ids_ffi(raw.as_mut_ptr(), cap, &mut count) };
    check(rc)?;

    let mut out = Vec::with_capacity(count as usize);
    for entry in raw.into_iter().take(count as usize) {
        let path = unsafe { CStr::from_ptr(entry.path.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let st = status(entry.id).unwrap_or(VaultStatus::Unknown(-999));
        out.push(VaultEntry {
            id: entry.id,
            path,
            status: st,
        });
    }
    Ok(out)
}

/// Isolation options for `run_sandbox`. Mirrors `iso_*`/`no_fuse`/
/// `seccomp_strict` fields in CliConfig exposed by UI.
#[derive(Clone, Debug, Default)]
pub struct SandboxOptions {
    pub no_net: bool,
    pub wayland: bool,
    pub x11: bool,
    pub audio: bool,
    pub ro_home: bool,
    pub no_fuse: bool,
    pub seccomp_strict: bool,
    pub use_chroot: bool,
    pub image: Option<String>,
}

/// Accepts "one path per line" or "path, path, path" in the same text field
/// used by the UI without requiring widget changes. Spaces inside a
/// path will not break operations as each entry becomes its own CString.
pub fn split_paths(field: &str) -> Vec<String> {
    field
        .split(['\n', ','])
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Constructs CString + array of pointers for a path list while keeping
/// CString instances alive (pointer array is valid only while CStrings exist).
fn cstring_array(paths: &[String]) -> (Vec<CString>, Vec<*const c_char>) {
    let owned: Vec<CString> = paths.iter().map(|p| cstr(p)).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    (owned, ptrs)
}

/// Launches isolated `exec_path` inside vault `id` sandbox using typed options
/// and bind arrays (ro/rw/blacklist) passed as typed parameters.
pub fn run_sandbox(
    id: u32,
    password: &str,
    exec_path: &str,
    opts: &SandboxOptions,
    ro_paths: &[String],
    rw_paths: &[String],
    blacklist_paths: &[String],
) -> VResult {
    let pass_c = cstr(password);
    let exec_c = cstr(exec_path);
    let image_c = opts.image.as_ref().map(|s| cstr(s));
    let image_ptr = image_c.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null());

    let (_ro_owned, ro_ptrs) = cstring_array(ro_paths);
    let (_rw_owned, rw_ptrs) = cstring_array(rw_paths);
    let (_bl_owned, bl_ptrs) = cstring_array(blacklist_paths);

    unsafe {
        check(vault_sandbox_run_ffi(
            id,
            pass_c.as_ptr(),
            exec_c.as_ptr(),
            opts.no_net,
            opts.wayland,
            opts.x11,
            opts.audio,
            opts.ro_home,
            opts.no_fuse,
            opts.seccomp_strict,
            opts.use_chroot,
            ro_ptrs.as_ptr(),
            ro_ptrs.len() as u32,
            rw_ptrs.as_ptr(),
            rw_ptrs.len() as u32,
            bl_ptrs.as_ptr(),
            bl_ptrs.len() as u32,
        ))
    }
}

/// Executes any Nuk4sd command line directly in memory via C core.
pub fn exec_cli_cmd(cmd_line: &str) -> (i32, String) {
    let mut args: Vec<String> = vec!["Nuk4sd".to_string()];
    args.extend(cmd_line.split_whitespace().map(|s| s.to_string()));

    let c_args: Vec<CString> = args
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap_or_default())
        .collect();

    let c_ptrs: Vec<*const c_char> = c_args.iter().map(|s| s.as_ptr()).collect();

    let exit_code = unsafe {
        vault_cli_parse_and_exec(c_ptrs.len() as c_int, c_ptrs.as_ptr())
    };

    (exit_code, format!("Command executed: {} (return code: {})", cmd_line, exit_code))
}

/// C -> Rust callback for safe file copying
#[no_mangle]
pub extern "C" fn rust_vault_copy_file(src: *const c_char, dst: *const c_char) -> c_int {
    if src.is_null() || dst.is_null() {
        return -1;
    }
    let src_str = match unsafe { CStr::from_ptr(src) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let dst_str = match unsafe { CStr::from_ptr(dst) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match std::fs::copy(src_str, dst_str) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_generate_mac_secret(out_buffer: *mut c_char, buffer_size: usize) -> c_int {
    if out_buffer.is_null() || buffer_size == 0 {
        return -1;
    }
    
    match crypto::generate_mac_secret() {
        Ok(phrase) => {
            let c_str = match CString::new(phrase) {
                Ok(s) => s,
                Err(_) => return -1,
            };
            
            let bytes = c_str.as_bytes_with_nul();
            if bytes.len() > buffer_size {
                return -1;
            }
            
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buffer as *mut u8, bytes.len());
            }
            0 // success
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_validate_mac_secret(phrase_ptr: *const c_char) -> c_int {
    if phrase_ptr.is_null() {
        return 0; // false
    }
    let phrase = unsafe { CStr::from_ptr(phrase_ptr) }.to_string_lossy();
    if crypto::validate_mac_secret(&phrase) {
        1 // true
    } else {
        0 // false
    }
}
