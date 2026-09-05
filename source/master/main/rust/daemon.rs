//! Daemon local do Nuk4sd.
//!
//! O daemon expõe somente operações explicitamente allowlisted sobre um socket
//! Unix privado. Ele não recebe shell, caminhos ou argv do cliente. As respostas
//! de vaults vêm diretamente da FFI real; quando o core não está disponível, a
//! conexão falha fechada.

use crate::ffi;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const PROTOCOL: &str = "nuk4sd-daemon.v1";
const MAX_LINE_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
struct Request {
    protocol: String,
    op: String,
    #[serde(default)]
    vault_id: Option<u32>,
}

#[derive(Debug, Serialize)]
struct Response {
    protocol: &'static str,
    ok: bool,
    data: Option<Value>,
    error: Option<String>,
}

struct RuntimeGuard {
    socket: PathBuf,
    pid: PathBuf,
    lock: PathBuf,
    _lock_file: File,
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_file(&self.pid);
        let _ = fs::remove_file(&self.lock);
    }
}

fn response_ok(data: Value) -> Response {
    Response {
        protocol: PROTOCOL,
        ok: true,
        data: Some(data),
        error: None,
    }
}

fn response_err(message: impl Into<String>) -> Response {
    Response {
        protocol: PROTOCOL,
        ok: false,
        data: None,
        error: Some(message.into()),
    }
}

fn send(stream: &mut UnixStream, response: Response) -> std::io::Result<()> {
    let line = serde_json::to_vec(&response)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "response serialization failed"))?;
    stream.write_all(&line)?;
    stream.write_all(b"\n")?;
    stream.flush()
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 || len < std::mem::size_of::<libc::ucred>() as libc::socklen_t {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(_stream: &UnixStream) -> std::io::Result<u32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "peer credentials unavailable",
    ))
}

fn list_vaults() -> Result<Value, String> {
    let entries = ffi::list_vaults().map_err(|e| e.message())?;
    let values = entries
        .into_iter()
        .map(|entry| {
            json!({
                "id": entry.id,
                "path": entry.path,
                "status": entry.status.label(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({ "vaults": values }))
}

fn handle_request(request: Request) -> Response {
    if request.protocol != PROTOCOL {
        return response_err("unsupported_protocol");
    }
    match request.op.as_str() {
        "health" => response_ok(json!({ "ready": true, "pid": std::process::id() })),
        "status" => {
            let Some(id) = request.vault_id else {
                return response_err("vault_id_required");
            };
            match ffi::status(id) {
                Ok(status) => response_ok(json!({ "id": id, "status": status.label() })),
                Err(error) => response_err(error.message()),
            }
        }
        "vault.list" => match list_vaults() {
            Ok(data) => response_ok(data),
            Err(error) => response_err(error),
        },
        _ => response_err("operation_not_allowlisted"),
    }
}

fn handle_client(mut stream: UnixStream, expected_uid: u32) {
    let uid = match peer_uid(&stream) {
        Ok(value) => value,
        Err(_) => return,
    };
    if uid != expected_uid {
        return;
    }

    let reader_stream = match stream.try_clone() {
        Ok(value) => value,
        Err(_) => return,
    };
    let mut reader = BufReader::new(reader_stream);
    let mut line = Vec::with_capacity(512);
    if reader.read_until(b'\n', &mut line).is_err() || line.len() > MAX_LINE_BYTES {
        return;
    }
    let request: Request = match serde_json::from_slice(&line) {
        Ok(value) => value,
        Err(_) => {
            let _ = send(&mut stream, response_err("invalid_json"));
            return;
        }
    };
    let _ = send(&mut stream, handle_request(request));
}

#[cfg(target_os = "linux")]
fn enforce_unprivileged() -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("refusing_root_daemon".into());
    }
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(format!("no_new_privs: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enforce_unprivileged() -> Result<(), String> {
    Err("unsupported_platform".into())
}

fn prepare_runtime(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

fn acquire_guard(dir: &Path, socket: &Path, pid: &Path) -> std::io::Result<RuntimeGuard> {
    let lock = dir.join("nuk4sd-daemon.lock");
    let lock_file = OpenOptions::new().write(true).create_new(true).open(&lock)?;
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
    fs::write(pid, format!("{}\n", std::process::id()))?;
    fs::set_permissions(pid, fs::Permissions::from_mode(0o600))?;
    Ok(RuntimeGuard {
        socket: socket.to_path_buf(),
        pid: pid.to_path_buf(),
        lock,
        _lock_file: lock_file,
    })
}

pub fn run(socket: PathBuf, pid: PathBuf, runtime_dir: PathBuf) -> Result<(), String> {
    enforce_unprivileged()?;
    prepare_runtime(&runtime_dir).map_err(|e| format!("runtime_dir: {e}"))?;
    if socket.exists() {
        return Err("socket_already_exists".into());
    }
    let guard = acquire_guard(&runtime_dir, &socket, &pid).map_err(|e| format!("lock_or_pid: {e}"))?;
    let listener = UnixListener::bind(&socket).map_err(|e| format!("bind: {e}"))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).map_err(|e| format!("socket_permissions: {e}"))?;

    let running = Arc::new(AtomicBool::new(true));
    let signal_running = Arc::clone(&running);
    ctrlc::set_handler(move || signal_running.store(false, Ordering::SeqCst))
        .map_err(|e| format!("signal_handler: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("nonblocking: {e}"))?;
    let expected_uid = unsafe { libc::geteuid() };

    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => handle_client(stream, expected_uid),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => return Err(format!("accept: {error}")),
        }
    }
    drop(guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_operation() {
        let response = handle_request(Request {
            protocol: PROTOCOL.into(),
            op: "shell".into(),
            vault_id: None,
        });
        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("operation_not_allowlisted"));
    }

    #[test]
    fn rejects_wrong_protocol() {
        let response = handle_request(Request {
            protocol: "other".into(),
            op: "health".into(),
            vault_id: None,
        });
        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("unsupported_protocol"));
    }
}

pub fn protocol_name() -> &'static str {
    PROTOCOL
}
