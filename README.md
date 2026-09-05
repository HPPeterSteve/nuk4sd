# Nuk4sd

> Pragmatic Linux process sandboxing paired with encrypted storage (AES-256-GCM + Argon2id). Built using Linux namespaces, Seccomp-BPF, Landlock, and FUSE.

[![Version](https://img.shields.io/badge/version-0.9.26-blue)](https://github.com/Vault-Founders/Nuk4sd/releases)
[![Platform](https://img.shields.io/badge/platform-Linux-informational)](https://kernel.org)
[![License](https://img.shields.io/badge/license-MPL--2.0-green)](#license)
[![Language](https://img.shields.io/badge/core-C%20%2B%20Rust-orange)](https://github.com/Vault-Founders/Nuk4sd)

---

## Overview

**Nuk4sd** is a hybrid C/Rust utility that combines process-level sandboxing with hardware-independent encrypted storage. It allows you to run untrusted or sensitive applications inside an isolated environment while storing their persistent data in encrypted vaults.

Rather than relying on heavyweight container runtimes or complex virtual machines, Nuk4sd leverages core Linux kernel primitives: **User Namespaces**, **Mount Namespaces**, **Seccomp-BPF**, **Landlock**, and **FUSE**.

---

## Development Status

### ✅ Working & Stable
* **Process Sandboxing:** User namespace isolation (`CLONE_NEWUSER`), PID isolation (`CLONE_NEWPID`), and Mount namespaces (`CLONE_NEWNS`) with `pivot_root`.
* **Syscall Filtering:** Seccomp-BPF allowlisting with standard and strict profile modes, plus capability dropping (`cap_drop(ALL)`) and `NO_NEW_PRIVS`.
* **Landlock LSM Integration:** Path-based access control rules enforced at the kernel level.
* **Storage Encryption:** File & vault payload encryption using **AES-256-GCM** with **Argon2id** key derivation (64 MB memory cost, 3 iterations).
* **WORM (Write Once Read Many) Protection:** Fine-grained kernel/FUSE flags to block `unlink`, `rename`, `write`, or `read` operations.
* **Integrity Monitoring:** Leaky-bucket algorithm for file access throttling and integrity alerts.
* **CLI & Interactive REPL:** Command-line runner and interactive shell interface (`Nuk4sd`).

### 🟡 In Progress / Limitations
* **Native Windows Build:** The codebase relies directly on Linux kernel APIs (`pivot_root`, `fanotify`, `landlock`, `seccomp`). Native compilation on Windows is not supported (requires WSL2 or Linux host).
* **Unprivileged Fanotify:** Active `fanotify` filesystem blocking requires `CAP_SYS_ADMIN` / `root`. When run unprivileged, Nuk4sd automatically degrades to passive FUSE monitoring without crashing.
* **App Profile Coverage:** Default profiles are lighter compared to projects with large community rulebases (like Firejail).

### ❌ Abandoned / Replaced Approaches
* **Helper Binaries (`newuidmap`/`newgidmap`):** Originally used 2-line UID mappings requiring external setuid helpers. Replaced with single-line `unshare()` mapping to keep Nuk4sd fully rootless and self-contained.
* **PBKDF2-HMAC-SHA256:** Legacy key derivation was replaced with Argon2id to provide memory-hard resistance against GPU/ASIC cracking.

---

## Comparison & Trade-offs

| Feature / Property | Nuk4sd | Firejail | Bubblewrap | Docker / Podman | Cryptomator / gocryptfs |
|---|:---:|:---:|:---:|:---:|:---:|
| **Built-in Encrypted Vaults** | **Yes** (AES-GCM + Argon2id) | ❌ | ❌ | ❌ | **Yes** |
| **Process Sandboxing** | **Yes** (Seccomp + Landlock) | **Yes** | **Yes** | **Yes** | ❌ |
| **Daemonless & Rootless** | **Yes** | Setuid wrapper | **Yes** | Requires Daemon/Podman | **Yes** |
| **WORM File Locking** | **Yes** | ❌ | ❌ | ❌ | ❌ |
| **Active Access Throttling** | **Yes** (Leaky bucket) | ❌ | ❌ | ❌ | ❌ |
| **Resource Overhead** | Minimal (< 10 MB) | Minimal | Minimal | Heavy (Image/Daemon) | Minimal |

---

## Security Architecture

```
                    ┌────────────────────────────────────────┐
                    │            Nuk4sd Sandbox              │
                    │                                        │
                    │  ┌──────────────────────────────────┐  │
                    │  │         Target Process           │  │
                    │  └──────────────────────────────────┘  │
                    │                   │                    │
                    │   - Seccomp-BPF   │  - Landlock LSM    │
                    │   - cap_drop(ALL) │  - NO_NEW_PRIVS    │
                    └───────────────────┼────────────────────┘
                                        │ (Mount / Pivot)
                    ┌───────────────────▼────────────────────┐
                    │               FUSE Layer               │
                    │       (WORM Flags & Leaky Bucket)      │
                    └───────────────────┬────────────────────┘
                                        │ (AES-256-GCM)
                    ┌───────────────────▼────────────────────┐
                    │            Encrypted Vault             │
                    │          (Argon2id Key Deriv)          │
                    └────────────────────────────────────────┘
```

1. **User Space Execution:** Runs as an unprivileged user process without requiring a setuid binary.
2. **5-Layer Defense-in-Depth:** `User Namespaces` → `Mount Namespaces` → `pivot_root` → `Capability Drop` → `Seccomp-BPF` / `Landlock`.
3. **Decoy Labyrinth Engine:** Generates honeypot structures to detect and halt suspicious directory traversal or ransomware-like sweep attacks.

---

## Installation & Build

### Prerequisites (Linux)
- **Rust Toolchain** (1.70+)
- **GCC / Clang**
- **Libraries:** `libfuse3-dev`, `libssl-dev`, `libseccomp-dev`, `libcap-dev`, `libargon2-dev`

### Build Command

```bash
git clone https://github.com/Vault-Founders/Nuk4sd.git
cd Nuk4sd
cargo build --release
```

The compiled binary will be located at `target/release/Nuk4sd`.

---

## Usage & Flag Reference

### General Usage

```bash
# Launch interactive REPL mode
Nuk4sd

# List existing vaults
Nuk4sd --ls

# Create a protected vault with Argon2id password protection
Nuk4sd --new my_vault --protected

# Run an application inside the sandbox
Nuk4sd --vault 1 --run /usr/bin/firefox --no-net --wayland
```

### Complete Command Line Flags

#### Vault Operations
* `--ls` : List all configured vaults and status.
* `--new <name>` : Create a new vault.
  * `--path <dir>` : Specify storage path (default: `~/.local/share/Nuk4sd`).
  * `--protected` : Enable password protection (AES-256-GCM + Argon2id).
  * `--engine <0-5>` : Set obfuscation layer complexity (0=none, 5=20 layers + decoys).
* `--vault <id>` : Select active vault for operation.
  * `--info` : Display vault details and metadata.
  * `--files` : List tracked files and SHA-256 integrity hashes.
  * `--scan` : Execute SHA-256 integrity verification pass.
  * `--encrypt` : Encrypt vault contents with AES-256-GCM.
  * `--decrypt` : Decrypt vault contents.
  * `--mount` : Mount vault using FUSE driver.
  * `--umount` : Unmount FUSE driver.
  * `--export --dest <dir>` : Export vault contents to a directory.
  * `--rm` : Delete vault irreversibly.
  * `--rename <name>` : Change vault name in catalog.
  * `--passwd` : Change vault password using Argon2id.

#### Sandbox Execution (`--run <executable>`)
* **Filesystem Controls:**
  * `--ro <path>` : Bind mount path as read-only.
  * `--rw <path>` : Bind mount path as read-write.
  * `--blacklist <path>` : Hide path using tmpfs/null overlay.
  * `--ro-home` : Mount `$HOME` read-only.
  * `--rw-home` : Mount `$HOME` read-write.
  * `--tmp-home` : Provide ephemeral `$HOME` in tmpfs.
* **Network & IPC:**
  * `--no-net` : Isolate network namespace (`CLONE_NEWNET`).
  * `--unshare-ipc` : Isolate IPC namespace (SysV SHM, semaphores, message queues).
  * `--unshare-uts` : Isolate UTS namespace (hostname).
  * `--hostname <name>` : Set sandbox hostname.
* **Display & Subsystems:**
  * `--wayland` : Pass Wayland display socket (read-only).
  * `--x11` : Pass X11 display socket (read-only).
  * `--audio` : Pass PulseAudio/PipeWire sockets.
  * `--gpu` : Expose `/dev/dri` for hardware acceleration.
  * `--no-dbus` : Block D-Bus session bus access.
* **Syscall & Security Options:**
  * `--seccomp-strict` : Enable restrictive syscall allowlist.
  * `--no-seccomp` : Disable seccomp filtering (not recommended).
  * `--chroot` : Fallback to `chroot` instead of `pivot_root`.
  * `--permissive` : Relax sandbox restrictions for troubleshooting.
  * `--audit` : Log execution arguments, environment changes, and mounts.

#### WORM Protection Flags
* `--vault <id> --worm-status` : Show active WORM flags for vault.
* `--vault <id> --protect-delete` : Block `unlink`/`rmdir` (returns `EPERM`).
* `--vault <id> --protect-rename` : Block file/directory renaming (`EPERM`).
* `--vault <id> --protect-write` : Block modifications to existing files (`EPERM`).
* `--vault <id> --protect-read` : Block read access (`EPERM`).
* `--vault <id> --clear-delete` : Clear delete protection flag.

---

## License

This project is licensed under the **Mozilla Public License 2.0 (MPL-2.0)**. See the [LICENSE](LICENSE) file for details.

