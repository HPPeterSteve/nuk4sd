# Nuk4sd v0.9.30 — Release Notes (Planned)

**Date:** In planning  
**Branch:** main  
**Type:** Debug / Stability release

---

## Overview

Stabilization release following full debugging of the 0.9.30 cycle. Focus on regression test coverage, container runtime hardening, and validation of all escape vectors prior to public release.

---

## In Planning

- [ ] Complete regression testing post `c_src/` refactor
- [ ] Validation of new `container/` and `sandbox/` modules against known escape vectors
- [ ] Hardening of `oci.rs` (layer limits, digest validation)
- [ ] Performance review of `vault/` following modular reorganization

---

---

# Nuk4sd v0.9.30 — Release Notes (In Development)

**Date:** August 12, 2026  
**Branch:** main  
**Type:** Refactor + Feature release

---

## Overview

Version 0.9.30 represents a deep reorganization of the C codebase structure, migrating from monolithic files to a modular architecture organized by responsibility. It introduces the `oci.rs` module for integration with the OCI container runtime and adds support for containers with overlay filesystems.

---

## Key Changes

### Refactor: Modular Structure of `c_src/`

C source files that previously resided flat in `c_src/` have been reorganized into modules by responsibility:

| Module | Contents |
|---|---|
| `c_src/sandbox/` | `jail.c`, `caps.c`, `seccomp.c`, `userns.c`, `mounts.c`, `rlimits.c`, `landlock.c` |
| `c_src/vault/` | `vault_core.h`, `vault_engine.c`, `vault_crypto.c`, `vault_catalog.c`, `vault_ffi.c`, `vault_fuse.c`, `vault_health.c`, `vault_monitor.c` |
| `c_src/cli/` | `vault_cli.c`, `vault_cli_log.c`, `vault_cli_log.h` |
| `c_src/container/` | `container.c`, `container.h`, `overlay.c`, `overlay.h` |

### New Feature: `rust/oci.rs`

Integration with the OCI (Open Container Initiative) runtime:
- Pull and extraction of OCI images via `reqwest` + `tar` + `flate2`
- Support for overlayfs container layers
- Compatible with standard registries (Docker Hub, GHCR)

### New Feature: Synthetic /dev (--mount-dev)

Introduced full hardware device isolation. Instead of inheriting (bind-mounting) the host `/dev`, the sandbox now creates a synthetic in-memory `/dev` (`tmpfs`) containing strictly essential nodes (`null`, `zero`, `random`, `urandom`, `tty`, `console`) and dedicated pseudoterminals under `/dev/pts`. This eliminates any host hardware exposure to the isolated process.

### Update: `rust/ffi.rs` and `rust/main.rs`

FFI bindings updated to reflect the new modular layout of `c_src/`, with includes pointing to the new subdirectories.

### Test Scripts

- Added `sandbox_check.sh` — fast sandbox integrity verification script
- Updated `sandbox_mass_test.sh` — mass testing suite for escape vectors

---

## Modified Files in This Release

- `c_src/sandbox/` — isolation module (migrated from flat)
- `c_src/vault/` — vault module (migrated from flat)
- `c_src/cli/` — CLI module (migrated from flat)
- `c_src/container/` — new overlay container module
- `rust/oci.rs` — new: OCI runtime
- `rust/ffi.rs` — updated: bindings for new layout
- `rust/main.rs` — updated: integrations
- `build.rs` — updated: build paths for new structure
- `Cargo.toml` — version 0.9.30
- `examples/` — new: usage examples

---

---

# Nuk4sd v0.9.28 — Release Notes

**Date:** July 31, 2026
**Branch:** main
**Type:** Bugfix + Security + Feature release

---

## Overview

Version 0.9.28 represents a deep overhaul of the sandbox isolation layer, addressing namespace leakage vulnerabilities, critical graphical application execution issues, and native Rust interface refinements. The project remains free of root/sudo dependencies for creating functional sandboxes, operating with technical parity to Bubblewrap (bwrap), the engine behind Flatpak.

---

## Fixed Vulnerabilities

### [SEC-01] Host PID Leakage via /proc (Severity: Medium)

The sandbox bound `/proc` from the host via inherited bind-mount prior to `pivot_root`, and the post-pivot remount silently failed because the mountpoint was already occupied. Consequently, processes inside the sandbox could enumerate actual host PIDs through `/proc`, violating PID namespace isolation.

**Impact:** A malicious process inside the sandbox could observe running processes on the host, infer workloads and timing, and potentially use `/proc/<pid>/fd` as a read channel if accessible open file descriptors existed.

**Fix:** Implemented a robust three-stage sequence prior to mounting a fresh `/proc`: (1) `umount2(MNT_DETACH)` to detach inherited procfs lazily without blocking on open file descriptors; (2) mountpoint creation with `EEXIST` validation; (3) mounting a new procfs scoped to the sandbox PID namespace with `MS_NOSUID | MS_NOEXEC | MS_NODEV`. Each step features structured logging via `vault_log()`, and mount failures log `LOG_ERROR` in the audit log rather than suppressing errors with `perror()`.

### [SEC-02] RLIMIT_AS Breaking 64-bit Allocators in GUI Mode (Severity: High)

By default, the sandbox imposed a strict virtual address space limit (`RLIMIT_AS`) of 4 to 8 GB across all modes. Modern 64-bit allocators—especially Firefox's SpiderMonkey JIT and Chromium's V8—`mmap()` virtual memory regions far larger than physical RAM (virtual address space reservation). With the limit active, the kernel returned `ENOMEM` on `mmap()` calls during startup, leading to silent process failure prior to rendering.

**Impact:** All modern graphical applications based on Electron, Firefox, or Chromium failed to start inside the sandbox with exit code 11 (SIGSEGV due to unmapped memory access).

**Fix:** `RLIMIT_AS` removed from automatic defaults. The limit is only enforced when the user explicitly specifies `--max-mem <GB>` via CLI.

### [SEC-03] Seccomp Profile Blocking Application Internal Sandboxes (Severity: High)

Firefox, Chromium, and Electron-based applications attempt to construct an internal content process mini-sandbox by calling `capset()` and `chroot()` post primary execution. The standard Nuk4sd seccomp profile returned `EPERM` for `capset()`, which Firefox interpreted as a fatal error in the `futex` synchronization primitive, aborting with "The futex facility returned an unexpected error code."

**Impact:** Firefox, GIMP, VS Code, and other GUI applications with their own internal sandboxes failed to launch.

**Fix:** Added automatic "GUI friendly" mode triggered whenever the sandbox detects Wayland or X11 mode (`--wayland`/`--x11`). In this mode, `capset()`, `chroot()`, `setuid()`, and `setgid()` are permitted in the seccomp profile so internal application sandboxing works. True isolation remains guaranteed by Nuk4sd layers (cleared capabilities, PID namespace, filesystem pivot_root), rendering the calls harmless even if allowed in the BPF filter.

### [SEC-04] Missing /dev Device Nodes in Unprivileged Sandbox (Severity: High)

In unprivileged mode (without sudo), the sandbox could not create device nodes via `mknod()` because that syscall requires `CAP_MKNOD`, which is absent in user namespaces. Regular file placeholders created for `/dev/null`, `/dev/zero`, and `/dev/tty` were empty regular files rather than true character devices.

**Impact:** Applications writing to `/dev/null` accumulated data on disk; reads from `/dev/zero` returned EOF; missing `/dev/shm`, `/dev/pts`, and `/dev/urandom` caused graphical and cryptographic applications to fail due to lack of entropy or shared memory.

**Fix:** Implemented selective bind-mounting of host device nodes into the sandbox with read/write flags for `/dev/*` nodes. The following devices are now inherited from the host in read/write mode: `/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/random`, `/dev/shm`, `/dev/pts`, `/dev/dri`. Other directory bind-mounts remain read-only.

---

## New Features and Improvements

### Native Rust Interface (egui/eframe)

The graphical interface was completely rewritten in pure Rust using the `egui` framework with an `eframe` backend. The legacy `nuk4sd_gui.py` (2635 lines, PyQt5 dependency) was removed. The new GUI:

- Has no dependencies on Python, pip, or Qt on the host OS.
- Is statically compiled into the `Nuk4sd` binary without a separate runtime.
- Communicates directly with the C core via FFI without subprocesses or stdout parsing.
- Persists application profiles in `~/.config/nuk4sd/desktop_apps.json` via serde_json.
- Features five tabs: Desktop Grid, Vaults FUSE, Launcher, Active Sandboxes, and CLI Terminal.
- Exposes all available isolation flags in the UI without hiding advanced options.
- Visual design in neutral navy blue and dark gray without external theme libraries.

### GUI Application Launcher Without Vault (--no-fuse)

Desktop Grid now automatically detects when `vault_id == 0` and uses `--no-fuse`, creating a temporary jail in `/tmp` without requiring the user to create a FUSE vault beforehand. `--rw-home` is added automatically so applications maintain access to the user's home directory and settings.

### Automatic Preflight Scan

Prior to launching any binary, Nuk4sd analyzes executable dependencies via `ldd` and configures automatically:
- GPU usage detection → mounts `/dev/dri` and `/sys/dev/char`
- GTK/Qt detection → configures Wayland/X11 environment variables and mounts `/tmp/.X11-unix`
- Audio detection → mounts PipeWire and PulseAudio sockets
- Network usage detection → warns if `--no-net` was not specified

### Verified Rootless Compatibility

Confirmed that Nuk4sd operates with technical parity to Bubblewrap in non-root environments. The isolation sequence is equivalent:

```
unshare(CLONE_NEWUSER)  →  write uid_map/gid_map  →
unshare(CLONE_NEWNS | CLONE_NEWPID)  →  bind-mounts  →
pivot_root()  →  drop capabilities  →  NO_NEW_PRIVS  →
seccomp-BPF  →  execvp()
```

Unlike Firejail (SUID root binary), Nuk4sd does not require the setuid bit and never executes code as root at any point.

---

## Escape Test Results (v0.9.28)

Test executed with `escape_test.sh` inside the sandbox, compared to host baseline:

| Vector | Host (un-sandboxed) | Nuk4sd v0.9.28 |
|---|---|---|
| Read /etc/shadow | No (permission) | Blocked |
| Access ~/.ssh | No (permission) | Blocked |
| Host PIDs via /proc | Sees 245 PIDs | Blocked (own PID=1) |
| mount procfs/bind/tmpfs | No (no caps) | Blocked |
| chroot | No (no caps) | Blocked |
| SUID/setuid binary | No (no caps) | Blocked (NO_NEW_PRIVS) |
| Effective capabilities | Cleared (normal user) | Cleared |
| kexec_load | Open | Blocked (KILL_PROCESS) |
| Nested pivot_root | No (no caps) | Blocked |
| /dev/mem, /dev/sda, /dev/kmem | Inaccessible | Unexposed |
| External network access | Open | Blocked (host network shared by default) |

---

## Comparison with Firejail 0.9.72

Test conducted using `firejail --noprofile firefox` and `firejail firefox` (with default profile):

| Layer | Firejail unprofiled | Firejail profiled | Nuk4sd v0.9.28 |
|---|---|---|---|
| Dedicated user namespace | No (host) | No (host) | Yes |
| PID namespace | Yes | Yes | Yes |
| Mount namespace | Yes | Yes | Yes |
| pivot_root | No | No | Yes (host detached) |
| Seccomp-BPF | Disabled | Active (mode 2) | Active (mode 1) |
| NO_NEW_PRIVS | No | Yes | Yes |
| Capabilities | CapBnd full | CapBnd cleared | CapEff zero |
| Requires SUID root | Yes | Yes | No |
| Per-app profiles | No | 900+ profiles | Generic (category presets) |

Firejail holds an advantage in application-specific profiles with path whitelists and custom seccomp rules for each program. Nuk4sd holds the advantage in dedicated user namespaces, full pivot_root, and absence of SUID.

---

## Modified Files in This Release

- `c_src/jail.c` — bind-mount device nodes `/dev/*` in RW mode; fixed inherited `/proc`
- `c_src/vault_cli.c` — removed `RLIMIT_AS` defaults; automatic friendly seccomp for GUI; robust `/proc` remount with `umount2(MNT_DETACH)` + structured logging
- `c_src/seccomp.c` — expanded justification comments; permissive mode for application internal sandboxing
- `rust/gui.rs` — full native egui interface; Desktop Grid; Vaults Manager; Launcher; Terminal
- `rust/ffi.rs` — full FFI bindings; `rust_vault_copy_file` exported as C symbol
- `rust/main.rs` — `--gui` route for native interface
- `Cargo.toml` — serde/serde_json dependencies; version 0.9.28
- `.gitignore` — excluded logs, compiled objects, keys, and session files
