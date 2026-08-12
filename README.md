# Nuk4sd

> A Linux process sandbox with encrypted storage. No wrappers, no buzzwords — just namespaces, FUSE and seccomp doing their job.

[![Version](https://img.shields.io/badge/version-0.9.26-blue)](https://github.com/Vault-Founders/Nuk4sd/releases)
[![Platform](https://img.shields.io/badge/platform-Linux-informational)](https://kernel.org)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)
[![Language](https://img.shields.io/badge/core-C%20%2B%20Rust-orange)](https://github.com/Vault-Founders/Nuk4sd)

---

## What it does

Nuk4sd runs a program inside an isolated environment (sandbox) while keeping its data in an encrypted storage vault (FUSE + AES-256-GCM).

The goal is simple: **you decide what a program can see, touch and talk to.** Network, display server, home directory, audio, D-Bus — you allow or deny each one explicitly.

```bash
# Run Firefox with no network access, isolated from the host home directory
Nuk4sd --vault 0 --run /usr/bin/firefox --no-net --wayland --ro-home

# Run VS Code with access to ~/projects only
Nuk4sd --vault 1 --run /usr/bin/code --wayland --rw ~/projects --blacklist ~/.ssh

# Encrypt all files stored in vault 2
Nuk4sd --vault 2 --encrypt
```

---

## How it works

Each sandbox is built from standard Linux primitives — nothing exotic, nothing that requires a kernel patch:

| Layer | Technology |
|---|---|
| Process isolation | User namespaces (`CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWPID`) |
| Filesystem isolation | `pivot_root` + bind mounts into a FUSE-mounted vault |
| Privilege dropping | `NO_NEW_PRIVS` + `cap_drop(ALL)` |
| Syscall filtering | Seccomp-BPF (standard + strict modes) |
| Encrypted storage | AES-256-GCM via OpenSSL, key derived with Argon2 |
| Mount-level encryption | FUSE driver (no external dependency like `gocryptfs`) |

The sandbox runs as your own user — `sudo` is only required for the initial mount/unmount of the FUSE volume.

---

## Comparison

|  | Nuk4sd | Firejail | Bubblewrap | Docker |
|---|---|---|---|---|
| Encrypted storage built-in | ✅ | ❌ | ❌ | ❌ |
| No kernel module required | ✅ | ✅ | ✅ | ❌ |
| Runs as regular user | ✅ | ✅ | ✅ | ❌ |
| Per-app GUI profiles | ✅ | Partial | ❌ | ❌ |
| FUSE vault (own impl.) | ✅ | ❌ | ❌ | ❌ |
| Graphical interface (GUI) | ✅ | ❌ | ❌ | Partial |
| Seccomp-BPF | ✅ | ✅ | ✅ | ✅ |

---

## Installation

### Build from source

```bash
# Dependencies: Rust toolchain, GCC, libfuse3-dev, libssl-dev, python3-pyqt5
git clone https://github.com/Vault-Founders/Nuk4sd
cd Nuk4sd
cargo build --release

sudo cp target/release/Nuk4sd /usr/local/bin/
```

### GUI (optional)

```bash
# Requires: python3-pyqt5
python3 nuk4sd_gui.py

# Or as a persistent systemd user service:
systemctl --user start nuk4sd.service
```

---

## Key flags

```
--vault <id>          Select which encrypted vault to mount
--run <exe>           Program to execute inside the sandbox
--no-net              Block all network access (CLONE_NEWNET)
--no-fuse             Skip vault mount — use a plain temp directory instead
--wayland             Allow Wayland socket access
--x11                 Allow X11 socket access
--ro <path>           Mount path read-only inside the sandbox
--rw <path>           Mount path read-write inside the sandbox
--blacklist <path>    Hide path entirely from the sandboxed process
--ro-home             Mount home directory as read-only
--audio               Allow PipeWire/PulseAudio socket access
--no-dbus             Block D-Bus session socket
--seccomp-strict      Enable strict syscall filtering
--debug               Print detailed sandbox construction log
--verbose             Verbose output during execution
--encrypt             Encrypt all files in the vault (AES-256-GCM)
--decrypt             Decrypt all files in the vault
--ls                  List all configured vaults and their status
--new <name>          Create a new vault
--export              Export vault contents to a plain directory
```

---

## Vaults

A vault is an encrypted directory managed by Nuk4sd. It only gets unlocked when you explicitly run something inside it, and it re-seals the moment the process exits.

```bash
# Create a new vault
Nuk4sd --new work --path ~/.local/share/nuk4sd/work

# List vaults and their status
Nuk4sd --ls

# Run a program inside vault 0, then auto-unmount on exit
Nuk4sd --vault 0 --run /usr/bin/gedit
```

---

## GUI

Nuk4sd ships with a PyQt5 desktop interface:

- **Sandbox Desktop** — launch sandboxed apps from a visual desktop (custom wallpaper, icon grid, right-click context menus)
- **Per-app profiles** — save flag sets and mount configurations per application
- **Vault Manager** — encrypt, decrypt and browse vault contents visually
- **Active Monitor** — see running sandbox processes in real time, with kill support
- **Audit Log** — view the full Seccomp/kernel audit trail
- **Achievements** — a lightweight gamification layer that tracks usage patterns

The GUI calls the same binary. It is a frontend, not a separate implementation.

---

## Use cases

**Daily browser isolation**
Run Firefox with `--no-net` on certain vaults, or `--ro-home` so it cannot read your SSH keys, wallet files or other browser profiles.

**Untrusted software**
That Electron app, closed-source installer or random script from the internet — run it with explicit, auditable permissions and nothing else.

**Secure document editing**
Open sensitive files inside an encrypted vault. They never touch your main filesystem in plaintext outside the session.

**Development environments**
Give a project access to `~/projects/foo` and nothing else. No accidental writes to `~/.config` or `~/.local`.

**Penetration testing tools**
Run network tools from an isolated environment without exposing your host credentials or contaminating your main session.

---

## Status

Version `0.9.26`. Used daily on GNOME/X11 and Wayland systems.

Core sandbox functionality (namespaces, seccomp, mounts) is stable. FUSE mount reliability depends on your kernel version — tested on Linux 6.x. Breaking changes are possible before `1.0`.

---

## Contributing

Issues and pull requests are open. For security concerns, open an issue tagged `security` — no bounty program yet, just responsible disclosure.

---

## License

MPL 2.0

```
Copyright (c) 2025 Peter — Vault-Founders
```
