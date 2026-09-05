# Nuk4sd

Nuk4sd is a Linux process isolation and encrypted vault management tool written in C and Rust. It relies on Linux kernel primitives—including user namespaces, mount namespaces, Seccomp-BPF filters, Landlock LSM rules, and FUSE filesystems—to run target processes in restricted environments and handle password-protected file storage.

## Architecture

The project is structured into two main operational components: process sandboxing and encrypted vault management.

### Sandbox Component (C Core)
- **Namespaces**: Isolates user (`CLONE_NEWUSER`), mount (`CLONE_NEWNS`), PID (`CLONE_NEWPID`), network (`CLONE_NEWNET`), IPC (`CLONE_NEWIPC`), and UTS (`CLONE_NEWUTS`) namespaces.
- **Syscall Filtering**: Implements Seccomp-BPF filters with standard and strict allowlist profiles to restrict available system calls.
- **Access Control**: Enforces Landlock LSM rules for path-level filesystem access restriction.
- **Privilege Dropping**: Drops capabilities via `cap_drop` and sets `PR_SET_NO_NEW_PRIVS`.
- **Filesystem Mounts**: Supports read-only (`--ro`), read-write (`--rw`), tmpfs overlays, and path blacklisting using mount namespaces and `pivot_root`.
- **Network Isolation**: Provides network namespace detachment and integration with `libnftables` filtering rules.

### Vault & Storage Component (C & Rust)
- **Encryption**: Uses AES-256-GCM for file/payload encryption paired with Argon2id key derivation.
- **FUSE Interface**: Mounts encrypted vault payload directories using FUSE 3.
- **WORM Constraints**: Enforces kernel/FUSE level flags to restrict file deletion (`unlink`), renaming, writing, or reading.
- **Integrity & Throttling**: Includes SHA-256 integrity scanning and leaky-bucket access rate limiting.
- **Catalog Management**: Manages vault metadata, password updates, and volume status.

### Interfaces
- **CLI**: Command-line interface (`Nuk4sd`) accepting vault management and process sandboxing options.
- **Interactive REPL**: Terminal shell for managing vaults and executing isolated processes.
- **DSL Parsing**: Experimental C parser (`Nukfile`) for declarative environment configurations.

## Requirements & Platform Limits

- **Host OS**: Linux kernel 5.13+ (required for Landlock LSM support).
- **Dependencies**: GCC/Clang, Rust toolchain (1.70+), `libfuse3`, `libssl`, `libseccomp`, `libcap`, `libargon2`.
- **Windows / macOS**: Native execution is not supported due to direct Linux kernel syscall dependencies. Execution on Windows requires WSL2.
- **Unprivileged Execution**: Fanotify monitoring requires `CAP_SYS_ADMIN`. When executed unprivileged, passive FUSE monitoring is used as a fallback.

## Build

To compile the project from source:

```bash
cargo build --release
```

The compiled binary will be placed at `target/release/Nuk4sd`.

## Usage

### Vault Management

```bash
# List configured vaults
Nuk4sd --ls

# Create a new encrypted vault
Nuk4sd --new my_vault --protected

# Mount vault via FUSE
Nuk4sd --vault 1 --mount
```

### Sandbox Execution

```bash
# Run process in isolated environment with disabled network
Nuk4sd --vault 1 --run /usr/bin/python3 --no-net

# Bind mount specific paths as read-only
Nuk4sd --run /bin/bash --ro /usr --tmp-home
```

## CLI Reference

### Vault Options
- `--ls`: List configured vaults and operational state.
- `--new <name>`: Create a vault volume.
- `--path <dir>`: Set storage directory (default: `~/.local/share/Nuk4sd`).
- `--protected`: Enable AES-256-GCM encryption with Argon2id key derivation.
- `--vault <id>`: Select active vault target.
- `--info`: Display metadata and catalog details.
- `--files`: List tracked files and SHA-256 integrity hashes.
- `--scan`: Compute and check SHA-256 file hashes.
- `--encrypt` / `--decrypt`: Encrypt or decrypt vault contents.
- `--mount` / `--umount`: Mount or unmount FUSE filesystem.
- `--export --dest <dir>`: Extract vault contents to specified directory.
- `--rm`: Delete vault volume.
- `--rename <name>`: Rename vault entry in catalog.
- `--passwd`: Change Argon2id vault password.

### Sandbox Options
- `--run <path>`: Executable to launch inside sandbox.
- `--ro <path>`: Bind mount path as read-only.
- `--rw <path>`: Bind mount path as read-write.
- `--blacklist <path>`: Hide path using empty tmpfs mount.
- `--ro-home`: Mount user home directory as read-only.
- `--rw-home`: Mount user home directory as read-write.
- `--tmp-home`: Mount ephemeral home directory in tmpfs.
- `--no-net`: Unshare network namespace (`CLONE_NEWNET`).
- `--unshare-ipc`: Unshare IPC namespace.
- `--unshare-uts`: Unshare UTS namespace.
- `--hostname <name>`: Set custom sandbox hostname.
- `--wayland`: Expose Wayland display socket (read-only).
- `--x11`: Expose X11 display socket (read-only).
- `--audio`: Expose PulseAudio/PipeWire sockets.
- `--gpu`: Expose `/dev/dri` device nodes.
- `--no-dbus`: Block D-Bus session socket.
- `--seccomp-strict`: Apply strict Seccomp-BPF syscall allowlist.
- `--no-seccomp`: Disable Seccomp filtering.
- `--chroot`: Fallback to chroot instead of pivot_root.
- `--permissive`: Relax enforcement for debugging.
- `--audit`: Log execution arguments, environment variables, and mount steps.

### WORM Options
- `--vault <id> --worm-status`: Display active WORM protection flags.
- `--vault <id> --protect-delete`: Block file deletion (`unlink`/`rmdir`).
- `--vault <id> --protect-rename`: Block file and directory renaming.
- `--vault <id> --protect-write`: Block modification of existing files.
- `--vault <id> --protect-read`: Block file read operations.
- `--vault <id> --clear-delete`: Clear deletion protection flag.

## License

Mozilla Public License 2.0 (MPL-2.0). See [LICENSE](LICENSE) for full terms.
