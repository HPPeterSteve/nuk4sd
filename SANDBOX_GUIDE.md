# Nuk4sd Sandbox Guide

This guide details how to use the Nuk4sd secure environment (sandbox) to run graphical applications and CLI utilities. With recent security updates (such as granular Seccomp filters and kernel audit logs), the sandbox provides maximum isolation with full observability.

## 1. Running Programs via CLI

To run a program inside the isolated vault, use the `--run` flag:

```bash
# Basic Format
Nuk4sd --vault <id> --run <executable> [-- program_args]

# Example: Running a protected bash shell (assuming system mounts)
Nuk4sd --vault 1 --ro /bin --ro /lib --ro /usr --run /bin/bash
```

The command executes the program by performing `pivot_root` into your vault, dropping all Linux capabilities (`NO_NEW_PRIVS`), and enabling Seccomp filters.

## 2. Controlling Seccomp-BPF

The Seccomp implementation is hardened to block common exploit vectors, specifically abusive flags in `clone()` (such as `CLONE_NEWUSER`). Three approaches are available:

*   **Default**: Allows full I/O, sockets, and basic memory usage, as well as `clone3` used in recent glibc releases.
*   **Strict (`-q` or `--seccomp-strict`)**: Aggressively blocks Sockets, Shared Memory (shm), and `clone3`. Restricts the app to the maximum degree, preventing inter-process communication relying on these syscalls.
*   **Clone3 Allow (`-k` or `--allow-clone3`)**: Creates an exception in strict mode specifically for `clone3`. Extremely useful for modern programs that break without thread creation via `clone3`, but where network/socket access remains undesirable.

**Maximum Protection Example**:
```bash
Nuk4sd --vault 1 --run secret_app --seccomp-strict --allow-clone3 
```

## 4. Using Profiles

Rather than passing long CLI flags every time you launch a program, you can create ready-to-use `.conf` profile files.

### 4.1. Creating a Profile

Create a file at `~/.config/Nuk4sd/browser.conf`:

```text
# Strict Browser Profile
--no-net
--wayland
--ro /usr
--ro /lib
--ro-home
--blacklist ~/.ssh
--blacklist ~/.gnupg
--audit
```

### 4.2. Loading a Profile

To execute with the profile:

```bash
Nuk4sd --vault 1 --profile ~/.config/Nuk4sd/browser.conf --run firefox
```

Nuk4sd reads each flag and configures all bind mounts (`--ro`, `--rw`, `--blacklist`) and graphical isolation options (`--wayland`, `--x11`) in a single step.

## 5. Essential Isolation Flags

Here are crucial flags used for running programs:

*   **Bind Mounts:** `--ro <path>`, `--rw <path>`, `--blacklist <path>` (hides directory).
*   **Networking:** `--no-net` (creates a new network namespace, isolating it from the internet).
*   **Graphics:** `--wayland` and `--x11` (mounts necessary display sockets, allowing GUI rendering from inside the vault).
*   **Environment/Home Directories:** `--ro-home` (makes user home directory read-only) and `--tmp-home` (provides a temporary ephemeral `/home` that disappears upon closing).
*   **D-Bus:** `--no-dbus` (Isolates from host session D-Bus).

## 6. Hardened GUI Application Execution Example

To execute a secret PDF reader inside vault ID 3, bind-mounting system binaries in read-only mode while ensuring WORM protection and Wayland isolation:

```bash
Nuk4sd --vault 3 \
  --ro /bin --ro /usr --ro /lib --ro /etc \
  --run zathura \
  --wayland \
  --no-net \
  --seccomp-strict \
  --allow-clone3 \
  -- secret_document.pdf
```
