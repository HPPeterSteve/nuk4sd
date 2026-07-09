# nuk4sd

CLI for managing encrypted vaults on Linux, with a sandbox layer for running
programs isolated inside them.

Status: **beta**. Manually tested on build v0.9.24. There are behaviors
observed during testing that deserve attention before using this in
production — see "Observed limitations" below.

## What it is

Each **vault** is an isolated unit: a directory whose actual content is
stored encrypted (AES-256-GCM) in `~/.local/share/Nuk4sd/cipher_<id>`, and
only exposed via FUSE when you mount the vault or run something inside it.
Otherwise, the vault directory sits at permission `000` (no access, not even
for the owner).

`--run` mounts the vault and also builds a sandbox around the process: new
namespaces, root switched into the vault (pivot_root), and all Linux
capabilities dropped before the program executes.

## Interactive mode

Running with no arguments opens a prompt (`nuk4sd>`), accepting the same
commands line by line, `exit` to quit.

## Commands tested

### Catalog

```
nuk4sd --ls                    # list registered vaults
nuk4sd --version                # binary version
nuk4sd --help                   # full help
```

### Create a vault

```
nuk4sd --new <name> --path <dir>                          # no password
nuk4sd --new <name> --path <dir> --protected --password <pass> --engine <0-5>
```

`--engine` controls the obfuscation level (0 = none, up to 5 = 20 layers +
fake `.enc` file). 

### Query a vault

```
nuk4sd --vault <id> --status            # OK / LOCKED / ALERT / DELETED
nuk4sd --vault <id> --info              # name, type, path, file count, etc.
nuk4sd --vault <id> --files             # tracked files + hash
nuk4sd --vault <id> --scan              # integrity scan (SHA-256)
```

`--json` works on `--status` and `--scan`, compact output like
`{"id":1,"status":"OK"}`.

### Run a program inside the vault

```
nuk4sd --vault <id> --run <program> [isolation flags] -- [program args]
```

Isolation flags tested: `--ro <path>`, `--rw <path>`, `--no-net`, `--audit`.
The rest (`--wayland`, `--x11`, `--no-dbus`, `--unshare-ipc`,
`--unshare-uts`, `--no-proc`, `--blacklist`, `--profile`) show up in
`--help` but I did not test them individually.

### Delete / manage a vault

```
nuk4sd --vault <id> --rm                          # delete vault (asks for password if protected)
nuk4sd --vault <id> --passwd                      # change password
nuk4sd --vault <id> --worm-status                 # show active WORM protection flags
nuk4sd --vault <id> --protect-delete/--protect-write/...   # block operations on the vault
```

## Observed limitations

This is what I saw running the binary, not a code audit — treat it as a
starting point for investigation, not a final verdict.

- **The `--run` sandbox is an empty jail.** It does a `pivot_root` into the
  vault content, so host binaries (`bash`, `echo`, etc.) don't show up
  inside the sandbox by default. I tested with `--ro /bin --ro /usr --ro
  /lib --ro /lib64` and the binary was still not found after the pivot —
  the audit log confirms the binds were registered, but `execvp` kept
  failing. I don't know if this is a mount-ordering bug, an intentional
  design limit (only run what's already inside the vault), or a mistake on
  my end. Worth investigating before relying on `--run` to execute system
  programs.
- **Silent dependency auto-install.** When it couldn't find a shell inside
  the jail, `nuk4sd` tried installing `busybox-static` on the host via
  `apt-get install` on its own, without asking for confirmation first.
  This isn't documented in `--help`. It's a side effect that changes the
  host system outside the vault — good to know before running this in CI
  or on a third-party machine.
- **`--status` on a nonexistent vault doesn't error out.** `nuk4sd --vault
  99 --status` (an id that never existed) returned `DELETED` with exit
  code 0, instead of an error / nonzero exit code. If a script relies on
  the exit code to check whether the vault exists, this could be
  confusing.
- **Verbose logging by default.** Every `--run` produces a lot of log
  lines (including expected FUSE `getattr` errors during mount), even
  without `--verbose`. Can clutter output in automated scripts.
- Not tested: manual `--mount`/`--umount`, `--export`, `--mount-export`,
  `--rename`, `--unlock`, `--rule`/`--hours`, or `--engine` levels beyond
  0 and 1.

## Observed requirements

- I ran it as root — did not test whether it works without elevated
  privileges (pivot_root and some namespace operations usually require
  `CAP_SYS_ADMIN` or user namespaces enabled).
- `fusermount3` needs to be available.
- `apt-get` reachable, in case the `busybox-static` auto-install gets
  triggered.

## Similar projects / inspired by

Tools that solve parts of the same problem (process isolation via
namespaces, or encrypted vaults via FUSE), split by area:

**Namespace-based sandboxing**
- [Firejail](https://github.com/netblue30/firejail) — namespace + seccomp-bpf
  based sandbox, with ready-made per-application profiles.
- [Bubblewrap](https://github.com/containers/bubblewrap) — low-level tool
  for building sandboxes without root privileges, the base of Flatpak.
- [Snap (snapd)](https://snapcraft.io/) and [Flatpak](https://flatpak.org/)
  — packaging with a built-in sandbox (Flatpak uses bubblewrap under the
  hood).
- [systemd-nspawn](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html)
  — namespaces + lightweight containers, aimed at system administration.
- [gVisor](https://gvisor.dev/) — sandbox at a different layer (intercepts
  syscalls in user space), stronger isolation than plain namespaces.

**Encrypted vaults / FUSE filesystems**
- [gocryptfs](https://github.com/rfjakob/gocryptfs) — per-file encrypted
  filesystem, mounted via FUSE.
- [EncFS](https://github.com/vgough/encfs) — same idea, older, with a
  documented history of security flaws.
- [CryFS](https://www.cryfs.org/) — per-file/block encryption via FUSE,
  aimed at use with cloud sync services.
- [VeraCrypt](https://veracrypt.fr/) — encrypted volume/container vault,
  no sandbox built in.
- [gocryptfs vs EncFS vs CryFS](https://nuetzlich.net/gocryptfs/comparison/)
  — technical comparison between the three, useful for understanding the
  design space nuk4sd also occupies on the vault side.

None of these tools combine both things (encrypted vault + execution
sandbox) in a single binary the way nuk4sd sets out to — the combination
itself is the design differentiator, not a missing feature in the others.
