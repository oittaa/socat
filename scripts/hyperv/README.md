# Hyper-V classic test lab

This lab runs Ubuntu 26.04 LTS directly under Hyper-V for high-fidelity classic
`test.sh` coverage. It uses Hyper-V's existing `Default Switch`, so it does not
create or alter host NAT, IP addresses, or physical network adapters.

The VM defaults are:

- name: `socat-classic-ubuntu2604`
- Generation 2 with Linux Secure Boot
- 6 virtual CPUs, 12 GiB static memory
- 64 GiB dynamically expanding VHDX
- cloud-init SSH user: `socat-user` (configurable, key only, passwordless sudo)

To use a different generic lab account, pass the same `-GuestUser <name>` value
to every action. The default does not depend on the Windows account name.

Generated images, SSH keys, disks, seed data, and state are kept outside the
repository under `%LOCALAPPDATA%\socat-hyperv`.

## One-time host prerequisite

The official Ubuntu cloud image is QCOW2. Install QEMU's `qemu-img` converter
from an elevated PowerShell:

```powershell
winget install --exact --id SoftwareFreedomConservancy.QEMU
```

The account running the script must be in the local `Hyper-V Administrators`
group. The script itself does not need to run elevated.

## Create and provision

Run these from a PowerShell process that can manage Hyper-V:

```powershell
./scripts/hyperv/socat-classic-lab.ps1 download
./scripts/hyperv/socat-classic-lab.ps1 create
./scripts/hyperv/socat-classic-lab.ps1 provision
./scripts/hyperv/socat-classic-lab.ps1 checkpoint
```

`download` verifies Canonical's pinned SHA-256. `create` refuses to overwrite an
existing VM or disk. `provision` installs the Go toolchain, the CI-pinned
`golangci-lint` and `gosec` tools needed by `make check`, the `systemd`
package (for `systemd-socket-activate` / classic `ACCEPT_FD`), plus the
build dependencies used by `make classic-parity`. It fails if
`systemd-socket-activate` is missing. `checkpoint` requires successful
provisioning, performs a clean guest shutdown, detaches the cloud-init seed, and
records a powered-off `clean-provisioned` checkpoint.

## Routine use

```powershell
./scripts/hyperv/socat-classic-lab.ps1 status
./scripts/hyperv/socat-classic-lab.ps1 reset
./scripts/hyperv/socat-classic-lab.ps1 check
./scripts/hyperv/socat-classic-lab.ps1 parity
```

`reset` deliberately discards changes since `clean-provisioned`, starts the VM,
and waits for SSH. Copy scorecard output back to the Windows repository before
resetting it.

`check` packages the current Windows working tree into an isolated guest
directory and runs the complete Linux `make check`. It loads the kernel's real
AF_VSOCK loopback transport and then reruns every `TestVSOCK` with caching
disabled; any VSOCK skip fails the check. It does not contact repo.or.cz. The
guest directory is removed after the run.

`parity` runs `make classic-parity` in the same kind of isolated guest directory.
Its official source cache is persistent at
`/var/lib/socat-lab/classic-parity`; the repository URL, release, and reviewed
master commits come only from `scripts/classic-baseline.json`. The first run
clones the official repository, and later runs fetch into that same cache.

By default `check` reuses the running VM and its Go caches. Use
`-ResetBeforeCheck` for validation from the `clean-provisioned` checkpoint, or
`-KeepGuestWorktree` to retain the isolated guest source tree for debugging:

```powershell
./scripts/hyperv/socat-classic-lab.ps1 check -ResetBeforeCheck
./scripts/hyperv/socat-classic-lab.ps1 check -KeepGuestWorktree
```

The runner verifies that Go, `golangci-lint`, `gosec`, and
`systemd-socket-activate` exist before copying the workspace. `parity` also
requires its persistent cache directory. If an older checkpoint lacks the
required setup, the runner provisions it automatically; subsequent runs keep
the warm caches.
