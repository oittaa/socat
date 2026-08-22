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
`golangci-lint` and `gosec` tools needed by `make check`, and classic socat
`tag-1.8.1.3`, including available optional protocol libraries. `checkpoint`
requires successful provisioning, performs a clean guest shutdown, detaches the
cloud-init seed, and records a powered-off `clean-provisioned` checkpoint.

## Routine use

```powershell
./scripts/hyperv/socat-classic-lab.ps1 status
./scripts/hyperv/socat-classic-lab.ps1 reset
```

`reset` deliberately discards changes since `clean-provisioned`, starts the VM,
and waits for SSH. Copy scorecard output back to the Windows repository before
resetting it.
