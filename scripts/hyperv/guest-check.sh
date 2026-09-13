#!/usr/bin/env bash
set -euo pipefail

readonly lint_cache="$(mktemp -d)"
trap 'rm -rf "$lint_cache"' EXIT

if [[ "$(uname -s)" != 'Linux' ]]; then
  echo 'Hyper-V guest check requires Linux' >&2
  exit 1
fi
if [[ ! -f /var/lib/socat-lab/provisioned ]]; then
  echo 'guest is not provisioned; run socat-classic-lab.ps1 provision' >&2
  exit 1
fi
if ! command -v systemd-socket-activate >/dev/null 2>&1; then
  echo 'systemd-socket-activate is missing; re-run socat-classic-lab.ps1 provision' >&2
  exit 1
fi
echo '==> loading real Linux AF_VSOCK loopback transport'
sudo modprobe vsock_loopback

echo '==> running complete pre-commit validation'
# golangci-lint records absolute source paths. Each check uses a disposable
# worktree, so isolate this cache while retaining Go's reusable build cache.
export GOLANGCI_LINT_CACHE="$lint_cache"
make check
