#!/usr/bin/env bash
set -euo pipefail

readonly lint_cache="$(mktemp -d)"
readonly vsock_log="$(mktemp)"
trap 'rm -rf "$lint_cache"; rm -f "$vsock_log"' EXIT

if [[ "$(uname -s)" != 'Linux' ]]; then
  echo 'Hyper-V guest check requires Linux' >&2
  exit 1
fi
if [[ ! -f /var/lib/socat-lab/provisioned ]]; then
  echo 'guest is not provisioned; run socat-classic-lab.ps1 provision' >&2
  exit 1
fi
echo '==> loading real Linux AF_VSOCK loopback transport'
sudo modprobe vsock_loopback

echo '==> running complete pre-commit validation'
# golangci-lint records absolute source paths. Each check uses a disposable
# worktree, so isolate this cache while retaining Go's reusable build cache.
export GOLANGCI_LINT_CACHE="$lint_cache"
make check

echo '==> requiring every VSOCK test to execute without skips'
go test -count=1 -v ./internal/xio/netopen -run '^TestVSOCK' | tee "$vsock_log"
if ! grep -q -- '^=== RUN   TestVSOCK' "$vsock_log"; then
  echo 'no VSOCK tests executed' >&2
  exit 1
fi
if grep -q -- '^[[:space:]]*--- SKIP: TestVSOCK' "$vsock_log"; then
  echo 'one or more required VSOCK tests were skipped' >&2
  exit 1
fi
