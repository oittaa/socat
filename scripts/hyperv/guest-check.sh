#!/usr/bin/env bash
set -euo pipefail

readonly classic_source="${SOCAT_CLASSIC_SOURCE:-/opt/socat-classic}"
readonly classic_commit='12c08bf66d709fba17035ce95d85bd218428d9ba'
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
if [[ ! -d "$classic_source/.git" ]]; then
  echo "classic socat checkout is missing: $classic_source" >&2
  exit 1
fi

# The provisioned checkout is intentionally owned by root. Trust only this
# pinned path for this process and its child tests; do not alter global Git
# configuration in the disposable guest.
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0='safe.directory'
export GIT_CONFIG_VALUE_0="$classic_source"
actual_classic_commit="$(git -C "$classic_source" rev-parse HEAD)"
if [[ "$actual_classic_commit" != "$classic_commit" ]]; then
  echo "classic socat checkout is $actual_classic_commit, want $classic_commit" >&2
  exit 1
fi

echo '==> loading real Linux AF_VSOCK loopback transport'
sudo modprobe vsock_loopback

echo '==> running complete pre-commit validation'
export SOCAT_CLASSIC_SOURCE="$classic_source"
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
