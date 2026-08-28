#!/usr/bin/env bash
# Run Linux tests that need root in a privileged container.
# Host non-root cannot create /run/netns, call setns, or open SOCK_RAW.
#
# Usage:
#   ./scripts/docker-netns-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="${IMAGE:-golang:1.27}"
GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
docker run --rm --privileged \
  -v "$ROOT:/src" \
  -v "$GOMODCACHE:/go/pkg/mod:ro" \
  -w /src \
  -e CGO_ENABLED=0 \
  -e GOPROXY=off \
  -e GOFLAGS="${GOFLAGS:-}" \
  -e SOCAT_REQUIRE_RAWIP=1 \
  "$IMAGE" \
  bash -c 'set -euo pipefail
apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 >/dev/null
go test -count=1 -timeout 180s ./internal/xio/ -run "TestNetNS|TestWithNetNSRestoreOnPanic|TestLookupResolver|TestWrapNetNS"
go test -v -count=1 -timeout 30s ./internal/xio/ -run "^TestIP4RecvfromNonForkPIPEEcho$"'
