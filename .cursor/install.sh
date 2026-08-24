#!/usr/bin/env bash
# Cloud Agent bootstrap for github.com/oittaa/socat.
#
# Installs the pinned lint/security tools that `make check` needs. Go itself is
# supplied by the base image, and go.mod's `toolchain` directive fetches the
# exact compiler (go1.26.x) on first use, so we do not install Go here.
#
# Idempotent: safe to re-run. Tools land in $(go env GOPATH)/bin, which the
# agent's login shell already has on PATH, so `make lint`/`make gosec` find the
# bare `golangci-lint` and `gosec` binaries.
set -euo pipefail

# Keep these in sync with .github/workflows/ci.yml (golangci-lint-action /
# securego/gosec versions) so local `make check` matches CI.
GOLANGCI_LINT_VERSION="v2.12.2"
GOSEC_VERSION="v2.28.0"

GOBIN="$(go env GOPATH)/bin"
mkdir -p "$GOBIN"
export GOBIN

# Guard on the GOBIN path directly (not `command -v`) so a warm boot skips the
# reinstall even when the install shell's PATH lacks GOBIN.
if [ -x "$GOBIN/golangci-lint" ] &&
	"$GOBIN/golangci-lint" version 2>&1 | grep -q "${GOLANGCI_LINT_VERSION#v}"; then
	echo "golangci-lint ${GOLANGCI_LINT_VERSION} already present"
else
	echo "installing golangci-lint ${GOLANGCI_LINT_VERSION}"
	go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"
fi

# gosec built via `go install` reports its version as "dev", so guard on
# presence only; the pinned version is fixed by the module query below.
if [ -x "$GOBIN/gosec" ]; then
	echo "gosec already present"
else
	echo "installing gosec ${GOSEC_VERSION}"
	go install "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
fi

# Prime the module cache so build/test/e2e runs are fast and offline-safe.
go mod download

echo "socat Cloud Agent environment ready"
