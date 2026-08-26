#!/usr/bin/env bash
# Cloud Agent bootstrap for github.com/oittaa/socat.
#
# Installs the pinned lint/security tools that `make check` needs. Go itself is
# supplied by the base image, and go.mod's `toolchain` directive fetches the
# exact compiler (go1.27.x) on first use, so we do not install Go here.
#
# The Makefile invokes the bare `golangci-lint` and `gosec` binaries, but the
# agent shell does not add $(go env GOPATH)/bin to PATH. So after building each
# tool we place it on a directory that is already on PATH (mirroring the repo's
# own `make install`, which targets /usr/local/bin) so `make lint`/`make gosec`
# resolve them in any shell. Idempotent: safe to re-run.
set -euo pipefail

# Keep these in sync with .github/workflows/ci.yml (golangci-lint-action /
# securego/gosec versions) so local `make check` matches CI.
GOLANGCI_LINT_VERSION="v2.13.1"
GOSEC_VERSION="v2.28.0"

GOBIN="$(go env GOPATH)/bin"
mkdir -p "$GOBIN"
export GOBIN

# Pick a bin directory that is already on PATH and installable. Prefer the
# standard /usr/local/bin (via sudo when needed); fall back to a writable
# on-PATH directory if sudo is unavailable.
if [ -w /usr/local/bin ]; then
	BINDIR=/usr/local/bin
	SUDO=""
elif sudo -n true 2>/dev/null; then
	BINDIR=/usr/local/bin
	SUDO="sudo"
elif [ -w /usr/local/cargo/bin ]; then
	BINDIR=/usr/local/cargo/bin
	SUDO=""
else
	BINDIR="$GOBIN"
	SUDO=""
fi
echo "placing tools in ${BINDIR}"

place_on_path() { # <name>
	local name="$1"
	[ "$BINDIR" = "$GOBIN" ] && return 0
	$SUDO install -m 0755 "$GOBIN/$name" "$BINDIR/$name"
}

# `go install pkg@version` otherwise follows that module's go.mod and can
# build with an older toolchain. golangci-lint only lints Go versions <= the
# compiler that built it, so build it with the go.mod toolchain.
GO_TOOLCHAIN="$(awk '/^toolchain / { print $2; exit }' go.mod)"

if [ -x "$BINDIR/golangci-lint" ] &&
	"$BINDIR/golangci-lint" version 2>&1 | grep -q "${GOLANGCI_LINT_VERSION#v}" &&
	"$BINDIR/golangci-lint" version 2>&1 | grep -q "built with ${GO_TOOLCHAIN}"; then
	echo "golangci-lint ${GOLANGCI_LINT_VERSION} already present"
else
	echo "installing golangci-lint ${GOLANGCI_LINT_VERSION} with ${GO_TOOLCHAIN}"
	GOTOOLCHAIN="${GO_TOOLCHAIN}" go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"
	place_on_path golangci-lint
fi

# gosec built via `go install` reports its version as "dev", so guard on
# presence only; the pinned version is fixed by the module query below.
if [ -x "$BINDIR/gosec" ]; then
	echo "gosec already present"
else
	echo "installing gosec ${GOSEC_VERSION}"
	GOTOOLCHAIN="${GO_TOOLCHAIN}" go install "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
	place_on_path gosec
fi

# Prime the module cache so build/test/e2e runs are fast and offline-safe.
go mod download

echo "socat Cloud Agent environment ready"
