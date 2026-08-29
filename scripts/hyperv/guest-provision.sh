#!/usr/bin/env bash
set -euo pipefail

GO_VERSION="${GO_VERSION:-1.27.0}"
GOLANGCI_LINT_VERSION="${GOLANGCI_LINT_VERSION:-v2.13.1}"
GOSEC_VERSION="${GOSEC_VERSION:-v2.28.0}"
GUEST_USER="${SOCAT_GUEST_USER:-socat-user}"
CLASSIC_PARITY_WORKDIR='/var/lib/socat-lab/classic-parity'

if [[ "$(id -u)" -ne 0 ]]; then
  echo "guest-provision.sh must run as root" >&2
  exit 2
fi
if [[ ! "$GUEST_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || ! id "$GUEST_USER" >/dev/null 2>&1; then
  echo "invalid guest user: $GUEST_USER" >&2
  exit 2
fi
GUEST_GROUP="$(id -gn "$GUEST_USER")"

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  autoconf \
  automake \
  build-essential \
  ca-certificates \
  curl \
  dnsutils \
  expect \
  file \
  git \
  iproute2 \
  iptables \
  iputils-ping \
  jq \
  kmod \
  libbsd-dev \
  liblzma-dev \
  libreadline-dev \
  libssl-dev \
  libzstd-dev \
  net-tools \
  netcat-openbsd \
  nftables \
  openssh-client \
  openssl \
  pkg-config \
  procps \
  psmisc \
  python3 \
  python3-venv \
  strace \
  systemd-container \
  tcpdump \
  util-linux \
  xz-utils \
  zlib1g-dev

# Optional packages differ between Ubuntu releases. Missing packages should
# reduce classic coverage, not abort the complete lab provisioning process.
for package in libwrap0-dev libsctp-dev lksctp-tools; do
  if apt-cache show "$package" >/dev/null 2>&1; then
    apt-get install -y --no-install-recommends "$package"
  else
    echo "optional package unavailable: $package" >&2
  fi
done

for module in tun sctp dccp dccp_ipv4 dccp_ipv6; do
  modprobe "$module" 2>/dev/null || true
done

install_go() {
  local installed=""
  if [[ -x /usr/local/go/bin/go ]]; then
    installed="$(/usr/local/go/bin/go env GOVERSION 2>/dev/null || true)"
  fi
  if [[ "$installed" == "go${GO_VERSION}" ]]; then
    return
  fi

  local metadata archive sha expected actual
  metadata="$(mktemp)"
  archive="$(mktemp --suffix=.tar.gz)"
  trap 'rm -f "$metadata" "$archive"' RETURN

  curl --fail --location --retry 5 \
    'https://go.dev/dl/?mode=json&include=all' >"$metadata"
  expected="$(jq -r --arg version "go${GO_VERSION}" '
    .[] | select(.version == $version) | .files[] |
    select(.os == "linux" and .arch == "amd64" and .kind == "archive") | .sha256
  ' "$metadata")"
  if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
    echo "could not obtain the official checksum for Go ${GO_VERSION}" >&2
    exit 1
  fi

  curl --fail --location --retry 5 \
    --output "$archive" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  actual="$(sha256sum "$archive" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "Go archive checksum mismatch: got $actual, want $expected" >&2
    exit 1
  fi

  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$archive"
}

install_go
cat >/etc/profile.d/go.sh <<'EOF'
export PATH=/usr/local/go/bin:$PATH
EOF

# Keep the clean VM checkpoint capable of running the repository's mandatory
# `make check` target. These versions match .github/workflows/ci.yml.
# Pin GOTOOLCHAIN so `go install pkg@version` does not switch to the tool
# module's older go.mod toolchain (golangci-lint cannot lint a newer Go).
GOBIN=/usr/local/bin GOTOOLCHAIN="go${GO_VERSION}" /usr/local/go/bin/go install \
  "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"
GOBIN=/usr/local/bin GOTOOLCHAIN="go${GO_VERSION}" /usr/local/go/bin/go install \
  "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"

install -d -m 0755 /var/lib/socat-lab
install -d -m 0755 -o "$GUEST_USER" -g "$GUEST_GROUP" "$CLASSIC_PARITY_WORKDIR"
if command -v lsb_release >/dev/null 2>&1; then
  ubuntu_release="$(lsb_release -ds)"
else
  # shellcheck disable=SC1091
  . /etc/os-release
  ubuntu_release="$PRETTY_NAME"
fi
cat >/var/lib/socat-lab/provisioned <<EOF
ubuntu=$ubuntu_release
kernel=$(uname -r)
go=$(/usr/local/go/bin/go version)
golangci_lint_version=$GOLANGCI_LINT_VERSION
gosec_version=$GOSEC_VERSION
classic_parity_workdir=$CLASSIC_PARITY_WORKDIR
provisioned_at=$(date --iso-8601=seconds)
EOF

echo "socat Hyper-V guest provisioning complete"
cat /var/lib/socat-lab/provisioned
