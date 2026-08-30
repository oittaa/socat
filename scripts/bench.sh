#!/usr/bin/env bash
# Loopback benchmarks: this Go socat vs classic C (when CLASSIC_SOCAT is set).
# Not part of make test or make e2e.
#
# Usage:
#   ./scripts/bench.sh
#   CLASSIC_SOCAT=/tmp/socat-1.8.1.3/bin/socat ./scripts/bench.sh
#   SIZE=64M RUNS=3 ./scripts/bench.sh tcp udp tls ws wss quic
#   SAVE_BASELINE=testdata/bench/host.json ./scripts/bench.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SKIP_BUILD="${SKIP_BUILD:-0}"
if [[ "$SKIP_BUILD" != "1" ]]; then
  make -s build
fi

SOCAT="${SOCAT:-$ROOT/socat}"
if [[ ! -x "$SOCAT" ]]; then
  echo "socat not found: $SOCAT (run make build)" >&2
  exit 2
fi

OPENSSL_BIN="${OPENSSL_BIN:-$(command -v openssl || true)}"

CLASSIC_SOCAT="${CLASSIC_SOCAT:-}"
if [[ -z "$CLASSIC_SOCAT" ]]; then
  for c in \
    /tmp/socat-1.8.1.3/bin/socat \
    /tmp/socat-1.8.1.3/socat \
    /opt/classic/bin/socat
  do
    if [[ -x "$c" ]]; then
      CLASSIC_SOCAT="$c"
      break
    fi
  done
fi

WORKDIR="${WORKDIR:-$ROOT/testdata/tmp/bench}"
mkdir -p "$WORKDIR/certs" "$WORKDIR/logs"

if [[ -z "${OPENSSL_BIN:-}" || ! -x "$OPENSSL_BIN" ]]; then
  echo "openssl is required (certificates, payload, TLS probe)" >&2
  exit 2
fi

CERT_DIR="$WORKDIR/certs"
umask 077
"$OPENSSL_BIN" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 2 -nodes \
  -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.pem" \
  -subj "/CN=socat-bench-ca" >/dev/null 2>&1
"$OPENSSL_BIN" req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes \
  -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
  -subj "/CN=localhost" >/dev/null 2>&1
cat >"$CERT_DIR/server.ext" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
EOF
"$OPENSSL_BIN" x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial -out "$CERT_DIR/server.crt" -days 2 \
  -extfile "$CERT_DIR/server.ext" >/dev/null 2>&1
rm -f "$CERT_DIR/server.csr" "$CERT_DIR/server.ext" "$CERT_DIR/ca.srl"
chmod 644 "$CERT_DIR/ca.pem" "$CERT_DIR/server.crt"
chmod 600 "$CERT_DIR/server.key" "$CERT_DIR/ca.key"

BENCHCLIENT="${BENCHCLIENT:-$WORKDIR/benchclient}"
if [[ "${SKIP_CLIENT_BUILD:-0}" != "1" ]]; then
  go build -o "$BENCHCLIENT" "$ROOT/scripts/benchclient"
fi
if [[ ! -x "$BENCHCLIENT" ]]; then
  echo "benchclient not found: $BENCHCLIENT" >&2
  exit 2
fi

export SOCAT CLASSIC_SOCAT OPENSSL_BIN WORKDIR BENCHCLIENT
export SIZE="${SIZE:-256M}"
export RUNS="${RUNS:-5}"
export WARMUP="${WARMUP:-1}"
export BUF="${BUF:-8192}"
export BENCH_CA="$CERT_DIR/ca.pem"
export BENCH_CERT="$CERT_DIR/server.crt"
export BENCH_KEY="$CERT_DIR/server.key"
export BENCH_OUT="${BENCH_OUT:-$WORKDIR/results.json}"
export SAVE_BASELINE="${SAVE_BASELINE:-}"
export BENCH_PAYLOAD="${BENCH_PAYLOAD:-}"

if [[ -z "${CLASSIC_SOCAT:-}" ]]; then
  echo "CLASSIC_SOCAT is unset; classic columns will be skipped." >&2
fi

exec python3 "$ROOT/scripts/bench.py" "$@"
