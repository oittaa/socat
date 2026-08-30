#!/usr/bin/env bash
# Loopback benchmarks: this Go socat vs classic C when available.
# Not part of make test or make e2e.
#
# Usage:
#   ./scripts/bench.sh
#   SOCAT_CLASSIC_BIN=/path/to/classic/socat ./scripts/bench.sh
#   SOCAT_BENCH_SIZE=64M SOCAT_BENCH_RUNS=3 ./scripts/bench.sh tcp udp tls ws wss quic
#   SOCAT_BENCH_SAVE_BASELINE=testdata/bench/host.json ./scripts/bench.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

skip_build="${SOCAT_BENCH_SKIP_BUILD:-0}"
if [[ "$skip_build" != "1" ]]; then
  make -s build
fi

SOCAT_BIN="${SOCAT_BIN:-$ROOT/socat}"
if [[ ! -x "$SOCAT_BIN" ]]; then
  echo "socat not found: $SOCAT_BIN (run make build)" >&2
  exit 2
fi

openssl_bin="${SOCAT_BENCH_OPENSSL_BIN:-$(command -v openssl || true)}"

SOCAT_CLASSIC_BIN="${SOCAT_CLASSIC_BIN:-}"
if [[ -z "$SOCAT_CLASSIC_BIN" ]]; then
  path_socat="$(command -v socat || true)"
  if [[ -n "$path_socat" && -x "$path_socat" ]] && ! [[ "$path_socat" -ef "$SOCAT_BIN" ]]; then
    SOCAT_CLASSIC_BIN="$path_socat"
  fi
fi
workdir="${SOCAT_BENCH_WORKDIR:-$ROOT/testdata/tmp/bench}"
mkdir -p "$workdir/certs" "$workdir/logs"

if [[ -z "$openssl_bin" || ! -x "$openssl_bin" ]]; then
  echo "openssl is required (certificates, payload, TLS probe)" >&2
  exit 2
fi

cert_dir="$workdir/certs"
umask 077
"$openssl_bin" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 2 -nodes \
  -keyout "$cert_dir/ca.key" -out "$cert_dir/ca.pem" \
  -subj "/CN=socat-bench-ca" >/dev/null 2>&1
"$openssl_bin" req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes \
  -keyout "$cert_dir/server.key" -out "$cert_dir/server.csr" \
  -subj "/CN=localhost" >/dev/null 2>&1
cat >"$cert_dir/server.ext" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
EOF
"$openssl_bin" x509 -req -in "$cert_dir/server.csr" -CA "$cert_dir/ca.pem" -CAkey "$cert_dir/ca.key" \
  -CAcreateserial -out "$cert_dir/server.crt" -days 2 \
  -extfile "$cert_dir/server.ext" >/dev/null 2>&1
rm -f "$cert_dir/server.csr" "$cert_dir/server.ext" "$cert_dir/ca.srl"
chmod 644 "$cert_dir/ca.pem" "$cert_dir/server.crt"
chmod 600 "$cert_dir/server.key" "$cert_dir/ca.key"

benchclient_bin="${SOCAT_BENCH_CLIENT_BIN:-$workdir/benchclient}"
if [[ "${SOCAT_BENCH_SKIP_CLIENT_BUILD:-0}" != "1" ]]; then
  go build -o "$benchclient_bin" "$ROOT/scripts/benchclient"
fi
if [[ ! -x "$benchclient_bin" ]]; then
  echo "benchclient not found: $benchclient_bin" >&2
  exit 2
fi

export SOCAT_BIN SOCAT_CLASSIC_BIN
export SOCAT_BENCH_OPENSSL_BIN="$openssl_bin"
export SOCAT_BENCH_WORKDIR="$workdir"
export SOCAT_BENCH_CLIENT_BIN="$benchclient_bin"
export SOCAT_BENCH_SIZE="${SOCAT_BENCH_SIZE:-256M}"
export SOCAT_BENCH_RUNS="${SOCAT_BENCH_RUNS:-5}"
export SOCAT_BENCH_WARMUP="${SOCAT_BENCH_WARMUP:-1}"
export SOCAT_BENCH_BUFFER="${SOCAT_BENCH_BUFFER:-8192}"
export SOCAT_BENCH_CA="$cert_dir/ca.pem"
export SOCAT_BENCH_CERT="$cert_dir/server.crt"
export SOCAT_BENCH_KEY="$cert_dir/server.key"
export SOCAT_BENCH_OUT="${SOCAT_BENCH_OUT:-$workdir/results.json}"
export SOCAT_BENCH_SAVE_BASELINE="${SOCAT_BENCH_SAVE_BASELINE:-}"
export SOCAT_BENCH_PAYLOAD="${SOCAT_BENCH_PAYLOAD:-}"

if [[ -z "${SOCAT_CLASSIC_BIN:-}" ]]; then
  echo "SOCAT_CLASSIC_BIN is unset and socat was not found on PATH; classic columns will be skipped." >&2
fi

exec python3 "$ROOT/scripts/bench.py" "$@"
