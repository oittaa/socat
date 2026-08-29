#!/usr/bin/env bash
# Make a short-lived lab CA and a server cert with SAN DNS:server.
# Usage: gen.sh [outdir]   (default: directory of this script / out)
set -euo pipefail

OUT="${1:-}"
if [[ -z "$OUT" ]]; then
  OUT="$(cd "$(dirname "$0")" && pwd)/out"
fi
mkdir -p "$OUT"
cd "$OUT"

umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -sha256 -days 2 -nodes \
  -keyout ca.key -out ca.pem \
  -subj "/CN=socat-lab-ca" >/dev/null 2>&1

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -sha256 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=server" >/dev/null 2>&1

cat >server.ext <<'EOF'
subjectAltName=DNS:server
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out server.crt -days 2 \
  -extfile server.ext >/dev/null 2>&1

rm -f server.csr server.ext ca.srl
chmod 644 ca.pem server.crt
chmod 600 server.key ca.key
echo "wrote $OUT/ca.pem $OUT/server.crt $OUT/server.key"
