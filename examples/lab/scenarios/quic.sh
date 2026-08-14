#!/usr/bin/env bash
# HTTP over a QUIC byte tunnel (ALPN socat). This is not HTTP/3.
set -euo pipefail
# shellcheck source=lib.sh
. /lab/scenarios/lib.sh

SOCAT_QUIC_LISTEN='socat QUIC-LISTEN:4433,reuseaddr,fork,bind=0.0.0.0,cert=/certs/server.crt,key=/certs/server.key,verify=0 TCP:127.0.0.1:8080'
SOCAT_QUIC_CLIENT='socat TCP4-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1 QUIC:server:4433,verify=1,cafile=/certs/ca.pem'

case "${1:-}" in
  server)
    log "=== quic server ==="
    log "python3 -m http.server 8080 --bind 127.0.0.1"
    log_cmd "$SOCAT_QUIC_LISTEN"
    start_httpd
    exec $SOCAT_QUIC_LISTEN
    ;;
  client)
    log "=== quic client ==="
    log_cmd "$SOCAT_QUIC_CLIENT"
    log_cmd "curl -fsS http://127.0.0.1:8080/"
    $SOCAT_QUIC_CLIENT &
    body=""
    i=0
    while [[ $i -lt 40 ]]; do
      if body=$(curl_local 2>/dev/null); then
        break
      fi
      i=$((i + 1))
      sleep 0.25
    done
    check_body "${body:-}"
    ;;
  *)
    echo "usage: $0 server|client" >&2
    exit 2
    ;;
esac
