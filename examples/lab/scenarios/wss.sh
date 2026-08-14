#!/usr/bin/env bash
# HTTP over a WSS (TLS WebSocket) byte tunnel.
set -euo pipefail
# shellcheck source=lib.sh
. /lab/scenarios/lib.sh

SOCAT_WSS_LISTEN='socat WSS-LISTEN:443,reuseaddr,fork,bind=0.0.0.0,cert=/certs/server.crt,key=/certs/server.key,verify=0 TCP:127.0.0.1:8080'
SOCAT_WSS_CLIENT='socat TCP4-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1 WSS:server:443,verify=1,cafile=/certs/ca.pem'

case "${1:-}" in
  server)
    log "=== wss server ==="
    log "python3 -m http.server 8080 --bind 127.0.0.1"
    log_cmd "$SOCAT_WSS_LISTEN"
    start_httpd
    exec $SOCAT_WSS_LISTEN
    ;;
  client)
    log "=== wss client ==="
    log_cmd "$SOCAT_WSS_CLIENT"
    log_cmd "curl -fsS http://127.0.0.1:8080/"
    wait_tcp server 443 60
    $SOCAT_WSS_CLIENT &
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
