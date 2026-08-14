#!/usr/bin/env bash
# SOCKS5 client wrap. microsocks is the real SOCKS daemon on server.
# Target 127.0.0.1:8080 is the HTTP app on the SOCKS host (server).
set -euo pipefail
# shellcheck source=lib.sh
. /lab/scenarios/lib.sh

SOCAT_SOCKS_CLIENT='socat TCP4-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1 SOCKS5:server:127.0.0.1:8080,socksport=1080'

case "${1:-}" in
  server)
    log "=== socks5 server ==="
    log "python3 -m http.server 8080 --bind 127.0.0.1"
    log "microsocks -i 0.0.0.0 -p 1080"
    start_httpd
    microsocks -i 0.0.0.0 -p 1080 &
    wait_tcp 127.0.0.1 1080 50
    wait
    ;;
  client)
    log "=== socks5 client ==="
    log_cmd "$SOCAT_SOCKS_CLIENT"
    log_cmd "curl -fsS http://127.0.0.1:8080/"
    wait_tcp server 1080 60
    $SOCAT_SOCKS_CLIENT &
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
