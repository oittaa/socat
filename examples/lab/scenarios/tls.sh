#!/usr/bin/env bash
# Wrap a local HTTP file server with OPENSSL-LISTEN.
# curl (a real TLS client) talks HTTPS to the other container.
set -euo pipefail
# shellcheck source=lib.sh
. /lab/scenarios/lib.sh

SOCAT_TLS_LISTEN='socat OPENSSL-LISTEN:443,reuseaddr,fork,bind=0.0.0.0,cert=/certs/server.crt,key=/certs/server.key,verify=0 TCP:127.0.0.1:8080'
CURL_TLS='curl -fsS --cacert /certs/ca.pem https://server/'

case "${1:-}" in
  server)
    log "=== tls server ==="
    log "python3 -m http.server 8080 --bind 127.0.0.1"
    log_cmd "$SOCAT_TLS_LISTEN"
    start_httpd
    exec $SOCAT_TLS_LISTEN
    ;;
  client)
    log "=== tls client ==="
    log_cmd "$CURL_TLS"
    wait_tcp server 443 60
    body="$($CURL_TLS)"
    check_body "$body"
    ;;
  *)
    echo "usage: $0 server|client" >&2
    exit 2
    ;;
esac
