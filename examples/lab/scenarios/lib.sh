# Shared helpers for lab scenarios. Source from a scenario script.
# shellcheck shell=bash

MARKER="lab-ok"

log() { printf '%s\n' "$*"; }
log_cmd() { printf '+ %s\n' "$*"; }

wait_tcp() {
  local host="$1" port="$2" tries="${3:-50}"
  local i
  for i in $(seq 1 "$tries"); do
    if timeout 1 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  log "timeout waiting for ${host}:${port}"
  return 1
}

start_httpd() {
  local dir="${1:-/tmp/lab-www}"
  mkdir -p "$dir"
  printf '%s\n' "$MARKER" >"$dir/index.html"
  python3 -m http.server 8080 --bind 127.0.0.1 --directory "$dir" &
  wait_tcp 127.0.0.1 8080 50
}

check_body() {
  local body="$1"
  printf '%s\n' "$body"
  echo "$body" | grep -q "$MARKER"
}

curl_local() {
  curl -fsS --max-time 10 http://127.0.0.1:8080/
}
