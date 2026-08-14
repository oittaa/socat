#!/usr/bin/env bash
# ROLE=server|client  SCENARIO=tls|quic|socks5|wss
set -euo pipefail
if [[ -z "${SCENARIO:-}" || -z "${ROLE:-}" ]]; then
  echo "SCENARIO and ROLE must be set" >&2
  exit 2
fi
script="/lab/scenarios/${SCENARIO}.sh"
if [[ ! -f "$script" ]]; then
  echo "unknown scenario: $SCENARIO" >&2
  exit 2
fi
# shellcheck source=/dev/null
exec bash "$script" "$ROLE"
