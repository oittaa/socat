#!/usr/bin/env bash
# Keep classic TUNREAD's virtual net off the host/container as a local address.
#
# Classic test.sh sets TUNNET=a.b.c and sends UDP to a.b.c.2. That peer must
# stay remote so the packet exits the TUN device. Do not patch test.sh: read
# TUNNET= from the file we are about to run (survives a classic git sync).
#
# Usage:
#   classic-tunnet-guard.sh /path/to/test.sh
#
# CLASSIC_FIX_TUNNET=1  — delete colliding local addresses (container netns)
# CLASSIC_FIX_TUNNET=0  — warn only
# unset: delete when /.dockerenv exists, otherwise warn only
set -euo pipefail

TEST_SH="${1:-}"
if [[ -z "$TEST_SH" || ! -f "$TEST_SH" ]]; then
  echo "classic-tunnet-guard: usage: $0 /path/to/classic/test.sh" >&2
  exit 2
fi

if ! command -v ip >/dev/null 2>&1; then
  echo "classic-tunnet-guard: ip(8) not found; skip" >&2
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "classic-tunnet-guard: python3 not found; skip" >&2
  exit 0
fi

FIX="${CLASSIC_FIX_TUNNET:-}"
if [[ -z "$FIX" ]]; then
  if [[ -f /.dockerenv ]]; then
    FIX=1
  else
    FIX=0
  fi
fi

# Three-octet prefixes only (classic: TUNNET=10.255.255 → peer .2).
mapfile -t TUNNETS < <(sed -n 's/^[[:space:]]*TUNNET=\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)[[:space:]]*$/\1/p' "$TEST_SH" | sort -u)
if [[ ${#TUNNETS[@]} -eq 0 ]]; then
  exit 0
fi

collisions_for() {
  local prefix="$1"
  python3 - "$prefix" <<'PY'
import ipaddress, subprocess, sys
prefix = sys.argv[1]
peer = ipaddress.ip_address(prefix + ".2")
try:
    out = subprocess.check_output(["ip", "-4", "-o", "addr", "show"], text=True)
except (OSError, subprocess.CalledProcessError):
    sys.exit(0)
for line in out.splitlines():
    parts = line.split()
    if len(parts) < 4 or parts[2] != "inet":
        continue
    iface, cidr = parts[1], parts[3]
    if iface.startswith("tun") or iface.startswith("tap"):
        continue
    try:
        ifc = ipaddress.ip_interface(cidr)
    except ValueError:
        continue
    if ifc.ip == peer or peer in ifc.network:
        print(f"{iface} {cidr}")
PY
}

status=0
for prefix in "${TUNNETS[@]}"; do
  peer="${prefix}.2"
  mapfile -t hits < <(collisions_for "$prefix")
  if [[ ${#hits[@]} -eq 0 ]]; then
    continue
  fi
  for hit in "${hits[@]}"; do
    iface="${hit%% *}"
    cidr="${hit##* }"
    echo "classic-tunnet-guard: $cidr on $iface collides with TUNNET=$prefix (TUNREAD peer $peer)" >&2
    if [[ "$FIX" == "1" ]]; then
      if ip addr del "$cidr" dev "$iface"; then
        echo "classic-tunnet-guard: removed $cidr from $iface" >&2
      else
        echo "classic-tunnet-guard: failed to remove $cidr from $iface" >&2
        status=1
      fi
    else
      echo "classic-tunnet-guard: not removing (set CLASSIC_FIX_TUNNET=1 in a disposable netns)" >&2
    fi
  done
done
exit "$status"
