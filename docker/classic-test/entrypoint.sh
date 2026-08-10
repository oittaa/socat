#!/usr/bin/env bash
# Entrypoint for socat-classic-test image.
# Prepares network for classic test.sh, then runs scripts/classic-scorecard.sh.
set -euo pipefail

export PATH="${CLASSIC_PREFIX:-/opt/classic}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Classic test.sh / socat expect a normal login-like environment.
# Minimal docker images leave these empty → ABSTRACT_USER, SHELL:*, TIOCSWINSZ fail.
export USER="${USER:-$(id -un)}"
export LOGNAME="${LOGNAME:-$USER}"
export HOME="${HOME:-$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6)}"
export HOME="${HOME:-/root}"
export SHELL="${SHELL:-/bin/bash}"
export TERM="${TERM:-xterm}"

echo "=== socat scorecard container ==="
echo "  uid=$(id -u) gid=$(id -g) user=$(id -un) USER=$USER SHELL=$SHELL"
echo "  LABEL=${LABEL:-}"
echo "  SOCAT=${SOCAT:-}"
echo "  FILAN=${FILAN:-}"
echo "  PROCAN=${PROCAN:-}"
echo "  MODE=${MODE:-classic}"
echo "  OUT_DIR=${OUT_DIR:-/out}"
echo "  CLASSIC_TEST_SH=${CLASSIC_TEST_SH:-/opt/classic-src/test.sh}"
if [[ -n "${SOCAT:-}" && -x "${SOCAT}" ]]; then
  "${SOCAT}" -V 2>&1 | head -8 || true
elif [[ -n "${SOCAT:-}" ]]; then
  echo "  warning: SOCAT not executable: $SOCAT" >&2
fi

# --- network prep (root + NET_ADMIN) ---
# Entire 127/8 is loopback on Linux; classic uses SECONDADDR=127.1.0.1.
ip link set lo up 2>/dev/null || true
# Ensure IPv6 loopback is usable for UDP6/TCP6 tests.
sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1 || true
# Some raw/multicast tests are happier with rp_filter relaxed in the ns.
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true

# Optional second interface address for tests that bind non-127 IPs.
# Prefer eth0/en* if present (bridge network).
for ifc in eth0 ens3 enp0s3; do
  if ip link show "$ifc" >/dev/null 2>&1; then
    # Add a secondary /32 only if not already present (idempotent).
    if ! ip -4 addr show dev "$ifc" | grep -q ' 10.255.255.2/'; then
      ip addr add 10.255.255.2/32 dev "$ifc" 2>/dev/null || true
    fi
    break
  fi
done

mkdir -p "${OUT_DIR:-/out}"

# Host-mounted baselines (optional)
BASELINE_ARG=()
if [[ -n "${BASELINE:-}" && -f "${BASELINE}" ]]; then
  BASELINE_ARG+=(BASELINE="${BASELINE}")
fi
# Default save path depends on which binary we exercise.
if [[ -z "${SAVE_BASELINE:-}" ]]; then
  if [[ "${LABEL:-classic}" == "go" ]]; then
    SAVE_BASELINE="${OUT_DIR}/go-docker-baseline.json"
  else
    SAVE_BASELINE="${OUT_DIR}/classic-docker-baseline.json"
  fi
fi
SAVE="$SAVE_BASELINE"

cd /opt/scorecard

# LABEL=go defaults to /opt/go/* when present; classic stays at /opt/classic.
if [[ "${LABEL:-}" == "go" ]]; then
  export SOCAT="${SOCAT:-/opt/go/socat}"
  export FILAN="${FILAN:-/opt/go/filan}"
  export PROCAN="${PROCAN:-/opt/go/procan}"
else
  export SOCAT="${SOCAT:-/opt/classic/bin/socat}"
  export FILAN="${FILAN:-/opt/classic/bin/filan}"
  export PROCAN="${PROCAN:-/opt/classic/bin/procan}"
fi
export SKIP_BUILD="${SKIP_BUILD:-1}"
export LABEL="${LABEL:-classic}"
export MODE="${MODE:-classic}"
export OUT_DIR="${OUT_DIR:-/out}"
export SAVE_BASELINE="$SAVE"
export JOBS="${JOBS:-1}"
export VAL_T="${VAL_T:-auto}"
export SHARD_TIMEOUT="${SHARD_TIMEOUT:-7200}"
export REGRESSION_EXIT="${REGRESSION_EXIT:-0}"
# Allow ONLY / MAX_N / BASELINE from caller env.
export ONLY="${ONLY:-}"
export MAX_N="${MAX_N:-}"
export BASELINE="${BASELINE:-}"
export KEEP_LOGS="${KEEP_LOGS:-1}"

TEST_SH="${CLASSIC_TEST_SH:-/opt/classic-src/test.sh}"
if [[ ! -f "$TEST_SH" ]]; then
  echo "error: classic test.sh not found at $TEST_SH" >&2
  exit 2
fi

# Extra args: only treat as test.sh override when the path looks like test.sh.
# (Avoid "docker run image /opt/go/socat -V" stealing the binary path as TEST_SH.)
if [[ $# -gt 0 && -f "${1:-}" && "$(basename "$1")" == "test.sh" ]]; then
  TEST_SH="$1"
  shift
elif [[ $# -gt 0 ]]; then
  # Non-scorecard command: exec it (debug shell, socat -V, …).
  exec "$@"
fi

echo "=== starting classic-scorecard.sh ==="
set +e
/opt/scorecard/scripts/classic-scorecard.sh "$TEST_SH" "$@"
ec=$?
set -e

echo "=== scorecard exit=$ec ==="
if [[ -f "${OUT_DIR}/results.json" ]]; then
  python3 - <<PY
import json
from pathlib import Path
p = Path("${OUT_DIR}/results.json")
d = json.loads(p.read_text())
s = d.get("summary", {})
print(f"results: OK={s.get('ok')} FAILED={s.get('failed')} CANT={s.get('cant')} "
      f"TIMEOUT={s.get('timeout')} UNKNOWN={s.get('unknown')} total={s.get('total_recorded')}")
PY
fi

# Optional: verify host baseline OK ⊆ docker OK (classic image smoke only).
# Skip for LABEL=go unless VERIFY_HOST=1 (host baseline is non-root classic).
if [[ -n "${HOST_BASELINE:-}" && -f "${HOST_BASELINE}" && -f "${OUT_DIR}/results.json" ]] \
   && { [[ "${LABEL:-}" != "go" ]] || [[ "${VERIFY_HOST:-0}" == "1" ]]; }; then
  echo "=== compare host baseline OK set vs docker ==="
  python3 - <<'PY'
import json, os, sys
from pathlib import Path

host = json.loads(Path(os.environ["HOST_BASELINE"]).read_text())
cur = json.loads(Path(os.environ["OUT_DIR"], "results.json").read_text())
ht = host.get("tests", {})
ct = cur.get("tests", {})

def st(t, k):
    v = t.get(str(k)) or t.get(int(k) if str(k).isdigit() else k)
    if v is None:
        return None
    if isinstance(v, str):
        return v
    return v.get("status") or v.get("result")

# Only compare tests that actually ran in the docker suite (ONLY=… filters).
cur_ids = {str(k) for k in ct}
host_ok = {str(k) for k in ht if st(ht, k) == "OK"}
host_ok_ran = sorted(host_ok & cur_ids, key=lambda x: int(x) if x.isdigit() else x)
lost = []
still_ok = 0
for k in host_ok_ran:
    s = st(ct, k)
    if s == "OK":
        still_ok += 1
        continue
    name = ""
    v = ct.get(str(k), {})
    if isinstance(v, dict):
        name = v.get("name", "")
    lost.append((k, s or "MISSING", name))

# Host CANTs that became OK in docker (among tests that ran).
gained_from_cant = []
for k, v in ht.items():
    ks = str(k)
    if ks not in cur_ids:
        continue
    if st(ht, k) != "CANT":
        continue
    if st(ct, k) == "OK":
        name = v.get("name", "") if isinstance(v, dict) else ""
        gained_from_cant.append((ks, name))

print(f"host OK (full baseline): {len(host_ok)}")
print(f"host OK that ran here:   {len(host_ok_ran)}")
print(f"still OK in docker:      {still_ok}")
print(f"lost (OK → non-OK):      {len(lost)}")
print(f"host CANT → docker OK:   {len(gained_from_cant)}")
if lost:
    print("\nREGRESSIONS (host OK not OK in docker):")
    for k, s, name in lost[:40]:
        print(f"  {k} {s} {name}")
    if len(lost) > 40:
        print(f"  ... and {len(lost)-40} more")
if gained_from_cant:
    print("\nNew OK from host CANT (sample):")
    for k, name in gained_from_cant[:30]:
        print(f"  {k} {name}")
    if len(gained_from_cant) > 30:
        print(f"  ... and {len(gained_from_cant)-30} more")

# Write machine-readable verify report
report = {
    "host_ok": len(host_ok),
    "host_ok_ran": len(host_ok_ran),
    "still_ok": still_ok,
    "lost_count": len(lost),
    "lost": [{"id": k, "status": s, "name": n} for k, s, n in lost],
    "gained_from_cant_count": len(gained_from_cant),
    "gained_from_cant": [{"id": k, "name": n} for k, n in gained_from_cant],
}
Path(os.environ["OUT_DIR"], "host-vs-docker-verify.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print(f"wrote {os.environ['OUT_DIR']}/host-vs-docker-verify.json")
# Known host→docker environment gaps (not classic binary bugs):
#   216 UDP6MULTICAST — bridge netns often lacks IPv6 mcast route
#   304 IOCTL_VOID    — permission/root interaction on PTY ioctl
#   410 VSOCK_ECHO    — no AF_VSOCK device in typical containers
#   453 GOPEN_TO_DENIED — classic skips "not with root"
#   492 ACCEPT_FD     — needs systemd-socket-activate
allow_raw = os.environ.get("ALLOW_LOST", "216,304,410,453,492")
allow = {x.strip() for x in allow_raw.split(",") if x.strip()}
unexpected = [x for x in lost if str(x[0]) not in allow]
if unexpected:
    print(f"\nUNEXPECTED losses (not in ALLOW_LOST={allow_raw}): {len(unexpected)}")
    for k, s, name in unexpected:
        print(f"  {k} {s} {name}")
    sys.exit(1)
if lost:
    print(f"\nVERIFY OK with {len(lost)} expected env losses (ALLOW_LOST)")
else:
    print("\nVERIFY OK: all host-OK tests that ran still pass")
sys.exit(0)
PY
  verify_ec=$?
  if [[ $verify_ec -ne 0 ]]; then
    echo "VERIFY FAILED: unexpected host-OK losses in docker" >&2
    # Prefer verify exit for CI; still leave scorecard logs in /out.
    exit "$verify_ec"
  fi
fi

# Prefer verify success; scorecard may still have classic FAILs (non-zero ec).
# Use SCORECARD_EXIT=1 to surface classic FAILED count as process exit.
if [[ "${SCORECARD_EXIT:-0}" == "1" ]]; then
  exit "$ec"
fi
exit 0
