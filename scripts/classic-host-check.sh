#!/usr/bin/env bash
# Report host capabilities that affect classic socat test.sh CANT rate.
# Does not require root; prints what would raise OK/CANT for upstream socat.
set -euo pipefail

echo "classic test.sh host checklist"
echo "=============================="
echo "user: $(id -un) uid=$(id -u) groups=$(id -Gn)"
echo

ok() { echo "  [ok]  $*"; }
miss() { echo "  [..]  $*"; }
warn() { echo "  [!!]  $*"; }

echo "Privilege (≈58 CANT if non-root: RAWIP, TUN, some interface/SCM)"
if [ "$(id -u)" -eq 0 ]; then
  ok "running as root"
else
  miss "not root — raw IP / some interface tests will CANT (use sudo -E for full suite)"
fi
echo

echo "Build-time optional libraries (rebuild classic socat after install)"
for pkg in libreadline-dev libwrap0-dev; do
  if dpkg -s "$pkg" &>/dev/null; then
    ok "$pkg installed"
  else
    miss "$pkg missing — apt install $pkg && reconfigure classic"
  fi
done
if dpkg -s libssl-dev &>/dev/null; then
  ok "libssl-dev (OpenSSL)"
else
  miss "libssl-dev missing"
fi
echo

echo "Kernel / devices"
[ -e /dev/net/tun ] && ok "/dev/net/tun" || miss "/dev/net/tun (TUN tests)"
[ -e /dev/vsock ] && ok "/dev/vsock" || miss "/dev/vsock (VSOCK tests)"
echo

echo "Network"
if ip -4 -o addr show scope global 2>/dev/null | grep -q .; then
  ok "global IPv4: $(ip -4 -o addr show scope global | awk '{print $4}' | head -3 | tr '\n' ' ')"
else
  miss "no global IPv4 (SECONDADDR / multi-homed tests)"
fi
if ip -6 -o addr show scope global 2>/dev/null | grep -q .; then
  ok "global IPv6 present"
else
  miss "no global IPv6"
fi
echo

echo "test.sh invocation tips"
echo "  # Default (non-root): ~480–490 OK, ~100–120 CANT, few FAIL"
echo "  ./test.sh -t 0.1"
echo "  # More tests (needs outbound DNS/HTTP):"
echo "  ./test.sh -t 0.1 --internet"
echo "  # Root for RAWIP/TUN/etc. (careful):"
echo "  sudo -E env PATH=\"\$PATH\" SOCAT=\$PWD/socat ./test.sh -t 0.1"
echo
echo "Classic CANT buckets observed on this class of host:"
echo "  ~50%  must be root"
echo "  ~15%  libwrap (libwrap0-dev + rebuild)"
echo "  ~10%  --internet"
echo "  ~rest FIPS/READLINE/OpenSSL 3.0 renego / DEVTESTS / options"
echo
echo "Done."
