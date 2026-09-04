#!/usr/bin/env bash
# Guest body for Hyper-V check and classic-parity.
# Invoked as a login-shell program with argv, not a nested bash -lc string:
#   env SOCAT_CLASSIC_PARITY_WORKDIR=... bash --login \
#     "$workdir/scripts/hyperv/guest-login-run.sh" "$workdir" check|parity
set -euo pipefail

workdir=${1:?guest workdir is required}
task=${2:?task is required (check or parity)}

cd -- "$workdir"

case "$task" in
  check)
    exec bash scripts/hyperv/guest-check.sh
    ;;
  parity)
    export SOCAT_CLASSIC_PARITY_WORKDIR="${SOCAT_CLASSIC_PARITY_WORKDIR:-/var/lib/socat-lab/classic-parity}"
    exec make classic-parity
    ;;
  *)
    echo "unknown Hyper-V guest task: $task" >&2
    exit 2
    ;;
esac
