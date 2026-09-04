#!/usr/bin/env bash
# Process ownership for classic-scorecard.sh.
#
# Match leftover socat (and helper) processes by this invocation's environment
# rather than by binary path, so one shard cannot terminate a sibling shard or
# another scorecard from the same checkout. External SOCAT binaries inherit the
# same markers from the shard subshell that runs test.sh.

scorecard_is_self_or_ancestor() {
	local pid=$1
	local p=$$
	while [ -n "$p" ] && [ "$p" != "0" ] && [ "$p" != "1" ]; do
		if [ "$pid" = "$p" ]; then
			return 0
		fi
		if [ -r "/proc/$p/status" ]; then
			p=$(awk '/^PPid:/{print $2; exit}' "/proc/$p/status" 2>/dev/null || true)
		else
			break
		fi
	done
	[ "$pid" = "$PPID" ]
}

# True when pid's environment has key=value as a whole record (so SHARD=1
# does not match SHARD=10). Empty value means "key is present".
scorecard_pid_has_env() {
	local pid=$1
	local key=$2
	local value=$3
	local envfile="/proc/$pid/environ"
	if [ -r "$envfile" ]; then
		if [ -n "$value" ]; then
			grep -F -z -x -q "${key}=${value}" "$envfile" 2>/dev/null
		else
			grep -F -z -q "${key}=" "$envfile" 2>/dev/null
		fi
		return $?
	fi
	if command -v ps >/dev/null 2>&1; then
		local psout
		psout=$(ps eww -p "$pid" 2>/dev/null || true)
		[ -n "$psout" ] || return 1
		if [ -n "$value" ]; then
			printf '%s\n' "$psout" | tr ' ' '\n' | grep -F -x -q "${key}=${value}"
		else
			printf '%s\n' "$psout" | tr ' ' '\n' | grep -F -q "${key}="
		fi
		return $?
	fi
	return 1
}

# List PIDs owned by this scorecard run. If shard_id is non-empty, restrict to
# that shard. Run-wide matches require a shard marker so the scorecard process
# itself (RUN exported, SHARD unset) is never selected.
scorecard_find_owned_pids() {
	local run_id=$1
	local shard_id=${2-}
	local pid
	[ -n "$run_id" ] || return 0
	if [ -d /proc ]; then
		for pid in /proc/[0-9]*; do
			pid=${pid#/proc/}
			if ! scorecard_pid_has_env "$pid" SOCAT_SCORECARD_RUN "$run_id"; then
				continue
			fi
			if [ -n "$shard_id" ]; then
				if ! scorecard_pid_has_env "$pid" SOCAT_SCORECARD_SHARD "$shard_id"; then
					continue
				fi
			elif ! scorecard_pid_has_env "$pid" SOCAT_SCORECARD_SHARD ""; then
				continue
			fi
			if scorecard_is_self_or_ancestor "$pid"; then
				continue
			fi
			printf '%s\n' "$pid"
		done
		return 0
	fi
	local line
	while IFS= read -r line; do
		pid=${line// /}
		[ -n "$pid" ] || continue
		if ! scorecard_pid_has_env "$pid" SOCAT_SCORECARD_RUN "$run_id"; then
			continue
		fi
		if [ -n "$shard_id" ]; then
			if ! scorecard_pid_has_env "$pid" SOCAT_SCORECARD_SHARD "$shard_id"; then
				continue
			fi
		elif ! scorecard_pid_has_env "$pid" SOCAT_SCORECARD_SHARD ""; then
			continue
		fi
		if [ "$pid" = "$$" ] || [ "$pid" = "$PPID" ]; then
			continue
		fi
		printf '%s\n' "$pid"
	done < <(ps axo pid= 2>/dev/null || true)
}

# Bounded cleanup of leftover processes owned by this run (optional shard).
# TERM, wait up to SOCAT_SCORECARD_CLEANUP_GRACE seconds (default 8), then KILL.
# Re-scan /proc after signalling: a single readdir can skip PIDs while other
# processes fork and exit. Grace 0 is TERM then immediate KILL passes.
scorecard_cleanup_owned() {
	local run_id=${1:-${SOCAT_SCORECARD_RUN-}}
	local shard_id=${2-}
	local grace=${SOCAT_SCORECARD_CLEANUP_GRACE:-8}
	local pid i pass
	local -a pid_arr

	pid_arr=()
	while IFS= read -r pid; do
		[ -n "$pid" ] || continue
		pid_arr+=("$pid")
	done < <(scorecard_find_owned_pids "$run_id" "$shard_id")
	[ "${#pid_arr[@]}" -gt 0 ] || return 0
	kill -TERM "${pid_arr[@]}" 2>/dev/null || true
	i=0
	while [ "$i" -lt "$grace" ]; do
		pid_arr=()
		while IFS= read -r pid; do
			[ -n "$pid" ] || continue
			pid_arr+=("$pid")
		done < <(scorecard_find_owned_pids "$run_id" "$shard_id")
		[ "${#pid_arr[@]}" -gt 0 ] || return 0
		sleep 1
		i=$((i + 1))
	done
	pass=0
	while [ "$pass" -lt 3 ]; do
		pid_arr=()
		while IFS= read -r pid; do
			[ -n "$pid" ] || continue
			pid_arr+=("$pid")
		done < <(scorecard_find_owned_pids "$run_id" "$shard_id")
		[ "${#pid_arr[@]}" -gt 0 ] || return 0
		kill -KILL "${pid_arr[@]}" 2>/dev/null || true
		pass=$((pass + 1))
	done
}
