#!/usr/bin/env bash
# Summarize a go coverprofile for CI logs and $GITHUB_STEP_SUMMARY.
# Functions at 0.0% are the useful signal: a test named after a helper
# that never ran (see TestDualStdio) shows up here.
set -euo pipefail

profile=${1:?usage: coverage-summary.sh <coverprofile>}
if [ ! -f "$profile" ]; then
	echo "missing coverprofile $profile" >&2
	exit 1
fi

func=$(go tool cover -func="$profile")
total=$(printf '%s\n' "$func" | awk '/^total:/ { print }')
zero=$(printf '%s\n' "$func" | awk '$NF == "0.0%" { print }' || true)
zero_count=0
if [ -n "$zero" ]; then
	zero_count=$(printf '%s\n' "$zero" | wc -l | tr -d ' ')
fi

echo "$total"
echo
echo "=== functions at 0.0% ($zero_count) ==="
if [ -z "$zero" ]; then
	echo "(none)"
else
	printf '%s\n' "$zero" | awk 'NR<=80 { print }'
	if [ "$zero_count" -gt 80 ]; then
		echo "... truncated ($zero_count total)"
	fi
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		echo "### $(basename "$profile")"
		echo
		echo "\`$total\`"
		echo
		echo "<details><summary>Functions at 0.0% ($zero_count)</summary>"
		echo
		echo '```'
		if [ -z "$zero" ]; then
			echo "(none)"
		else
			printf '%s\n' "$zero" | awk 'NR<=80 { print }'
			if [ "$zero_count" -gt 80 ]; then
				echo "... truncated ($zero_count total)"
			fi
		fi
		echo '```'
		echo "</details>"
		echo
	} >>"$GITHUB_STEP_SUMMARY"
fi
