//go:build linux

package cli

import (
	"os/exec"
	"strings"
	"testing"
)

// TestClassicTestShUDPDatagramPeerportVersionGate characterizes official
// test.sh's SOCAT_VERSION extraction and the UDP_DATAGRAM_PEERPORT 1.7.4.0
// skip using fixed -V samples. That test never requests udp-ignore-peerport.
// Do not require live product -V to keep CANT-skipping.
func TestClassicTestShUDPDatagramPeerportVersionGate(t *testing.T) {
	cases := []struct {
		name          string
		versionOutput string
		wantExtracted string
		wantSkip      bool
	}{
		{
			name:          "classicLine2Version1813Runs",
			versionOutput: "header\nsocat version 1.8.1.3 on 2026-01-01\n",
			wantExtracted: "1.8.1.3",
			wantSkip:      false,
		},
		{
			name:          "classicLine2Version1740Runs",
			versionOutput: "header\nsocat version 1.7.4.0 on 2026-01-01\n",
			wantExtracted: "1.7.4.0",
			wantSkip:      false,
		},
		{
			name:          "classicLine2Version1734Skips",
			versionOutput: "header\nsocat version 1.7.3.4 on 2026-01-01\n",
			wantExtracted: "1.7.3.4",
			wantSkip:      true,
		},
		{
			name:          "classicLine2Version103DevSkips",
			versionOutput: "header\nsocat version 1.0.3-dev on 2026-01-01\n",
			wantExtracted: "1.0.3-dev",
			wantSkip:      true,
		},
		{
			name: "goLayoutSkipsEvenWhenLine1Is1813",
			versionOutput: "socat version 1.8.1.3 on 2026-01-01\n" +
				"   running on Go reimplementation (github.com/oittaa/socat)\n",
			wantSkip: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extracted, gate := classicTestShVersionGate(t, tc.versionOutput)
			skip := gate == "1.7.3.4"
			if skip != tc.wantSkip {
				t.Fatalf("extracted %q gate_max %q skip=%v want skip=%v", extracted, gate, skip, tc.wantSkip)
			}
			if tc.wantExtracted != "" && extracted != tc.wantExtracted {
				t.Fatalf("extracted %q want %q", extracted, tc.wantExtracted)
			}
		})
	}
}

// classicTestShVersionGate replicates official test.sh:277 extraction and the
// UDP_DATAGRAM_PEERPORT comparison against 1.7.3.4 (sort -n, echo $E).
func classicTestShVersionGate(t *testing.T, versionOutput string) (extracted, gateMax string) {
	t.Helper()
	cmd := exec.Command("bash", "-c", `
set -e
if [ $(echo "x\c") = "x" ]; then E=""
elif [ $(echo -e "x\c") = "x" ]; then E="-e"
else
	echo "cannot detect echo escape mode" >&2
	exit 2
fi
SOCAT_VERSION=$(head -n 2 | tail -n 1 | sed 's/.* \([0-9][1-9]*\.[0-9][0-9]*\.[0-9][^[:space:]]*\).*/\1/')
GATE=$(echo $E "$SOCAT_VERSION\n1.7.3.4" | sort -n | tail -n 1)
printf '%s\n' "$SOCAT_VERSION"
printf '%s\n' "$GATE"
`)
	cmd.Stdin = strings.NewReader(versionOutput)
	got, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("classic test.sh version-gate replica: %v\n%s", err, got)
	}
	parts := strings.Split(strings.TrimRight(string(got), "\n"), "\n")
	if len(parts) != 2 {
		t.Fatalf("classic test.sh version-gate replica output %q", got)
	}
	return parts[0], parts[1]
}
