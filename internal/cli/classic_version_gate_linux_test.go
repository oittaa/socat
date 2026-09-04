//go:build linux

package cli

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/oittaa/socat"
)

// TestClassicTestShVersionGateSkipsUDPDatagramPeerport locks the official
// test.sh SOCAT_VERSION gate that makes UDP_DATAGRAM_PEERPORT CANT here.
// That test never requests udp-ignore-peerport; it is a version skip, not an
// unimplemented datagram option.
func TestClassicTestShVersionGateSkipsUDPDatagramPeerport(t *testing.T) {
	var buf bytes.Buffer
	if err := printVersion(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		t.Fatalf("-V too short:\n%s", out)
	}
	if !strings.HasPrefix(lines[0], "socat version "+socat.Version+" ") {
		t.Fatalf("-V line 1 %q does not start with socat version %s", lines[0], socat.Version)
	}

	extracted, gate := classicTestShVersionGate(t, out)
	if gate != "1.7.3.4" {
		t.Fatalf("official test.sh would no longer CANT-skip UDP_DATAGRAM_PEERPORT: extracted %q gate_max %q; update testdata/scorecard/README.md", extracted, gate)
	}

	t.Run("line1ProductVersionAlsoBelow1740", func(t *testing.T) {
		_, line1Gate := classicTestShVersionGate(t, lines[0]+"\n")
		if line1Gate != "1.7.3.4" {
			t.Fatalf("product version %q would pass the 1.7.4.0 gate if test.sh read -V line 1; update testdata/scorecard/README.md", socat.Version)
		}
	})
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
