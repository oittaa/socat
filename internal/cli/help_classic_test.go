package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpDoesNotTriggerClassicOptionArraySentinel(t *testing.T) {
	var output bytes.Buffer
	printHelp(&output, 3)
	// Classic test.sh uses the loose expression /opt:/ as an internal-help
	// sentinel. Human-readable descriptions must not accidentally match it.
	if strings.Contains(output.String(), "opt:") {
		t.Fatal("-hhh output contains classic test.sh's internal option-array sentinel \"opt:\"")
	}
}
