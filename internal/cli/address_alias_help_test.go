package cli

import (
	"bytes"
	"strings"
	"testing"

	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestTCPLStaysDirectHelpRow(t *testing.T) {
	var h bytes.Buffer
	if err := printHelp(&h, 1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.String(), "TCP-L:") {
		t.Fatal("-h missing directly registered TCP-L syntax")
	}
}
