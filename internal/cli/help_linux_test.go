//go:build linux

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/xio"
)

func TestLinuxHelpListsEveryRegisteredTermiosSpelling(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	advertised := helpLineNames(b.String())
	var missing []string
	for _, name := range xio.TermiosHelpNames() {
		if !advertised[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("linux -hhh missing registered TERMIOS spellings: %s", strings.Join(missing, ", "))
	}
}

func TestLinuxVersionDefinesVSOCK(t *testing.T) {
	var b bytes.Buffer
	if err := printVersion(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "#define WITH_VSOCK 1") {
		t.Fatalf("missing WITH_VSOCK 1:\n%s", b.String())
	}
}
