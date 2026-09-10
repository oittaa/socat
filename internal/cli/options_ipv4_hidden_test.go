package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestHiddenGetOnlyIPv4NamesStayOutOfHelp(t *testing.T) {
	var buf bytes.Buffer
	if err := printHelp(&buf, 3); err != nil {
		t.Fatal(err)
	}
	listed := helpLineNames(buf.String())
	for _, name := range []string{"ip-mtu", "ipmtu", "mtu", "ip-pktoptions", "ippktoptions", "pktoptions", "pktopts"} {
		if listed[name] {
			t.Errorf("-hhh advertises %s", name)
		}
	}
	if !listed["ip-mtu-discover"] {
		t.Fatal("-hhh missing ip-mtu-discover")
	}
}

func TestGetOnlyIPv4CLIAddressCaps(t *testing.T) {
	err := validateParsed(t, "UNIX-LISTEN:x,ip-mtu")
	if err == nil || !strings.Contains(err.Error(), "not supported with this address type") {
		t.Fatalf("UNIX-LISTEN: %v", err)
	}
	err = validateParsed(t, "UDP4:127.0.0.1:1,mtu=1")
	if err == nil || !strings.Contains(err.Error(), "get-only") {
		t.Fatalf("UDP4: %v", err)
	}
}
