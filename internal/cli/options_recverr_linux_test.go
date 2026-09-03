//go:build linux

package cli

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestIPRecvErrAcceptedOnLinux(t *testing.T) {
	for _, spec := range []string{
		"UDP4:localhost:1,ip-recverr",
		"UDP:localhost:1,recverr=1",
		"UDP4:localhost:1,ip-recverr=2",
		"UDP:localhost:1,recverr=2",
		"UDP6:[::1]:1,ip-recverr",
		"TCP:localhost:1,ip-recverr",
		"TCP6:[::1]:1,ip-recverr=0",
	} {
		ch, err := parse.ParseChannel(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if err := validateChannelOptions(ch); err != nil {
			t.Errorf("%s: %v", spec, err)
		}
	}
}

func TestIPRecvErrRejectsNonIntegerOnLinux(t *testing.T) {
	ch, err := parse.ParseChannel("UDP4:localhost:1,ip-recverr=true")
	if err != nil {
		t.Fatal(err)
	}
	err = validateChannelOptions(ch)
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("error=%v want invalid", err)
	}
}
