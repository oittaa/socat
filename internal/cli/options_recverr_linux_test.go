//go:build linux

package cli

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestIPRecvErrAcceptedOnLinux(t *testing.T) {
	for _, spec := range []string{
		"UDP4:localhost:1,ip-recverr",
		"UDP:localhost:1,recverr=1",
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
