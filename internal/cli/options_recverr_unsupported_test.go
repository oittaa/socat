//go:build darwin || windows

package cli

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestIPRecvErrRejectedOffLinux(t *testing.T) {
	for _, spec := range []string{
		"UDP4:localhost:1,ip-recverr",
		"UDP:localhost:1,recverr=1",
		"TCP:localhost:1,ip-recverr",
	} {
		ch, err := parse.ParseChannel(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		err = validateChannelOptions(ch)
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Errorf("%s: error=%v want not supported", spec, err)
		}
	}
}
