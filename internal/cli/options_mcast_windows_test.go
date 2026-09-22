//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestMulticastOptionsRejectedOnWindows(t *testing.T) {
	for _, spec := range []string{
		"UDP6:localhost:1,ipv6-multicast-loop=0",
		"UDP6:localhost:1,mcloop6",
		"UDP6:localhost:1,ipv6-join-source-group=[ff3e::1]:lo:[::1]",
		"UDP6:localhost:1,join-source-group=[ff3e::1]:lo:[::1]",
		"UDP4:localhost:1,ip-add-source-membership=232.1.1.1:127.0.0.1:127.0.0.1",
		"UDP4:localhost:1,ip-multicast-ttl=9,ip-multicast-loop=0,ip-multicast-if=127.0.0.1",
		"UDP6:localhost:1,ipv6-join-group=[ff02::2]:lo",
		"UDP6-RECV:1,ipv6-join-group=[ff02::2]:lo",
		"TCP6:localhost:1,ipv6-join-group=[ff02::2]:lo",
		"UDP6:localhost:1,join-group=[ff02::2]:lo",
		"TCP6:localhost:1,ipv6-add-membership=[ff02::2]:lo",
		"UDP4:localhost:1,ip-add-membership=224.0.0.1:lo",
		"UDP4-RECV:1,ip-add-membership=224.0.0.1:lo",
		"UDP6:localhost:1,ip-add-membership=[ff02::2]:lo",
		"UDP6-RECV:1,ip-add-membership=[ff02::2]:lo",
		"UDP4:localhost:1,add-membership=224.0.0.1:lo",
		"UDP4:localhost:1,membership=224.0.0.1:lo",
		"UDP6:localhost:1,ip-membership=[ff02::2]:lo",
	} {
		ch, err := parse.ParseChannel(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		_, err = xio.PrepareChannel(ch)
		if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
			t.Errorf("%s: error=%v", spec, err)
		}
	}
}
