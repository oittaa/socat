//go:build windows

package sockopt_test

import (
	"errors"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio/sockopt"
)

func TestLowWaterOptionsUnsupportedWindows(t *testing.T) {
	for _, specText := range []string{
		"TCP:127.0.0.1:9,so-rcvlowat=64",
		"TCP:127.0.0.1:9,rcvlowat=64",
		"TCP:127.0.0.1:9,so-sndlowat=64",
		"TCP:127.0.0.1:9,sndlowat=64",
	} {
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		err = sockopt.ApplySocketOptions(0, mustDecodeAddress(t, spec))
		if err == nil || !errors.Is(err, sockopt.ErrNamedOptUnsupported) {
			t.Fatalf("%s: error=%v want %v", specText, err, sockopt.ErrNamedOptUnsupported)
		}
	}
}
