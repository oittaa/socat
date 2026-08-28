//go:build windows

package xio

import (
	"errors"
	"testing"

	"github.com/oittaa/socat/internal/parse"
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
		err = ApplySocketOptions(0, spec)
		if err == nil || !errors.Is(err, errNamedOptUnsupported) {
			t.Fatalf("%s: error=%v want %v", specText, err, errNamedOptUnsupported)
		}
	}
}
