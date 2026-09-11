package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func mustSpec(t *testing.T, raw string) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHasFDLifecycleOptionsCloexec(t *testing.T) {
	for _, raw := range []string{"FD:3,cloexec", "FD:3,cloexec=0", "TCP:localhost:1,cloexec=1", "OPEN:file,cloexec"} {
		config, err := decodeAddress(mustSpec(t, raw))
		if err != nil {
			t.Fatal(err)
		}
		if !hasConfiguredFDActions(config.File, FDSkip{}) {
			t.Errorf("%s: cloexec must trigger ApplyFDOptions", raw)
		}
	}
}
