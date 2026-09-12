package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/optionmeta"
)

func TestHasFDLifecycleOptionsIoctl(t *testing.T) {
	for _, raw := range []string{
		"FD:3,ioctl-void=1",
		"TCP:localhost:1,ioctl=1",
		"OPEN:file,ioctl-string=1:x",
	} {
		config, err := decodeAddress(mustSpec(t, raw))
		if err != nil {
			t.Fatal(err)
		}
		if !hasConfiguredFDActions(config.File, FDSkip{}) {
			t.Fatalf("%s must trigger ApplyFDOptions", raw)
		}
	}
}

func TestGenericIoctlOptionNames(t *testing.T) {
	for _, name := range []string{"ioctl", "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string"} {
		def, ok := optionmeta.Lookup(name)
		if !ok {
			t.Errorf("%s: unknown ioctl option", name)
			continue
		}
		switch def.Canonical {
		case "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string":
		default:
			t.Errorf("%s: canonical %q", name, def.Canonical)
		}
	}
}
