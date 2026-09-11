package xio

import (
	"context"
	"testing"
)

func TestHasFDLifecycleOptionsIoctl(t *testing.T) {
	for _, raw := range []string{
		"FD:3,ioctl-void=1",
		"TCP:localhost:1,ioctl=1",
		"OPEN:file,ioctl-string=1:x",
	} {
		config, err := OpeningConfig(context.Background(), mustSpec(t, raw))
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
		if !GenericIoctlOption(name) {
			t.Errorf("%s: GenericIoctlOption=false", name)
		}
	}
	if GenericIoctlOption("setsockopt") {
		t.Fatal("setsockopt is not a generic ioctl option")
	}
}
