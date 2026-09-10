package xio

import (
	"testing"
)

func TestHasFDLifecycleOptionsIoctl(t *testing.T) {
	if !hasFDLifecycleOptions(mustSpec(t, "FD:3,ioctl-void=1"), FDSkip{}) {
		t.Fatal("ioctl-void must trigger ApplyFDOptions")
	}
	if !hasFDLifecycleOptions(mustSpec(t, "TCP:localhost:1,ioctl=1"), FDSkip{}) {
		t.Fatal("ioctl alias must trigger ApplyFDOptions")
	}
	if !hasFDLifecycleOptions(mustSpec(t, "OPEN:file,ioctl-string=1:x"), FDSkip{}) {
		t.Fatal("ioctl-string must trigger ApplyFDOptions")
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
