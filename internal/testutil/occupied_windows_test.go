package testutil

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestBindBusyIncludesAddrInUseAndAcces(t *testing.T) {
	for _, err := range []error{windows.WSAEADDRINUSE, windows.WSAEACCES} {
		if !BindBusy(err) {
			t.Fatalf("BindBusy(%v)=false", err)
		}
	}
}
