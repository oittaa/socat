//go:build linux

package netopen

import (
	"fmt"
	"net"
	"testing"
)

func TestUDPSecondBindWithReuseaddrSucceeds(t *testing.T) {
	first, err := listenUDPOnPort(t, parseUDPSpec(t, "UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	port := first.LocalAddr().(*net.UDPAddr).Port
	second, err := listenUDPOnPort(t, parseUDPSpec(t, fmt.Sprintf("UDP4-LISTEN:%d,bind=127.0.0.1,reuseaddr", port)), port)
	if err != nil {
		t.Fatalf("second UDP-LISTEN,reuseaddr: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
}
