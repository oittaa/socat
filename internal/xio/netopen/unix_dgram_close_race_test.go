//go:build linux || darwin

package netopen

import (
	"net"
	"testing"
	"time"
)

func TestUnixPacketConnConcurrentCloseOwnedOnce(t *testing.T) {
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "close-owned.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	u := &unixPacketConn{c: c}
	errs := concurrentCloses(t, u.Close, 32)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Close[%d]=%v", i, err)
		}
	}
	if err := u.Close(); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(time.Millisecond)); err == nil {
		t.Fatal("owned unixgram socket still usable after Close")
	}
}

func TestUnixPacketConnSharedCloseDoesNotCloseParent(t *testing.T) {
	parent, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "close-shared.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	u := &unixPacketConn{c: parent, shared: true}
	errs := concurrentCloses(t, u.Close, 16)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Close[%d]=%v", i, err)
		}
	}
	if err := parent.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("shared Close closed parent: %v", err)
	}
}
