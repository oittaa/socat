//go:build darwin

package filan

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSockAddrInfoIncludesLen(t *testing.T) {
	sa := &unix.SockaddrInet4{Port: 2345, Addr: [4]byte{127, 0, 0, 1}}
	got := SockAddrInfo(sa)
	if !strings.HasPrefix(got, "LEN=") {
		t.Fatalf("darwin SockAddrInfo=%q", got)
	}
}
