//go:build darwin || freebsd

package xio

import (
	"bytes"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIPv4MembershipNameUsesIPMreqInterfaceAddress(t *testing.T) {
	ifi := multicastLoopback(t)
	wantInterface := net.ParseIP(firstIPv4(t, ifi)).To4()
	group := net.IPv4(239, 255, 76, 12)
	fd := mustUDP4Socket(t)

	var payload []byte
	restore := SetSockoptTestHook(func(call SockoptCall) {
		if call.Level == unix.IPPROTO_IP && call.Opt == unix.IP_ADD_MEMBERSHIP {
			payload = append([]byte(nil), call.Bytes...)
		}
	})
	t.Cleanup(restore)

	if err := setIPv4MembershipFD(fd, group, nil, uint32(ifi.Index), true); err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), group.To4()...), wantInterface...)
	if !bytes.Equal(payload, want) {
		t.Fatalf("IP_ADD_MEMBERSHIP payload=%v want ip_mreq %v", payload, want)
	}
}
