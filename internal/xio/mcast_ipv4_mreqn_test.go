//go:build linux

package xio

import (
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIPv4MembershipHighBitIndexReturnsKernelError(t *testing.T) {
	for _, token := range []string{"-1", "-2147483648"} {
		t.Run(token, func(t *testing.T) {
			req := decodeMulticastJoin(t, "UDP:127.0.0.1:9,ip-add-membership=224.0.0.1:"+token)
			if !req.InterfaceIsID {
				t.Fatalf("token %s must decode as an interface index: %+v", token, req)
			}
			err := setIPv4MembershipFD(mustUDP4Socket(t), net.ParseIP("224.0.0.1").To4(), nil, req.InterfaceID, true)
			if !errors.Is(err, unix.ENODEV) {
				t.Fatalf("membership with index %s: got %v, want kernel ENODEV", token, err)
			}
		})
	}
}
