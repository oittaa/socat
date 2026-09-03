//go:build linux

package xio

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIPv4MembershipHighBitIndexReturnsKernelError(t *testing.T) {
	for _, token := range []string{"-1", "-2147483648"} {
		t.Run(token, func(t *testing.T) {
			p, err := parseMcastSpec("224.0.0.1:"+token, "ip-add-membership")
			if err != nil {
				t.Fatal(err)
			}
			index, set, err := resolveMcastInterface(p, "ip-add-membership")
			if err != nil || !set {
				t.Fatalf("resolve index: set=%v err=%v", set, err)
			}
			err = setIPv4MembershipFD(mustUDP4Socket(t), p.group, p.ifaceAddr, index, set)
			if !errors.Is(err, unix.ENODEV) {
				t.Fatalf("membership with index %s: got %v, want kernel ENODEV", token, err)
			}
		})
	}
}
