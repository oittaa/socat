//go:build linux

package sockopt_test

import (
	"testing"

	"github.com/oittaa/socat/internal/xio/sockopt"
	"golang.org/x/sys/unix"
)

func TestLinuxOwnerIoctlMatchesSIOCSPGRPABI(t *testing.T) {
	switch uint(unix.SIOCSPGRP) {
	case 0x8902:
		if sockopt.OwnerIoctlFIOSETOWN != 0x8901 || sockopt.OwnerIoctlFIOGETOWN != 0x8903 {
			t.Fatalf("asm-generic FIOSETOWN=%#x FIOGETOWN=%#x want 0x8901/0x8903",
				sockopt.OwnerIoctlFIOSETOWN, sockopt.OwnerIoctlFIOGETOWN)
		}
	case 0x80047308:
		if sockopt.OwnerIoctlFIOSETOWN != 0x8004667c || sockopt.OwnerIoctlFIOGETOWN != 0x4004667b {
			t.Fatalf("MIPS FIOSETOWN=%#x FIOGETOWN=%#x want 0x8004667c/0x4004667b",
				sockopt.OwnerIoctlFIOSETOWN, sockopt.OwnerIoctlFIOGETOWN)
		}
	default:
		t.Fatalf("unexpected SIOCSPGRP=%#x", uint(unix.SIOCSPGRP))
	}
}

func assertFIOGETOWN(t *testing.T, fd, want int) {
	t.Helper()
	if got := ownerIoctlGet(t, fd, sockopt.OwnerIoctlFIOGETOWN); got != want {
		t.Fatalf("FIOGETOWN=%d want %d", got, want)
	}
}
