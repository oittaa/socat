//go:build linux

package xio

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxOwnerIoctlMatchesSIOCSPGRPABI(t *testing.T) {
	switch uint(unix.SIOCSPGRP) {
	case 0x8902:
		if ownerIoctlFIOSETOWN != 0x8901 || ownerIoctlFIOGETOWN != 0x8903 {
			t.Fatalf("asm-generic FIOSETOWN=%#x FIOGETOWN=%#x want 0x8901/0x8903",
				ownerIoctlFIOSETOWN, ownerIoctlFIOGETOWN)
		}
	case 0x80047308:
		if ownerIoctlFIOSETOWN != 0x8004667c || ownerIoctlFIOGETOWN != 0x4004667b {
			t.Fatalf("MIPS FIOSETOWN=%#x FIOGETOWN=%#x want 0x8004667c/0x4004667b",
				ownerIoctlFIOSETOWN, ownerIoctlFIOGETOWN)
		}
	default:
		t.Fatalf("unexpected SIOCSPGRP=%#x", uint(unix.SIOCSPGRP))
	}
}
