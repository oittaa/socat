//go:build linux

package xio

import "syscall"

func interfaceProtocolFamily(pf int) bool {
	return pf == syscall.AF_PACKET
}
