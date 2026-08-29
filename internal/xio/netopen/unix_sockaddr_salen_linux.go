//go:build linux

package netopen

import "golang.org/x/sys/unix"

func setUnixSockaddrLen(*unix.RawSockaddrUnix, int) {}
