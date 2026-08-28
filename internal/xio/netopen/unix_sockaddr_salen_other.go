//go:build unix && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !aix

package netopen

import "golang.org/x/sys/unix"

func setUnixSockaddrLen(*unix.RawSockaddrUnix, int) {}
