//go:build linux

package main

import (
	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

func printPipeSize(fd int, b *outbuf.Buf) {
	if size, err := unix.FcntlInt(uintptr(fd), unix.F_GETPIPE_SZ, 0); err == nil {
		b.Printf("\tF_GETPIPE_SZ=%d", size)
	}
}
