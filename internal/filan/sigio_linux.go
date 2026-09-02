//go:build linux

package filan

import (
	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

func appendSigioHeader(b *outbuf.Buf) {
	b.Print("\tsigio")
}

func appendSigio(b *outbuf.Buf, fd int) {
	sigio, _ := unix.FcntlInt(uintptr(fd), unix.F_GETSIG, 0)
	b.Printf("\t%d", sigio)
}
