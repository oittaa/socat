//go:build linux || darwin

package xio

import (
	"os"

	"github.com/oittaa/socat/internal/filan"
	"github.com/oittaa/socat/internal/outbuf"
	"github.com/oittaa/socat/internal/relay"
)

func (g *Global) dumpSessionFDs(left, right relay.Stream) {
	if g == nil || !g.DumpFDs {
		return
	}
	out := g.DumpFDOut
	if out == nil {
		out = os.Stderr
	}
	var b outbuf.Buf
	filan.WriteHeader(&b)
	dumpSideFDs(&b, left)
	dumpSideFDs(&b, right)
	_ = b.Flush(out)
}

func dumpSideFDs(b *outbuf.Buf, s relay.Stream) {
	if s == nil {
		return
	}
	rfd := relay.StreamReadFD(s)
	wfd := relay.StreamWriteFD(s)
	if rfd >= 0 {
		filan.WriteFD(b, rfd, filan.Options{})
	}
	if wfd >= 0 && wfd != rfd {
		filan.WriteFD(b, wfd, filan.Options{})
	}
}
