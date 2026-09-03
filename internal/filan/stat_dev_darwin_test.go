//go:build darwin

package filan

import (
	"bytes"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

func TestDarwinStatDevPreservesHighBit(t *testing.T) {
	// 0x80010203 as signed int32 has the high bit set.
	const rawDev = int32(int64(0x80010203) - (1 << 32))
	st := unix.Stat_t{
		Dev:  rawDev,
		Rdev: rawDev,
	}

	dev, rdev := statDev(&st)
	if dev != 0x80010203 || rdev != 0x80010203 {
		t.Fatalf("statDev did not preserve device bits: got dev=%#x, rdev=%#x; want 0x80010203", dev, rdev)
	}

	var b outbuf.Buf
	WriteStat(&b, 0, 0, &st, Options{})
	var buf bytes.Buffer
	if err := b.Flush(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// classicDevPair(0x80010203) formats as "258,3" ((0x80010203>>8)&0xffff = 258, 0x80010203&0xff = 3).
	if !strings.Contains(out, "258,3") {
		t.Fatalf("WriteStat did not preserve device number: got %q, want it to contain 258,3", out)
	}
	if strings.Contains(out, "\t0,0\t") {
		t.Fatalf("WriteStat replaced high-bit device number with zero: %q", out)
	}
}
