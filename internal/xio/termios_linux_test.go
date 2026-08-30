package xio

import (
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestApplyTermiosLinuxVSWTC(t *testing.T) {
	fd := openPTYSlave(t)
	tio := applyTermiosSpec(t, fd, "PTY,swtch=0x42")
	if tio.Cc[unix.VSWTC] != 0x42 {
		t.Fatalf("VSWTC=%#x want 0x42", tio.Cc[unix.VSWTC])
	}
}

func TestApplyTermiosLinuxB7200Effect(t *testing.T) {
	fd := openPTYSlave(t)
	tio := applyTermiosSpec(t, fd, "PTY,b7200")
	if tio.Ispeed != 7200 || tio.Ospeed != 7200 {
		t.Fatalf("b7200 speed=%d/%d", tio.Ispeed, tio.Ospeed)
	}
	if got := tio.Cflag & termiosBits(unix.CBAUD); got != termiosBits(unix.BOTHER) {
		t.Fatalf("b7200 CBAUD=%#x want BOTHER %#x", got, unix.BOTHER)
	}
}

func TestApplyTermiosLinuxXTABS(t *testing.T) {
	fd := openPTYSlave(t)
	tio := applyTermiosSpec(t, fd, "PTY,sane,xtabs")
	if got := tio.Oflag & termiosTABDLY; got != termiosBits(unix.XTABS) {
		t.Fatalf("xtabs Oflag&TABDLY=%#x want %#x", got, unix.XTABS)
	}
}

func TestApplyTermiosSetFlagsMatchesClassicULongTruncation(t *testing.T) {
	if strconv.IntSize != 64 {
		t.Skip("unsigned long is not wider than a 32-bit tcflag_t")
	}
	fd := openPTYSlave(t)
	tio := applyTermiosSpec(t, fd, "PTY,termios-setflags=0:0x100000001")
	if tio.Iflag != 1 {
		t.Fatalf("Iflag=%#x want low tcflag_t word 1", tio.Iflag)
	}
}
