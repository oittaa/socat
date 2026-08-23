//go:build linux

package xio

import (
	"slices"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestLinuxSetSpeedUsesKernelEncoding(t *testing.T) {
	termios := &unix.Termios{
		Cflag:  termiosBits(unix.CREAD | unix.B9600),
		Ispeed: termiosBits(unix.B9600),
		Ospeed: termiosBits(unix.B9600),
	}

	setSpeed(termios, 115200, true, false)
	if got := termios.Cflag & termiosBits(unix.CBAUD); got != termiosBits(unix.B9600) {
		t.Fatalf("output CBAUD=%#x, want %#x", got, unix.B9600)
	}
	if got := termios.Cflag & termiosBits(unix.CIBAUD); got != (termiosBits(unix.B115200)<<16)&termiosBits(unix.CIBAUD) {
		t.Fatalf("input CIBAUD=%#x, want encoded B115200", got)
	}
	if termios.Ispeed != termiosBits(unix.B115200) {
		t.Fatalf("Ispeed=%#x, want %#x", termios.Ispeed, unix.B115200)
	}

	setSpeed(termios, 4000000, false, true)
	if got := termios.Cflag & termiosBits(unix.CBAUD); got != termiosBits(unix.B4000000) {
		t.Fatalf("output CBAUD=%#x, want %#x", got, unix.B4000000)
	}
	if termios.Ospeed != termiosBits(unix.B4000000) {
		t.Fatalf("Ospeed=%#x, want %#x", termios.Ospeed, unix.B4000000)
	}
}

func TestLinuxHelpIncludesHighestNamedBaud(t *testing.T) {
	if !slices.Contains(TermiosHelpNames(), "b4000000") {
		t.Fatal("TermiosHelpNames does not include b4000000")
	}
}

func TestApplyTermiosLinuxBaud(t *testing.T) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	defer func() { _ = master.Close() }()
	defer func() { _ = slave.Close() }()

	spec, err := parse.ParseSpec("PTY,ispeed=115200,ospeed=115200")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTermios(int(slave.Fd()), spec); err != nil {
		t.Fatal(err)
	}
	termios, err := getTermios(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if got := termios.Cflag & termiosBits(unix.CBAUD); got != termiosBits(unix.B115200) {
		t.Fatalf("output CBAUD=%#x, want %#x", got, unix.B115200)
	}
	if got := termios.Cflag & termiosBits(unix.CIBAUD); got != (termiosBits(unix.B115200)<<16)&termiosBits(unix.CIBAUD) {
		t.Fatalf("input CIBAUD=%#x, want encoded B115200", got)
	}
}
