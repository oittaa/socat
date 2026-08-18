//go:build unix

package xio

import (
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplyTermiosEchoAndWinsz(t *testing.T) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	defer func() { _ = master.Close() }()
	defer func() { _ = slave.Close() }()

	s, err := parse.ParseSpec("PTY,echo=0,tiocswinsz=177:37")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTermios(int(slave.Fd()), s); err != nil {
		t.Fatal(err)
	}
	tio, err := getTermios(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if tio.Lflag&unix.ECHO != 0 {
		t.Fatal("echo still set")
	}
	ws, err := unix.IoctlGetWinsize(int(slave.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Col != 177 || ws.Row != 37 {
		t.Fatalf("winsz %dx%d", ws.Col, ws.Row)
	}
}

func TestRestoreTermios(t *testing.T) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	defer func() { _ = master.Close() }()
	defer func() { _ = slave.Close() }()

	before, err := getTermios(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	o := &Opened{}
	s, err := parse.ParseSpec("PTY,cfmakeraw")
	if err != nil {
		t.Fatal(err)
	}
	if err := AttachTermios(o, int(slave.Fd()), s); err != nil {
		t.Fatal(err)
	}
	mid, err := getTermios(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if mid.Lflag&unix.ECHO != 0 {
		t.Fatal("cfmakeraw did not clear echo")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := getTermios(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if after.Lflag != before.Lflag || after.Iflag != before.Iflag {
		t.Fatalf("not restored: before L=%#x I=%#x after L=%#x I=%#x",
			before.Lflag, before.Iflag, after.Lflag, after.Iflag)
	}
}

func TestWaitPTYSlave(t *testing.T) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	name := slave.Name()
	_ = slave.Close()
	done := make(chan error, 1)
	go func() {
		done <- WaitPTYSlave(int(master.Fd()), 20*time.Millisecond)
	}()
	time.Sleep(50 * time.Millisecond)
	s2, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(s2) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wait-slave timeout")
	}
	_ = master.Close()
}

func TestParseWinsz(t *testing.T) {
	c, r, err := parseWinsz("177:37")
	if err != nil || c != 177 || r != 37 {
		t.Fatalf("%d %d %v", c, r, err)
	}
}
