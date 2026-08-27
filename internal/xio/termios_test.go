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

func TestApplyTermiosCatalogAliases(t *testing.T) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	defer func() { _ = master.Close() }()
	defer func() { _ = slave.Close() }()

	s, err := parse.ParseSpec("PTY,crterase=0,termios-cfmakeraw")
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
		t.Fatal("termios-cfmakeraw did not clear echo")
	}

	s, err = parse.ParseSpec("PTY,sane,echoe=1,crterase=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTermios(int(slave.Fd()), s); err != nil {
		t.Fatal(err)
	}
	tio, err = getTermios(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if tio.Lflag&unix.ECHOE != 0 {
		t.Fatal("last-wins crterase=0 left ECHOE set")
	}

	s, err = parse.ParseSpec("PTY,hup,tandem")
	if err != nil {
		t.Fatal(err)
	}
	if !s.BoolOption("hupcl") || !s.BoolOption("ixoff") {
		t.Fatalf("hup/tandem did not fold: options=%v", s.Options)
	}
}

func TestRawAndCFMakeRawRemainDistinct(t *testing.T) {
	base := unix.Termios{
		Iflag: termiosBits(unix.IXOFF | unix.IMAXBEL),
		Cflag: termiosBits(unix.PARENB | unix.CS7),
		Lflag: termiosBits(unix.ECHO | unix.IEXTEN | unix.ISIG | unix.ICANON),
	}

	raw := base
	applyCombo(&raw, "raw")
	if raw.Iflag&termiosBits(unix.IXOFF|unix.IMAXBEL) != 0 {
		t.Fatalf("raw left classic input processing enabled: Iflag=%#x", raw.Iflag)
	}
	if raw.Lflag&termiosBits(unix.ECHO|unix.IEXTEN) != termiosBits(unix.ECHO|unix.IEXTEN) {
		t.Fatalf("raw unexpectedly changed ECHO/IEXTEN: Lflag=%#x", raw.Lflag)
	}
	if raw.Cflag != base.Cflag {
		t.Fatalf("raw unexpectedly changed character size/parity: Cflag=%#x want %#x", raw.Cflag, base.Cflag)
	}

	cfmake := base
	applyCombo(&cfmake, "cfmakeraw")
	if cfmake.Iflag&termiosBits(unix.IXOFF|unix.IMAXBEL) != termiosBits(unix.IXOFF|unix.IMAXBEL) {
		t.Fatalf("cfmakeraw unexpectedly used classic raw input mask: Iflag=%#x", cfmake.Iflag)
	}
	if cfmake.Lflag&termiosBits(unix.ECHO|unix.IEXTEN) != 0 {
		t.Fatalf("cfmakeraw left ECHO/IEXTEN enabled: Lflag=%#x", cfmake.Lflag)
	}
	if cfmake.Cflag&termiosBits(unix.PARENB|unix.CSIZE) != termiosBits(unix.CS8) {
		t.Fatalf("cfmakeraw did not select eight-bit no-parity mode: Cflag=%#x", cfmake.Cflag)
	}
}

func TestApplyTermiosUsesCommandLineOrder(t *testing.T) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	defer func() { _ = master.Close() }()
	defer func() { _ = slave.Close() }()

	for _, tc := range []struct {
		spec     string
		wantEcho bool
	}{
		{spec: "PTY,echo=0,sane", wantEcho: true},
		{spec: "PTY,sane,echo=0", wantEcho: false},
		{spec: "PTY,cfmakeraw,sane", wantEcho: true},
		{spec: "PTY,sane,cfmakeraw", wantEcho: false},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			s, parseErr := parse.ParseSpec(tc.spec)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if applyErr := ApplyTermios(int(slave.Fd()), s); applyErr != nil {
				t.Fatal(applyErr)
			}
			tio, getErr := getTermios(int(slave.Fd()))
			if getErr != nil {
				t.Fatal(getErr)
			}
			if got := tio.Lflag&unix.ECHO != 0; got != tc.wantEcho {
				t.Fatalf("ECHO=%v want %v (Lflag=%#x)", got, tc.wantEcho, tio.Lflag)
			}
		})
	}
}
