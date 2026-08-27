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

func openPTYSlave(t *testing.T) (fd int) {
	t.Helper()
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		_ = slave.Close()
	})
	return int(slave.Fd())
}

func applyTermiosSpec(t *testing.T, fd int, spec string) *unix.Termios {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTermios(fd, s); err != nil {
		t.Fatal(err)
	}
	tio, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	return tio
}

func TestApplyTermiosControlChars(t *testing.T) {
	fd := openPTYSlave(t)
	const want byte = 0x42
	chars := []struct {
		opt string
		idx int
	}{
		{"vintr", unix.VINTR},
		{"vquit", unix.VQUIT},
		{"verase", unix.VERASE},
		{"vkill", unix.VKILL},
		{"veof", unix.VEOF},
		{"veol", unix.VEOL},
		{"veol2", unix.VEOL2},
		{"vmin", unix.VMIN},
		{"vtime", unix.VTIME},
		{"vstart", unix.VSTART},
		{"vstop", unix.VSTOP},
		{"vsusp", unix.VSUSP},
		{"vwerase", unix.VWERASE},
		{"vlnext", unix.VLNEXT},
		{"vdiscard", unix.VDISCARD},
		{"vreprint", unix.VREPRINT},
	}
	for _, tc := range chars {
		t.Run(tc.opt, func(t *testing.T) {
			tio := applyTermiosSpec(t, fd, "PTY,"+tc.opt+"=0x42")
			if tio.Cc[tc.idx] != want {
				t.Fatalf("cc[%s]=%d want %d", tc.opt, tio.Cc[tc.idx], want)
			}
		})
	}
}

func TestApplyTermiosControlCharAliases(t *testing.T) {
	fd := openPTYSlave(t)
	tio := applyTermiosSpec(t, fd, "PTY,intr=3,quit=0x1c,erase=8,min=4,reprint=18,eol2=0xff")
	if tio.Cc[unix.VINTR] != 3 {
		t.Fatalf("vintr=%d", tio.Cc[unix.VINTR])
	}
	if tio.Cc[unix.VQUIT] != 0x1c {
		t.Fatalf("vquit=%d", tio.Cc[unix.VQUIT])
	}
	if tio.Cc[unix.VERASE] != 8 {
		t.Fatalf("verase=%d", tio.Cc[unix.VERASE])
	}
	if tio.Cc[unix.VMIN] != 4 {
		t.Fatalf("vmin=%d", tio.Cc[unix.VMIN])
	}
	if tio.Cc[unix.VREPRINT] != 18 {
		t.Fatalf("vreprint=%d", tio.Cc[unix.VREPRINT])
	}
	if tio.Cc[unix.VEOL2] != 255 {
		t.Fatalf("veol2=%d", tio.Cc[unix.VEOL2])
	}
}

func TestApplyTermiosCharLastWins(t *testing.T) {
	fd := openPTYSlave(t)
	tio := applyTermiosSpec(t, fd, "PTY,vintr=1,intr=7")
	if tio.Cc[unix.VINTR] != 7 {
		t.Fatalf("vintr last-wins=%d want 7", tio.Cc[unix.VINTR])
	}
}

func TestApplyTermiosCommandLineOrder(t *testing.T) {
	fd := openPTYSlave(t)
	echoOff := applyTermiosSpec(t, fd, "PTY,sane,echo=0")
	if echoOff.Lflag&unix.ECHO != 0 {
		t.Fatal("sane,echo=0 left ECHO set")
	}
	echoOn := applyTermiosSpec(t, fd, "PTY,echo=0,sane")
	if echoOn.Lflag&unix.ECHO == 0 {
		t.Fatal("echo=0,sane left ECHO clear")
	}
}

func TestApplyTermiosRawVsCfmakeraw(t *testing.T) {
	fd := openPTYSlave(t)
	raw := applyTermiosSpec(t, fd, "PTY,raw")
	if raw.Lflag&unix.ICANON != 0 {
		t.Fatal("raw did not clear ICANON")
	}
	if raw.Lflag&unix.ISIG != 0 {
		t.Fatal("raw did not clear ISIG")
	}
	if raw.Lflag&unix.ECHO == 0 {
		t.Fatal("classic raw must not clear ECHO")
	}
	if raw.Cc[unix.VMIN] != 1 || raw.Cc[unix.VTIME] != 0 {
		t.Fatalf("raw vmin/vtime=%d/%d", raw.Cc[unix.VMIN], raw.Cc[unix.VTIME])
	}

	cf := applyTermiosSpec(t, fd, "PTY,sane,cfmakeraw")
	if cf.Lflag&unix.ECHO != 0 {
		t.Fatal("cfmakeraw did not clear ECHO")
	}
	if cf.Lflag&unix.ICANON != 0 {
		t.Fatal("cfmakeraw did not clear ICANON")
	}
}

func TestApplyTermiosSaneSetsCanonical(t *testing.T) {
	fd := openPTYSlave(t)
	tio := applyTermiosSpec(t, fd, "PTY,rawer,sane")
	if tio.Lflag&unix.ICANON == 0 || tio.Lflag&unix.ECHO == 0 || tio.Lflag&unix.ISIG == 0 {
		t.Fatalf("sane Lflag=%#x", tio.Lflag)
	}
	if tio.Oflag&unix.OPOST == 0 || tio.Oflag&unix.ONLCR == 0 {
		t.Fatalf("sane Oflag=%#x", tio.Oflag)
	}
}

func TestApplyTermiosBareVintrIsOne(t *testing.T) {
	fd := openPTYSlave(t)
	tio := applyTermiosSpec(t, fd, "PTY,vintr")
	if tio.Cc[unix.VINTR] != 1 {
		t.Fatalf("bare vintr=%d want 1", tio.Cc[unix.VINTR])
	}
}

func TestApplyTermiosHelpNamesIncludeCharsAndNotHPUnix(t *testing.T) {
	names := TermiosHelpNames()
	want := []string{"vintr", "intr", "veol2", "eol2", "vmin", "min", "sane", "raw", "cfmakeraw"}
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, n := range want {
		if !have[n] {
			t.Errorf("TermiosHelpNames missing %q", n)
		}
	}
	for _, n := range []string{"dsusp", "vdsusp", "b900", "b3600"} {
		if have[n] {
			t.Errorf("TermiosHelpNames must not advertise HP-UX-only %q", n)
		}
	}
}
