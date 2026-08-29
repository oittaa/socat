//go:build linux || darwin

package xio

import (
	"fmt"
	"strings"
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
	tio := applyTermiosSpec(t, fd, "PTY,intr=3,quit=0x1c,erase=8,kill=21,eof=4,eol=0,min=4,time=1,start=17,stop=19,susp=26,werase=23,lnext=22,discard=15,reprint=18,eol2=0xff")
	if tio.Cc[unix.VINTR] != 3 {
		t.Fatalf("vintr=%d", tio.Cc[unix.VINTR])
	}
	if tio.Cc[unix.VQUIT] != 0x1c {
		t.Fatalf("vquit=%d", tio.Cc[unix.VQUIT])
	}
	if tio.Cc[unix.VERASE] != 8 {
		t.Fatalf("verase=%d", tio.Cc[unix.VERASE])
	}
	if tio.Cc[unix.VKILL] != 21 {
		t.Fatalf("vkill=%d", tio.Cc[unix.VKILL])
	}
	if tio.Cc[unix.VEOF] != 4 {
		t.Fatalf("veof=%d", tio.Cc[unix.VEOF])
	}
	if tio.Cc[unix.VMIN] != 4 {
		t.Fatalf("vmin=%d", tio.Cc[unix.VMIN])
	}
	if tio.Cc[unix.VTIME] != 1 {
		t.Fatalf("vtime=%d", tio.Cc[unix.VTIME])
	}
	if tio.Cc[unix.VSTART] != 17 {
		t.Fatalf("vstart=%d", tio.Cc[unix.VSTART])
	}
	if tio.Cc[unix.VSTOP] != 19 {
		t.Fatalf("vstop=%d", tio.Cc[unix.VSTOP])
	}
	if tio.Cc[unix.VSUSP] != 26 {
		t.Fatalf("vsusp=%d", tio.Cc[unix.VSUSP])
	}
	if tio.Cc[unix.VWERASE] != 23 {
		t.Fatalf("vwerase=%d", tio.Cc[unix.VWERASE])
	}
	if tio.Cc[unix.VLNEXT] != 22 {
		t.Fatalf("vlnext=%d", tio.Cc[unix.VLNEXT])
	}
	if tio.Cc[unix.VDISCARD] != 15 {
		t.Fatalf("vdiscard=%d", tio.Cc[unix.VDISCARD])
	}
	if tio.Cc[unix.VREPRINT] != 18 {
		t.Fatalf("vreprint=%d", tio.Cc[unix.VREPRINT])
	}
	if tio.Cc[unix.VEOL2] != 255 {
		t.Fatalf("veol2=%d", tio.Cc[unix.VEOL2])
	}
	rprnt := applyTermiosSpec(t, fd, "PTY,rprnt=9")
	if rprnt.Cc[unix.VREPRINT] != 9 {
		t.Fatalf("rprnt=%d", rprnt.Cc[unix.VREPRINT])
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

func TestApplyTermiosBareVintrIsRejected(t *testing.T) {
	fd := openPTYSlave(t)
	s, err := parse.ParseSpec("PTY,vintr")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTermios(fd, s); err == nil || !strings.Contains(err.Error(), "value required") {
		t.Fatalf("bare vintr error=%v", err)
	}
}

func TestApplyTermiosByteOverflowClamps(t *testing.T) {
	fd := openPTYSlave(t)
	tio := applyTermiosSpec(t, fd, "PTY,vintr=256")
	if tio.Cc[unix.VINTR] != 255 {
		t.Fatalf("vintr overflow=%d want 255", tio.Cc[unix.VINTR])
	}
	hex := applyTermiosSpec(t, fd, "PTY,veol2=0x100")
	if hex.Cc[unix.VEOL2] != 255 {
		t.Fatalf("veol2 overflow=%d want 255", hex.Cc[unix.VEOL2])
	}
	huge := applyTermiosSpec(t, fd, "PTY,vquit=999999999999999999999999999999999999999")
	if huge.Cc[unix.VQUIT] != 255 {
		t.Fatalf("vquit huge overflow=%d want 255", huge.Cc[unix.VQUIT])
	}
}

func TestApplyTermiosHelpNamesIncludeCharsAndNotHPUnix(t *testing.T) {
	names := TermiosHelpNames()
	want := []string{
		"vintr", "intr", "veol2", "eol2", "vmin", "min", "sane", "raw",
		"cfmakeraw", "termios-cfmakeraw", "rawer", "termios-rawer",
		"termios-setflags", "setflags", "echoprt", "prterase",
	}
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

func TestApplyTermiosSetFlagsAndOrder(t *testing.T) {
	fd := openPTYSlave(t)
	spec := fmt.Sprintf("PTY,setflags=0:%d,brkint", unix.IGNBRK)
	tio := applyTermiosSpec(t, fd, spec)
	want := termiosBits(unix.IGNBRK | unix.BRKINT)
	if got := tio.Iflag & want; got != want {
		t.Fatalf("setflags then brkint: Iflag=%#x want bits %#x", tio.Iflag, want)
	}

	spec = fmt.Sprintf("PTY,brkint,termios-setflags=0:%d", unix.IGNBRK)
	tio = applyTermiosSpec(t, fd, spec)
	if tio.Iflag&termiosBits(unix.BRKINT) != 0 || tio.Iflag&termiosBits(unix.IGNBRK) == 0 {
		t.Fatalf("last termios-setflags did not replace iflag: %#x", tio.Iflag)
	}
}

func TestApplyTermiosRejectsInvalidOptionTypes(t *testing.T) {
	fd := openPTYSlave(t)
	for _, spec := range []string{
		"PTY,echo=false",
		"PTY,raw=0",
		"PTY,b9600=0",
		"PTY,ispeed=bad",
		"PTY,termios-setflags=4:1",
		"PTY,termios-setflags=0",
		"PTY,tiocswinsz",
	} {
		t.Run(spec, func(t *testing.T) {
			s, err := parse.ParseSpec(spec)
			if err != nil {
				t.Fatal(err)
			}
			if err := ApplyTermios(fd, s); err == nil {
				t.Fatal("ApplyTermios succeeded")
			}
		})
	}
}

func TestValidateTermiosOptionClassicIntegerDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  string
	}{
		{value: "b19200", want: "missing numerical value"},
		{value: "19200B", want: "trailing garbage"},
	} {
		err := ValidateTermiosOption(parse.Option{Name: "ispeed", Value: tc.value, Has: true})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("ispeed=%q: err=%v want %q", tc.value, err, tc.want)
		}
	}
	if err := ValidateTermiosOption(parse.Option{Name: "ispeed", Value: "0x2580", Has: true}); err != nil {
		t.Fatalf("base-0 ispeed: %v", err)
	}
}

func TestApplyTermiosDoesNotIgnoreStateOptionsOnNonTTY(t *testing.T) {
	pipeFDs := []int{0, 0}
	if err := unix.Pipe(pipeFDs); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(pipeFDs[0]) }()
	defer func() { _ = unix.Close(pipeFDs[1]) }()

	plain, err := parse.ParseSpec("FD:3")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTermios(pipeFDs[0], plain); err != nil {
		t.Fatalf("plain non-TTY spec: %v", err)
	}

	withEcho, err := parse.ParseSpec("FD:3,echo=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTermios(pipeFDs[0], withEcho); err == nil {
		t.Fatal("echo=0 on non-TTY was silently ignored")
	}
}

func TestApplyTermiosCatalogAliases(t *testing.T) {
	fd := openPTYSlave(t)
	tio := applyTermiosSpec(t, fd, "PTY,crterase=0,termios-cfmakeraw")
	if tio.Lflag&unix.ECHO != 0 {
		t.Fatal("termios-cfmakeraw did not clear echo")
	}

	tio = applyTermiosSpec(t, fd, "PTY,sane,echoe=1,crterase=0")
	if tio.Lflag&unix.ECHOE != 0 {
		t.Fatal("last-wins crterase=0 left ECHOE set")
	}

	s, err := parse.ParseSpec("PTY,hup,tandem")
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
	fd := openPTYSlave(t)
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
			tio := applyTermiosSpec(t, fd, tc.spec)
			if got := tio.Lflag&unix.ECHO != 0; got != tc.wantEcho {
				t.Fatalf("ECHO=%v want %v (Lflag=%#x)", got, tc.wantEcho, tio.Lflag)
			}
		})
	}
}
