//go:build linux || darwin

package xio

import (
	"fmt"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestParseWinsz(t *testing.T) {
	spec, err := parse.ParseSpec("PTY,tiocswinsz=177:37")
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: "PTY"})
	if err != nil {
		t.Fatal(err)
	}
	if got := config.Terminal.Actions; len(got) != 1 || got[0].Col != 177 || got[0].Row != 37 {
		t.Fatalf("winsize action=%+v", got)
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
	config, err := addrconfig.Decode(s, addrconfig.Facts{Type: "PTY"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyConfiguredTermios(fd, config.Terminal); err != nil {
		t.Fatal(err)
	}
	tio, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	return tio
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
	s, err := parse.ParseSpec("PTY,vintr")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := addrconfig.Decode(s, addrconfig.Facts{Type: "PTY"}); err == nil || !strings.Contains(err.Error(), "value required") {
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

func TestApplyConfiguredTermiosPreservesActionOrder(t *testing.T) {
	fd := openPTYSlave(t)
	spec, err := parse.ParseSpec("PTY,sane,echo=0,vintr=7")
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: "PTY"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyConfiguredTermios(fd, config.Terminal); err != nil {
		t.Fatal(err)
	}
	tio, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if tio.Lflag&unix.ECHO != 0 || tio.Cc[unix.VINTR] != 7 {
		t.Fatalf("prepared actions left ECHO=%t VINTR=%d", tio.Lflag&unix.ECHO != 0, tio.Cc[unix.VINTR])
	}
}
