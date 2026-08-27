//go:build linux || darwin

package xio

import (
	"runtime"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestApplyTermiosLegacyFlags(t *testing.T) {
	fd := openPTYSlave(t)
	type flagCase struct {
		spec string
		word func(*unix.Termios) termiosBits
		mask termiosBits
		want termiosBits
	}
	cases := []flagCase{
		{"PTY,sane,pendin", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.PENDIN), termiosBits(unix.PENDIN)},
		{"PTY,sane,ofill", func(t *unix.Termios) termiosBits { return t.Oflag }, termiosBits(unix.OFILL), termiosBits(unix.OFILL)},
		{"PTY,sane,ofdel", func(t *unix.Termios) termiosBits { return t.Oflag }, termiosBits(unix.OFDEL), termiosBits(unix.OFDEL)},
		{"PTY,sane,crtscts", func(t *unix.Termios) termiosBits { return t.Cflag }, termiosBits(unix.CRTSCTS), termiosBits(unix.CRTSCTS)},
		{"PTY,sane,hupcl", func(t *unix.Termios) termiosBits { return t.Cflag }, termiosBits(unix.HUPCL), termiosBits(unix.HUPCL)},
		{"PTY,sane,cstopb", func(t *unix.Termios) termiosBits { return t.Cflag }, termiosBits(unix.CSTOPB), termiosBits(unix.CSTOPB)},
		{"PTY,sane,parodd", func(t *unix.Termios) termiosBits { return t.Cflag }, termiosBits(unix.PARODD), termiosBits(unix.PARODD)},
		{"PTY,sane,icanon=0", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.ICANON), 0},
		{"PTY,sane,isig=0", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.ISIG), 0},
		{"PTY,sane,iexten=0", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.IEXTEN), 0},
		{"PTY,sane,ixon=0", func(t *unix.Termios) termiosBits { return t.Iflag }, termiosBits(unix.IXON), 0},
		{"PTY,sane,ixoff", func(t *unix.Termios) termiosBits { return t.Iflag }, termiosBits(unix.IXOFF), termiosBits(unix.IXOFF)},
		{"PTY,sane,ixany", func(t *unix.Termios) termiosBits { return t.Iflag }, termiosBits(unix.IXANY), termiosBits(unix.IXANY)},
		{"PTY,sane,echoe=0", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.ECHOE), 0},
		{"PTY,sane,echok=0", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.ECHOK), 0},
		{"PTY,sane,echonl", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.ECHONL), termiosBits(unix.ECHONL)},
		{"PTY,sane,echoctl=0", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.ECHOCTL), 0},
		{"PTY,sane,echoke=0", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.ECHOKE), 0},
		{"PTY,sane,noflsh", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.NOFLSH), termiosBits(unix.NOFLSH)},
		{"PTY,sane,tostop", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.TOSTOP), termiosBits(unix.TOSTOP)},
		{"PTY,sane,icanon=0,icanon", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.ICANON), termiosBits(unix.ICANON)},
	}
	if runtime.GOOS == "linux" {
		cases = append(cases,
			flagCase{"PTY,sane,iuclc", func(t *unix.Termios) termiosBits { return t.Iflag }, termiosIUCLC, termiosIUCLC},
			flagCase{"PTY,sane,iuclc=0", func(t *unix.Termios) termiosBits { return t.Iflag }, termiosIUCLC, 0},
			flagCase{"PTY,sane,olcuc", func(t *unix.Termios) termiosBits { return t.Oflag }, termiosOLCUC, termiosOLCUC},
			flagCase{"PTY,sane,xcase", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosXCASE, termiosXCASE},
		)
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			tio := applyTermiosSpec(t, fd, tc.spec)
			if got := tc.word(tio) & tc.mask; got != tc.want {
				t.Fatalf("got %#x want %#x (word=%#x)", got, tc.want, tc.word(tio))
			}
		})
	}
}

func TestApplyTermiosDelayPatterns(t *testing.T) {
	fd := openPTYSlave(t)
	patterns := []struct {
		spec     string
		mask     termiosBits
		want     termiosBits
		linuxDLY bool
	}{
		{"PTY,sane,nl1", termiosNLDLY, termiosBits(unix.NL1), true},
		{"PTY,sane,nl1,nl0", termiosNLDLY, termiosNL0, true},
		{"PTY,sane,cr1", termiosCRDLY, termiosBits(unix.CR1), true},
		{"PTY,sane,cr2", termiosCRDLY, termiosBits(unix.CR2), true},
		{"PTY,sane,cr3", termiosCRDLY, termiosBits(unix.CR3), true},
		{"PTY,sane,cr3,cr0", termiosCRDLY, termiosCR0, true},
		{"PTY,sane,tab1", termiosTABDLY, termiosBits(unix.TAB1), true},
		{"PTY,sane,tab2", termiosTABDLY, termiosBits(unix.TAB2), true},
		{"PTY,sane,tab3", termiosTABDLY, termiosBits(unix.TAB3), true},
		{"PTY,sane,tab1,tab3", termiosTABDLY, termiosBits(unix.TAB3), true},
		{"PTY,sane,bs1", termiosBSDLY, termiosBits(unix.BS1), true},
		{"PTY,sane,bs1,bs0", termiosBSDLY, termiosBS0, true},
		{"PTY,sane,vt1", termiosVTDLY, termiosBits(unix.VT1), true},
		{"PTY,sane,ff1", termiosFFDLY, termiosBits(unix.FF1), true},
		{"PTY,sane,onlcr=0", termiosBits(unix.ONLCR), 0, false},
		{"PTY,sane,ocrnl", termiosBits(unix.OCRNL), termiosBits(unix.OCRNL), false},
		{"PTY,sane,onocr", termiosBits(unix.ONOCR), termiosBits(unix.ONOCR), false},
		{"PTY,sane,onlret", termiosBits(unix.ONLRET), termiosBits(unix.ONLRET), false},
	}
	for _, tc := range patterns {
		t.Run(tc.spec, func(t *testing.T) {
			if tc.linuxDLY && runtime.GOOS != "linux" {
				t.Skip("classic Linux NLDLY/CRDLY/TABDLY/BSDLY/VTDLY/FFDLY field masks")
			}
			tio := applyTermiosSpec(t, fd, tc.spec)
			if got := tio.Oflag & tc.mask; got != tc.want {
				t.Fatalf("Oflag&mask=%#x want %#x (Oflag=%#x)", got, tc.want, tio.Oflag)
			}
		})
	}
}

func TestTermiosHelpIncludesCompletion(t *testing.T) {
	names := TermiosHelpNames()
	want := []string{
		"vintr", "intr", "pendin", "ofill", "ofdel",
		"nl0", "nl1", "cr0", "cr1", "cr2", "cr3", "tab0", "tab3", "bs0", "bs1",
		"vt0", "vt1", "ff0", "ff1", "sane", "raw",
	}
	if runtime.GOOS == "linux" {
		want = append(want, "iuclc", "olcuc", "xcase")
	}
	for _, n := range want {
		if !slices.Contains(names, n) {
			t.Errorf("TermiosHelpNames missing %q", n)
		}
	}
	has7200 := slices.Contains(names, "b7200")
	switch runtime.GOOS {
	case "linux":
		if has7200 {
			t.Fatal("b7200 must not be advertised on Linux without unix.B7200")
		}
	case "darwin":
		if !has7200 {
			t.Fatal("b7200 must be advertised on Darwin (unix.B7200)")
		}
	}
	if slices.Contains(names, "extproc") {
		t.Fatal("extproc is not in classic Linux -hhh; do not advertise")
	}
}
