//go:build linux || darwin

package xio

import (
	"runtime"
	"slices"
	"testing"

	"github.com/oittaa/socat/internal/parse"
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
		{"PTY,sane,echoprt", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.ECHOPRT), termiosBits(unix.ECHOPRT)},
		{"PTY,sane,flusho", func(t *unix.Termios) termiosBits { return t.Lflag }, termiosBits(unix.FLUSHO), termiosBits(unix.FLUSHO)},
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
		{"PTY,sane,nldly", func(t *unix.Termios) termiosBits { return t.Oflag }, termiosNLDLY, termiosNLDLY},
		{"PTY,sane,bsdly", func(t *unix.Termios) termiosBits { return t.Oflag }, termiosBSDLY, termiosBSDLY},
		{"PTY,sane,vtdly", func(t *unix.Termios) termiosBits { return t.Oflag }, termiosVTDLY, termiosVTDLY},
		{"PTY,sane,ffdly", func(t *unix.Termios) termiosBits { return t.Oflag }, termiosFFDLY, termiosFFDLY},
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
		spec string
		mask termiosBits
		want termiosBits
	}{
		{"PTY,sane,nl1", termiosNLDLY, termiosBits(unix.NL1)},
		{"PTY,sane,nl1,nl0", termiosNLDLY, termiosNL0},
		{"PTY,sane,cr1", termiosCRDLY, termiosBits(unix.CR1)},
		{"PTY,sane,cr2", termiosCRDLY, termiosBits(unix.CR2)},
		{"PTY,sane,cr3", termiosCRDLY, termiosBits(unix.CR3)},
		{"PTY,sane,cr3,cr0", termiosCRDLY, termiosCR0},
		{"PTY,sane,tab1", termiosTABDLY, termiosBits(unix.TAB1)},
		{"PTY,sane,tab2", termiosTABDLY, termiosBits(unix.TAB2)},
		{"PTY,sane,tab3", termiosTABDLY, termiosBits(unix.TAB3)},
		{"PTY,sane,tab1,tab3", termiosTABDLY, termiosBits(unix.TAB3)},
		{"PTY,sane,bs1", termiosBSDLY, termiosBits(unix.BS1)},
		{"PTY,sane,bs1,bs0", termiosBSDLY, termiosBS0},
		{"PTY,sane,vt1", termiosVTDLY, termiosBits(unix.VT1)},
		{"PTY,sane,ff1", termiosFFDLY, termiosBits(unix.FF1)},
		{"PTY,sane,onlcr=0", termiosBits(unix.ONLCR), 0},
		{"PTY,sane,ocrnl", termiosBits(unix.OCRNL), termiosBits(unix.OCRNL)},
		{"PTY,sane,onocr", termiosBits(unix.ONOCR), termiosBits(unix.ONOCR)},
		{"PTY,sane,onlret", termiosBits(unix.ONLRET), termiosBits(unix.ONLRET)},
	}
	if f, ok := lookupTermiosFlag("xtabs"); ok {
		patterns = append(patterns, struct {
			spec string
			mask termiosBits
			want termiosBits
		}{"PTY,sane,xtabs", f.clr, f.mask})
	}
	for _, tc := range patterns {
		t.Run(tc.spec, func(t *testing.T) {
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
		"vt0", "vt1", "ff0", "ff1", "sane", "raw", "b7200",
		"nldly", "crdly", "bsdly", "vtdly", "ffdly", "csize",
		"echoprt", "prterase", "flusho",
	}
	switch runtime.GOOS {
	case "linux":
		want = append(want, "tabdly", "xtabs", "vswtc", "swtc", "swtch", "iuclc", "olcuc", "xcase")
	case "darwin":
		for _, n := range []string{"tabdly", "xtabs", "vswtc", "swtc", "swtch", "iuclc"} {
			if slices.Contains(names, n) {
				t.Errorf("TermiosHelpNames must not advertise %q on Darwin", n)
			}
		}
	}
	for _, n := range want {
		if !slices.Contains(names, n) {
			t.Errorf("TermiosHelpNames missing %q", n)
		}
	}
	if !slices.Contains(names, "b7200") {
		t.Fatalf("b7200 must be advertised on %s", runtime.GOOS)
	}
	if slices.Contains(names, "extproc") {
		t.Fatal("extproc is not advertised")
	}
}

func TestApplyTermiosValueOptions(t *testing.T) {
	fd := openPTYSlave(t)
	tio := applyTermiosSpec(t, fd, "PTY,sane,crdly=3,csize=3")
	if got := tio.Oflag & termiosCRDLY; got != termiosBits(unix.CR3) {
		t.Fatalf("crdly=3 got %#x want %#x", got, unix.CR3)
	}
	if got := tio.Cflag & termiosBits(unix.CSIZE); got != termiosBits(unix.CS8) {
		t.Fatalf("csize=3 got %#x want %#x", got, unix.CS8)
	}
	if _, ok := lookupTermiosValue("tabdly"); ok {
		withTab := applyTermiosSpec(t, fd, "PTY,sane,tabdly=2")
		if got := withTab.Oflag & termiosTABDLY; got != termiosBits(unix.TAB2) {
			t.Fatalf("tabdly=2 got %#x want %#x", got, unix.TAB2)
		}
	}

	invalid := []string{"PTY,crdly=4", "PTY,csize=4"}
	if _, ok := lookupTermiosValue("tabdly"); ok {
		invalid = append(invalid, "PTY,tabdly=4")
	}
	for _, spec := range invalid {
		s, err := parse.ParseSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplyTermios(fd, s); err == nil {
			t.Errorf("%s succeeded", spec)
		}
	}
}

func TestPOSIXTermiosValuesMatchTwoBitFields(t *testing.T) {
	if _, ok := termiosTwoBitShift(termiosCRDLY); !ok {
		t.Fatal("CRDLY must be a 2-bit field")
	}
	if _, ok := termiosTwoBitShift(termiosBits(unix.CSIZE)); !ok {
		t.Fatal("CSIZE must be a 2-bit field")
	}
	_, tabField := termiosTwoBitShift(termiosTABDLY)
	_, hasTabdly := lookupTermiosValue("tabdly")
	if tabField != hasTabdly {
		t.Fatalf("tabdly advertised=%v two-bit-field=%v", hasTabdly, tabField)
	}
	switch runtime.GOOS {
	case "linux":
		if !hasTabdly {
			t.Fatal("Linux TABDLY is a 2-bit field; tabdly must be advertised")
		}
		if _, ok := lookupTermiosFlag("xtabs"); !ok {
			t.Fatal("Linux must advertise xtabs")
		}
	case "darwin":
		if hasTabdly {
			t.Fatal("Darwin TABDLY is not a 2-bit field; do not advertise tabdly")
		}
		if _, ok := lookupTermiosFlag("xtabs"); ok {
			t.Fatal("Darwin does not define XTABS; do not advertise xtabs")
		}
	}
}
