//go:build linux || darwin

package xio

import (
	"fmt"
	"os"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio/termios"
	"golang.org/x/sys/unix"
)

// TestSignalExitRestoresPTYTermios is the regression for signal exit leaving
// the terminal in raw mode. SIGTERM/SIGHUP/SIGINT call UnlinkRegisteredPaths
// and then os.Exit, which skips Opened.Close. STDIO applies the same options
// to two descriptors of one terminal, so the later snapshot is the raw state
// and must run first.
func TestSignalExitRestoresPTYTermios(t *testing.T) {
	master, slave, err := termios.OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		_ = slave.Close()
	})
	dupFD, err := unix.Dup(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(dupFD) })

	orig, err := termios.GetTermios(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if orig.Lflag&unix.ECHO == 0 || orig.Lflag&unix.ICANON == 0 {
		t.Fatalf("pty slave is not cooked: %s", formatTermios(orig))
	}

	o, err := NewReady("STDIO", relay.FDStream{C: NopCloser{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	config := terminalConfig(t, "STDIO,raw,echo=0")
	if err := AttachConfiguredTermios(o, int(slave.Fd()), config); err != nil {
		t.Fatal(err)
	}
	if err := AttachConfiguredTermios(o, dupFD, config); err != nil {
		t.Fatal(err)
	}
	raw, err := termios.GetTermios(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if raw.Lflag&unix.ECHO != 0 || raw.Lflag&unix.ICANON != 0 {
		t.Fatalf("raw,echo=0 did not clear echo/canonical: %s", formatTermios(raw))
	}

	// Signal exit does not Close the endpoint.
	UnlinkRegisteredPaths()

	got, err := termios.GetTermios(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if !termiosEqual(orig, got) {
		t.Fatalf("signal exit left the terminal changed\n orig %s\n got  %s", formatTermios(orig), formatTermios(got))
	}
}

// TestCloseDropsTTYExitHook checks that Close restores the terminal and drops
// the signal-exit hook. A later signal cleanup must leave later terminal
// changes alone.
func TestCloseDropsTTYExitHook(t *testing.T) {
	master, slave, err := termios.OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		_ = slave.Close()
	})
	fd := int(slave.Fd())
	orig, err := termios.GetTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewReady("STDIO", relay.FDStream{C: NopCloser{}})
	if err != nil {
		t.Fatal(err)
	}
	config := terminalConfig(t, "STDIO,raw,echo=0")
	before := exitHookCount()
	if err := AttachConfiguredTermios(o, fd, config); err != nil {
		t.Fatal(err)
	}
	if got := exitHookCount(); got != before+1 {
		t.Fatalf("exit hooks=%d want %d", got, before+1)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if got := exitHookCount(); got != before {
		t.Fatalf("close left the exit hook registered: hooks=%d want %d", got, before)
	}
	restored, err := termios.GetTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if !termiosEqual(orig, restored) {
		t.Fatalf("close did not restore termios\n orig %s\n got  %s", formatTermios(orig), formatTermios(restored))
	}
	if err := termios.ApplyConfiguredTermios(fd, config); err != nil {
		t.Fatal(err)
	}
	UnlinkRegisteredPaths()
	got, err := termios.GetTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if got.Lflag&unix.ECHO != 0 || got.Lflag&unix.ICANON != 0 {
		t.Fatalf("closed endpoint's exit hook restored termios: %s", formatTermios(got))
	}
}

// ptyHalfClose is what ShutdownWrite must do to a raw terminal.
type ptyHalfClose int

const (
	ptyNoHalfClose ptyHalfClose = iota
	ptyHalfStaysRaw
	ptyHalfStaysRawError
	ptyHalfRestores
)

// TestPTYTermiosScenarios covers the paths that restore a raw terminal, and
// the half-closes that must leave it raw. shut-close closes the descriptor,
// so it restores during ShutdownWrite. A row with no custom stream is built
// from its address spec.
func TestPTYTermiosScenarios(t *testing.T) {
	stdio := func(slave *os.File) relay.Stream {
		return relay.FDStream{R: slave, W: slave, C: NopCloser{}, CloseW: func() error { return nil }}
	}
	cases := []struct {
		name   string
		spec   string
		stream func(*os.File) relay.Stream
		half   ptyHalfClose
	}{
		{name: "stream close", spec: "OPEN,raw,echo=0"},
		{name: "half-close", spec: "OPEN,raw,echo=0", half: ptyHalfStaysRaw},
		{name: "escape", spec: "OPEN:/dev/null,raw,echo=0,escape=0x1d", half: ptyHalfStaysRaw},
		{name: "readbytes", spec: "OPEN:/dev/null,raw,echo=0,readbytes=100", half: ptyHalfStaysRaw},
		{name: "stdio", spec: "STDIO,raw,echo=0", stream: stdio, half: ptyHalfStaysRaw},
		{name: "shut-none", spec: "OPEN:/dev/null,raw,echo=0,shut-none", half: ptyHalfStaysRaw},
		{name: "shut-down", spec: "OPEN:/dev/null,raw,echo=0,shut-down", half: ptyHalfStaysRawError},
		{name: "end-close", spec: "OPEN,raw,echo=0,end-close", half: ptyHalfStaysRaw},
		{name: "shut-close", spec: "OPEN:/dev/null,raw,echo=0,shut-close", half: ptyHalfRestores},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			master, slave, err := termios.OpenPTYPair()
			if err != nil {
				t.Skipf("pty: %v", err)
			}
			t.Cleanup(func() { _ = master.Close() })
			fd := int(slave.Fd())
			dupFD, err := unix.Dup(fd)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(dupFD) })
			orig, err := termios.GetTermios(fd)
			if err != nil {
				t.Fatal(err)
			}
			if orig.Lflag&unix.ECHO == 0 || orig.Lflag&unix.ICANON == 0 {
				t.Fatalf("pty slave is not cooked: %s", formatTermios(orig))
			}
			config := mustDecodeAddress(t, mustSpec(t, tc.spec))
			var st relay.Stream
			if tc.stream != nil {
				st = tc.stream(slave)
			} else {
				st, err = WrapAfterFD(config, FileStream(slave))
				if err != nil {
					t.Fatal(err)
				}
			}
			o, err := NewReady("OPEN", st)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			if err := AttachConfiguredTermios(o, fd, config.Terminal); err != nil {
				t.Fatal(err)
			}
			raw, err := termios.GetTermios(dupFD)
			if err != nil {
				t.Fatal(err)
			}
			if raw.Lflag&unix.ECHO != 0 || raw.Lflag&unix.ICANON != 0 {
				t.Fatalf("raw,echo=0 did not clear echo/canonical: %s", formatTermios(raw))
			}
			if config.Transfer.EndClose.Value && !streamIsEndClose(o.Stream()) {
				t.Fatal("termios restore wrapper hid end-close")
			}
			if tc.half != ptyNoHalfClose {
				err := o.Stream().ShutdownWrite()
				if tc.half == ptyHalfStaysRawError {
					if err == nil {
						t.Fatal("half-close succeeded")
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if tc.half == ptyHalfRestores {
					mid, err := termios.GetTermios(dupFD)
					if err != nil {
						t.Fatal(err)
					}
					if !termiosEqual(orig, mid) {
						t.Fatalf("half-close left the terminal changed\n orig %s\n got  %s", formatTermios(orig), formatTermios(mid))
					}
				} else {
					if _, err := termios.GetTermios(fd); err != nil {
						t.Fatalf("half-close closed the terminal: %v", err)
					}
					mid, err := termios.GetTermios(dupFD)
					if err != nil {
						t.Fatal(err)
					}
					if mid.Lflag&unix.ECHO != 0 || mid.Lflag&unix.ICANON != 0 || termiosEqual(orig, mid) {
						t.Fatalf("half-close left %s", formatTermios(mid))
					}
				}
			}
			if err := o.Stream().Close(); err != nil {
				t.Fatal(err)
			}
			got, err := termios.GetTermios(dupFD)
			if err != nil {
				t.Fatal(err)
			}
			if !termiosEqual(orig, got) {
				t.Fatalf("close left the terminal changed\n orig %s\n got  %s", formatTermios(orig), formatTermios(got))
			}
			// STDIO and end-close leave the descriptor open.
			if config.Type == "STDIO" || config.Transfer.EndClose.Value {
				if _, err := termios.GetTermios(fd); err != nil {
					t.Fatalf("close closed the descriptor: %v", err)
				}
			}
		})
	}
}

func exitHookCount() int {
	unlinkMu.Lock()
	defer unlinkMu.Unlock()
	return len(exitHooks)
}

func terminalConfig(t *testing.T, spec string) addrconfig.Terminal {
	t.Helper()
	parsed, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(parsed, addrconfig.Facts{Type: parsed.Type})
	if err != nil {
		t.Fatal(err)
	}
	return config.Terminal
}

func termiosEqual(a, b *unix.Termios) bool {
	return a.Iflag == b.Iflag && a.Oflag == b.Oflag && a.Cflag == b.Cflag && a.Lflag == b.Lflag && a.Cc == b.Cc && a.Ispeed == b.Ispeed && a.Ospeed == b.Ospeed
}

func formatTermios(t *unix.Termios) string {
	return fmt.Sprintf("iflag=%#x oflag=%#x cflag=%#x lflag=%#x", t.Iflag, t.Oflag, t.Cflag, t.Lflag)
}
