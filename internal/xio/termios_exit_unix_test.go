//go:build linux || darwin

package xio

import (
	"fmt"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

// TestSignalExitRestoresPTYTermios is the regression for signal exit leaving
// the terminal in raw mode. SIGTERM/SIGHUP/SIGINT call UnlinkRegisteredPaths
// and then os.Exit, which skips Opened.Close. STDIO applies the same options
// to two descriptors of one terminal, so the later snapshot is the raw state
// and must run first.
func TestSignalExitRestoresPTYTermios(t *testing.T) {
	master, slave, err := OpenPTYPair()
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

	orig, err := getTermios(int(slave.Fd()))
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
	raw, err := getTermios(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if raw.Lflag&unix.ECHO != 0 || raw.Lflag&unix.ICANON != 0 {
		t.Fatalf("raw,echo=0 did not clear echo/canonical: %s", formatTermios(raw))
	}

	// Signal exit does not Close the endpoint.
	UnlinkRegisteredPaths()

	got, err := getTermios(int(slave.Fd()))
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
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		_ = slave.Close()
	})
	fd := int(slave.Fd())
	orig, err := getTermios(fd)
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
	restored, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if !termiosEqual(orig, restored) {
		t.Fatalf("close did not restore termios\n orig %s\n got  %s", formatTermios(orig), formatTermios(restored))
	}
	if err := ApplyConfiguredTermios(fd, config); err != nil {
		t.Fatal(err)
	}
	UnlinkRegisteredPaths()
	got, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if got.Lflag&unix.ECHO != 0 || got.Lflag&unix.ICANON != 0 {
		t.Fatalf("closed endpoint's exit hook restored termios: %s", formatTermios(got))
	}
}

// TestStreamCloseRestoresPTYTermios is the normal-exit path. The relay
// closes the stream before Opened.Close, so restore has to run from that
// close while the descriptor is still open.
func TestStreamCloseRestoresPTYTermios(t *testing.T) {
	master, slave, err := OpenPTYPair()
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
	orig, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if orig.Lflag&unix.ECHO == 0 || orig.Lflag&unix.ICANON == 0 {
		t.Fatalf("pty slave is not cooked: %s", formatTermios(orig))
	}
	o, err := NewReady("OPEN", FileStream(slave))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	config := terminalConfig(t, "OPEN,raw,echo=0")
	if err := AttachConfiguredTermios(o, fd, config); err != nil {
		t.Fatal(err)
	}
	raw, err := getTermios(dupFD)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Lflag&unix.ECHO != 0 || raw.Lflag&unix.ICANON != 0 {
		t.Fatalf("raw,echo=0 did not clear echo/canonical: %s", formatTermios(raw))
	}
	if err := o.Stream().Close(); err != nil {
		t.Fatal(err)
	}
	got, err := getTermios(dupFD)
	if err != nil {
		t.Fatal(err)
	}
	if !termiosEqual(orig, got) {
		t.Fatalf("stream close left the terminal changed\n orig %s\n got  %s", formatTermios(orig), formatTermios(got))
	}
}

// TestShutdownWriteRestoresPTYTermios is the path where the other side ends
// first. Half-close leaves a terminal open and raw; Close restores it.
func TestShutdownWriteRestoresPTYTermios(t *testing.T) {
	master, slave, err := OpenPTYPair()
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
	orig, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if orig.Lflag&unix.ECHO == 0 || orig.Lflag&unix.ICANON == 0 {
		t.Fatalf("pty slave is not cooked: %s", formatTermios(orig))
	}
	o, err := NewReady("OPEN", FileStream(slave))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if err := AttachConfiguredTermios(o, fd, terminalConfig(t, "OPEN,raw,echo=0")); err != nil {
		t.Fatal(err)
	}
	raw, err := getTermios(dupFD)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Lflag&unix.ECHO != 0 || raw.Lflag&unix.ICANON != 0 {
		t.Fatalf("raw,echo=0 did not clear echo/canonical: %s", formatTermios(raw))
	}
	stream := o.Stream()
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	mid, err := getTermios(fd)
	if err != nil {
		t.Fatalf("half-close closed the terminal: %v", err)
	}
	if mid.Lflag&unix.ECHO != 0 || mid.Lflag&unix.ICANON != 0 {
		t.Fatalf("half-close restored the terminal: %s", formatTermios(mid))
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := getTermios(dupFD)
	if err != nil {
		t.Fatal(err)
	}
	if !termiosEqual(orig, got) {
		t.Fatalf("close left the terminal changed\n orig %s\n got  %s", formatTermios(orig), formatTermios(got))
	}
}

// TestWrappedHalfCloseRestoresPTYTermios covers escape= and readbytes=, which
// nest an FDStream around the file. ShutdownWrite must not panic, and Close
// restores the terminal.
func TestWrappedHalfCloseRestoresPTYTermios(t *testing.T) {
	for _, spec := range []string{
		"OPEN:/dev/null,raw,echo=0,escape=0x1d",
		"OPEN:/dev/null,raw,echo=0,readbytes=100",
	} {
		t.Run(spec, func(t *testing.T) {
			master, slave, err := OpenPTYPair()
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
			orig, err := getTermios(fd)
			if err != nil {
				t.Fatal(err)
			}
			config := mustDecodeAddress(t, mustSpec(t, spec))
			st, err := WrapAfterFD(config, FileStream(slave))
			if err != nil {
				t.Fatal(err)
			}
			o, err := NewReady("OPEN", st)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			if err := AttachConfiguredTermios(o, fd, config.Terminal); err != nil {
				t.Fatal(err)
			}
			if err := o.Stream().ShutdownWrite(); err != nil {
				t.Fatal(err)
			}
			mid, err := getTermios(fd)
			if err != nil {
				t.Fatalf("half-close closed the terminal: %v", err)
			}
			if mid.Lflag&unix.ECHO != 0 || mid.Lflag&unix.ICANON != 0 {
				t.Fatalf("half-close restored the terminal: %s", formatTermios(mid))
			}
			if err := o.Stream().Close(); err != nil {
				t.Fatal(err)
			}
			got, err := getTermios(dupFD)
			if err != nil {
				t.Fatal(err)
			}
			if !termiosEqual(orig, got) {
				t.Fatalf("close left the terminal changed\n orig %s\n got  %s", formatTermios(orig), formatTermios(got))
			}
		})
	}
}

// TestSTDIOShutdownWriteKeepsRaw matches bidirectional STDIO: CloseW is a
// no-op and the write side is an *os.File. Half-close must leave the
// terminal raw.
func TestSTDIOShutdownWriteKeepsRaw(t *testing.T) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })
	fd := int(slave.Fd())
	orig, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	stream := relay.FDStream{
		R: slave,
		W: slave,
		C: NopCloser{},
		CloseW: func() error {
			return nil
		},
	}
	o, err := NewReady("STDIO", stream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if err := AttachConfiguredTermios(o, fd, terminalConfig(t, "STDIO,raw,echo=0")); err != nil {
		t.Fatal(err)
	}
	if err := o.Stream().ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if got.Lflag&unix.ECHO != 0 || got.Lflag&unix.ICANON != 0 {
		t.Fatalf("half-close restored STDIO\n orig %s\n raw  %s\n got  %s", formatTermios(orig), "echo/icanon clear", formatTermios(got))
	}
	if termiosEqual(orig, got) {
		t.Fatal("raw,echo=0 did not change the terminal")
	}
}

// TestShutdownWriteKeepsOpenTerminalRaw checks options that leave the
// descriptor open. Half-close must not restore; Close still does.
func TestShutdownWriteKeepsOpenTerminalRaw(t *testing.T) {
	cases := []struct {
		name string
		wrap func(relay.Stream) relay.Stream
	}{
		{name: "shut-none", wrap: func(s relay.Stream) relay.Stream { return shutNoneStream{Stream: s} }},
		{name: "end-close", wrap: func(s relay.Stream) relay.Stream { return endCloseStream{Stream: s} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			master, slave, err := OpenPTYPair()
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
			orig, err := getTermios(fd)
			if err != nil {
				t.Fatal(err)
			}
			o, err := NewReady("OPEN", tc.wrap(FileStream(slave)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			if err := AttachConfiguredTermios(o, fd, terminalConfig(t, "OPEN,raw,echo=0")); err != nil {
				t.Fatal(err)
			}
			if err := o.Stream().ShutdownWrite(); err != nil {
				t.Fatal(err)
			}
			mid, err := getTermios(dupFD)
			if err != nil {
				t.Fatal(err)
			}
			if mid.Lflag&unix.ECHO != 0 || mid.Lflag&unix.ICANON != 0 {
				t.Fatalf("half-close restored the terminal early: %s", formatTermios(mid))
			}
			if err := o.Stream().Close(); err != nil {
				t.Fatal(err)
			}
			got, err := getTermios(dupFD)
			if err != nil {
				t.Fatal(err)
			}
			if !termiosEqual(orig, got) {
				t.Fatalf("close left the terminal changed\n orig %s\n got  %s", formatTermios(orig), formatTermios(got))
			}
		})
	}
}

// TestTermiosWrapKeepsEndClose checks that the restore wrapper stays outside
// end-close without hiding it or closing the descriptor.
func TestTermiosWrapKeepsEndClose(t *testing.T) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })
	fd := int(slave.Fd())
	orig, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewReady("OPEN", endCloseStream{Stream: FileStream(slave)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	config := terminalConfig(t, "OPEN,raw,echo=0,end-close")
	if err := AttachConfiguredTermios(o, fd, config); err != nil {
		t.Fatal(err)
	}
	if !StreamIsEndClose(o.Stream()) {
		t.Fatal("termios restore wrapper hid end-close")
	}
	if err := o.Stream().Close(); err != nil {
		t.Fatal(err)
	}
	got, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if !termiosEqual(orig, got) {
		t.Fatalf("end-close stream close left the terminal changed\n orig %s\n got  %s", formatTermios(orig), formatTermios(got))
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
