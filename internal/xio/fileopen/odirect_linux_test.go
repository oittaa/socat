//go:build linux

package fileopen

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestOpenFlagsSetsODirect(t *testing.T) {
	spec, err := parse.ParseSpec("OPEN:x,o-direct")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_DIRECT == 0 {
		t.Fatalf("flags=%#x do not contain O_DIRECT", flags)
	}

	off, err := parse.ParseSpec("OPEN:x,o-direct=0")
	if err != nil {
		t.Fatal(err)
	}
	flags, err = OpenFlags(off, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_DIRECT != 0 {
		t.Fatalf("o-direct=0 set O_DIRECT (flags=%#x)", flags)
	}

	alias, err := parse.ParseSpec("OPEN:x,direct")
	if err != nil {
		t.Fatal(err)
	}
	flags, err = OpenFlags(alias, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_DIRECT == 0 {
		t.Fatalf("direct alias flags=%#x do not contain O_DIRECT", flags)
	}
}

func TestOpenODirectAppearsInFcntl(t *testing.T) {
	path := filepath.Join(t.TempDir(), "odirect.bin")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",o-direct")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		t.Skipf("O_DIRECT open: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	got, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got&unix.O_DIRECT == 0 {
		t.Fatalf("F_GETFL=%#x does not contain O_DIRECT", got)
	}
}

func TestCREATEDoesNotApplyODirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "create.bin")
	spec, err := parse.ParseSpec("CREATE:" + path + ",o-direct")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openCREATE(context.Background(), spec, xio.ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	flags := openedReaderFlags(t, o)
	if flags&unix.O_DIRECT != 0 {
		t.Fatalf("CREATE F_GETFL=%#x contains O_DIRECT; classic CREATE is not GROUP_OPEN", flags)
	}
}

func TestNamedPIPEAppliesODirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	spec, err := parse.ParseSpec("PIPE:" + path + ",o-direct,nonblock")
	if err != nil {
		t.Fatal(err)
	}
	flags := os.O_RDONLY | oNonblock
	flags, err = applyODirectFlag(spec, flags)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_DIRECT == 0 {
		t.Fatalf("PIPE flags=%#x do not contain O_DIRECT", flags)
	}

	o, err := openPIPE(context.Background(), spec, xio.ModeRead, nil)
	if err != nil {
		// Classic xio-pipe.c → _xioopen_open: Linux open(2) of a FIFO with
		// O_DIRECT returns EINVAL (tag-1.8.1.3). That is still applying the flag.
		if errors.Is(err, unix.EINVAL) {
			return
		}
		t.Fatalf("PIPE o-direct: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if got := openedReaderFlags(t, o); got&unix.O_DIRECT == 0 {
		t.Fatalf("PIPE F_GETFL=%#x does not contain O_DIRECT", got)
	}

	wspec, err := parse.ParseSpec("PIPE:" + filepath.Join(t.TempDir(), "wfifo") + ",o-direct,nonblock")
	if err != nil {
		t.Fatal(err)
	}
	w, err := openPIPE(context.Background(), wspec, xio.ModeWrite, nil)
	if err != nil {
		if errors.Is(err, unix.EINVAL) {
			return
		}
		t.Fatalf("PIPE write o-direct: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if got := openedReaderFlags(t, w); got&unix.O_DIRECT == 0 {
		t.Fatalf("PIPE write F_GETFL=%#x does not contain O_DIRECT", got)
	}
}

func TestNamedPIPEBidirectionalAppliesODirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	spec, err := parse.ParseSpec("PIPE:" + path + ",o-direct,nonblock")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openPIPE(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		if errors.Is(err, unix.EINVAL) {
			return
		}
		t.Fatalf("PIPE rdwr o-direct: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })
	rFlags, wFlags := openedRWFlags(t, o)
	if rFlags&unix.O_DIRECT == 0 {
		t.Fatalf("PIPE read F_GETFL=%#x does not contain O_DIRECT", rFlags)
	}
	if wFlags&unix.O_DIRECT == 0 {
		t.Fatalf("PIPE write F_GETFL=%#x does not contain O_DIRECT", wFlags)
	}
}

func TestUnnamedPIPERejectsODirect(t *testing.T) {
	spec, err := parse.ParseSpec("PIPE,o-direct")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openPIPE(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("unnamed PIPE,o-direct was accepted")
	}
	if !strings.Contains(err.Error(), "unnamed PIPE") {
		t.Fatalf("unnamed PIPE o-direct: %v", err)
	}

	off, err := parse.ParseSpec("PIPE,o-direct=0")
	if err != nil {
		t.Fatal(err)
	}
	o, err = openPIPE(context.Background(), off, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
}

func openedReaderFlags(t *testing.T, o *xio.Opened) int {
	t.Helper()
	f := openedFile(t, o.Stream, true)
	got, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func openedRWFlags(t *testing.T, o *xio.Opened) (rFlags, wFlags int) {
	t.Helper()
	r := openedFile(t, o.Stream, true)
	w := openedFile(t, o.Stream, false)
	var err error
	rFlags, err = unix.FcntlInt(r.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	wFlags, err = unix.FcntlInt(w.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return rFlags, wFlags
}

func openedFile(t *testing.T, stream relay.Stream, reader bool) *os.File {
	t.Helper()
	fds, ok := stream.(relay.FDStream)
	if !ok {
		t.Fatalf("stream is %T, want relay.FDStream", stream)
	}
	var src any = fds.R
	if !reader {
		src = fds.W
	}
	f, ok := src.(*os.File)
	if !ok {
		t.Fatalf("endpoint is %T, want *os.File", src)
	}
	return f
}
