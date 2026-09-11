//go:build linux

package fileopen

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestCREATEDoesNotApplyODirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "create.bin")
	spec, err := parse.ParseSpec("CREATE:" + path + ",o-direct")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xio.PrepareSpec(spec); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("PrepareSpec err=%v want not supported", err)
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: spec.Type})
	if err != nil {
		t.Fatal(err)
	}
	o, err := openCREATE(context.Background(), config, xio.ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	flags := openedReaderFlags(t, o)
	if flags&unix.O_DIRECT != 0 {
		t.Fatalf("CREATE F_GETFL=%#x contains O_DIRECT; classic CREATE is not GROUP_OPEN", flags)
	}
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
