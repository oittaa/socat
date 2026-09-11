//go:build windows

package fileopen

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/windows"
)

func dupPipeHandle(t *testing.T) (nfd int, w *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	process := windows.CurrentProcess()
	var handle windows.Handle
	if err := windows.DuplicateHandle(
		process,
		windows.Handle(r.Fd()),
		process,
		&handle,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	return int(handle), w
}

func readInheritedHandle(t *testing.T, nfd int, n int) ([]byte, error) {
	t.Helper()
	buf := make([]byte, n)
	var done uint32
	err := windows.ReadFile(windows.Handle(nfd), buf, &done, nil)
	return buf[:done], err
}

func TestFDEndCloseClosesInheritedDescriptorWindows(t *testing.T) {
	nfd, _ := dupPipeHandle(t)
	parsed, err := parse.ParseSpec("FD:" + strconv.Itoa(nfd) + ",end-close")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := xio.PrepareSpec(parsed)
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenPreparedSpec(context.Background(), prepared, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readInheritedHandle(t, nfd, 1); err == nil {
		t.Fatal("end-close left inherited handle open")
	}
}
