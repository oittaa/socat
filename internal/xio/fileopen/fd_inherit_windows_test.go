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

func TestFDCloseLeavesInheritedDescriptorOpenWindows(t *testing.T) {
	nfd, w := dupPipeHandle(t)
	parsed, err := parse.ParseSpec("FD:" + strconv.Itoa(nfd))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openFD(context.Background(), parsed, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf, err := readInheritedHandle(t, nfd, 2)
	if err != nil {
		t.Fatalf("inherited handle was closed: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("read %q want ok", buf)
	}
}

func TestFDEndCloseClosesInheritedDescriptorWindows(t *testing.T) {
	nfd, _ := dupPipeHandle(t)
	parsed, err := parse.ParseSpec("FD:" + strconv.Itoa(nfd) + ",end-close")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openFD(context.Background(), parsed, xio.ModeRead, nil)
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

func TestFDRepeatedOpenReusesCallerDescriptorWindows(t *testing.T) {
	nfd, w := dupPipeHandle(t)
	before := inheritedSessionLive.Load()
	spec, err := parse.ParseSpec("FD:" + strconv.Itoa(nfd))
	if err != nil {
		t.Fatal(err)
	}
	const rounds = 32
	for i := 0; i < rounds; i++ {
		o, err := openFD(context.Background(), spec, xio.ModeRead, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := inheritedSessionLive.Load(); got != before {
		t.Fatalf("live session wrappers=%d want %d after %d open/close cycles", got, before, rounds)
	}
	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf, err := readInheritedHandle(t, nfd, 2)
	if err != nil {
		t.Fatalf("inherited handle was closed: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("read %q want ok", buf)
	}
}

func TestFDFailedOpenDoesNotKeepSessionWrapperWindows(t *testing.T) {
	nfd, _ := dupPipeHandle(t)
	before := inheritedSessionLive.Load()
	spec, err := parse.ParseSpec("FD:" + strconv.Itoa(nfd) + ",cloexec")
	if err != nil {
		t.Fatal(err)
	}
	const rounds = 32
	for i := 0; i < rounds; i++ {
		_, err := openFD(context.Background(), spec, xio.ModeRead, nil)
		if err == nil {
			t.Fatal("cloexec on windows succeeded")
		}
	}
	if got := inheritedSessionLive.Load(); got != before {
		t.Fatalf("live session wrappers=%d want %d after failed opens", got, before)
	}
	if _, err := windows.GetFileType(windows.Handle(nfd)); err != nil {
		t.Fatalf("failed open closed inherited handle: %v", err)
	}
}
