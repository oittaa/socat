//go:build unix

package fileopen

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// TestNamedPipeRemoveUnlinksBeforeWriter mimics classic test.sh PIPE_REMOVE:
// socat -u PIPE:<path> FILE:/dev/null creates the FIFO, then SIGTERM arrives
// while open(O_RDONLY) is still waiting for a writer. Classic xio-pipe.c
// (tag-1.8.1.3) records unlink_close after Mkfifo and before that open, so
// UnlinkRegisteredPaths removes the entry. Registering only after open returns
// leaves the FIFO behind.
func TestNamedPipeRemoveUnlinksBeforeWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	ch, err := parse.ParseChannel("PIPE:" + path)
	if err != nil {
		t.Fatal(err)
	}

	opened := make(chan error, 1)
	go func() {
		o, err := xio.OpenChannel(context.Background(), ch, xio.ModeRead, nil)
		if err != nil {
			opened <- err
			return
		}
		opened <- o.Close()
	}()

	waitPathExists(t, path, 2*time.Second)
	select {
	case err := <-opened:
		t.Fatalf("PIPE ModeRead open returned before a writer: %v", err)
	default:
	}

	xio.UnlinkRegisteredPaths()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("FIFO still exists after UnlinkRegisteredPaths: %v", err)
	}

	t.Cleanup(func() {
		if _, err := os.Lstat(path); err == nil {
			w, werr := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- test-created FIFO path
			if werr == nil {
				_ = w.Close()
			}
			select {
			case <-opened:
			case <-time.After(2 * time.Second):
			}
		}
	})
}

func TestNamedPipeUnlinkCloseZeroKeepsFIFODuringBlockedOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	ch, err := parse.ParseChannel("PIPE:" + path + ",unlink-close=0")
	if err != nil {
		t.Fatal(err)
	}

	opened := make(chan resultOpened, 1)
	go func() {
		o, err := xio.OpenChannel(context.Background(), ch, xio.ModeRead, nil)
		opened <- resultOpened{o: o, err: err}
	}()
	waitPathExists(t, path, 2*time.Second)

	xio.UnlinkRegisteredPaths()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("unlink-close=0 FIFO was removed while blocked in open: %v", err)
	}

	w, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- test-created FIFO path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()

	select {
	case r := <-opened:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if err := r.o.Close(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PIPE ModeRead open did not resume after a writer opened")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("unlink-close=0 FIFO was removed on close: %v", err)
	}
}

func TestNamedPipeDoesNotUnlinkPreexistingFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := mkfifo(path, 0o666); err != nil {
		t.Fatal(err)
	}
	ch, err := parse.ParseChannel("PIPE:" + path + ",nonblock")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(context.Background(), ch, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	xio.UnlinkRegisteredPaths()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("pre-existing FIFO was unlinked on signal sweep: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("pre-existing FIFO was unlinked on close: %v", err)
	}
}

type resultOpened struct {
	o   *xio.Opened
	err error
}

func waitPathExists(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}
