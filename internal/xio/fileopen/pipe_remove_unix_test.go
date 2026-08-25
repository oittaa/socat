//go:build unix

package fileopen

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

const (
	blockedPipeHelperEnv  = "SOCAT_TEST_BLOCKED_PIPE_HELPER"
	blockedPipePathEnv    = "SOCAT_TEST_BLOCKED_PIPE_PATH"
	blockedPipeChannelEnv = "SOCAT_TEST_BLOCKED_PIPE_CHANNEL"
	blockedPipeReplaceEnv = "SOCAT_TEST_BLOCKED_PIPE_REPLACE"
)

// TestNamedPipeRemoveUnlinksBeforeWriter mimics classic test.sh PIPE_REMOVE:
// socat -u PIPE:<path> FILE:/dev/null creates the FIFO, then SIGTERM arrives
// while open(O_RDONLY) is still waiting for a writer. Classic xio-pipe.c
// (tag-1.8.1.3) records unlink_close after Mkfifo and before that open, so
// UnlinkRegisteredPaths removes the entry. Registering only after open returns
// leaves the FIFO behind.
func TestNamedPipeRemoveUnlinksBeforeWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	runBlockedPipeHelper(t, path, "PIPE:"+path, false)
}

// TestNamedPipeUnlinkEarlyReplacesAndRemovesBeforeWriter covers classic's
// ordering: unlink the stale FIFO, create/register a replacement, then block
// opening it. A signal cleanup must remove the replacement.
func TestNamedPipeUnlinkEarlyReplacesAndRemovesBeforeWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := mkfifo(path, 0o666); err != nil {
		t.Fatal(err)
	}
	runBlockedPipeHelper(t, path, "PIPE:"+path+",unlink-early", true)
}

func TestNamedPipeUnlinkEarlyRequiresExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	ch, err := parse.ParseChannel("PIPE:" + path + ",unlink-early")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(context.Background(), ch, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("PIPE,unlink-early unexpectedly accepted a missing path")
	}
}

// TestNamedPipeBlockedOpenHelper runs in a subprocess. Unlinking a FIFO while
// open(O_RDONLY) is blocked leaves that syscall blocked on an unreachable
// inode, so isolating it avoids leaking a goroutine and OS thread in the main
// unit-test process.
func TestNamedPipeBlockedOpenHelper(t *testing.T) {
	if os.Getenv(blockedPipeHelperEnv) != "1" {
		t.Skip("subprocess helper")
	}
	path := os.Getenv(blockedPipePathEnv)
	raw := os.Getenv(blockedPipeChannelEnv)
	wantReplacement := os.Getenv(blockedPipeReplaceEnv) == "1"
	if path == "" || raw == "" {
		t.Fatal("missing blocked PIPE helper environment")
	}

	var original os.FileInfo
	if wantReplacement {
		// Keep the stale FIFO inode referenced while unlink-early replaces it.
		// Otherwise some filesystems can immediately reuse the inode number,
		// making os.SameFile report that the replacement is still the old FIFO.
		oldFIFO, err := os.OpenFile(path, os.O_RDONLY|oNonblock, 0) // #nosec G304 -- test-created FIFO whose inode identity is under test
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = oldFIFO.Close() }()
		original, err = oldFIFO.Stat()
		if err != nil {
			t.Fatal(err)
		}
	}
	ch, err := parse.ParseChannel(raw)
	if err != nil {
		t.Fatal(err)
	}
	opened := make(chan resultOpened, 1)
	go func() {
		o, err := xio.OpenChannel(context.Background(), ch, xio.ModeRead, nil)
		opened <- resultOpened{o: o, err: err}
	}()

	waitPipeReady(t, path, original, wantReplacement, 2*time.Second)
	select {
	case r := <-opened:
		if r.o != nil {
			_ = r.o.Close()
		}
		t.Fatalf("PIPE ModeRead open returned before a writer: %v", r.err)
	default:
	}
	xio.UnlinkRegisteredPaths()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("FIFO still exists after UnlinkRegisteredPaths: %v", err)
	}
}

func runBlockedPipeHelper(t *testing.T, path, raw string, wantReplacement bool) {
	t.Helper()
	replace := "0"
	if wantReplacement {
		replace = "1"
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNamedPipeBlockedOpenHelper$", "-test.v") // #nosec G204 -- re-exec this test binary without a shell
	cmd.Env = append(os.Environ(),
		blockedPipeHelperEnv+"=1",
		blockedPipePathEnv+"="+path,
		blockedPipeChannelEnv+"="+raw,
		blockedPipeReplaceEnv+"="+replace,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("blocked PIPE helper failed: %v\n%s", err, output)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("FIFO still exists after helper exit: %v", err)
	}
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

func waitPipeReady(t *testing.T, path string, original os.FileInfo, wantReplacement bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		current, err := os.Lstat(path)
		switch {
		case err == nil && (!wantReplacement || !os.SameFile(original, current)):
			return
		case err == nil:
		case os.IsNotExist(err):
		default:
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if wantReplacement {
		t.Fatalf("timed out waiting for replacement FIFO %s", path)
	}
	t.Fatalf("timed out waiting for %s", path)
}
