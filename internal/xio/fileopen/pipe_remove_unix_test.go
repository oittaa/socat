//go:build linux || darwin

package fileopen

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

const (
	blockedPipeHelperEnv  = "SOCAT_TEST_BLOCKED_PIPE_HELPER"
	blockedPipePathEnv    = "SOCAT_TEST_BLOCKED_PIPE_PATH"
	blockedPipeChannelEnv = "SOCAT_TEST_BLOCKED_PIPE_CHANNEL"
)

// TestNamedPipeRemoveUnlinksBeforeWriter mimics classic test.sh PIPE_REMOVE:
// socat -u PIPE:<path> FILE:/dev/null creates the FIFO, then SIGTERM arrives
// while open(O_RDONLY) is still waiting for a writer. Classic xio-pipe.c
// (tag-1.8.1.3) records unlink_close after Mkfifo and before that open, so
// UnlinkRegisteredPaths removes the entry. Registering only after open returns
// leaves the FIFO behind.
func TestNamedPipeRemoveUnlinksBeforeWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	runBlockedPipeHelper(t, path, "PIPE:"+path)
}

// TestNamedPipeUnlinkEarlyReplacesAndRemovesBeforeWriter covers classic's
// ordering: unlink the stale FIFO, create/register a replacement, then block
// opening it. A signal cleanup must remove the replacement.
func TestNamedPipeUnlinkEarlyReplacesAndRemovesBeforeWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := mkfifo(path, 0o666); err != nil {
		t.Fatal(err)
	}
	runBlockedPipeHelper(t, path, "PIPE:"+path+",unlink-early")
}

func TestNamedPipeUnlinkEarlyMissingPathFails(t *testing.T) {
	// Classic xio-pipe.c Unlink()s unlink-early even when the name is
	// missing; ENOENT aborts before mkfifo (tag-1.8.1.3 / master).
	path := filepath.Join(t.TempDir(), "missing")
	ch, err := parse.ParseChannel("PIPE:" + path + ",unlink-early,nonblock")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(context.Background(), ch, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("PIPE,unlink-early of a missing path succeeded")
	}
	if !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("error=%v want ENOENT", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("missing path was created: %v", err)
	}
}

func TestNamedPipePermEarlyChmodsExistingFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := mkfifo(path, 0o666); err != nil {
		t.Fatal(err)
	}
	ch, err := parse.ParseChannel("PIPE:" + path + ",perm-early=0600,nonblock,unlink-close=0")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(context.Background(), ch, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	assertNamedMode(t, path, 0o600)
}

func runBlockedPipeHelper(t *testing.T, path, raw string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestNamedPipeBlockedOpenHelper$", "-test.v") // #nosec G204 -- re-exec this test binary without a shell
	cmd.Env = append(os.Environ(),
		blockedPipeHelperEnv+"=1",
		blockedPipePathEnv+"="+path,
		blockedPipeChannelEnv+"="+raw,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("blocked PIPE helper failed: %v\n%s", err, output)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("FIFO still exists after helper exit: %v", err)
	}
}

func TestNamedPipeBlockedOpenHelper(t *testing.T) {
	if os.Getenv(blockedPipeHelperEnv) != "1" {
		t.Skip("subprocess helper")
	}
	runNamedPipeBlockedOpenHelper(t)
}

func runNamedPipeBlockedOpenHelper(t *testing.T) {
	t.Helper()
	path := os.Getenv(blockedPipePathEnv)
	raw := os.Getenv(blockedPipeChannelEnv)
	if path == "" || raw == "" {
		t.Fatal("missing blocked PIPE helper environment")
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
	waitRegisteredUnlink(t, opened, 2*time.Second)
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

type resultOpened struct {
	o   *xio.Opened
	err error
}

func waitRegisteredUnlink(t *testing.T, opened <-chan resultOpened, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case r := <-opened:
			if r.o != nil {
				_ = r.o.Close()
			}
			t.Fatalf("PIPE ModeRead open returned before a writer: %v", r.err)
		default:
		}
		if xio.RegisteredUnlinkCount() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for PIPE unlink registration")
}
