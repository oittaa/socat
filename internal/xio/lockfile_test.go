package xio

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
)

func TestAcquireLockFileCancellation(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AcquireLockFile(ctx, path, true, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v want context.Canceled", err)
	}
}

func TestAcquireLockFileDoesNotCreateAfterCancellation(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AcquireLockFile(ctx, path, true, time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v want context.Canceled", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled acquisition created a lock: %v", err)
	}
}

func TestAcquireLockFileWithoutWaitReportsExistingLock(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLockFile(context.Background(), path, false, time.Millisecond); err == nil {
		t.Fatal("existing lock was accepted")
	}
}

func TestCreateLockFileWritesPID(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	if _, err := CreateLockFile(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%d\n", os.Getpid()); string(got) != want {
		t.Fatalf("contents=%q want %q", got, want)
	}
}

func TestHoldLockFileDoesNotRemoveReplacement(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	release, err := HoldLockFile(context.Background(), path, false, CLILockPollInterval)
	if err != nil {
		t.Fatal(err)
	}
	replaceAtPath(t, path, []byte("replacement"), 0o600)
	release()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("contents=%q", got)
	}
}

func TestHoldLockFileRemovesAcquiredName(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	release, err := HoldLockFile(context.Background(), path, false, CLILockPollInterval)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("lock file survived release: %v", err)
	}
}

func TestLockPollIntervals(t *testing.T) {
	if AddressWaitLockPollInterval != time.Second {
		t.Fatalf("address waitlock interval=%v want 1s (classic xiowaitlock)", AddressWaitLockPollInterval)
	}
	if CLILockPollInterval != time.Second {
		t.Fatalf("CLI -W interval=%v want 1s", CLILockPollInterval)
	}
}

func TestHoldLockFileIdempotentRelease(t *testing.T) {
	dir := filepath.Dir(testutil.UnixSocketPath(t, "x"))
	path := filepath.Join(dir, "socat.lock")
	release, err := HoldLockFile(context.Background(), path, false, CLILockPollInterval)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err := os.WriteFile(path, []byte("later\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("second release removed a new file: %v", err)
	}
	if string(got) != "later\n" {
		t.Fatalf("contents=%q", got)
	}
}
