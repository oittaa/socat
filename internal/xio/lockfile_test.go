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

func TestAcquireLockFileWaitsForAtomicCreate(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	if err := os.WriteFile(path, []byte("owner\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- AcquireLockFile(context.Background(), path, true, time.Millisecond)
	}()
	select {
	case err := <-done:
		t.Fatalf("wait returned before the owner released the lock: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("lock was not acquired after release")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("acquired lock is missing: %v", err)
	}
}

func TestAcquireLockFileCancellation(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := AcquireLockFile(ctx, path, true, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v want context.Canceled", err)
	}
}

func TestAcquireLockFileDoesNotCreateAfterCancellation(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := AcquireLockFile(ctx, path, true, time.Millisecond); !errors.Is(err, context.Canceled) {
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
	if err := AcquireLockFile(context.Background(), path, false, time.Millisecond); err == nil {
		t.Fatal("existing lock was accepted")
	}
}

func TestCreateLockFileWritesPID(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	if err := CreateLockFile(path); err != nil {
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
	release, err := HoldLockFile(context.Background(), path, false)
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
	release, err := HoldLockFile(context.Background(), path, false)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("lock file survived release: %v", err)
	}
}

func TestHoldLockFileIdempotentRelease(t *testing.T) {
	dir := filepath.Dir(testutil.UnixSocketPath(t, "x"))
	path := filepath.Join(dir, "socat.lock")
	release, err := HoldLockFile(context.Background(), path, false)
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
