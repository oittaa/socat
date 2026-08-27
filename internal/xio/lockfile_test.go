package xio

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
		_, err := AcquireLockFile(context.Background(), path, true, time.Millisecond)
		done <- err
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
	if CLILockPollInterval != 100*time.Millisecond {
		t.Fatalf("CLI -W interval=%v want 100ms", CLILockPollInterval)
	}
}

func TestHoldLockFileSignalCleanupDoesNotRemoveReplacement(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	release, err := HoldLockFile(context.Background(), path, false, CLILockPollInterval)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	replaceAtPath(t, path, []byte("replacement"), 0o600)
	UnlinkRegisteredPaths()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("signal cleanup removed replacement: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("contents=%q", got)
	}
	release()
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("normal release removed replacement: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("contents=%q", got)
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

func TestHoldLockFileReplacementBetweenCreateAndRegister(t *testing.T) {
	path := testutil.UnixSocketPath(t, "socat.lock")
	lockfileAfterCreateHook = func(p string) {
		replaceAtPath(t, p, []byte("replacement"), 0o600)
	}
	t.Cleanup(func() { lockfileAfterCreateHook = nil })

	release, err := HoldLockFile(context.Background(), path, false, CLILockPollInterval)
	if release != nil {
		t.Fatal("release func returned after the lock was replaced")
	}
	if err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("error=%v want acquired name was replaced", err)
	}
	UnlinkRegisteredPaths()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("contents=%q", got)
	}
}
