package xio_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func lockTestDir(t testing.TB) string {
	t.Helper()
	return filepath.Dir(testutil.UnixSocketPath(t, "x"))
}

func echoLockSpec(option, path string) parse.Spec {
	return parse.Spec{
		Type:    "ECHO",
		Options: []parse.Option{{Name: option, Value: path, Has: true}},
	}
}

func openEchoLock(t *testing.T, ctx context.Context, option, path string) *xio.Opened {
	t.Helper()
	o, err := xio.OpenSpec(ctx, echoLockSpec(option, path), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func TestLockfileFailsWhenPathExists(t *testing.T) {
	path := testutil.UnixSocketPath(t, "exists.lock")
	if err := os.WriteFile(path, []byte("held\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := xio.OpenSpec(context.Background(), echoLockSpec("lockfile", path), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil || !strings.Contains(err.Error(), "lockfile "+path+" exists") {
		t.Fatalf("error=%v want lockfile exists", err)
	}
}

func TestLockfileSucceedsWhenAbsentContainsPID(t *testing.T) {
	path := testutil.UnixSocketPath(t, "absent.lock")
	o := openEchoLock(t, context.Background(), "lockfile", path)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%d\n", os.Getpid()); string(got) != want {
		t.Fatalf("contents=%q want %q", got, want)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("lock file survived close: %v", err)
	}
}

func TestWaitlockWaitsThenAcquires(t *testing.T) {
	path := testutil.UnixSocketPath(t, "wait.lock")
	if err := os.WriteFile(path, []byte("owner\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	var opened *xio.Opened
	go func() {
		o, err := xio.OpenSpec(context.Background(), echoLockSpec("waitlock", path), xio.ModeRDWR, &xio.Global{Log: logx.New()})
		opened = o
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("waitlock returned before release: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitlock did not acquire after release")
	}
	t.Cleanup(func() {
		if opened != nil {
			_ = opened.Close()
		}
	})
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("acquired waitlock is missing: %v", err)
	}
}

func TestWaitlockCancellationDoesNotCreate(t *testing.T) {
	path := testutil.UnixSocketPath(t, "cancel.lock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := xio.OpenSpec(ctx, echoLockSpec("waitlock", path), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v want context.Canceled", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled waitlock created a lock: %v", err)
	}
}

func TestTwoAddressLocksDuringTransferIdentitySafe(t *testing.T) {
	dir := lockTestDir(t)
	leftLock := filepath.Join(dir, "left.lock")
	rightLock := filepath.Join(dir, "right.lock")
	left := openEchoLock(t, context.Background(), "lockfile", leftLock)
	right := openEchoLock(t, context.Background(), "lockfile", rightLock)
	if _, err := os.Stat(leftLock); err != nil {
		t.Fatalf("left lock missing during transfer: %v", err)
	}
	if _, err := os.Stat(rightLock); err != nil {
		t.Fatalf("right lock missing during transfer: %v", err)
	}
	if err := os.WriteFile(leftLock+".new", []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(leftLock+".new", leftLock); err != nil {
		t.Fatal(err)
	}
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
	if err := right.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(leftLock)
	if err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("contents=%q", got)
	}
	if _, err := os.Lstat(rightLock); !os.IsNotExist(err) {
		t.Fatalf("right lock survived close: %v", err)
	}
}

func TestLockfileAndWaitlockTogetherError(t *testing.T) {
	dir := lockTestDir(t)
	lockA := filepath.Join(dir, "a.lock")
	lockB := filepath.Join(dir, "b.lock")
	spec := parse.Spec{
		Type: "ECHO",
		Options: []parse.Option{
			{Name: "lockfile", Value: lockA, Has: true},
			{Name: "waitlock", Value: lockB, Has: true},
		},
	}
	_, err := xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil || !strings.Contains(err.Error(), "only one use of options lockfile and waitlock allowed") {
		t.Fatalf("error=%v want only one use", err)
	}
	if _, err := os.Stat(lockA); !os.IsNotExist(err) {
		t.Fatalf("rejected combo created lockfile: %v", err)
	}
	if _, err := os.Stat(lockB); !os.IsNotExist(err) {
		t.Fatalf("rejected combo created waitlock: %v", err)
	}
}

func TestTwoLockfileOccurrencesError(t *testing.T) {
	dir := lockTestDir(t)
	spec := parse.Spec{
		Type: "ECHO",
		Options: []parse.Option{
			{Name: "lockfile", Value: filepath.Join(dir, "a.lock"), Has: true},
			{Name: "lockfile", Value: filepath.Join(dir, "b.lock"), Has: true},
		},
	}
	_, err := xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil || !strings.Contains(err.Error(), "only one use of options lockfile and waitlock allowed") {
		t.Fatalf("error=%v want only one use", err)
	}
}

func TestSamePathBothAddressesLockfileFails(t *testing.T) {
	path := testutil.UnixSocketPath(t, "shared.lock")
	left := openEchoLock(t, context.Background(), "lockfile", path)
	_, err := xio.OpenSpec(context.Background(), echoLockSpec("lockfile", path), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("error=%v want lockfile exists", err)
	}
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLockfileLeftThenRightAcquisitionOrder(t *testing.T) {
	dir := lockTestDir(t)
	leftLock := filepath.Join(dir, "left.lock")
	rightLock := filepath.Join(dir, "right.lock")
	outPath := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(rightLock, []byte("hold\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	left := parse.Channel{Single: &parse.Spec{
		Type:    "TEXT",
		Params:  []string{"hello"},
		Options: []parse.Option{{Name: "lockfile", Value: leftLock, Has: true}},
	}}
	right := parse.Channel{Single: &parse.Spec{
		Type:    "CREATE",
		Params:  []string{outPath},
		Options: []parse.Option{{Name: "waitlock", Value: rightLock, Has: true}},
	}}
	g := testGlobal()
	g.LeftToRight = true
	done := make(chan error, 1)
	go func() { done <- xio.Run(ctx, left, right, g) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(leftLock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("left lock was not acquired while right waitlock was blocked")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("Run finished before right lock was released: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatal("right CREATE ran before waitlock was released")
	}
	if err := os.Remove(rightLock); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not finish after right waitlock was released")
	}
}

func TestLockfileReleasedWhenOpenerFails(t *testing.T) {
	dir := lockTestDir(t)
	lockPath := filepath.Join(dir, "fail.lock")
	missing := filepath.Join(dir, "missing.txt")
	spec := parse.Spec{
		Type:    "OPEN",
		Params:  []string{missing},
		Options: []parse.Option{{Name: "lockfile", Value: lockPath, Has: true}},
	}
	_, err := xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil {
		t.Fatal("OPEN of missing file succeeded")
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock file survived failed opener: %v", err)
	}
}

func TestLockfileFollowsChdir(t *testing.T) {
	dir := lockTestDir(t)
	spec := parse.Spec{
		Type: "ECHO",
		Options: []parse.Option{
			{Name: "chdir", Value: dir, Has: true},
			{Name: "lockfile", Value: "rel.lock", Has: true},
		},
	}
	o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if _, err := os.Stat(filepath.Join(dir, "rel.lock")); err != nil {
		t.Fatalf("chdir lock missing: %v", err)
	}
}
