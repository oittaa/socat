package xio_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
