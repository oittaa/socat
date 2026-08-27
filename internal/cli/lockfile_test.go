package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestCLILockAndAddressLockDifferentPaths(t *testing.T) {
	dir := filepath.Dir(testutil.UnixSocketPath(t, "x"))
	cliPath := filepath.Join(dir, "cli.lock")
	addrPath := filepath.Join(dir, "addr.lock")
	unlock, err := acquireLockFiles(context.Background(), &Config{LockFile: cliPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unlock)
	spec := parse.Spec{
		Type:    "ECHO",
		Options: []parse.Option{{Name: "lockfile", Value: addrPath, Has: true}},
	}
	o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cliPath); err != nil {
		t.Fatalf("CLI lock missing: %v", err)
	}
	if _, err := os.Stat(addrPath); err != nil {
		t.Fatalf("address lock missing: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(addrPath); !os.IsNotExist(err) {
		t.Fatalf("address lock survived close: %v", err)
	}
	if _, err := os.Stat(cliPath); err != nil {
		t.Fatalf("CLI lock removed while still held: %v", err)
	}
	unlock()
	if _, err := os.Lstat(cliPath); !os.IsNotExist(err) {
		t.Fatalf("CLI lock survived unlock: %v", err)
	}
}

func TestCLILockSamePathAsAddressLockfileFails(t *testing.T) {
	path := testutil.UnixSocketPath(t, "shared.lock")
	unlock, err := acquireLockFiles(context.Background(), &Config{LockFile: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unlock)
	spec := parse.Spec{
		Type:    "ECHO",
		Options: []parse.Option{{Name: "lockfile", Value: path, Has: true}},
	}
	_, err = xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("error=%v want lockfile exists", err)
	}
}

func TestCLILockIdentitySafeRelease(t *testing.T) {
	path := testutil.UnixSocketPath(t, "cli.lock")
	unlock, err := acquireLockFiles(context.Background(), &Config{LockFile: path})
	if err != nil {
		t.Fatal(err)
	}
	other := path + ".new"
	if err := os.WriteFile(other, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
	unlock()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("contents=%q", got)
	}
}
