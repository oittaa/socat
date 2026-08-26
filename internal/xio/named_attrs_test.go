//go:build unix

package xio

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestApplyNamedAttrsSetsPerm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named")
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",perm=0600")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAttrs(path, spec, nil); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("perm=%#o want 0600", got)
	}
}

func TestApplyNamedAfterBindPermEarlyWinsOverPerm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",perm=0777,perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAfterBind(path, spec, nil); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("perm=%#o want 0600 (perm-early after perm=)", got)
	}
}

func TestApplyNamedAfterBindSkipsAbstract(t *testing.T) {
	spec, err := parse.ParseSpec("UNIX-LISTEN:@abs,perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAfterBind("@abs", spec, nil); err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAfterBind("\x00abs", spec, nil); err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAfterBind("", spec, nil); err != nil {
		t.Fatal(err)
	}
}
