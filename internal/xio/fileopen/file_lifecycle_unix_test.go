//go:build unix

package fileopen

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestNamedFileOwnerPrecedesLateFtruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase-order")
	if err := os.WriteFile(path, []byte("abcdefgh"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",user=" + strconv.Itoa(os.Getuid()) + ",ftruncate=3")
	if err != nil {
		t.Fatal(err)
	}
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) { ops = append(ops, op) })
	t.Cleanup(restore)
	o, err := openOPEN(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if len(ops) < 2 || ops[0] != "chown" || ops[len(ops)-1] != "ftruncate" {
		t.Fatalf("lifecycle order=%v want chown before ftruncate", ops)
	}
}

func TestCREATEOwnerAppliesToDescriptorOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "create-owner")
	spec, err := parse.ParseSpec("CREATE:" + path + ",user=" + strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) { ops = append(ops, op) })
	t.Cleanup(restore)
	o, err := openCREATE(context.Background(), spec, xio.ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	var fchowns, chowns int
	for _, op := range ops {
		switch op {
		case "fchown":
			fchowns++
		case "chown":
			chowns++
		}
	}
	if fchowns != 1 || chowns != 0 {
		t.Fatalf("CREATE ownership ops=%v want one fchown and no path chown", ops)
	}
}

func TestOPENPermLateAfterPerm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perm-late")
	if err := os.WriteFile(path, []byte("data"), 0o666); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",perm=0644,perm-late=0600")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm=%#o want 0600 from perm-late", st.Mode().Perm())
	}
}

func TestOPENLseekChangesOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lseek")
	if err := os.WriteFile(path, []byte("abcdefghij"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",lseek=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	buf := make([]byte, 2)
	n, err := o.Stream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || string(buf) != "ef" {
		t.Fatalf("read %q n=%d want ef after lseek=4", buf[:n], n)
	}
}
