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
