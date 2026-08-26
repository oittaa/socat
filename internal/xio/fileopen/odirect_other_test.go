//go:build !linux

package fileopen

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestODirectRejectedWhenUnsupported(t *testing.T) {
	enabled := parse.Spec{Type: "OPEN", Params: []string{"x"}, Options: []parse.Option{{Name: "o-direct"}}}
	if _, err := OpenFlags(enabled, xio.ModeRead); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("enabled o-direct: %v", err)
	}
	if _, err := openOPEN(context.Background(), enabled, xio.ModeRead, nil); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("openOPEN enabled o-direct: %v", err)
	}

	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	disabled, err := parse.ParseSpec("OPEN:" + path + ",o-direct=0")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), disabled, xio.ModeRead, nil)
	if err != nil {
		t.Fatalf("disabled o-direct: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })
}
