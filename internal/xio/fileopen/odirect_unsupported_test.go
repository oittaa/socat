//go:build darwin || windows

package fileopen

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestPIPEODirectRejectedWhenUnsupported(t *testing.T) {
	named := parse.Spec{Type: "PIPE", Params: []string{filepath.Join(t.TempDir(), "fifo")}, Options: []parse.Option{{Name: "o-direct"}}}
	if _, err := openPIPE(context.Background(), named, xio.ModeRead, nil); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("named PIPE o-direct: %v", err)
	}
	unnamed := parse.Spec{Type: "PIPE", Options: []parse.Option{{Name: "o-direct"}}}
	if _, err := openPIPE(context.Background(), unnamed, xio.ModeRDWR, nil); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unnamed PIPE o-direct: %v", err)
	}
}
