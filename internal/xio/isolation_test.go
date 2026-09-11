package xio_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestIsolationOptionsRejectedBeforeCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "created.txt")
	spec, err := parse.ParseSpec("CREATE:" + path + ",setuid=65534")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenSpec(context.Background(), spec, xio.ModeWrite, nil)
	if err == nil || !strings.Contains(err.Error(), "not supported") || !strings.Contains(err.Error(), "isolation") {
		t.Fatalf("OpenSpec error=%v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("CREATE path exists after isolation rejection: %v", statErr)
	}
}

func TestIsolationOptionsRejectedOnOpenSpec(t *testing.T) {
	cases := []struct {
		spec     string
		spelling string
	}{
		{"TCP:127.0.0.1:1,setuid=65534", "setuid"},
		{"TCP:127.0.0.1:1,su=65534", "su"},
		{"TCP:127.0.0.1:1,su-d=65534", "su-d"},
		{"TCP:127.0.0.1:1,setgid-early=65534", "setgid-early"},
		{"TCP:127.0.0.1:1,chroot=/tmp", "chroot"},
		{"TCP:127.0.0.1:1,substuser-early=65534", "substuser-early"},
		{"PIPE,substuser-delayed=65534", "substuser-delayed"},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			s, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			_, err = xio.OpenSpec(context.Background(), s, xio.ModeRDWR, nil)
			if err == nil || !strings.Contains(err.Error(), "not supported") || !strings.Contains(err.Error(), "isolation") {
				t.Fatalf("OpenSpec error=%v", err)
			}
			if !strings.Contains(err.Error(), `option "`+tc.spelling+`"`) {
				t.Fatalf("error=%v want spelling %q", err, tc.spelling)
			}
		})
	}
}

func TestIsolationTypoIsNotRecognized(t *testing.T) {
	s, err := parse.ParseSpec("PIPE,setuidd=65534")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := addrconfig.Decode(s, addrconfig.Facts{Type: s.Type}); err != nil {
		t.Fatalf("typo treated as isolation option: %v", err)
	}
}
