//go:build unix

package fileopen

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestCreatePathsUseClassic0666BeforeUmask(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	t.Run("create", func(t *testing.T) {
		path := filepath.Join(dir, "create.bin")
		spec, err := parse.ParseSpec("CREATE:" + path + ",umask=0")
		if err != nil {
			t.Fatal(err)
		}
		o, err := openCREATE(ctx, spec, xio.ModeWrite, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		assertPerm(t, path, 0o666)
	})

	t.Run("open-creat", func(t *testing.T) {
		path := filepath.Join(dir, "open.bin")
		spec, err := parse.ParseSpec("OPEN:" + path + ",creat,umask=0")
		if err != nil {
			t.Fatal(err)
		}
		o, err := openOPEN(ctx, spec, xio.ModeWrite, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		assertPerm(t, path, 0o666)
	})

	t.Run("gopen", func(t *testing.T) {
		path := filepath.Join(dir, "gopen.bin")
		spec, err := parse.ParseSpec("GOPEN:" + path + ",umask=0")
		if err != nil {
			t.Fatal(err)
		}
		o, err := openGOPEN(ctx, spec, xio.ModeWrite, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		assertPerm(t, path, 0o666)
	})

	t.Run("fifo", func(t *testing.T) {
		path := filepath.Join(dir, "named.pipe")
		spec, err := parse.ParseSpec("PIPE:" + path + ",umask=0,nonblock")
		if err != nil {
			t.Fatal(err)
		}
		o, err := openPIPE(ctx, spec, xio.ModeRead, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		assertPerm(t, path, 0o666)
	})
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode=%#o want %#o", path, got, want)
	}
}
