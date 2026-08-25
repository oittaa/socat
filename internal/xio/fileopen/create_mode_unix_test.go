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

	t.Run("umask-masks-perm", func(t *testing.T) {
		path := filepath.Join(dir, "perm.bin")
		spec, err := parse.ParseSpec("CREATE:" + path + ",umask=077,perm=0666")
		if err != nil {
			t.Fatal(err)
		}
		o, err := openCREATE(ctx, spec, xio.ModeWrite, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		assertPerm(t, path, 0o600)
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

func TestCreatePermPreservesSetuidBits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "setuid.bin")
	spec, err := parse.ParseSpec("CREATE:" + path + ",umask=0,perm=4755")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openCREATE(context.Background(), spec, xio.ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid == 0 || info.Mode().Perm() != 0o755 {
		t.Fatalf("mode=%#o setuid=%v want 04755", info.Mode(), info.Mode()&os.ModeSetuid != 0)
	}
}

func TestOpenExistingFileDoesNotChmod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.bin")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",perm=0600")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	assertPerm(t, path, 0o644)
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
