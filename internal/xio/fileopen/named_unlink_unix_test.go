//go:build linux || darwin

package fileopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func openSpec(t *testing.T, raw string, mode xio.Mode) *xio.Opened {
	t.Helper()
	spec, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenSpec(context.Background(), spec, mode, nil)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestOpenUnlinkEarlyRemovesThenOpenFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",unlink-early")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("OPEN,unlink-early of existing file without creat succeeded")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("name survived unlink-early: %v", err)
	}
}

func TestCreateUnlinkLateRemovesNameWhileOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	o := openSpec(t, "CREATE:"+path+",unlink-late", xio.ModeWrite)
	defer func() { _ = o.Close() }()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("CREATE unlink-late left the name: %v", err)
	}
	if _, err := o.Stream().Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
}

func TestGOPENUnlinkEarlyExistingRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// unlink-early (PH_EARLY) sets exists=false, so GOPEN creates a replacement.
	o := openSpec(t, "GOPEN:"+path+",unlink-early", xio.ModeWrite)
	t.Cleanup(func() { _ = o.Close() })
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("GOPEN,unlink-early left no name: %v", err)
	}
	if string(got) == "OLD\n" {
		t.Fatal("GOPEN,unlink-early reused the old file contents")
	}
}

func TestNamedPipeUnlinkPreOpenIgnoresMissingPath(t *testing.T) {
	dir := t.TempDir()
	for _, opt := range []string{"unlink", "delete", "remove"} {
		t.Run(opt, func(t *testing.T) {
			path := filepath.Join(dir, opt)
			spec, err := parse.ParseSpec("PIPE:" + path + "," + opt + ",nonblock")
			if err != nil {
				t.Fatal(err)
			}
			o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRead, nil)
			if err != nil {
				t.Fatalf("PIPE,%s of a missing path: %v", opt, err)
			}
			t.Cleanup(func() { _ = o.Close() })
		})
	}
}

func TestNamedPipeUnlinkLateRemovesNameWhileOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	spec, err := parse.ParseSpec("PIPE:" + path + ",unlink-late,nonblock,unlink-close=0")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("PIPE unlink-late left the name: %v", err)
	}
}

func TestOpenUnlinkLateEqualsZeroDoesNotUnlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := openSpec(t, "OPEN:"+path+",unlink-late=0", xio.ModeRead)
	defer func() { _ = o.Close() }()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("unlink-late=0 removed the name: %v", err)
	}
	got, err := io.ReadAll(o.Stream())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello\n" {
		t.Fatalf("read %q want hello\\n", got)
	}
}

func TestOpenUnlinkCloseEqualsZeroDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := openSpec(t, "OPEN:"+path+",unlink-close=0", xio.ModeRead)
	if xio.RegisteredUnlinkCount() != 0 {
		t.Fatal("unlink-close=0 registered a signal-exit unlink")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("unlink-close=0 removed the name: %v", err)
	}
}

func TestGOPENUnlinkEqualsZeroKeepsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := openSpec(t, "GOPEN:"+path+",unlink=0", xio.ModeWrite)
	t.Cleanup(func() { _ = o.Close() })
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("GOPEN,unlink=0 removed the name: %v", err)
	}
	if string(got) != "OLD\n" {
		t.Fatalf("content=%q want OLD\\n", got)
	}
}

func TestNamedPipeUnlinkEqualsZeroMissingCreatesFIFO(t *testing.T) {
	dir := t.TempDir()
	for _, opt := range []string{"unlink=0", "delete=0", "remove=0"} {
		t.Run(opt, func(t *testing.T) {
			path := filepath.Join(dir, opt)
			spec, err := parse.ParseSpec("PIPE:" + path + "," + opt + ",nonblock")
			if err != nil {
				t.Fatal(err)
			}
			o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRead, nil)
			if err != nil {
				t.Fatalf("PIPE,%s of a missing path: %v", opt, err)
			}
			t.Cleanup(func() { _ = o.Close() })
		})
	}
}

func TestNamedPipeUnlinkLateEqualsZeroKeepsName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	spec, err := parse.ParseSpec("PIPE:" + path + ",unlink-late=0,nonblock,unlink-close=0")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("PIPE unlink-late=0 removed the name: %v", err)
	}
}

func TestOpenPermEarlyChmodsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := openSpec(t, "OPEN:"+path+",perm-early=0600", xio.ModeRead)
	t.Cleanup(func() { _ = o.Close() })
	assertNamedMode(t, path, 0o600)
	got, err := io.ReadAll(o.Stream())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "OLD\n" {
		t.Fatalf("read %q want OLD\\n", got)
	}
}

func TestOpenPermDoesNotChmodExistingFile(t *testing.T) {
	// perm= is create mode, not PH_PREOPEN chmod. Contrast perm-early.
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := openSpec(t, "OPEN:"+path+",perm=0600", xio.ModeRead)
	t.Cleanup(func() { _ = o.Close() })
	assertNamedMode(t, path, 0o644)
}

func TestOpenUserEarlyGroupEarlyCurrentIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	raw := fmt.Sprintf("OPEN:%s,user-early=%d,group-early=%d", path, uid, gid)
	o := openSpec(t, raw, xio.ModeRead)
	t.Cleanup(func() { _ = o.Close() })
	gotUID, gotGID := fileOwner(t, path)
	if gotUID != uid || gotGID != gid {
		t.Fatalf("owner=%d:%d want %d:%d", gotUID, gotGID, uid, gid)
	}
}

func TestOpenPermEarlyDroppedOnMissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	spec, err := parse.ParseSpec("OPEN:" + path + ",perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("OPEN of missing path with perm-early succeeded")
	}
	if strings.Contains(err.Error(), "chmod") {
		t.Fatalf("perm-early was applied to a missing name: %v", err)
	}
	if !os.IsNotExist(err) && !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("error=%v want not-exist", err)
	}
}

func TestCreatePermStillUsesCreateModeAndUmask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	o := openSpec(t, "CREATE:"+path+",umask=077,perm=0666", xio.ModeWrite)
	t.Cleanup(func() { _ = o.Close() })
	assertNamedMode(t, path, 0o600)
}

func TestUIDEAndGIDEAliases(t *testing.T) {
	s, err := parse.ParseSpec("OPEN:file,uid-e=1000,gid-e=100")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Options) != 2 || s.Options[0].Name != "user-early" || s.Options[0].Value != "1000" ||
		s.Options[1].Name != "group-early" || s.Options[1].Value != "100" {
		t.Fatalf("uid-e/gid-e did not fold: %v", s.Options)
	}
}

func assertNamedMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode=%#o want %#o", path, got, want)
	}
}

func fileOwner(t *testing.T, path string) (uid, gid int) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat sys type %T", info.Sys())
	}
	return int(st.Uid), int(st.Gid)
}
