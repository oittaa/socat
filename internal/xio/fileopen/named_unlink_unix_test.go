//go:build unix

package fileopen

import (
	"context"
	"io"
	"os"
	"path/filepath"
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
	var o *xio.Opened
	switch spec.Type {
	case "OPEN", "FILE":
		o, err = openOPEN(context.Background(), spec, mode, nil)
	case "CREATE", "CREAT":
		o, err = openCREATE(context.Background(), spec, mode, nil)
	case "GOPEN":
		o, err = openGOPEN(context.Background(), spec, mode, nil)
	default:
		t.Fatalf("unexpected type %q", spec.Type)
	}
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
	o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("OPEN,unlink-early of existing file without creat succeeded")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("name survived unlink-early: %v", err)
	}
}

func TestOpenCreatUnlinkEarlyCreatesNewInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	old, err := held.Stat()
	if err != nil {
		t.Fatal(err)
	}
	o := openSpec(t, "OPEN:"+path+",creat,unlink-early", xio.ModeWrite)
	t.Cleanup(func() { _ = o.Close() })
	newInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("creat+unlink-early left no name: %v", err)
	}
	if os.SameFile(old, newInfo) {
		t.Fatal("OPEN,creat,unlink-early reused the old inode instead of unlinking first")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("new file content=%q want empty", got)
	}
}

func TestOpenUnlinkLateRemovesNameWhileFDOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := openSpec(t, "OPEN:"+path+",unlink-late", xio.ModeRead)
	defer func() { _ = o.Close() }()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("unlink-late left the name: %v", err)
	}
	if xio.RegisteredUnlinkCount() != 0 {
		t.Fatal("unlink-late registered a signal-exit unlink")
	}
	got, err := io.ReadAll(o.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello\n" {
		t.Fatalf("read %q want hello\\n", got)
	}
}

func TestOpenUnlinkCloseKeepsNameUntilClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := openSpec(t, "OPEN:"+path+",unlink-close", xio.ModeRead)
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("unlink-close removed the name while open: %v", err)
	}
	if xio.RegisteredUnlinkCount() == 0 {
		t.Fatal("unlink-close did not register a signal-exit unlink")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("unlink-close left the name after Close: %v", err)
	}
	if xio.RegisteredUnlinkCount() != 0 {
		t.Fatal("Close left a signal-exit unlink registration")
	}
}

func TestOpenUnlinkPreOpenAlias(t *testing.T) {
	for _, opt := range []string{"unlink", "delete", "remove"} {
		t.Run(opt, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			spec, err := parse.ParseSpec("OPEN:" + path + "," + opt)
			if err != nil {
				t.Fatal(err)
			}
			o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
			if err == nil {
				_ = o.Close()
				t.Fatal("expected open to fail after pre-open unlink")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("%s left the name: %v", opt, err)
			}
		})
	}
}

func TestCreateUnlinkLateRemovesNameWhileOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	o := openSpec(t, "CREATE:"+path+",unlink-late", xio.ModeWrite)
	defer func() { _ = o.Close() }()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("CREATE unlink-late left the name: %v", err)
	}
	if _, err := o.Stream.Write([]byte("x")); err != nil {
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

func TestGOPENUnlinkPreOpenExistingRegularFileFails(t *testing.T) {
	// PH_PREOPEN unlink removes the name but does not change GOPEN's
	// already-selected existing-file path, so open fails ENOENT instead of
	// creating a replacement (classic xio-gopen.c / _xioopen_named_early).
	for _, opt := range []string{"unlink", "delete", "remove"} {
		t.Run(opt, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			spec, err := parse.ParseSpec("GOPEN:" + path + "," + opt)
			if err != nil {
				t.Fatal(err)
			}
			o, err := openGOPEN(context.Background(), spec, xio.ModeWrite, nil)
			if err == nil {
				_ = o.Close()
				t.Fatal("GOPEN of an unlinked existing file succeeded")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("GOPEN,%s left or replaced the name: %v", opt, err)
			}
		})
	}
}

func TestOpenCreatUnlinkEarlyDanglingSymlinkCreatesTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "link")
	target := filepath.Join(dir, "target")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	// Stat of a dangling symlink is ENOENT, so unlink-early must not remove
	// the link. O_CREAT then creates the target through it.
	o := openSpec(t, "OPEN:"+path+",creat,unlink-early", xio.ModeWrite)
	t.Cleanup(func() { _ = o.Close() })
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("symlink was removed: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("OPEN,creat,unlink-early replaced the dangling symlink with a regular file")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("symlink target was not created: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("target content=%q want empty", got)
	}
}

func TestOpenUnlinkLateRemovesNameOnFDOptionFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",unlink-late,f-setpipe-sz=4096")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("f-setpipe-sz on a regular file succeeded")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("unlink-late left the name after setup failure: %v", err)
	}
	if xio.RegisteredUnlinkCount() != 0 {
		t.Fatal("failed open left a signal-exit unlink registration")
	}
}

func TestOpenUnlinkCloseRemovesNameOnFDOptionFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",unlink-close,f-setpipe-sz=4096")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("f-setpipe-sz on a regular file succeeded")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("unlink-close left the name after setup failure: %v", err)
	}
	if xio.RegisteredUnlinkCount() != 0 {
		t.Fatal("failed open left a signal-exit unlink registration")
	}
}

func TestNamedPipeUnlinkLateRemovesNameOnFDOptionFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("PIPE:" + path + ",unlink-late,f-setpipe-sz=4096")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openPIPE(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("f-setpipe-sz on a regular file succeeded")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("PIPE unlink-late left the name after setup failure: %v", err)
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
			o, err := openPIPE(context.Background(), spec, xio.ModeRead, nil)
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
	o, err := openPIPE(context.Background(), spec, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("PIPE unlink-late left the name: %v", err)
	}
}
