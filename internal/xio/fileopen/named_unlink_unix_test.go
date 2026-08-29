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

func isUnlinkDirectoryError(err error) bool {
	return errors.Is(err, syscall.EISDIR) || errors.Is(err, syscall.EPERM)
}

func TestOpenCreatUnlinkEarlyLeavesEmptyDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "emptydir")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",creat,unlink-early")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeWrite, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("OPEN,creat,unlink-early deleted an empty directory")
	}
	if !isUnlinkDirectoryError(err) {
		t.Fatalf("error=%v want EISDIR or EPERM", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("empty directory was replaced; mode=%v", info.Mode())
	}
}

func TestNamedPipeUnlinkEarlyLeavesEmptyDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "emptydir")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("PIPE:" + path + ",unlink-early,nonblock")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openPIPE(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("PIPE,unlink-early deleted an empty directory")
	}
	if !isUnlinkDirectoryError(err) {
		t.Fatalf("error=%v want EISDIR or EPERM", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("empty directory was replaced; mode=%v", info.Mode())
	}
}

func TestOpenUnlinkLateFailsWhenParentNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can unlink in unwritable directories")
	}
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "file")
	if err := os.WriteFile(path, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",unlink-late")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		got, _ := io.ReadAll(o.Stream)
		_ = o.Close()
		t.Fatalf("unlink-late succeeded and transferred %q", got)
	}
	if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) {
		t.Fatalf("error=%v want EACCES or EPERM", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret\n" {
		t.Fatalf("file contents=%q want secret\\n", got)
	}
}

func TestOpenUnlinkEqualsZeroDoesNotUnlink(t *testing.T) {
	// Documented TYPE_BOOL: unlink=0 must not delete. Classic applyopts_named
	// ignores the stored false and would unlink; we do not copy that bug.
	for _, opt := range []string{"unlink=0", "delete=0", "remove=0"} {
		t.Run(opt, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			o := openSpec(t, "OPEN:"+path+","+opt, xio.ModeRead)
			t.Cleanup(func() { _ = o.Close() })
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("%s removed the name: %v", opt, err)
			}
			got, err := io.ReadAll(o.Stream)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "OLD\n" {
				t.Fatalf("read %q want OLD\\n", got)
			}
		})
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
	got, err := io.ReadAll(o.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello\n" {
		t.Fatalf("read %q want hello\\n", got)
	}
}

func TestOpenUnlinkEarlyEqualsZeroDisabled(t *testing.T) {
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
	o := openSpec(t, "OPEN:"+path+",creat,unlink-early=0", xio.ModeWrite)
	t.Cleanup(func() { _ = o.Close() })
	newInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("unlink-early=0 left no name: %v", err)
	}
	if !os.SameFile(old, newInfo) {
		t.Fatal("unlink-early=0 unlinked instead of opening the existing inode")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "OLD\n" {
		t.Fatalf("content=%q want OLD\\n", got)
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
			o, err := openPIPE(context.Background(), spec, xio.ModeRead, nil)
			if err != nil {
				t.Fatalf("PIPE,%s of a missing path: %v", opt, err)
			}
			t.Cleanup(func() { _ = o.Close() })
		})
	}
}

func TestNamedPipeUnlinkEqualsZeroLeavesLeftoverFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale")
	if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("PIPE:" + path + ",unlink=0,nonblock")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openPIPE(context.Background(), spec, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("PIPE,unlink=0 removed the leftover: %v", err)
	}
	if fi.Mode()&os.ModeNamedPipe != 0 {
		t.Fatal("PIPE,unlink=0 replaced the leftover file with a FIFO")
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("PIPE,unlink=0 left mode=%v want regular file", fi.Mode())
	}
}

func TestNamedPipeUnlinkLateEqualsZeroKeepsName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	spec, err := parse.ParseSpec("PIPE:" + path + ",unlink-late=0,nonblock,unlink-close=0")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openPIPE(context.Background(), spec, xio.ModeRead, nil)
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
	got, err := io.ReadAll(o.Stream)
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

func TestOpenUnlinkEarlyDropsPermEarly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",unlink-early,perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("OPEN,unlink-early,perm-early of existing file without creat succeeded")
	}
	if strings.Contains(err.Error(), "chmod") {
		t.Fatalf("perm-early was applied after unlink-early: %v", err)
	}
	if !os.IsNotExist(err) && !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("error=%v want not-exist", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("name survived unlink-early: %v", err)
	}
}

func TestOpenUnlinkThenPermEarlyFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",unlink,perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("OPEN,unlink,perm-early succeeded")
	}
	if !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("error=%v want chmod after unlink", err)
	}
	if !os.IsNotExist(err) && !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("error=%v want ENOENT from chmod", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("name survived unlink: %v", err)
	}
}

func TestOpenPermEarlyThenUnlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	link := filepath.Join(dir, "hardlink")
	if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",perm-early=0600,unlink")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("OPEN,perm-early,unlink without creat succeeded")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("name survived unlink: %v", err)
	}
	assertNamedMode(t, link, 0o600)
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
	o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
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

func TestOpenUserAfterOpenIndependentOfUserEarly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	o := openSpec(t, fmt.Sprintf("OPEN:%s,user-early=%d,user=%d", path, uid, uid), xio.ModeRead)
	t.Cleanup(func() { _ = o.Close() })
	gotUID, _ := fileOwner(t, path)
	if gotUID != uid {
		t.Fatalf("uid=%d want %d", gotUID, uid)
	}

	spec, err := parse.ParseSpec("OPEN:" + path + ",user=socat-user-that-must-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	bad, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = bad.Close()
		t.Fatal("OPEN,user=unknown succeeded")
	}
	if !strings.Contains(err.Error(), "user") {
		t.Fatalf("error=%v want user lookup failure", err)
	}
}

func TestUIDEAndGIDEAliases(t *testing.T) {
	s, err := parse.ParseSpec("OPEN:file,uid-e=1000,gid-e=100")
	if err != nil {
		t.Fatal(err)
	}
	if s.OptionValue("user-early", "") != "1000" {
		t.Fatalf("uid-e did not parse as user-early: %v", s.Options)
	}
	if s.OptionValue("group-early", "") != "100" {
		t.Fatalf("gid-e did not parse as group-early: %v", s.Options)
	}
	if len(s.Options) != 2 || s.Options[0].Name != "user-early" || s.Options[1].Name != "group-early" {
		t.Fatalf("stored names=%v", s.Options)
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
