//go:build unix

package xio

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestApplyFDOptionsAsyncSetsOASYNC(t *testing.T) {
	// Linux F_SETFL O_ASYNC only sticks on fds with an fasync op (pipes,
	// sockets). Regular files accept F_SETFL but F_GETFL stays unchanged.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	if err := ApplyFDOptions(r, mustSpec(t, "FD:3,async")); err != nil {
		t.Fatal(err)
	}
	if fcntlFlags(t, r)&unix.O_ASYNC == 0 {
		t.Fatal("async did not set O_ASYNC")
	}
	if err := ApplyFDOptions(r, mustSpec(t, "FD:3,o-async=0")); err != nil {
		t.Fatal(err)
	}
	if fcntlFlags(t, r)&unix.O_ASYNC != 0 {
		t.Fatal("o-async=0 left O_ASYNC set")
	}
}

func TestApplyFDOptionsLseekMovesOffset(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "lseek")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write([]byte("abcdefghij")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,lseek=4")); err != nil {
		t.Fatal(err)
	}
	off, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if off != 4 {
		t.Fatalf("offset=%d want 4", off)
	}
}

func TestApplyFDOptionsLseekAliasesLastWins(t *testing.T) {
	tests := []struct {
		raw  string
		want int64
	}{
		{raw: "FD:3,lseek=2,seek-end=-3", want: 7},
		{raw: "FD:3,seek-end=0,lseek64=3", want: 3},
		{raw: "FD:3,lseek32-cur=1,seek-set=6", want: 6},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "lseek-alias")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			if _, err := f.Write([]byte("0123456789")); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			if err := ApplyFDOptions(f, mustSpec(t, tc.raw)); err != nil {
				t.Fatal(err)
			}
			off, err := f.Seek(0, io.SeekCurrent)
			if err != nil {
				t.Fatal(err)
			}
			if off != tc.want {
				t.Fatalf("offset=%d want %d", off, tc.want)
			}
		})
	}
}

func TestApplyFDOptionsLseekThenFtruncateOrder(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "lseek-trunc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	ops := captureLifecycleSyscalls(t)
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,ftruncate=8,lseek=3")); err != nil {
		t.Fatal(err)
	}
	if len(*ops) < 2 || (*ops)[0] != "ftruncate" || (*ops)[1] != "lseek" {
		t.Fatalf("ops=%v want [ftruncate lseek]", *ops)
	}
	off, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if off != 3 {
		t.Fatalf("offset=%d want 3", off)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 8 {
		t.Fatalf("size=%d want 8", st.Size())
	}
}

func TestApplyFDOptionsPermLateAfterPerm(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "perm-late")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Chmod(0o666); err != nil {
		t.Fatal(err)
	}
	ops := captureLifecycleSyscalls(t)
	raw := "FD:3,perm-late=0600,perm=0644"
	if err := ApplyFDOptions(f, mustSpec(t, raw)); err != nil {
		skipIfOwnerChangeDenied(t, err)
	}
	if len(*ops) != 2 || (*ops)[0] != "fchmod" || (*ops)[1] != "fchmod" {
		t.Fatalf("ops=%v want [fchmod fchmod] (PH_FD perm then PH_LATE perm-late)", *ops)
	}
	if fileUnixMode(t, f)&0o777 != 0o600 {
		t.Fatalf("perm=%#o want 0600 from perm-late", fileUnixMode(t, f)&0o777)
	}
}

func TestApplyFDOptionsModeLateAlias(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "mode-late")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,mode-late=0600")); err != nil {
		skipIfOwnerChangeDenied(t, err)
	}
	if fileUnixMode(t, f)&0o777 != 0o600 {
		t.Fatalf("perm=%#o want 0600", fileUnixMode(t, f)&0o777)
	}
}

func TestApplyFDOptionsUserLateAfterUser(t *testing.T) {
	uid := strconv.Itoa(os.Getuid())
	f, err := os.CreateTemp(t.TempDir(), "user-late")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	ops := captureLifecycleSyscalls(t)
	raw := "FD:3,user-late=" + uid + ",user=" + uid
	if err := ApplyFDOptions(f, mustSpec(t, raw)); err != nil {
		skipIfOwnerChangeDenied(t, err)
	}
	if got := countOp(*ops, "fchown"); got != 2 {
		t.Fatalf("fchown count=%d want 2 (PH_FD then PH_LATE); ops=%v", got, *ops)
	}
}

func TestApplyFDOptionsFlockExclusiveConflicts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flock")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := ApplyFDOptions(a, mustSpec(t, "FD:3,flock")); err != nil {
		t.Fatal(err)
	}
	err = ApplyFDOptions(b, mustSpec(t, "FD:3,flock-nb"))
	if err == nil {
		t.Fatal("second exclusive flock-nb succeeded")
	}
	if !strings.Contains(err.Error(), "flock") {
		t.Fatalf("error=%v want flock", err)
	}
}

func TestApplyFDOptionsFlockSharedAllowsShared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flock-sh")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := ApplyFDOptions(a, mustSpec(t, "FD:3,flock-sh")); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(b, mustSpec(t, "FD:3,flock-sh-nb")); err != nil {
		t.Fatal(err)
	}
}

func TestApplyFDOptionsFlockDoesNotBreakSetlk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flock-setlk")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,flock-sh")); err != nil {
		t.Fatal(err)
	}
	if err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &unix.Flock_t{
		Type:   unix.F_RDLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}); err != nil {
		t.Fatalf("setlk-style F_RDLCK after flock-sh: %v", err)
	}
}

func TestApplyFDOptionsLseekRejectsPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	err = ApplyFDOptions(r, mustSpec(t, "FD:3,lseek=0"))
	if err == nil {
		t.Fatal("lseek on a pipe succeeded")
	}
}
