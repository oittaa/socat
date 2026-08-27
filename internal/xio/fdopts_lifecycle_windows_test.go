//go:build windows

package xio

import (
	"os"
	"strings"
	"testing"
)

func TestApplyFDOptionsWindowsRejectsInheritedPermUserGroupAppend(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fd-reject")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	tests := []struct {
		raw     string
		wantSub string
	}{
		{raw: "FD:3,perm=0600", wantSub: "fchmod"},
		{raw: "FD:3,mode=0600", wantSub: "fchmod"},
		{raw: "FD:3,user=1", wantSub: "not supported"},
		{raw: "FD:3,uid=1", wantSub: "not supported"},
		{raw: "FD:3,owner=1", wantSub: "not supported"},
		{raw: "FD:3,group=1", wantSub: "not supported"},
		{raw: "FD:3,gid=1", wantSub: "not supported"},
		{raw: "FD:3,append", wantSub: "O_APPEND"},
		{raw: "STDIO,append", wantSub: "O_APPEND"},
		{raw: "FD:3,async", wantSub: "O_ASYNC"},
		{raw: "FD:3,flock", wantSub: "flock"},
		{raw: "FD:3,ioctl-void=1", wantSub: "not supported"},
		{raw: "FD:3,ioctl=1", wantSub: "not supported"},
		{raw: "FD:3,ioctl-int=1:0", wantSub: "not supported"},
		{raw: "FD:3,ioctl-intp=1:0", wantSub: "not supported"},
		{raw: "FD:3,ioctl-bin=1:x01", wantSub: "not supported"},
		{raw: "FD:3,ioctl-string=1:x", wantSub: "not supported"},
		{raw: "FD:3,ioctl-void=4294967296", wantSub: "invalid ioctl-void"},
		{raw: "FD:3,ioctl-bin=1:not-a-dalan", wantSub: "invalid ioctl-bin"},
		{raw: "FD:3,perm-late=0600", wantSub: "fchmod"},
		{raw: "FD:3,user-late=1", wantSub: "not supported"},
		{raw: "FD:3,group-late=1", wantSub: "not supported"},
	}
	for _, tc := range tests {
		err := ApplyFDOptions(f, mustSpec(t, tc.raw))
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Fatalf("%s: error=%v want substring %q", tc.raw, err, tc.wantSub)
		}
	}
}

func TestApplyFDOptionsWindowsLseekMovesOffset(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fd-lseek")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write([]byte("abcdefghij")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,lseek=4")); err != nil {
		t.Fatal(err)
	}
	off, err := f.Seek(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if off != 4 {
		t.Fatalf("offset=%d want 4", off)
	}
}

func TestApplyFDOptionsWindowsFtruncateShortensFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fd-trunc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write([]byte("abcdefghij")); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,ftruncate=4")); err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 4 {
		t.Fatalf("size=%d want 4", st.Size())
	}
}

func TestApplyFDOptionsWindowsFtruncate32And64LastWins(t *testing.T) {
	tests := []struct {
		raw  string
		want int64
	}{
		{raw: "FD:3,ftruncate32=3", want: 3},
		{raw: "FD:3,ftruncate64=5", want: 5},
		{raw: "FD:3,ftruncate=9,ftruncate32=2", want: 2},
		{raw: "FD:3,ftruncate64=2,ftruncate=6", want: 6},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "fd-trunc-alias")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			if _, err := f.Write([]byte("0123456789abcdef")); err != nil {
				t.Fatal(err)
			}
			if err := ApplyFDOptions(f, mustSpec(t, tc.raw)); err != nil {
				t.Fatal(err)
			}
			st, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if st.Size() != tc.want {
				t.Fatalf("size=%d want %d", st.Size(), tc.want)
			}
		})
	}
}

func TestApplyFDOptionsWindowsNamedOPENSkipsPermAppendAppliesFtruncate(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "open-skip")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write([]byte("abcdefghij")); err != nil {
		t.Fatal(err)
	}
	spec := mustSpec(t, "OPEN:file,perm=0600,mode=0600,user=1,group=1,append,ftruncate=3")
	if err := ApplyFDOptions(f, spec); err != nil {
		t.Fatalf("OPEN lifecycle at FD layer: %v", err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 3 {
		t.Fatalf("OPEN ftruncate is PH_LATE on the descriptor; size=%d want 3", st.Size())
	}
}
