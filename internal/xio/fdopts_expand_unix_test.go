//go:build linux || darwin

package xio

import (
	"os"
	"strconv"
	"testing"
)

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
