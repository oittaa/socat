//go:build linux || darwin

package xio

import (
	"os"
	"testing"
)

func TestApplyFDOptionsLseekRejectsPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	err = ApplyFDOptions(r, mustDecodeAddress(t, mustSpec(t, "FD:3,lseek=0")))
	if err == nil {
		t.Fatal("lseek on a pipe succeeded")
	}
}
