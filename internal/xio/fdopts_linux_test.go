//go:build linux

package xio

import (
	"os"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func openFSFlagProbe(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fs-flags")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS); err != nil {
		t.Skipf("FS_IOC_GETFLAGS: %v", err)
	}
	// Clear unlink-blocking inode flags before Close/TempDir (LIFO).
	clearInodeFlagsOnCleanup(t, f, fsAppendFL, fsImmutableFL)
	return f
}

func clearInodeFlagsOnCleanup(t *testing.T, f *os.File, masks ...int) {
	t.Helper()
	t.Cleanup(func() {
		fd := int(f.Fd())
		for _, mask := range masks {
			_ = applyFSIoctlMask(fd, mask, false)
		}
	})
}

func TestApplyFDOptionsFSImmutableReturnsKernelError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can set FS_IMMUTABLE_FL")
	}
	f := openFSFlagProbe(t)
	spec, err := parse.ParseSpec("FD:3,fs-immutable")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyFDOptions(f, mustDecodeAddress(t, spec))
	if err == nil {
		t.Fatal("unprivileged fs-immutable succeeded")
	}
	if !strings.Contains(err.Error(), "fs-immutable") {
		t.Fatalf("error %q must name fs-immutable", err)
	}
}
