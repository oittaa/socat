//go:build linux

package xio

import (
	"os"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplyFDOptionsNoatime(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "noatime")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	spec, err := parse.ParseSpec("FD:3,o-noatime")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, spec); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_NOATIME == 0 {
		t.Fatalf("flags=%#x do not contain O_NOATIME", flags)
	}
}

func TestApplyFDOptionsPipeSize(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	spec, err := parse.ParseSpec("FD:3,pipesz=4096")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(r, spec); err != nil {
		t.Fatal(err)
	}
	size, err := unix.FcntlInt(r.Fd(), unix.F_GETPIPE_SZ, 0)
	if err != nil {
		t.Fatal(err)
	}
	if size != 4096 {
		t.Fatalf("pipe size=%d want 4096", size)
	}
}

func TestApplyFDOptionsFSNoatime(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fs-noatime")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS); err != nil {
		t.Skipf("FS_IOC_GETFLAGS: %v", err)
	}

	spec, err := parse.ParseSpec("FD:3,fs-noatime")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, spec); err != nil {
		t.Skipf("fs-noatime: %v", err)
	}
	flags, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		t.Fatal(err)
	}
	if flags&fsNoatimeFL == 0 {
		t.Fatalf("inode flags=%#x do not contain FS_NOATIME_FL", flags)
	}
	fcntlFlags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fcntlFlags&unix.O_NOATIME != 0 {
		t.Fatalf("fs-noatime must not set O_NOATIME (fcntl flags=%#x)", fcntlFlags)
	}

	clear, err := parse.ParseSpec("FD:3,fs-noatime=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, clear); err != nil {
		t.Fatal(err)
	}
	flags, err = unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		t.Fatal(err)
	}
	if flags&fsNoatimeFL != 0 {
		t.Fatalf("fs-noatime=0 left FS_NOATIME_FL set (flags=%#x)", flags)
	}
}

func openFSFlagProbe(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fs-flags")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS); err != nil {
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

func inodeFlags(t *testing.T, f *os.File) int {
	t.Helper()
	flags, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		t.Fatal(err)
	}
	return flags
}

func TestApplyFDOptionsFSNodumpSetClearLastWins(t *testing.T) {
	f := openFSFlagProbe(t)
	before := inodeFlags(t, f)

	spec, err := parse.ParseSpec("FD:3,fs-nodump")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, spec); err != nil {
		t.Skipf("fs-nodump: %v", err)
	}
	afterSet := inodeFlags(t, f)
	if afterSet&fsNodumpFL == 0 {
		t.Fatalf("inode flags=%#x do not contain FS_NODUMP_FL", afterSet)
	}
	if afterSet&^fsNodumpFL != before&^fsNodumpFL {
		t.Fatalf("unrelated bits changed: before=%#x after=%#x", before, afterSet)
	}

	clear, err := parse.ParseSpec("FD:3,nodump=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, clear); err != nil {
		t.Fatal(err)
	}
	afterClear := inodeFlags(t, f)
	if afterClear&fsNodumpFL != 0 {
		t.Fatalf("nodump=0 left FS_NODUMP_FL set (flags=%#x)", afterClear)
	}
	if afterClear&^fsNodumpFL != afterSet&^fsNodumpFL {
		t.Fatalf("clear changed unrelated bits: set=%#x clear=%#x", afterSet, afterClear)
	}

	lastWins, err := parse.ParseSpec("FD:3,fs-nodump,ext2-nodump=0,nodump")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, lastWins); err != nil {
		t.Fatal(err)
	}
	if inodeFlags(t, f)&fsNodumpFL == 0 {
		t.Fatal("last nodump must win")
	}
}

func TestApplyFDOptionsFSAppendIsNotOAppend(t *testing.T) {
	f := openFSFlagProbe(t)
	spec, err := parse.ParseSpec("FD:3,append")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, spec); err != nil {
		t.Fatal(err)
	}
	fcntlFlags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fcntlFlags&unix.O_APPEND == 0 {
		t.Fatalf("append must set O_APPEND (fcntl flags=%#x)", fcntlFlags)
	}
	if inodeFlags(t, f)&fsAppendFL != 0 {
		t.Fatalf("append must not set FS_APPEND_FL (inode flags=%#x)", inodeFlags(t, f))
	}

	f2 := openFSFlagProbe(t)
	clearInodeFlagsOnCleanup(t, f2, fsAppendFL)
	fsSpec, err := parse.ParseSpec("FD:3,fs-append")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyFDOptions(f2, fsSpec)
	fcntlFlags, ferr := unix.FcntlInt(f2.Fd(), unix.F_GETFL, 0)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if fcntlFlags&unix.O_APPEND != 0 {
		t.Fatalf("fs-append must not set O_APPEND (fcntl flags=%#x)", fcntlFlags)
	}
	if err != nil {
		if !strings.Contains(err.Error(), "fs-append") {
			t.Fatalf("error %q must name fs-append", err)
		}
		return
	}
	if inodeFlags(t, f2)&fsAppendFL == 0 {
		t.Fatal("fs-append succeeded without FS_APPEND_FL")
	}
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
	err = ApplyFDOptions(f, spec)
	if err == nil {
		t.Fatal("unprivileged fs-immutable succeeded")
	}
	if !strings.Contains(err.Error(), "fs-immutable") {
		t.Fatalf("error %q must name fs-immutable", err)
	}
}

func TestApplyFDOptionsDoesNotSetODirect(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "odirect")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	spec, err := parse.ParseSpec("FD:3,o-direct")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, spec); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_DIRECT != 0 {
		t.Fatalf("ApplyFDOptions must not set O_DIRECT (flags=%#x)", flags)
	}
}

func TestApplyFDOptionsPHFDCommandLineOrderCrossFamily(t *testing.T) {
	f := openFSFlagProbe(t)
	var ops []string
	restore := InstallLifecycleSyscallHook(func(op string) { ops = append(ops, op) })
	t.Cleanup(restore)

	spec, err := parse.ParseSpec("FD:3,perm=0600,fs-nodump,o-noatime,nodump=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, spec); err != nil {
		t.Skipf("mixed PH_FD apply: %v", err)
	}
	want := []string{"fchmod", "FS_IOC_SETFLAGS", "F_SETFL", "FS_IOC_SETFLAGS"}
	if len(ops) != len(want) {
		t.Fatalf("ops=%v want %v", ops, want)
	}
	for i := range want {
		if ops[i] != want[i] {
			t.Fatalf("ops=%v want %v", ops, want)
		}
	}
	if inodeFlags(t, f)&fsNodumpFL != 0 {
		t.Fatalf("last nodump=0 must win after perm/o-noatime: %#x", inodeFlags(t, f))
	}
	mode, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if mode.Mode().Perm() != 0o600 {
		t.Fatalf("perm=%o want 0600", mode.Mode().Perm())
	}
	fcntlFlags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fcntlFlags&unix.O_NOATIME == 0 {
		t.Fatalf("o-noatime missing after mixed PH_FD walk (flags=%#x)", fcntlFlags)
	}

	f2 := openFSFlagProbe(t)
	ops = nil
	spec, err = parse.ParseSpec("FD:3,fs-nodump,perm=0640,o-noatime")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f2, spec); err != nil {
		t.Fatal(err)
	}
	want = []string{"FS_IOC_SETFLAGS", "fchmod", "F_SETFL"}
	if len(ops) != len(want) {
		t.Fatalf("reversed ops=%v want %v", ops, want)
	}
	for i := range want {
		if ops[i] != want[i] {
			t.Fatalf("reversed ops=%v want %v", ops, want)
		}
	}
}

func TestApplyFDOptionsPermBeforeFSImmutableFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can set FS_IMMUTABLE_FL")
	}
	f := openFSFlagProbe(t)
	spec, err := parse.ParseSpec("FD:3,perm=0600,fs-immutable")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyFDOptions(f, spec)
	if err == nil {
		t.Fatal("unprivileged fs-immutable succeeded")
	}
	if !strings.Contains(err.Error(), "fs-immutable") {
		t.Fatalf("error %q must name fs-immutable", err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm must apply before fs-immutable fails: mode=%o", st.Mode().Perm())
	}

	f2 := openFSFlagProbe(t)
	before, err := f2.Stat()
	if err != nil {
		t.Fatal(err)
	}
	spec, err = parse.ParseSpec("FD:3,fs-immutable,perm=0600")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyFDOptions(f2, spec)
	if err == nil {
		t.Fatal("unprivileged fs-immutable succeeded")
	}
	after, err := f2.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("perm must not apply after fs-immutable fails: before=%o after=%o", before.Mode().Perm(), after.Mode().Perm())
	}
}

