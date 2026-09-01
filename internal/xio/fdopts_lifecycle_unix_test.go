//go:build linux || darwin

package xio

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/testutil"
	"golang.org/x/sys/unix"
)

func fcntlFlags(t *testing.T, f *os.File) int {
	t.Helper()
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return flags
}

func fcntlFD(t *testing.T, f *os.File) int {
	t.Helper()
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	return flags
}

func TestApplyFDOptionsAppendSetsOAPPEND(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "append")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if fcntlFlags(t, f)&unix.O_APPEND != 0 {
		t.Fatal("new file already has O_APPEND")
	}
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,append")); err != nil {
		t.Fatal(err)
	}
	if fcntlFlags(t, f)&unix.O_APPEND == 0 {
		t.Fatal("append did not set O_APPEND")
	}
}

func TestApplyFDOptionsOAppendAlias(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "o-append")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,o-append")); err != nil {
		t.Fatal(err)
	}
	if fcntlFlags(t, f)&unix.O_APPEND == 0 {
		t.Fatal("o-append did not set O_APPEND")
	}
}

func TestApplyFDOptionsAppendZeroClearsOAPPEND(t *testing.T) {
	path := filepath.Join(t.TempDir(), "append0")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if fcntlFlags(t, f)&unix.O_APPEND == 0 {
		t.Fatal("expected O_APPEND from open")
	}
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,append=0")); err != nil {
		t.Fatal(err)
	}
	if fcntlFlags(t, f)&unix.O_APPEND != 0 {
		t.Fatal("append=0 left O_APPEND set")
	}
}

func TestApplyFDOptionsFtruncateShortensFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "trunc")
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

func TestApplyFDOptionsTruncateAlias(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "truncate-alias")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write([]byte("xyz")); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,truncate=1")); err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 1 {
		t.Fatalf("size=%d want 1", st.Size())
	}
}

func TestApplyFDOptionsFtruncateRejectsPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	err = ApplyFDOptions(r, mustSpec(t, "FD:3,ftruncate=0"))
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error=%v want not a regular file", err)
	}
}

func TestApplyFDOptionsPermChmodsFD(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "perm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,perm=0600")); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied") {
			t.Skipf("fchmod not permitted: %v", err)
		}
		t.Fatal(err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm=%#o want 0600", st.Mode().Perm())
	}
}

func TestApplyFDOptionsUserGroupSameIDs(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	spec := mustSpec(t, "FD:3,user="+strconv.Itoa(os.Getuid())+",group="+strconv.Itoa(os.Getgid()))
	if err := ApplyFDOptions(f, spec); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied") {
			t.Skipf("fchown not permitted: %v", err)
		}
		t.Fatal(err)
	}
}

func TestApplyFDOptionsThenWrapCommonAppliesOnce(t *testing.T) {
	tests := []struct {
		name string
		raw  func() string
		op   string
	}{
		{name: "append", raw: func() string { return "FD:3,append" }, op: "F_SETFL"},
		{name: "cloexec", raw: func() string { return "FD:3,cloexec=0" }, op: "F_SETFD"},
		{name: "ftruncate", raw: func() string { return "FD:3,ftruncate=4" }, op: "ftruncate"},
		{name: "perm", raw: func() string { return "FD:3,perm=0600" }, op: "fchmod"},
		{name: "user", raw: func() string { return "FD:3,user=" + strconv.Itoa(os.Getuid()) }, op: "fchown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "once-"+tc.name)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			if tc.op == "ftruncate" {
				if _, err := f.Write([]byte("abcdefghij")); err != nil {
					t.Fatal(err)
				}
			}
			ops := captureLifecycleSyscalls(t)
			spec := mustSpec(t, tc.raw())
			if err := ApplyFDOptions(f, spec); err != nil {
				skipIfOwnerChangeDenied(t, err)
			}
			if _, err := WrapCommon(spec, FileStream(f)); err != nil {
				skipIfOwnerChangeDenied(t, err)
			}
			if got := countOp(*ops, tc.op); got != 1 {
				t.Fatalf("%s applied %d times want exactly 1 (ops=%v)", tc.op, got, *ops)
			}
			if tc.op == "F_SETFL" && fcntlFlags(t, f)&unix.O_APPEND == 0 {
				t.Fatal("O_APPEND missing after ApplyFDOptions + WrapCommon")
			}
			if tc.op == "F_SETFD" && fcntlFD(t, f)&unix.FD_CLOEXEC != 0 {
				t.Fatal("FD_CLOEXEC still set after cloexec=0 + WrapCommon")
			}
		})
	}
}

func TestWrapCommonAppliesUnmarkedPeerAfterApplyFDOptions(t *testing.T) {
	// Unnamed PIPE calls ApplyFDOptions on the read end only, then WrapCommon
	// on both ends. Skipping the whole stream would drop append on the writer.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	spec := mustSpec(t, "PIPE,append")
	if err := ApplyFDOptions(r, spec); err != nil {
		t.Fatal(err)
	}
	if fcntlFlags(t, r)&unix.O_APPEND == 0 {
		t.Fatal("read end missing O_APPEND after ApplyFDOptions")
	}
	if fcntlFlags(t, w)&unix.O_APPEND != 0 {
		t.Fatal("write end already had O_APPEND")
	}
	ops := captureLifecycleSyscalls(t)
	if _, err := WrapCommon(spec, relay.FDStream{R: r, W: w, C: r}); err != nil {
		t.Fatal(err)
	}
	if got := countOp(*ops, "F_SETFL"); got != 1 {
		t.Fatalf("unmarked write end F_SETFL count=%d want 1 (ops=%v)", got, *ops)
	}
	if fcntlFlags(t, w)&unix.O_APPEND == 0 {
		t.Fatal("write end missing O_APPEND after WrapCommon")
	}
}

func TestWrapCommonFileStreamDedupsSameFD(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "filestream")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	var n atomic.Int32
	fdLifecycleTestHook = func(int) { n.Add(1) }
	t.Cleanup(func() { fdLifecycleTestHook = nil })

	spec := mustSpec(t, "STDIO,append")
	if _, err := WrapCommon(spec, FileStream(f)); err != nil {
		t.Fatal(err)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("FileStream R/W/C applied %d times want 1", got)
	}
}

func TestWrapCommonFtruncateRejectsTCP(t *testing.T) {
	cli, srv := localTCPPair(t)
	spec := mustSpec(t, "TCP:127.0.0.1:1,ftruncate=0")
	_, err := WrapCommon(spec, relay.NetStream{Conn: cli})
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error=%v want not a regular file", err)
	}
	_ = srv
}

func TestWrapCommonPermOnAnonymousSocketPropagatesFchmodError(t *testing.T) {
	// Type TCP so skipDescriptorOwnerOpts does not skip. Classic applyopt_spec
	// Fchmod reports EINVAL on Darwin sockets; that error must propagate.
	cli, srv := localTCPPair(t)
	spec := mustSpec(t, "TCP:127.0.0.1:1,perm=0600")
	_, err := WrapCommon(spec, relay.NetStream{Conn: cli})
	if runtime.GOOS == "linux" {
		// Linux fchmod(2) on a socket fd can succeed; do not hide either outcome.
		_ = err
		_ = srv
		return
	}
	if err == nil {
		t.Fatal("expected fchmod error on anonymous socket descriptor")
	}
	if !strings.Contains(err.Error(), "fchmod") && !errors.Is(err, unix.EINVAL) {
		t.Fatalf("error=%v want fchmod EINVAL", err)
	}
	_ = srv
}

func TestWrapCommonUNIXConnectAppliesDescriptorFchmod(t *testing.T) {
	// Classic _xioopen_connect applyopts(PH_FD) fchmods the socket descriptor
	// (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba). Darwin fchmod
	// on UNIX sockets returns EINVAL; that error must propagate.
	listen := testutil.UnixSocketPath(t, "l.sock")
	ln, err := net.Listen("unix", listen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, accErr := ln.Accept()
		if accErr != nil {
			return
		}
		_ = c.Close()
	}()
	cli, err := net.Dial("unix", listen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	spec := mustSpec(t, "UNIX-CONNECT:"+listen+",perm=0600")
	ops := captureLifecycleSyscalls(t)
	_, err = WrapCommon(spec, relay.NetStream{Conn: cli})
	if runtime.GOOS != "linux" {
		if err == nil {
			t.Fatal("expected fchmod error on UNIX-CONNECT socket")
		}
		if !strings.Contains(err.Error(), "fchmod") && !errors.Is(err, unix.EINVAL) {
			t.Fatalf("error=%v want fchmod EINVAL", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if n := countOp(*ops, "fchmod"); n != 1 {
		t.Fatalf("fchmod count=%d want 1", n)
	}
}

func TestWrapCommonAppendOnSocket(t *testing.T) {
	cli, srv := localTCPPair(t)
	spec := mustSpec(t, "TCP:127.0.0.1:1,append")
	if _, err := WrapCommon(spec, relay.NetStream{Conn: cli}); err != nil {
		t.Fatal(err)
	}
	flags := connFcntlFlags(t, cli)
	if flags&unix.O_APPEND == 0 {
		t.Fatalf("socket flags=%#x do not contain O_APPEND", flags)
	}
	_ = srv
}

func TestWrapCommonDoesNotSkipGenericSocketRecvDescriptor(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "socket-recv-visible-fd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := WrapCommon(mustSpec(t, "SOCKET-RECV:2:2:0:x00,append"), FileStream(f)); err != nil {
		t.Fatal(err)
	}
	if fcntlFlags(t, f)&unix.O_APPEND == 0 {
		t.Fatal("SOCKET-RECV descriptor was skipped by datagram wrapper detection")
	}
}

func localTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, accErr := ln.Accept()
		if accErr != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	srv := <-accepted
	if srv == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = srv.Close() })
	return cli, srv
}

func connFcntlFlags(t *testing.T, c net.Conn) int {
	t.Helper()
	sc, ok := c.(syscall.Conn)
	if !ok {
		t.Fatalf("%T is not syscall.Conn", c)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var ferr error
	if err := raw.Control(func(fd uintptr) {
		flags, ferr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if ferr != nil {
		t.Fatal(ferr)
	}
	return flags
}

func skipIfOwnerChangeDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied") {
		t.Skipf("%v", err)
	}
	t.Fatal(err)
}

func TestApplyFDOptionsReusesFDNumberWithSameSpec(t *testing.T) {
	// Regression for process-global fdLifecycleApplied: the kernel reuses fd
	// numbers after close, and tests/callers reuse the same parsed Spec.
	spec := mustSpec(t, "FD:3,ftruncate=3")
	dir := t.TempDir()

	path1 := filepath.Join(dir, "one")
	fd1, err := unix.Open(path1, unix.O_RDWR|unix.O_CREAT, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fd1, []byte("0123456789")); err != nil {
		_ = unix.Close(fd1)
		t.Fatal(err)
	}
	f1 := os.NewFile(uintptr(fd1), path1)
	if err := ApplyFDOptions(f1, spec); err != nil {
		_ = f1.Close()
		t.Fatal(err)
	}
	st, err := f1.Stat()
	if err != nil {
		_ = f1.Close()
		t.Fatal(err)
	}
	if st.Size() != 3 {
		_ = f1.Close()
		t.Fatalf("first apply size=%d want 3", st.Size())
	}
	if err := f1.Close(); err != nil {
		t.Fatal(err)
	}

	path2 := filepath.Join(dir, "two")
	fd2, err := unix.Open(path2, unix.O_RDWR|unix.O_CREAT, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fd2, []byte("abcdefghij")); err != nil {
		_ = unix.Close(fd2)
		t.Fatal(err)
	}
	if fd2 != fd1 {
		if err := unix.Dup2(fd2, fd1); err != nil {
			_ = unix.Close(fd2)
			t.Fatal(err)
		}
		if err := unix.Close(fd2); err != nil {
			t.Fatal(err)
		}
		fd2 = fd1
	}
	f2 := os.NewFile(uintptr(fd2), path2)
	t.Cleanup(func() { _ = f2.Close() })
	st, err = f2.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 10 {
		t.Fatalf("reused fd pre-apply size=%d want 10", st.Size())
	}
	if err := ApplyFDOptions(f2, spec); err != nil {
		t.Fatal(err)
	}
	st, err = f2.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 3 {
		t.Fatalf("reused fd %d size=%d want 3 (same spec skipped?)", fd2, st.Size())
	}
}

func TestApplyFDOptionsModeAliasLastWins(t *testing.T) {
	tests := []struct {
		raw  string
		want os.FileMode
	}{
		{raw: "FD:3,mode=0600", want: 0o600},
		{raw: "FD:3,perm=0644,mode=0600", want: 0o600},
		{raw: "FD:3,mode=0600,perm=0644", want: 0o644},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "mode")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			if err := f.Chmod(0o666); err != nil {
				t.Fatal(err)
			}
			st, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != 0o666 {
				t.Skipf("chmod 0666 did not stick (perm=%#o)", st.Mode().Perm())
			}
			if err := ApplyFDOptions(f, mustSpec(t, tc.raw)); err != nil {
				skipIfOwnerChangeDenied(t, err)
			}
			st, err = f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != tc.want {
				t.Fatalf("perm=%#o want %#o", st.Mode().Perm(), tc.want)
			}
		})
	}
}

func TestApplyFDOptionsUIDOwnerGIDAliases(t *testing.T) {
	uid := strconv.Itoa(os.Getuid())
	gid := strconv.Itoa(os.Getgid())
	for _, raw := range []string{
		"FD:3,uid=" + uid,
		"FD:3,owner=" + uid,
		"FD:3,gid=" + gid,
		"FD:3,uid=" + uid + ",gid=" + gid,
		"FD:3,owner=" + uid + ",user=" + uid,
		"FD:3,gid=" + gid + ",group=" + gid,
	} {
		t.Run(raw, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "owner-alias")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			if err := ApplyFDOptions(f, mustSpec(t, raw)); err != nil {
				skipIfOwnerChangeDenied(t, err)
			}
		})
	}
}

func TestApplyFDOptionsFtruncate32And64LastWins(t *testing.T) {
	tests := []struct {
		raw  string
		want int64
	}{
		{raw: "FD:3,ftruncate32=4", want: 4},
		{raw: "FD:3,ftruncate64=5", want: 5},
		{raw: "FD:3,ftruncate=10,ftruncate32=3", want: 3},
		{raw: "FD:3,ftruncate64=3,ftruncate=8", want: 8},
		{raw: "FD:3,ftruncate32=2,ftruncate64=6", want: 6},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "trunc-alias")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			if _, err := f.Write([]byte("0123456789abcdefghij")); err != nil {
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

func captureLifecycleSyscalls(t *testing.T) *[]string {
	t.Helper()
	var ops []string
	restore := InstallLifecycleSyscallHook(func(op string) {
		ops = append(ops, op)
	})
	t.Cleanup(restore)
	return &ops
}

func countOp(ops []string, want string) int {
	n := 0
	for _, op := range ops {
		if op == want {
			n++
		}
	}
	return n
}

func fileUnixMode(t *testing.T, f *os.File) uint32 {
	t.Helper()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return FileModeToUnix(st.Mode())
}

func TestApplyFDOptionsPermUserOrderSetuidBits(t *testing.T) {
	uid := strconv.Itoa(os.Getuid())
	const wantSetid uint32 = 0o4755
	const wantCleared uint32 = 0o0755

	tests := []struct {
		name string
		raw  string
		want uint32
	}{
		{
			name: "user then perm keeps setuid",
			raw:  "FD:3,user=" + uid + ",perm=04755",
			want: wantSetid,
		},
		{
			name: "perm then user clears setuid",
			raw:  "FD:3,perm=04755,user=" + uid,
			want: wantCleared,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "setuid-order")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			if err := ApplyFDOptions(f, mustSpec(t, tc.raw)); err != nil {
				skipIfOwnerChangeDenied(t, err)
			}
			got := fileUnixMode(t, f) & 0o7777
			if got&0o4000 == 0 && tc.want&0o4000 != 0 {
				t.Skipf("setuid bit did not stick (mode=%#o); filesystem may be nosuid", got)
			}
			if got != tc.want {
				t.Fatalf("mode=%#o want %#o", got, tc.want)
			}
		})
	}
}

func TestApplyFDOptionsRepeatsEachOccurrence(t *testing.T) {
	t.Run("perm twice", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "perm-repeat")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		ops := captureLifecycleSyscalls(t)
		if err := ApplyFDOptions(f, mustSpec(t, "FD:3,perm=0644,perm=0600")); err != nil {
			skipIfOwnerChangeDenied(t, err)
		}
		if got := countOp(*ops, "fchmod"); got != 2 {
			t.Fatalf("fchmod count=%d want 2 (ops=%v)", got, *ops)
		}
		if fileUnixMode(t, f)&0o777 != 0o600 {
			t.Fatalf("perm=%#o want 0600", fileUnixMode(t, f)&0o777)
		}
	})
	t.Run("append then append=0", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "append-repeat")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		ops := captureLifecycleSyscalls(t)
		if err := ApplyFDOptions(f, mustSpec(t, "FD:3,append,append=0")); err != nil {
			t.Fatal(err)
		}
		if got := countOp(*ops, "F_SETFL"); got != 2 {
			t.Fatalf("F_SETFL count=%d want 2 (ops=%v)", got, *ops)
		}
		if fcntlFlags(t, f)&unix.O_APPEND != 0 {
			t.Fatal("append then append=0 left O_APPEND set")
		}
	})
	t.Run("ftruncate twice", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "trunc-repeat")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		if _, err := f.Write([]byte("0123456789abcdefghij")); err != nil {
			t.Fatal(err)
		}
		ops := captureLifecycleSyscalls(t)
		if err := ApplyFDOptions(f, mustSpec(t, "FD:3,ftruncate=8,ftruncate=3")); err != nil {
			t.Fatal(err)
		}
		if got := countOp(*ops, "ftruncate"); got != 2 {
			t.Fatalf("ftruncate count=%d want 2 (ops=%v)", got, *ops)
		}
		st, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() != 3 {
			t.Fatalf("size=%d want 3", st.Size())
		}
	})
}

func TestApplyFDOptionsAliasCanonicalEachOccurrence(t *testing.T) {
	uid := strconv.Itoa(os.Getuid())
	gid := strconv.Itoa(os.Getgid())
	t.Run("mode then perm", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "mode-perm")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		ops := captureLifecycleSyscalls(t)
		if err := ApplyFDOptions(f, mustSpec(t, "FD:3,mode=0644,perm=0600")); err != nil {
			skipIfOwnerChangeDenied(t, err)
		}
		if got := countOp(*ops, "fchmod"); got != 2 {
			t.Fatalf("fchmod count=%d want 2 (ops=%v)", got, *ops)
		}
		if fileUnixMode(t, f)&0o777 != 0o600 {
			t.Fatalf("perm=%#o want 0600", fileUnixMode(t, f)&0o777)
		}
	})
	t.Run("uid then user", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "uid-user")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		ops := captureLifecycleSyscalls(t)
		raw := "FD:3,uid=" + uid + ",user=" + uid
		if err := ApplyFDOptions(f, mustSpec(t, raw)); err != nil {
			skipIfOwnerChangeDenied(t, err)
		}
		if got := countOp(*ops, "fchown"); got != 2 {
			t.Fatalf("fchown count=%d want 2 (ops=%v)", got, *ops)
		}
	})
	t.Run("owner then user", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "owner-user")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		ops := captureLifecycleSyscalls(t)
		raw := "FD:3,owner=" + uid + ",user=" + uid
		if err := ApplyFDOptions(f, mustSpec(t, raw)); err != nil {
			skipIfOwnerChangeDenied(t, err)
		}
		if got := countOp(*ops, "fchown"); got != 2 {
			t.Fatalf("fchown count=%d want 2 (ops=%v)", got, *ops)
		}
	})
	t.Run("gid then group", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "gid-group")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		ops := captureLifecycleSyscalls(t)
		raw := "FD:3,gid=" + gid + ",group=" + gid
		if err := ApplyFDOptions(f, mustSpec(t, raw)); err != nil {
			skipIfOwnerChangeDenied(t, err)
		}
		if got := countOp(*ops, "fchown"); got != 2 {
			t.Fatalf("fchown count=%d want 2 (ops=%v)", got, *ops)
		}
	})
	t.Run("truncate then ftruncate", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "trunc-alias-order")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		if _, err := f.Write([]byte("0123456789abcdefghij")); err != nil {
			t.Fatal(err)
		}
		ops := captureLifecycleSyscalls(t)
		if err := ApplyFDOptions(f, mustSpec(t, "FD:3,truncate=8,ftruncate=3")); err != nil {
			t.Fatal(err)
		}
		if got := countOp(*ops, "ftruncate"); got != 2 {
			t.Fatalf("ftruncate count=%d want 2 (ops=%v)", got, *ops)
		}
		st, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() != 3 {
			t.Fatalf("size=%d want 3", st.Size())
		}
	})
	t.Run("ftruncate32 then ftruncate64", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "trunc32-64")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		if _, err := f.Write([]byte("0123456789abcdefghij")); err != nil {
			t.Fatal(err)
		}
		ops := captureLifecycleSyscalls(t)
		if err := ApplyFDOptions(f, mustSpec(t, "FD:3,ftruncate32=8,ftruncate64=5")); err != nil {
			t.Fatal(err)
		}
		if got := countOp(*ops, "ftruncate"); got != 2 {
			t.Fatalf("ftruncate count=%d want 2 (ops=%v)", got, *ops)
		}
		st, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() != 5 {
			t.Fatalf("size=%d want 5", st.Size())
		}
	})
}

func TestApplyFDOptionsPhaseOrderPermBeforeAppend(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "phase-order")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	ops := captureLifecycleSyscalls(t)
	raw := "FD:3,append,perm=0600"
	if err := ApplyFDOptions(f, mustSpec(t, raw)); err != nil {
		skipIfOwnerChangeDenied(t, err)
	}
	if len(*ops) != 2 || (*ops)[0] != "fchmod" || (*ops)[1] != "F_SETFL" {
		t.Fatalf("ops=%v want [fchmod F_SETFL] (PH_FD before PH_LATE)", *ops)
	}
}

func TestApplyUDPConnOptsAppendFcntlOnce(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	ops := captureLifecycleSyscalls(t)
	spec := mustSpec(t, "UDP-RECV:0,append")
	if err := ApplyUDPConnOpts(pc, spec, "udp4"); err != nil {
		t.Fatal(err)
	}
	if n := countOp(*ops, "F_SETFL"); n != 1 {
		t.Fatalf("F_SETFL count=%d want 1 (ops=%v)", n, *ops)
	}
	if connFcntlFlags(t, pc)&unix.O_APPEND == 0 {
		t.Fatal("UDP-RECV append did not set O_APPEND")
	}
}

func TestWrapCommonEXECPtyWriteOnlyAppliesAppendOnce(t *testing.T) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		_ = slave.Close()
	})
	w := &halfCloseWriter{w: master}
	stream := relay.FDStream{
		R:      EOFReader{},
		W:      w,
		C:      NewMultiCloser(nil, nil),
		CloseW: func() error { w.closeWrite(); return nil },
	}
	ops := captureLifecycleSyscalls(t)
	if _, err := WrapCommon(mustSpec(t, "EXEC:/bin/true,pty,append"), stream); err != nil {
		t.Fatal(err)
	}
	if n := countOp(*ops, "F_SETFL"); n != 1 {
		t.Fatalf("F_SETFL count=%d want 1 (ops=%v)", n, *ops)
	}
	if fcntlFlags(t, master)&unix.O_APPEND == 0 {
		t.Fatal("EXEC pty write-only append did not set O_APPEND")
	}
}

func TestEXECPtyOwnerOptionsApplyToSlaveOnly(t *testing.T) {
	spec := mustSpec(t, "EXEC:true,pty,perm=0600")
	ops := captureLifecycleSyscalls(t)
	master, slave, cleanup, err := openExecPTYPair(&exec.Cmd{}, spec, nil)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() {
		if cleanup != nil {
			cleanup()
		}
		_ = master.Close()
		_ = slave.Close()
	})
	st, err := slave.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("PTY slave mode=%#o want 0600", st.Mode().Perm())
	}
	if err := ApplyFDOptions(master, spec); err != nil {
		t.Fatal(err)
	}
	if got := countOp(*ops, "chmod"); got != 1 {
		t.Fatalf("PTY slave chmod count=%d want 1 (ops=%v)", got, *ops)
	}
	if got := countOp(*ops, "fchmod"); got != 0 {
		t.Fatalf("PTY master unexpectedly received fchmod (ops=%v)", *ops)
	}
}

func TestApplyNamedFileFtruncateRepeatsEachOccurrence(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "named-ftruncate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.WriteString("0123456789"); err != nil {
		t.Fatal(err)
	}
	ops := captureLifecycleSyscalls(t)
	if err := ApplyNamedFileFtruncate(f, mustSpec(t, "OPEN:f,ftruncate=8,ftruncate=3")); err != nil {
		t.Fatal(err)
	}
	if n := countOp(*ops, "ftruncate"); n != 2 {
		t.Fatalf("ftruncate count=%d want 2 (ops=%v)", n, *ops)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 3 {
		t.Fatalf("size=%d want 3", st.Size())
	}
}

func TestApplyFDOptionsCloexecSetsAndClearsFDCLOEXEC(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "cloexec")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if fcntlFD(t, f)&unix.FD_CLOEXEC == 0 {
		t.Fatal("Go temp file is missing default FD_CLOEXEC")
	}
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,cloexec")); err != nil {
		t.Fatal(err)
	}
	if fcntlFD(t, f)&unix.FD_CLOEXEC == 0 {
		t.Fatal("bare cloexec cleared FD_CLOEXEC")
	}
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,cloexec=0")); err != nil {
		t.Fatal(err)
	}
	if fcntlFD(t, f)&unix.FD_CLOEXEC != 0 {
		t.Fatal("cloexec=0 left FD_CLOEXEC set")
	}
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,cloexec=1")); err != nil {
		t.Fatal(err)
	}
	if fcntlFD(t, f)&unix.FD_CLOEXEC == 0 {
		t.Fatal("cloexec=1 did not set FD_CLOEXEC")
	}
}

func TestApplyFDOptionsCloexecOccurrenceOrder(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "cloexec-order")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,cloexec,cloexec=0")); err != nil {
		t.Fatal(err)
	}
	if fcntlFD(t, f)&unix.FD_CLOEXEC != 0 {
		t.Fatal("cloexec then cloexec=0 left FD_CLOEXEC set")
	}
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,cloexec=0,cloexec=1")); err != nil {
		t.Fatal(err)
	}
	if fcntlFD(t, f)&unix.FD_CLOEXEC == 0 {
		t.Fatal("cloexec=0 then cloexec=1 left FD_CLOEXEC clear")
	}
}

func TestWrapCommonCloexecOnTCP(t *testing.T) {
	cli, srv := localTCPPair(t)
	t.Cleanup(func() { _ = srv.Close() })
	spec := mustSpec(t, "TCP:127.0.0.1:1,cloexec=0")
	if _, err := WrapCommon(spec, relay.NetStream{Conn: cli}); err != nil {
		t.Fatal(err)
	}
	sc, ok := cli.(syscall.Conn)
	if !ok {
		t.Fatal("tcp conn is not syscall.Conn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var flagErr error
	if err := raw.Control(func(fd uintptr) {
		flags, flagErr = unix.FcntlInt(fd, unix.F_GETFD, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if flagErr != nil {
		t.Fatal(flagErr)
	}
	if flags&unix.FD_CLOEXEC != 0 {
		t.Fatal("WrapCommon cloexec=0 left FD_CLOEXEC set on TCP")
	}
}

func TestWrapCommonCloexecRejectsStreamWithoutDescriptor(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	_, err := WrapCommon(mustSpec(t, "TCP:127.0.0.1:9,cloexec=0"), relay.NetStream{Conn: a})
	if err == nil || !strings.Contains(err.Error(), "does not expose a descriptor") {
		t.Fatalf("error=%v want stream does not expose a descriptor", err)
	}
}

func TestApplyFDLifecycleToPacketConnCloexecRejectsNonSocket(t *testing.T) {
	err := ApplyFDLifecycleToPacketConn(stubPacketConn{}, mustSpec(t, "QUIC-LISTEN:0,cloexec"))
	if err == nil || !strings.Contains(err.Error(), "does not expose a socket") {
		t.Fatalf("error=%v want packet connection does not expose a socket", err)
	}
}
