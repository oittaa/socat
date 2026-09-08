//go:build linux || darwin

package xio

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/relay"
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

func TestSetupStreamFileStreamDedupsSameFD(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "filestream")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	var n atomic.Int32
	fdLifecycleTestHook = func(int) { n.Add(1) }
	t.Cleanup(func() { fdLifecycleTestHook = nil })

	spec := mustSpec(t, "STDIO,append")
	if _, err := SetupStream(spec, FileStream(f)); err != nil {
		t.Fatal(err)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("FileStream R/W/C applied %d times want 1", got)
	}
}

func TestSetupStreamFtruncateRejectsTCP(t *testing.T) {
	cli, srv := localTCPPair(t)
	spec := mustSpec(t, "TCP:127.0.0.1:1,ftruncate=0")
	_, err := SetupStream(spec, relay.NetStream{Conn: cli})
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error=%v want not a regular file", err)
	}
	_ = srv
}

func TestSetupStreamPermOnAnonymousSocketPropagatesFchmodError(t *testing.T) {
	// Type TCP so skipDescriptorOwnerOpts does not skip. Classic applyopt_spec
	// Fchmod reports EINVAL on Darwin sockets; that error must propagate.
	cli, srv := localTCPPair(t)
	spec := mustSpec(t, "TCP:127.0.0.1:1,perm=0600")
	_, err := SetupStream(spec, relay.NetStream{Conn: cli})
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

func TestSetupStreamAppendOnSocket(t *testing.T) {
	cli, srv := localTCPPair(t)
	spec := mustSpec(t, "TCP:127.0.0.1:1,append")
	if _, err := SetupStream(spec, relay.NetStream{Conn: cli}); err != nil {
		t.Fatal(err)
	}
	flags := connFcntlFlags(t, cli)
	if flags&unix.O_APPEND == 0 {
		t.Fatalf("socket flags=%#x do not contain O_APPEND", flags)
	}
	_ = srv
}

func TestSetupStreamDoesNotSkipGenericSocketRecvDescriptor(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "socket-recv-visible-fd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := SetupStream(mustSpec(t, "SOCKET-RECV:2:2:0:x00,append"), FileStream(f)); err != nil {
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

func TestSetupStreamCloexecRejectsStreamWithoutDescriptor(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	_, err := SetupStream(mustSpec(t, "TCP:127.0.0.1:9,cloexec=0"), relay.NetStream{Conn: a})
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
