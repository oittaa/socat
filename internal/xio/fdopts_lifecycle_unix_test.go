//go:build unix

package xio

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

func mustSpec(t *testing.T, raw string) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func fcntlFlags(t *testing.T, f *os.File) int {
	t.Helper()
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
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
	f, err := os.CreateTemp(t.TempDir(), "dedup")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	var n atomic.Int32
	fdLifecycleTestHook = func(int) { n.Add(1) }
	t.Cleanup(func() { fdLifecycleTestHook = nil })

	spec := mustSpec(t, "FD:3,append")
	if err := ApplyFDOptions(f, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := WrapCommon(spec, FileStream(f)); err != nil {
		t.Fatal(err)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("lifecycle applied %d times want 1 (ApplyFDOptions + WrapCommon on the same fd)", got)
	}
	if fcntlFlags(t, f)&unix.O_APPEND == 0 {
		t.Fatal("O_APPEND missing after deduped apply")
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
