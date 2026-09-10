//go:build linux || darwin

package filan

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

func TestClassicDevPairHighLow16(t *testing.T) {
	if got := classicDevPair(0xa5c); got != "10,92" {
		t.Fatalf("classicDevPair(0xa5c)=%q want 10,92", got)
	}
	if got := classicDevPair(0); got != "0,0" {
		t.Fatalf("classicDevPair(0)=%q", got)
	}
}

func TestFDPathStdinOrFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "filan-path")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	got := FDPath(int(f.Fd()))
	if got == "" {
		t.Fatal("FDPath empty")
	}
	if !strings.Contains(got, "filan-path") {
		t.Fatalf("FDPath=%q", got)
	}
}

func dumpFD(t *testing.T, fd int) string {
	t.Helper()
	var b outbuf.Buf
	var buf bytes.Buffer
	WriteFD(&b, fd, Options{})
	if err := b.Flush(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestWriteFDReportsTermiosOnPTY(t *testing.T) {
	master, slave, err := openTestPTY()
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = slave.Close(); _ = master.Close() })
	got := dumpFD(t, int(slave.Fd()))
	if !strings.Contains(got, "IFLAGS=") || !strings.Contains(got, "cc[0]=") {
		t.Fatalf("missing termios: %q", got)
	}
}

func TestSockaddrLenUnnamedUnixIgnoresAnonDisplay(t *testing.T) {
	sa := &unix.SockaddrUnix{}
	got := sockaddrLen(sa)
	hdr := int(unsafe.Offsetof(unix.RawSockaddrUnix{}.Path))
	if got != hdr {
		t.Fatalf("sockaddrLen unnamed=%d want header %d", got, hdr)
	}
	if got == hdr+len("<anon>")+1 {
		t.Fatal("sockaddrLen used <anon> display width")
	}
}

func TestSockAddrInfoInet4(t *testing.T) {
	sa := &unix.SockaddrInet4{Port: 2345, Addr: [4]byte{127, 0, 0, 1}}
	got := SockAddrInfo(sa)
	if !strings.Contains(got, "AF=") || !strings.Contains(got, "127.0.0.1:2345") {
		t.Fatalf("SockAddrInfo=%q", got)
	}
	if short := SockAddrString(sa); short != "127.0.0.1:2345" {
		t.Fatalf("SockAddrString=%q", short)
	}
}
