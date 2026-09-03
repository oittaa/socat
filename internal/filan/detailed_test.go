//go:build linux || darwin

package filan

import (
	"bytes"
	"net"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

func TestWriteHeaderColumns(t *testing.T) {
	want := []string{
		"  FD  type", "device", "inode", "mode", "links", "uid", "gid", "rdev",
		"size", "blksize", "blocks", "atime", "mtime", "ctime", "cloexec", "flags", "sigown",
	}
	if runtime.GOOS == "linux" {
		want = append(want, "sigio")
	}
	for _, raw := range []bool{false, true} {
		var b outbuf.Buf
		var buf bytes.Buffer
		WriteHeader(&b, Options{Raw: raw})
		if err := b.Flush(&buf); err != nil {
			t.Fatal(err)
		}
		header := strings.TrimSuffix(buf.String(), "\n")
		var cols []string
		for _, c := range strings.Split(header, "\t") {
			if c != "" {
				cols = append(cols, c)
			}
		}
		if !reflect.DeepEqual(cols, want) {
			t.Fatalf("raw=%v header cols=%q want %q", raw, cols, want)
		}
	}
}

func TestWriteFDColumns(t *testing.T) {
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	var b outbuf.Buf
	var buf bytes.Buffer
	WriteFD(&b, int(f.Fd()), Options{})
	if err := b.Flush(&buf); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSuffix(buf.String(), "\n")
	fields := strings.Split(line, "\t")
	if len(fields) < 17 {
		t.Fatalf("too few columns: %q", fields)
	}
	if fields[8] != "0" {
		t.Fatalf("size=%q want 0", fields[8])
	}
	if _, err := strconv.Atoi(fields[9]); err != nil {
		t.Fatalf("blksize=%q", fields[9])
	}
	if _, err := strconv.Atoi(fields[10]); err != nil {
		t.Fatalf("blocks=%q", fields[10])
	}
	if !strings.HasPrefix(fields[3], "0") {
		t.Fatalf("mode=%q want leading 0", fields[3])
	}
	if !strings.Contains(fields[7], ",") {
		t.Fatalf("rdev=%q want high,low pair", fields[7])
	}
	if !strings.Contains(line, "\tpoll: ") {
		t.Fatalf("missing poll: %q", line)
	}
	if runtime.GOOS != "linux" {
		return
	}
	if len(fields) < 18 {
		t.Fatalf("missing sigio: %q", fields)
	}
	if _, err := strconv.Atoi(fields[17]); err != nil {
		t.Fatalf("sigio=%q", fields[17])
	}
}

func TestClassicDevPairHighLow16(t *testing.T) {
	if got := classicDevPair(0xa5c); got != "10,92" {
		t.Fatalf("classicDevPair(0xa5c)=%q want 10,92", got)
	}
	if got := classicDevPair(0); got != "0,0" {
		t.Fatalf("classicDevPair(0)=%q", got)
	}
}

func TestWriteFDSocketHasFamilyAndLinger(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tcp, ok := ln.(*net.TCPListener)
	if !ok {
		t.Fatal("tcp listener")
	}
	c, err := tcp.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	if err := c.Control(func(h uintptr) { fd = int(h) }); err != nil {
		t.Fatal(err)
	}

	var b outbuf.Buf
	var buf bytes.Buffer
	WriteFD(&b, fd, Options{})
	if err := b.Flush(&buf); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	if !strings.Contains(line, "AF=") {
		t.Fatalf("missing AF=: %q", line)
	}
	if runtime.GOOS == "darwin" && !strings.Contains(line, "LEN=") {
		t.Fatalf("darwin missing LEN=: %q", line)
	}
	if !strings.Contains(line, "LINGER=") {
		t.Fatalf("missing LINGER: %q", line)
	}
	if !strings.Contains(line, "TYPE=") {
		t.Fatalf("missing TYPE: %q", line)
	}
	if strings.Contains(line, "\tSTREAM") {
		t.Fatalf("unexpected STREAM word: %q", line)
	}
	fields := strings.Split(strings.TrimSuffix(line, "\n"), "\t")
	if fields[7] == "" {
		t.Fatalf("socket rdev should be printed: %q", fields)
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

func connFD(t *testing.T, c net.Conn) int {
	t.Helper()
	sc, ok := c.(syscall.Conn)
	if !ok {
		t.Fatal("conn is not syscall.Conn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	if err := raw.Control(func(h uintptr) { fd = int(h) }); err != nil {
		t.Fatal(err)
	}
	return fd
}

func connectedTCP(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	got := <-ch
	if got.err != nil {
		t.Fatal(got.err)
	}
	t.Cleanup(func() { _ = got.c.Close() })
	return client, got.c
}

func waitPOLLIN(t *testing.T, fd int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pfd := []unix.PollFd{{
			Fd:     int32(fd), // #nosec G115 -- pollfd.fd is C int
			Events: unix.POLLIN,
		}}
		n, err := unix.Poll(pfd, 50)
		if err == nil && n > 0 && pfd[0].Revents&unix.POLLIN != 0 {
			return
		}
	}
	t.Fatal("timeout waiting for POLLIN")
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

func TestWriteFDRecvmsgPeekLeavesPayload(t *testing.T) {
	client, server := connectedTCP(t)
	payload := []byte("hello")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	fd := connFD(t, server)
	waitPOLLIN(t, fd)
	got := dumpFD(t, fd)
	if !strings.Contains(got, "recvmsg=1,") {
		t.Fatalf("missing 1-byte recvmsg peek: %q", got)
	}
	buf := make([]byte, len(payload)+1)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload consumed or altered: %q", buf[:n])
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
	if runtime.GOOS == "darwin" && !strings.HasPrefix(got, "LEN=") {
		t.Fatalf("darwin SockAddrInfo=%q", got)
	}
	if short := SockAddrString(sa); short != "127.0.0.1:2345" {
		t.Fatalf("SockAddrString=%q", short)
	}
}
