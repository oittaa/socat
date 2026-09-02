//go:build linux || darwin

package filan

import (
	"bytes"
	"net"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

func TestWriteHeaderTabSeparatedColumns(t *testing.T) {
	var b outbuf.Buf
	var buf bytes.Buffer
	WriteHeader(&b, Options{})
	if err := b.Flush(&buf); err != nil {
		t.Fatal(err)
	}
	header := strings.TrimSuffix(buf.String(), "\n")
	if !strings.Contains(header, "\tatime\t\t\t\tmtime\t\t\t\tctime\t\t\t\tcloexec") {
		t.Fatalf("header missing padded time tabs: %q", header)
	}
	var cols []string
	for _, c := range strings.Split(header, "\t") {
		if c != "" {
			cols = append(cols, c)
		}
	}
	want := []string{
		"  FD  type", "device", "inode", "mode", "links", "uid", "gid", "rdev",
		"size", "blksize", "blocks", "atime", "mtime", "ctime", "cloexec", "flags", "sigown",
	}
	if runtime.GOOS == "linux" {
		want = append(want, "sigio")
	}
	if !reflect.DeepEqual(cols, want) {
		t.Fatalf("header cols=%q want %q", cols, want)
	}
}

func TestWriteHeaderRawTimeTabs(t *testing.T) {
	var b outbuf.Buf
	var buf bytes.Buffer
	WriteHeader(&b, Options{Raw: true})
	if err := b.Flush(&buf); err != nil {
		t.Fatal(err)
	}
	header := buf.String()
	if !strings.Contains(header, "\tatime\t\tmtime\t\tctime\t\tcloexec") {
		t.Fatalf("raw header missing time tabs: %q", header)
	}
}

func TestWriteFDPlacesTimesAfterBlksizeAndBlocks(t *testing.T) {
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
	iso := regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} *$`)
	for _, i := range []int{11, 12, 13} {
		if !iso.MatchString(fields[i]) {
			t.Fatalf("time field %d = %q", i, fields[i])
		}
		if len(fields[i]) != asctimeWidth {
			t.Fatalf("time field %d width=%d want %d (%q)", i, len(fields[i]), asctimeWidth, fields[i])
		}
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

func TestWriteFDReportsTermiosOnPTY(t *testing.T) {
	master, slave, err := openTestPTY()
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = slave.Close(); _ = master.Close() })
	var b outbuf.Buf
	var buf bytes.Buffer
	WriteFD(&b, int(slave.Fd()), Options{})
	if err := b.Flush(&buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "IFLAGS=") || !strings.Contains(got, "cc[0]=") {
		t.Fatalf("missing termios: %q", got)
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
