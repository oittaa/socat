//go:build unix

package xio

import (
	"errors"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestShutDownOnStreamSocketpair(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	local := os.NewFile(uintptr(fds[0]), "local")
	peer := os.NewFile(uintptr(fds[1]), "peer")
	defer func() { _ = local.Close() }()
	defer func() { _ = peer.Close() }()
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))

	spec, err := parse.ParseSpec("SOCKETPAIR,shut-down")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := WrapCommon(spec, FileStream(local))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := io.ReadFull(peer, buf[:2])
	if err != nil || n != 2 || string(buf[:2]) != "hi" {
		t.Fatalf("peer read n=%d err=%v data=%q", n, err, buf[:n])
	}
	n, err = peer.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("after shut-down peer Read n=%d err=%v want EOF", n, err)
	}
}
