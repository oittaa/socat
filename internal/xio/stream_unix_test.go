//go:build unix

package xio

import (
	"errors"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestDgramPairShutdownWriteKeepsReadSideOpen(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "parent")
	peer := os.NewFile(uintptr(fds[1]), "peer")
	defer func() { _ = parent.Close() }()
	defer func() { _ = peer.Close() }()
	_ = parent.SetDeadline(time.Now().Add(time.Second))
	_ = peer.SetDeadline(time.Now().Add(time.Second))

	stream := DgramPairStream(parent)
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatalf("ShutdownWrite: %v", err)
	}
	var marker [1]byte
	if n, err := peer.Read(marker[:]); n != 0 || (err != nil && !errors.Is(err, io.EOF)) {
		t.Fatalf("shutdown marker: n=%d err=%v", n, err)
	}
	if _, err := peer.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if n, err := stream.Read(buf); err != nil || n != len(buf) || string(buf) != "reply" {
		t.Fatalf("Read after ShutdownWrite: n=%d data=%q err=%v", n, buf[:n], err)
	}
}
