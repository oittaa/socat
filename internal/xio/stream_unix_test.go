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

func TestFileStreamShutdownWriteKeepsDeadlines(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(fds[1], true); err != nil {
		t.Fatal(err)
	}
	local := os.NewFile(uintptr(fds[0]), "local")
	peer := os.NewFile(uintptr(fds[1]), "peer")
	defer func() { _ = local.Close() }()
	defer func() { _ = peer.Close() }()

	if err := FileStream(local).ShutdownWrite(); err != nil {
		t.Fatalf("ShutdownWrite: %v", err)
	}
	if err := local.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline after ShutdownWrite: %v", err)
	}
	buf := make([]byte, 1)
	_, err = local.Read(buf)
	if !os.IsTimeout(err) {
		t.Fatalf("Read: want timeout, got %v", err)
	}
}
